// Package seal implements the sealed envelope: values encrypted to a public
// key whose private half the sealing side never holds, each bound to where it
// is stored.
//
// The format comes from Wappie's archive (internal/crypto/seal), where the
// server holds only a device's public key and seals every message on the way
// in; the private key exists only in the browser. Two parts of it belong to a
// product and are parameters here, grouped in a Domain: the two magic bytes at
// the front of every envelope, and the label that prefixes the additional
// data and the HPKE info. A product also names its kinds, because a direct
// envelope's info carries the kind's name. Everything else is the standard and
// is fixed (SPEC.md §4).
//
// # Why HPKE rather than a sealed box
//
// HPKE accepts additional authenticated data; a NaCl sealed box does not.
// Without it, anybody with write access to the database can move a sealed
// value from one row to another and it still opens. The AAD binds every value
// to its tenant, its kind, its row and its own header, so a relocation fails
// authentication.
//
// # Why content keys
//
// One asymmetric operation per value makes opening a large history slow on a
// phone. Batch mode seals values under a symmetric content key, and the
// content key is sealed once, directly, to the public key.
//
// # Kinds and profiles
//
// A Kind is a byte bound into the AAD, and its name is part of a direct
// envelope's HPKE info. Each profile declares its own kind type implementing
// Kind, and the type carries the profile's Domain, so a value of one product's
// kind type cannot be sealed under another product's label. Wappie's is
// profiles/wappie.Kind.
package seal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

// Domain is the part of the envelope a product chooses.
type Domain struct {
	// Magic is bytes 0-1 of every envelope, so a foreign blob is rejected
	// before any cryptography runs.
	Magic [2]byte
	// Label prefixes the additional data and the HPKE info. Printable ASCII,
	// not empty. Two products with different labels can never open each
	// other's envelopes, whatever their kinds.
	Label string
}

func (d Domain) check() error {
	if d.Label == "" {
		return errors.New("seal: the domain has no label")
	}
	for i := 0; i < len(d.Label); i++ {
		if c := d.Label[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("seal: the domain label %q is not printable ASCII", d.Label)
		}
	}
	return nil
}

// Kind is implemented by each profile's own kind type.
//
// The byte is bound into the AAD. String is the wire name that goes into a
// direct envelope's HPKE info: it must be stable forever for every kind ever
// sealed in direct mode, match [a-z0-9_]+, and default to
// fmt.Sprintf("kind(%#x)", byte(k)) for a byte the profile does not name.
type Kind interface {
	~uint8
	String() string
	Domain() Domain
}

// Wire format constants.
const (
	// Version covers the layout. A parser that does not recognise it fails
	// rather than guessing.
	Version = 0x01

	// SuiteV1 is the HPKE suite of package hpke with AES-256-GCM content
	// keys. Frozen: nothing is negotiated at runtime.
	SuiteV1 = 0x01

	// ModeDirect seals straight to a public key: content keys, grants and
	// other low-volume values.
	ModeDirect = 0x01
	// ModeBatch seals under a content key.
	ModeBatch = 0x02

	// HeaderLen is the fixed prefix of every envelope.
	HeaderLen = 8
	// KeyLen is the size of a content key, and of the keys package hpke takes.
	KeyLen = 32

	encLen   = 32
	nonceLen = 12
	tagLen   = 16

	// BatchOverhead and DirectOverhead are the fixed cost per sealed value.
	BatchOverhead  = HeaderLen + 4 + nonceLen + tagLen // 40 bytes
	DirectOverhead = HeaderLen + encLen + tagLen       // 56 bytes
)

// The core kind bytes. They mean the same in every profile, and every profile
// must name them.
const (
	// KindContentKey is a content key sealed directly to a public key.
	KindContentKey = 0x06
	// KindGrant is a private key sealed directly to another public key, at
	// GrantRow: how a person is given read access by signing in.
	KindGrant = 0x07
	// KindUserWrap is reserved. Wappie named it and never sealed it.
	KindUserWrap = 0x08
)

var (
	ErrShort          = errors.New("seal: envelope too short")
	ErrMagic          = errors.New("seal: not an envelope")
	ErrVersion        = errors.New("seal: unsupported envelope version")
	ErrSuite          = errors.New("seal: unsupported cipher suite")
	ErrMode           = errors.New("seal: unknown envelope mode")
	ErrAuthentication = errors.New("seal: authentication failed")
	// ErrKeyMismatch is a batch envelope presented to a content key other
	// than the one it names.
	ErrKeyMismatch = errors.New("seal: content key mismatch")
	// ErrInvalidKey is a missing public or private key, or a public key of
	// low order, with which no secret can be agreed.
	ErrInvalidKey = errors.New("seal: no key")
)

// classified is an error with its own text that matches one of the sentinels
// above. The texts are the ones Wappie logged before the move.
type classified struct {
	text  string
	class error
}

func (e *classified) Error() string        { return e.text }
func (e *classified) Is(target error) bool { return target == e.class }

// Header is the fixed prefix every envelope carries.
type Header struct {
	Version byte
	Suite   byte
	Mode    byte
	Epoch   uint16
}

func encodeHeader(d Domain, mode byte, epoch uint16) []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = d.Magic[0], d.Magic[1]
	b[2] = Version
	b[3] = SuiteV1
	b[4] = mode
	binary.BigEndian.PutUint16(b[5:7], epoch)
	b[7] = 0 // reserved
	return b
}

// ParseHeader validates an envelope's prefix for a domain.
//
// The suite is checked before any key material is touched: a parser that
// guessed at an unknown suite would be a downgrade path. The reserved byte is
// not checked here; it is bound by the AAD, so a non-zero one fails as
// ErrAuthentication when the envelope is opened.
func ParseHeader(d Domain, b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrShort
	}
	if b[0] != d.Magic[0] || b[1] != d.Magic[1] {
		return Header{}, ErrMagic
	}
	h := Header{Version: b[2], Suite: b[3], Mode: b[4], Epoch: binary.BigEndian.Uint16(b[5:7])}
	if h.Version != Version {
		return Header{}, fmt.Errorf("%w: %#x", ErrVersion, h.Version)
	}
	if h.Suite != SuiteV1 {
		return Header{}, fmt.Errorf("%w: %#x", ErrSuite, h.Suite)
	}
	if h.Mode != ModeDirect && h.Mode != ModeBatch {
		return Header{}, fmt.Errorf("%w: %#x", ErrMode, h.Mode)
	}
	return h, nil
}

// AAD binds a sealed value to where it lives and to its own header:
//
//	label ‖ kind (1) ‖ tenant (16) ‖ row (16) ‖ header (8)
//
// The tenant and row are never transmitted, only rebuilt from the columns
// beside the value, so moving it elsewhere changes them and the open fails.
// The header is included because it is otherwise unauthenticated: an epoch or
// mode byte flipped in the clear would still open.
func AAD[K Kind](kind K, tenant, row uuid.UUID, header []byte) []byte {
	label := kind.Domain().Label
	aad := make([]byte, 0, len(label)+1+16+16+len(header))
	aad = append(aad, label...)
	aad = append(aad, byte(kind))
	aad = append(aad, tenant[:]...)
	aad = append(aad, row[:]...)
	return append(aad, header...)
}

// Info is the HPKE info of a direct envelope, giving each use of a public key
// its own domain:
//
//	label "/" name(kind) "/" tenant "/" decimal(epoch)
//
// with the tenant as lowercase hyphenated text. A content key sealed for one
// epoch cannot be replayed as a grant.
func Info[K Kind](kind K, tenant uuid.UUID, epoch uint16) []byte {
	return fmt.Appendf(nil, "%s/%s/%s/%d", kind.Domain().Label, kind.String(), tenant, epoch)
}

var kindName = regexp.MustCompile(`^[a-z0-9_]+$`)

// ValidateKinds checks a profile's kind type: every byte's name is either a
// wire name matching [a-z0-9_]+ or the kind(0x..) default, no two bytes share
// a name, the core kinds are named, 0x00 is not, and the domain is valid.
func ValidateKinds[K Kind]() error {
	var zero K
	if err := zero.Domain().check(); err != nil {
		return err
	}
	seen := map[string]int{}
	for b := range 256 {
		k := K(b)
		name := k.String()
		if k.Domain() != zero.Domain() {
			return fmt.Errorf("seal: kind %#x has another domain", b)
		}
		if name == fmt.Sprintf("kind(%#x)", b) {
			if b == KindContentKey || b == KindGrant || b == KindUserWrap {
				return fmt.Errorf("seal: core kind %#x has no name", b)
			}
			continue
		}
		if b == 0 {
			return errors.New("seal: kind 0x00 must stay unnamed")
		}
		if !kindName.MatchString(name) {
			return fmt.Errorf("seal: kind %#x is named %q, which is not [a-z0-9_]+", b, name)
		}
		if other, ok := seen[name]; ok {
			return fmt.Errorf("seal: kinds %#x and %#x are both named %q", other, b, name)
		}
		seen[name] = b
	}
	return nil
}
