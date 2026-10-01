package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
)

var (
	errNoPublicKey  = &classified{"seal: no public key", ErrInvalidKey}
	errNoPrivateKey = &classified{"seal: no private key", ErrInvalidKey}
)

// ---------------------------------------------------------------------------
// Direct mode: sealed straight to a public key.
// ---------------------------------------------------------------------------

// SealDirect seals a small, low-volume value to a public key:
//
//	header ‖ enc (32) ‖ HPKE ciphertext
//
// Used for content keys and grants. Never for high-volume content: one
// asymmetric operation per value is what makes a large history slow to open.
func SealDirect[K Kind](pub hpke.PublicKey, kind K, tenant, row uuid.UUID, epoch uint16, plaintext []byte) ([]byte, error) {
	if !pub.Valid() {
		return nil, errNoPublicKey
	}
	d := kind.Domain()
	if err := d.check(); err != nil {
		return nil, err
	}
	hdr := encodeHeader(d, ModeDirect, epoch)
	enc, ct, err := hpke.Seal(pub, Info(kind, tenant, epoch), AAD(kind, tenant, row, hdr), plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	out := make([]byte, 0, HeaderLen+len(enc)+len(ct))
	out = append(out, hdr...)
	out = append(out, enc...)
	return append(out, ct...), nil
}

// OpenDirect reverses SealDirect. Every failure after the header checks is
// ErrAuthentication: telling a wrong key from a moved row from a tampered
// byte would give anybody with write access an oracle for the binding.
func OpenDirect[K Kind](priv hpke.PrivateKey, kind K, tenant, row uuid.UUID, envelope []byte) ([]byte, error) {
	if !priv.Valid() {
		return nil, errNoPrivateKey
	}
	h, err := ParseHeader(kind.Domain(), envelope)
	if err != nil {
		return nil, err
	}
	if h.Mode != ModeDirect {
		return nil, fmt.Errorf("%w: expected direct, got %#x", ErrMode, h.Mode)
	}
	if len(envelope) < DirectOverhead {
		return nil, ErrShort
	}
	enc := envelope[HeaderLen : HeaderLen+encLen]
	ct := envelope[HeaderLen+encLen:]
	pt, err := hpke.Open(priv, enc, Info(kind, tenant, h.Epoch), AAD(kind, tenant, row, envelope[:HeaderLen]), ct)
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// Batch mode: sealed under a content key.
// ---------------------------------------------------------------------------

// ContentKey is a symmetric key covering a batch of sealed values.
type ContentKey[K Kind] struct {
	// ID names the key inside every envelope sealed under it, so a reader
	// knows which one to unwrap. It is bound only through the content key's
	// own row (ContentKeyRow), not through the batch envelope's AAD.
	ID    uint32
	Epoch uint16

	// Sealed is the key sealed directly to the public key at ContentKeyRow.
	// It is what is stored; the raw key never is.
	Sealed []byte

	key []byte // 32 bytes, AES-256-GCM
}

// NewContentKey generates a content key and seals it to pub, bound to
// ContentKeyRow(tenant, device, id).
func NewContentKey[K Kind](pub hpke.PublicKey, tenant, device uuid.UUID, epoch uint16, id uint32) (*ContentKey[K], error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("seal: entropy: %w", err)
	}
	sealed, err := SealDirect(pub, K(KindContentKey), tenant, ContentKeyRow(tenant, device, id), epoch, key)
	if err != nil {
		return nil, err
	}
	return &ContentKey[K]{ID: id, Epoch: epoch, key: key, Sealed: sealed}, nil
}

// OpenContentKey unwraps a stored content key. Its epoch is the one in the
// sealed key's header.
func OpenContentKey[K Kind](priv hpke.PrivateKey, tenant, device uuid.UUID, id uint32, sealed []byte) (*ContentKey[K], error) {
	kind := K(KindContentKey)
	h, err := ParseHeader(kind.Domain(), sealed)
	if err != nil {
		return nil, err
	}
	key, err := OpenDirect(priv, kind, tenant, ContentKeyRow(tenant, device, id), sealed)
	if err != nil {
		return nil, err
	}
	if len(key) != KeyLen {
		return nil, &classified{fmt.Sprintf("seal: content key is %d bytes, want %d", len(key), KeyLen), ErrShort}
	}
	return &ContentKey[K]{ID: id, Epoch: h.Epoch, key: key, Sealed: sealed}, nil
}

// Seal encrypts a value under this content key:
//
//	header ‖ u32be id ‖ nonce (12) ‖ AES-256-GCM ciphertext ‖ tag
func (c *ContentKey[K]) Seal(kind K, tenant, row uuid.UUID, plaintext []byte) ([]byte, error) {
	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: entropy: %w", err)
	}
	hdr := encodeHeader(kind.Domain(), ModeBatch, c.Epoch)
	out := make([]byte, 0, BatchOverhead+len(plaintext))
	out = append(out, hdr...)
	out = binary.BigEndian.AppendUint32(out, c.ID)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, AAD(kind, tenant, row, hdr)), nil
}

// Open decrypts a value sealed under this content key. The key id is checked
// before decryption.
func (c *ContentKey[K]) Open(kind K, tenant, row uuid.UUID, envelope []byte) ([]byte, error) {
	h, err := ParseHeader(kind.Domain(), envelope)
	if err != nil {
		return nil, err
	}
	if h.Mode != ModeBatch {
		return nil, fmt.Errorf("%w: expected batch, got %#x", ErrMode, h.Mode)
	}
	if len(envelope) < BatchOverhead {
		return nil, ErrShort
	}
	if id := binary.BigEndian.Uint32(envelope[HeaderLen : HeaderLen+4]); id != c.ID {
		return nil, &classified{fmt.Sprintf("seal: envelope needs content key %d, have %d", id, c.ID), ErrKeyMismatch}
	}
	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := envelope[HeaderLen+4 : HeaderLen+4+nonceLen]
	ct := envelope[HeaderLen+4+nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, AAD(kind, tenant, row, envelope[:HeaderLen]))
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

func (c *ContentKey[K]) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("seal: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: gcm: %w", err)
	}
	return gcm, nil
}

// ContentKeyID reads which content key a batch envelope needs, without
// opening it.
func ContentKeyID[K Kind](envelope []byte) (id uint32, epoch uint16, err error) {
	var kind K
	h, err := ParseHeader(kind.Domain(), envelope)
	if err != nil {
		return 0, 0, err
	}
	if h.Mode != ModeBatch {
		return 0, h.Epoch, fmt.Errorf("%w: not a batch envelope", ErrMode)
	}
	if len(envelope) < HeaderLen+4 {
		return 0, 0, ErrShort
	}
	return binary.BigEndian.Uint32(envelope[HeaderLen : HeaderLen+4]), h.Epoch, nil
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

// Row derives a row identity from a namespace and a name: the RFC 9562
// version 5 UUID (SHA-1) of the namespace and the concatenation of the parts.
// Values whose identity is derived rather than stored bind to one of these,
// so they cannot be presented in another slot.
func Row(namespace uuid.UUID, name ...[]byte) uuid.UUID {
	n := 0
	for _, part := range name {
		n += len(part)
	}
	joined := make([]byte, 0, n)
	for _, part := range name {
		joined = append(joined, part...)
	}
	return uuid.NewSHA1(namespace, joined)
}

// ContentKeyRow is the row a content key binds to: Row(tenant, device ‖ u32be id).
func ContentKeyRow(tenant, device uuid.UUID, id uint32) uuid.UUID {
	return Row(tenant, device[:], binary.BigEndian.AppendUint32(nil, id))
}

// GrantRow is the row a grant binds to: Row(tenant, device ‖ user ‖ u16be epoch).
// Binding the user means a grant issued to one person cannot be presented as
// another's; binding the device means it cannot unlock another device.
func GrantRow(tenant, device, user uuid.UUID, epoch uint16) uuid.UUID {
	return Row(tenant, device[:], user[:], binary.BigEndian.AppendUint16(nil, epoch))
}
