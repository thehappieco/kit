//go:build go1.26

// Package idvectors writes the golden vectors of the id protocol, version 1
// (docs/protocol/id-v1.md, sections 6, 7.14 and 8.5), by running the kit's
// platform profile (github.com/thehappieco/kit/profiles/platform, imported
// as idcrypto) over fixed inputs. The TypeScript implementation
// (web/shared/crypto) and the kit test themselves against the same files;
// the kit embeds a copy of them (vectors/platform/id-v1).
//
// The rule it enforces: the vectors are a pure function of this code. Every
// input, nonce and root comes from a fixed seed, cases are in a fixed order,
// and the output is 2-space indented ASCII JSON with a trailing newline, so
// regenerating them gives the same bytes and a diff means the protocol
// moved. go run ./tools/vectors writes them; internal/crypto/idkit's
// TestTheGoldenVectorsAreUpToDate compares them byte for byte.
//
// The files are frozen (decision 0017): since the platform's own copy of the
// protocol crypto was replaced by the kit, the code that writes them is the
// code they test, so a regenerated file that differs is a regression of the
// kit, never a new truth. New cases come as new files.
//
// Each case declares the outcome it expects, and Generate refuses to write a
// file whose cases do not come out that way, so a regression cannot be
// recorded as the new truth by accident.
//
// Every file is {"format": "thehappie-id/vectors", "version": 1, "kind":
// "<kind>", "cases": [...]}; every case has a name and either its outputs or
// "error": "<name>" (idcrypto.ErrorCode). Binary values are base64url. The
// Argon2id cases use the floor parameters and are kept few.
//
// The key-delivery vectors need a seal under a given ephemeral key, which
// crypto/hpke cannot make; hpke.go makes it, and its tests tie it to the RFC
// 9180 test vector for the suite and to crypto/hpke.
//
// It builds on the standard library and the kit's platform profile alone,
// and on nothing newer than Go 1.26, like the kit: the kit carries copies of
// it beside the vectors (vectors/platform/_generators-<commit>).
package idvectors

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// Format and Version open every vector file.
	Format  = "thehappie-id/vectors"
	Version = 1
	// Dir is where the files live, relative to the module root.
	Dir = "testdata/vectors/id-v1"
)

// The kinds, in the order of spec sections 6, 7.14 and 8.5. Each is written
// to <kind>.json.
const (
	KindPasswordProfile = "password-profile"
	// KindPasswordStreamSafe holds password-profile cases at and one past
	// the run limit of spec 2.1, step 2, in the shape of
	// KindPasswordProfile (PasswordProfileCase).
	KindPasswordStreamSafe = "password-stream-safe"
	KindKDF                = "kdf"
	KindRootWrap           = "root-wrap"
	KindRecoveryCode       = "recovery-code"
	KindProductKey         = "product-key"
	KindVerifier           = "verifier"
	KindEmail              = "email"
	KindKeyBundle          = "key-bundle"
	KindKeyDelivery        = "key-delivery"
	KindPKCE               = "pkce"
	KindPasskey            = "passkey"
	KindClientExtensions   = "client-extensions"
	// KindRPIDEndsInNumber holds relying party ids a URL parser reads as a
	// number (spec 8.1, RPIDEndsInNumberCase): a file added after the switch
	// to the kit, which kit v0.4.0 does not embed yet.
	KindRPIDEndsInNumber = "rp-id-ends-in-number"
)

// Kinds lists every kind in file order.
var Kinds = []string{
	KindPasswordProfile, KindPasswordStreamSafe, KindKDF, KindRootWrap, KindRecoveryCode,
	KindProductKey, KindVerifier, KindEmail, KindKeyBundle,
	KindKeyDelivery, KindPKCE,
	KindPasskey, KindClientExtensions,
	KindRPIDEndsInNumber,
}

// FileName returns the file a kind is written to.
func FileName(kind string) string { return kind + ".json" }

// Vectors is the shape of every vector file.
type Vectors[C any] struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Cases   []C    `json:"cases"`
}

// File is one generated vector file.
type File struct {
	Kind string
	Name string // FileName(Kind)
	Data []byte
}

// Generate builds every vector file, in Kinds order.
func Generate() ([]File, error) {
	gens := map[string]func() ([]byte, error){
		KindPasswordProfile:    func() ([]byte, error) { return encode(KindPasswordProfile, passwordProfileCases) },
		KindPasswordStreamSafe: func() ([]byte, error) { return encode(KindPasswordStreamSafe, passwordStreamSafeCases) },
		KindKDF:                func() ([]byte, error) { return encode(KindKDF, kdfCases) },
		KindRootWrap:           func() ([]byte, error) { return encode(KindRootWrap, rootWrapCases) },
		KindRecoveryCode:       func() ([]byte, error) { return encode(KindRecoveryCode, recoveryCodeCases) },
		KindProductKey:         func() ([]byte, error) { return encode(KindProductKey, productKeyCases) },
		KindVerifier:           func() ([]byte, error) { return encode(KindVerifier, verifierCases) },
		KindEmail:              func() ([]byte, error) { return encode(KindEmail, emailCases) },
		KindKeyBundle:          func() ([]byte, error) { return encode(KindKeyBundle, keyBundleCases) },
		KindKeyDelivery:        func() ([]byte, error) { return encode(KindKeyDelivery, keyDeliveryCases) },
		KindPKCE:               func() ([]byte, error) { return encode(KindPKCE, pkceCases) },
		KindPasskey:            func() ([]byte, error) { return encode(KindPasskey, passkeyCases) },
		KindClientExtensions:   func() ([]byte, error) { return encode(KindClientExtensions, clientExtensionsCases) },
		KindRPIDEndsInNumber:   func() ([]byte, error) { return encode(KindRPIDEndsInNumber, rpIDEndsInNumberCases) },
	}
	out := make([]File, 0, len(Kinds))
	for _, kind := range Kinds {
		data, err := gens[kind]()
		if err != nil {
			return nil, fmt.Errorf("idvectors: %s: %w", kind, err)
		}
		out = append(out, File{Kind: kind, Name: FileName(kind), Data: data})
	}
	return out, nil
}

func encode[C any](kind string, build func() ([]C, error)) ([]byte, error) {
	cases, err := build()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Vectors[C]{Format: Format, Version: Version, Kind: kind, Cases: cases}); err != nil {
		return nil, err
	}
	return asciiJSON(buf.Bytes()), nil
}

// asciiJSON rewrites every non-ASCII character of a JSON text as a \u escape
// (a surrogate pair above U+FFFF). Outside strings JSON is ASCII already, so
// this changes no value; it keeps invisible and combining characters visible
// in a diff and safe from editors that normalize what they save.
func asciiJSON(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r < utf8.RuneSelf {
			out = append(out, b[0])
			b = b[1:]
			continue
		}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			out = fmt.Appendf(out, `\u%04x\u%04x`, hi, lo)
		} else {
			out = fmt.Appendf(out, `\u%04x`, r)
		}
		b = b[size:]
	}
	return out
}

// seeded returns n deterministic bytes for label. The seeds only need to be
// fixed and distinct; the outputs they lead to are what the files record.
func seeded(label string, n int) []byte {
	b, err := hkdf.Key(sha256.New, []byte("thehappie-id/vectors/v1"), nil, label, n)
	if err != nil {
		panic(fmt.Sprintf("idvectors: seed %q: %v", label, err)) // n is a small constant
	}
	return b
}

// seq returns the bytes from, from+1, ..., n of them.
func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i) //nolint:gosec // wraps past 255 by design
	}
	return b
}

// vectorTime is the instant every generated time is taken from.
var vectorTime = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// uuid7 returns a deterministic UUIDv7 for label, as lowercase hyphenated
// text, with vectorTime as its timestamp.
func uuid7(label string) string {
	b := seeded("sub/"+label, 16)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(vectorTime.UnixMilli())) //nolint:gosec // a 2026 timestamp is positive
	copy(b[:6], ts[2:])
	b[6] = 0x70 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// mismatch reports a case that did not come out as declared. It never
// prints the case's inputs or outputs, only its name and the error names.
func mismatch(name, got, want string) error {
	if got == "" {
		got = "success"
	}
	if want == "" {
		want = "success"
	}
	return fmt.Errorf("case %s: got %s, declared %s", strconv.Quote(name), got, want)
}

func ptr[T any](v T) *T { return &v }
