package platform

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Key bundle (section 11.9): what a command-line tool opens with the
// password, or with the recovery code, to read a person's data without the
// platform. It holds only what the server already stores, so downloading it
// is safe.
//
// Honest limit: a bundle downloaded before a password or recovery code change
// still opens with the old one. The root does not change, so this is
// inherent.
const (
	KeyBundleFormat  = "thehappie-id/key-bundle"
	KeyBundleVersion = 1

	// maxKeyBundleLen bounds what ParseKeyBundle reads. A real bundle is
	// about 1 KiB.
	maxKeyBundleLen = 64 << 10
	// maxIssuerLen bounds the issuer, which is an origin.
	maxIssuerLen = 256
)

// ProductPublicKey is one {product, epoch, pub} entry, as sign-up sends it
// and the key bundle lists it. Pub is base64url.
type ProductPublicKey struct {
	Product string `json:"product"`
	Epoch   int    `json:"epoch"`
	Pub     string `json:"pub"`
}

// KeyBundle is the key bundle as JSON, field for field. Binary fields are
// base64url text; CreatedAt is RFC 3339 in UTC, ending in 'Z' (a numeric
// offset, even +00:00, is refused), with at most nine fraction digits.
type KeyBundle struct {
	Format          string             `json:"format"`
	Version         int                `json:"version"`
	Issuer          string             `json:"issuer"`
	Sub             string             `json:"sub"`
	Email           string             `json:"email"`
	AccountKeyEpoch int                `json:"account_key_epoch"`
	KDF             KDF                `json:"kdf"`
	KDFSalt         string             `json:"kdf_salt"`
	PasswordWrap    string             `json:"password_wrap"`
	RecoveryWrap    string             `json:"recovery_wrap"`
	ProductKeys     []ProductPublicKey `json:"product_keys"`
	CreatedAt       string             `json:"created_at"`
}

var bundleMembers = []string{
	"format", "version", "issuer", "sub", "email", "account_key_epoch", "kdf",
	"kdf_salt", "password_wrap", "recovery_wrap", "product_keys", "created_at",
}

// Validate checks every field of the bundle, in the order of section 11.9. KDF parameters outside the
// bounds wrap ErrKDFPolicy, as they would anywhere else on the client; every
// other defect wraps ErrBundle. It does not open anything.
func (b *KeyBundle) Validate() error {
	if b.Format != KeyBundleFormat || b.Version != KeyBundleVersion {
		return fmt.Errorf("%w: unknown format or version", ErrBundle)
	}
	if b.Issuer == "" || len(b.Issuer) > maxIssuerLen || !printableASCII(b.Issuer) {
		return fmt.Errorf("%w: issuer", ErrBundle)
	}
	if _, err := parseSub(b.Sub); err != nil {
		return fmt.Errorf("%w: sub", ErrBundle)
	}
	if e, err := NormalizeEmail(b.Email); err != nil || e != b.Email {
		return fmt.Errorf("%w: email is not a normalized address", ErrBundle)
	}
	if !checkEpoch(b.AccountKeyEpoch) {
		return fmt.Errorf("%w: account_key_epoch", ErrBundle)
	}
	if err := b.KDF.Check(); err != nil {
		return err
	}
	if _, err := DecodeB64(b.KDFSalt, SaltLen); err != nil {
		return fmt.Errorf("%w: kdf_salt", ErrBundle)
	}
	for _, w := range []struct {
		kind WrapKind
		text string
	}{{WrapPassword, b.PasswordWrap}, {WrapRecovery, b.RecoveryWrap}} {
		raw, err := DecodeB64(w.text, WrapLen)
		if err != nil {
			return fmt.Errorf("%w: %s_wrap", ErrBundle, w.kind)
		}
		if err := CheckWrapShape(w.kind, raw); err != nil {
			return fmt.Errorf("%w: %s_wrap", ErrBundle, w.kind)
		}
	}
	if len(b.ProductKeys) == 0 {
		return fmt.Errorf("%w: no product keys", ErrBundle)
	}
	for i, pk := range b.ProductKeys {
		if !ValidProduct(pk.Product) || !checkEpoch(pk.Epoch) {
			return fmt.Errorf("%w: product key %d", ErrBundle, i)
		}
		if _, err := DecodeB64(pk.Pub, KeyLen); err != nil {
			return fmt.Errorf("%w: product key %d", ErrBundle, i)
		}
		if i > 0 && compareProductKeys(b.ProductKeys[i-1], pk) >= 0 {
			return fmt.Errorf("%w: product keys not sorted by product and epoch, or repeated", ErrBundle)
		}
	}
	if !utcTime(b.CreatedAt) {
		return fmt.Errorf("%w: created_at", ErrBundle)
	}
	return nil
}

// utcTime reports whether s is an RFC 3339 time in UTC in the one shape both
// readers accept: YYYY-MM-DDTHH:MM:SS, optionally '.' and 1 to 9 digits, then
// 'Z', naming an instant that exists in the proleptic Gregorian calendar
// (years 0000 to 9999, no leap second). time.Parse alone is wider: it takes
// any offset, a comma before the fraction and more than nine fraction
// digits, and the TypeScript reader takes none of them.
func utcTime(s string) bool {
	const whole = len("2006-01-02T15:04:05")
	if len(s) < whole+1 || s[len(s)-1] != 'Z' {
		return false
	}
	for i := 0; i < whole; i++ {
		var ok bool
		switch i {
		case 4, 7:
			ok = s[i] == '-'
		case 10:
			ok = s[i] == 'T'
		case 13, 16:
			ok = s[i] == ':'
		default:
			ok = '0' <= s[i] && s[i] <= '9'
		}
		if !ok {
			return false
		}
	}
	if frac := s[whole : len(s)-1]; frac != "" {
		if len(frac) < 2 || len(frac) > 10 || frac[0] != '.' {
			return false
		}
		for i := 1; i < len(frac); i++ {
			if frac[i] < '0' || frac[i] > '9' {
				return false
			}
		}
	}
	// The shape is fixed; time.Parse checks the ranges and the calendar.
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func compareProductKeys(a, b ProductPublicKey) int {
	if c := cmp.Compare(a.Product, b.Product); c != 0 {
		return c
	}
	return cmp.Compare(a.Epoch, b.Epoch)
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// MarshalKeyBundle returns the bundle as the file the user downloads:
// 2-space indented JSON with a trailing newline. It sorts a copy of the
// product keys, rewrites created_at in UTC to the second, and refuses a
// bundle that Validate refuses, so whatever it writes, ParseKeyBundle reads.
func MarshalKeyBundle(b KeyBundle) ([]byte, error) {
	b.ProductKeys = slices.Clone(b.ProductKeys)
	slices.SortFunc(b.ProductKeys, compareProductKeys)
	t, err := time.Parse(time.RFC3339, b.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: created_at", ErrBundle)
	}
	b.CreatedAt = t.UTC().Truncate(time.Second).Format(time.RFC3339)
	if err := b.Validate(); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	return append(out, '\n'), nil
}

// ParseKeyBundle reads a key bundle strictly: at most 64 KiB holding one JSON
// object with exactly the members of section 11.9, each once and spelled
// exactly (after unescaping), each of its own JSON type, then Validate. It
// opens nothing.
func ParseKeyBundle(data []byte) (*KeyBundle, error) {
	if len(data) > maxKeyBundleLen {
		return nil, fmt.Errorf("%w: over %d bytes", ErrBundle, maxKeyBundleLen)
	}
	m, err := readObject(data, bundleMembers...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	var b KeyBundle
	strs := []struct {
		name string
		dst  *string
	}{
		{"format", &b.Format}, {"issuer", &b.Issuer}, {"sub", &b.Sub}, {"email", &b.Email},
		{"kdf_salt", &b.KDFSalt}, {"password_wrap", &b.PasswordWrap},
		{"recovery_wrap", &b.RecoveryWrap}, {"created_at", &b.CreatedAt},
	}
	for _, f := range strs {
		if *f.dst, err = jsonString(m[f.name]); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrBundle, f.name, err)
		}
	}
	ints := []struct {
		name string
		dst  *int
	}{{"version", &b.Version}, {"account_key_epoch", &b.AccountKeyEpoch}}
	for _, f := range ints {
		if *f.dst, err = smallInt(m[f.name]); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrBundle, f.name, err)
		}
	}
	if b.KDF, err = readKDF(m["kdf"]); err != nil {
		return nil, fmt.Errorf("%w: kdf: %w", ErrBundle, err)
	}
	keys, err := jsonArray(m["product_keys"])
	if err != nil {
		return nil, fmt.Errorf("%w: product_keys: %w", ErrBundle, err)
	}
	for _, raw := range keys {
		pk, err := readProductPublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: product_keys: %w", ErrBundle, err)
		}
		b.ProductKeys = append(b.ProductKeys, pk)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// smallInt reads an integer that fits the protocol's range, [-2^31, 2^31).
// Range rules of each field come later; this only keeps int conversion
// exact on every platform.
func smallInt(raw json.RawMessage) (int, error) {
	n, err := jsonInt(raw)
	if err != nil {
		return 0, err
	}
	if n < -MaxEpoch-1 || n > MaxEpoch {
		return 0, errType
	}
	return int(n), nil
}

func readKDF(raw json.RawMessage) (KDF, error) {
	var k KDF
	m, err := readObject(bytes.TrimSpace(raw), "alg", "m", "t", "p")
	if err != nil {
		return k, err
	}
	if k.Alg, err = jsonString(m["alg"]); err != nil {
		return k, err
	}
	for _, f := range []struct {
		name string
		dst  *uint32
	}{{"m", &k.M}, {"t", &k.T}, {"p", &k.P}} {
		n, err := jsonInt(m[f.name])
		if err != nil {
			return k, err
		}
		// Out of uint32 range is out of the KDF bounds; Check reports it.
		if n < 0 || n > 1<<32-1 {
			n = 0
		}
		*f.dst = uint32(n)
	}
	return k, nil
}

func readProductPublicKey(raw json.RawMessage) (ProductPublicKey, error) {
	var pk ProductPublicKey
	m, err := readObject(bytes.TrimSpace(raw), "product", "epoch", "pub")
	if err != nil {
		return pk, err
	}
	if pk.Product, err = jsonString(m["product"]); err != nil {
		return pk, err
	}
	if pk.Epoch, err = smallInt(m["epoch"]); err != nil {
		return pk, err
	}
	if pk.Pub, err = jsonString(m["pub"]); err != nil {
		return pk, err
	}
	return pk, nil
}

// binding is what the bundle's wraps are bound to.
func (b *KeyBundle) binding() Binding { return Binding{Sub: b.Sub, Epoch: b.AccountKeyEpoch} }

// CheckProductKeys derives every listed product key from root and compares
// its public key with the listed one, wrapping ErrProductKey on the first
// mismatch. A reader must pass it before using any product key (section
// 11.9).
func (b *KeyBundle) CheckProductKeys(root []byte) error {
	for _, pk := range b.ProductKeys {
		want, err := DecodeB64(pk.Pub, KeyLen)
		if err != nil {
			return fmt.Errorf("%w: %s is not a 32-byte key", ErrProductKey, ProductKeyID(pk.Product, pk.Epoch))
		}
		sk, pub, err := ProductKey(root, pk.Product, pk.Epoch)
		clear(sk)
		if err != nil {
			return err
		}
		if !bytes.Equal(pub, want) {
			return fmt.Errorf("%w: %s does not match the root", ErrProductKey, ProductKeyID(pk.Product, pk.Epoch))
		}
	}
	return nil
}

// OpenKeyBundle parses a bundle, derives the password keys under its KDF
// parameters, opens the password wrap and checks every product key against
// the root. It returns the root, which the caller clears, and the bundle.
//
// The order is fixed, so a bundle with several defects fails the same way
// everywhere: the bundle (ErrBundle, or ErrKDFPolicy for its parameters),
// then the password profile, then the wrap (ErrWrap: a wrong password, or a
// bundle whose sub or epoch was changed), then the product keys
// (ErrProductKey).
func OpenKeyBundle(data []byte, password string) ([]byte, *KeyBundle, error) {
	b, err := ParseKeyBundle(data)
	if err != nil {
		return nil, nil, err
	}
	salt, err := DecodeB64(b.KDFSalt, SaltLen)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: kdf_salt", ErrBundle)
	}
	keys, err := DerivePasswordKeys(password, b.KDF, salt)
	if err != nil {
		return nil, nil, err
	}
	defer keys.Zero()
	return b.open(WrapPassword, b.PasswordWrap, keys.Wrap[:])
}

// OpenKeyBundleWithRecoveryCode is OpenKeyBundle with the recovery code, in
// any spelling CanonicalRecoveryCode accepts, instead of the password. A
// malformed code wraps ErrRecoveryCode; a wrong one, ErrWrap.
func OpenKeyBundleWithRecoveryCode(data []byte, code string) ([]byte, *KeyBundle, error) {
	b, err := ParseKeyBundle(data)
	if err != nil {
		return nil, nil, err
	}
	keys, err := DeriveRecovery(code)
	if err != nil {
		return nil, nil, err
	}
	defer keys.Zero()
	return b.open(WrapRecovery, b.RecoveryWrap, keys.Wrap[:])
}

func (b *KeyBundle) open(kind WrapKind, wrapText string, key []byte) ([]byte, *KeyBundle, error) {
	wrap, err := DecodeB64(wrapText, WrapLen)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s_wrap", ErrBundle, kind)
	}
	root, err := Unwrap(kind, key, wrap, b.binding())
	if err != nil {
		return nil, nil, err
	}
	if err := b.CheckProductKeys(root); err != nil {
		clear(root)
		return nil, nil, err
	}
	return root, b, nil
}
