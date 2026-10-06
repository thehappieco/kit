package passkey_test

import (
	"bytes"
	"testing"

	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/wappie"
)

// EndsInANumber is the WHATWG checker step by step: one trailing empty part
// is dropped, the last part ends in a number when it is all ASCII digits or
// the IPv4 number parser takes it (radix 16 after "0x" or "0X", radix 8
// after a leading "0" of two or more code points, an empty rest being zero).
func TestEndsInANumber(t *testing.T) {
	for _, s := range []string{
		"0", "1", "127.0.0.1", "id.123", "1.2.3.4.", "id.09", "0x", "0X", "0x.", "id.0x", "0x.0x", "0x7f000001", "0X7F000001",
		"id.0xff", "x.0XFF", "1.2.3.0x4", "id.0x1.", "id.thehappie.0x100000000", "a.0x00000000000000000000001", "07", "0.017",
	} {
		if !passkey.EndsInANumber(s) {
			t.Errorf("%q does not end in a number", s)
		}
	}
	for _, s := range []string{
		"", ".", "..", "a..", "id.0x1..", "id.thehappie.co", "0x7f000001.thehappie.co", "id.0x1g", "0x1g", "id.0x0x",
		"id.0xabc-def", "id.00x1", "id.1e3", "id.0b1", "id.x7f", "1.2.3.4a", "x0", "0xg", "1.2.3.4 ", " 1", "1\x00", "١", "１",
	} {
		if passkey.EndsInANumber(s) {
			t.Errorf("%q ends in a number", s)
		}
	}
}

// The generic scheme checks no spelling of the relying party id (SPEC
// section 7): an id that ends in a number gives a salt and a key, and its
// wrap opens. The profile or the product refuses such an id where it is
// configured.
func TestTheSchemeDoesNotRefuseAnIDThatEndsInANumber(t *testing.T) {
	p := wappie.Passkey()
	prf, key := bytes.Repeat([]byte{0x5a}, passkey.PRFLen), bytes.Repeat([]byte{0x33}, passkey.KeyLen)
	for _, rp := range []string{"0x7f000001", "127.0.0.1"} {
		if salt := passkey.PRFSalt(p, rp); salt == ([32]byte{}) {
			t.Fatalf("%q: no salt", rp)
		}
		env, err := passkey.Wrap(p, key, prf, rp, []byte("aad"))
		if err != nil {
			t.Fatalf("%q: %v", rp, err)
		}
		if got, err := passkey.Unwrap(p, env, prf, rp, []byte("aad")); err != nil || !bytes.Equal(got, key) {
			t.Fatalf("%q: %v", rp, err)
		}
	}
}
