package platform

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/thehappieco/kit/passkey"
)

// Passkeys with PRF (SPEC section 11.16, the platform's decision 0008). A
// passkey whose authenticator supports the WebAuthn PRF extension gives the
// id. page a 32-byte secret, different for every credential, from which the
// page derives a key that wraps the account root:
//
//	PRF_SALT = SHA-256(UTF-8("thehappie-id/v1/passkey-prf|" + rp_id))      32 bytes
//	prf      = the PRF output for eval.first = PRF_SALT                    32 bytes
//	K_pk     = HKDF-SHA256(IKM = prf, salt = UTF-8(rp_id), info = "thehappie-id/v1/passkey/wrap", L = 32)
//	wrap     = the root wrap of section 11.5, kind 0x03, under K_pk, with
//	           AAD = ["thehappie-id/root-wrap",1,"passkey",sub,epoch,rp_id,credential_id]
//
// This is section 7, the kit's passkey PRF wrap, with PasskeyProfile: the
// salt and the key are passkey.PRFSalt and passkey.Key with that profile,
// and passkey.Wrap with it and WrapAAD's AAD writes the same 62 bytes for
// the same nonce. The wrap is sealed and opened here by Wrap and Unwrap,
// which add the self-test of section 11.5 and the one error name.
//
// The rule it enforces: a passkey wrap opens only with the PRF output of the
// credential it names, only on the relying party it names, and only for the
// account and epoch it was made for. The relying party is in the PRF salt,
// in the HKDF salt and in the AAD, and has one spelling (ValidRPID); the
// credential is in the PRF output itself and in the AAD.
//
// The PRF salt is public and one per relying party, so a discoverable login
// can ask for the PRF before anyone knows which account will answer. What
// stays secret is the PRF output, which never leaves the page: the server
// only ever runs PRFSalt, to put it in the options it sends, and
// CheckClientExtensions, to refuse a credential that carries an output. The
// WebAuthn ceremony itself is the platform's.
//
// Taken from the platform's internal/crypto/idcrypto/passkey.go at b5d9f69,
// with idcrypto's names and signatures.

const (
	// PRFOutputLen is the length of the PRF output the passkey wrap key is
	// derived from: the WebAuthn PRF extension's results.first.
	PRFOutputLen = 32
	// PRFSaltLen is the length of the PRF salt, a SHA-256 digest.
	PRFSaltLen = sha256.Size

	// maxRPIDLen bounds a relying party id, a domain name.
	maxRPIDLen = 253
	// maxRPIDLabelLen bounds one label of a relying party id.
	maxRPIDLabelLen = 63

	// labelPasskeyPRF is hashed with the relying party id into the PRF salt.
	// The '|' cannot occur in a relying party id, so the prefix ends where
	// the id begins.
	labelPasskeyPRF = "thehappie-id/v1/passkey-prf|"
	// labelPasskeyWrap is the HKDF info of K_pk.
	labelPasskeyWrap = "thehappie-id/v1/passkey/wrap" //nolint:gosec // an HKDF label
)

// PasskeyProfile is the platform's profile for package passkey (SPEC section
// 7): the PRF evaluation prefix "thehappie-id/v1/passkey-prf|", the HKDF info
// of K_pk "thehappie-id/v1/passkey/wrap", and the header of a kind-3 root
// wrap, 0x01 0x03. With it and WrapAAD's AAD, passkey.Wrap and passkey.Unwrap
// seal and open the 62-byte envelope of section 11.5; the functions of this
// file use it for the salt and the key, and seal with Wrap, which self-tests.
// Every call returns a fresh value.
//
// passkey.Wrap with this profile checks neither the relying party id's
// spelling nor that the id it derives the key from is the one in the AAD,
// and it skips the self-test: a passkey wrap is sealed with NewPasskeyWrap,
// which takes the id once for both. The profile is for opening and for
// showing that the two schemes are one.
func PasskeyProfile() passkey.Profile {
	return passkey.Profile{
		EvalPrefix: labelPasskeyPRF,
		WrapInfo:   labelPasskeyWrap,
		Header:     []byte{WrapVersion, byte(WrapPasskey)},
	}
}

// ValidRPID reports whether rpID is a relying party id in its one spelling:
// a domain name of 1 to 253 bytes whose dot-separated labels are each 1 to
// 63 bytes from [a-z0-9-], none starting or ending with '-', that does not
// end in a number as the WHATWG URL Standard's host parser decides it
// (passkey.EndsInANumber). Every such name is the host of an origin as a
// browser serializes it, and the rule leaves out what cannot be the id of a
// relying party: upper case, which a browser never serializes, a port or a
// scheme, which are not part of a host, a trailing dot, and every host a
// browser reads as an IPv4 address or refuses, whose last label is all
// digits or "0x" and zero or more hex digits ("127.0.0.1", "0x7f000001",
// "1.2.3.0x4", "id.0xff"). So "id.thehappie.co" and "id.thehappie.localhost"
// pass, and so do "id.0x1g" and "id.00x1", which a browser keeps as domains;
// "ID.thehappie.co", "id.thehappie.co:443", "https://id.thehappie.co",
// "127.0.0.1" and "id.0xff" do not. Kit v0.4.0 refused only an all-decimal
// last label; the platform's server refuses the rest since its 75b6b94.
//
// The protocol needs one spelling because the relying party id is hashed into
// the PRF salt and the HKDF salt and written into the AAD: a second spelling
// would be a second salt, a second key and a wrap that does not open, with
// nothing to say why. It also catches a server configured with an origin
// where a host belongs. Every spelling it accepts is drawn from the AAD
// alphabet of section 11.1, so WrapAAD accepts it too. It checks a spelling,
// never a list: whether a browser accepts the id for a page's origin is the
// ceremony's concern.
func ValidRPID(rpID string) bool {
	if len(rpID) < 1 || len(rpID) > maxRPIDLen {
		return false
	}
	start := 0
	for i := 0; i <= len(rpID); i++ {
		if i < len(rpID) && rpID[i] != '.' {
			switch c := rpID[i]; {
			case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-':
			default:
				return false
			}
			continue
		}
		label := rpID[start:i]
		if len(label) < 1 || len(label) > maxRPIDLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		start = i + 1
	}
	return !passkey.EndsInANumber(rpID)
}

// PRFSalt returns the public PRF salt of a relying party (section 11.16):
//
//	PRF_SALT = SHA-256(UTF-8("thehappie-id/v1/passkey-prf|" + rp_id))
//
// Every create and every get on id. passes it as prf.eval.first. It refuses,
// wrapping ErrWrap, a relying party id ValidRPID does not accept: the salt
// is the first step towards a passkey wrap, and an id with no wrap key has
// no wrap either.
func PRFSalt(rpID string) ([]byte, error) {
	if !ValidRPID(rpID) {
		return nil, fmt.Errorf("%w: not a relying party id", ErrWrap)
	}
	sum := passkey.PRFSalt(PasskeyProfile(), rpID)
	return sum[:], nil
}

// PasskeyWrapKey derives K_pk, the key of a passkey wrap, from a PRF output
// (section 11.16):
//
//	K_pk = HKDF-SHA256(IKM = prf, salt = UTF-8(rp_id), info = "thehappie-id/v1/passkey/wrap", L = 32)
//
// It refuses, wrapping ErrWrap and before anything is derived, a PRF output
// that is not exactly 32 bytes (an empty or absent result, or results.first
// and results.second run together) and a relying party id ValidRPID does not
// accept. Any 32 bytes are a PRF output, 32 zeros included. The caller
// clears the key; the PRF output is the caller's too.
//
// The key is for opening. Wrap with WrapPasskey and this key does not check
// that the Binding's RPID is rpID: under another id, even another valid one,
// it makes a wrap that passes its self-test and CheckWrapShape and that
// OpenPasskeyWrap never opens. A passkey wrap is sealed with NewPasskeyWrap,
// which takes the relying party id once, from the Binding, for both.
func PasskeyWrapKey(prf []byte, rpID string) ([]byte, error) {
	if len(prf) != PRFOutputLen {
		return nil, fmt.Errorf("%w: a PRF output of %d bytes, not %d", ErrWrap, len(prf), PRFOutputLen)
	}
	if !ValidRPID(rpID) {
		return nil, fmt.Errorf("%w: not a relying party id", ErrWrap)
	}
	key, err := passkey.Key(PasskeyProfile(), prf, rpID)
	if err != nil {
		// Not reachable after the checks above; never package passkey's
		// error, which is not a name of the protocol.
		clear(key)
		return nil, fmt.Errorf("%w: the passkey wrap key could not be derived", ErrWrap)
	}
	return key, nil
}

// NewPasskeyWrap wraps root for the passkey that gave the PRF output prf:
// K_pk from prf and b.RPID, then Wrap with WrapPasskey and b, which self-tests
// the result (section 11.5). Taking the relying party from the binding keeps
// the key and the AAD on the same one. The nonce comes from r (crypto/rand
// when nil; a fixed reader replays a vector). It is the page's registration
// step, for Go code that plays the browser. K_pk is cleared before it
// returns; root and prf are the caller's.
func NewPasskeyWrap(r io.Reader, prf, root []byte, b Binding) ([]byte, error) {
	key, err := PasskeyWrapKey(prf, b.RPID)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return Wrap(r, WrapPasskey, key, root, b)
}

// OpenPasskeyWrap opens a passkey wrap with the PRF output of its credential:
// K_pk from prf and b.RPID, then Unwrap with WrapPasskey and b. Every failure
// is ErrWrap and says no more. K_pk is cleared before it returns; the caller
// clears the returned root.
func OpenPasskeyWrap(prf, wrap []byte, b Binding) ([]byte, error) {
	key, err := PasskeyWrapKey(prf, b.RPID)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return Unwrap(WrapPasskey, key, wrap, b)
}
