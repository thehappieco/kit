package platform_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/platform"
)

// The platform's golden vectors (vectors/platform/id-v1), read unchanged:
// every output must match byte for byte, and every must-fail case must be
// refused with exactly the error name it records. Failure messages name the
// case and the error names only, never the values.

// outcome fails the test unless err matches the case's error name ("" for
// success). An error with no protocol name, such as one of package account
// leaking out, fails as such. It reports whether the case expects success.
func outcome(t *testing.T, err error, want string) bool {
	t.Helper()
	got := platform.ErrorCode(err)
	if err != nil && got == "" {
		t.Fatalf("an error outside the protocol's names: %v", err)
	}
	if got != want {
		if got == "" {
			got = "success"
		}
		if want == "" {
			want = "success"
		}
		t.Fatalf("got %s, want %s", got, want)
	}
	return want == ""
}

func same(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s differs from the vector", what)
	}
}

var b64 = vectest.B64URL

var wrapKinds = map[string]platform.WrapKind{
	"password": platform.WrapPassword,
	"recovery": platform.WrapRecovery,
	"passkey":  platform.WrapPasskey,
}

// wtf8 encodes UTF-16 code units as a lax encoder would: pairs as one code
// point, lone surrogates as their own three bytes. It checks that the two
// forms of an ill-formed password case are one input.
func wtf8(units []uint16) []byte {
	var out []byte
	for i := 0; i < len(units); i++ {
		r := rune(units[i])
		if utf16.IsSurrogate(r) && i+1 < len(units) {
			if pair := utf16.DecodeRune(r, rune(units[i+1])); pair != 0xfffd {
				r = pair
				i++
			}
		}
		u := uint32(r)
		switch {
		case u < 0x80:
			out = append(out, byte(u))
		case u < 0x800:
			out = append(out, 0xc0|byte(u>>6), 0x80|byte(u&0x3f))
		case u < 0x10000:
			out = append(out, 0xe0|byte(u>>12), 0x80|byte(u>>6&0x3f), 0x80|byte(u&0x3f))
		default:
			out = append(out, 0xf0|byte(u>>18), 0x80|byte(u>>12&0x3f), 0x80|byte(u>>6&0x3f), 0x80|byte(u&0x3f))
		}
	}
	return out
}

func TestPlatformVectorsPasswordProfile(t *testing.T) { runPasswordProfile(t, "password-profile") }

// password-stream-safe.json holds the platform's cases of the run rule of
// section 11.2, step 2, in the members of password-profile.json.
func TestPlatformVectorsPasswordStreamSafe(t *testing.T) {
	runPasswordProfile(t, "password-stream-safe")
}

func runPasswordProfile(t *testing.T, kind string) {
	for _, c := range vectest.Platform[vectest.PasswordProfileCase](t, kind) {
		t.Run(c.Name, func(t *testing.T) {
			var password string
			switch {
			case c.Password != nil && c.PasswordUTF8 == "" && len(c.PasswordUTF16) == 0:
				password = *c.Password
			case c.Password == nil && c.PasswordUTF8 != "" && len(c.PasswordUTF16) > 0:
				// Go takes the bytes as its string (invalid UTF-8); both forms
				// must be one input.
				raw := b64(t, c.PasswordUTF8)
				if !bytes.Equal(wtf8(c.PasswordUTF16), raw) {
					t.Fatal("the UTF-16 and UTF-8 forms are not one input")
				}
				password = string(raw)
			default:
				t.Fatal("a case needs a password in exactly one form")
			}
			prepare := platform.PreparePassword
			if c.New {
				prepare = platform.PrepareNewPassword
			}
			got, err := prepare(password)
			if outcome(t, err, c.Error) {
				if c.Prepared == nil {
					t.Fatal("a good case without prepared_b64url")
				}
				same(t, "prepared_b64url", platform.EncodeB64(got), *c.Prepared)
			} else if c.Prepared != nil {
				t.Fatal("a must-fail case with an output")
			}
		})
	}
}

func TestPlatformVectorsKDF(t *testing.T) {
	for _, c := range vectest.Platform[vectest.KDFCase](t, "kdf") {
		t.Run(c.Name, func(t *testing.T) {
			prepared, salt := b64(t, c.Prepared), b64(t, c.Salt)
			keys, err := platform.DerivePassword(prepared, salt, c.KDF)
			if !outcome(t, err, c.Error) {
				return
			}
			same(t, "k_auth", platform.EncodeB64(keys.Auth[:]), c.KAuth)
			same(t, "k_wrap", platform.EncodeB64(keys.Wrap[:]), c.KWrap)
			same(t, "auth_key", keys.AuthKey(), c.AuthKey)
			// The same split through package account, with the platform's
			// profile: SPEC section 6.3 with the platform's labels.
			d, err := account.DerivePrepared(platform.Account(), prepared, salt, c.KDF.Params())
			if err != nil {
				t.Fatal(err)
			}
			same(t, "account's auth key", d.AuthKey, c.AuthKey)
			same(t, "account's wrap key", platform.EncodeB64(d.Wrap), c.KWrap)
		})
	}
}

func TestPlatformVectorsRootWrap(t *testing.T) {
	for _, c := range vectest.Platform[vectest.RootWrapCase](t, "root-wrap") {
		t.Run(c.Name, func(t *testing.T) {
			kind, ok := wrapKinds[c.Kind]
			if !ok {
				t.Fatal("an unknown kind")
			}
			b := platform.Binding{Sub: c.Sub, Epoch: c.Epoch, RPID: c.RPID, CredentialID: c.CredentialID}
			key, wrap := b64(t, c.Key), b64(t, c.Wrap)
			root, err := platform.Unwrap(kind, key, wrap, b)
			if !outcome(t, err, c.Error) {
				if c.Root != "" || c.AAD != "" || c.Nonce != "" {
					t.Fatal("a must-fail case with outputs")
				}
				return
			}
			same(t, "the opened root", platform.EncodeB64(root), c.Root)
			aad, err := platform.WrapAAD(kind, b)
			if err != nil {
				t.Fatal(err)
			}
			same(t, "aad", string(aad), c.AAD)
			again, err := platform.Wrap(bytes.NewReader(b64(t, c.Nonce)), kind, key, b64(t, c.Root), b)
			if err != nil {
				t.Fatal(err)
			}
			same(t, "wrap", platform.EncodeB64(again), c.Wrap)
			// The envelope of SPEC section 6.5 with the header 0x01 || kind:
			// package account opens it with the platform's per-kind profile.
			opened, stale, err := account.Unwrap(platform.RootWrapProfile(kind), key, wrap, aad)
			if err != nil || stale {
				t.Fatalf("account.Unwrap: %v", err)
			}
			same(t, "account's opened root", platform.EncodeB64(opened), c.Root)
		})
	}
}

func TestPlatformVectorsRecoveryCode(t *testing.T) {
	for _, c := range vectest.Platform[vectest.RecoveryCodeCase](t, "recovery-code") {
		t.Run(c.Name, func(t *testing.T) {
			var code string
			var err error
			switch {
			case c.Bytes != "" && c.Input == nil:
				code, err = platform.RecoveryCodeFromBytes(b64(t, c.Bytes))
			case c.Input != nil && c.Bytes == "":
				code, err = platform.CanonicalRecoveryCode(*c.Input)
			default:
				t.Fatal("a case needs exactly one of bytes and input")
			}
			if !outcome(t, err, c.Error) {
				return
			}
			same(t, "canonical", code, c.Canonical)
			display, err := platform.DisplayRecoveryCode(code)
			if err != nil {
				t.Fatal(err)
			}
			same(t, "display", display, c.Display)
			// What was typed, the canonical form and the display form derive
			// the same keys, here and through package account.
			forms := []string{code, display}
			if c.Input != nil {
				forms = append(forms, *c.Input)
			}
			for _, from := range forms {
				keys, err := platform.DeriveRecovery(from)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "k_rwrap", platform.EncodeB64(keys.Wrap[:]), c.KRWrap)
				same(t, "recovery_auth", keys.RecoveryAuth(), c.RecoveryAuth)
				k, err := account.RecoveryKey(platform.Account(), from)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "account's recovery key", platform.EncodeB64(k), c.KRWrap)
				proof, err := account.RecoveryProof(platform.Account(), from)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "account's recovery proof", proof, c.RecoveryAuth)
			}
		})
	}
}

func TestPlatformVectorsProductKey(t *testing.T) {
	for _, c := range vectest.Platform[vectest.ProductKeyCase](t, "product-key") {
		t.Run(c.Name, func(t *testing.T) {
			sk, pub, err := platform.ProductKey(b64(t, c.Root), c.Product, c.Epoch)
			if !outcome(t, err, c.Error) {
				return
			}
			same(t, "sk", platform.EncodeB64(sk), c.SK)
			same(t, "pub", platform.EncodeB64(pub), c.Pub)
			same(t, "product_key_id", platform.ProductKeyID(c.Product, c.Epoch), c.ProductKeyID)
			if err := platform.CheckPublicKey(pub); err != nil {
				t.Fatalf("the server refuses a derived key: %v", err)
			}
			priv, err := hpke.ParsePrivateKey(sk)
			if err != nil {
				t.Fatal(err)
			}
			hpub, err := priv.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			same(t, "hpke's public key", platform.EncodeB64(hpub.Bytes()), c.Pub)
		})
	}
}

func TestPlatformVectorsVerifier(t *testing.T) {
	for _, c := range vectest.Platform[vectest.VerifierCase](t, "verifier") {
		t.Run(c.Name, func(t *testing.T) {
			switch {
			case c.KAuth != "" && c.RProof == "":
				v, err := platform.AuthVerifier(c.Sub, b64(t, c.KAuth))
				if outcome(t, err, c.Error) {
					same(t, "auth_verifier", platform.EncodeB64(v[:]), c.AuthVerifier)
					if !platform.VerifierMatches(b64(t, c.AuthVerifier), v) {
						t.Fatal("the verifier does not match itself")
					}
				}
			case c.RProof != "" && c.KAuth == "":
				v, err := platform.RecoveryVerifier(c.Sub, b64(t, c.RProof))
				if outcome(t, err, c.Error) {
					same(t, "recovery_verifier", platform.EncodeB64(v[:]), c.RecoveryVerifier)
				}
			default:
				t.Fatal("a case needs exactly one of k_auth and r_proof")
			}
		})
	}
}

func TestPlatformVectorsEmail(t *testing.T) {
	for _, c := range vectest.Platform[vectest.EmailCase](t, "email") {
		t.Run(c.Name, func(t *testing.T) {
			got, err := platform.NormalizeEmail(c.Input)
			if outcome(t, err, c.Error) {
				same(t, "email_norm", got, c.EmailNorm)
				if again, err := platform.NormalizeEmail(got); err != nil || again != got {
					t.Fatal("a normalised address does not normalise to itself")
				}
			}
		})
	}
}

func TestPlatformVectorsKeyBundle(t *testing.T) {
	for _, c := range vectest.Platform[vectest.KeyBundleCase](t, "key-bundle") {
		t.Run(c.Name, func(t *testing.T) {
			var data []byte
			switch {
			case len(c.Bundle) > 0 && c.BundleText == nil:
				data = c.Bundle
			case c.BundleText != nil && len(c.Bundle) == 0:
				data = []byte(*c.BundleText)
			default:
				t.Fatal("a case needs exactly one of bundle and bundle_text")
			}
			var root []byte
			var b *platform.KeyBundle
			var err error
			switch {
			case c.Password != nil && c.RecoveryCode == nil:
				root, b, err = platform.OpenKeyBundle(data, *c.Password)
			case c.RecoveryCode != nil && c.Password == nil:
				root, b, err = platform.OpenKeyBundleWithRecoveryCode(data, *c.RecoveryCode)
			default:
				t.Fatal("a case needs exactly one of password and recovery_code")
			}
			if !outcome(t, err, c.Error) {
				return
			}
			same(t, "root", platform.EncodeB64(root), c.Root)
			// What the reader parsed, written again, is the bundle it read,
			// value for value. MarshalKeyBundle keeps whole seconds only, so a
			// fractional created_at is left out of the comparison.
			again, err := platform.MarshalKeyBundle(*b)
			if err != nil {
				t.Fatal(err)
			}
			x, y := jsonValue(t, again), jsonValue(t, data)
			if strings.Contains(b.CreatedAt, ".") {
				delete(x, "created_at")
				delete(y, "created_at")
			}
			if !reflect.DeepEqual(x, y) {
				t.Fatal("MarshalKeyBundle does not reproduce the bundle")
			}
		})
	}
}

// jsonValue decodes a JSON object with exact numbers, for comparing two
// texts value for value.
func jsonValue(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatal("not a JSON object")
	}
	return v
}

func TestPlatformVectorsPKCE(t *testing.T) {
	for _, c := range vectest.Platform[vectest.PKCECase](t, "pkce") {
		t.Run(c.Name, func(t *testing.T) {
			got, err := platform.PKCEChallenge(c.CodeVerifier)
			if outcome(t, err, c.Error) {
				same(t, "code_challenge", got, c.CodeChallenge)
			} else if c.CodeChallenge != "" {
				t.Fatal("a must-fail case with an output")
			}
		})
	}
}

// keyDeliveryBinding is the binding a key-delivery case names, its pk_p
// decoded at whatever length it has.
func keyDeliveryBinding(t *testing.T, c vectest.KeyDeliveryCase) platform.KeyDeliveryBinding {
	return platform.KeyDeliveryBinding{
		Issuer: c.Iss, ClientID: c.ClientID, RedirectURI: c.RedirectURI, Sub: c.Sub,
		ProductKeyID: c.ProductKeyID, ProductKey: b64(t, c.PKP),
		CodeChallenge: c.CodeChallenge, Nonce: c.Nonce,
	}
}

// x25519Public is X25519(priv, 9).
func x25519Public(t *testing.T, priv []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// The key-delivery vectors. A good case is opened, its AAD and akd_pub
// recomputed, and its blob sealed again byte for byte under its recorded
// ephemeral key through internal/forge (tests only: no function of the kit
// takes an ephemeral key); a fresh SealProductKey of the same inputs opens
// alike. An "open" case is refused by OpenProductKey and a "seal" case by
// SealProductKey, each with exactly its error and nothing returned.
func TestPlatformVectorsKeyDelivery(t *testing.T) {
	counts := map[string]int{}
	for _, c := range vectest.Platform[vectest.KeyDeliveryCase](t, "key-delivery") {
		counts["op "+c.Op]++
		if c.Error != "" {
			counts[c.Error]++
		}
		t.Run(c.CaseName(), func(t *testing.T) {
			b := keyDeliveryBinding(t, c)
			switch {
			case c.Error == "" && c.Op == "":
				sk, pub, err := platform.ProductKey(b64(t, c.Root), c.Product, c.Epoch)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "pk_p", platform.EncodeB64(pub), c.PKP)
				same(t, "product_key_id", platform.ProductKeyID(c.Product, c.Epoch), c.ProductKeyID)
				aad, err := platform.KeyDeliveryAAD(b)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "aad", string(aad), c.AAD)
				akdPriv, akdPub := b64(t, c.AKDPriv), b64(t, c.AKDPub)
				same(t, "akd_pub", platform.EncodeB64(x25519Public(t, akdPriv)), c.AKDPub)
				if err := platform.CheckPublicKey(akdPub); err != nil {
					t.Fatalf("the server refuses akd_pub: %v", err)
				}
				sealed := b64(t, c.AKDSealed)
				same(t, "enc", platform.EncodeB64(sealed[:hpke.EncLen]), platform.EncodeB64(x25519Public(t, b64(t, c.EphPriv))))
				got, err := platform.OpenProductKey(akdPriv, sealed, b)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				same(t, "the opened sk_p", platform.EncodeB64(got), platform.EncodeB64(sk))
				replay, err := forge.SealBase(akdPub, b64(t, c.EphPriv), []byte(platform.KeyDeliveryInfo), aad, sk)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "akd_sealed (replayed)", platform.EncodeB64(replay), c.AKDSealed)
				fresh, err := platform.SealProductKey(nil, akdPub, sk, b)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(fresh, sealed) {
					t.Fatal("a fresh seal repeats the vector's ephemeral key")
				}
				if got, err := platform.OpenProductKey(akdPriv, fresh, b); err != nil || !bytes.Equal(got, sk) {
					t.Fatalf("a fresh seal does not open: %v", err)
				}
			case c.Error != "" && c.Op == vectest.KeyDeliveryOpOpen:
				if c.Root != "" || c.EphPriv != "" || c.AAD != "" || c.AKDPub != "" {
					t.Fatal("an open case with the seal's inputs")
				}
				got, err := platform.OpenProductKey(b64(t, c.AKDPriv), b64(t, c.AKDSealed), b)
				outcome(t, err, c.Error)
				if got != nil {
					t.Fatal("a refusal returned key material")
				}
			case c.Error != "" && c.Op == vectest.KeyDeliveryOpSeal:
				if c.AKDPriv != "" || c.AKDSealed != "" || c.EphPriv != "" || c.AAD != "" {
					t.Fatal("a seal case with the open's inputs or outputs")
				}
				sk, pub, err := platform.ProductKey(b64(t, c.Root), c.Product, c.Epoch)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "pk_p", platform.EncodeB64(pub), c.PKP)
				same(t, "product_key_id", platform.ProductKeyID(c.Product, c.Epoch), c.ProductKeyID)
				got, err := platform.SealProductKey(nil, b64(t, c.AKDPub), sk, b)
				outcome(t, err, c.Error)
				if got != nil {
					t.Fatal("a refusal returned a blob")
				}
			default:
				t.Fatal("a case is good without an op, or must fail with op open or seal")
			}
		})
	}
	want := map[string]int{"op ": 9, "op open": 39, "op seal": 25, "key_delivery": 61, "product_key": 3}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("counts %v, want %v", counts, want)
	}
}

// The vector whose sealer spelled enc with bit 255 set, in the blob and in
// the KEM context alike, opens under RFC 9180 (crypto/hpke through package
// hpke) to the good case's key; only rule (a) of section 11.12 refuses it.
func TestTheAliasedEncVectorTestsTheCanonicalCheck(t *testing.T) {
	var good, aliased vectest.KeyDeliveryCase
	for _, c := range vectest.Platform[vectest.KeyDeliveryCase](t, "key-delivery") {
		switch c.CaseName() {
		case "wappie-app in production":
			good = c
		case "open/enc spelled with bit 255 set by the sealer, in the blob and in the KEM context alike":
			aliased = c
		}
	}
	if good.Name == "" || aliased.Name == "" {
		t.Fatal("the cases are missing")
	}
	b := keyDeliveryBinding(t, aliased)
	aad, err := platform.KeyDeliveryAAD(b)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "aad", string(aad), good.AAD)
	sealed := b64(t, aliased.AKDSealed)
	if sealed[31]&0x80 == 0 {
		t.Fatal("enc has bit 255 clear")
	}
	priv, err := hpke.ParsePrivateKey(b64(t, aliased.AKDPriv))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := hpke.Open(priv, sealed[:hpke.EncLen], []byte(platform.KeyDeliveryInfo), aad, sealed[hpke.EncLen:])
	if err != nil {
		t.Fatalf("RFC 9180 does not open the aliased blob, so the case tests nothing: %v", err)
	}
	sk, _, err := platform.ProductKey(b64(t, good.Root), good.Product, good.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "the aliased blob's plaintext", platform.EncodeB64(pt), platform.EncodeB64(sk))
	if got, err := platform.OpenProductKey(b64(t, aliased.AKDPriv), sealed, b); platform.ErrorCode(err) != "key_delivery" || got != nil {
		t.Fatalf("OpenProductKey: %v, want key_delivery", err)
	}
}
