package platform_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/platform"
)

// The platform's vectors of part 3 (SPEC section 11.16), read unchanged as
// the other runners of vectors_test.go read theirs: every output byte for
// byte, every must-fail case refused with exactly its error name, and the
// counts the file was captured with.

// TestPlatformVectorsPasskey runs passkey.json. A good case gives its salt,
// key, AAD and wrap, the wrap twice from its recorded nonce (by Wrap under
// k_pk and by NewPasskeyWrap from the PRF output), opens back to its root,
// and is section 7 with PasskeyProfile on the root wrap of section 11.5: the
// generic packages derive the same salt and key and open the same wrap. A
// must-fail case is refused at the step its op names, salt, key or open,
// with wrap and nothing returned.
func TestPlatformVectorsPasskey(t *testing.T) {
	counts := map[string]int{}
	for _, c := range vectest.Platform[vectest.PasskeyCase](t, "passkey") {
		counts[c.Op+"/"+c.Error]++
		t.Run(c.CaseName(), func(t *testing.T) {
			// A missing rp_id is not the empty one, which is a case of its
			// own (#salt/an empty relying party id).
			if c.RPID == nil {
				t.Fatal("a case without rp_id")
			}
			rpID := *c.RPID
			if c.Error != "" && (c.Root != "" || c.Nonce != "" || c.PRFSalt != "" || c.KPK != "" || c.AAD != "") {
				t.Fatal("a must-fail case with an output")
			}
			b := platform.Binding{Sub: c.Sub, Epoch: c.Epoch, RPID: rpID, CredentialID: c.CredentialID}
			switch {
			case c.Op == "" && c.Error == "":
				if c.PRF == nil {
					t.Fatal("a good case without a PRF output")
				}
				goodPasskeyVector(t, c, b)
			case c.Op == vectest.PasskeyOpSalt && c.Error != "":
				if c.PRF != nil || c.Wrap != "" || c.Sub != "" || c.Epoch != 0 || c.CredentialID != "" {
					t.Fatal("a salt case with more than a relying party id")
				}
				salt, err := platform.PRFSalt(rpID)
				outcome(t, err, c.Error)
				if salt != nil || platform.ValidRPID(rpID) {
					t.Fatal("a refused relying party id has a salt")
				}
				// An id refused at the salt has no key either, whatever the
				// PRF output.
				key, err := platform.PasskeyWrapKey(testBytes(platform.PRFOutputLen, 0x5a), rpID)
				outcome(t, err, c.Error)
				if key != nil {
					t.Fatal("a refused relying party id gave a key")
				}
			case c.Op == vectest.PasskeyOpKey && c.Error != "":
				if c.PRF == nil || c.Wrap != "" || c.Sub != "" || c.Epoch != 0 || c.CredentialID != "" {
					t.Fatal("a key case needs a PRF output and nothing of an account")
				}
				key, err := platform.PasskeyWrapKey(b64(t, *c.PRF), rpID)
				outcome(t, err, c.Error)
				if key != nil {
					t.Fatal("a refusal gave a key")
				}
			case c.Op == vectest.PasskeyOpOpen && c.Error != "":
				if c.PRF == nil || c.Wrap == "" || c.Sub == "" || c.CredentialID == "" {
					t.Fatal("an open case needs a PRF output, a wrap and its binding")
				}
				root, err := platform.OpenPasskeyWrap(b64(t, *c.PRF), b64(t, c.Wrap), b)
				outcome(t, err, c.Error)
				if root != nil {
					t.Fatal("a refusal returned a root")
				}
			default:
				t.Fatal("a case is good without an op, or must fail with op salt, key or open")
			}
		})
	}
	want := map[string]int{"/": 9, "salt/wrap": 16, "key/wrap": 6, "open/wrap": 13}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("op/error counts %v, want %v", counts, want)
	}
}

func goodPasskeyVector(t *testing.T, c vectest.PasskeyCase, b platform.Binding) {
	t.Helper()
	prf, root, nonce := b64(t, *c.PRF), b64(t, c.Root), b64(t, c.Nonce)
	if !platform.ValidRPID(b.RPID) {
		t.Fatal("the relying party id is refused")
	}
	salt, err := platform.PRFSalt(b.RPID)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "prf_salt", platform.EncodeB64(salt), c.PRFSalt)
	key, err := platform.PasskeyWrapKey(prf, b.RPID)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "k_pk", platform.EncodeB64(key), c.KPK)
	aad, err := platform.WrapAAD(platform.WrapPasskey, b)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "aad", string(aad), c.AAD)
	under, err := platform.Wrap(bytes.NewReader(nonce), platform.WrapPasskey, key, root, b)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "the wrap under k_pk", platform.EncodeB64(under), c.Wrap)
	w, err := platform.NewPasskeyWrap(bytes.NewReader(nonce), prf, root, b)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "wrap", platform.EncodeB64(w), c.Wrap)
	if err := platform.CheckWrapShape(platform.WrapPasskey, w); err != nil {
		t.Fatal("the server refuses the wrap")
	}
	opened, err := platform.OpenPasskeyWrap(prf, w, b)
	if err != nil {
		t.Fatalf("does not open: %s", platform.ErrorCode(err))
	}
	same(t, "root", platform.EncodeB64(opened), c.Root)

	// A fresh wrap draws its own nonce and opens alike.
	fresh, err := platform.NewPasskeyWrap(nil, prf, root, b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fresh, w) {
		t.Fatal("a fresh wrap repeats the vector's nonce")
	}
	if again, err := platform.OpenPasskeyWrap(prf, fresh, b); err != nil || !bytes.Equal(again, root) {
		t.Fatal("a fresh wrap does not open")
	}

	// Section 7 with the platform's passkey profile is the same scheme, and
	// its envelope with the header 0x01 0x03 is the root wrap of section
	// 11.5: the generic packages give the same salt and key, and open the
	// same bytes to the same root.
	p := platform.PasskeyProfile()
	gsalt := passkey.PRFSalt(p, b.RPID)
	same(t, "passkey.PRFSalt", platform.EncodeB64(gsalt[:]), c.PRFSalt)
	gkey, err := passkey.Key(p, prf, b.RPID)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "passkey.Key", platform.EncodeB64(gkey), c.KPK)
	gopened, err := passkey.Unwrap(p, w, prf, b.RPID, aad)
	if err != nil {
		t.Fatal("passkey.Unwrap does not open the wrap")
	}
	same(t, "passkey.Unwrap", platform.EncodeB64(gopened), c.Root)
	aopened, stale, err := account.Unwrap(platform.RootWrapProfile(platform.WrapPasskey), key, w, aad)
	if err != nil || stale {
		t.Fatal("account.Unwrap does not open the wrap")
	}
	same(t, "account.Unwrap", platform.EncodeB64(aopened), c.Root)
}

// TestPlatformVectorsClientExtensions runs client-extensions.json:
// CheckClientExtensions on each exact text accepts it or refuses it with
// exactly client_extensions.
func TestPlatformVectorsClientExtensions(t *testing.T) {
	accepted, refused := 0, 0
	for _, c := range vectest.Platform[vectest.ClientExtensionsCase](t, "client-extensions") {
		if c.Error == "" {
			accepted++
		} else {
			refused++
		}
		t.Run(c.CaseName(), func(t *testing.T) {
			if c.ClientExtensionResults == nil {
				t.Fatal("a case without client_extension_results")
			}
			if c.Error != "" && c.Error != "client_extensions" {
				t.Fatal("a must-fail case with another error name")
			}
			outcome(t, platform.CheckClientExtensions([]byte(*c.ClientExtensionResults)), c.Error)
		})
	}
	if accepted != 9 || refused != 37 {
		t.Errorf("%d accepted and %d refused, want 9 and 37", accepted, refused)
	}
}

// lenientAllowlist is the allowlist as a check over encoding/json's struct
// decoding would apply it, the way WebAuthn libraries read a credential:
// accepted when the decoded value names only the two flags and no PRF
// results. It is here to show what reading the text buys.
func lenientAllowlist(text string) bool {
	var v struct {
		CredProps *struct {
			RK *bool `json:"rk"`
		} `json:"credProps"`
		PRF *struct {
			Enabled *bool           `json:"enabled"`
			Results json.RawMessage `json:"results"`
		} `json:"prf"`
	}
	if json.Unmarshal([]byte(text), &v) != nil {
		return false
	}
	if v.CredProps != nil && v.CredProps.RK == nil {
		return false
	}
	return v.PRF == nil || v.PRF.Enabled != nil && v.PRF.Results == nil
}

// A check over encoding/json, which keeps the last of two members, matches
// names case-insensitively, ignores members it does not know and reads null
// as nothing, passes twelve texts the vectors refuse: repeats, names in
// another case, extensions outside the allowlist, null. CheckClientExtensions
// reads the text and refuses each of them.
func TestTheClientExtensionsVectorsTestTheStrictReader(t *testing.T) {
	var lenient []string
	for _, c := range vectest.Platform[vectest.ClientExtensionsCase](t, "client-extensions") {
		text := *c.ClientExtensionResults
		if c.Error == "" {
			if !lenientAllowlist(text) {
				t.Fatalf("%s: the lenient check refuses an accepted text", c.Name)
			}
			continue
		}
		if lenientAllowlist(text) {
			lenient = append(lenient, c.Name)
		}
		if platform.CheckClientExtensions([]byte(text)) == nil {
			t.Fatalf("%s: accepted", c.Name)
		}
	}
	want := []string{
		"prf null", "prf.enabled in another case", "credProps with another member", "an unknown extension",
		"the hmac-secret extension", "an unknown member next to the allowed ones", "prf in another case",
		"credProps in another case", "a duplicate member", "a duplicate member inside prf",
		"a duplicate member spelled with an escape", "null",
	}
	if !slices.Equal(lenient, want) {
		t.Errorf("the lenient check passes %q, want %q", lenient, want)
	}
}
