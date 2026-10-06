//go:build go1.26

package idvectors

import (
	"bytes"
	"fmt"
	"strings"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// PasskeyCase is one passkey vector (spec 8.2 and 8.5).
//
// A good case has the inputs rp_id, prf (the 32-byte PRF output), root, sub,
// epoch, credential_id (base64url) and nonce, and the outputs: prf_salt, the
// public salt of the relying party; k_pk, the wrap key; the AAD as text; and
// the 62-byte wrap of kind 0x03, which opens back to root.
//
// An error case says in op which step must refuse it, always with "wrap":
//
//   - "salt": PRF_SALT from rp_id, for a relying party id that is not in
//     its one spelling (idcrypto.ValidRPID).
//   - "key": K_pk from prf and rp_id, for a PRF output that is not 32 bytes
//     or a relying party id that is not in its one spelling.
//   - "open": what the page holds after a get (rp_id, prf, sub, epoch,
//     credential_id) and a wrap it must refuse: K_pk from prf and rp_id,
//     then the passkey unwrap, with one thing changed from a good case.
type PasskeyCase struct {
	Name         string  `json:"name"`
	Op           string  `json:"op,omitempty"`
	RPID         string  `json:"rp_id"`
	PRF          *string `json:"prf,omitempty"`
	Root         string  `json:"root,omitempty"`
	Sub          string  `json:"sub,omitempty"`
	Epoch        int     `json:"epoch,omitempty"`
	CredentialID string  `json:"credential_id,omitempty"`
	Nonce        string  `json:"nonce,omitempty"`
	PRFSalt      string  `json:"prf_salt,omitempty"`
	KPK          string  `json:"k_pk,omitempty"`
	AAD          string  `json:"aad,omitempty"`
	Wrap         string  `json:"wrap,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// The ops of passkey error cases.
const (
	PasskeyOpSalt = "salt"
	PasskeyOpKey  = "key"
	PasskeyOpOpen = "open"
)

// The relying parties of spec 8.1, as the vectors use them.
const (
	prodRPID = "id.thehappie.co"
	devRPID  = "id.thehappie.localhost"
)

func passkeyCases() ([]PasskeyCase, error) {
	sub := uuid7("passkey")
	otherSub := uuid7("passkey/another")
	root := seeded("passkey/root", idcrypto.KeyLen)
	prfA := seeded("passkey/prf-a", idcrypto.PRFOutputLen)
	prfB := seeded("passkey/prf-b", idcrypto.PRFOutputLen)
	credA := idcrypto.EncodeB64(seeded("passkey/credential-a", 16))
	credB := idcrypto.EncodeB64(seeded("passkey/credential-b", 32))
	// WebAuthn allows credential ids of up to 1023 bytes.
	credLongest := idcrypto.EncodeB64(seeded("passkey/credential-longest", 1023))
	// 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 bytes, the longest domain name.
	rpLongest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	zero := func(n int) []byte { return make([]byte, n) }

	type good struct {
		name  string
		prf   []byte
		root  []byte
		nonce []byte
		b     idcrypto.Binding
	}
	goods := []good{
		{"a passkey on the production relying party", prfA, root, seeded("passkey/nonce-1", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: prodRPID, CredentialID: credA}},
		{"the same PRF output and credential on the development relying party", prfA, root, seeded("passkey/nonce-2", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: devRPID, CredentialID: credA}},
		{"a second passkey of the same account", prfB, root, seeded("passkey/nonce-3", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: prodRPID, CredentialID: credB}},
		{"a passkey at the largest epoch", prfA, root, seeded("passkey/nonce-4", 12), idcrypto.Binding{Sub: sub, Epoch: idcrypto.MaxEpoch, RPID: prodRPID, CredentialID: credA}},
		{"an all-zero PRF output, root and nonce", zero(32), zero(32), zero(12), idcrypto.Binding{Sub: otherSub, Epoch: 1, RPID: prodRPID, CredentialID: credA}},
		{"a credential id of one byte", prfA, root, seeded("passkey/nonce-5", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: prodRPID, CredentialID: idcrypto.EncodeB64([]byte{0x00})}},
		{"a credential id of 1023 bytes", prfB, root, seeded("passkey/nonce-6", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: prodRPID, CredentialID: credLongest}},
		{"a single-label relying party", prfA, root, seeded("passkey/nonce-7", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: "localhost", CredentialID: credA}},
		{"a relying party of 253 bytes", prfA, root, seeded("passkey/nonce-8", 12), idcrypto.Binding{Sub: sub, Epoch: 1, RPID: rpLongest, CredentialID: credA}},
	}
	var out []PasskeyCase
	wraps := map[string][]byte{}
	for _, g := range goods {
		c, w, err := goodPasskeyCase(g.name, g.prf, g.root, g.nonce, g.b)
		if err != nil {
			return nil, err
		}
		wraps[g.name] = w
		out = append(out, c)
	}

	// Refused relying party ids: the salt cannot be made, nor the key.
	badRPIDs := []struct{ name, rpID string }{
		{"an empty relying party id", ""},
		{"a relying party id in upper case", "ID.thehappie.co"},
		{"a relying party id with a port", prodRPID + ":443"},
		{"an origin instead of a relying party id", "https://" + prodRPID},
		{"a relying party id with a trailing dot", prodRPID + "."},
		{"a relying party id with a leading dot", "." + prodRPID},
		{"a relying party id with an empty label", "id..thehappie.co"},
		{"a label starting with a dash", "-id.thehappie.co"},
		{"a label ending with a dash", "id-.thehappie.co"},
		{"a label of 64 bytes", strings.Repeat("a", 64) + ".thehappie.co"},
		{"a relying party id of 254 bytes", "e" + rpLongest},
		{"an IPv4 address", "127.0.0.1"},
		{"a bracketed IPv6 address", "[::1]"},
		{"an underscore", "id_1.thehappie.co"},
		{"a space", "id thehappie.co"},
		{"a non-ASCII relying party id", "id.th\u00e9happie.co"},
	}
	for _, s := range badRPIDs {
		salt, err := idcrypto.PRFSalt(s.rpID)
		if got := idcrypto.ErrorCode(err); got != "wrap" || salt != nil {
			return nil, mismatch(s.name, got, "wrap")
		}
		out = append(out, PasskeyCase{Name: s.name, Op: PasskeyOpSalt, RPID: s.rpID, Error: "wrap"})
	}

	badKeys := []struct {
		name string
		prf  []byte
		rpID string
	}{
		{"an empty PRF output", []byte{}, prodRPID},
		{"a PRF output of 31 bytes", prfA[:31], prodRPID},
		{"a PRF output of 33 bytes", append(bytes.Clone(prfA), 0x00), prodRPID},
		{"the first and second PRF outputs run together", append(bytes.Clone(prfA), prfB...), prodRPID},
		{"a good PRF output with a relying party id in upper case", prfA, "ID.thehappie.co"},
		{"a good PRF output with an origin instead of a relying party id", prfA, "https://" + prodRPID},
	}
	for _, s := range badKeys {
		key, err := idcrypto.PasskeyWrapKey(s.prf, s.rpID)
		if got := idcrypto.ErrorCode(err); got != "wrap" || key != nil {
			return nil, mismatch(s.name, got, "wrap")
		}
		out = append(out, PasskeyCase{Name: s.name, Op: PasskeyOpKey, RPID: s.rpID, PRF: ptr(idcrypto.EncodeB64(s.prf)), Error: "wrap"})
	}

	w := wraps["a passkey on the production relying party"]
	edit := func(f func([]byte) []byte) []byte { return f(bytes.Clone(w)) }
	flip := func(i int, bit byte) []byte { return edit(func(b []byte) []byte { b[i] ^= bit; return b }) }
	set := func(i int, v byte) []byte { return edit(func(b []byte) []byte { b[i] = v; return b }) }
	base := idcrypto.Binding{Sub: sub, Epoch: 1, RPID: prodRPID, CredentialID: credA}
	with := func(f func(*idcrypto.Binding)) idcrypto.Binding { b := base; f(&b); return b }
	badOpens := []struct {
		name string
		prf  []byte
		b    idcrypto.Binding
		wrap []byte
	}{
		{"another relying party", prfA, with(func(b *idcrypto.Binding) { b.RPID = devRPID }), w},
		{"the development wrap opened on the production relying party", prfA, base, wraps["the same PRF output and credential on the development relying party"]},
		{"another credential id", prfA, with(func(b *idcrypto.Binding) { b.CredentialID = credB }), w},
		{"the PRF output of another credential", prfB, base, w},
		{"another sub", prfA, with(func(b *idcrypto.Binding) { b.Sub = otherSub }), w},
		{"another epoch", prfA, with(func(b *idcrypto.Binding) { b.Epoch = 2 }), w},
		{"a flipped nonce bit", prfA, base, flip(2, 0x01)},
		{"a flipped ciphertext bit", prfA, base, flip(14, 0x01)},
		{"a flipped tag bit", prfA, base, flip(61, 0x80)},
		{"the password kind byte", prfA, base, set(1, byte(idcrypto.WrapPassword))},
		{"version byte 0x02", prfA, base, set(0, 0x02)},
		{"truncated to 61 bytes", prfA, base, w[:61]},
		{"a trailing byte", prfA, base, append(bytes.Clone(w), 0x00)},
	}
	for _, s := range badOpens {
		got, err := idcrypto.OpenPasskeyWrap(s.prf, s.wrap, s.b)
		if code := idcrypto.ErrorCode(err); code != "wrap" || got != nil {
			clear(got)
			return nil, mismatch(s.name, code, "wrap")
		}
		out = append(out, PasskeyCase{
			Name: s.name, Op: PasskeyOpOpen, RPID: s.b.RPID, PRF: ptr(idcrypto.EncodeB64(s.prf)),
			Sub: s.b.Sub, Epoch: s.b.Epoch, CredentialID: s.b.CredentialID,
			Wrap: idcrypto.EncodeB64(s.wrap), Error: "wrap",
		})
	}
	return out, nil
}

// goodPasskeyCase seals root for b under the passkey that gave prf, checks
// that the parts the page computes separately (salt, key, AAD, a wrap under
// that key) agree with NewPasskeyWrap and that the wrap opens, and returns
// the case and the wrap.
func goodPasskeyCase(name string, prf, root, nonce []byte, b idcrypto.Binding) (PasskeyCase, []byte, error) {
	fail := func(err error) (PasskeyCase, []byte, error) {
		return PasskeyCase{}, nil, fmt.Errorf("case %q: %w", name, err)
	}
	salt, err := idcrypto.PRFSalt(b.RPID)
	if err != nil {
		return fail(err)
	}
	key, err := idcrypto.PasskeyWrapKey(prf, b.RPID)
	if err != nil {
		return fail(err)
	}
	defer clear(key)
	aad, err := idcrypto.WrapAAD(idcrypto.WrapPasskey, b)
	if err != nil {
		return fail(err)
	}
	w, err := idcrypto.NewPasskeyWrap(bytes.NewReader(nonce), prf, root, b)
	if err != nil {
		return fail(err)
	}
	again, err := idcrypto.Wrap(bytes.NewReader(nonce), idcrypto.WrapPasskey, key, root, b)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(again, w) {
		return PasskeyCase{}, nil, mismatch(name, "another wrap under k_pk", "the wrap NewPasskeyWrap makes")
	}
	opened, err := idcrypto.OpenPasskeyWrap(prf, w, b)
	if err != nil {
		return fail(err)
	}
	defer clear(opened)
	if !bytes.Equal(opened, root) {
		return PasskeyCase{}, nil, mismatch(name, "another root", "the root it wraps")
	}
	return PasskeyCase{
		Name: name, RPID: b.RPID, PRF: ptr(idcrypto.EncodeB64(prf)), Root: idcrypto.EncodeB64(root),
		Sub: b.Sub, Epoch: b.Epoch, CredentialID: b.CredentialID, Nonce: idcrypto.EncodeB64(nonce),
		PRFSalt: idcrypto.EncodeB64(salt), KPK: idcrypto.EncodeB64(key), AAD: string(aad), Wrap: idcrypto.EncodeB64(w),
	}, w, nil
}

// ClientExtensionsCase is one client-extensions vector (spec 8.2 and 8.5):
// a credential's clientExtensionResults and whether the allowlist accepts
// it. client_extension_results is the exact JSON text, carried as a JSON
// string, because what must be refused includes texts a parsed value cannot
// carry (a repeated member, a byte order mark, data after the object). A
// case without "error" is accepted; the error is always
// "client_extensions". The page's allowlist must never produce a refused
// text, and the server must refuse every one.
type ClientExtensionsCase struct {
	Name                   string `json:"name"`
	ClientExtensionResults string `json:"client_extension_results"`
	Error                  string `json:"error,omitempty"`
}

func clientExtensionsCases() ([]ClientExtensionsCase, error) {
	// A made-up PRF output, shaped like a real one.
	output := idcrypto.EncodeB64(seeded("client-extensions/prf-output", idcrypto.PRFOutputLen))
	second := idcrypto.EncodeB64(seeded("client-extensions/prf-output-2", idcrypto.PRFOutputLen))
	const refused = "client_extensions"
	specs := []struct{ name, text, err string }{
		{"no extension results", `{}`, ""},
		{"credProps only", `{"credProps":{"rk":true}}`, ""},
		{"credProps for a credential that is not discoverable", `{"credProps":{"rk":false}}`, ""},
		{"prf enabled", `{"prf":{"enabled":true}}`, ""},
		{"prf not enabled", `{"prf":{"enabled":false}}`, ""},
		{"both, as a create sends them", `{"credProps":{"rk":true},"prf":{"enabled":true}}`, ""},
		{"both, prf first", `{"prf":{"enabled":false},"credProps":{"rk":true}}`, ""},
		{"insignificant whitespace", " \t\r\n{ \"credProps\" : { \"rk\" : true } ,\n  \"prf\" : { \"enabled\" : false } }\n", ""},
		{"member names spelled with escapes", `{"pr\u0066":{"en\u0061bled":true}}`, ""},

		{"a create result with the PRF output, as the browser reports it", `{"credProps":{"rk":true},"prf":{"enabled":true,"results":{"first":"` + output + `"}}}`, refused},
		{"a get result with the PRF output, as the browser reports it", `{"prf":{"results":{"first":"` + output + `"}}}`, refused},
		{"both PRF outputs", `{"prf":{"results":{"first":"` + output + `","second":"` + second + `"}}}`, refused},
		{"prf.results present but empty", `{"prf":{"results":{}}}`, refused},
		{"prf.results null next to enabled", `{"prf":{"enabled":true,"results":null}}`, refused},
		{"prf.enabled as a string", `{"prf":{"enabled":"true"}}`, refused},
		{"prf.enabled as a number", `{"prf":{"enabled":1}}`, refused},
		{"prf.enabled null", `{"prf":{"enabled":null}}`, refused},
		{"an empty prf", `{"prf":{}}`, refused},
		{"prf null", `{"prf":null}`, refused},
		{"prf as a boolean", `{"prf":true}`, refused},
		{"prf.enabled in another case", `{"prf":{"Enabled":true}}`, refused},
		{"credProps.rk as a number", `{"credProps":{"rk":1}}`, refused},
		{"credProps.rk as a string", `{"credProps":{"rk":"true"}}`, refused},
		{"credProps.rk null", `{"credProps":{"rk":null}}`, refused},
		{"an empty credProps", `{"credProps":{}}`, refused},
		{"credProps as a boolean", `{"credProps":true}`, refused},
		{"credProps with another member", `{"credProps":{"rk":true,"authenticatorDisplayName":"Passkey"}}`, refused},
		{"an unknown extension", `{"largeBlob":{"supported":true}}`, refused},
		{"the hmac-secret extension", `{"hmacCreateSecret":true}`, refused},
		{"an unknown member next to the allowed ones", `{"credProps":{"rk":true},"prf":{"enabled":true},"appid":false}`, refused},
		{"prf in another case", `{"PRF":{"enabled":true}}`, refused},
		{"credProps in another case", `{"credprops":{"rk":true}}`, refused},
		{"a duplicate member", `{"prf":{"enabled":true},"prf":{"enabled":true}}`, refused},
		{"a duplicate member that would replace the first", `{"prf":{"enabled":false},"prf":{"results":{"first":"` + output + `"}}}`, refused},
		{"a duplicate member inside prf", `{"prf":{"enabled":false,"enabled":true}}`, refused},
		{"a duplicate member spelled with an escape", `{"prf":{"enabled":true},"pr\u0066":{"enabled":true}}`, refused},
		{"an array", `[]`, refused},
		{"an array holding the object", `[{"prf":{"enabled":true}}]`, refused},
		{"null", `null`, refused},
		{"a string holding the object", `"{}"`, refused},
		{"a boolean", `true`, refused},
		{"a number", `0`, refused},
		{"an empty text", ``, refused},
		{"two objects", `{}{}`, refused},
		{"a trailing comma", `{"prf":{"enabled":true},}`, refused},
		{"a byte order mark", "\ufeff{}", refused},
	}
	var out []ClientExtensionsCase
	for _, s := range specs {
		err := idcrypto.CheckClientExtensions([]byte(s.text))
		if got := idcrypto.ErrorCode(err); got != s.err {
			return nil, mismatch(s.name, got, s.err)
		}
		out = append(out, ClientExtensionsCase{Name: s.name, ClientExtensionResults: s.text, Error: s.err})
	}
	return out, nil
}
