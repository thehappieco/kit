//go:build go1.26

package idvectors

import (
	"bytes"
	"fmt"
	"strings"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// RootWrapCase is one root-wrap vector (spec 2.4). A good case gives the
// sealing inputs (kind, key, nonce, root, sub, epoch, and for a passkey wrap
// rp_id and credential_id) and the outputs: the AAD as text and the 62-byte
// wrap, which opens back to root. An error case gives what an opener holds
// (kind, key, sub, epoch, rp_id, credential_id) and a wrap it must refuse.
type RootWrapCase struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Key          string `json:"key"`
	Nonce        string `json:"nonce,omitempty"`
	Root         string `json:"root,omitempty"`
	Sub          string `json:"sub"`
	Epoch        int    `json:"epoch"`
	RPID         string `json:"rp_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	AAD          string `json:"aad,omitempty"`
	Wrap         string `json:"wrap"`
	Error        string `json:"error,omitempty"`
}

// WrapKinds maps the kind names used in vectors to the kit's wrap kinds.
var WrapKinds = map[string]idcrypto.WrapKind{
	"password": idcrypto.WrapPassword,
	"recovery": idcrypto.WrapRecovery,
	"passkey":  idcrypto.WrapPasskey,
}

func rootWrapCases() ([]RootWrapCase, error) {
	sub := uuid7("root-wrap")
	otherSub := uuid7("root-wrap/another")
	root := seeded("root-wrap/root", idcrypto.KeyLen)
	passwordKey := seeded("root-wrap/password-key", idcrypto.KeyLen)
	recoveryKey := seeded("root-wrap/recovery-key", idcrypto.KeyLen)
	passkeyKey := seeded("root-wrap/passkey-key", idcrypto.KeyLen)
	credentialID := idcrypto.EncodeB64(seeded("root-wrap/credential-id", 16))
	const rpID = "id.thehappie.co"

	type good struct {
		name  string
		kind  idcrypto.WrapKind
		key   []byte
		nonce []byte
		root  []byte
		b     idcrypto.Binding
	}
	goods := []good{
		{"a password wrap", idcrypto.WrapPassword, passwordKey, seeded("root-wrap/nonce-1", 12), root, idcrypto.Binding{Sub: sub, Epoch: 1}},
		{"a recovery wrap of the same root", idcrypto.WrapRecovery, recoveryKey, seeded("root-wrap/nonce-2", 12), root, idcrypto.Binding{Sub: sub, Epoch: 1}},
		{"a passkey wrap of the same root", idcrypto.WrapPasskey, passkeyKey, seeded("root-wrap/nonce-3", 12), root, idcrypto.Binding{Sub: sub, Epoch: 1, RPID: rpID, CredentialID: credentialID}},
		{"a password wrap at the largest epoch", idcrypto.WrapPassword, passwordKey, seeded("root-wrap/nonce-4", 12), root, idcrypto.Binding{Sub: sub, Epoch: idcrypto.MaxEpoch}},
		{"a password wrap of an all-zero root under an all-zero nonce", idcrypto.WrapPassword, passwordKey, make([]byte, 12), make([]byte, 32), idcrypto.Binding{Sub: otherSub, Epoch: 1}},
	}
	var out []RootWrapCase
	wraps := map[string][]byte{}
	for _, g := range goods {
		aad, err := idcrypto.WrapAAD(g.kind, g.b)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", g.name, err)
		}
		w, err := idcrypto.Wrap(bytes.NewReader(g.nonce), g.kind, g.key, g.root, g.b)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", g.name, err)
		}
		wraps[g.name] = w
		out = append(out, RootWrapCase{
			Name: g.name, Kind: g.kind.String(), Key: idcrypto.EncodeB64(g.key),
			Nonce: idcrypto.EncodeB64(g.nonce), Root: idcrypto.EncodeB64(g.root),
			Sub: g.b.Sub, Epoch: g.b.Epoch, RPID: g.b.RPID, CredentialID: g.b.CredentialID,
			AAD: string(aad), Wrap: idcrypto.EncodeB64(w),
		})
	}

	pw := wraps["a password wrap"]
	pk := wraps["a passkey wrap of the same root"]
	edit := func(w []byte, f func([]byte) []byte) []byte { return f(bytes.Clone(w)) }
	flip := func(w []byte, i int, bit byte) []byte {
		return edit(w, func(b []byte) []byte { b[i] ^= bit; return b })
	}
	set := func(w []byte, i int, v byte) []byte {
		return edit(w, func(b []byte) []byte { b[i] = v; return b })
	}
	base := idcrypto.Binding{Sub: sub, Epoch: 1}
	passkeyBase := idcrypto.Binding{Sub: sub, Epoch: 1, RPID: rpID, CredentialID: credentialID}

	type bad struct {
		name string
		kind idcrypto.WrapKind
		key  []byte
		b    idcrypto.Binding
		wrap []byte
	}
	bads := []bad{
		{"a flipped ciphertext bit", idcrypto.WrapPassword, passwordKey, base, flip(pw, 14, 0x01)},
		{"a flipped bit in the last ciphertext byte", idcrypto.WrapPassword, passwordKey, base, flip(pw, 45, 0x80)},
		{"a flipped tag bit", idcrypto.WrapPassword, passwordKey, base, flip(pw, 61, 0x01)},
		{"a flipped nonce bit", idcrypto.WrapPassword, passwordKey, base, flip(pw, 2, 0x01)},
		{"version byte 0x02", idcrypto.WrapPassword, passwordKey, base, set(pw, 0, 0x02)},
		{"version byte 0x00", idcrypto.WrapPassword, passwordKey, base, set(pw, 0, 0x00)},
		{"opened as another kind", idcrypto.WrapRecovery, passwordKey, base, pw},
		{"the kind byte relabelled and opened as that kind", idcrypto.WrapRecovery, passwordKey, base, set(pw, 1, byte(idcrypto.WrapRecovery))},
		{"an unknown kind byte", idcrypto.WrapPassword, passwordKey, base, set(pw, 1, 0x04)},
		{"another sub", idcrypto.WrapPassword, passwordKey, idcrypto.Binding{Sub: otherSub, Epoch: 1}, pw},
		{"another epoch", idcrypto.WrapPassword, passwordKey, idcrypto.Binding{Sub: sub, Epoch: 2}, pw},
		{"another key", idcrypto.WrapPassword, recoveryKey, base, pw},
		{"truncated to 61 bytes", idcrypto.WrapPassword, passwordKey, base, pw[:61]},
		{"a trailing byte", idcrypto.WrapPassword, passwordKey, base, append(bytes.Clone(pw), 0x00)},
		{"empty", idcrypto.WrapPassword, passwordKey, base, []byte{}},
		{"a passkey wrap for another relying party", idcrypto.WrapPasskey, passkeyKey, idcrypto.Binding{Sub: sub, Epoch: 1, RPID: "id.thehappie.localhost", CredentialID: credentialID}, pk},
		{"a passkey wrap for another credential", idcrypto.WrapPasskey, passkeyKey, idcrypto.Binding{Sub: sub, Epoch: 1, RPID: rpID, CredentialID: idcrypto.EncodeB64(seeded("root-wrap/credential-id-2", 16))}, pk},
		{"a passkey wrap opened as a password wrap", idcrypto.WrapPassword, passkeyKey, base, pk},
		{"a passkey wrap with a flipped tag bit", idcrypto.WrapPasskey, passkeyKey, passkeyBase, flip(pk, 61, 0x01)},

		// Bindings that have no AAD at all: refused before the cipher runs.
		{"a sub in upper case", idcrypto.WrapPassword, passwordKey, idcrypto.Binding{Sub: strings.ToUpper(sub), Epoch: 1}, pw},
		{"epoch 0", idcrypto.WrapPassword, passwordKey, idcrypto.Binding{Sub: sub, Epoch: 0}, pw},
		{"an epoch of 2^31", idcrypto.WrapPassword, passwordKey, idcrypto.Binding{Sub: sub, Epoch: epochPast()}, pw},
		{"a passkey wrap without its relying party", idcrypto.WrapPasskey, passkeyKey, idcrypto.Binding{Sub: sub, Epoch: 1, CredentialID: credentialID}, pk},
		{"a relying party outside the AAD alphabet", idcrypto.WrapPasskey, passkeyKey, idcrypto.Binding{Sub: sub, Epoch: 1, RPID: "id thehappie.co", CredentialID: credentialID}, pk},
		{"a padded credential id", idcrypto.WrapPasskey, passkeyKey, idcrypto.Binding{Sub: sub, Epoch: 1, RPID: rpID, CredentialID: credentialID + "=="}, pk},
		{"a password wrap opened with passkey fields", idcrypto.WrapPassword, passwordKey, passkeyBase, pw},
	}
	for _, c := range bads {
		root, err := idcrypto.Unwrap(c.kind, c.key, c.wrap, c.b)
		clear(root)
		if got := idcrypto.ErrorCode(err); got != "wrap" {
			return nil, mismatch(c.name, got, "wrap")
		}
		out = append(out, RootWrapCase{
			Name: c.name, Kind: c.kind.String(), Key: idcrypto.EncodeB64(c.key),
			Sub: c.b.Sub, Epoch: c.b.Epoch, RPID: c.b.RPID, CredentialID: c.b.CredentialID,
			Wrap: idcrypto.EncodeB64(c.wrap), Error: "wrap",
		})
	}
	return out, nil
}
