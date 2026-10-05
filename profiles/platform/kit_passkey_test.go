package platform_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/platform"
)

// TestKitPlatformPasskeyVectors reproduces the kit's own cases of the
// platform profile's part 3 (SPEC section 11.16) that the TypeScript side
// wrote: the fresh file platform-passkey-ts.json in $KIT_CROSS_IN, in the
// cross-language job. PRF salts of relying party ids, fresh passkey wraps
// replayed byte for byte from the nonce each drew and opened, the same
// wraps refused with one thing changed, and the allowlist's verdict on
// client extension results.
func TestKitPlatformPasskeyVectors(t *testing.T) {
	std := func(s string) []byte { return vectest.B64(t, s) }
	for _, c := range vectest.Fresh(t, "platform-passkey-ts.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) { kitPasskeyCase(t, c, std) })
	}
}

func kitPasskeyCase(t *testing.T, c vectest.Case, std func(string) []byte) {
	var in struct {
		RPID         string  `json:"rp_id"`
		PRF          string  `json:"prf_b64"`
		Root         string  `json:"root_b64"`
		Sub          string  `json:"sub"`
		Epoch        int     `json:"epoch"`
		CredentialID string  `json:"credential_id"`
		Nonce        string  `json:"nonce_b64"`
		Wrap         string  `json:"wrap_b64"`
		Text         *string `json:"text"`
	}
	var out struct {
		PRFSalt  string `json:"prf_salt_b64"`
		AAD      string `json:"aad"`
		Wrap     string `json:"wrap_b64"`
		KPK      string `json:"k_pk_b64"`
		Accepted bool   `json:"accepted"`
	}
	vectest.Decode(t, c.In, &in)
	if len(c.Out) > 0 {
		vectest.Decode(t, c.Out, &out)
	}
	enc := base64.StdEncoding.EncodeToString
	b := platform.Binding{Sub: in.Sub, Epoch: in.Epoch, RPID: in.RPID, CredentialID: in.CredentialID}
	switch c.Op {
	case "platform.prf_salt":
		salt, err := platform.PRFSalt(in.RPID)
		if outcome(t, err, c.Error) {
			same(t, "prf_salt", enc(salt), out.PRFSalt)
		} else if salt != nil {
			t.Fatal("a refusal returned a salt")
		}
		if platform.ValidRPID(in.RPID) != (c.Error == "") {
			t.Fatal("ValidRPID disagrees with PRFSalt")
		}
	case "platform.passkey_wrap":
		prf, root := std(in.PRF), std(in.Root)
		aad, err := platform.WrapAAD(platform.WrapPasskey, b)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "aad", string(aad), out.AAD)
		w, err := platform.NewPasskeyWrap(bytes.NewReader(std(in.Nonce)), prf, root, b)
		if err != nil {
			t.Fatal(err)
		}
		same(t, "wrap (replayed)", enc(w), out.Wrap)
		got, err := platform.OpenPasskeyWrap(prf, std(out.Wrap), b)
		if err != nil {
			t.Fatalf("does not open: %s", platform.ErrorCode(err))
		}
		same(t, "root", enc(got), in.Root)
		if out.KPK != "" {
			key, err := platform.PasskeyWrapKey(prf, in.RPID)
			if err != nil {
				t.Fatal(err)
			}
			same(t, "k_pk", enc(key), out.KPK)
		}
	case "platform.open_passkey_wrap":
		got, err := platform.OpenPasskeyWrap(std(in.PRF), std(in.Wrap), b)
		outcome(t, err, c.Error)
		if c.Error == "" || got != nil {
			t.Fatal("an open case is a refusal")
		}
	case "platform.check_client_extensions":
		if in.Text == nil {
			t.Fatal("no text")
		}
		if outcome(t, platform.CheckClientExtensions([]byte(*in.Text)), c.Error) && !out.Accepted {
			t.Fatal("an accepted case without accepted")
		}
	default:
		t.Fatalf("unhandled op %s", c.Op)
	}
}
