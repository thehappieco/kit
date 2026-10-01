package passkey_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/wappie"
)

// TestWappiePasskeyVectors reproduces Wappie's browser wraps
// (golden/passkey-ts.json) and its server's PRF salts (golden/passkey-salt-go.json).
func TestWappiePasskeyVectors(t *testing.T) {
	p := wappie.Passkey()
	for _, f := range vectest.Files(t, "wappie/golden/passkey-ts.json", "wappie/golden/passkey-salt-go.json", "kit/passkey-ts.json") {
		for _, c := range f.Cases {
			if !c.ForGo() {
				continue
			}
			t.Run(c.ID, func(t *testing.T) {
				var in struct {
					RPID         string `json:"rp_id"`
					UserID       string `json:"user_id"`
					CredentialID string `json:"credential_id"`
					PRF          string `json:"prf_b64"`
					PrivateKey   string `json:"private_key_b64"`
					Nonce        string `json:"nonce_b64"`
					Envelope     string `json:"envelope_b64"`
				}
				var out struct {
					Salt       string `json:"salt_b64"`
					AAD        string `json:"aad_b64"`
					Key        string `json:"key_b64"`
					Envelope   string `json:"envelope_b64"`
					PrivateKey string `json:"private_key_b64"`
				}
				vectest.Decode(t, c.In, &in)
				if c.Error == "" {
					vectest.Decode(t, c.Out, &out)
				}
				b := func(s string) []byte { return vectest.B64(t, s) }
				aad := wappie.PasskeyAAD(in.RPID, in.UserID, in.CredentialID)
				wantErr := func(err error) {
					t.Helper()
					var e *passkey.Error
					if !errors.As(err, &e) || e.Reason != c.Error {
						t.Errorf("error %v, want %s", err, c.Error)
					}
				}
				switch c.Op {
				case "passkey.prf_salt":
					if got := passkey.PRFSalt(p, in.RPID); !bytes.Equal(got[:], b(out.Salt)) {
						t.Errorf("salt %x", got)
					}
				case "passkey.aad":
					if !bytes.Equal(aad, b(out.AAD)) {
						t.Errorf("aad %q, want %q", aad, b(out.AAD))
					}
				case "passkey.key":
					if got, err := passkey.Key(p, b(in.PRF), in.RPID); err != nil || !bytes.Equal(got, b(out.Key)) {
						t.Errorf("key: %v", err)
					}
				case "passkey.wrap":
					if c.Error != "" {
						_, err := passkey.Wrap(p, b(in.PrivateKey), b(in.PRF), in.RPID, aad)
						wantErr(err)
						return
					}
					got, err := passkey.WrapWithNonce(p, b(in.PrivateKey), b(in.PRF), in.RPID, aad, b(in.Nonce))
					if err != nil || !bytes.Equal(got, b(out.Envelope)) {
						t.Errorf("wrap %x: %v", got, err)
					}
				case "passkey.unwrap":
					got, err := passkey.Unwrap(p, b(in.Envelope), b(in.PRF), in.RPID, aad)
					if c.Error != "" {
						wantErr(err)
					} else if err != nil || !bytes.Equal(got, b(out.PrivateKey)) {
						t.Errorf("unwrap: %v", err)
					}
				default:
					vectest.Unhandled(t, c)
				}
			})
		}
	}
}

func TestRoundTripAndRefusals(t *testing.T) {
	p := wappie.Passkey()
	key, prf := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	aad := wappie.PasskeyAAD("wappie.thehappie.co", "u", "c")
	env, err := passkey.Wrap(p, key, prf, "wappie.thehappie.co", aad)
	if err != nil || len(env) != 61 || env[0] != 1 {
		t.Fatalf("%x %v", env, err)
	}
	if got, err := passkey.Unwrap(p, env, prf, "wappie.thehappie.co", aad); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := passkey.Unwrap(p, env, prf, "evil.example", aad); !errors.Is(err, passkey.ErrOpenFailed) {
		t.Errorf("another RP: %v", err)
	}
	other, err := passkey.Wrap(p, key, prf, "wappie.thehappie.co", aad)
	if err != nil || bytes.Equal(other, env) {
		t.Error("two wraps share a nonce")
	}
	// The platform's draft wraps with a two-byte header; the length follows.
	p2 := passkey.Profile{EvalPrefix: "test/v1/passkey-prf|", WrapInfo: "test/v1/passkey/wrap", Header: []byte{1, 3}}
	env2, err := passkey.Wrap(p2, key, prf, "id.example", aad)
	if err != nil || len(env2) != 62 {
		t.Fatalf("%d %v", len(env2), err)
	}
	if _, err := passkey.Unwrap(p, env2, prf, "id.example", aad); !errors.Is(err, passkey.ErrBadEnvelope) {
		t.Errorf("one profile's envelope in another: %v", err)
	}
	if s1, s2 := passkey.PRFSalt(p, "x"), passkey.PRFSalt(p2, "x"); s1 == s2 {
		t.Error("two profiles share a PRF salt")
	}
}
