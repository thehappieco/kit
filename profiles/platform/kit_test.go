package platform_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/platform"
)

// TestKitPlatformVectors reproduces the kit's own platform cases: those the
// TypeScript side wrote (kit/platform-ts.json and kit/platform-password-ts.json,
// and the fresh files of the same names in $KIT_CROSS_IN in the
// cross-language job) and those this side wrote at release time
// (kit/platform-go.json and kit/platform-password-go.json), which keep every
// later version to the same bytes.
func TestKitPlatformVectors(t *testing.T) {
	std := func(s string) []byte { return vectest.B64(t, s) }
	for _, c := range vectest.Cases(t, "kit/platform-ts.json", "kit/platform-go.json", "kit/platform-password-ts.json", "kit/platform-password-go.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				Password     string       `json:"password"`
				New          bool         `json:"new"`
				Prepared     string       `json:"prepared_b64"`
				Salt         string       `json:"salt_b64"`
				KDF          platform.KDF `json:"kdf"`
				Kind         string       `json:"kind"`
				Key          string       `json:"key_b64"`
				Root         string       `json:"root_b64"`
				Sub          string       `json:"sub"`
				Epoch        int          `json:"epoch"`
				RPID         string       `json:"rp_id"`
				CredentialID string       `json:"credential_id"`
				Nonce        string       `json:"nonce_b64"`
				Wrap         string       `json:"wrap_b64"`
				Random       string       `json:"random_b64"`
				Typed        string       `json:"typed"`
				Product      string       `json:"product"`
				Pub          string       `json:"pub_b64"`
				KAuth        string       `json:"k_auth_b64"`
				RProof       string       `json:"r_proof_b64"`
				Input        string       `json:"input"`
				BundleText   string       `json:"bundle_text"`
				RecoveryCode *string      `json:"recovery_code"`
			}
			var out struct {
				Prepared         string `json:"prepared_b64"`
				AuthKey          string `json:"auth_key"`
				Wrap             string `json:"wrap_b64"`
				AAD              string `json:"aad"`
				Canonical        string `json:"canonical"`
				Display          string `json:"display"`
				RecoveryAuth     string `json:"recovery_auth"`
				SK               string `json:"sk_b64"`
				Pub              string `json:"pub_b64"`
				ProductKeyID     string `json:"product_key_id"`
				AuthVerifier     string `json:"auth_verifier_b64"`
				RecoveryVerifier string `json:"recovery_verifier_b64"`
				EmailNorm        string `json:"email_norm"`
				Root             string `json:"root_b64"`
				Valid            bool   `json:"valid"`
			}
			vectest.Decode(t, c.In, &in)
			if len(c.Out) > 0 {
				vectest.Decode(t, c.Out, &out)
			}
			enc := base64.StdEncoding.EncodeToString
			kind := wrapKinds[in.Kind]
			binding := platform.Binding{Sub: in.Sub, Epoch: in.Epoch, RPID: in.RPID, CredentialID: in.CredentialID}
			switch c.Op {
			case "platform.prepare_password":
				prepare := platform.PreparePassword
				if in.New {
					prepare = platform.PrepareNewPassword
				}
				p, err := prepare(in.Password)
				if outcome(t, err, c.Error) {
					same(t, "prepared", enc(p), out.Prepared)
				}
			case "platform.derive_password":
				keys, err := platform.DerivePassword(std(in.Prepared), std(in.Salt), in.KDF)
				if outcome(t, err, c.Error) {
					same(t, "auth_key", keys.AuthKey(), out.AuthKey)
					same(t, "wrap key", enc(keys.Wrap[:]), out.Wrap)
				}
			case "platform.root_wrap":
				aad, err := platform.WrapAAD(kind, binding)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "aad", string(aad), out.AAD)
				wrap, err := platform.Wrap(bytes.NewReader(std(in.Nonce)), kind, std(in.Key), std(in.Root), binding)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "wrap", enc(wrap), out.Wrap)
				root, err := platform.Unwrap(kind, std(in.Key), std(out.Wrap), binding)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "root", enc(root), in.Root)
			case "platform.open_root_wrap":
				_, err := platform.Unwrap(kind, std(in.Key), std(in.Wrap), binding)
				outcome(t, err, c.Error)
			case "platform.recovery_code":
				if in.Random != "" {
					code, err := platform.RecoveryCodeFromBytes(std(in.Random))
					if err != nil {
						t.Fatal(err)
					}
					same(t, "canonical from the bytes", code, out.Canonical)
				}
				code, err := platform.CanonicalRecoveryCode(in.Typed)
				if !outcome(t, err, c.Error) {
					return
				}
				same(t, "canonical", code, out.Canonical)
				display, err := platform.DisplayRecoveryCode(in.Typed)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "display", display, out.Display)
				keys, err := platform.DeriveRecovery(in.Typed)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "wrap key", enc(keys.Wrap[:]), out.Wrap)
				same(t, "recovery_auth", keys.RecoveryAuth(), out.RecoveryAuth)
			case "platform.product_key":
				sk, pub, err := platform.ProductKey(std(in.Root), in.Product, in.Epoch)
				if outcome(t, err, c.Error) {
					same(t, "sk", enc(sk), out.SK)
					same(t, "pub", enc(pub), out.Pub)
					same(t, "product_key_id", platform.ProductKeyID(in.Product, in.Epoch), out.ProductKeyID)
					if err := platform.CheckPublicKey(pub); err != nil {
						t.Fatalf("the server refuses a derived key: %v", err)
					}
				}
			case "platform.check_public_key":
				if outcome(t, platform.CheckPublicKey(std(in.Pub)), c.Error) && !out.Valid {
					t.Fatal("a case with outputs that is not valid")
				}
			case "platform.verifier":
				if in.KAuth != "" {
					v, err := platform.AuthVerifier(in.Sub, std(in.KAuth))
					if outcome(t, err, c.Error) {
						same(t, "auth_verifier", enc(v[:]), out.AuthVerifier)
					}
				} else {
					v, err := platform.RecoveryVerifier(in.Sub, std(in.RProof))
					if outcome(t, err, c.Error) {
						same(t, "recovery_verifier", enc(v[:]), out.RecoveryVerifier)
					}
				}
			case "platform.normalize_email":
				e, err := platform.NormalizeEmail(in.Input)
				if outcome(t, err, c.Error) {
					same(t, "email_norm", e, out.EmailNorm)
				}
			case "platform.key_bundle":
				var root []byte
				var err error
				if in.RecoveryCode != nil {
					root, _, err = platform.OpenKeyBundleWithRecoveryCode([]byte(in.BundleText), *in.RecoveryCode)
				} else {
					root, _, err = platform.OpenKeyBundle([]byte(in.BundleText), in.Password)
				}
				if outcome(t, err, c.Error) {
					same(t, "root", enc(root), out.Root)
				}
			default:
				vectest.Unhandled(t, c)
			}
		})
	}
}
