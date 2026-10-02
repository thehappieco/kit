package platform_test

import (
	"encoding/base64"
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/platform"
)

// TestKitPlatformDeliveryVectors reproduces the kit's own cases of the
// platform profile's part 2 (SPEC sections 11.12 and 11.13) that the
// TypeScript side wrote: key-delivery AADs, fresh deliveries opened (a fresh
// seal cannot be replayed, so it is opened), the seal's refusals of akd_pub,
// and PKCE challenges.
func TestKitPlatformDeliveryVectors(t *testing.T) {
	std := func(s string) []byte { return vectest.B64(t, s) }
	cases := vectest.Fresh(t, "platform-delivery-ts.json")
	if len(cases) == 0 {
		t.Skip("no fresh platform-delivery-ts.json: KIT_CROSS_IN is not set")
	}
	for _, c := range cases {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) { kitDeliveryCase(t, c, std) })
	}
}

func kitDeliveryCase(t *testing.T, c vectest.Case, std func(string) []byte) {
	var in struct {
		Iss           string `json:"iss"`
		ClientID      string `json:"client_id"`
		RedirectURI   string `json:"redirect_uri"`
		Sub           string `json:"sub"`
		ProductKeyID  string `json:"product_key_id"`
		PKP           string `json:"pk_p_b64"`
		CodeChallenge string `json:"code_challenge"`
		Nonce         string `json:"nonce"`
		AKDPriv       string `json:"akd_priv_b64"`
		AKDSealed     string `json:"akd_sealed_b64"`
		AKDPub        string `json:"akd_pub_b64"`
		Root          string `json:"root_b64"`
		Product       string `json:"product"`
		Epoch         int    `json:"epoch"`
		CodeVerifier  string `json:"code_verifier"`
	}
	var out struct {
		AAD           string `json:"aad"`
		SK            string `json:"sk_b64"`
		CodeChallenge string `json:"code_challenge"`
	}
	vectest.Decode(t, c.In, &in)
	if len(c.Out) > 0 {
		vectest.Decode(t, c.Out, &out)
	}
	enc := base64.StdEncoding.EncodeToString
	b := platform.KeyDeliveryBinding{
		Issuer: in.Iss, ClientID: in.ClientID, RedirectURI: in.RedirectURI, Sub: in.Sub,
		ProductKeyID: in.ProductKeyID, ProductKey: std(in.PKP), CodeChallenge: in.CodeChallenge, Nonce: in.Nonce,
	}
	switch c.Op {
	case "platform.key_delivery_aad":
		aad, err := platform.KeyDeliveryAAD(b)
		if outcome(t, err, c.Error) {
			same(t, "aad", string(aad), out.AAD)
		}
	case "platform.open_product_key":
		sk, err := platform.OpenProductKey(std(in.AKDPriv), std(in.AKDSealed), b)
		if outcome(t, err, c.Error) {
			same(t, "sk_p", enc(sk), out.SK)
		} else if sk != nil {
			t.Fatal("a refusal returned key material")
		}
	case "platform.seal_product_key":
		sk, pub, err := platform.ProductKey(std(in.Root), in.Product, in.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		b.ProductKeyID, b.ProductKey = platform.ProductKeyID(in.Product, in.Epoch), pub
		sealed, err := platform.SealProductKey(nil, std(in.AKDPub), sk, b)
		if outcome(t, err, c.Error) {
			t.Fatal("a seal case with outputs")
		} else if sealed != nil {
			t.Fatal("a refusal returned a blob")
		}
	case "platform.pkce_challenge":
		ch, err := platform.PKCEChallenge(in.CodeVerifier)
		if outcome(t, err, c.Error) {
			same(t, "code_challenge", ch, out.CodeChallenge)
		}
	default:
		vectest.Unhandled(t, c)
	}
}
