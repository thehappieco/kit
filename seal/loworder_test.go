package seal_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

// TestLowOrderGrants is the attack the low-order check exists for. Anybody
// who can write the database knows the account's public key, so with an
// encapsulated key of low order they can seal a grant of their own choosing
// under the all-zero secret. It must not open. And a "public key" of low
// order, which a server could serve in place of an account's, must not be
// sealed to: the server could open the result. hpke.TestForgeIsHPKE shows
// the forger seals real HPKE, so these are what an unchecked open accepts.
func TestLowOrderGrants(t *testing.T) {
	pub, priv := keys(t)
	user := uuid.MustParse("33333333-3333-7333-8333-333333333333")
	row := seal.GrantRow(tenant, testDevice, user, 1)
	chosen := bytes.Repeat([]byte{0x66}, 32) // the device key the attacker wants accepted
	magic := wappie.SealDomain().Magic
	hdr := []byte{magic[0], magic[1], seal.Version, seal.SuiteV1, seal.ModeDirect, 0, 1, 0} // epoch 1
	info := seal.Info(wappie.KindDeviceGrant, tenant, 1)
	aad := seal.AAD(wappie.KindDeviceGrant, tenant, row, hdr)
	for _, lo := range forge.LowOrder {
		t.Run(lo.Name, func(t *testing.T) {
			envelope := append(append(append([]byte(nil), hdr...), lo.Point...), forge.Seal(make([]byte, 32), lo.Point, pub.Bytes(), info, aad, chosen)...)
			if got, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, row, envelope); !errors.Is(err, seal.ErrAuthentication) {
				t.Errorf("a forged grant opened: %x %v", got, err)
			}
			bad, err := hpke.ParsePublicKey(lo.Point)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seal.SealDirect(bad, wappie.KindDeviceGrant, tenant, row, 1, chosen); !errors.Is(err, seal.ErrInvalidKey) {
				t.Errorf("sealed a grant to a low-order key: %v", err)
			}
		})
	}
}
