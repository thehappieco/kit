package platform_test

import (
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/platform"
)

// TestPlatformVectorsRPIDEndsInNumber runs rp-id-ends-in-number.json, the
// platform's file at 75b6b94 (SPEC section 11.16). Every case's
// ends_in_a_number is passkey.EndsInANumber's answer. An accepted relying
// party id gives exactly its PRF salt, the same as section 7's with the
// platform's passkey profile, a key, and a passkey wrap that opens; a refused
// one gives wrap from PRFSalt, PasskeyWrapKey and NewPasskeyWrap, and
// OpenPasskeyWrap refuses with wrap a wrap that section 7's generic scheme,
// which checks no spelling, seals and opens under it. The counts are the file's: 12 accepted
// and 17 refused, 8 of which v0.4.0's rule accepted.
func TestPlatformVectorsRPIDEndsInNumber(t *testing.T) {
	accepted, refused, hexForms := 0, 0, 0
	prf, root := testBytes(platform.PRFOutputLen, 0x5a), testBytes(platform.KeyLen, 0x33)
	for _, c := range vectest.Platform[vectest.RPIDEndsInNumberCase](t, "rp-id-ends-in-number") {
		t.Run(c.CaseName(), func(t *testing.T) {
			if c.RPID == nil || c.EndsInANumber == nil {
				t.Fatal("a case without rp_id or ends_in_a_number")
			}
			rpID := *c.RPID
			if got := passkey.EndsInANumber(rpID); got != *c.EndsInANumber {
				t.Fatalf("ends in a number: %t, the file says %t", got, *c.EndsInANumber)
			}
			b := platform.Binding{Sub: testSub, Epoch: 1, RPID: rpID, CredentialID: "AA"}
			salt, err := platform.PRFSalt(rpID)
			key, kErr := platform.PasskeyWrapKey(prf, rpID)
			wrap, wErr := platform.NewPasskeyWrap(nil, prf, root, b)
			if outcome(t, err, c.Error) {
				if c.PRFSalt == "" {
					t.Fatal("an accepted case without prf_salt")
				}
				same(t, "prf_salt", platform.EncodeB64(salt), c.PRFSalt)
				if g := passkey.PRFSalt(platform.PasskeyProfile(), rpID); platform.EncodeB64(g[:]) != c.PRFSalt {
					t.Fatal("section 7 with the platform's passkey profile gives another salt")
				}
				if !platform.ValidRPID(rpID) || *c.EndsInANumber {
					t.Fatal("an accepted case the rule refuses")
				}
				if kErr != nil || len(key) != platform.KeyLen || wErr != nil {
					t.Fatalf("an accepted relying party id: key %v, wrap %v", kErr, wErr)
				}
				got, err := platform.OpenPasskeyWrap(prf, wrap, b)
				if err != nil || string(got) != string(root) {
					t.Fatalf("the wrap does not open: %v", err)
				}
				accepted++
				return
			}
			if c.PRFSalt != "" {
				t.Fatal("a refused case with prf_salt")
			}
			outcome(t, kErr, c.Error)
			outcome(t, wErr, c.Error)
			// A wrap the generic scheme seals under this id, which checks no
			// spelling (section 7), opens there and is refused here.
			aad, err := platform.WrapAAD(platform.WrapPasskey, b)
			if err != nil {
				t.Fatalf("the root-wrap AAD, which checks only its alphabet: %v", err)
			}
			blob, err := passkey.Wrap(platform.PasskeyProfile(), root, prf, rpID, aad)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := passkey.Unwrap(platform.PasskeyProfile(), blob, prf, rpID, aad); err != nil || string(got) != string(root) {
				t.Fatalf("section 7 does not open its own wrap: %v", err)
			}
			if got, err := platform.OpenPasskeyWrap(prf, blob, b); got != nil {
				t.Fatal("OpenPasskeyWrap opened a wrap under a refused relying party id")
			} else {
				outcome(t, err, c.Error)
			}
			if salt != nil || key != nil || wrap != nil || platform.ValidRPID(rpID) {
				t.Fatal("a refused relying party id gives a salt, a key or a wrap")
			}
			refused++
			if *c.EndsInANumber && v040ValidRPID(rpID) {
				hexForms++
			}
		})
	}
	if accepted != 12 || refused != 17 || hexForms != 8 {
		t.Fatalf("%d accepted, %d refused, %d of them accepted by v0.4.0; the file has 12, 17 and 8", accepted, refused, hexForms)
	}
}

// v040ValidRPID is ValidRPID as v0.4.0 shipped it, which refused a last
// label only when it was all digits.
func v040ValidRPID(rpID string) bool {
	return rpIDSpelling(rpID) && !rpIDDigits.MatchString(lastLabel(rpID))
}
