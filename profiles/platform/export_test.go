package platform

import (
	"testing"

	"github.com/thehappieco/kit/account"
)

// CountDerivations counts the Argon2id derivations this package starts for
// the rest of the test, so a test can prove that a refusal happened before
// anything was derived. Tests that use it must not run in parallel with
// tests that derive.
func CountDerivations(t testing.TB) *int {
	t.Helper()
	calls := new(int)
	orig := deriveFn
	deriveFn = func(p account.Profile, prepared, salt []byte, params account.KDFParams) (account.Derived, error) {
		*calls++
		return orig(p, prepared, salt, params)
	}
	t.Cleanup(func() { deriveFn = orig })
	return calls
}

// MarkRunTooLong and Counted are the run rule of section 11.2, step 2, for
// the tests that walk every code point.
var (
	MarkRunTooLong = markRunTooLong
	Counted        = counted
)
