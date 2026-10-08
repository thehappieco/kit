//go:build !kitdevkek

package thcseal_test

import "testing"

// The tests of this package and its golden vectors seal under the local KEK
// (kms/localkek), which compiles only with the build tag kitdevkek. Without
// the tag they are left out, and this test fails rather than let the package
// pass with its vectors unread.
func TestTheTestsOfThisPackageNeedTheTagKitdevkek(t *testing.T) {
	t.Fatal("THCSEAL's tests and its golden vectors need the local KEK: go test -tags kitdevkek (make test-go passes it)")
}
