//go:build !kitdevkek

package awskms_test

import "testing"

// The tests of the real SDK client against a fake KMS (sdk_test.go) wrap
// data keys under the local KEK (kms/localkek), which compiles only with the
// build tag kitdevkek. Without the tag they are left out, and this test
// fails rather than let the package pass without them.
func TestTheTestsOfThisPackageNeedTheTagKitdevkek(t *testing.T) {
	t.Fatal("the tests of the real SDK client against a fake KMS need the local KEK: go test -tags kitdevkek (make test-go passes it)")
}
