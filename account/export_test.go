package account

// The randomness-consuming functions with their randomness as an argument,
// so the tests can reproduce the reference client's recorded outputs.
var (
	WrapWithNonce    = wrap
	RecoveryCodeFrom = recoveryCode
)
