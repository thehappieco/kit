package passkey

// WrapWithNonce is Wrap with its nonce as an argument, so the tests can
// reproduce the reference client's recorded envelopes.
func WrapWithNonce(p Profile, privateKey, prf []byte, rpID string, aad, nonce []byte) ([]byte, error) {
	return wrap(p, privateKey, prf, rpID, aad, nonce)
}
