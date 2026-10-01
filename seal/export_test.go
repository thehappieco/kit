package seal

// ContentKeyBytes exposes a content key's raw bytes to the tests, which
// compare them with the vectors' content_key_b64.
func ContentKeyBytes[K Kind](c *ContentKey[K]) []byte { return c.key }
