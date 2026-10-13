package contract

import "time"

// ShortenTimeouts sets the bounds a Client applies, for a test that waits
// for one to pass, and returns what puts them back.
func ShortenTimeouts(call, grace time.Duration) (restore func()) {
	oldCall, oldGrace := callTimeout, feedGrace
	callTimeout, feedGrace = call, grace
	return func() { callTimeout, feedGrace = oldCall, oldGrace }
}
