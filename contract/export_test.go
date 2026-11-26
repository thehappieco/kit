package contract

import "time"

// ShortenTimeouts sets the bounds a Client applies, for a test that waits
// for one to pass, and returns what puts them back.
func ShortenTimeouts(call, grace time.Duration) (restore func()) {
	oldCall, oldGrace := callTimeout, feedGrace
	callTimeout, feedGrace = call, grace
	return func() { callTimeout, feedGrace = oldCall, oldGrace }
}

// LowerTrimResultBodyLimit sets the bound PostTrimResult holds a body to,
// and returns what puts it back.
func LowerTrimResultBodyLimit(n int) (restore func()) {
	old := trimResultBodyLimit
	trimResultBodyLimit = n
	return func() { trimResultBodyLimit = old }
}
