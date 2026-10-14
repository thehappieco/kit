package contracttest

// ShortenFeedPages sets how many bytes of documents a feed page holds, for
// a test of a page that ends before its 200 documents, and returns what
// puts it back.
func ShortenFeedPages(bytes int) (restore func()) {
	old := maxFeedPageBytes
	maxFeedPageBytes = bytes
	return func() { maxFeedPageBytes = old }
}

// StoredLen is what the platform counts of a document against a feed
// page's bound.
var StoredLen = storedLen
