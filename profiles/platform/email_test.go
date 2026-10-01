package platform_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestEmailNormalizationFoldsOnlyASCIICaseAndKeepsDotsAndTags(t *testing.T) {
	got, err := platform.NormalizeEmail("\t A.Na+Tag@Mail.Example.ORG \r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.na+tag@mail.example.org" {
		t.Fatal("normalized to another address")
	}
}

func TestEveryPrintableASCIIByteIsEitherAllowedOrRefusedInTheLocalPart(t *testing.T) {
	allowed := "abcdefghijklmnopqrstuvwxyz0123456789.!#$%&'*+/=?^_`{|}~-"
	for c := byte(0x21); c <= 0x7e; c++ {
		if c == '.' || c == '@' {
			continue // '.' needs neighbours and '@' is the separator; both have their own cases
		}
		local := "a" + string(c) + "b"
		got, err := platform.NormalizeEmail(local + "@example.com")
		lower := c
		if 'A' <= c && c <= 'Z' {
			lower = c + ('a' - 'A')
		}
		ok := strings.IndexByte(allowed, lower) >= 0
		if ok != (err == nil) {
			t.Errorf("0x%02x: accepted=%v, allowed=%v", c, err == nil, ok)
		}
		if err == nil && got != "a"+string(lower)+"b@example.com" {
			t.Errorf("0x%02x: normalized to another address", c)
		}
	}
}

func TestEmailLengthLimitsAreInBytes(t *testing.T) {
	local := strings.Repeat("x", 64)
	if _, err := platform.NormalizeEmail(local + "@example.com"); err != nil {
		t.Fatalf("64-byte local part: %v", err)
	}
	if _, err := platform.NormalizeEmail(local + "x@example.com"); !errors.Is(err, platform.ErrEmailInvalid) {
		t.Fatalf("65-byte local part: %v", err)
	}
	// A huge input is refused on length, before any per-byte work.
	if _, err := platform.NormalizeEmail(strings.Repeat("a", 1<<20) + "@example.com"); !errors.Is(err, platform.ErrEmailInvalid) {
		t.Fatalf("1 MiB address: %v", err)
	}
}
