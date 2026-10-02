package oidcrp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"sync"
)

// Verdict is the pin's answer for a login (SPEC section 11.15, step 6).
type Verdict string

const (
	// PinNew is the first login of (sub, product_key_id) here: its key is
	// now pinned.
	PinNew Verdict = "new"
	// PinSame is a login with the pinned key.
	PinSame Verdict = "same"
	// PinChanged is a login with another key than the pinned one: it is
	// refused with ErrAccountKeyChanged, and the pin is kept.
	PinChanged Verdict = "account_key_changed"
)

// PinStore keeps the first product key seen for each (sub, product_key_id),
// insert only. The package documentation has the table and the two
// statements of a database's implementation.
type PinStore interface {
	// InsertPin stores productKey for (sub, productKeyID) if nothing is
	// stored there, never replaces what is, and returns what is stored there
	// afterwards and whether this call stored it. It must be atomic: of two
	// concurrent first logins with different keys, one stores its key and
	// the other is answered with that key.
	InsertPin(ctx context.Context, sub, productKeyID string, productKey []byte) (pinned []byte, inserted bool, err error)
}

// Pin pins productKey for (sub, productKeyID) through s and compares it, in
// constant time, with what is pinned there: PinNew when this call pinned
// it, PinSame when it equals the pinned key, and PinChanged with
// ErrAccountKeyChanged when it does not. A pin is never replaced. The
// store's own errors are returned as they are.
func Pin(ctx context.Context, s PinStore, sub, productKeyID string, productKey []byte) (Verdict, error) {
	v, _, err := pin(ctx, s, sub, productKeyID, productKey)
	return v, err
}

// pin is Pin, and also returns what is pinned.
func pin(ctx context.Context, s PinStore, sub, productKeyID string, productKey []byte) (Verdict, []byte, error) {
	if s == nil {
		return "", nil, errors.New("oidcrp: no pin store")
	}
	pinned, inserted, err := s.InsertPin(ctx, sub, productKeyID, productKey)
	if err != nil {
		return "", nil, err
	}
	if subtle.ConstantTimeCompare(pinned, productKey) == 1 {
		if inserted {
			return PinNew, pinned, nil
		}
		return PinSame, pinned, nil
	}
	if inserted {
		return "", nil, errors.New("oidcrp: the pin store inserted another key than it was given")
	}
	return PinChanged, pinned, ErrAccountKeyChanged
}

// MemoryPins is a PinStore in memory, for tests and development: bounded,
// safe for concurrent use, and gone when the process ends.
type MemoryPins struct {
	mu   sync.Mutex
	pins map[pinKey][]byte
	max  int
}

type pinKey struct{ sub, productKeyID string }

// NewMemoryPins returns a MemoryPins that holds at most max pins; a new pin
// past that is ErrPinStoreFull, while pinned keys keep being recognised.
func NewMemoryPins(max int) *MemoryPins {
	return &MemoryPins{pins: make(map[pinKey][]byte), max: max}
}

// InsertPin implements PinStore. What it returns is a copy: neither the
// caller's slice nor the answer is the pin.
func (m *MemoryPins) InsertPin(_ context.Context, sub, productKeyID string, productKey []byte) ([]byte, bool, error) {
	k := pinKey{sub: sub, productKeyID: productKeyID}
	m.mu.Lock()
	defer m.mu.Unlock()
	if stored, ok := m.pins[k]; ok {
		return bytes.Clone(stored), false, nil
	}
	if len(m.pins) >= m.max {
		return nil, false, ErrPinStoreFull
	}
	m.pins[k] = bytes.Clone(productKey)
	return bytes.Clone(productKey), true, nil
}

// Len is the number of pins held.
func (m *MemoryPins) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pins)
}
