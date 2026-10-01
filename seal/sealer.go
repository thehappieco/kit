package seal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
)

// Rotation limits for a content key.
const (
	// MaxSealsPerKey bounds how many values one content key covers, so a key
	// lost to a memory disclosure exposes a bounded window while a reader
	// still unwraps few keys.
	MaxSealsPerKey = 1000

	// MaxKeyAge bounds the same window in time, for a quiet device.
	MaxKeyAge = 15 * time.Minute

	// hardSealLimit is the cryptographic ceiling: nonces are 96 random bits,
	// and collision probability grows with the square of the count. Reaching
	// it means the policy limits were bypassed, so it fails.
	hardSealLimit = 1 << 20
)

// KeyStore persists sealed content keys. An interface so this package needs
// no database.
type KeyStore interface {
	// CreateContentKey allocates the next id for the device and stores the
	// key sealed against it, atomically. The callback exists because a
	// content key binds to its own id, which is known only once the store
	// has allocated it.
	CreateContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
		seal func(id uint32) ([]byte, error)) (uint32, error)

	// CloseContentKey marks a key as no longer accepting new values. Advisory.
	CloseContentKey(ctx context.Context, tenant, device uuid.UUID, id uint32) error
}

// SealerOption configures a Sealer.
type SealerOption func(*sealerOptions)

type sealerOptions struct {
	now func() time.Time
}

// WithClock replaces the clock the age limit reads, for tests.
func WithClock(now func() time.Time) SealerOption {
	return func(o *sealerOptions) { o.now = now }
}

// Sealer seals content for one device, rotating its content key by count and
// age. Rotation happens under the same lock as sealing, so a racing caller can
// never use a key past its limit.
type Sealer[K Kind] struct {
	storeTenant uuid.UUID
	namespace   uuid.UUID
	device      uuid.UUID
	pub         hpke.PublicKey
	epoch       uint16
	store       KeyStore
	now         func() time.Time

	mu      sync.Mutex
	current *ContentKey[K]
	seals   int
	born    time.Time
}

// NewSealer builds a sealer for one device at one epoch.
//
// storeTenant is who the key store files content keys under, and may change
// when a device moves between workspaces. namespace is the immutable tenant
// every envelope binds to, so values sealed before a move still open after it.
func NewSealer[K Kind](store KeyStore, storeTenant, namespace, device uuid.UUID, pub hpke.PublicKey, epoch uint16, opts ...SealerOption) (*Sealer[K], error) {
	if namespace == uuid.Nil {
		return nil, errors.New("seal: archive tenant is required")
	}
	if !pub.Valid() {
		return nil, fmt.Errorf("seal: device %s has no archive key; it must be created before anything can be stored", device)
	}
	if store == nil {
		return nil, errors.New("seal: sealer needs a key store")
	}
	var k K
	if err := k.Domain().check(); err != nil {
		return nil, err
	}
	o := &sealerOptions{now: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	return &Sealer[K]{storeTenant: storeTenant, namespace: namespace, device: device, pub: pub, epoch: epoch, store: store, now: o.now}, nil
}

// Tenant returns the tenant the key store files this sealer's keys under.
func (s *Sealer[K]) Tenant() uuid.UUID { return s.storeTenant }

// Namespace returns the tenant every envelope binds to.
func (s *Sealer[K]) Namespace() uuid.UUID { return s.namespace }

// Device returns the device whose public key this sealer seals to.
func (s *Sealer[K]) Device() uuid.UUID { return s.device }

// Epoch returns the epoch being sealed to.
func (s *Sealer[K]) Epoch() uint16 { return s.epoch }

// Seal encrypts one value, rotating the content key when it is due.
func (s *Sealer[K]) Seal(ctx context.Context, kind K, row uuid.UUID, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.keyLocked(ctx)
	if err != nil {
		return nil, err
	}
	sealed, err := key.Seal(kind, s.namespace, row, plaintext)
	if err != nil {
		return nil, err
	}
	s.seals++
	return sealed, nil
}

// SealAll seals several values for one row under the same content key, so a
// reader unwraps once. Each keeps its own kind. Map iteration decides the
// order nonces are drawn in.
func (s *Sealer[K]) SealAll(ctx context.Context, row uuid.UUID, values map[K][]byte) (map[K][]byte, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.keyLocked(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make(map[K][]byte, len(values))
	for kind, plaintext := range values {
		sealed, err := key.Seal(kind, s.namespace, row, plaintext)
		if err != nil {
			return nil, 0, err
		}
		out[kind] = sealed
		s.seals++
	}
	return out, key.ID, nil
}

// Rotate forces a fresh content key on the next seal.
func (s *Sealer[K]) Rotate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateLocked(ctx)
}

// CurrentKeyID reports the content key in use, or zero before the first.
func (s *Sealer[K]) CurrentKeyID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return 0
	}
	return s.current.ID
}

func (s *Sealer[K]) keyLocked(ctx context.Context) (*ContentKey[K], error) {
	if s.current != nil && !s.dueLocked() {
		return s.current, nil
	}
	if err := s.rotateLocked(ctx); err != nil {
		return nil, err
	}
	return s.current, nil
}

func (s *Sealer[K]) dueLocked() bool {
	return s.seals >= MaxSealsPerKey || s.now().Sub(s.born) >= MaxKeyAge
}

func (s *Sealer[K]) rotateLocked(ctx context.Context) error {
	if s.seals >= hardSealLimit {
		return fmt.Errorf("seal: content key exceeded the hard limit of %d seals", hardSealLimit)
	}
	previous := s.current
	var fresh *ContentKey[K]
	id, err := s.store.CreateContentKey(ctx, s.storeTenant, s.device, s.epoch, func(id uint32) ([]byte, error) {
		ck, err := NewContentKey[K](s.pub, s.namespace, s.device, s.epoch, id)
		if err != nil {
			return nil, err
		}
		fresh = ck
		return ck.Sealed, nil
	})
	if err != nil {
		return fmt.Errorf("seal: create content key: %w", err)
	}
	if fresh == nil || fresh.ID != id {
		return fmt.Errorf("seal: store allocated id %d but the key was not sealed against it", id)
	}
	s.current, s.seals, s.born = fresh, 0, s.now()
	if previous != nil {
		// Advisory: the key is already out of use, and failing the rotation
		// over bookkeeping would stop sealing.
		_ = s.store.CloseContentKey(ctx, s.storeTenant, s.device, previous.ID)
	}
	return nil
}
