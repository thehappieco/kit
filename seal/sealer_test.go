package seal_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

// Wappie's Sealer tests (internal/crypto/seal/archive_test.go and
// archive_namespace_test.go), moved here with the Sealer.

type lockedStore struct {
	mu     sync.Mutex
	next   uint32
	stored map[uint32][]byte
	closed map[uint32]bool
	fail   error
	want   uuid.UUID // when set, the tenant every key must be filed under
	t      *testing.T
}

func newStore(t *testing.T) *lockedStore {
	return &lockedStore{stored: map[uint32][]byte{}, closed: map[uint32]bool{}, t: t}
}

func (m *lockedStore) CreateContentKey(_ context.Context, storeTenant, _ uuid.UUID, _ uint16, fn func(uint32) ([]byte, error)) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.want != uuid.Nil && storeTenant != m.want {
		m.t.Errorf("key filed under %s, want %s", storeTenant, m.want)
	}
	if m.fail != nil {
		return 0, m.fail
	}
	m.next++
	sealed, err := fn(m.next)
	if err != nil {
		m.next--
		return 0, err
	}
	m.stored[m.next] = sealed
	return m.next, nil
}

func (m *lockedStore) CloseContentKey(_ context.Context, _, _ uuid.UUID, id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = true
	return nil
}

func (m *lockedStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.stored)
}

func newSealer(t *testing.T, opts ...seal.SealerOption) (*seal.Sealer[wappie.Kind], *lockedStore, hpke.PrivateKey) {
	t.Helper()
	pub, priv := keys(t)
	store := newStore(t)
	s, err := seal.NewSealer[wappie.Kind](store, tenant, tenant, testDevice, pub, 1, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, store, priv
}

func TestSealerCreatesKeyLazily(t *testing.T) {
	s, store, _ := newSealer(t)
	if store.count() != 0 {
		t.Fatal("a content key was created before anything needed sealing")
	}
	if _, err := s.Seal(context.Background(), wappie.KindBody, rowA, []byte("x")); err != nil || store.count() != 1 {
		t.Fatalf("%d keys: %v", store.count(), err)
	}
}

func TestManySealsShareOneKey(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()
	for range seal.MaxSealsPerKey {
		if _, err := s.Seal(ctx, wappie.KindBody, rowA, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if store.count() != 1 {
		t.Fatalf("stored %d keys for %d seals", store.count(), seal.MaxSealsPerKey)
	}
	if _, err := s.Seal(ctx, wappie.KindBody, rowA, []byte("x")); err != nil || store.count() != 2 {
		t.Fatalf("one past the limit: %d keys, %v", store.count(), err)
	}
}

func TestRotationClosesThePreviousKey(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()
	if _, err := s.Seal(ctx, wappie.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	first := s.CurrentKeyID()
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if s.CurrentKeyID() == first {
		t.Fatal("Rotate did not produce a new key")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.closed[first] {
		t.Error("the previous key was not closed")
	}
}

func TestKeyRotatesOnAge(t *testing.T) {
	now := time.Now()
	s, store, _ := newSealer(t, seal.WithClock(func() time.Time { return now }))
	ctx := context.Background()
	seal1 := func() {
		if _, err := s.Seal(ctx, wappie.KindBody, rowA, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	seal1()
	now = now.Add(seal.MaxKeyAge - time.Second)
	seal1()
	if store.count() != 1 {
		t.Fatalf("rotated early: %d keys", store.count())
	}
	now = now.Add(2 * time.Second)
	seal1()
	if store.count() != 2 {
		t.Fatalf("did not rotate on age: %d keys", store.count())
	}
}

func TestSealAllSharesOneKeyButNotOneKind(t *testing.T) {
	s, store, priv := newSealer(t)
	values := map[wappie.Kind][]byte{
		wappie.KindBody: []byte("uma legenda"), wappie.KindMediaKey: make([]byte, 32),
		wappie.KindThumbnail: []byte("thumb bytes"), wappie.KindRawProto: []byte("protobuf bytes"),
	}
	sealed, keyID, err := s.SealAll(context.Background(), rowA, values)
	if err != nil || store.count() != 1 {
		t.Fatalf("%d keys: %v", store.count(), err)
	}
	ck, err := seal.OpenContentKey[wappie.Kind](priv, tenant, testDevice, keyID, store.stored[keyID])
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range values {
		if got, err := ck.Open(kind, tenant, rowA, sealed[kind]); err != nil || string(got) != string(want) {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if _, err := ck.Open(wappie.KindBody, tenant, rowA, sealed[wappie.KindThumbnail]); err == nil {
		t.Error("a thumbnail opened as a message body")
	}
}

// Rotation happens under the same lock as sealing, so no key is used past its
// limit by a racing caller. Run with -race.
func TestConcurrentSealing(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()
	const workers, each = 8, 400
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Go(func() {
			for range each {
				if _, err := s.Seal(ctx, wappie.KindBody, rowA, []byte("x")); err != nil {
					errs[i] = err
					return
				}
			}
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	if store.count() < 3 {
		t.Errorf("stored %d keys for %d seals", store.count(), workers*each)
	}
}

func TestSealerRefusesWhatCannotSeal(t *testing.T) {
	pub, _ := keys(t)
	if _, err := seal.NewSealer[wappie.Kind](newStore(t), tenant, tenant, testDevice, hpke.PublicKey{}, 1); err == nil {
		t.Error("a sealer was built without a public key")
	}
	if _, err := seal.NewSealer[wappie.Kind](newStore(t), tenant, uuid.Nil, testDevice, pub, 1); err == nil {
		t.Error("a sealer was built without a namespace")
	}
	if _, err := seal.NewSealer[wappie.Kind](nil, tenant, tenant, testDevice, pub, 1); err == nil {
		t.Error("a sealer was built without a store")
	}
}

func TestStoreFailurePropagates(t *testing.T) {
	s, store, _ := newSealer(t)
	store.fail = errors.New("database is down")
	out, err := s.Seal(context.Background(), wappie.KindBody, rowA, []byte("secret"))
	if err == nil || out != nil {
		t.Fatalf("%x, %v", out, err)
	}
}

// The store files keys under the current workspace; envelopes bind to the
// immutable namespace, so values sealed before a move still open after it.
func TestNamespaceSurvivesAWorkspaceMove(t *testing.T) {
	pub, priv := keys(t)
	namespace, personal := uuid.New(), uuid.New()
	store := newStore(t)
	store.want = namespace
	before, err := seal.NewSealer[wappie.Kind](store, namespace, namespace, testDevice, pub, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := before.Seal(context.Background(), wappie.KindBody, rowA, []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	aID := before.CurrentKeyID()
	store.want = personal
	after, err := seal.NewSealer[wappie.Kind](store, personal, namespace, testDevice, pub, 1)
	if err != nil || after.Tenant() != personal || after.Namespace() != namespace || after.Device() != testDevice || after.Epoch() != 1 {
		t.Fatal(err)
	}
	b, err := after.Seal(context.Background(), wappie.KindBody, rowA, []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id   uint32
		blob []byte
		want string
	}{{aID, a, "before"}, {after.CurrentKeyID(), b, "after"}} {
		ck, err := seal.OpenContentKey[wappie.Kind](priv, namespace, testDevice, c.id, store.stored[c.id])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ck.Open(wappie.KindBody, namespace, rowA, c.blob); err != nil || string(got) != c.want {
			t.Fatalf("%q %v", got, err)
		}
		if _, err := ck.Open(wappie.KindBody, personal, rowA, c.blob); err == nil {
			t.Fatal("the workspace id stood in for the namespace")
		}
	}
}
