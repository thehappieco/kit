package seal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"testing/cryptotest"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

type kind = wappie.Kind

// errorCode names an error the way the vector format does.
func errorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, seal.ErrShort):
		return "short"
	case errors.Is(err, seal.ErrMagic):
		return "magic"
	case errors.Is(err, seal.ErrVersion):
		return "version"
	case errors.Is(err, seal.ErrSuite):
		return "suite"
	case errors.Is(err, seal.ErrMode):
		return "mode"
	case errors.Is(err, seal.ErrAuthentication):
		return "authentication"
	case errors.Is(err, seal.ErrKeyMismatch):
		return "key_mismatch"
	case errors.Is(err, seal.ErrInvalidKey):
		return "invalid_key"
	}
	return "unclassified: " + err.Error()
}

func expectError(t *testing.T, c vectest.Case, err error) {
	t.Helper()
	if got := errorCode(err); got != c.Error {
		t.Errorf("%s: error %q, want %q", c.ID, got, c.Error)
	}
}

// keyRing holds a file's named keys.
type keyRing struct {
	pub  map[string]hpke.PublicKey
	priv map[string]hpke.PrivateKey
}

func keysOf(t *testing.T, f *vectest.File) keyRing {
	t.Helper()
	k := keyRing{pub: map[string]hpke.PublicKey{}, priv: map[string]hpke.PrivateKey{}}
	for name, key := range f.Keys {
		priv, err := hpke.ParsePrivateKey(vectest.B64(t, key.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub.Bytes(), vectest.B64(t, key.PublicKey)) {
			t.Fatalf("key %s: the private key's public half is not the recorded public key", name)
		}
		k.pub[name], k.priv[name] = pub, priv
	}
	return k
}

type contentKeyRef struct {
	Tenant string `json:"tenant"`
	Device string `json:"device"`
	ID     uint32 `json:"id"`
	Sealed string `json:"sealed_b64"`
}

type sealIn struct {
	Key        string        `json:"key"`
	Kind       int           `json:"kind"`
	Tenant     string        `json:"tenant"`
	Device     string        `json:"device"`
	Row        string        `json:"row"`
	User       string        `json:"user"`
	Epoch      uint16        `json:"epoch"`
	ID         uint32        `json:"id"`
	Plaintext  string        `json:"plaintext_b64"`
	Envelope   string        `json:"envelope_b64"`
	Sealed     string        `json:"sealed_b64"`
	Header     string        `json:"header_b64"`
	Seed       uint64        `json:"seed"`
	ContentKey contentKeyRef `json:"content_key"`
	Namespace  string        `json:"namespace"`
	Name       string        `json:"name_b64"`
	// wappie.draft_row
	Connection string  `json:"connection"`
	Draft      string  `json:"draft"`
	Reply      *string `json:"reply"`
	ChatKey    string  `json:"chat_key"`
	// seal.sealer
	StoreTenant string            `json:"store_tenant"`
	Steps       []json.RawMessage `json:"steps"`
}

type sealOut struct {
	Name       string `json:"name"`
	Info       string `json:"info"`
	AAD        string `json:"aad_b64"`
	Row        string `json:"row"`
	Envelope   string `json:"envelope_b64"`
	Plaintext  string `json:"plaintext_b64"`
	Sealed     string `json:"sealed_b64"`
	ContentKey string `json:"content_key_b64"`
	Epoch      uint16 `json:"epoch"`
	ID         uint32 `json:"id"`
	PrivateKey string `json:"private_key_b64"`
	PublicKey  string `json:"public_key_b64"`
}

// draftRow is how Wappie keeps DraftRow on top of the kit: the number, the
// connection, the draft, the message it replies to (sixteen zero bytes for
// none) and the chat.
func draftRow(tenant, device, connection, draft uuid.UUID, reply *uuid.UUID, chatKey string) uuid.UUID {
	r := make([]byte, 16)
	if reply != nil {
		r = reply[:]
	}
	return seal.Row(tenant, device[:], connection[:], draft[:], r, []byte(chatKey))
}

func openContentKey(t *testing.T, k keyRing, keyName string, ref contentKeyRef) (*seal.ContentKey[kind], error) {
	t.Helper()
	return seal.OpenContentKey[kind](k.priv[keyName], vectest.UUID(t, ref.Tenant), vectest.UUID(t, ref.Device), ref.ID, vectest.B64(t, ref.Sealed))
}

// TestWappieSealVectors runs every case of the seal vectors Wappie's Go code
// wrote (golden/seal-go.json) and Wappie's TypeScript wrote (golden/seal-ts.json).
func TestWappieSealVectors(t *testing.T) {
	for _, f := range vectest.Files(t, "wappie/golden/seal-go.json", "wappie/golden/seal-ts.json", "kit/seal-ts.json") {
		keys := keysOf(t, f)
		t.Run(f.Path, func(t *testing.T) {
			for _, c := range f.Cases {
				if !c.ForGo() {
					continue
				}
				t.Run(c.ID, func(t *testing.T) { runSealCase(t, f, keys, c) })
			}
		})
	}
}

func runSealCase(t *testing.T, f *vectest.File, keys keyRing, c vectest.Case) {
	var in sealIn
	var out sealOut
	vectest.Decode(t, c.In, &in)
	if c.Error == "" {
		vectest.Decode(t, c.Out, &out)
	}
	u := func(s string) uuid.UUID { return vectest.UUID(t, s) }
	b := func(s string) []byte { return vectest.B64(t, s) }
	switch c.Op {
	case "seal.generate_key_pair":
		f.SkipReplay(t)
		cryptotest.SetGlobalRandom(t, in.Seed)
		pub, priv, err := hpke.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := priv.Bytes()
		if !bytes.Equal(raw, b(out.PrivateKey)) || !bytes.Equal(pub.Bytes(), b(out.PublicKey)) {
			t.Error("the replayed key pair differs")
		}
	case "seal.kind_name":
		if got := kind(in.Kind).String(); got != out.Name {
			t.Errorf("name %q, want %q", got, out.Name)
		}
	case "seal.info":
		if got := string(seal.Info(kind(in.Kind), u(in.Tenant), in.Epoch)); got != out.Info {
			t.Errorf("info %q, want %q", got, out.Info)
		}
	case "seal.aad":
		if got := seal.AAD(kind(in.Kind), u(in.Tenant), u(in.Row), b(in.Header)); !bytes.Equal(got, b(out.AAD)) {
			t.Errorf("aad %x, want %x", got, b(out.AAD))
		}
	case "seal.content_key_row":
		if got := seal.ContentKeyRow(u(in.Tenant), u(in.Device), in.ID).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "seal.grant_row":
		if got := seal.GrantRow(u(in.Tenant), u(in.Device), u(in.User), in.Epoch).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "seal.row":
		if got := seal.Row(u(in.Namespace), b(in.Name)).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "wappie.draft_row":
		var reply *uuid.UUID
		if in.Reply != nil {
			r := u(*in.Reply)
			reply = &r
		}
		if got := draftRow(u(in.Tenant), u(in.Device), u(in.Connection), u(in.Draft), reply, in.ChatKey).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "seal.seal_direct":
		if c.Error != "" {
			_, err := seal.SealDirect(keys.pub[in.Key], kind(in.Kind), u(in.Tenant), u(in.Row), in.Epoch, b(in.Plaintext))
			expectError(t, c, err)
			return
		}
		got, err := seal.OpenDirect(keys.priv[in.Key], kind(in.Kind), u(in.Tenant), u(in.Row), b(out.Envelope))
		if err != nil || !bytes.Equal(got, b(in.Plaintext)) {
			t.Fatalf("the recorded envelope does not open: %v", err)
		}
		if in.Seed == 0 {
			return // sealed by TypeScript: its ephemeral key cannot be injected here
		}
		f.SkipReplay(t)
		cryptotest.SetGlobalRandom(t, in.Seed)
		env, err := seal.SealDirect(keys.pub[in.Key], kind(in.Kind), u(in.Tenant), u(in.Row), in.Epoch, b(in.Plaintext))
		if err != nil || !bytes.Equal(env, b(out.Envelope)) {
			t.Errorf("the replayed envelope differs: %v", err)
		}
	case "seal.open_direct":
		got, err := seal.OpenDirect(keys.priv[in.Key], kind(in.Kind), u(in.Tenant), u(in.Row), b(in.Envelope))
		if c.Error != "" {
			expectError(t, c, err)
		} else if err != nil || !bytes.Equal(got, b(out.Plaintext)) {
			t.Errorf("opened to %x, %v", got, err)
		}
	case "seal.new_content_key":
		ck, err := seal.OpenContentKey[kind](keys.priv[in.Key], u(in.Tenant), u(in.Device), in.ID, b(out.Sealed))
		if err != nil {
			t.Fatalf("the recorded content key does not open: %v", err)
		}
		if ck.Epoch != in.Epoch || ck.ID != in.ID || !bytes.Equal(seal.ContentKeyBytes(ck), b(out.ContentKey)) {
			t.Errorf("content key %d/%d %x", ck.ID, ck.Epoch, seal.ContentKeyBytes(ck))
		}
		f.SkipReplay(t)
		cryptotest.SetGlobalRandom(t, in.Seed)
		fresh, err := seal.NewContentKey[kind](keys.pub[in.Key], u(in.Tenant), u(in.Device), in.Epoch, in.ID)
		if err != nil || !bytes.Equal(fresh.Sealed, b(out.Sealed)) || !bytes.Equal(seal.ContentKeyBytes(fresh), b(out.ContentKey)) {
			t.Errorf("the replayed content key differs: %v", err)
		}
	case "seal.open_content_key":
		ck, err := seal.OpenContentKey[kind](keys.priv[in.Key], u(in.Tenant), u(in.Device), in.ID, b(in.Sealed))
		if c.Error != "" {
			expectError(t, c, err)
		} else if err != nil || ck.Epoch != out.Epoch {
			t.Errorf("content key: %v", err)
		}
	case "seal.seal_batch":
		ck, err := openContentKey(t, keys, in.Key, in.ContentKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ck.Open(kind(in.Kind), u(in.Tenant), u(in.Row), b(out.Envelope))
		if err != nil || !bytes.Equal(got, b(in.Plaintext)) {
			t.Fatalf("the recorded envelope does not open: %v", err)
		}
		f.SkipReplay(t)
		cryptotest.SetGlobalRandom(t, in.Seed)
		env, err := ck.Seal(kind(in.Kind), u(in.Tenant), u(in.Row), b(in.Plaintext))
		if err != nil || !bytes.Equal(env, b(out.Envelope)) {
			t.Errorf("the replayed envelope differs: %v", err)
		}
	case "seal.open_batch":
		ck, err := openContentKey(t, keys, in.Key, in.ContentKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ck.Open(kind(in.Kind), u(in.Tenant), u(in.Row), b(in.Envelope))
		if c.Error != "" {
			expectError(t, c, err)
		} else if err != nil || !bytes.Equal(got, b(out.Plaintext)) {
			t.Errorf("opened to %x, %v", got, err)
		}
	case "seal.content_key_id":
		id, epoch, err := seal.ContentKeyID[kind](b(in.Envelope))
		if c.Error != "" {
			expectError(t, c, err)
		} else if err != nil || id != out.ID || epoch != out.Epoch {
			t.Errorf("id %d epoch %d: %v", id, epoch, err)
		}
	case "seal.sealer":
		runSealer(t, f, keys, in, c.Out)
	default:
		vectest.Unhandled(t, c)
	}
}

type memStore struct {
	next   uint32
	keys   map[uint32][]byte
	order  []uint32
	closed []uint32
}

func (m *memStore) CreateContentKey(_ context.Context, _, _ uuid.UUID, _ uint16, fn func(uint32) ([]byte, error)) (uint32, error) {
	m.next++
	sealed, err := fn(m.next)
	if err != nil {
		m.next--
		return 0, err
	}
	m.keys[m.next] = sealed
	m.order = append(m.order, m.next)
	return m.next, nil
}

func (m *memStore) CloseContentKey(_ context.Context, _, _ uuid.UUID, id uint32) error {
	m.closed = append(m.closed, id)
	return nil
}

// runSealer opens every value a recorded Sealer sequence produced, then, on the
// recording toolchain, replays the sequence and compares every byte.
func runSealer(t *testing.T, f *vectest.File, keys keyRing, in sealIn, rawOut json.RawMessage) {
	type value struct {
		Kind      int    `json:"kind"`
		Plaintext string `json:"plaintext_b64"`
		Envelope  string `json:"envelope_b64"`
	}
	type step struct {
		Action    string  `json:"action"`
		Kind      int     `json:"kind"`
		Row       string  `json:"row"`
		Plaintext string  `json:"plaintext_b64"`
		Values    []value `json:"values"`
		KeyID     uint32  `json:"key_id"`
		Envelope  string  `json:"envelope_b64"`
		Envelopes []value `json:"envelopes"`
	}
	var out struct {
		Steps       []step `json:"steps"`
		ContentKeys []struct {
			ID     uint32 `json:"id"`
			Sealed string `json:"sealed_b64"`
		} `json:"content_keys"`
		Closed []uint32 `json:"closed"`
	}
	vectest.Decode(t, rawOut, &out)
	steps := make([]step, len(in.Steps))
	for i, raw := range in.Steps {
		vectest.Decode(t, raw, &steps[i])
	}
	tenant, device := vectest.UUID(t, in.Tenant), vectest.UUID(t, in.Device)
	stored := map[uint32][]byte{}
	for _, k := range out.ContentKeys {
		stored[k.ID] = vectest.B64(t, k.Sealed)
	}
	open := func(keyID uint32, k int, row, envelope string) []byte {
		ck, err := seal.OpenContentKey[kind](keys.priv[in.Key], tenant, device, keyID, stored[keyID])
		if err != nil {
			t.Fatal(err)
		}
		pt, err := ck.Open(kind(k), tenant, vectest.UUID(t, row), vectest.B64(t, envelope))
		if err != nil {
			t.Fatal(err)
		}
		return pt
	}
	for i, s := range steps {
		switch s.Action {
		case "seal":
			if got := open(out.Steps[i].KeyID, s.Kind, s.Row, out.Steps[i].Envelope); !bytes.Equal(got, vectest.B64(t, s.Plaintext)) {
				t.Errorf("step %d opened to %q", i, got)
			}
		case "seal_all":
			for j, v := range s.Values {
				if got := open(out.Steps[i].KeyID, v.Kind, s.Row, out.Steps[i].Envelopes[j].Envelope); !bytes.Equal(got, vectest.B64(t, v.Plaintext)) {
					t.Errorf("step %d value %d opened to %q", i, j, got)
				}
			}
		}
	}

	f.SkipReplay(t)
	cryptotest.SetGlobalRandom(t, in.Seed)
	store := &memStore{keys: map[uint32][]byte{}}
	s, err := seal.NewSealer[kind](store, vectest.UUID(t, in.StoreTenant), tenant, device, func() hpke.PublicKey { return keys.pub[in.Key] }(), in.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, st := range steps {
		want := out.Steps[i]
		switch st.Action {
		case "seal":
			env, err := s.Seal(ctx, kind(st.Kind), vectest.UUID(t, st.Row), vectest.B64(t, st.Plaintext))
			if err != nil || !bytes.Equal(env, vectest.B64(t, want.Envelope)) || s.CurrentKeyID() != want.KeyID {
				t.Errorf("step %d: the replayed envelope differs: %v", i, err)
			}
		case "seal_all":
			values := map[kind][]byte{}
			for _, v := range st.Values {
				values[kind(v.Kind)] = vectest.B64(t, v.Plaintext)
			}
			sealed, keyID, err := s.SealAll(ctx, vectest.UUID(t, st.Row), values)
			if err != nil || keyID != want.KeyID {
				t.Fatalf("step %d: %v", i, err)
			}
			for _, v := range want.Envelopes {
				if !bytes.Equal(sealed[kind(v.Kind)], vectest.B64(t, v.Envelope)) {
					t.Errorf("step %d: the replayed %s differs", i, kind(v.Kind))
				}
			}
		case "rotate":
			if err := s.Rotate(ctx); err != nil || s.CurrentKeyID() != want.KeyID {
				t.Errorf("step %d: rotate: %v", i, err)
			}
		}
	}
	for _, k := range out.ContentKeys {
		if !bytes.Equal(store.keys[k.ID], vectest.B64(t, k.Sealed)) {
			t.Errorf("content key %d differs", k.ID)
		}
	}
	if len(store.order) != len(out.ContentKeys) || len(store.closed) != len(out.Closed) {
		t.Errorf("stored %v closed %v", store.order, store.closed)
	}
}
