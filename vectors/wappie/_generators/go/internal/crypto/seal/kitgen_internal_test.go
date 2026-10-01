// Vector generator for github.com/thehappieco/kit, vectors/wappie/golden/seal-go.json.
//
// This file is not part of Wappie. vectors/wappie/_generators/run.sh copies it
// into a throwaway extraction of Wappie at a recorded commit and runs it there,
// so what it writes is what this package's code produced at that commit. It
// sits in package seal (an internal test) to reach buildAAD, infoFor and the
// raw content key, which the exported API does not show.
//
// Every random draw comes from testing/cryptotest.SetGlobalRandom, reset to the
// seed recorded in the case before the call that consumes it. Rerunning the
// generator at the same commit with the same toolchain writes the same bytes,
// and the kit replays each seeded call to prove it consumes randomness the same
// way. The file is opened with O_EXCL: nothing here overwrites a vector.

package seal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/google/uuid"
)

type kgFile struct {
	Format      string           `json:"format"`
	Module      string           `json:"module"`
	Profile     string           `json:"profile"`
	GeneratedBy kgSource         `json:"generated_by"`
	Note        string           `json:"note"`
	Keys        map[string]kgKey `json:"keys,omitempty"`
	Cases       []kgCase         `json:"cases"`
}

type kgSource struct {
	Lang       string `json:"lang"`
	Source     string `json:"source"`
	Toolchain  string `json:"toolchain"`
	Randomness string `json:"randomness"`
	Generator  string `json:"generator"`
}

type kgKey struct {
	PrivateKey string `json:"private_key_b64"`
	PublicKey  string `json:"public_key_b64"`
	Seed       uint64 `json:"seed"`
}

type kgCase struct {
	ID    string         `json:"id"`
	Op    string         `json:"op"`
	In    map[string]any `json:"in"`
	Out   map[string]any `json:"out,omitempty"`
	Error string         `json:"error,omitempty"`
	Note  string         `json:"note,omitempty"`
}

func kgB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// kgPattern is n deterministic bytes, so plaintexts are reproducible and
// differ from one another.
func kgPattern(n int, mul, add byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)*mul + add
	}
	return b
}

type kgGen struct {
	t     *testing.T
	seed  uint64
	cases []kgCase
	ids   map[string]bool
}

// draw resets the global randomness to a fresh seed and returns it.
func (g *kgGen) draw() uint64 {
	g.seed++
	cryptotest.SetGlobalRandom(g.t, g.seed)
	return g.seed
}

func (g *kgGen) add(c kgCase) {
	if g.ids[c.ID] {
		g.t.Fatalf("duplicate case id %s", c.ID)
	}
	g.ids[c.ID] = true
	if (c.Out == nil) == (c.Error == "") {
		g.t.Fatalf("case %s must have exactly one of out and error", c.ID)
	}
	g.cases = append(g.cases, c)
}

// kgClass names an error the way the vector format does. The sentinel errors
// map directly; the two unclassified errors this package returns are named by
// the code the TypeScript client gives the same condition, and the case notes
// the Go message.
func (g *kgGen) class(err error) (code, note string) {
	switch {
	case errors.Is(err, ErrShort):
		return "short", ""
	case errors.Is(err, ErrMagic):
		return "magic", ""
	case errors.Is(err, ErrVersion):
		return "version", ""
	case errors.Is(err, ErrSuite):
		return "suite", ""
	case errors.Is(err, ErrMode):
		return "mode", ""
	case errors.Is(err, ErrAuthentication):
		return "authentication", ""
	case strings.Contains(err.Error(), "envelope needs content key"):
		return "key_mismatch", "Wappie's Go returned an unclassified error: " + err.Error()
	case strings.HasPrefix(err.Error(), "seal: content key is "):
		return "short", "Wappie's Go returned an unclassified error: " + err.Error()
	case strings.HasPrefix(err.Error(), "seal: hpke recipient: "):
		return "authentication", "Wappie's Go returned an unclassified error: " + err.Error() + "; the kit reports every direct-mode failure as authentication"
	case err.Error() == "seal: no public key" || err.Error() == "seal: no private key":
		return "invalid_key", "Wappie's Go returned an unclassified error: " + err.Error()
	}
	g.t.Fatalf("unclassified error: %v", err)
	return "", ""
}

func (g *kgGen) failure(id, op string, in map[string]any, err error) {
	if err == nil {
		g.t.Fatalf("%s: expected an error", id)
	}
	code, note := g.class(err)
	g.add(kgCase{ID: id, Op: op, In: in, Error: code, Note: note})
}

type kgStore struct {
	next   uint32
	keys   []map[string]any
	closed []uint32
}

func (s *kgStore) CreateContentKey(_ context.Context, _, _ uuid.UUID, _ uint16, fn func(uint32) ([]byte, error)) (uint32, error) {
	s.next++
	sealed, err := fn(s.next)
	if err != nil {
		s.next--
		return 0, err
	}
	s.keys = append(s.keys, map[string]any{"id": s.next, "sealed_b64": kgB64(sealed)})
	return s.next, nil
}

func (s *kgStore) CountSeal(context.Context, uuid.UUID, uuid.UUID, uint32, int) error { return nil }

func (s *kgStore) CloseContentKey(_ context.Context, _, _ uuid.UUID, id uint32) error {
	s.closed = append(s.closed, id)
	return nil
}

func TestKitGenSeal(t *testing.T) {
	dir := os.Getenv("KITGEN_OUT")
	if dir == "" {
		t.Skip("KITGEN_OUT is not set; this generator runs only from the kit's run.sh")
	}
	g := &kgGen{t: t, ids: map[string]bool{}}

	tenant := uuid.MustParse("cc7d6b51-db4b-40d2-8e40-7826c8e4d835")
	device := uuid.MustParse("3eef2237-5b8e-4c4f-9a59-1c2f0d6e7a81")
	otherTenant := uuid.MustParse("99999999-9999-7999-8999-999999999999")
	otherDevice := uuid.MustParse("00000000-0000-4000-8000-0000000000bb")
	user := uuid.MustParse("7b0c5e1a-4d2f-4a8e-b1c3-9e5f6a7b8c9d")
	rowA := uuid.MustParse("11111111-1111-7111-8111-111111111111")
	rowB := uuid.MustParse("22222222-2222-7222-8222-222222222222")
	ctx := context.Background()

	// The keys. Each is generated under its own seed and recorded as a
	// replayable case as well.
	keys := map[string]kgKey{}
	keyPair := func(name string) (PublicKey, PrivateKey) {
		seed := g.draw()
		pub, priv, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := priv.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = kgKey{PrivateKey: kgB64(raw), PublicKey: kgB64(pub.Bytes()), Seed: seed}
		g.add(kgCase{ID: "seal/keys/" + name, Op: "seal.generate_key_pair", In: map[string]any{"seed": seed},
			Out: map[string]any{"private_key_b64": kgB64(raw), "public_key_b64": kgB64(pub.Bytes())}})
		return pub, priv
	}
	pub, priv := keyPair("archive")
	_, otherPriv := keyPair("other")
	_ = otherPriv

	// Kind names: every byte a reader meets, the reserved 0x0F, and both ends.
	for _, k := range []int{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff} {
		g.add(kgCase{ID: "seal/kind-name/" + Kind(k).String(), Op: "seal.kind_name",
			In: map[string]any{"kind": k}, Out: map[string]any{"name": Kind(k).String()}})
	}

	// HPKE info strings and AAD bytes.
	epochs := []uint16{0, 1, 2, 9, 10, 255, 256, 65535}
	for _, k := range []Kind{KindBody, KindContentKey, KindDeviceGrant, KindMcpDraft, Kind(0x0f)} {
		for _, e := range epochs {
			g.add(kgCase{ID: "seal/info/" + k.String() + "/epoch-" + kgItoa(int(e)), Op: "seal.info",
				In:  map[string]any{"kind": int(k), "tenant": tenant.String(), "epoch": e},
				Out: map[string]any{"info": string(infoFor(k, tenant, e))}})
		}
	}
	reserved := header{Version: Version, Suite: SuiteV1, Mode: ModeBatch, Epoch: 1}.encode()
	reserved[7] = 0x01
	for _, h := range []struct {
		name string
		hdr  []byte
	}{
		{"direct-epoch-1", header{Version: Version, Suite: SuiteV1, Mode: ModeDirect, Epoch: 1}.encode()},
		{"batch-epoch-0", header{Version: Version, Suite: SuiteV1, Mode: ModeBatch, Epoch: 0}.encode()},
		{"batch-epoch-65535", header{Version: Version, Suite: SuiteV1, Mode: ModeBatch, Epoch: 65535}.encode()},
		{"batch-reserved-1", reserved},
	} {
		for _, k := range []Kind{KindBody, KindContentKey} {
			g.add(kgCase{ID: "seal/aad/" + k.String() + "/" + h.name, Op: "seal.aad",
				In:  map[string]any{"kind": int(k), "tenant": tenant.String(), "row": rowA.String(), "header_b64": kgB64(h.hdr)},
				Out: map[string]any{"aad_b64": kgB64(buildAAD(k, tenant, rowA, h.hdr))}})
		}
	}

	// Rows.
	ids := []uint32{0, 1, 7, 255, 256, 65535, 1<<31 - 1, 1<<32 - 1}
	for _, id := range ids {
		g.add(kgCase{ID: "seal/content-key-row/id-" + kgItoa(int(id)), Op: "seal.content_key_row",
			In:  map[string]any{"tenant": tenant.String(), "device": device.String(), "id": id},
			Out: map[string]any{"row": ContentKeyRow(tenant, device, id).String()}})
	}
	for _, e := range epochs {
		g.add(kgCase{ID: "seal/grant-row/epoch-" + kgItoa(int(e)), Op: "seal.grant_row",
			In:  map[string]any{"tenant": tenant.String(), "device": device.String(), "user": user.String(), "epoch": e},
			Out: map[string]any{"row": GrantRow(tenant, device, user, e).String()}})
	}
	for i, name := range [][]byte{nil, {0}, []byte("x"), kgPattern(20, 3, 1), kgPattern(100, 5, 2)} {
		g.add(kgCase{ID: "seal/row/" + kgItoa(i), Op: "seal.row",
			In:  map[string]any{"namespace": tenant.String(), "name_b64": kgB64(name)},
			Out: map[string]any{"row": uuid.NewSHA1(tenant, name).String()}})
	}
	connection := uuid.MustParse("5f0c3a4b-2d1e-4f6a-8b9c-0d1e2f3a4b5c")
	draft := uuid.MustParse("0b6f8a52-1c1e-4b3f-9d6a-3c0e2a7f4d11")
	reply := uuid.MustParse("018f3a2b-0000-7000-8000-000000000014")
	for i, d := range []struct {
		reply *uuid.UUID
		chat  string
	}{
		{nil, "5511999990000@s.whatsapp.net"}, {&reply, "5511999990000@s.whatsapp.net"},
		{nil, "120363041234567890@g.us"}, {nil, "ação@s.whatsapp.net"}, {&reply, ""},
	} {
		in := map[string]any{"tenant": tenant.String(), "device": device.String(), "connection": connection.String(),
			"draft": draft.String(), "reply": nil, "chat_key": d.chat}
		if d.reply != nil {
			in["reply"] = d.reply.String()
		}
		g.add(kgCase{ID: "wappie/draft-row/" + kgItoa(i), Op: "wappie.draft_row", In: in,
			Out: map[string]any{"row": DraftRow(tenant, device, connection, draft, d.reply, d.chat).String()}})
	}

	// Direct mode.
	directIn := func(kind Kind, row uuid.UUID, epoch uint16, pt []byte, seed uint64) map[string]any {
		return map[string]any{"key": "archive", "kind": int(kind), "tenant": tenant.String(), "row": row.String(),
			"epoch": epoch, "plaintext_b64": kgB64(pt), "seed": seed}
	}
	sealDirect := func(id string, kind Kind, row uuid.UUID, epoch uint16, pt []byte) []byte {
		seed := g.draw()
		env, err := SealDirect(pub, kind, tenant, row, epoch, pt)
		if err != nil {
			t.Fatal(err)
		}
		back, err := OpenDirect(priv, kind, tenant, row, env)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("%s does not open: %v", id, err)
		}
		g.add(kgCase{ID: id, Op: "seal.seal_direct", In: directIn(kind, row, epoch, pt, seed), Out: map[string]any{"envelope_b64": kgB64(env)}})
		return env
	}
	sizes := []int{0, 1, 31, 32, 33, 4096}
	for _, k := range []Kind{KindContentKey, KindDeviceGrant, KindMcpDraft, Kind(0x0f)} {
		for _, n := range sizes {
			sealDirect("seal/direct/"+k.String()+"/epoch-1/len-"+kgItoa(n), k, rowA, 1, kgPattern(n, 7, byte(k)))
		}
	}
	for _, e := range epochs {
		sealDirect("seal/direct/device_grant/epoch-"+kgItoa(int(e))+"/grant-row", KindDeviceGrant, GrantRow(tenant, device, user, e), e, kgPattern(32, 0, 0xA0))
	}
	grant := sealDirect("seal/direct/device_grant/negatives-base", KindDeviceGrant, GrantRow(tenant, device, user, 1), 1, kgPattern(32, 1, 0xA0))

	// Content keys.
	type contentKey struct {
		ck     *ContentKey
		sealed []byte
	}
	contentKeys := map[string]contentKey{}
	newContentKey := func(name string, epoch uint16, id uint32) {
		seed := g.draw()
		ck, err := NewContentKey(pub, tenant, device, epoch, id)
		if err != nil {
			t.Fatal(err)
		}
		contentKeys[name] = contentKey{ck: ck, sealed: ck.Sealed}
		g.add(kgCase{ID: "seal/content-key/" + name, Op: "seal.new_content_key",
			In:  map[string]any{"key": "archive", "tenant": tenant.String(), "device": device.String(), "epoch": epoch, "id": id, "seed": seed},
			Out: map[string]any{"sealed_b64": kgB64(ck.Sealed), "content_key_b64": kgB64(ck.key)}})
	}
	for _, id := range ids {
		newContentKey("epoch-1/id-"+kgItoa(int(id)), 1, id)
	}
	for _, e := range []uint16{0, 2, 65535} {
		newContentKey("epoch-"+kgItoa(int(e))+"/id-7", e, 7)
	}
	ckRef := func(name string) map[string]any {
		c := contentKeys[name]
		return map[string]any{"tenant": tenant.String(), "device": device.String(), "id": c.ck.ID, "sealed_b64": kgB64(c.sealed)}
	}

	// Batch mode: every kind byte under one key, the sizes, and other keys.
	samples := map[Kind][]byte{
		KindBody:         []byte("olá, tudo bem? — acentuação e emoji 🇧🇷👋"),
		KindRawProto:     kgPattern(48, 11, 0x08),
		KindMediaKey:     kgPattern(32, 7, 0),
		KindThumbnail:    {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},
		KindContactName:  []byte("Grupo da Serra"),
		KindContentKey:   kgPattern(32, 13, 5),
		KindDeviceGrant:  kgPattern(32, 17, 6),
		KindUserWrap:     kgPattern(61, 19, 7),
		KindPayload:      []byte(`{"location":{"lat":-23.5505,"lon":-46.6333,"name":"São Paulo"}}`),
		KindPushName:     []byte("Felipe"),
		KindFullName:     []byte("Felipe Restum"),
		KindBusinessName: []byte("Padaria do Zé Ltda"),
		KindAvatar:       {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		KindMcpDraft:     []byte(`{"v":1,"text":"Oi! Confirmo amanhã às 10h — até lá 👋"}`),
		Kind(0x0f):       []byte("reserved kind"),
	}
	batchIn := func(name string, kind Kind, row uuid.UUID, pt []byte, seed uint64) map[string]any {
		return map[string]any{"key": "archive", "content_key": ckRef(name), "kind": int(kind), "tenant": tenant.String(),
			"row": row.String(), "plaintext_b64": kgB64(pt), "seed": seed}
	}
	sealBatch := func(id, name string, kind Kind, row uuid.UUID, pt []byte) []byte {
		seed := g.draw()
		env, err := contentKeys[name].ck.Seal(kind, tenant, row, pt)
		if err != nil {
			t.Fatal(err)
		}
		g.add(kgCase{ID: id, Op: "seal.seal_batch", In: batchIn(name, kind, row, pt, seed), Out: map[string]any{"envelope_b64": kgB64(env)}})
		return env
	}
	for k := Kind(0x01); k <= 0x0f; k++ {
		sealBatch("seal/batch/"+k.String()+"/epoch-1/id-7", "epoch-1/id-7", k, rowA, samples[k])
	}
	for _, n := range sizes {
		sealBatch("seal/batch/body/epoch-1/id-7/len-"+kgItoa(n), "epoch-1/id-7", KindBody, rowB, kgPattern(n, 3, 9))
	}
	for _, name := range slices.Sorted(maps.Keys(contentKeys)) {
		if name == "epoch-1/id-7" {
			continue
		}
		sealBatch("seal/batch/body/"+name, name, KindBody, rowA, []byte("under content key "+name))
	}
	body := sealBatch("seal/batch/body/negatives-base", "epoch-1/id-7", KindBody, rowA, []byte("integrity matters"))
	underZero := sealBatch("seal/batch/body/negatives-other-key", "epoch-1/id-0", KindBody, rowA, []byte("sealed under id 0"))

	// ContentKeyID.
	for _, c := range []struct {
		id  string
		env []byte
	}{{"batch-id-7", body}, {"batch-id-0", underZero}} {
		id, epoch, err := ContentKeyID(c.env)
		if err != nil {
			t.Fatal(err)
		}
		g.add(kgCase{ID: "seal/content-key-id/" + c.id, Op: "seal.content_key_id",
			In: map[string]any{"envelope_b64": kgB64(c.env)}, Out: map[string]any{"id": id, "epoch": epoch}})
	}
	for _, c := range []struct {
		id  string
		env []byte
	}{{"direct", grant}, {"empty", nil}, {"header-only-short", body[:7]}, {"header-only", body[:8]}, {"no-id", body[:11]}, {"magic", append([]byte{0}, body[1:]...)}} {
		_, _, err := ContentKeyID(c.env)
		if c.id == "header-only" || c.id == "no-id" {
			// Eight to eleven bytes: a batch header with no room for the id.
			if err == nil {
				t.Fatalf("%s: no error", c.id)
			}
		}
		g.failure("seal/content-key-id/"+c.id, "seal.content_key_id", map[string]any{"envelope_b64": kgB64(c.env)}, err)
	}

	// Negatives, batch.
	ck7 := contentKeys["epoch-1/id-7"].ck
	openBatch := func(id string, kind Kind, ten, row uuid.UUID, env []byte, name string) {
		_, err := contentKeys[name].ck.Open(kind, ten, row, env)
		in := map[string]any{"key": "archive", "content_key": ckRef(name), "kind": int(kind), "tenant": ten.String(),
			"row": row.String(), "envelope_b64": kgB64(env)}
		g.failure(id, "seal.open_batch", in, err)
	}
	flip := func(b []byte, i int, bit byte) []byte {
		out := bytes.Clone(b)
		out[i] ^= bit
		return out
	}
	openBatch("seal/batch/refuses/row-moved", KindBody, tenant, rowB, body, "epoch-1/id-7")
	openBatch("seal/batch/refuses/kind-swapped", KindThumbnail, tenant, rowA, body, "epoch-1/id-7")
	openBatch("seal/batch/refuses/tenant-swapped", KindBody, otherTenant, rowA, body, "epoch-1/id-7")
	for i := range len(body) {
		for _, bit := range []byte{0x01, 0x80} {
			if i >= 24 && i < len(body)-16 && bit == 0x80 {
				continue // one flip per ciphertext byte is enough
			}
			openBatch("seal/batch/refuses/byte-"+kgItoa(i)+"-bit-"+kgItoa(int(bit)), KindBody, tenant, rowA, flip(body, i, bit), "epoch-1/id-7")
		}
	}
	for n := range 40 {
		openBatch("seal/batch/refuses/truncated-"+kgItoa(n), KindBody, tenant, rowA, body[:n], "epoch-1/id-7")
	}
	openBatch("seal/batch/refuses/truncated-"+kgItoa(len(body)-1), KindBody, tenant, rowA, body[:len(body)-1], "epoch-1/id-7")
	for _, c := range []struct {
		name string
		at   int
		v    byte
	}{{"magic-0", 0, 0x00}, {"magic-1", 1, 0x00}, {"version-0", 2, 0x00}, {"version-2", 2, 0x02}, {"version-255", 2, 0xff},
		{"suite-0", 3, 0x00}, {"suite-2", 3, 0x02}, {"suite-153", 3, 0x99}, {"mode-0", 4, 0x00}, {"mode-3", 4, 0x03}, {"mode-7", 4, 0x07},
		{"reserved-1", 7, 0x01}, {"reserved-255", 7, 0xff}} {
		bad := bytes.Clone(body)
		bad[c.at] = c.v
		openBatch("seal/batch/refuses/"+c.name, KindBody, tenant, rowA, bad, "epoch-1/id-7")
	}
	openBatch("seal/batch/refuses/key-mismatch", KindBody, tenant, rowA, underZero, "epoch-1/id-7")
	openBatch("seal/batch/refuses/direct-envelope", KindDeviceGrant, tenant, GrantRow(tenant, device, user, 1), grant, "epoch-1/id-7")
	_ = ck7

	// Negatives, direct.
	openDirect := func(id, key string, k PrivateKey, kind Kind, ten, row uuid.UUID, env []byte) {
		_, err := OpenDirect(k, kind, ten, row, env)
		g.failure(id, "seal.open_direct", map[string]any{"key": key, "kind": int(kind), "tenant": ten.String(), "row": row.String(),
			"envelope_b64": kgB64(env)}, err)
	}
	grantRow := GrantRow(tenant, device, user, 1)
	openDirect("seal/direct/refuses/row-moved", "archive", priv, KindDeviceGrant, tenant, rowB, grant)
	openDirect("seal/direct/refuses/other-device", "archive", priv, KindDeviceGrant, tenant, GrantRow(tenant, otherDevice, user, 1), grant)
	openDirect("seal/direct/refuses/other-user", "archive", priv, KindDeviceGrant, tenant, GrantRow(tenant, device, otherDevice, 1), grant)
	openDirect("seal/direct/refuses/other-epoch-row", "archive", priv, KindDeviceGrant, tenant, GrantRow(tenant, device, user, 2), grant)
	openDirect("seal/direct/refuses/kind-swapped", "archive", priv, KindContentKey, tenant, grantRow, grant)
	openDirect("seal/direct/refuses/tenant-swapped", "archive", priv, KindDeviceGrant, otherTenant, grantRow, grant)
	openDirect("seal/direct/refuses/wrong-key", "other", otherPriv, KindDeviceGrant, tenant, grantRow, grant)
	openDirect("seal/direct/refuses/batch-envelope", "archive", priv, KindBody, tenant, rowA, body)
	for i := range len(grant) {
		if i >= 8 && i%8 != 0 && i != len(grant)-1 {
			continue // every header byte, then a sample of enc, ciphertext and tag
		}
		openDirect("seal/direct/refuses/byte-"+kgItoa(i)+"-bit-1", "archive", priv, KindDeviceGrant, tenant, grantRow, flip(grant, i, 0x01))
	}
	for _, c := range []struct {
		name string
		enc  []byte
	}{{"enc-zero", make([]byte, 32)}, {"enc-low-order-1", append([]byte{1}, make([]byte, 31)...)}} {
		// An encapsulated key with no shared secret: X25519 with a low-order
		// point is all zeros, which crypto/ecdh refuses.
		bad := bytes.Clone(grant)
		copy(bad[8:40], c.enc)
		openDirect("seal/direct/refuses/"+c.name, "archive", priv, KindDeviceGrant, tenant, grantRow, bad)
	}
	for n := range 56 {
		openDirect("seal/direct/refuses/truncated-"+kgItoa(n), "archive", priv, KindDeviceGrant, tenant, grantRow, grant[:n])
	}
	openDirect("seal/direct/refuses/truncated-"+kgItoa(len(grant)-1), "archive", priv, KindDeviceGrant, tenant, grantRow, grant[:len(grant)-1])
	for _, c := range []struct {
		name string
		at   int
		v    byte
	}{{"version-2", 2, 0x02}, {"suite-2", 3, 0x02}, {"mode-2", 4, 0x02}, {"mode-3", 4, 0x03}, {"reserved-1", 7, 0x01}} {
		bad := bytes.Clone(grant)
		bad[c.at] = c.v
		openDirect("seal/direct/refuses/"+c.name, "archive", priv, KindDeviceGrant, tenant, grantRow, bad)
	}
	{
		_, err := OpenDirect(PrivateKey{}, KindDeviceGrant, tenant, grantRow, grant)
		g.failure("seal/direct/refuses/no-private-key", "seal.open_direct", map[string]any{"key": "", "kind": int(KindDeviceGrant),
			"tenant": tenant.String(), "row": grantRow.String(), "envelope_b64": kgB64(grant)}, err)
		_, err = SealDirect(PublicKey{}, KindBody, tenant, rowA, 1, []byte("x"))
		g.failure("seal/direct/refuses/no-public-key", "seal.seal_direct", map[string]any{"key": "", "kind": int(KindBody),
			"tenant": tenant.String(), "row": rowA.String(), "epoch": 1, "plaintext_b64": kgB64([]byte("x")), "seed": 0}, err)
	}

	// Negatives, content keys.
	openCK := func(id, key string, k PrivateKey, ten, dev uuid.UUID, ckID uint32, sealed []byte) {
		_, err := OpenContentKey(k, ten, dev, ckID, sealed)
		g.failure(id, "seal.open_content_key", map[string]any{"key": key, "tenant": ten.String(), "device": dev.String(), "id": ckID,
			"sealed_b64": kgB64(sealed)}, err)
	}
	sealed7 := contentKeys["epoch-1/id-7"].sealed
	openCK("seal/content-key/refuses/other-id", "archive", priv, tenant, device, 8, sealed7)
	openCK("seal/content-key/refuses/other-device", "archive", priv, tenant, otherDevice, 7, sealed7)
	openCK("seal/content-key/refuses/other-tenant", "archive", priv, otherTenant, device, 7, sealed7)
	openCK("seal/content-key/refuses/wrong-key", "other", otherPriv, tenant, device, 7, sealed7)
	openCK("seal/content-key/refuses/epoch-flipped", "archive", priv, tenant, device, 7, flip(sealed7, 6, 0x01))
	openCK("seal/content-key/refuses/empty", "archive", priv, tenant, device, 7, nil)
	openCK("seal/content-key/refuses/batch-envelope", "archive", priv, tenant, device, 7, body)
	{
		// A direct envelope at the right row whose plaintext is not 32 bytes.
		seed := g.draw()
		short, err := SealDirect(pub, KindContentKey, tenant, ContentKeyRow(tenant, device, 9), 1, kgPattern(31, 1, 1))
		if err != nil {
			t.Fatal(err)
		}
		g.add(kgCase{ID: "seal/content-key/short-key-envelope", Op: "seal.seal_direct",
			In: directIn(KindContentKey, ContentKeyRow(tenant, device, 9), 1, kgPattern(31, 1, 1), seed), Out: map[string]any{"envelope_b64": kgB64(short)}})
		openCK("seal/content-key/refuses/31-byte-key", "archive", priv, tenant, device, 9, short)
	}
	for _, name := range []string{"epoch-1/id-7", "epoch-65535/id-7", "epoch-1/id-4294967295"} {
		c := contentKeys[name]
		ck, err := OpenContentKey(priv, tenant, device, c.ck.ID, c.sealed)
		if err != nil {
			t.Fatal(err)
		}
		g.add(kgCase{ID: "seal/content-key/opens/" + name, Op: "seal.open_content_key",
			In:  map[string]any{"key": "archive", "tenant": tenant.String(), "device": device.String(), "id": c.ck.ID, "sealed_b64": kgB64(c.sealed)},
			Out: map[string]any{"epoch": ck.Epoch}})
	}

	// Sealers: a replayable sequence of seals and rotations.
	type step = map[string]any
	runSealer := func(id string, storeTenant, archiveTenant uuid.UUID, epoch uint16, steps []step) {
		store := &kgStore{}
		var s *Sealer
		var err error
		seed := g.draw()
		if storeTenant == archiveTenant {
			s, err = NewSealer(storeTenant, device, pub, epoch, store)
		} else {
			s, err = NewSealerWithArchiveTenant(storeTenant, archiveTenant, device, pub, epoch, store)
		}
		if err != nil {
			t.Fatal(err)
		}
		var outs []step
		for _, st := range steps {
			switch st["action"] {
			case "seal":
				pt, _ := base64.StdEncoding.DecodeString(st["plaintext_b64"].(string))
				env, err := s.Seal(ctx, Kind(st["kind"].(int)), uuid.MustParse(st["row"].(string)), pt)
				if err != nil {
					t.Fatal(err)
				}
				outs = append(outs, step{"key_id": s.CurrentKeyID(), "envelope_b64": kgB64(env)})
			case "seal_all":
				values := map[Kind][]byte{}
				for _, v := range st["values"].([]step) {
					pt, _ := base64.StdEncoding.DecodeString(v["plaintext_b64"].(string))
					values[Kind(v["kind"].(int))] = pt
				}
				sealed, keyID, err := s.SealAll(ctx, uuid.MustParse(st["row"].(string)), values)
				if err != nil {
					t.Fatal(err)
				}
				var envs []step
				for _, v := range st["values"].([]step) {
					envs = append(envs, step{"kind": v["kind"], "envelope_b64": kgB64(sealed[Kind(v["kind"].(int))])})
				}
				outs = append(outs, step{"key_id": keyID, "envelopes": envs})
			case "rotate":
				if err := s.Rotate(ctx); err != nil {
					t.Fatal(err)
				}
				outs = append(outs, step{"key_id": s.CurrentKeyID()})
			}
		}
		closed := store.closed
		if closed == nil {
			closed = []uint32{}
		}
		g.add(kgCase{ID: id, Op: "seal.sealer",
			In: map[string]any{"key": "archive", "store_tenant": storeTenant.String(), "tenant": archiveTenant.String(),
				"device": device.String(), "epoch": epoch, "seed": seed, "steps": steps},
			Out: map[string]any{"steps": outs, "content_keys": store.keys, "closed": closed}})
	}
	ptStep := func(kind Kind, row uuid.UUID, s string) step {
		return step{"action": "seal", "kind": int(kind), "row": row.String(), "plaintext_b64": kgB64([]byte(s))}
	}
	runSealer("seal/sealer/rotation", tenant, tenant, 1, []step{
		ptStep(KindBody, rowA, "first"), ptStep(KindPayload, rowB, `{"mentions":[]}`), {"action": "rotate"},
		ptStep(KindBody, rowA, "after rotation"),
		{"action": "seal_all", "row": rowB.String(), "values": []step{{"kind": int(KindThumbnail), "plaintext_b64": kgB64([]byte("thumb"))}}},
	})
	runSealer("seal/sealer/archive-namespace", otherTenant, tenant, 2, []step{
		ptStep(KindBody, rowA, "stored under one workspace, bound to the archive namespace"), ptStep(KindAvatar, rowB, "\x89PNG"),
	})

	f := kgFile{
		Format:  "thehappieco-kit-vectors/1",
		Module:  "seal",
		Profile: "wappie",
		GeneratedBy: kgSource{
			Lang:       "go",
			Source:     "github.com/thehappieco/wappie@" + os.Getenv("KITGEN_COMMIT") + " internal/crypto/seal",
			Toolchain:  runtime.Version(),
			Randomness: "testing/cryptotest.SetGlobalRandom, reset to in.seed before each seeded call",
			Generator:  "vectors/wappie/_generators/go/internal/crypto/seal/kitgen_internal_test.go",
		},
		Note: "Wappie's archive envelope, captured from its Go code. Fixture keys protect nothing. " +
			"Seeded cases replay byte for byte only on the toolchain recorded above.",
		Keys:  keys,
		Cases: g.cases,
	}
	kgWrite(t, dir, "seal-go.json", f)
}

func kgItoa(n int) string { return strconv.Itoa(n) }

func kgWrite(t *testing.T, dir, name string, f kgFile) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("refusing to overwrite a vector file: %v", err)
	}
	defer fh.Close()
	if _, err := fh.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d cases)", name, len(f.Cases))
}
