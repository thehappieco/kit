//go:build kitdevkek

package thcseal

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"testing"
	"testing/cryptotest"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/localkek"
	"github.com/thehappieco/kit/vectors"
)

// The golden vectors are the platform's file, frozen in the kit at
// vectors/platform/thcseal-v1/thcseal-v1.json (the platform's
// internal/seal/testdata/thcseal-v1.json at d32b663; vectors/PROVENANCE.md),
// including the envelopes that must not open. They are sealed with localkek
// under a published test KEK, with crypto/rand made deterministic for the
// run, so the same generator gives the same file and a diff means the
// format moved. The kit never rewrites the file: writeGolden, the
// platform's generator, writes into memory, and
// TestThisPackageWritesTheGoldenVectorsAgain compares its bytes with the
// frozen ones. make vectors-thcseal-check runs the platform's own copy.
const (
	goldenPath = "platform/thcseal-v1/thcseal-v1.json"
	goldenSeed = 0x7468637365616c31 // "thcseal1"

	// The frozen file's counts (vectors/PROVENANCE.md).
	goldenValidCount   = 5
	goldenInvalidCount = 21
)

type goldenFile struct {
	Comment  []string        `json:"comment"`
	Provider string          `json:"provider"`
	KEK      string          `json:"kek_hex"`
	Valid    []goldenValid   `json:"valid"`
	Invalid  []goldenInvalid `json:"invalid"`
}

type goldenContext struct {
	Service string `json:"service"`
	Env     string `json:"env"`
	Purpose string `json:"purpose"`
	Ref     string `json:"ref"`
}

func (c goldenContext) kms() kms.Context {
	return kms.Context{Service: c.Service, Env: c.Env, Purpose: c.Purpose, Ref: c.Ref}
}

type goldenValid struct {
	Name      string        `json:"name"`
	Context   goldenContext `json:"context"`
	Plaintext string        `json:"plaintext_hex"`
	Envelope  string        `json:"envelope_hex"`
	// DataKey and AAD are intermediate values, for whoever is debugging a
	// second implementation.
	DataKey string `json:"data_key_hex"`
	AAD     string `json:"aad_hex"`
}

type goldenInvalid struct {
	Name     string        `json:"name"`
	Context  goldenContext `json:"context"`
	Envelope string        `json:"envelope_hex"`
	// Error is "malformed", "provider_mismatch" or "decrypt".
	Error string `json:"error"`
}

var goldenErrors = map[string]error{
	"malformed":         ErrMalformed,
	"provider_mismatch": ErrProviderMismatch,
	"decrypt":           ErrDecrypt,
}

func goldenKEK() []byte {
	kek := make([]byte, localkek.KEKLen)
	for i := range kek {
		kek[i] = byte(i)
	}
	return kek
}

func TestTheGoldenVectorsOpenAndTheBadOnesFailAsRecorded(t *testing.T) {
	raw, err := fs.ReadFile(vectors.FS, goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	// Strictly, as the kit's runners read every vector file: a member this
	// runner does not read, or anything after the object, fails the run.
	var g goldenFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		t.Fatalf("%s: %v", goldenPath, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("%s: data after the object", goldenPath)
	}
	if len(g.Valid) != goldenValidCount || len(g.Invalid) != goldenInvalidCount {
		t.Fatalf("%s: %d valid and %d invalid vectors, want %d and %d", goldenPath, len(g.Valid), len(g.Invalid), goldenValidCount, goldenInvalidCount)
	}
	kek, _ := hex.DecodeString(g.KEK)
	w, err := localkek.New(kek)
	if err != nil {
		t.Fatalf("localkek.New: %v", err)
	}
	if len(g.Valid) == 0 || len(g.Invalid) == 0 {
		t.Fatal("the golden file is missing its vectors")
	}

	for _, v := range g.Valid {
		t.Run(v.Name, func(t *testing.T) {
			env := unhex(t, v.Envelope)
			got, err := Open(context.Background(), w, v.Context.kms(), env)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, unhex(t, v.Plaintext)) {
				t.Fatalf("opened to %x", got)
			}
			e, err := Decode(env)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if a := aad(e.header, v.Context.kms()); !bytes.Equal(a, unhex(t, v.AAD)) {
				t.Fatalf("aad %x, recorded %s", a, v.AAD)
			}
			dek, err := w.Decrypt(context.Background(), e.WrappedKey, v.Context.kms())
			if err != nil || !bytes.Equal(dek, unhex(t, v.DataKey)) {
				t.Fatalf("data key %x, %v; recorded %s", dek, err, v.DataKey)
			}
		})
	}
	for _, v := range g.Invalid {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := goldenErrors[v.Error]
			if !ok {
				t.Fatalf("unknown error %q", v.Error)
			}
			if _, err := Open(context.Background(), w, v.Context.kms(), unhex(t, v.Envelope)); !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
		})
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestThisPackageWritesTheGoldenVectorsAgain runs the platform's generator
// over this package's code and compares what it writes with the frozen file,
// byte for byte. Its randomness is cryptotest's stream under the file's
// seed, so it runs on every toolchain; PROVENANCE.md records those it was
// checked on.
func TestThisPackageWritesTheGoldenVectorsAgain(t *testing.T) {
	want, err := fs.ReadFile(vectors.FS, goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := writeGolden(t); !bytes.Equal(got, want) {
		t.Fatalf("this package writes other bytes than %s: %d bytes, the file has %d", goldenPath, len(got), len(want))
	}
}

// writeGolden is the generator of the platform's internal/seal/golden_test.go
// at d32b663, which wrote the frozen file, unchanged but that it returns the
// file's bytes rather than writing them. The comment lines below are part of
// those bytes, so they still name the platform's path.
func writeGolden(t *testing.T) []byte {
	cryptotest.SetGlobalRandom(t, goldenSeed)
	w, err := localkek.New(goldenKEK())
	if err != nil {
		t.Fatal(err)
	}

	seq := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}
	config := goldenContext{"platform", "test", "config/smtp-password", "smtp-password"}
	valid := []struct {
		name      string
		ctx       goldenContext
		plaintext []byte
	}{
		{"empty plaintext", config, nil},
		{"a short secret", config, []byte("correct horse battery staple")},
		{"a 32-byte server key", goldenContext{"platform", "test", "serverkey/oidc-signing", "kid-2026-10-01"}, seq(32)},
		{"every byte value, no ref", goldenContext{"platform", "test", "backup", ""}, seq(256)},
		{"another service", goldenContext{"mailie", "dev", "credentials", "acc_01:imap/password"}, []byte("p")},
	}

	g := goldenFile{
		Comment: []string{
			"THCSEAL v1 golden vectors, generated by internal/seal/golden_test.go. Test data only.",
			"Envelope: \"THCSEAL\" | 0x01 | provider | L u16 BE | wrapped data key (L) | nonce (12) | AES-256-GCM ciphertext || tag (16).",
			"AAD: envelope bytes [0, 11+L) || for service, env, purpose, ref: u16 BE length || bytes.",
			"Provider 0x7f, localkek: wrapped = nonce (12) || AES-256-GCM(kek, data key, aad) || tag (16),",
			"  with aad = \"thcseal-localkek/v1\\n\" + service + \"\\n\" + env + \"\\n\" + purpose + \"\\n\" + ref.",
			"Every valid envelope must open to plaintext_hex under kek_hex and its context.",
			"Every invalid envelope must fail with the error named, checked in this order: malformed, provider_mismatch, decrypt.",
		},
		Provider: "localkek (0x7f)",
		KEK:      hex.EncodeToString(goldenKEK()),
	}
	var base []byte
	for _, v := range valid {
		env, err := Seal(context.Background(), w, v.ctx.kms(), v.plaintext)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		e, _ := Decode(env)
		dek, err := w.Decrypt(context.Background(), e.WrappedKey, v.ctx.kms())
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		g.Valid = append(g.Valid, goldenValid{
			Name: v.name, Context: v.ctx,
			Plaintext: hex.EncodeToString(v.plaintext), Envelope: hex.EncodeToString(env),
			DataKey: hex.EncodeToString(dek), AAD: hex.EncodeToString(aad(e.header, v.ctx.kms())),
		})
		if v.name == "a short secret" {
			base = env
		}
	}

	l := int(binary.BigEndian.Uint16(base[9:11]))
	edit := func(f func([]byte) []byte) []byte { return f(bytes.Clone(base)) }
	flip := func(i int) []byte { return edit(func(b []byte) []byte { b[i] ^= 0x01; return b }) }
	setL := func(n int) []byte {
		return edit(func(b []byte) []byte { binary.BigEndian.PutUint16(b[9:11], uint16(n)); return b })
	}
	with := func(f func(*goldenContext)) goldenContext { c := config; f(&c); return c }
	invalid := []struct {
		name string
		ctx  goldenContext
		env  []byte
		err  string
	}{
		{"another purpose", with(func(c *goldenContext) { c.Purpose = "config/stripe-secret-key" }), base, "decrypt"},
		{"another ref", with(func(c *goldenContext) { c.Ref = "smtp-password-next" }), base, "decrypt"},
		{"no ref", with(func(c *goldenContext) { c.Ref = "" }), base, "decrypt"},
		{"another service", with(func(c *goldenContext) { c.Service = "mailie" }), base, "decrypt"},
		{"another env", with(func(c *goldenContext) { c.Env = "prod" }), base, "decrypt"},
		{"empty input", config, nil, "malformed"},
		{"magic altered", config, edit(func(b []byte) []byte { b[0] = 'X'; return b }), "malformed"},
		{"version 2", config, edit(func(b []byte) []byte { b[7] = 2; return b }), "malformed"},
		{"provider relabelled as aws-kms", config, edit(func(b []byte) []byte { b[8] = kms.ProviderAWS; return b }), "provider_mismatch"},
		{"wrapped key length 0", config, setL(0), "malformed"},
		{"wrapped key length 6145", config, setL(MaxWrappedKeyLen + 1), "malformed"},
		{"wrapped key length one short", config, setL(l - 1), "decrypt"},
		{"wrapped key length past the end", config, setL(len(base)), "malformed"},
		{"wrapped key byte flipped", config, flip(headerLen), "decrypt"},
		{"nonce byte flipped", config, flip(headerLen + l), "decrypt"},
		{"ciphertext byte flipped", config, flip(headerLen + l + nonceLen), "decrypt"},
		{"tag byte flipped", config, flip(len(base) - 1), "decrypt"},
		{"truncated in the header", config, base[:10], "malformed"},
		{"truncated after the nonce", config, base[:headerLen+l+nonceLen], "malformed"},
		{"truncated by one byte", config, base[:len(base)-1], "decrypt"},
		{"a trailing byte", config, append(bytes.Clone(base), 0), "decrypt"},
	}
	for _, v := range invalid {
		g.Invalid = append(g.Invalid, goldenInvalid{Name: v.name, Context: v.ctx, Envelope: hex.EncodeToString(v.env), Error: v.err})
	}

	out, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}
