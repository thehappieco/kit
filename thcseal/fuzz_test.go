//go:build kitdevkek

package thcseal_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"testing"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/localkek"
	"github.com/thehappieco/kit/thcseal"
	"github.com/thehappieco/kit/vectors"
)

// FuzzDecodeAcceptsOnlyTheLayoutItDocuments feeds arbitrary bytes to Decode.
// It must never panic, and whatever it accepts must be exactly the documented
// layout: the fields it returns, laid end to end behind the fixed header,
// rebuild the input byte for byte.
func FuzzDecodeAcceptsOnlyTheLayoutItDocuments(f *testing.F) {
	w := local(f, 1)
	f.Add(mustSeal(f, w, ec(), nil))
	f.Add(mustSeal(f, w, ec(), []byte("a tier-2 secret")))
	f.Add(mustSeal(f, newFixed(kms.ProviderAWS), ec(), []byte("x")))
	f.Add([]byte("THCSEAL\x01\x7f\x00\x01"))
	f.Add([]byte("THCSEAL\x01\x7f\xff\xff"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := thcseal.Decode(b)
		if err != nil {
			if !errors.Is(err, thcseal.ErrMalformed) {
				t.Fatalf("Decode failed with %v, not ErrMalformed", err)
			}
			return
		}
		if e.Version != thcseal.Version1 {
			t.Fatalf("accepted version %d", e.Version)
		}
		if n := len(e.WrappedKey); n < 1 || n > thcseal.MaxWrappedKeyLen {
			t.Fatalf("accepted a %d-byte wrapped key", n)
		}
		if len(e.Nonce) != 12 || len(e.Ciphertext) < 16 || len(e.Ciphertext) > thcseal.MaxPlaintext+16 {
			t.Fatalf("accepted nonce %d, ciphertext %d", len(e.Nonce), len(e.Ciphertext))
		}
		rebuilt := []byte(thcseal.Magic)
		rebuilt = append(rebuilt, e.Version, e.Provider)
		rebuilt = binary.BigEndian.AppendUint16(rebuilt, uint16(len(e.WrappedKey)))
		rebuilt = append(rebuilt, e.WrappedKey...)
		rebuilt = append(rebuilt, e.Nonce...)
		rebuilt = append(rebuilt, e.Ciphertext...)
		if !bytes.Equal(rebuilt, b) {
			t.Fatalf("Decode does not account for every byte:\n in %x\nout %x", b, rebuilt)
		}
	})
}

// FuzzOpenNeverOpensAnAlteredEnvelope opens arbitrary bytes and arbitrary
// edits of the golden envelopes. It must never panic, must fail only with
// the three documented errors, and must open nothing but an untouched golden
// envelope sealed under the context it is opened with.
//
// The seeds come from the golden file rather than from a fresh Seal, because
// fuzzing runs this setup again in every worker and a fresh envelope would
// differ from one worker to the next.
func FuzzOpenNeverOpensAnAlteredEnvelope(f *testing.F) {
	g := readGolden(f)
	w, err := localkek.New(g.kek)
	if err != nil {
		f.Fatal(err)
	}
	opens := map[string][]byte{} // envelope -> plaintext, for g.ctx
	for _, v := range g.valid {
		if v.ctx == g.ctx {
			opens[string(v.env)] = v.plaintext
		}
		f.Add(v.env, uint16(0), byte(0), uint16(0xffff))
		f.Add(v.env, uint16(9), byte(0x01), uint16(0xffff))
		f.Add(v.env, uint16(len(v.env)-1), byte(0x80), uint16(0xffff))
	}
	for _, env := range g.invalid {
		f.Add(env, uint16(0), byte(0), uint16(0xffff))
	}
	if len(opens) == 0 {
		f.Fatal("no golden envelope under the fuzzed context")
	}
	f.Fuzz(func(t *testing.T, base []byte, at uint16, xor byte, cut uint16) {
		env := bytes.Clone(base)
		if len(env) > 0 {
			env[int(at)%len(env)] ^= xor
		}
		if int(cut) < len(env) {
			env = env[:cut]
		}
		got, err := thcseal.Open(bg, w, g.ctx, env)
		if err == nil {
			want, ok := opens[string(env)]
			if !ok {
				t.Fatalf("an envelope that was never sealed opened: %x", env)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("a golden envelope opened to %x", got)
			}
			return
		}
		if !errors.Is(err, thcseal.ErrMalformed) && !errors.Is(err, thcseal.ErrProviderMismatch) && !errors.Is(err, thcseal.ErrDecrypt) {
			t.Fatalf("Open failed with %v, outside the documented errors", err)
		}
	})
}

type golden struct {
	kek     []byte
	ctx     kms.Context
	valid   []goldenEnvelope
	invalid [][]byte
}

type goldenEnvelope struct {
	ctx            kms.Context
	env, plaintext []byte
}

// readGolden loads the frozen vectors, vectors/platform/thcseal-v1/
// thcseal-v1.json (the platform's internal/seal/testdata/thcseal-v1.json).
// ctx is the context of the first valid vector, the one the fuzzer opens
// everything under.
func readGolden(tb testing.TB) golden {
	tb.Helper()
	raw, err := fs.ReadFile(vectors.FS, "platform/thcseal-v1/thcseal-v1.json")
	if err != nil {
		tb.Fatal(err)
	}
	type jctx struct{ Service, Env, Purpose, Ref string }
	var j struct {
		KEK   string `json:"kek_hex"`
		Valid []struct {
			Context   jctx   `json:"context"`
			Plaintext string `json:"plaintext_hex"`
			Envelope  string `json:"envelope_hex"`
		} `json:"valid"`
		Invalid []struct {
			Envelope string `json:"envelope_hex"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		tb.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			tb.Fatal(err)
		}
		return b
	}
	g := golden{kek: unhex(j.KEK)}
	for _, v := range j.Valid {
		c := kms.Context(v.Context)
		g.valid = append(g.valid, goldenEnvelope{ctx: c, env: unhex(v.Envelope), plaintext: unhex(v.Plaintext)})
	}
	for _, v := range j.Invalid {
		g.invalid = append(g.invalid, unhex(v.Envelope))
	}
	if len(g.valid) == 0 {
		tb.Fatal("the golden file has no valid vectors")
	}
	g.ctx = g.valid[0].ctx
	return g
}
