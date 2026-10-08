//go:build kitdevkek

package thcseal_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/localkek"
	"github.com/thehappieco/kit/thcseal"
)

var bg = context.Background()

func local(t testing.TB, b byte) *localkek.Wrapper {
	t.Helper()
	w, err := localkek.New(bytes.Repeat([]byte{b}, localkek.KEKLen))
	if err != nil {
		t.Fatalf("localkek.New: %v", err)
	}
	return w
}

func ec() kms.Context {
	return kms.Context{Service: "platform", Env: "test", Purpose: "config/smtp-password", Ref: "smtp-password"}
}

func mustSeal(t testing.TB, w kms.Wrapper, c kms.Context, plaintext []byte) []byte {
	t.Helper()
	env, err := thcseal.Seal(bg, w, c, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return env
}

// fixed is a wrapper that hands out one known data key and ignores the
// wrapped bytes and the context when unwrapping. It stands for a provider
// that checks nothing, so a test can show what the envelope alone enforces.
type fixed struct {
	provider byte
	dek      []byte
	wrapped  []byte
	genErr   error
	decErr   error
	given    [][]byte
	decrypts int
}

func newFixed(provider byte) *fixed {
	return &fixed{provider: provider, dek: bytes.Repeat([]byte{0x42}, kms.DataKeyLen), wrapped: []byte("wrapped-by-nobody")}
}

func (f *fixed) Provider() byte { return f.provider }

func (f *fixed) GenerateDataKey(context.Context, kms.Context) ([]byte, []byte, error) {
	if f.genErr != nil {
		return nil, nil, f.genErr
	}
	k := bytes.Clone(f.dek)
	f.given = append(f.given, k)
	return k, bytes.Clone(f.wrapped), nil
}

func (f *fixed) Decrypt(context.Context, []byte, kms.Context) ([]byte, error) {
	f.decrypts++
	if f.decErr != nil {
		return nil, f.decErr
	}
	k := bytes.Clone(f.dek)
	f.given = append(f.given, k)
	return k, nil
}

func TestASealedSecretRoundTrips(t *testing.T) {
	w := local(t, 1)
	for _, n := range []int{0, 1, 15, 16, 17, 32, 1000, 64 << 10} {
		want := bytes.Repeat([]byte{0xA5}, n)
		env := mustSeal(t, w, ec(), want)
		if n >= 8 && bytes.Contains(env, want[:8]) {
			t.Fatalf("%d bytes: the plaintext is visible in the envelope", n)
		}
		got, err := thcseal.Open(bg, w, ec(), env)
		if err != nil {
			t.Fatalf("%d bytes: Open: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d bytes: the round trip changed the value", n)
		}
	}
}

func TestAZeroLengthPlaintextSealsAndOpens(t *testing.T) {
	w := local(t, 1)
	env := mustSeal(t, w, ec(), nil)
	got, err := thcseal.Open(bg, w, ec(), env)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want an empty plaintext", got, err)
	}
}

func TestTheEnvelopeHasTheDocumentedLayout(t *testing.T) {
	w := local(t, 1)
	env := mustSeal(t, w, ec(), []byte("hunter2"))

	if string(env[:7]) != "THCSEAL" || env[7] != thcseal.Version1 || env[8] != kms.ProviderLocal {
		t.Fatalf("header %x", env[:9])
	}
	l := int(binary.BigEndian.Uint16(env[9:11]))
	if l != localkek.WrappedLen {
		t.Fatalf("L = %d, want %d", l, localkek.WrappedLen)
	}
	if want := 11 + l + 12 + len("hunter2") + 16; len(env) != want {
		t.Fatalf("%d bytes, want %d", len(env), want)
	}
	e, err := thcseal.Decode(env)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if e.Version != thcseal.Version1 || e.Provider != kms.ProviderLocal ||
		!bytes.Equal(e.WrappedKey, env[11:11+l]) || !bytes.Equal(e.Nonce, env[11+l:23+l]) ||
		!bytes.Equal(e.Ciphertext, env[23+l:]) {
		t.Fatalf("Decode disagrees with the layout: %+v", e)
	}
}

func TestEveryEnvelopeHasItsOwnDataKeyAndNonce(t *testing.T) {
	w := local(t, 1)
	a, _ := thcseal.Decode(mustSeal(t, w, ec(), []byte("same")))
	b, _ := thcseal.Decode(mustSeal(t, w, ec(), []byte("same")))
	if bytes.Equal(a.WrappedKey, b.WrappedKey) {
		t.Fatal("two envelopes share a wrapped data key")
	}
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatal("two envelopes share a nonce")
	}
}

func TestAnEnvelopeForAnotherContextDoesNotOpen(t *testing.T) {
	cases := map[string]func(*kms.Context){
		"purpose": func(c *kms.Context) { c.Purpose = "config/stripe-secret-key" },
		"ref":     func(c *kms.Context) { c.Ref = "smtp-password-next" },
		"no ref":  func(c *kms.Context) { c.Ref = "" },
		"service": func(c *kms.Context) { c.Service = "mailie" },
		"env":     func(c *kms.Context) { c.Env = "prod" },
	}
	// Under localkek the wrapped key already refuses another context; under
	// a wrapper that checks nothing, the envelope's own additional data must.
	wrappers := map[string]kms.Wrapper{"localkek": local(t, 1), "context-blind": newFixed(kms.ProviderLocal)}
	for wname, w := range wrappers {
		env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))
		for name, edit := range cases {
			t.Run(wname+"/"+name, func(t *testing.T) {
				c := ec()
				edit(&c)
				if _, err := thcseal.Open(bg, w, c, env); !errors.Is(err, thcseal.ErrDecrypt) {
					t.Fatalf("want ErrDecrypt, got %v", err)
				}
			})
		}
	}
}

func TestAnEnvelopeUnderAnotherKEKDoesNotOpen(t *testing.T) {
	env := mustSeal(t, local(t, 1), ec(), []byte("a tier-2 secret"))
	if _, err := thcseal.Open(bg, local(t, 2), ec(), env); !errors.Is(err, thcseal.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestFlippingAnyByteBreaksTheEnvelope(t *testing.T) {
	w := local(t, 1)
	env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))
	for i := range env {
		for _, bit := range []byte{0x01, 0x80} {
			bad := bytes.Clone(env)
			bad[i] ^= bit
			if _, err := thcseal.Open(bg, w, ec(), bad); err == nil {
				t.Fatalf("byte %d (bit %#x) was changed without detection", i, bit)
			}
		}
	}
}

func TestTheHeaderIsAuthenticatedEvenWhenTheWrapperChecksNothing(t *testing.T) {
	// The fixed wrapper returns the same data key whatever wrapped bytes it is
	// given, so only the additional data can notice an edited wrapped key.
	w := newFixed(kms.ProviderLocal)
	env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))
	for i := 11; i < 11+len(w.wrapped); i++ {
		bad := bytes.Clone(env)
		bad[i] ^= 0x01
		if _, err := thcseal.Open(bg, w, ec(), bad); !errors.Is(err, thcseal.ErrDecrypt) {
			t.Fatalf("wrapped-key byte %d: want ErrDecrypt, got %v", i-11, err)
		}
	}
}

func TestRelabellingTheProviderByteDoesNotOpen(t *testing.T) {
	// An attacker with write access rewrites byte 8 so that the envelope is
	// handed to another provider holding the same data key. The provider byte
	// is in the additional data, so it still fails.
	sealer := newFixed(kms.ProviderAWS)
	env := mustSeal(t, sealer, ec(), []byte("a tier-2 secret"))
	env[8] = kms.ProviderLocal
	if _, err := thcseal.Open(bg, newFixed(kms.ProviderLocal), ec(), env); !errors.Is(err, thcseal.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestAnEnvelopeFromAnotherProviderIsRefusedWithoutUnwrapping(t *testing.T) {
	// A development envelope reaches production: the AWS wrapper must refuse
	// it outright, before any call to KMS.
	env := mustSeal(t, local(t, 1), ec(), []byte("a tier-2 secret"))
	aws := newFixed(kms.ProviderAWS)
	if _, err := thcseal.Open(bg, aws, ec(), env); !errors.Is(err, thcseal.ErrProviderMismatch) {
		t.Fatalf("want ErrProviderMismatch, got %v", err)
	}
	if aws.decrypts != 0 {
		t.Fatal("the wrapper was asked to unwrap a foreign envelope")
	}

	// And the other way round.
	env = mustSeal(t, aws, ec(), []byte("a tier-2 secret"))
	if _, err := thcseal.Open(bg, local(t, 1), ec(), env); !errors.Is(err, thcseal.ErrProviderMismatch) {
		t.Fatalf("want ErrProviderMismatch, got %v", err)
	}
}

func TestATruncatedEnvelopeIsRefused(t *testing.T) {
	w := local(t, 1)
	env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))
	for n := range len(env) {
		_, err := thcseal.Open(bg, w, ec(), env[:n])
		if !errors.Is(err, thcseal.ErrMalformed) && !errors.Is(err, thcseal.ErrDecrypt) {
			t.Fatalf("%d of %d bytes: want ErrMalformed or ErrDecrypt, got %v", n, len(env), err)
		}
	}
	// Up to the end of the nonce, nothing is even an envelope.
	for n := range 11 + localkek.WrappedLen + 12 + 16 {
		if _, err := thcseal.Decode(env[:n]); !errors.Is(err, thcseal.ErrMalformed) {
			t.Fatalf("Decode of %d bytes: want ErrMalformed, got %v", n, err)
		}
	}
}

func TestBytesThatAreNotAnEnvelopeAreMalformed(t *testing.T) {
	good := mustSeal(t, local(t, 1), ec(), []byte("x"))
	edit := func(f func([]byte)) []byte { b := bytes.Clone(good); f(b); return b }
	cases := map[string][]byte{
		"empty":             nil,
		"magic":             edit(func(b []byte) { b[0] = 'X' }),
		"version 0":         edit(func(b []byte) { b[7] = 0 }),
		"version 2":         edit(func(b []byte) { b[7] = 2 }),
		"L = 0":             edit(func(b []byte) { binary.BigEndian.PutUint16(b[9:], 0) }),
		"L over 6144":       edit(func(b []byte) { binary.BigEndian.PutUint16(b[9:], thcseal.MaxWrappedKeyLen+1) }),
		"L past the end":    edit(func(b []byte) { binary.BigEndian.PutUint16(b[9:], uint16(len(b))) }),
		"a JSON document":   []byte(`{"secret":"this is not sealed at all"}`),
		"a mailie envelope": append([]byte{1, 1}, make([]byte, 40)...),
	}
	for name, b := range cases {
		if _, err := thcseal.Open(bg, local(t, 1), ec(), b); !errors.Is(err, thcseal.ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestAPlaintextOver256MiBIsRefused(t *testing.T) {
	// The allocation is never written, so the pages are not touched.
	big := make([]byte, thcseal.MaxPlaintext+1)
	w := newFixed(kms.ProviderLocal)
	if _, err := thcseal.Seal(bg, w, ec(), big); !errors.Is(err, thcseal.ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if len(w.given) != 0 {
		t.Fatal("a data key was made for a plaintext that was going to be refused")
	}

	env := make([]byte, 11+1+12+thcseal.MaxPlaintext+16+1)
	copy(env, "THCSEAL\x01\x7f\x00\x01")
	if _, err := thcseal.Decode(env); !errors.Is(err, thcseal.ErrMalformed) {
		t.Fatalf("Decode of an oversized envelope: want ErrMalformed, got %v", err)
	}
}

func TestTheDataKeyIsZeroedAfterUse(t *testing.T) {
	w := newFixed(kms.ProviderLocal)
	env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))
	if _, err := thcseal.Open(bg, w, ec(), env); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A failed open must not leave the key behind either.
	if _, err := thcseal.Open(bg, w, kms.Context{Service: "platform", Env: "test", Purpose: "other"}, env); err == nil {
		t.Fatal("opened under another purpose")
	}
	if len(w.given) != 3 {
		t.Fatalf("%d data keys handed out, want 3", len(w.given))
	}
	for i, k := range w.given {
		if !bytes.Equal(k, make([]byte, kms.DataKeyLen)) {
			t.Fatalf("data key %d was left in memory: %x", i, k)
		}
	}
}

func TestAnUnreachableWrapperIsNotReportedAsTampering(t *testing.T) {
	unavailable := errors.New("kms: connection refused")
	w := newFixed(kms.ProviderAWS)
	env := mustSeal(t, w, ec(), []byte("a tier-2 secret"))

	w.decErr = unavailable
	_, err := thcseal.Open(bg, w, ec(), env)
	if !errors.Is(err, unavailable) || errors.Is(err, thcseal.ErrDecrypt) {
		t.Fatalf("an outage must surface as itself, not as ErrDecrypt: %v", err)
	}

	w.decErr = kms.ErrUnwrap
	if _, err := thcseal.Open(bg, w, ec(), env); !errors.Is(err, thcseal.ErrDecrypt) || errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("a key that does not unwrap is the one opaque ErrDecrypt: %v", err)
	}

	w.genErr = unavailable
	if _, err := thcseal.Seal(bg, w, ec(), []byte("x")); !errors.Is(err, unavailable) {
		t.Fatalf("Seal: want the wrapper's error, got %v", err)
	}
}

func TestAWrapperThatMisbehavesCannotProduceAnEnvelope(t *testing.T) {
	cases := map[string]func(*fixed){
		"short data key":        func(f *fixed) { f.dek = make([]byte, 16) },
		"long data key":         func(f *fixed) { f.dek = make([]byte, 33) },
		"empty wrapped key":     func(f *fixed) { f.wrapped = nil },
		"oversized wrapped key": func(f *fixed) { f.wrapped = make([]byte, thcseal.MaxWrappedKeyLen+1) },
	}
	for name, edit := range cases {
		w := newFixed(kms.ProviderAWS)
		edit(w)
		if env, err := thcseal.Seal(bg, w, ec(), []byte("x")); err == nil {
			t.Errorf("%s: sealed %x", name, env)
		}
	}

	// A wrapper that unwraps to a key of the wrong size opens nothing.
	w := newFixed(kms.ProviderAWS)
	env := mustSeal(t, w, ec(), []byte("x"))
	w.dek = make([]byte, 16)
	if _, err := thcseal.Open(bg, w, ec(), env); !errors.Is(err, thcseal.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestAnInvalidContextIsRefusedBeforeTheWrapperIsCalled(t *testing.T) {
	w := newFixed(kms.ProviderLocal)
	env := mustSeal(t, w, ec(), []byte("x"))
	bad := ec()
	bad.Ref = "someone@example.com"
	if _, err := thcseal.Seal(bg, w, bad, []byte("x")); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("Seal: want ErrInvalidContext, got %v", err)
	}
	if _, err := thcseal.Open(bg, w, bad, env); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("Open: want ErrInvalidContext, got %v", err)
	}
	if len(w.given) != 1 || w.decrypts != 0 {
		t.Fatal("the wrapper was called with an invalid context")
	}
}

func TestANilWrapperIsAnErrorNotAPanic(t *testing.T) {
	if _, err := thcseal.Seal(bg, nil, ec(), []byte("x")); err == nil {
		t.Fatal("Seal accepted a nil wrapper")
	}
	if _, err := thcseal.Open(bg, nil, ec(), []byte("x")); err == nil {
		t.Fatal("Open accepted a nil wrapper")
	}
}
