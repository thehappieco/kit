//go:build kitdevkek

package localkek_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/localkek"
)

func kek(b byte) []byte { return bytes.Repeat([]byte{b}, localkek.KEKLen) }

func wrapper(t *testing.T, b byte) *localkek.Wrapper {
	t.Helper()
	w, err := localkek.New(kek(b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func ctx() kms.Context {
	return kms.Context{Service: "platform", Env: "test", Purpose: "serverkey/oidc-signing", Ref: "kid-1"}
}

func TestAKEKThatIsNot32BytesIsRefused(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := localkek.New(make([]byte, n)); !errors.Is(err, localkek.ErrKEKLength) {
			t.Errorf("%d bytes: want ErrKEKLength, got %v", n, err)
		}
	}
}

func TestTheLocalProviderSaysSoInEveryEnvelope(t *testing.T) {
	if got := wrapper(t, 1).Provider(); got != kms.ProviderLocal {
		t.Fatalf("Provider() = %#x, want %#x", got, kms.ProviderLocal)
	}
}

func TestAWrappedDataKeyUnwrapsUnderTheSameContext(t *testing.T) {
	w := wrapper(t, 1)
	dek, wrapped, err := w.GenerateDataKey(context.Background(), ctx())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dek) != kms.DataKeyLen || len(wrapped) != localkek.WrappedLen {
		t.Fatalf("got a %d-byte key wrapped in %d bytes", len(dek), len(wrapped))
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("the data key is visible in its wrapped form")
	}
	got, err := w.Decrypt(context.Background(), wrapped, ctx())
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("the unwrapped key differs from the generated one")
	}
}

func TestEveryDataKeyIsFresh(t *testing.T) {
	w := wrapper(t, 1)
	a, wa, _ := w.GenerateDataKey(context.Background(), ctx())
	b, wb, _ := w.GenerateDataKey(context.Background(), ctx())
	if bytes.Equal(a, b) || bytes.Equal(wa, wb) {
		t.Fatal("two calls returned the same key or the same wrap")
	}
}

func TestAWrappedDataKeyDoesNotUnwrapUnderAnotherContext(t *testing.T) {
	w := wrapper(t, 1)
	_, wrapped, _ := w.GenerateDataKey(context.Background(), ctx())

	for name, edit := range map[string]func(*kms.Context){
		"service": func(c *kms.Context) { c.Service = "mailie" },
		"env":     func(c *kms.Context) { c.Env = "prod" },
		"purpose": func(c *kms.Context) { c.Purpose = "serverkey/login-decoy" },
		"ref":     func(c *kms.Context) { c.Ref = "kid-2" },
		"no ref":  func(c *kms.Context) { c.Ref = "" },
		// The same bytes split differently between purpose and ref are another
		// context: the separators are part of what is authenticated.
		"shifted boundary": func(c *kms.Context) { c.Purpose, c.Ref = "serverkey/oidc-signingkid-1", "" },
	} {
		t.Run(name, func(t *testing.T) {
			ec := ctx()
			edit(&ec)
			if _, err := w.Decrypt(context.Background(), wrapped, ec); !errors.Is(err, kms.ErrUnwrap) {
				t.Fatalf("want ErrUnwrap, got %v", err)
			}
		})
	}
}

func TestAWrappedDataKeyDoesNotUnwrapUnderAnotherKEK(t *testing.T) {
	_, wrapped, _ := wrapper(t, 1).GenerateDataKey(context.Background(), ctx())
	if _, err := wrapper(t, 2).Decrypt(context.Background(), wrapped, ctx()); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("want ErrUnwrap, got %v", err)
	}
}

func TestAnAlteredOrTruncatedWrapDoesNotUnwrap(t *testing.T) {
	w := wrapper(t, 1)
	_, wrapped, _ := w.GenerateDataKey(context.Background(), ctx())
	for i := range wrapped {
		bad := bytes.Clone(wrapped)
		bad[i] ^= 0x80
		if _, err := w.Decrypt(context.Background(), bad, ctx()); !errors.Is(err, kms.ErrUnwrap) {
			t.Fatalf("byte %d: want ErrUnwrap, got %v", i, err)
		}
	}
	for _, n := range []int{0, 1, localkek.WrappedLen - 1} {
		if _, err := w.Decrypt(context.Background(), wrapped[:n], ctx()); !errors.Is(err, kms.ErrUnwrap) {
			t.Fatalf("%d bytes: want ErrUnwrap, got %v", n, err)
		}
	}
	if _, err := w.Decrypt(context.Background(), append(bytes.Clone(wrapped), 0), ctx()); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("a trailing byte: want ErrUnwrap, got %v", err)
	}
}

func TestAnInvalidContextIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	w := wrapper(t, 1)
	bad := ctx()
	bad.Purpose = ""
	if _, _, err := w.GenerateDataKey(context.Background(), bad); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("GenerateDataKey: want ErrInvalidContext, got %v", err)
	}
	if _, err := w.Decrypt(context.Background(), make([]byte, localkek.WrappedLen), bad); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("Decrypt: want ErrInvalidContext, got %v", err)
	}
}

func TestACancelledContextStopsTheCall(t *testing.T) {
	w := wrapper(t, 1)
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := w.GenerateDataKey(c, ctx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateDataKey: want context.Canceled, got %v", err)
	}
	if _, err := w.Decrypt(c, make([]byte, localkek.WrappedLen), ctx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt: want context.Canceled, got %v", err)
	}
}
