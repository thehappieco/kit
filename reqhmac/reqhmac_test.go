package reqhmac_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/reqhmac"
)

// TestWappieRequestHMACVectors reproduces golden/reqhmac-go.json, which
// Wappie's internal/mcpauth wrote, including its two contract vectors.
func TestWappieRequestHMACVectors(t *testing.T) {
	s := wappie.MCPHMAC()
	for _, f := range vectest.Files(t, "wappie/golden/reqhmac-go.json", "kit/reqhmac-ts.json") {
		runHMACFile(t, s, f)
	}
}

func runHMACFile(t *testing.T, s reqhmac.Scheme, f *vectest.File) {
	for _, c := range f.Cases {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				Secret, Direction, Sender, Method, Target, Timestamp, Nonce, Signature string
				Body                                                                   string              `json:"body_b64"`
				Headers                                                                map[string][]string `json:"headers"`
				Now                                                                    int64               `json:"now"`
				Secrets                                                                []string            `json:"secrets"`
				Capacity                                                               int                 `json:"capacity"`
				Lifetime                                                               int64               `json:"lifetime_seconds"`
				Steps                                                                  []struct {
					Direction, Sender, Nonce string
					Timestamp, Now           int64
				} `json:"steps"`
				Seed uint64 `json:"seed"`
			}
			var out struct {
				Signature, Canonical, Timestamp, Nonce string
				Unix                                   int64             `json:"unix"`
				OK                                     bool              `json:"ok"`
				Results                                []*string         `json:"results"`
				Len                                    int               `json:"len"`
				Headers                                map[string]string `json:"headers"`
			}
			vectest.Decode(t, c.In, &in)
			if c.Error == "" {
				vectest.Decode(t, c.Out, &out)
			}
			body := vectest.B64(t, in.Body)
			switch c.Op {
			case "reqhmac.signature":
				if got := s.Canonical(in.Direction, in.Sender, in.Method, in.Target, in.Timestamp, in.Nonce, body); got != out.Canonical {
					t.Errorf("canonical %q, want %q", got, out.Canonical)
				}
				if got := s.Signature(in.Secret, in.Direction, in.Sender, in.Method, in.Target, in.Timestamp, in.Nonce, body); got != out.Signature {
					t.Errorf("signature %s, want %s", got, out.Signature)
				}
			case "reqhmac.read":
				h := http.Header{}
				for name, values := range in.Headers {
					for _, v := range values {
						h.Add(name, v)
					}
				}
				got, err := s.Read(h, time.Unix(in.Now, 0))
				if c.Error != "" {
					if err == nil || err.Error() != c.Error {
						t.Errorf("error %v, want %s", err, c.Error)
					}
				} else if err != nil || got.Timestamp != out.Timestamp || got.Unix != out.Unix || got.Nonce != out.Nonce || got.Signature != out.Signature {
					t.Errorf("read %+v: %v", got, err)
				}
			case "reqhmac.signed_by":
				got := reqhmac.Signed{Timestamp: in.Timestamp, Nonce: in.Nonce, Signature: in.Signature}
				if ok := s.SignedBy(in.Secrets, got, in.Direction, in.Sender, in.Method, in.Target, body); ok != out.OK {
					t.Errorf("signed by: %v, want %v", ok, out.OK)
				}
			case "reqhmac.replay":
				cache := reqhmac.NewReplayCache(in.Capacity, time.Duration(in.Lifetime)*time.Second)
				for i, st := range in.Steps {
					err := cache.Admit(st.Direction, st.Sender, st.Nonce, st.Timestamp, time.Unix(st.Now, 0))
					want := out.Results[i]
					switch {
					case want == nil && err != nil:
						t.Errorf("step %d: %v", i, err)
					case want != nil && (err == nil || err.Error() != *want):
						t.Errorf("step %d: %v, want %s", i, err, *want)
					}
				}
				if cache.Len() != out.Len {
					t.Errorf("len %d, want %d", cache.Len(), out.Len)
				}
			case "reqhmac.sign":
				f.SkipReplay(t)
				cryptotest.SetGlobalRandom(t, in.Seed)
				h := http.Header{}
				if err := s.Sign(h, in.Secret, in.Direction, in.Sender, in.Method, in.Target, body, time.Unix(in.Now, 0)); err != nil {
					t.Fatal(err)
				}
				for name, want := range out.Headers {
					if got := h.Get(name); got != want {
						t.Errorf("%s: %s, want %s", name, got, want)
					}
				}
			default:
				vectest.Unhandled(t, c)
			}
		})
	}
}

func TestSignReadVerify(t *testing.T) {
	s := wappie.MCPHMAC()
	now := time.Unix(1_790_300_000, 0)
	h := http.Header{}
	if err := s.Sign(h, "secret", wappie.DirectionToGo, "enclave", "post", "/v1/x?y=1", []byte("body"), now); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(h, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Wappie-Reader") != "enclave" || len(got.Nonce) != reqhmac.NonceLen {
		t.Fatalf("headers %v", h)
	}
	if !s.SignedBy([]string{"old", "secret"}, got, wappie.DirectionToGo, "enclave", "POST", "/v1/x?y=1", []byte("body")) {
		t.Fatal("a fresh signature did not verify")
	}
	for name, ok := range map[string]bool{
		"other direction": s.SignedBy([]string{"secret"}, got, wappie.DirectionToReader, "enclave", "POST", "/v1/x?y=1", []byte("body")),
		"other target":    s.SignedBy([]string{"secret"}, got, wappie.DirectionToGo, "enclave", "POST", "/v1/x?y=2", []byte("body")),
		"other body":      s.SignedBy([]string{"secret"}, got, wappie.DirectionToGo, "enclave", "POST", "/v1/x?y=1", []byte("bodY")),
		"other sender":    s.SignedBy([]string{"secret"}, got, wappie.DirectionToGo, "staging", "POST", "/v1/x?y=1", []byte("body")),
	} {
		if ok {
			t.Errorf("%s verified", name)
		}
	}
	if _, err := s.Read(h, now.Add(61*time.Second)); !errors.Is(err, reqhmac.ErrStale) {
		t.Errorf("stale: %v", err)
	}
	// Another label signs differently: the platform's contract reuses the
	// scheme without its signatures meaning anything to Wappie.
	other := s
	other.Label = "thehappie-platform-hmac/v1"
	if other.Signature("secret", "a", "b", "GET", "/", "1", "n", nil) == s.Signature("secret", "a", "b", "GET", "/", "1", "n", nil) {
		t.Error("two labels signed alike")
	}
	if !strings.HasPrefix(s.Canonical("a", "b", "get", "/", "1", "n", nil), "wappie-mcp-hmac/v1\na\nb\nGET\n/\n1\nn\n") {
		t.Error("canonical shape")
	}
}

// Arbitrary headers must never panic: they come from the network.
func FuzzRead(f *testing.F) {
	s := wappie.MCPHMAC()
	f.Add("1790300000", strings.Repeat("A", 22), "v1="+strings.Repeat("0", 64))
	f.Add("", "", "")
	f.Add("0", "=", "v1=")
	f.Fuzz(func(t *testing.T, ts, nonce, sig string) {
		h := http.Header{}
		h.Set(s.Headers.Timestamp, ts)
		h.Set(s.Headers.Nonce, nonce)
		h.Set(s.Headers.Signature, sig)
		got, err := s.Read(h, time.Unix(1_790_300_000, 0))
		if err == nil && (len(got.Nonce) != reqhmac.NonceLen || len(got.Signature) != 67) {
			t.Fatalf("accepted %+v", got)
		}
	})
}
