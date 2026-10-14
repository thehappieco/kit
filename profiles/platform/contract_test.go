package platform_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/profiles/platform"
	"github.com/thehappieco/kit/reqhmac"
	"github.com/thehappieco/kit/vectors"
)

// The values of SPEC section 11.17 and Appendix C, written out here rather
// than read from package contract, so a change there fails the profile.
func TestTheContractHMACIsSection11_17(t *testing.T) {
	s := platform.ContractHMAC()
	want := reqhmac.Scheme{
		Label: "thehappie-platform-hmac/v1",
		Headers: reqhmac.Headers{
			Sender:    "X-Happie-App",
			Timestamp: "X-Happie-Timestamp",
			Nonce:     "X-Happie-Nonce",
			Signature: "X-Happie-Signature",
		},
		Skew: 60 * time.Second,
	}
	if s != want {
		t.Fatalf("ContractHMAC() = %+v", s)
	}
	if s != contract.Scheme() {
		t.Fatal("the profile's scheme is not package contract's")
	}
	if platform.ContractToPlatform != "to-platform" || platform.ContractToApp != "to-app" || platform.ContractSecretLen != 43 {
		t.Fatalf("directions %q %q, secret length %d", platform.ContractToPlatform, platform.ContractToApp, platform.ContractSecretLen)
	}
	if platform.ErrAnswerNonce.Error() != "answer_nonce" || !errors.Is(platform.ErrAnswerNonce, contract.ErrAnswerNonce) ||
		!errors.Is(platform.ErrContractSecret, contract.ErrSecret) {
		t.Fatal("the profile's errors are not package contract's")
	}
	// The contract's refusals are not id-v1's error names (section 11.10).
	if platform.ErrorCode(platform.ErrAnswerNonce) != "" || platform.ErrorCode(platform.ErrContractSecret) != "" {
		t.Fatal("a contract refusal has an id-v1 error name")
	}
}

// The platform's contract vectors (vectors/platform/contract-v1/
// signatures.json) under the profile's names: every answer check ends as
// it records, and every pair of secrets is accepted or refused as it says.
func TestTheProfileVerifiesEveryContractAnswerAsTheVectorsSay(t *testing.T) {
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	type signed struct {
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		Direction string `json:"direction"`
		App       string `json:"app"`
		Method    string `json:"method"`
		Target    string `json:"target"`
		Timestamp string `json:"timestamp"`
		Nonce     string `json:"nonce"`
		Body      string `json:"body"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
	}
	var f struct {
		Format      string   `json:"format"`
		Version     int      `json:"version"`
		Kind        string   `json:"kind"`
		Description string   `json:"description"`
		Label       string   `json:"label"`
		Headers     []string `json:"headers"`
		Skew        int      `json:"skew_seconds"`
		Requests    []signed `json:"requests"`
		Answers     []signed `json:"answers"`
		Checks      []struct {
			Name      string            `json:"name"`
			Headers   map[string]string `json:"headers"`
			Secrets   []string          `json:"secrets"`
			App       string            `json:"app"`
			Method    string            `json:"method"`
			Target    string            `json:"target"`
			SentNonce string            `json:"sent_nonce"`
			Body      string            `json:"body"`
			Now       int64             `json:"now"`
			Result    string            `json:"result"`
		} `json:"answer_checks"`
		Secrets []struct {
			Name    string `json:"name"`
			Current string `json:"current"`
			Next    string `json:"next"`
			Valid   bool   `json:"valid"`
		} `json:"secrets"`
	}
	// Strictly, as the kit's runners read: a member this test does not read
	// fails it, and so does anything after the value.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Fatal("more than one value")
	}
	if f.Format != "thehappie-contract/vectors" || f.Version != 1 || f.Kind != "signatures" || f.Description == "" {
		t.Fatalf("the file is %q version %d, kind %q", f.Format, f.Version, f.Kind)
	}
	s := platform.ContractHMAC()
	if f.Label != s.Label || strings.Join(f.Headers, ",") != strings.Join([]string{s.Headers.Sender, s.Headers.Timestamp, s.Headers.Nonce, s.Headers.Signature}, ",") ||
		time.Duration(f.Skew)*time.Second != s.Skew {
		t.Fatalf("the file's scheme is %q %v %d s", f.Label, f.Headers, f.Skew)
	}
	for _, r := range append(f.Requests, f.Answers...) {
		if got := s.Canonical(r.Direction, r.App, r.Method, r.Target, r.Timestamp, r.Nonce, []byte(r.Body)); got != r.Canonical {
			t.Errorf("%s: another canonical string", r.Name)
		}
		if got := s.Signature(r.Secret, r.Direction, r.App, r.Method, r.Target, r.Timestamp, r.Nonce, []byte(r.Body)); got != r.Signature {
			t.Errorf("%s: another signature", r.Name)
		}
	}
	for _, c := range f.Checks {
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		got := "ok"
		if err := platform.VerifyAnswer(h, c.Secrets, c.App, c.Method, c.Target, c.SentNonce, []byte(c.Body), time.Unix(c.Now, 0)); err != nil {
			got = err.Error()
		}
		if got != c.Result {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Result)
		}
	}
	for _, c := range f.Secrets {
		err := platform.CheckContractSecrets(c.Current, c.Next)
		if (err == nil) != c.Valid || (err != nil && !errors.Is(err, platform.ErrContractSecret)) {
			t.Errorf("secrets %s: %v, valid should be %v", c.Name, err, c.Valid)
		}
	}
	if len(f.Requests) != 4 || len(f.Answers) != 3 || len(f.Checks) != 10 || len(f.Secrets) != 7 {
		t.Fatalf("%d requests, %d answers, %d answer checks and %d secret cases", len(f.Requests), len(f.Answers), len(f.Checks), len(f.Secrets))
	}
}

// An answer the profile signs verifies for its request only.
func TestTheProfileSignsAnAnswerBoundToItsRequest(t *testing.T) {
	secret := strings.Repeat("A", platform.ContractSecretLen)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	req := http.Header{}
	if err := platform.ContractHMAC().Sign(req, secret, platform.ContractToPlatform, "wappie", http.MethodGet, "/contract/v1/feed?after=0", nil, now); err != nil {
		t.Fatal(err)
	}
	sent := req.Get("X-Happie-Nonce")
	body := []byte(`{"items":[]}`)
	h := http.Header{}
	platform.SignAnswer(h, secret, "wappie", http.MethodGet, "/contract/v1/feed?after=0", sent, body, now)
	if err := platform.VerifyAnswer(h, []string{secret}, "wappie", http.MethodGet, "/contract/v1/feed?after=0", sent, body, now); err != nil {
		t.Fatalf("its own answer: %v", err)
	}
	if err := platform.VerifyAnswer(req, []string{secret}, "wappie", http.MethodGet, "/contract/v1/feed?after=0", sent, body, now); !errors.Is(err, reqhmac.ErrBad) {
		t.Fatalf("the request's own signature taken as an answer: %v", err)
	}
	// Another one always: the random nonce may start with any character.
	other := "A" + sent[1:]
	if sent[0] == 'A' {
		other = "B" + sent[1:]
	}
	if err := platform.VerifyAnswer(h, []string{secret}, "wappie", http.MethodGet, "/contract/v1/feed?after=0", other, body, now); !errors.Is(err, platform.ErrAnswerNonce) {
		t.Fatalf("another request's answer: %v", err)
	}
}
