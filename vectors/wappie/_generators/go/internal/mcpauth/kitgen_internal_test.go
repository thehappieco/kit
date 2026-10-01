// Vector generator for github.com/thehappieco/kit, vectors/wappie/golden/reqhmac-go.json.
//
// This file is not part of Wappie. vectors/wappie/_generators/run.sh copies it
// into a throwaway extraction of Wappie at a recorded commit and runs it there.
// It is an internal test so it can call the unexported helpers of hmac.go
// (readSignedHeaders, signedBy, the replay cache and sign) exactly as the
// server does. The one random draw (sign's nonce) is seeded with
// testing/cryptotest.SetGlobalRandom and recorded.

package mcpauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"
)

type kgFile struct {
	Format      string   `json:"format"`
	Module      string   `json:"module"`
	Profile     string   `json:"profile"`
	GeneratedBy kgSource `json:"generated_by"`
	Note        string   `json:"note"`
	Cases       []kgCase `json:"cases"`
}

type kgSource struct {
	Lang       string `json:"lang"`
	Source     string `json:"source"`
	Toolchain  string `json:"toolchain"`
	Randomness string `json:"randomness"`
	Generator  string `json:"generator"`
}

type kgCase struct {
	ID    string         `json:"id"`
	Op    string         `json:"op"`
	Langs []string       `json:"langs,omitempty"`
	In    map[string]any `json:"in"`
	Out   map[string]any `json:"out,omitempty"`
	Error string         `json:"error,omitempty"`
	Note  string         `json:"note,omitempty"`
}

func TestKitGenRequestHMAC(t *testing.T) {
	dir := os.Getenv("KITGEN_OUT")
	if dir == "" {
		t.Skip("KITGEN_OUT is not set; this generator runs only from the kit's run.sh")
	}
	var cases []kgCase
	seen := map[string]bool{}
	add := func(c kgCase) {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
		cases = append(cases, c)
	}
	b64 := base64.StdEncoding.EncodeToString

	// Signatures. The canonical string is the generator's rendering of the
	// scheme; it is recorded only after the HMAC over it is checked against
	// what Signature returned, so it is proven, not assumed.
	type sig struct {
		id, secret, direction, sender, method, target, timestamp, nonce string
		body                                                            []byte
	}
	const secret = "wappie-test-relay-secret-0123456789abcdefghij"
	contractBody := []byte(`{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`)
	binary := make([]byte, 1024)
	for i := range binary {
		binary[i] = byte(i * 31)
	}
	sigs := []sig{
		{"contract-to-reader", secret, DirectionToReader, "enclave", "POST", "/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/prepare", "1790300000", "BBBBBBBBBBBBBBBBBBBBBB", contractBody},
		{"contract-to-go", secret, DirectionToGo, "enclave", "GET", "/v1/mcp/enclave/cimd?url=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata", "1790300000", "CCCCCCCCCCCCCCCCCCCCCC", nil},
		{"method-lowercase", secret, DirectionToGo, "enclave", "get", "/x", "1", "n", nil},
		{"method-uppercase", secret, DirectionToGo, "enclave", "GET", "/x", "1", "n", nil},
		{"method-mixed", secret, DirectionToReader, "enclave", "Patch", "/v1/x", "1790300001", "DDDDDDDDDDDDDDDDDDDDDD", []byte("{}")},
		{"empty-body-vs-nil", secret, DirectionToReader, "enclave", "POST", "/v1/x", "1790300001", "DDDDDDDDDDDDDDDDDDDDDD", []byte{}},
		{"binary-body", secret, DirectionToReader, "staging", "PUT", "/internal/state", "1790300002", "EEEEEEEEEEEEEEEEEEEEEE", binary},
		{"query-and-escapes", secret, DirectionToGo, "enclave", "GET", "/v1/mcp/enclave/x?a=1&b=%2F%20&c=%C3%A9", "1790300003", "abcdefghijklmnopqrstuv", nil},
		{"root-target", secret, DirectionToGo, "enclave", "DELETE", "/", "9999999999", "-_-_-_-_-_-_-_-_-_-_-_", nil},
		{"multibyte-secret", "segredo-çãø-🔑-0123456789", DirectionToReader, "enclave", "POST", "/internal/x", "1790300004", "FFFFFFFFFFFFFFFFFFFFFF", []byte("olá")},
		{"empty-secret", "", DirectionToReader, "enclave", "POST", "/internal/x", "1790300004", "FFFFFFFFFFFFFFFFFFFFFF", nil},
		{"long-secret", strings.Repeat("k", 200), DirectionToGo, "r", "POST", "/internal/x", "1790300005", "GGGGGGGGGGGGGGGGGGGGGG", []byte("x")},
		{"sender-with-dash", secret, DirectionToGo, "reader-2", "POST", "/v1/mcp/enclave/connections/a/revoke", "1790300006", "HHHHHHHHHHHHHHHHHHHHHH", nil},
		{"18-digit-timestamp", secret, DirectionToGo, "enclave", "GET", "/", "100000000000000000", "IIIIIIIIIIIIIIIIIIIIII", nil},
	}
	for _, s := range sigs {
		got := Signature(s.secret, s.direction, s.sender, s.method, s.target, s.timestamp, s.nonce, s.body)
		sum := sha256.Sum256(s.body)
		canonical := strings.Join([]string{"wappie-mcp-hmac/v1", s.direction, s.sender, strings.ToUpper(s.method), s.target, s.timestamp, s.nonce, hex.EncodeToString(sum[:])}, "\n")
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write([]byte(canonical))
		if "v1="+hex.EncodeToString(mac.Sum(nil)) != got {
			t.Fatalf("%s: the generator's canonical string does not reproduce Signature", s.id)
		}
		add(kgCase{ID: "reqhmac/signature/" + s.id, Op: "reqhmac.signature",
			In: map[string]any{"secret": s.secret, "direction": s.direction, "sender": s.sender, "method": s.method,
				"target": s.target, "timestamp": s.timestamp, "nonce": s.nonce, "body_b64": b64(s.body)},
			Out: map[string]any{"signature": got, "canonical": canonical, "body_sha256_hex": hex.EncodeToString(sum[:])}})
	}

	// Header grammar and skew, through readSignedHeaders.
	const now = int64(1_790_300_000)
	goodSig := "v1=" + strings.Repeat("0123456789abcdef", 4)
	goodNonce := strings.Repeat("A", 22)
	headers := func(ts, nonce, signature []string) map[string][]string {
		h := map[string][]string{}
		if ts != nil {
			h[HeaderTimestamp] = ts
		}
		if nonce != nil {
			h[HeaderNonce] = nonce
		}
		if signature != nil {
			h[HeaderSignature] = signature
		}
		return h
	}
	one := func(s string) []string { return []string{s} }
	type read struct {
		id string
		h  map[string][]string
		at int64
	}
	reads := []read{
		{"ok", headers(one("1790300000"), one(goodNonce), one(goodSig)), now},
		{"ok-skew-plus-60", headers(one("1790300060"), one(goodNonce), one(goodSig)), now},
		{"ok-skew-minus-60", headers(one("1790299940"), one(goodNonce), one(goodSig)), now},
		{"stale-plus-61", headers(one("1790300061"), one(goodNonce), one(goodSig)), now},
		{"stale-minus-61", headers(one("1790299939"), one(goodNonce), one(goodSig)), now},
		{"timestamp-empty", headers(one(""), one(goodNonce), one(goodSig)), now},
		{"timestamp-zero", headers(one("0"), one(goodNonce), one(goodSig)), now},
		{"timestamp-leading-zero", headers(one("01"), one(goodNonce), one(goodSig)), now},
		{"timestamp-18-digits", headers(one("100000000000000000"), one(goodNonce), one(goodSig)), now},
		{"timestamp-19-digits", headers(one("1000000000000000000"), one(goodNonce), one(goodSig)), now},
		{"timestamp-plus-sign", headers(one("+1790300000"), one(goodNonce), one(goodSig)), now},
		{"timestamp-minus-sign", headers(one("-1790300000"), one(goodNonce), one(goodSig)), now},
		{"timestamp-space", headers(one(" 1790300000"), one(goodNonce), one(goodSig)), now},
		{"timestamp-decimal", headers(one("1790300000.5"), one(goodNonce), one(goodSig)), now},
		{"timestamp-missing", headers(nil, one(goodNonce), one(goodSig)), now},
		{"timestamp-twice", headers([]string{"1790300000", "1790300000"}, one(goodNonce), one(goodSig)), now},
		{"nonce-21", headers(one("1790300000"), one(goodNonce[:21]), one(goodSig)), now},
		{"nonce-23", headers(one("1790300000"), one(goodNonce+"A"), one(goodSig)), now},
		{"nonce-base64url-alphabet", headers(one("1790300000"), one("azAZ09-_azAZ09-_azAZ09"), one(goodSig)), now},
		{"nonce-padding", headers(one("1790300000"), one(goodNonce[:20]+"=="), one(goodSig)), now},
		{"nonce-standard-alphabet", headers(one("1790300000"), one(goodNonce[:20]+"+/"), one(goodSig)), now},
		{"nonce-missing", headers(one("1790300000"), nil, one(goodSig)), now},
		{"nonce-twice", headers(one("1790300000"), []string{goodNonce, goodNonce}, one(goodSig)), now},
		{"signature-wrong-prefix", headers(one("1790300000"), one(goodNonce), one("v2="+goodSig[3:])), now},
		{"signature-no-prefix", headers(one("1790300000"), one(goodNonce), one(goodSig[3:])), now},
		{"signature-uppercase-hex", headers(one("1790300000"), one(goodNonce), one(strings.ToUpper(goodSig[:3])+strings.ToUpper(goodSig[3:]))), now},
		{"signature-uppercase-digest", headers(one("1790300000"), one(goodNonce), one("v1="+strings.ToUpper(goodSig[3:]))), now},
		{"signature-63-digits", headers(one("1790300000"), one(goodNonce), one(goodSig[:66])), now},
		{"signature-65-digits", headers(one("1790300000"), one(goodNonce), one(goodSig+"0")), now},
		{"signature-missing", headers(one("1790300000"), one(goodNonce), nil), now},
		{"signature-twice", headers(one("1790300000"), one(goodNonce), []string{goodSig, goodSig}), now},
		{"empty-value-twice", headers([]string{"", "1790300000"}, one(goodNonce), one(goodSig)), now},
	}
	for _, r := range reads {
		h := http.Header{}
		for name, values := range r.h {
			for _, v := range values {
				h.Add(name, v)
			}
		}
		in := map[string]any{"headers": r.h, "now": r.at}
		got, err := readSignedHeaders(h, time.Unix(r.at, 0))
		if err != nil {
			add(kgCase{ID: "reqhmac/read/" + r.id, Op: "reqhmac.read", In: in, Error: err.Error()})
			continue
		}
		add(kgCase{ID: "reqhmac/read/" + r.id, Op: "reqhmac.read", In: in,
			Out: map[string]any{"timestamp": got.timestamp, "unix": got.unix, "nonce": got.nonce, "signature": got.signature}})
	}

	// signedBy over one, two and no secrets.
	right := Signature(secret, DirectionToGo, "enclave", "POST", "/v1/x", "1790300000", goodNonce, []byte("b"))
	for _, c := range []struct {
		id        string
		secrets   []string
		signature string
		direction string
	}{
		{"one-right", []string{secret}, right, DirectionToGo},
		{"next-then-current", []string{"another-secret", secret}, right, DirectionToGo},
		{"current-then-next", []string{secret, "another-secret"}, right, DirectionToGo},
		{"only-wrong", []string{"another-secret"}, right, DirectionToGo},
		{"none", []string{}, right, DirectionToGo},
		{"same-secret-twice", []string{secret, secret}, right, DirectionToGo},
		{"other-direction", []string{secret}, right, DirectionToReader},
		{"flipped-digit", []string{secret}, right[:len(right)-1] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", right[len(right)-1])+1)%16]), DirectionToGo},
	} {
		got := signedHeaders{timestamp: "1790300000", unix: 1790300000, nonce: goodNonce, signature: c.signature}
		ok := signedBy(c.secrets, got, c.direction, "enclave", "POST", "/v1/x", []byte("b"))
		add(kgCase{ID: "reqhmac/signed-by/" + c.id, Op: "reqhmac.signed_by",
			In: map[string]any{"secrets": c.secrets, "timestamp": got.timestamp, "nonce": got.nonce, "signature": got.signature,
				"direction": c.direction, "sender": "enclave", "method": "POST", "target": "/v1/x", "body_b64": b64([]byte("b"))},
			Out: map[string]any{"ok": ok}})
	}
	if c := cases[len(cases)-1]; c.Out["ok"] != false {
		t.Fatal("a flipped signature was accepted")
	}

	// The replay cache, as a sequence.
	type admit = map[string]any
	replay := func(id string, capacity int, steps []admit) {
		c := newReplayCache(capacity)
		var results []any
		for _, s := range steps {
			err := c.admit(s["direction"].(string), s["sender"].(string), s["nonce"].(string), s["timestamp"].(int64), time.Unix(s["now"].(int64), 0))
			switch {
			case err == nil:
				results = append(results, nil)
			case errors.Is(err, errReplay), errors.Is(err, errReplayFull):
				results = append(results, err.Error())
			default:
				t.Fatal(err)
			}
		}
		// The replay cache and sign are server-side: the kit has them in Go only.
		add(kgCase{ID: "reqhmac/replay/" + id, Op: "reqhmac.replay", Langs: []string{"go"},
			In:  map[string]any{"capacity": capacity, "lifetime_seconds": int64(replayLifetime / time.Second), "steps": steps},
			Out: map[string]any{"results": results, "len": len(c.seen)}})
	}
	step := func(direction, sender, nonce string, ts, at int64) admit {
		return admit{"direction": direction, "sender": sender, "nonce": nonce, "timestamp": ts, "now": at}
	}
	replay("wappie-internal-test", 2, []admit{
		step(DirectionToGo, "enclave", "a", now, now),
		step(DirectionToGo, "enclave", "a", now, now),
		step(DirectionToReader, "enclave", "a", now, now),
		step(DirectionToGo, "staging", "a", now, now),
		step(DirectionToGo, "staging", "a", now+61, now+61),
		step(DirectionToGo, "enclave", "a", now+61, now+61),
	})
	replay("lifetime-edge", 4, []admit{
		step(DirectionToGo, "enclave", "n1", now, now),
		step(DirectionToGo, "enclave", "n1", now, now+60),
		step(DirectionToGo, "enclave", "n1", now, now+61),
		step(DirectionToGo, "enclave", "n2", now-60, now),
		step(DirectionToGo, "enclave", "n2", now-60, now+1),
	})
	replay("full-then-drains", 1, []admit{
		step(DirectionToGo, "enclave", "n1", now, now),
		step(DirectionToGo, "enclave", "n2", now, now),
		step(DirectionToGo, "enclave", "n1", now, now+30),
		step(DirectionToGo, "enclave", "n2", now+61, now+61),
	})

	// sign, with the nonce drawn under a recorded seed.
	for i, c := range []struct {
		method, url string
		body        []byte
	}{
		{"POST", "https://mcp.wappie.thehappie.co:8443/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/prepare", contractBody},
		{"GET", "https://mcp.wappie.thehappie.co:8443/internal/state?since=4&x=%2F", nil},
	} {
		seed := uint64(100 + i)
		cryptotest.SetGlobalRandom(t, seed)
		req := httptest.NewRequest(c.method, c.url, bytes.NewReader(c.body))
		req.Header = http.Header{}
		if err := sign(req, secret, "enclave", c.body, time.Unix(now, 0)); err != nil {
			t.Fatal(err)
		}
		h := map[string]string{}
		for _, name := range []string{HeaderReader, HeaderTimestamp, HeaderNonce, HeaderSignature} {
			h[name] = req.Header.Get(name)
		}
		add(kgCase{ID: "reqhmac/sign/" + strconv.Itoa(i), Op: "reqhmac.sign", Langs: []string{"go"},
			In: map[string]any{"secret": secret, "direction": DirectionToReader, "sender": "enclave", "method": c.method,
				"target": req.URL.RequestURI(), "body_b64": b64(c.body), "now": now, "seed": seed},
			Out: map[string]any{"headers": h}})
	}

	f := kgFile{
		Format:  "thehappieco-kit-vectors/1",
		Module:  "reqhmac",
		Profile: "wappie",
		GeneratedBy: kgSource{
			Lang:       "go",
			Source:     "github.com/thehappieco/wappie@" + os.Getenv("KITGEN_COMMIT") + " internal/mcpauth/hmac.go",
			Toolchain:  runtime.Version(),
			Randomness: "testing/cryptotest.SetGlobalRandom, reset to in.seed before each sign",
			Generator:  "vectors/wappie/_generators/go/internal/mcpauth/kitgen_internal_test.go",
		},
		Note: "Wappie's request HMAC (wappie-mcp-hmac/v1), captured from internal/mcpauth. The secrets are fixture material. " +
			"Errors are the codes hmac.go returns (Wappie logs them).",
		Cases: cases,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(dir, "reqhmac-go.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("refusing to overwrite a vector file: %v", err)
	}
	defer fh.Close()
	if _, err := fh.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote reqhmac-go.json (%d cases)", len(cases))
}
