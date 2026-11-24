package contract_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// sampleQR is shaped as whatsmeow's MakeQRData writes a QR
// (https://wa.me/settings/linked_devices#, then comma-separated parts in
// base64), from made-up bytes, and 277 characters long, as every QR of the
// owner's relink measured.
func sampleQR(t *testing.T) string {
	t.Helper()
	part := func(seed byte) string {
		b := make([]byte, 32)
		for i := range b {
			b[i] = seed + byte(i)*7
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	head := "https://wa.me/settings/linked_devices#"
	tail := "," + part(1) + "," + part(2) + "," + part(3) + "," + part(4)
	ref := "2@" + strings.Repeat("Qk9HVVM", 20)
	qr := head + ref[:277-len(head)-len(tail)] + tail
	if len(qr) != 277 || !contract.ValidPairingQR(qr) {
		t.Fatalf("the sample is %d characters, valid %t", len(qr), contract.ValidPairingQR(qr))
	}
	return qr
}

var pairingNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func pairingBody(seq, qr, expires string) []byte {
	return []byte(`{"seq":` + seq + `,"qr":` + qr + `,"expires_at":` + expires + `}`)
}

// The pairing body is read strictly: exactly its three members, none null,
// none twice, none unknown, and expires_at in UTC with "Z".
func TestThePairingBodyIsReadStrictly(t *testing.T) {
	qr := `"` + sampleQR(t) + `"`
	at := `"2026-11-24T12:01:00Z"`
	var p contract.PairingQR
	if err := contract.DecodeStrict(pairingBody("1", qr, at), &p); err != nil {
		t.Fatal(err)
	}
	if p.Seq != 1 || p.QR != sampleQR(t) || !p.ExpiresAt.Equal(pairingNow.Add(time.Minute)) || p.ExpiresAt.Location() != time.UTC {
		t.Fatalf("decoded %d %v", p.Seq, p.ExpiresAt)
	}
	if err := p.ValidateAt(pairingNow); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"an unknown member":        `{"seq":1,"qr":` + qr + `,"expires_at":` + at + `,"code":"x"}`,
		"seq twice":                `{"seq":1,"seq":2,"qr":` + qr + `,"expires_at":` + at + `}`,
		"qr twice":                 `{"seq":1,"qr":` + qr + `,"qr":` + qr + `,"expires_at":` + at + `}`,
		"no seq":                   `{"qr":` + qr + `,"expires_at":` + at + `}`,
		"no qr":                    `{"seq":1,"expires_at":` + at + `}`,
		"no expires_at":            `{"seq":1,"qr":` + qr + `}`,
		"a null seq":               string(pairingBody("null", qr, at)),
		"a null qr":                string(pairingBody("1", "null", at)),
		"a null expires_at":        string(pairingBody("1", qr, "null")),
		"a seq in a string":        string(pairingBody(`"1"`, qr, at)),
		"a fractional seq":         string(pairingBody("1.5", qr, at)),
		"a member in another case": `{"Seq":1,"qr":` + qr + `,"expires_at":` + at + `}`,
		"a time at +00:00":         string(pairingBody("1", qr, `"2026-11-24T12:01:00+00:00"`)),
		"a time at another offset": string(pairingBody("1", qr, `"2026-11-24T13:01:00+01:00"`)),
		"a time with no zone":      string(pairingBody("1", qr, `"2026-11-24T12:01:00"`)),
		"a time in Unix seconds":   string(pairingBody("1", qr, "1795003260")),
		"null":                     `null`,
		"a list":                   `[]`,
		"two values":               string(pairingBody("1", qr, at)) + `{}`,
		"a lone surrogate in qr":   string(pairingBody("1", `"\ud800"`, at)),
	} {
		var p contract.PairingQR
		if err := contract.DecodeStrict([]byte(raw), &p); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The body's rules: a seq from 1, a QR of 1 to 512 characters of its
// alphabet, ASCII only, and an expires_at after the clock and at most 90 s
// after it.
func TestAPairingQRHoldsItsRules(t *testing.T) {
	good := contract.PairingQR{Seq: 1, QR: sampleQR(t), ExpiresAt: pairingNow.Add(time.Minute)}
	for name, p := range map[string]contract.PairingQR{
		"seq 1":                       good,
		"a rising seq":                {Seq: 7, QR: good.QR, ExpiresAt: good.ExpiresAt},
		"512 characters":              {Seq: 1, QR: strings.Repeat("A", contract.MaxPairingQR), ExpiresAt: good.ExpiresAt},
		"one character":               {Seq: 1, QR: "#", ExpiresAt: good.ExpiresAt},
		"every character of the set":  {Seq: 1, QR: "AZaz09+/=,@._:#-", ExpiresAt: good.ExpiresAt},
		"just after now":              {Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(time.Nanosecond)},
		"90 s after now":              {Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(contract.MaxPairingAhead)},
		"another zone, the same time": {Seq: 1, QR: good.QR, ExpiresAt: good.ExpiresAt.In(time.FixedZone("x", 3600))},
	} {
		if err := p.ValidateAt(pairingNow); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, p := range map[string]contract.PairingQR{
		"seq 0":                {Seq: 0, QR: good.QR, ExpiresAt: good.ExpiresAt},
		"a negative seq":       {Seq: -1, QR: good.QR, ExpiresAt: good.ExpiresAt},
		"an empty QR":          {Seq: 1, QR: "", ExpiresAt: good.ExpiresAt},
		"513 characters":       {Seq: 1, QR: strings.Repeat("A", contract.MaxPairingQR+1), ExpiresAt: good.ExpiresAt},
		"a space":              {Seq: 1, QR: "2@abc def", ExpiresAt: good.ExpiresAt},
		"a question mark":      {Seq: 1, QR: "https://wa.me/?x", ExpiresAt: good.ExpiresAt},
		"a non-ASCII letter":   {Seq: 1, QR: "2@abcé", ExpiresAt: good.ExpiresAt},
		"a line break":         {Seq: 1, QR: "2@abc\n", ExpiresAt: good.ExpiresAt},
		"a NUL":                {Seq: 1, QR: "2@abc\x00", ExpiresAt: good.ExpiresAt},
		"no expires_at":        {Seq: 1, QR: good.QR},
		"expires_at now":       {Seq: 1, QR: good.QR, ExpiresAt: pairingNow},
		"expires_at before":    {Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(-time.Second)},
		"91 s after now":       {Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(91 * time.Second)},
		"just over 90 s after": {Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(contract.MaxPairingAhead + time.Nanosecond)},
	} {
		err := p.ValidateAt(pairingNow)
		if !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if p.QR != "" && strings.Contains(err.Error(), p.QR) {
			t.Errorf("%s: the error carries the QR", name)
		}
	}
	// Validate judges the shape alone, never the clock.
	if err := (contract.PairingQR{Seq: 1, QR: good.QR, ExpiresAt: pairingNow.Add(-time.Hour)}).Validate(); err != nil {
		t.Errorf("Validate judged the clock: %v", err)
	}
}

// The body reaches the wire with exactly its three members, expires_at in
// UTC with "Z" whatever its zone, and reads back the same.
func TestAPairingQRWritesItsThreeMembersInUTC(t *testing.T) {
	p := contract.PairingQR{Seq: 3, QR: sampleQR(t), ExpiresAt: pairingNow.Add(time.Minute + 500*time.Millisecond).In(time.FixedZone("x", -3*3600))}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"seq":3,"qr":"` + p.QR + `","expires_at":"2026-11-24T12:01:00.5Z"}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
	var back contract.PairingQR
	if err := contract.DecodeStrict(b, &back); err != nil || back.Seq != 3 || back.QR != p.QR || !back.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatalf("read back %d %v: %v", back.Seq, back.ExpiresAt, err)
	}
}

// A QR is never printed or logged, whatever the verb or handler.
func TestAPairingQRIsNeverPrinted(t *testing.T) {
	p := contract.PairingQR{Seq: 2, QR: sampleQR(t), ExpiresAt: pairingNow.Add(time.Minute)}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("pairing", "p", p)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("pairing", "p", p, "ptr", &p)
	secret := p.QR[len(p.QR)-40:]
	for _, s := range []string{
		fmt.Sprintf("%v %+v %#v %s %q", p, p, p, p, p),
		fmt.Sprintf("%v %+v %#v %s", &p, &p, &p, &p),
		fmt.Sprint(p, []contract.PairingQR{p}),
		logged.String(),
	} {
		if strings.Contains(s, secret) {
			t.Fatalf("the QR printed: %s", s)
		}
	}
	if !strings.Contains(logged.String(), "seq=2") || !strings.Contains(fmt.Sprint(p), "Seq: 2") {
		t.Errorf("the seq is not shown: %s %s", logged.String(), fmt.Sprint(p))
	}
}

// The pairing answer is exactly {"accepted": a boolean}.
func TestThePairingAnswerIsReadStrictly(t *testing.T) {
	for raw, want := range map[string]bool{`{"accepted":true}`: true, `{"accepted":false}`: false} {
		var a contract.PairingAnswer
		if err := json.Unmarshal([]byte(raw), &a); err != nil || a.Accepted != want {
			t.Errorf("%s: %v %v", raw, a.Accepted, err)
		}
	}
	for _, raw := range []string{
		`{}`, `{"accepted":null}`, `{"accepted":"true"}`, `{"accepted":1}`, `{"accepted":true,"seq":1}`,
		`{"accepted":true,"accepted":false}`, `{"Accepted":true}`, `null`, `[]`, `true`,
	} {
		a := contract.PairingAnswer{Accepted: true}
		if err := json.Unmarshal([]byte(raw), &a); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

const relinkID = "0199c3a0-0000-7000-8000-000000000042"

// pairingPlatform answers each pairing call with answer, signed for the
// request, and records what came.
type pairingPlatform struct {
	answer   string
	unsigned bool
	method   string
	path     string
	body     []byte
	calls    int
}

func (pp *pairingPlatform) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pp.calls++
		pp.method, pp.path = r.Method, r.URL.Path
		pp.body, _ = io.ReadAll(r.Body)
		if !pp.unsigned {
			contract.SignAnswer(w.Header(), clientSecret, "wappie", r.Method, r.URL.RequestURI(), r.Header.Get(contract.HeaderNonce), []byte(pp.answer), time.Now())
		}
		_, _ = w.Write([]byte(pp.answer))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// PutPairing sends the body to the command's pairing route and returns the
// platform's verified answer: true held, false with no error not held but
// delivered, a signed refusal a *Refusal, and anything else ErrUnverified.
func TestPutPairingReturnsThePlatformsVerifiedAnswer(t *testing.T) {
	p := contract.PairingQR{Seq: 1, QR: sampleQR(t), ExpiresAt: time.Now().Add(time.Minute)}
	pp := &pairingPlatform{answer: `{"accepted":true}`}
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: pp.serve(t).URL}
	ok, err := c.PutPairing(t.Context(), relinkID, p)
	if err != nil || !ok {
		t.Fatalf("held: %t %v", ok, err)
	}
	if pp.method != http.MethodPut || pp.path != "/contract/v1/commands/"+relinkID+"/pairing" {
		t.Fatalf("sent %s %s", pp.method, pp.path)
	}
	var sent contract.PairingQR
	if err := contract.DecodeStrict(pp.body, &sent); err != nil || sent.Seq != 1 || sent.QR != p.QR || !sent.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatalf("the body %s: %v", pp.body, err)
	}
	if len(pp.body) > contract.PairingBodyLimit {
		t.Fatalf("a %d-byte body", len(pp.body))
	}

	pp.answer = `{"accepted":false}`
	if ok, err := c.PutPairing(t.Context(), relinkID, p); err != nil || ok {
		t.Fatalf("not held: %t %v", ok, err)
	}

	for _, code := range []string{"not_found", "invalid_request"} {
		pp.answer = `{"code":"` + code + `","message":"refused"}`
		ok, err := c.PutPairing(t.Context(), relinkID, p)
		var r *contract.Refusal
		if !errors.As(err, &r) || r.Code != code || ok {
			t.Fatalf("%s: %t %v", code, ok, err)
		}
	}

	for _, answer := range []string{`{}`, `{"accepted":"yes"}`, `{"accepted":true,"extra":1}`, `null`, `not json`} {
		pp.answer = answer
		if ok, err := c.PutPairing(t.Context(), relinkID, p); !errors.Is(err, contract.ErrUnverified) || ok {
			t.Errorf("%s: %t %v", answer, ok, err)
		} else if strings.Contains(err.Error(), p.QR[len(p.QR)-40:]) {
			t.Errorf("%s: the error carries the QR", answer)
		}
	}

	pp.answer, pp.unsigned = `{"accepted":true}`, true
	if ok, err := c.PutPairing(t.Context(), relinkID, p); !errors.Is(err, contract.ErrUnverified) || ok {
		t.Fatalf("an unsigned answer: %t %v", ok, err)
	}
}

// PutPairing sends nothing for an id that is no UUID or a body that fails
// its rules on the app's clock, and its errors carry neither the QR nor the
// id.
func TestPutPairingSendsNothingThatFailsItsRules(t *testing.T) {
	pp := &pairingPlatform{answer: `{"accepted":true}`}
	now := pairingNow
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: pp.serve(t).URL, Now: func() time.Time { return now }}
	qr := sampleQR(t)
	good := contract.PairingQR{Seq: 1, QR: qr, ExpiresAt: now.Add(time.Minute)}
	for name, tc := range map[string]struct {
		id string
		p  contract.PairingQR
	}{
		"an id that is no UUID":      {"../../feed", good},
		"an uppercase id":            {strings.ToUpper(relinkID), good},
		"seq 0":                      {relinkID, contract.PairingQR{Seq: 0, QR: qr, ExpiresAt: good.ExpiresAt}},
		"a QR out of the set":        {relinkID, contract.PairingQR{Seq: 1, QR: qr + " ", ExpiresAt: good.ExpiresAt}},
		"expired on the app's clock": {relinkID, contract.PairingQR{Seq: 1, QR: qr, ExpiresAt: now}},
		"too far on the app's clock": {relinkID, contract.PairingQR{Seq: 1, QR: qr, ExpiresAt: now.Add(2 * time.Minute)}},
	} {
		ok, err := c.PutPairing(t.Context(), tc.id, tc.p)
		if !errors.Is(err, contract.ErrInvalid) || ok {
			t.Errorf("%s: %t %v", name, ok, err)
		} else if strings.Contains(err.Error(), qr[len(qr)-40:]) {
			t.Errorf("%s: the error carries the QR", name)
		}
	}
	if pp.calls != 0 {
		t.Fatalf("%d calls sent", pp.calls)
	}
}

// A pairing call that never reached the platform names its route, never
// the command's id or the QR.
func TestAPairingTransportErrorNamesItsRouteAlone(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: base}
	qr := sampleQR(t)
	_, err := c.PutPairing(t.Context(), relinkID, contract.PairingQR{Seq: 1, QR: qr, ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil || strings.Contains(err.Error(), relinkID) || strings.Contains(err.Error(), qr[len(qr)-40:]) ||
		!strings.Contains(err.Error(), "PUT /contract/v1/commands/{id}/pairing") {
		t.Fatalf("a refused connection: %v", err)
	}
}
