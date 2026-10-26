package contract_test

// The generator of the contract's vectors (SPEC sections 11.17 and 11.18,
// vectors/platform/contract-v1): the platform's
// internal/contract/contractvec at ee45e3a, which writes the first four
// files, as test code over this package, and the kit's own generator of
// the five files v0.9.0 adds (contractvec_tokens_test.go).
// TestTheKitWritesTheContractVectorsAgain compares what it writes with the
// frozen files byte for byte in every test run: they are a pure function
// of this package, so a file that comes out differently is a regression of
// the kit.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/reqhmac"
)

// File is one vector file.
type File struct {
	Name string
	Data []byte
}

// Format names the files' format.
const Format = "thehappie-contract/vectors"

// The fixed material: made-up secrets that protect nothing, and a moment.
const (
	SecretA = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" //nolint:gosec // G101: a made-up vector secret that protects nothing
	SecretB = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8" //nolint:gosec // G101: a made-up vector secret that protects nothing
	NonceA  = "AAECAwQFBgcICQoLDA0ODw"
	NonceB  = "EBESExQVFhcYGRobHB0eHw"
)

// Now is the moment every vector is made at and checked against.
var Now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

// Generate makes every file.
func Generate() ([]File, error) {
	var files []File
	for _, gen := range []struct {
		name string
		make func() (any, error)
	}{
		{"signatures.json", signatures},
		{"labels.json", labels},
		{"wire.json", wire},
		{"wire-item-ids.json", wireItemIDs},
		// Kit v0.9.0: the token part, ordinal and tokens on items, and stop.
		{"tokens.json", tokensFile},
		{"reading-keys.json", readingKeysFile},
		{"wire-tokens.json", wireTokens},
		{"wire-snapshot-tokens.json", wireSnapshotTokens},
		{"wire-events-stop.json", wireEventsStop},
	} {
		v, err := gen.make()
		if err != nil {
			return nil, err
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		data, err := inlineBig(b.Bytes())
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: gen.name, Data: data})
	}
	return files, nil
}

// Request is one signed request.
type Request struct {
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

// AnswerCheck is one answer an app checks against the request it sent.
type AnswerCheck struct {
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
}

// SecretCheck is one pair of secrets and whether CheckSecrets accepts it.
type SecretCheck struct {
	Name    string `json:"name"`
	Current string `json:"current"`
	Next    string `json:"next"`
	Valid   bool   `json:"valid"`
}

// Signatures is signatures.json.
type Signatures struct {
	Format      string        `json:"format"`
	Version     int           `json:"version"`
	Kind        string        `json:"kind"`
	Description string        `json:"description"`
	Label       string        `json:"label"`
	Headers     []string      `json:"headers"`
	SkewSeconds int           `json:"skew_seconds"`
	Requests    []Request     `json:"requests"`
	Answers     []Request     `json:"answers"`
	Checks      []AnswerCheck `json:"answer_checks"`
	Secrets     []SecretCheck `json:"secrets"`
}

func signatures() (any, error) {
	s := contract.Scheme()
	ts := "1760356800"
	req := func(name, secret, direction, app, method, target, nonce, body string) Request {
		return Request{
			Name: name, Secret: secret, Direction: direction, App: app, Method: method, Target: target,
			Timestamp: ts, Nonce: nonce, Body: body,
			Canonical: s.Canonical(direction, app, method, target, ts, nonce, []byte(body)),
			Signature: s.Signature(secret, direction, app, method, target, ts, nonce, []byte(body)),
		}
	}
	out := Signatures{
		Format: Format, Version: 1, Kind: "signatures", Label: contract.Label,
		Description: "Requests to the platform (to-platform) and answers to the app (to-app), signed with the kit's reqhmac under the platform's label; the key is the secret's 43 characters as written. An app checks an answer with contract.VerifyAnswer: answer_checks gives the result for each case, 'ok' or the refusal's code.",
		Headers:     []string{contract.HeaderApp, contract.HeaderTimestamp, contract.HeaderNonce, contract.HeaderSignature},
		SkewSeconds: int(contract.Skew / time.Second),
		Requests: []Request{
			req("subscribe at a sign-in", SecretA, contract.ToPlatform, "wappie", "PUT", "/contract/v1/accounts/0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20", NonceA, ""),
			req("the feed, a target with a query", SecretA, contract.ToPlatform, "wappie", "GET", "/contract/v1/feed?after=41&wait=25", NonceA, ""),
			req("a snapshot, from mailie", SecretB, contract.ToPlatform, "mailie", "PUT", "/contract/v1/workspaces/01a034b7-d09c-7121-b7f8-41f210a9244a/access", NonceB, `{"v":1,"snapshot_seq":1760356800000,"items":[]}`),
			req("a lowercase method is signed in upper case", SecretA, contract.ToPlatform, "wappie", "post", "/contract/v1/events", NonceA, `{"events":[]}`),
		},
		Answers: []Request{
			req("the answer to a subscription", SecretA, contract.ToApp, "wappie", "PUT", "/contract/v1/accounts/0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20", NonceA, `{"v":1}`),
			req("the answer to the feed", SecretA, contract.ToApp, "wappie", "GET", "/contract/v1/feed?after=41&wait=25", NonceA, `{"items":[]}`),
			req("a signed refusal", SecretB, contract.ToApp, "mailie", "PUT", "/contract/v1/workspaces/01a034b7-d09c-7121-b7f8-41f210a9244a/access", NonceB, `{"code":"not_found","message":"no such workspace"}`),
		},
	}

	// The checks an app makes of an answer.
	target := "/contract/v1/feed?after=41&wait=25"
	body := `{"items":[]}`
	answer := func(secret, direction, app, method, tgt, nonce, b string, at time.Time) map[string]string {
		stamp := strconv.FormatInt(at.Unix(), 10)
		return map[string]string{
			contract.HeaderTimestamp: stamp,
			contract.HeaderNonce:     nonce,
			contract.HeaderSignature: s.Signature(secret, direction, app, method, tgt, stamp, nonce, []byte(b)),
		}
	}
	check := func(name string, h map[string]string, secrets []string, sent string, b string) AnswerCheck {
		c := AnswerCheck{Name: name, Headers: h, Secrets: secrets, App: "wappie", Method: "GET", Target: target, SentNonce: sent, Body: b, Now: Now.Unix()}
		hdr := http.Header{}
		for k, v := range h {
			hdr.Set(k, v)
		}
		switch err := contract.VerifyAnswer(hdr, secrets, c.App, c.Method, c.Target, sent, []byte(b), Now); {
		case err == nil:
			c.Result = "ok"
		case errors.Is(err, contract.ErrAnswerNonce), errors.Is(err, reqhmac.ErrBad), errors.Is(err, reqhmac.ErrStale), errors.Is(err, reqhmac.ErrMissing):
			c.Result = err.Error()
		default:
			c.Result = "error"
		}
		return c
	}
	good := answer(SecretA, contract.ToApp, "wappie", "GET", target, NonceA, body, Now)
	missing := map[string]string{contract.HeaderTimestamp: good[contract.HeaderTimestamp], contract.HeaderNonce: NonceA}
	decoded, _ := base64.RawURLEncoding.DecodeString(SecretA)
	out.Checks = []AnswerCheck{
		check("the answer to the app's own request", good, []string{SecretA}, NonceA, body),
		check("during a rotation, the next secret first", good, []string{SecretB, SecretA}, NonceA, body),
		check("a swapped nonce: the answer to another request", answer(SecretA, contract.ToApp, "wappie", "GET", target, NonceB, body, Now), []string{SecretA}, NonceA, body),
		check("a request's signature presented as an answer", answer(SecretA, contract.ToPlatform, "wappie", "GET", target, NonceA, body, Now), []string{SecretA}, NonceA, body),
		check("an answer signed for the other app", answer(SecretA, contract.ToApp, "mailie", "GET", target, NonceA, body, Now), []string{SecretA}, NonceA, body),
		check("another body", good, []string{SecretA}, NonceA, `{"items":null}`),
		check("the key taken as the 32 decoded bytes", good, []string{string(decoded)}, NonceA, body),
		check("another app's secret", good, []string{SecretB}, NonceA, body),
		check("a minute and a second late", answer(SecretA, contract.ToApp, "wappie", "GET", target, NonceA, body, Now.Add(-contract.Skew-time.Second)), []string{SecretA}, NonceA, body),
		check("unsigned", missing, []string{SecretA}, NonceA, body),
	}
	out.Secrets = []SecretCheck{
		{Name: "a secret", Current: SecretA, Valid: true},
		{Name: "a rotation", Current: SecretA, Next: SecretB, Valid: true},
		{Name: "empty", Valid: false},
		{Name: "the next equal to the current", Current: SecretA, Next: SecretA, Valid: false},
		{Name: "42 characters", Current: SecretA[:42], Valid: false},
		{Name: "padded", Current: SecretA[:42] + "=", Valid: false},
		{Name: "not the canonical encoding of 32 bytes", Current: SecretA[:42] + "B", Valid: false},
	}
	for _, c := range out.Secrets {
		if (contract.CheckSecrets(c.Current, c.Next) == nil) != c.Valid {
			return nil, errors.New("contractvec: a secret case disagrees with CheckSecrets: " + c.Name)
		}
	}
	return out, nil
}

// LabelCase is one raw name and what CleanLabel makes of it.
type LabelCase struct {
	Raw   string `json:"raw"`
	Clean string `json:"clean"`
}

// HintCase is one hint and whether ValidHint accepts it.
type HintCase struct {
	Hint  string `json:"hint"`
	Valid bool   `json:"valid"`
}

// Labels is labels.json.
type Labels struct {
	Format      string      `json:"format"`
	Version     int         `json:"version"`
	Kind        string      `json:"kind"`
	Description string      `json:"description"`
	Clean       []LabelCase `json:"clean"`
	Hints       []HintCase  `json:"hints"`
}

func labels() (any, error) {
	raws := []string{
		"Vendas", "  Vendas  ", "Suporte   24h",
		"+55 11 91234-5678", "+55 (11) 91234-5678", "11.91234.5678", "Tel: (11) 91234-5678",
		"Loja 11912345678", "Loja 1 - 12345", "Loja 1 - 123456", "Sala 12, ramal 1234567",
		"Filial 1234 567", "Número 2 e 3 de 1234567890",
		"vendas@loja.com", "Vendas (j@x)",
		"Ven\u202edas", "Ven\u200bdas", "Ven\x00das\x7f\u0085",
		"", "\u200b",
		// Separators, invisible splitters, other scripts' digits and
		// characters that read as "@" (the review of 2026-10-13).
		"+55\u201311\u201391234\u20135678", "+55/11/91234/5678", "55_11_91234_5678", "11,91234,5678",
		"119\u00b71234\u00b75678", "(11) 91234\u20115678", "11 91234\u00ad5678", "11 912\u034f34 5678",
		"\uff11\uff11\uff19\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18", "\u0661\u0661\u0669\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668",
		"joao\uff20gmail.com", "joao\ufe6bgmail.com",
		// The minus sign reads as a dash (the database's floor counts it).
		"Safra 2024\u22122025", "11 91234\u22125678",
	}
	out := Labels{
		Format: Format, Version: 1, Kind: "labels",
		Description: "contract.CleanLabel: what may cross the wire of a name a person gave a number or mailbox ('' means no label). Text with @, or a character that reads as one, goes; control and format characters go; whitespace collapses; a run of 7 or more decimal digits of any script, with spaces . , / _ ( ) + - · • * #, any dash or the minus sign between them, becomes … and its last four digits. The platform cleans every label again on intake. Hints are … and four ASCII digits, or a first character, …@ and a domain with fewer than 7 digits.",
	}
	for _, r := range raws {
		out.Clean = append(out.Clean, LabelCase{Raw: r, Clean: contract.CleanLabel(r)})
	}
	for _, h := range []string{"…5678", "j…@gmail.com", "7…@exemplo.com.br", "é…@exemplo.com.br", "j…@localhost", "5678", "…567", "...5678", "jo…@gmail.com", "j@gmail.com", "j…@Gmail.com", "j…@a..b", "a…@5511912345678.com", "…\uff15\uff16\uff17\uff18"} {
		out.Hints = append(out.Hints, HintCase{Hint: h, Valid: contract.ValidHint(h)})
	}
	return out, nil
}

// WireCase is one value and whether its Validate accepts it.
type WireCase struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
	Valid bool            `json:"valid"`
}

// BigValue is the size of compact JSON over which a value of the token
// part's files (kit v0.9.0) is written on one line, compact, rather than
// indented with the rest of its file, which would swell it several times.
const BigValue = 16 << 10

// The big values of the files being written, by the placeholder that
// stands for each until the file is encoded (inlineBig).
var (
	bigMu     sync.Mutex
	bigValues = map[string]json.RawMessage{}
)

// wireCase is a case of the token part's files. A value over BigValue
// bytes is held as a placeholder, which inlineBig replaces with its
// compact text once the file is encoded.
func wireCase(name string, raw json.RawMessage, valid bool) WireCase {
	if len(raw) > BigValue {
		sum := sha256.Sum256(raw)
		key := "\u0000big:" + hex.EncodeToString(sum[:])
		bigMu.Lock()
		bigValues[key] = raw
		bigMu.Unlock()
		raw, _ = json.Marshal(key)
	}
	return WireCase{Name: name, Value: raw, Valid: valid}
}

// bigPlaceholder is a placeholder as an encoded file holds it.
var bigPlaceholder = regexp.MustCompile(`"\\u0000big:[0-9a-f]{64}"`)

// inlineBig writes each big value's compact text in place of its
// placeholder.
func inlineBig(b []byte) ([]byte, error) {
	var missing error
	out := bigPlaceholder.ReplaceAllFunc(b, func(m []byte) []byte {
		var key string
		if err := json.Unmarshal(m, &key); err != nil {
			missing = err
			return m
		}
		bigMu.Lock()
		raw, ok := bigValues[key]
		bigMu.Unlock()
		if !ok {
			missing = errors.New("contractvec: a big value's placeholder has no value")
			return m
		}
		return raw
	})
	return out, missing
}

// caseValue is a case's value.
func caseValue(c WireCase) json.RawMessage { return c.Value }

// Wire is wire.json.
type Wire struct {
	Format      string     `json:"format"`
	Version     int        `json:"version"`
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Documents   []WireCase `json:"documents"`
	Snapshots   []WireCase `json:"snapshots"`
	Events      []WireCase `json:"events"`
}

func wire() (any, error) {
	out := Wire{
		Format: Format, Version: 1, Kind: "wire",
		Description: "Account documents, access snapshots and events, each with whether its Validate accepts it (documents: contract.AccountDoc; snapshots: contract.Snapshot; events: contract.Event).",
	}
	str := func(s string) *string { return &s }
	one := 1
	zero := 0
	doc := func(mut func(*contract.AccountDoc)) contract.AccountDoc {
		name := "TBFG"
		d := contract.AccountDoc{
			V: contract.DocV, Type: contract.DocType, App: "wappie",
			Generation: "0199b1e0-0000-7000-8000-000000000001", Sub: "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20",
			Version: 7, Status: contract.AccountActive,
			Workspaces: []contract.Workspace{
				{ID: "01a08e0e-c546-7db3-9c44-e6352636d330", Kind: contract.KindPersonal, Role: contract.RoleOwner, Status: contract.StatusOpen, WVersion: 1},
				{ID: "01a034b7-d09c-7121-b7f8-41f210a9244a", Kind: contract.KindTeam, Name: &name, Role: contract.RoleOwner, Status: contract.StatusOpen, WVersion: 3, Owners: &one},
			},
		}
		if mut != nil {
			mut(&d)
		}
		return d
	}
	revoked := contract.T(Now.Add(-time.Hour))
	docs := []struct {
		name string
		d    contract.AccountDoc
	}{
		{"an account with a personal workspace and a team", doc(nil)},
		{"sessions and integrations revoked by a recovery", doc(func(d *contract.AccountDoc) { d.SessionsRevokedAt, d.CredentialsRevokedAt = &revoked, &revoked })},
		{"a suspended account", doc(func(d *contract.AccountDoc) { d.Status, d.DisabledAt = contract.AccountDisabled, &revoked })},
		{"a closed account", doc(func(d *contract.AccountDoc) { d.Status, d.Workspaces = contract.AccountClosed, []contract.Workspace{} })},
		{"a closed team keeps its members", doc(func(d *contract.AccountDoc) { d.Workspaces[1].Status = contract.StatusClose })},
		{"version 2 of the format", doc(func(d *contract.AccountDoc) { d.V = 2 })},
		{"an unknown status", doc(func(d *contract.AccountDoc) { d.Status = "suspended" })},
		{"an uppercase sub", doc(func(d *contract.AccountDoc) { d.Sub = "0199A0C2-7D3E-7B51-9F0A-2C4E6B8D1F20" })},
		{"a closed account with workspaces", doc(func(d *contract.AccountDoc) { d.Status = contract.AccountClosed })},
		{"the personal workspace not first", doc(func(d *contract.AccountDoc) { d.Workspaces[0], d.Workspaces[1] = d.Workspaces[1], d.Workspaces[0] })},
		{"an open team with no owner", doc(func(d *contract.AccountDoc) { d.Workspaces[1].Owners = &zero })},
		{"a team name with a bidirectional control", doc(func(d *contract.AccountDoc) { d.Workspaces[1].Name = str("TB\u202eFG") })},
		{"the role of a service account", doc(func(d *contract.AccountDoc) { d.Workspaces[1].Role = "service" })},
	}
	for _, c := range docs {
		raw, err := json.Marshal(c.d)
		if err != nil {
			return nil, err
		}
		out.Documents = append(out.Documents, WireCase{Name: c.name, Value: raw, Valid: c.d.Validate() == nil})
	}

	sub, other := "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20", "0199c3d4-0000-7000-8000-000000000002"
	purge := contract.T(Now.Add(30 * 24 * time.Hour))
	snap := func(mut func(*contract.Item)) contract.Snapshot {
		it := contract.Item{
			ID: "0199e000-0000-7000-8000-000000000004", Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678"), State: contract.StateActive,
			People: []contract.Person{
				{Sub: sub, Can: []string{contract.CanRead, contract.CanSend}, Reads: true, Enrolled: true, HoldsKey: true},
				{Sub: other, Can: []string{contract.CanRead}, Waiting: true, Enrolled: true},
			},
			Protected: []string{sub},
		}
		if mut != nil {
			mut(&it)
		}
		return contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: Now.UnixMilli(), Items: []contract.Item{it}}
	}
	snaps := []struct {
		name string
		s    contract.Snapshot
	}{
		{"a number with its reader and a person waiting for the key", snap(nil)},
		{"a mailbox with no name, its hint only", snap(func(it *contract.Item) {
			it.ID, it.Kind, it.Label, it.Hint = "acc_7f3a", contract.ItemMailbox, nil, str("j…@gmail.com")
		})},
		{"a paused item says why", snap(func(it *contract.Item) { it.State, it.Reason = contract.StateSyncPaused, str("by_person") })},
		{"a deleted item until its purge", snap(func(it *contract.Item) { it.State, it.PurgeAt = contract.StateDeleted, &purge })},
		{"a label that is a phone number", snap(func(it *contract.Item) { it.Label = str("+55 11 91234-5678") })},
		{"a pause with no reason", snap(func(it *contract.Item) { it.State = contract.StateSyncPaused })},
		{"a deleted item with no purge date", snap(func(it *contract.Item) { it.State = contract.StateDeleted })},
		{"protecting someone the item does not list", snap(func(it *contract.Item) { it.Protected = []string{"0199f000-0000-7000-8000-000000000009"} })},
		{"an unknown flag", snap(func(it *contract.Item) { it.People[0].Can = []string{"delete"} })},
	}
	for _, c := range snaps {
		raw, err := json.Marshal(c.s)
		if err != nil {
			return nil, err
		}
		out.Snapshots = append(out.Snapshots, WireCase{Name: c.name, Value: raw, Valid: c.s.Validate() == nil})
	}

	ev := func(typ, kind string, mut func(*contract.Event)) contract.Event {
		readers := []string{sub, other}
		e := contract.Event{
			EventID: "0199d000-0000-7000-8000-000000000003", WorkspaceID: "01a034b7-d09c-7121-b7f8-41f210a9244a",
			Type: typ, OccurredAt: contract.T(Now), Item: contract.EventItem{ID: "0199e000-0000-7000-8000-000000000004", Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678")},
			Actor: str(sub), ActorKind: kind, Readers: &readers,
		}
		if mut != nil {
			mut(&e)
		}
		return e
	}
	events := []struct {
		name string
		e    contract.Event
	}{
		{"an owner deleted a number", ev(contract.EventDeleted, contract.ActorPerson, func(e *contract.Event) { e.PurgeAt = &purge })},
		{"an API key turned off a number's sync; the actor is its creator", ev(contract.EventSyncPaused, contract.ActorKey, nil)},
		{"an owner recovered it", ev(contract.EventRecovered, contract.ActorPerson, nil)},
		{"the app purged it", ev(contract.EventPurged, contract.ActorApp, func(e *contract.Event) { e.Actor = nil })},
		{"a membership ended and stranded it; the platform fills the cause", ev(contract.EventStranded, contract.ActorApp, func(e *contract.Event) { e.Actor, e.Person = nil, str(other) })},
		{"a holder with no sub was lost", ev(contract.EventStranded, contract.ActorApp, func(e *contract.Event) { e.Actor = nil; e.Cause = str("revoked") })},
		{"a number moved to its owner's personal workspace", ev(contract.EventMovedOut, contract.ActorPerson, func(e *contract.Event) { e.To = str(contract.MovedToPersonal) })},
		{"more readers than an event carries", ev(contract.EventSyncPaused, contract.ActorPerson, func(e *contract.Event) { e.Readers = nil })},
		{"a deletion with no purge date", ev(contract.EventDeleted, contract.ActorPerson, nil)},
		{"a deletion by an API key", ev(contract.EventDeleted, contract.ActorKey, func(e *contract.Event) { e.PurgeAt = &purge })},
		{"a mailbox moved", ev(contract.EventMovedOut, contract.ActorPerson, func(e *contract.Event) { e.Item.Kind, e.To = contract.ItemMailbox, str(contract.MovedToPersonal) })},
		{"a cause on a pause", ev(contract.EventSyncPaused, contract.ActorPerson, func(e *contract.Event) { e.Cause = str("removed") })},
		{"the app's own act with an actor", ev(contract.EventPurged, contract.ActorApp, nil)},
		{"a label that is an address", ev(contract.EventSyncPaused, contract.ActorPerson, func(e *contract.Event) { e.Item.Label = str("vendas@loja.com") })},
	}
	for _, c := range events {
		raw, err := json.Marshal(c.e)
		if err != nil {
			return nil, err
		}
		out.Events = append(out.Events, WireCase{Name: c.name, Value: raw, Valid: c.e.Validate() == nil})
	}
	// Times a decoder refuses: RFC 3339 has no comma before the fraction
	// (Go's time.Parse would take one), and at most nine digits follow the
	// dot.
	base, err := json.Marshal(ev(contract.EventSyncPaused, contract.ActorPerson, nil))
	if err != nil {
		return nil, err
	}
	at, err := json.Marshal(contract.T(Now))
	if err != nil {
		return nil, err
	}
	whole := strings.TrimSuffix(string(at), `Z"`)
	for _, c := range []struct{ name, at string }{
		{"a time with a comma before its fraction", whole + `,5Z"`},
		{"a time with ten fractional digits", whole + `.1234567890Z"`},
		{"a time in another zone", whole + `+01:00"`},
	} {
		raw := []byte(strings.Replace(string(base), `"occurred_at":`+string(at), `"occurred_at":`+c.at, 1))
		if string(raw) == string(base) {
			return nil, fmt.Errorf("contractvec: no occurred_at to replace")
		}
		var e contract.Event
		valid := json.Unmarshal(raw, &e) == nil && e.Validate() == nil
		out.Events = append(out.Events, WireCase{Name: c.name, Value: raw, Valid: valid})
	}
	return out, nil
}

// wireItemIDs is wire-item-ids.json, the cases added once wire.json was
// frozen: a snapshot lists each item id once, whatever its kind, since the
// platform keeps an app's items of a workspace by id.
func wireItemIDs() (any, error) {
	out := Wire{
		Format: Format, Version: 1, Kind: "wire",
		Description: "Access snapshots whose items share an id, each with whether contract.Snapshot's Validate accepts it: an id appears once in a snapshot, whatever its kind. Added after wire.json was frozen.",
		Documents:   []WireCase{}, Events: []WireCase{},
	}
	str := func(s string) *string { return &s }
	sub := "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	item := func(id, kind string) contract.Item {
		return contract.Item{
			ID: id, Kind: kind, Label: str("Vendas"), State: contract.StateActive,
			People:    []contract.Person{{Sub: sub, Can: []string{contract.CanRead}, Reads: true, Enrolled: true, HoldsKey: true}},
			Protected: []string{sub},
		}
	}
	snap := func(items ...contract.Item) contract.Snapshot {
		return contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: Now.UnixMilli(), Items: items}
	}
	const id = "0199e000-0000-7000-8000-000000000004"
	for _, c := range []struct {
		name string
		s    contract.Snapshot
	}{
		{"a number and a mailbox with their own ids", snap(item(id, contract.ItemNumber), item("acc_7f3a", contract.ItemMailbox))},
		{"one id for a number and a mailbox", snap(item(id, contract.ItemNumber), item(id, contract.ItemMailbox))},
		{"one number listed twice", snap(item(id, contract.ItemNumber), item(id, contract.ItemNumber))},
	} {
		raw, err := json.Marshal(c.s)
		if err != nil {
			return nil, err
		}
		out.Snapshots = append(out.Snapshots, WireCase{Name: c.name, Value: raw, Valid: c.s.Validate() == nil})
	}
	return out, nil
}
