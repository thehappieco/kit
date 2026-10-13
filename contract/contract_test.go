package contract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thehappieco/kit/reqhmac"
)

const (
	secretA = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	secretB = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	nonce   = "AAAAAAAAAAAAAAAAAAAAAA"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func TestASecretMustBeFortyThreeBase64urlCharactersAndTheNextMustDiffer(t *testing.T) {
	if err := CheckSecrets(secretA, ""); err != nil {
		t.Fatalf("a valid secret: %v", err)
	}
	if err := CheckSecrets(secretA, secretB); err != nil {
		t.Fatalf("a valid rotation: %v", err)
	}
	for name, pair := range map[string][2]string{
		"empty":                  {"", ""},
		"short":                  {secretA[:42], ""},
		"long":                   {secretA + "A", ""},
		"padded":                 {secretA[:42] + "=", ""},
		"standard alphabet":      {strings.Replace(secretA, "-", "+", 1)[:42] + "/", ""},
		"not canonical bits":     {secretA[:42] + "B", ""},
		"next equals current":    {secretA, secretA},
		"next malformed":         {secretA, "x"},
		"current empty, next ok": {"", secretB},
	} {
		if err := CheckSecrets(pair[0], pair[1]); !errors.Is(err, ErrSecret) {
			t.Errorf("%s: %v, want ErrSecret", name, err)
		}
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	if err := CheckSecrets(base64.RawURLEncoding.EncodeToString(raw), ""); err != nil {
		t.Errorf("any 32 bytes, encoded: %v", err)
	}
}

func signRequest(t *testing.T, secret, app, method, target string, body []byte) http.Header {
	t.Helper()
	h := http.Header{}
	if err := Scheme().Sign(h, secret, ToPlatform, app, method, target, body, now); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAnAnswerVerifiesOnlyForTheRequestWhoseNonceItEchoes(t *testing.T) {
	body := []byte(`{"accepted":true}`)
	h := http.Header{}
	SignAnswer(h, secretA, "wappie", "PUT", "/contract/v1/workspaces/x/access", nonce, body, now)
	if err := VerifyAnswer(h, []string{secretA}, "wappie", "PUT", "/contract/v1/workspaces/x/access", nonce, body, now); err != nil {
		t.Fatalf("the answer to its own request: %v", err)
	}
	other := "BBBBBBBBBBBBBBBBBBBBBB"
	if err := VerifyAnswer(h, []string{secretA}, "wappie", "PUT", "/contract/v1/workspaces/x/access", other, body, now); !errors.Is(err, ErrAnswerNonce) {
		t.Errorf("another request's answer: %v, want ErrAnswerNonce", err)
	}
	// A swapped nonce header, even signed consistently, is not the request's.
	swapped := http.Header{}
	SignAnswer(swapped, secretA, "wappie", "PUT", "/contract/v1/workspaces/x/access", other, body, now)
	if err := VerifyAnswer(swapped, []string{secretA}, "wappie", "PUT", "/contract/v1/workspaces/x/access", nonce, body, now); !errors.Is(err, ErrAnswerNonce) {
		t.Errorf("a swapped nonce: %v, want ErrAnswerNonce", err)
	}
}

func TestARequestSignatureIsNeverAnAnswer(t *testing.T) {
	body := []byte(`{}`)
	h := signRequest(t, secretA, "wappie", "GET", "/contract/v1/feed?after=0&wait=0", body)
	sent := h.Get(HeaderNonce)
	if err := VerifyAnswer(h, []string{secretA}, "wappie", "GET", "/contract/v1/feed?after=0&wait=0", sent, body, now); !errors.Is(err, reqhmac.ErrBad) {
		t.Errorf("a to-platform signature as an answer: %v, want ErrBad", err)
	}
}

func TestAnAnswerVerifiesOnlyForItsAppItsTargetItsBodyAndASecretOfTheApp(t *testing.T) {
	body := []byte(`{"accepted":true}`)
	target := "/contract/v1/workspaces/x/access"
	h := http.Header{}
	SignAnswer(h, secretA, "wappie", "PUT", target, nonce, body, now)
	for name, check := range map[string]func() error{
		"another app": func() error { return VerifyAnswer(h, []string{secretA}, "mailie", "PUT", target, nonce, body, now) },
		"another target": func() error {
			return VerifyAnswer(h, []string{secretA}, "wappie", "PUT", target+"?x=1", nonce, body, now)
		},
		"another method": func() error { return VerifyAnswer(h, []string{secretA}, "wappie", "POST", target, nonce, body, now) },
		"another body": func() error {
			return VerifyAnswer(h, []string{secretA}, "wappie", "PUT", target, nonce, []byte(`{"accepted":false}`), now)
		},
		"another secret": func() error { return VerifyAnswer(h, []string{secretB}, "wappie", "PUT", target, nonce, body, now) },
		"the key decoded as bytes": func() error {
			raw, _ := base64.RawURLEncoding.DecodeString(secretA)
			return VerifyAnswer(h, []string{string(raw)}, "wappie", "PUT", target, nonce, body, now)
		},
		"no secret": func() error { return VerifyAnswer(h, nil, "wappie", "PUT", target, nonce, body, now) },
	} {
		if err := check(); !errors.Is(err, reqhmac.ErrBad) {
			t.Errorf("%s: %v, want ErrBad", name, err)
		}
	}
	if err := VerifyAnswer(h, []string{secretB, secretA}, "wappie", "PUT", target, nonce, body, now); err != nil {
		t.Errorf("during a rotation: %v", err)
	}
}

func TestAStaleOrUnsignedAnswerDoesNotVerify(t *testing.T) {
	body := []byte(`{}`)
	h := http.Header{}
	SignAnswer(h, secretA, "wappie", "GET", "/contract/v1/accounts/x", nonce, body, now)
	if err := VerifyAnswer(h, []string{secretA}, "wappie", "GET", "/contract/v1/accounts/x", nonce, body, now.Add(Skew+time.Second)); !errors.Is(err, reqhmac.ErrStale) {
		t.Errorf("a minute late: %v, want ErrStale", err)
	}
	if err := VerifyAnswer(http.Header{}, []string{secretA}, "wappie", "GET", "/contract/v1/accounts/x", nonce, body, now); !errors.Is(err, reqhmac.ErrMissing) {
		t.Errorf("unsigned: %v, want ErrMissing", err)
	}
}

func TestCleanLabelMasksANumberTypedWithSeparators(t *testing.T) {
	for raw, want := range map[string]string{
		"Vendas":                     "Vendas",
		"+55 11 91234-5678":          "…5678",
		"+55 (11) 91234-5678":        "…5678",
		"11.91234.5678":              "…5678",
		"Loja 11912345678":           "Loja …5678",
		"Loja 1 - 123456":            "Loja …3456",
		"Loja 1 - 12345":             "Loja 1 - 12345",
		"Tel: (11) 91234-5678":       "Tel: …5678",
		"Sala 12, ramal 1234567":     "Sala 12, ramal …4567",
		"Filial 1234 567":            "Filial …4567",
		"Filial 1234 567":            "Filial …4567",
		"Suporte   24h":              "Suporte 24h",
		"  Vendas  ":                 "Vendas",
		"vendas@loja.com":            "",
		"Vendas (j@x)":               "",
		"Ven\u202edas":               "Vendas",
		"Ven\u200bdas":               "Vendas",
		"Ven\x00das\x7f\u0085":       "Vendas",
		"":                           "",
		"\u200b":                     "",
		"Número 2 e 3 de 1234567890": "Número 2 e 3 de …7890",
		"Safra 2024\u22122025":       "Safra …2025",
	} {
		if got := CleanLabel(raw); got != want {
			t.Errorf("CleanLabel(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestCleanLabelNeverLeavesHalfAFlagOrMoreThanEightyCharacters(t *testing.T) {
	long := strings.Repeat("a", 79) + "🇧🇷"
	got := CleanLabel(long)
	if utf8.RuneCountInString(got) > MaxLabel || strings.HasSuffix(got, "\U0001f1e7") {
		t.Errorf("CleanLabel left %q", got)
	}
	if got := CleanLabel(strings.Repeat("é", 200)); utf8.RuneCountInString(got) != MaxLabel {
		t.Errorf("cut to %d code points", utf8.RuneCountInString(got))
	}
}

func FuzzCleaningALabelTwiceChangesNothing(f *testing.F) {
	for _, s := range []string{"Vendas", "+55 11 91234-5678", "Loja 11912345678", "1234 567 89", "a@b", "🇧🇷🇵🇹", "\u202e1\u200b2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		once := CleanLabel(raw)
		if CleanLabel(once) != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, once, CleanLabel(once))
		}
		if once != "" && !ValidLabel(once) {
			t.Fatalf("CleanLabel(%q) = %q is not valid", raw, once)
		}
		if strings.Contains(once, "@") || utf8.RuneCountInString(once) > MaxLabel || strings.ContainsFunc(once, hidden) {
			t.Fatalf("CleanLabel(%q) = %q", raw, once)
		}
		digits := 0
		for _, r := range once {
			switch {
			case isDigit(r):
				digits++
				if digits >= DigitRun {
					t.Fatalf("CleanLabel(%q) = %q keeps a run of digits", raw, once)
				}
			case separator(r):
			default:
				digits = 0
			}
		}
	})
}

func TestAHintIsFourDigitsOrAFirstCharacterAndADomain(t *testing.T) {
	for _, ok := range []string{"…5678", "j…@gmail.com", "7…@exemplo.com.br"} {
		if !ValidHint(ok) {
			t.Errorf("ValidHint(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "5678", "…567", "…56789", "...5678", "jo…@gmail.com", "j…@", "j@gmail.com", "j…@Gmail.com", "j…@.com", "@…@gmail.com", "\u202e…@x.com", "j…@a..b", "é…@exemplo.com.br", "J…@gmail.com", "j…@localhost"} {
		if ValidHint(bad) {
			t.Errorf("ValidHint(%q) = true", bad)
		}
	}
}

func validDoc() AccountDoc {
	name, owners := "TBFG", 1
	return AccountDoc{
		V: DocV, Type: DocType, App: "wappie",
		Generation: "0199b1e0-0000-7000-8000-000000000001",
		Sub:        "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20",
		Version:    7, Status: AccountActive,
		Workspaces: []Workspace{
			{ID: "01a08e0e-c546-7db3-9c44-e6352636d330", Kind: KindPersonal, Role: RoleOwner, Status: StatusOpen, WVersion: 1},
			{ID: "01a034b7-d09c-7121-b7f8-41f210a9244a", Kind: KindTeam, Name: &name, Role: RoleOwner, Status: StatusOpen, WVersion: 3, Owners: &owners},
		},
	}
}

func TestADocumentIsRefusedForAnyMemberOutsideItsRules(t *testing.T) {
	if err := validDoc().Validate(); err != nil {
		t.Fatalf("a valid document: %v", err)
	}
	zero, bad := 0, "a\u202eb"
	for name, mutate := range map[string]func(*AccountDoc){
		"v 2":                             func(d *AccountDoc) { d.V = 2 },
		"unknown status":                  func(d *AccountDoc) { d.Status = "suspended" },
		"uppercase sub":                   func(d *AccountDoc) { d.Sub = strings.ToUpper(d.Sub) },
		"no workspaces list":              func(d *AccountDoc) { d.Workspaces = nil },
		"closed with workspaces":          func(d *AccountDoc) { d.Status = AccountClosed },
		"personal not first":              func(d *AccountDoc) { d.Workspaces[0], d.Workspaces[1] = d.Workspaces[1], d.Workspaces[0] },
		"personal with a name":            func(d *AccountDoc) { d.Workspaces[0].Name = &bad },
		"an open team with no owner":      func(d *AccountDoc) { d.Workspaces[1].Owners = &zero },
		"a team name with a bidi control": func(d *AccountDoc) { d.Workspaces[1].Name = &bad },
		"unknown role":                    func(d *AccountDoc) { d.Workspaces[1].Role = "service" },
		"wversion 0":                      func(d *AccountDoc) { d.Workspaces[1].WVersion = 0 },
		"a workspace twice":               func(d *AccountDoc) { d.Workspaces[1].ID = d.Workspaces[0].ID },
	} {
		d := validDoc()
		mutate(&d)
		if err := d.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	closed := validDoc()
	closed.Status, closed.Workspaces = AccountClosed, []Workspace{}
	if err := closed.Validate(); err != nil {
		t.Errorf("a closed account: %v", err)
	}
}

func TestATimeOnTheWireIsAlwaysUTC(t *testing.T) {
	var got struct{ At Time }
	if err := json.Unmarshal([]byte(`{"At":"2026-10-13T12:00:00Z"}`), &got); err != nil || !got.At.Equal(now) {
		t.Fatalf("UTC: %v %v", got.At, err)
	}
	if err := json.Unmarshal([]byte(`{"At":"2026-10-13T09:00:00-03:00"}`), &got); err == nil {
		t.Error("another zone was accepted")
	}
	b, _ := json.Marshal(struct{ At Time }{T(now.In(time.FixedZone("BRT", -3*3600)))})
	if string(b) != `{"At":"2026-10-13T12:00:00Z"}` {
		t.Errorf("marshalled %s", b)
	}
}

func str(s string) *string { return &s }

func TestEachEventCarriesOnlyItsOwnMembers(t *testing.T) {
	base := func(typ, kind string) Event {
		readers := []string{"0199c3d4-0000-7000-8000-000000000002"}
		return Event{
			EventID: "0199d000-0000-7000-8000-000000000003", WorkspaceID: "01a034b7-d09c-7121-b7f8-41f210a9244a",
			Type: typ, OccurredAt: T(now), Item: EventItem{ID: "dev_1", Kind: ItemNumber, Label: str("Vendas"), Hint: str("…5678")},
			Actor: str("0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"), ActorKind: kind, Readers: &readers,
		}
	}
	purge := T(now.Add(30 * 24 * time.Hour))
	good := []Event{
		func() Event { e := base(EventDeleted, ActorPerson); e.PurgeAt = &purge; return e }(),
		func() Event { e := base(EventDeleted, ActorPerson); e.PurgeAt = &purge; e.Actor = nil; return e }(),
		base(EventSyncPaused, ActorKey),
		base(EventRecovered, ActorPerson),
		func() Event { e := base(EventPurged, ActorApp); e.Actor = nil; return e }(),
		func() Event {
			e := base(EventStranded, ActorApp)
			e.Actor = nil
			e.Person = str(*base("", "").Actor)
			return e
		}(),
		func() Event { e := base(EventStranded, ActorPerson); e.Cause = str("revoked"); return e }(),
		func() Event { e := base(EventMovedOut, ActorPerson); e.To = str(MovedToPersonal); return e }(),
		func() Event { e := base(EventSyncPaused, ActorPerson); e.Readers = nil; return e }(),
	}
	for i, e := range good {
		if err := e.Validate(); err != nil {
			t.Errorf("good %d (%s): %v", i, e.Type, err)
		}
	}
	bad := map[string]Event{
		"deleted without purge_at": base(EventDeleted, ActorPerson),
		"deleted by a key":         func() Event { e := base(EventDeleted, ActorKey); e.PurgeAt = &purge; return e }(),
		"purge_at on a pause":      func() Event { e := base(EventSyncPaused, ActorPerson); e.PurgeAt = &purge; return e }(),
		"a cause on a pause":       func() Event { e := base(EventSyncPaused, ActorPerson); e.Cause = str("removed"); return e }(),
		"an unknown cause":         func() Event { e := base(EventStranded, ActorApp); e.Actor = nil; e.Cause = str("lost"); return e }(),
		"a mailbox moved": func() Event {
			e := base(EventMovedOut, ActorPerson)
			e.Item.Kind = ItemMailbox
			e.To = str(MovedToPersonal)
			return e
		}(),
		"an app's act with an actor": base(EventPurged, ActorApp),
		"an unknown type":            base("item.renamed", ActorPerson),
		"a label with an address":    func() Event { e := base(EventSyncPaused, ActorPerson); e.Item.Label = str("v@x.com"); return e }(),
		"a reader twice": func() Event {
			e := base(EventSyncPaused, ActorPerson)
			r := []string{*e.Actor, *e.Actor}
			e.Readers = &r
			return e
		}(),
	}
	for name, e := range bad {
		if err := e.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestASnapshotProtectsOnlyPeopleItLists(t *testing.T) {
	sub := "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	s := Snapshot{V: SnapshotV, SnapshotSeq: 1760356800000, Items: []Item{{
		ID: "dev_1", Kind: ItemNumber, Label: str("Vendas"), Hint: str("…5678"), State: StateActive,
		People:    []Person{{Sub: sub, Can: []string{CanRead, CanSend}, Reads: true, Enrolled: true, HoldsKey: true}},
		Protected: []string{sub},
	}}}
	if err := s.Validate(); err != nil {
		t.Fatalf("a valid snapshot: %v", err)
	}
	s.Items[0].Protected = []string{"0199c3d4-0000-7000-8000-000000000002"}
	if err := s.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("protecting someone not listed: %v", err)
	}
	s.Items[0].Protected = []string{sub}
	s.Items[0].State, s.Items[0].Reason = StateSyncPaused, str("by_person")
	if err := s.Validate(); err != nil {
		t.Errorf("a paused item: %v", err)
	}
	s.Items[0].Reason = nil
	if err := s.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("a pause with no reason: %v", err)
	}
}
