package contract_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/thehappieco/kit/contract"
)

// trialKey is a fixed test key: the bytes 0x01 to 0x20.
func trialKey(t *testing.T) contract.TrialKey {
	t.Helper()
	b := make([]byte, contract.TrialKeyLen)
	for i := range b {
		b[i] = byte(i + 1)
	}
	k, err := contract.NewTrialKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func trialCode(t *testing.T, app, kind, identifier string) string {
	t.Helper()
	code, err := contract.TrialCode(trialKey(t), app, kind, identifier)
	if err != nil {
		t.Fatalf("%s %s: %v", app, kind, err)
	}
	return code
}

// A code is the HMAC-SHA256, under the key's 32 raw bytes, of the label,
// the app, the kind and the normalized identifier joined by single zero
// bytes with no terminator, in unpadded base64url: 43 canonical characters.
func TestATrialCodeIsTheHMACOfItsFourPartsJoinedByZeroBytes(t *testing.T) {
	key := trialKey(t)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("thehappie-trial/v1\x00mailie\x00address\x00ana@gmail.com"))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	got := trialCode(t, "mailie", contract.TrialKindAddress, "A.N.A+news@GoogleMail.com")
	if got != want || len(got) != contract.TrialCodeLen || !contract.ValidTrialCode(got) {
		t.Fatalf("got %s, want %s", got, want)
	}
	if contract.TrialCodeLabel != "thehappie-trial/v1" {
		t.Error(contract.TrialCodeLabel)
	}
	for _, app := range []string{"wappie", "fakeproduct"} {
		mac := hmac.New(sha256.New, key[:])
		mac.Write([]byte("thehappie-trial/v1\x00" + app + "\x00e164\x00+5511988887777"))
		if got := trialCode(t, app, contract.TrialKindE164, "+5511988887777"); got != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
			t.Errorf("%s: %s", app, got)
		}
	}
}

// What the spec says must meet makes one code, and what must differ makes
// two.
func TestTrialCodesMeetAndDifferAsTheSpecSays(t *testing.T) {
	type id struct{ app, kind, identifier string }
	addr := func(s string) id { return id{"mailie", contract.TrialKindAddress, s} }
	login := func(s string) id { return id{"mailie", contract.TrialKindIMAPLogin, s} }
	imap := func(host, l string) id {
		kind, identifier, ok := contract.IMAPIdentity(host, l)
		if !ok {
			t.Fatalf("IMAPIdentity(%q, %q)", host, l)
		}
		return id{"mailie", kind, identifier}
	}
	code := func(i id) string { return trialCode(t, i.app, i.kind, i.identifier) }
	for _, c := range []struct {
		name string
		a, b id
	}{
		{"googlemail.com and gmail.com", addr("ana@googlemail.com"), addr("ana@gmail.com")},
		{"a Gmail dot", addr("a.n.a@gmail.com"), addr("ana@gmail.com")},
		{"a Gmail +tag", addr("ana+news@gmail.com"), addr("ana@gmail.com")},
		{"a+b+c@gmail.com and a@gmail.com", addr("a+b+c@gmail.com"), addr("a@gmail.com")},
		{"ASCII letters in any case", addr("Ana@Example.COM"), addr("ana@example.com")},
		{"an address from Google's sign-in and from imap.gmail.com", addr("Ana.Lima@gmail.com"), imap("IMAP.Gmail.com", "analima@gmail.com")},
		{"imap.googlemail.com is Google's", addr("ana@gmail.com"), imap("imap.googlemail.com", "ana@googlemail.com")},
		{"a host's case and trailing dot", login("mail.example.com/ana"), imap("Mail.Example.COM.", "Ana")},
	} {
		if code(c.a) != code(c.b) {
			t.Errorf("%s: do not meet", c.name)
		}
	}
	for _, c := range []struct {
		name string
		a, b id
	}{
		{"another app", id{"wappie", contract.TrialKindE164, "+5511988887777"}, id{"fakeproduct", contract.TrialKindE164, "+5511988887777"}},
		{"another kind", id{"wappie", contract.TrialKindE164, "+5511988887777"}, id{"wappie", contract.TrialKindWALID, "5511988887777"}},
		{"another domain's dot", addr("a.na@example.com"), addr("ana@example.com")},
		{"a +tag at another domain", addr("ana+news@example.com"), addr("ana@example.com")},
		{"victim@gmail.com as an address and as an imap_login on another host", addr("victim@gmail.com"), imap("imap.example.com", "victim@gmail.com")},
		{"one login without @ on two hosts", imap("imap.example.com", "ana"), imap("imap.example.org", "ana")},
		{"a bare iCloud name and that name @icloud.com", imap("imap.mail.me.com", "ana"), imap("imap.mail.me.com", "ana@icloud.com")},
		{"a Brazilian ninth digit", id{"wappie", contract.TrialKindE164, "+551188887777"}, id{"wappie", contract.TrialKindE164, "+5511988887777"}},
		{"a non-ASCII letter's case", addr("ÉVA@example.com"), addr("éva@example.com")},
		{"a login's dots and +tag kept", imap("imap.example.com", "a.na+x"), imap("imap.example.com", "ana")},
	} {
		if code(c.a) == code(c.b) {
			t.Errorf("%s: meet", c.name)
		}
	}
}

// Each kind's identifier normalizes as the spec says, and what makes no code
// is ErrNoCode, never a code.
func TestTrialIdentifiersNormalizeOrMakeNoCode(t *testing.T) {
	for _, c := range []struct{ kind, in, want string }{
		{contract.TrialKindE164, "+5511988887777", "+5511988887777"},
		{contract.TrialKindE164, "+12", "+12"},
		{contract.TrialKindE164, "+123456789012345", "+123456789012345"},
		{contract.TrialKindWALID, "0012345678901234", "0012345678901234"},
		{contract.TrialKindGoogleSub, "110169484474386276334", "110169484474386276334"},
		{contract.TrialKindGoogleSub, "Ab C", "Ab C"},
		{contract.TrialKindMSTidSub, "9188040d-6c67-4c5b-b112-36a304b66dad/AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ", "9188040d-6c67-4c5b-b112-36a304b66dad/AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"},
		{contract.TrialKindAddress, "A.N.A+News@GMAIL.com", "ana@gmail.com"},
		{contract.TrialKindAddress, "a+b+c@googlemail.com", "a@gmail.com"},
		{contract.TrialKindAddress, "A.Na+Tag@Example.com", "a.na+tag@example.com"},
		{contract.TrialKindAddress, "\"a@b\"@Example.com", "\"a@b\"@example.com"},
		{contract.TrialKindAddress, " Ana@example.com ", " ana@example.com "},
		{contract.TrialKindAddress, "ÉVA@Exämple.com", "Éva@exämple.com"},
		{contract.TrialKindIMAPLogin, "Mail.Example.com/Ana.Lima+X@Gmail.com", "mail.example.com/ana.lima+x@gmail.com"},
		{contract.TrialKindIMAPLogin, "imap.mail.me.com/Ana", "imap.mail.me.com/ana"},
		{contract.TrialKindIMAPLogin, "imap.example.com/a/b", "imap.example.com/a/b"},
	} {
		got, ok := contract.NormalizeTrialIdentifier(c.kind, c.in)
		if !ok || got != c.want {
			t.Errorf("%s %q: %q %v, want %q", c.kind, c.in, got, ok, c.want)
		}
		again, ok := contract.NormalizeTrialIdentifier(c.kind, got)
		if !ok || again != got {
			t.Errorf("%s %q: normalizing again gives %q %v", c.kind, got, again, ok)
		}
	}
	for _, c := range []struct{ kind, in string }{
		{contract.TrialKindAddress, "+x@gmail.com"},
		{contract.TrialKindAddress, ".@gmail.com"},
		{contract.TrialKindAddress, "+.@googlemail.com"},
		{contract.TrialKindAddress, "ana.example.com"},
		{contract.TrialKindAddress, "@example.com"},
		{contract.TrialKindAddress, "ana@"},
		{contract.TrialKindAddress, ""},
		{contract.TrialKindAddress, "ana\x00@example.com"},
		{contract.TrialKindAddress, "ana@exa\xffmple.com"},
		{contract.TrialKindE164, "+0511988887777"},
		{contract.TrialKindE164, "+1234567890123456"},
		{contract.TrialKindE164, "+1"},
		{contract.TrialKindE164, "5511988887777"},
		{contract.TrialKindE164, "+55 11 98888-7777"},
		{contract.TrialKindE164, "+٥٥١١٩٨٨٨٨٧٧٧٧"},
		{contract.TrialKindWALID, ""},
		{contract.TrialKindWALID, "123456789012345678901234567890123"},
		{contract.TrialKindWALID, "1234@lid"},
		{contract.TrialKindGoogleSub, ""},
		{contract.TrialKindGoogleSub, "1101\x00"},
		{contract.TrialKindMSTidSub, "tid"},
		{contract.TrialKindMSTidSub, "/sub"},
		{contract.TrialKindMSTidSub, "tid/"},
		{contract.TrialKindMSTidSub, "tid/sub/x"},
		{contract.TrialKindIMAPLogin, "imap.example.com"},
		{contract.TrialKindIMAPLogin, "imap.example.com/"},
		{contract.TrialKindIMAPLogin, "/ana"},
		{contract.TrialKindIMAPLogin, "imap.gmail.com/ana@gmail.com"},
		{contract.TrialKindIMAPLogin, "imap.example.com:993/ana"},
		{contract.TrialKindIMAPLogin, "imäp.example.com/ana"},
		{contract.TrialKindIMAPLogin, "imap.example.com../ana"},
		{contract.TrialKindIMAPLogin, "10.0.0.1/ana"},
		{"oid", "9188040d"},
	} {
		if got, ok := contract.NormalizeTrialIdentifier(c.kind, c.in); ok {
			t.Errorf("%s %q: normalized to %q", c.kind, c.in, got)
		}
		app := "mailie"
		if c.kind == contract.TrialKindE164 || c.kind == contract.TrialKindWALID {
			app = "wappie"
		}
		code, err := contract.TrialCode(trialKey(t), app, c.kind, c.in)
		want := contract.ErrNoCode
		if c.kind == "oid" {
			want = contract.ErrInvalid
		}
		if code != "" || !errors.Is(err, want) {
			t.Errorf("%s %q: %q %v", c.kind, c.in, code, err)
		}
	}
}

// IMAPIdentity applies the provider's-own-host rule: a login with @ is an
// address only on Google's two hosts and iCloud's; any other host, and a
// bare login on a provider's own host, is an imap_login.
func TestAnIMAPLoginIsAnAddressOnlyOnAProvidersOwnHost(t *testing.T) {
	for _, c := range []struct{ host, login, kind, identifier string }{
		{"imap.gmail.com", "A.na+x@Gmail.com", contract.TrialKindAddress, "ana@gmail.com"},
		{"imap.googlemail.com", "ana@googlemail.com", contract.TrialKindAddress, "ana@gmail.com"},
		{"IMAP.mail.me.com.", "Ana@iCloud.com", contract.TrialKindAddress, "ana@icloud.com"},
		{"imap.mail.me.com", "Ana", contract.TrialKindIMAPLogin, "imap.mail.me.com/ana"},
		{"imap.gmail.com", "ana", contract.TrialKindIMAPLogin, "imap.gmail.com/ana"},
		{"imap.example.com", "Ana.Lima+x@Gmail.com", contract.TrialKindIMAPLogin, "imap.example.com/ana.lima+x@gmail.com"},
		{"xn--imp-cla.example.com", "ana", contract.TrialKindIMAPLogin, "xn--imp-cla.example.com/ana"},
		{"gmail.com", "ana@gmail.com", contract.TrialKindIMAPLogin, "gmail.com/ana@gmail.com"},
		{"imap.gmail.com.example.com", "ana@gmail.com", contract.TrialKindIMAPLogin, "imap.gmail.com.example.com/ana@gmail.com"},
	} {
		kind, identifier, ok := contract.IMAPIdentity(c.host, c.login)
		if !ok || kind != c.kind || identifier != c.identifier {
			t.Errorf("%q %q: %s %q %v", c.host, c.login, kind, identifier, ok)
		}
	}
	for _, c := range []struct{ host, login string }{
		{"", "ana"},
		{"imap.example.com", ""},
		{"imap.example.com:993", "ana"},
		{"imäp.example.com", "ana"},
		{"imap.example.com..", "ana"},
		{"[::1]", "ana"},
		{"127.0.0.1", "ana"},
		{"imap.example.com", "an\x00a"},
		{"imap.gmail.com", "+x@gmail.com"},
		{"imap.gmail.com", "@gmail.com"},
	} {
		if kind, identifier, ok := contract.IMAPIdentity(c.host, c.login); ok {
			t.Errorf("%q %q: %s %q", c.host, c.login, kind, identifier)
		}
	}
	if got := contract.ProviderIMAPHosts(); !reflect.DeepEqual(got, []string{"imap.gmail.com", "imap.googlemail.com", "imap.mail.me.com"}) {
		t.Error(got)
	}
}

// MSTidSub joins a Microsoft account's tid and sub with one "/".
func TestMSTidSubJoinsTidAndSub(t *testing.T) {
	if got, ok := contract.MSTidSub("tid", "sub"); !ok || got != "tid/sub" {
		t.Error(got, ok)
	}
	for _, c := range [][2]string{{"", "sub"}, {"tid", ""}, {"t/id", "sub"}, {"tid", "s/ub"}, {"tid", "s\x00"}} {
		if got, ok := contract.MSTidSub(c[0], c[1]); ok {
			t.Errorf("%q: %q", c, got)
		}
	}
}

// Each app makes codes of its own kinds only, and TrialCode refuses a
// missing key, an unknown app and another app's kind as a caller's fault.
func TestTrialCodesAreMadeOnlyOfTheAppsKindsUnderAKey(t *testing.T) {
	for app, want := range map[string][]string{
		"wappie":      {"e164", "wa_lid"},
		"fakeproduct": {"e164", "wa_lid"},
		"mailie":      {"google_sub", "ms_tid_sub", "address", "imap_login"},
		"vaultie":     nil,
	} {
		if got := contract.TrialCodeKinds(app); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v", app, got)
		}
	}
	kinds := contract.TrialCodeKinds("wappie")
	kinds[0] = "address"
	if contract.TrialCodeKinds("wappie")[0] != "e164" {
		t.Error("TrialCodeKinds is not a copy")
	}
	key := trialKey(t)
	for _, c := range []struct {
		key              contract.TrialKey
		app, kind, ident string
	}{
		{contract.TrialKey{}, "wappie", contract.TrialKindE164, "+5511988887777"},
		{key, "vaultie", contract.TrialKindE164, "+5511988887777"},
		{key, "wappie", contract.TrialKindAddress, "ana@gmail.com"},
		{key, "mailie", contract.TrialKindE164, "+5511988887777"},
	} {
		if code, err := contract.TrialCode(c.key, c.app, c.kind, c.ident); code != "" || !errors.Is(err, contract.ErrInvalid) || errors.Is(err, contract.ErrNoCode) {
			t.Errorf("%s %s: %q %v", c.app, c.kind, code, err)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := contract.NewTrialKey(make([]byte, n)); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
	if _, err := contract.NewTrialKey(make([]byte, 32)); !errors.Is(err, contract.ErrInvalid) {
		t.Error("the zero key is a key")
	}
}

// The key never prints, in any verb or a structured log, and neither does
// an identifier in an error.
func TestATrialKeyNeverPrints(t *testing.T) {
	key := trialKey(t)
	secret := hex.EncodeToString(key[:])
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("k", "key", key)
	for _, s := range []string{
		fmt.Sprint(key), fmt.Sprintf("%v %+v %#v %s %x %X", key, key, key, key, key, key), logged.String(),
	} {
		if strings.Contains(strings.ToLower(s), secret) || strings.Contains(s, "1 2 3 4 5") || strings.Contains(s, "0x1") {
			t.Errorf("printed %s", s)
		}
	}
	_, err := contract.TrialCode(key, "wappie", contract.TrialKindE164, "+0511988887777")
	if err == nil || strings.Contains(err.Error(), "0511988887777") {
		t.Error(err)
	}
}

// A code's spelling is 43 canonical base64url characters.
func TestValidTrialCodeTakesOnlyTheCanonicalSpelling(t *testing.T) {
	good := strings.Repeat("A", 42) + "w"
	if !contract.ValidTrialCode(good) {
		t.Error(good)
	}
	for _, s := range []string{
		strings.Repeat("A", 42) + "B", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 42) + "=",
		strings.Repeat("A", 41) + "+w", "", strings.Repeat("A", 42) + "/",
	} {
		if contract.ValidTrialCode(s) {
			t.Errorf("%q", s)
		}
	}
}
