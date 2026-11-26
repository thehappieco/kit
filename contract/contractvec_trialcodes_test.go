package contract_test

// The kit's generator of trial-codes.json (kit v0.12.0, SPEC section
// 11.20): trial codes under a fixed key, the identifiers' normalizations,
// the identities that must meet and those that must differ, and the
// identifiers that make no code. Every case states the outcome the spec
// asks of it, and the generator fails rather than write a case whose
// outcome the code does not give.

import (
	"errors"
	"fmt"

	"github.com/thehappieco/kit/contract"
)

// TrialRef is one identity as an app holds it: of app, of kind, input as
// the app has it. An IMAP login names its host: its kind and identifier
// are then IMAPIdentity's (kind is what that gives, an address on a
// provider's own host for a login with @).
type TrialRef struct {
	App   string `json:"app"`
	Kind  string `json:"kind"`
	Host  string `json:"host,omitempty"`
	Input string `json:"input"`
}

// TrialCodeCase is one identity, its identifier normalized, and its code.
type TrialCodeCase struct {
	Name string `json:"name"`
	TrialRef
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
}

// TrialPair is two identities whose codes are equal (meet) or not
// (differ).
type TrialPair struct {
	Name string   `json:"name"`
	A    TrialRef `json:"a"`
	B    TrialRef `json:"b"`
}

// TrialNoCode is an identity that makes no code.
type TrialNoCode struct {
	Name string `json:"name"`
	TrialRef
}

// TrialCodesFile is trial-codes.json.
type TrialCodesFile struct {
	Format      string          `json:"format"`
	Version     int             `json:"version"`
	Kind        string          `json:"kind"`
	Description string          `json:"description"`
	Label       string          `json:"label"`
	KeyHex      string          `json:"key_hex"`
	Codes       []TrialCodeCase `json:"codes"`
	Meet        []TrialPair     `json:"meet"`
	Differ      []TrialPair     `json:"differ"`
	NoCode      []TrialNoCode   `json:"no_code"`
}

// trialOf is the kind, identifier and code of r under the vectors' key, or
// ErrNoCode: an IMAP login through IMAPIdentity (its kind must be the one
// that gives), any other through TrialCode.
func trialOf(r TrialRef) (kind, identifier, code string, err error) {
	kind, identifier = r.Kind, r.Input
	if r.Host != "" {
		k, id, ok := contract.IMAPIdentity(r.Host, r.Input)
		if !ok {
			return "", "", "", contract.ErrNoCode
		}
		if k != r.Kind {
			return "", "", "", fmt.Errorf("contractvec: %s/%s is %s, not %s", r.Host, r.Input, k, r.Kind)
		}
		kind, identifier = k, id
	}
	id, ok := contract.NormalizeTrialIdentifier(kind, identifier)
	if !ok {
		return "", "", "", contract.ErrNoCode
	}
	code, err = contract.TrialCode(vecTrialKey(), r.App, kind, identifier)
	return kind, id, code, err
}

func trialCodesFile() (any, error) {
	out := TrialCodesFile{
		Format: Format, Version: 1, Kind: "trial-codes", Label: contract.TrialCodeLabel, KeyHex: vecTrialKeyHex,
		Description: "Trial codes (SPEC section 11.20): code = base64url-nopad(HMAC-SHA256(key = K_app, msg = label || 0x00 || app || 0x00 || kind || 0x00 || identifier)), each part's UTF-8 bytes joined by single zero bytes, no terminator; K_app is key_hex's 32 bytes themselves. An identity is {app, kind, input}, or for an IMAP login {app, kind, host, input}: the host as dialled and the login, whose kind and identifier are IMAPIdentity's (an address for a login with @ on a provider's own host, imap.gmail.com, imap.googlemail.com and imap.mail.me.com; else an imap_login, host/login). identifier is the input normalized by its kind: e164 a + and 2 to 15 ASCII digits, the first not 0, never reformatted; wa_lid ASCII digits; google_sub as given; ms_tid_sub tid/sub as given; address with ASCII letters lowercased and nothing else changed, the domain after the last @, and for gmail.com and googlemail.com only the domain gmail.com, the local part cut at its first + and its dots removed; imap_login the host lowercased with no trailing dot, /, the login with its ASCII letters lowercased and nothing else changed. codes: identities with their identifier and code. meet: pairs whose codes are equal. differ: pairs whose codes differ. no_code: identities that make no code (an empty identifier, one holding a zero byte, an address with no @ or with an empty local part or domain once normalized, an e164 out of its form).",
	}
	ref := func(app, kind, input string) TrialRef { return TrialRef{App: app, Kind: kind, Input: input} }
	imap := func(host, login, kind string) TrialRef {
		return TrialRef{App: "mailie", Kind: kind, Host: host, Input: login}
	}
	addr := func(s string) TrialRef { return ref("mailie", contract.TrialKindAddress, s) }
	e164 := func(s string) TrialRef { return ref("wappie", contract.TrialKindE164, s) }

	for _, c := range []struct {
		name string
		r    TrialRef
		id   string
	}{
		{"a number's own phone number", e164("+5511988887777"), "+5511988887777"},
		{"a number's LID", ref("wappie", contract.TrialKindWALID, "185412945698817"), "185412945698817"},
		{"the reference app's number", ref(contract.ReferenceApp, contract.TrialKindE164, "+5511988887777"), "+5511988887777"},
		{"the shortest e164: + and 2 digits", e164("+12"), "+12"},
		{"the longest e164: + and 15 digits", e164("+123456789012345"), "+123456789012345"},
		{"a Google account's sub", ref("mailie", contract.TrialKindGoogleSub, "110248495921238986420"), "110248495921238986420"},
		{"a Microsoft account's tid and sub", ref("mailie", contract.TrialKindMSTidSub,
			"9188040d-6c67-4c5b-b112-36a304b66dad/AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"),
			"9188040d-6c67-4c5b-b112-36a304b66dad/AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"},
		{"an address", addr("ana@contoso.com"), "ana@contoso.com"},
		{"a Gmail address with dots and a +tag", addr("J.Doe+news@Gmail.com"), "jdoe@gmail.com"},
		{"a+b+c@gmail.com: cut at its first +", addr("a+b+c@gmail.com"), "a@gmail.com"},
		{"googlemail.com folded to gmail.com", addr("j.doe@googlemail.com"), "jdoe@gmail.com"},
		{"another domain's dots and +tag kept", addr("J.Doe+news@Example.com"), "j.doe+news@example.com"},
		{"ASCII letters alone lowercased: a non-ASCII letter left as given", addr("ÉLodie@Exemple.FR"), "Élodie@exemple.fr"},
		{"the domain after the last @", addr(`"a@b"@example.com`), `"a@b"@example.com`},
		{"an IMAP login with @ on imap.gmail.com: an address", imap("imap.gmail.com", "J.Doe+x@gmail.com", contract.TrialKindAddress), "jdoe@gmail.com"},
		{"an IMAP login with @ on iCloud's own host: an address", imap("IMAP.mail.me.com.", "Ana@iCloud.com", contract.TrialKindAddress), "ana@icloud.com"},
		{"an IMAP login on another host: host and login lowercased, the login's non-letters kept",
			imap("IMAP.Example.COM.", "John.Doe+tag@Example.com", contract.TrialKindIMAPLogin), "imap.example.com/john.doe+tag@example.com"},
		{"an IMAP login with no @ on iCloud's own host: an imap_login", imap("imap.mail.me.com", "AnaSilva", contract.TrialKindIMAPLogin), "imap.mail.me.com/anasilva"},
		{"an IMAP login with no @ on another host", imap("mail.example.org", "ana_silva-01", contract.TrialKindIMAPLogin), "mail.example.org/ana_silva-01"},
		{"an IMAP login written as its identifier", ref("mailie", contract.TrialKindIMAPLogin, "IMAP.Example.com/John.Doe@Example.com"), "imap.example.com/john.doe@example.com"},
	} {
		kind, id, code, err := trialOf(c.r)
		if err != nil {
			return nil, fmt.Errorf("contractvec: trial code %q: %w", c.name, err)
		}
		if id != c.id {
			return nil, fmt.Errorf("contractvec: trial code %q normalizes to %q, the spec asks %q", c.name, id, c.id)
		}
		c.r.Kind = kind
		out.Codes = append(out.Codes, TrialCodeCase{Name: c.name, TrialRef: c.r, Identifier: id, Code: code})
	}

	pairs := func(meet bool, list []TrialPair) ([]TrialPair, error) {
		for _, p := range list {
			_, _, a, err := trialOf(p.A)
			if err != nil {
				return nil, fmt.Errorf("contractvec: pair %q: %w", p.Name, err)
			}
			_, _, b, err := trialOf(p.B)
			if err != nil {
				return nil, fmt.Errorf("contractvec: pair %q: %w", p.Name, err)
			}
			if (a == b) != meet {
				return nil, fmt.Errorf("contractvec: pair %q meets %v, the spec asks %v", p.Name, a == b, meet)
			}
		}
		return list, nil
	}
	var err error
	out.Meet, err = pairs(true, []TrialPair{
		{"googlemail.com and gmail.com", addr("jdoe@googlemail.com"), addr("jdoe@gmail.com")},
		{"a Gmail dot", addr("j.doe@gmail.com"), addr("jdoe@gmail.com")},
		{"a Gmail +tag", addr("jdoe+shop@gmail.com"), addr("jdoe@gmail.com")},
		{"a+b+c@gmail.com and a@gmail.com", addr("a+b+c@gmail.com"), addr("a@gmail.com")},
		{"ASCII capitals", addr("Ana@Contoso.COM"), addr("ana@contoso.com")},
		{"an address from Google's sign-in and from imap.gmail.com", addr("j.doe@gmail.com"), imap("imap.gmail.com", "JDoe@gmail.com", contract.TrialKindAddress)},
		{"an address from imap.googlemail.com and from imap.gmail.com", imap("imap.googlemail.com", "jdoe@googlemail.com", contract.TrialKindAddress),
			imap("imap.gmail.com", "j.doe@gmail.com", contract.TrialKindAddress)},
		{"an IMAP host with capitals and a trailing dot", imap("Mail.Example.org.", "Ana", contract.TrialKindIMAPLogin),
			imap("mail.example.org", "ana", contract.TrialKindIMAPLogin)},
	})
	if err != nil {
		return nil, err
	}
	out.Differ, err = pairs(false, []TrialPair{
		{"another app", e164("+5511988887777"), ref(contract.ReferenceApp, contract.TrialKindE164, "+5511988887777")},
		{"another kind", ref("mailie", contract.TrialKindGoogleSub, "ana@contoso.com"), addr("ana@contoso.com")},
		{"a number and its digits as a LID", e164("+5511988887777"), ref("wappie", contract.TrialKindWALID, "5511988887777")},
		{"another domain's dot", addr("j.doe@example.com"), addr("jdoe@example.com")},
		{"a +tag at another domain", addr("jdoe+shop@example.com"), addr("jdoe@example.com")},
		{"victim@gmail.com as an address and as an imap_login on another host", addr("victim@gmail.com"),
			imap("imap.attacker.example", "victim@gmail.com", contract.TrialKindIMAPLogin)},
		{"one login without @ on two hosts", imap("mail.example.org", "ana", contract.TrialKindIMAPLogin), imap("imap.example.net", "ana", contract.TrialKindIMAPLogin)},
		{"a login without @ on imap.mail.me.com and that name with @icloud.com", imap("imap.mail.me.com", "ana", contract.TrialKindIMAPLogin),
			addr("ana@icloud.com")},
		{"a non-ASCII capital is not folded", addr("élodie@exemple.fr"), addr("Élodie@exemple.fr")},
		{"+551188887777 and +5511988887777: no ninth digit added or removed", e164("+551188887777"), e164("+5511988887777")},
	})
	if err != nil {
		return nil, err
	}

	for _, c := range []struct {
		name string
		r    TrialRef
	}{
		{"+x@gmail.com: the local part empty once cut at its +", addr("+x@gmail.com")},
		{".@gmail.com: the local part empty once its dots go", addr(".@gmail.com")},
		{"an address with no @", addr("ana.contoso.com")},
		{"an address with an empty domain", addr("ana@")},
		{"an address with an empty local part", addr("@contoso.com")},
		{"an empty address", addr("")},
		{"an empty sub", ref("mailie", contract.TrialKindGoogleSub, "")},
		{"an empty LID", ref("wappie", contract.TrialKindWALID, "")},
		{"a sub holding a zero byte", ref("mailie", contract.TrialKindGoogleSub, "1102484959\x0021238986420")},
		{"an address holding a zero byte", addr("ana\x00@contoso.com")},
		{"an e164 with a leading 0", e164("+05511988887777")},
		{"an e164 of 16 digits", e164("+1234567890123456")},
		{"an e164 of one digit", e164("+1")},
		{"an e164 without its +", e164("5511988887777")},
		{"an e164 with a space", e164("+55 11 98888 7777")},
		{"a LID with a letter", ref("wappie", contract.TrialKindWALID, "18541294569881a")},
		{"a tid and sub without their /", ref("mailie", contract.TrialKindMSTidSub, "9188040d-6c67-4c5b-b112-36a304b66dad")},
		{"a tid and sub with an empty sub", ref("mailie", contract.TrialKindMSTidSub, "9188040d-6c67-4c5b-b112-36a304b66dad/")},
		{"an imap_login whose login has @ on a provider's own host: an address, never an imap_login", ref("mailie", contract.TrialKindIMAPLogin, "imap.gmail.com/jdoe@gmail.com")},
		{"an imap_login with no host", ref("mailie", contract.TrialKindIMAPLogin, "/ana")},
		{"an imap_login with a port", ref("mailie", contract.TrialKindIMAPLogin, "mail.example.org:993/ana")},
		{"an IMAP login on a host that is no host name", imap("mail_example.org", "ana", contract.TrialKindIMAPLogin)},
		{"an empty IMAP login", imap("mail.example.org", "", contract.TrialKindIMAPLogin)},
		{"an IMAP login +x@gmail.com on imap.gmail.com", imap("imap.gmail.com", "+x@gmail.com", contract.TrialKindAddress)},
	} {
		if _, _, code, err := trialOf(c.r); !errors.Is(err, contract.ErrNoCode) {
			return nil, fmt.Errorf("contractvec: %q makes the code %q (%v), the spec asks none", c.name, code, err)
		}
		out.NoCode = append(out.NoCode, TrialNoCode{Name: c.name, TrialRef: c.r})
	}
	return out, nil
}
