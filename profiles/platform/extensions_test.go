package platform_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

// The platform's unit tests of the client-extension allowlist (its
// internal/crypto/idcrypto/extensions_test.go at b5d9f69), unchanged but for
// the package.

// A made-up PRF output in base64url, shaped like a real one.
const fakePRFOutput = "EhJD599fFQOFAB7ZW0Br9KT5OkI77uQwiPBVpt38MNM"

func TestTheAllowlistAcceptsExactlyCredPropsRKAndPRFEnabled(t *testing.T) {
	// Every subset of the two members, with every value, in both orders.
	members := map[string][]string{
		"credProps": {`"credProps":{"rk":true}`, `"credProps":{"rk":false}`},
		"prf":       {`"prf":{"enabled":true}`, `"prf":{"enabled":false}`},
	}
	accepted := []string{`{}`}
	for _, c := range members["credProps"] {
		accepted = append(accepted, "{"+c+"}")
		for _, p := range members["prf"] {
			accepted = append(accepted, "{"+c+","+p+"}", "{"+p+","+c+"}")
		}
	}
	for _, p := range members["prf"] {
		accepted = append(accepted, "{"+p+"}")
	}
	for _, text := range accepted {
		if err := platform.CheckClientExtensions([]byte(text)); err != nil {
			t.Errorf("%s: %v", text, err)
		}
	}
	if len(accepted) != 1+2+8+2 {
		t.Fatalf("%d texts; the combinations are wrong", len(accepted))
	}
}

func TestAPRFOutputNeverGetsPastTheAllowlist(t *testing.T) {
	results := `{"first":"` + fakePRFOutput + `"}`
	for _, text := range []string{
		`{"prf":{"enabled":true,"results":` + results + `}}`,
		`{"prf":{"results":` + results + `,"enabled":true}}`,
		`{"prf":{"results":` + results + `}}`,
		`{"prf":{"results":{}}}`,
		`{"prf":{"results":null}}`,
		`{"prf":{"results":[]}}`,
		`{"prf":{"enabled":true},"results":` + results + `}`,
		`{"credProps":{"rk":true,"results":` + results + `}}`,
		`{"prf":{"enabled":false},"prf":{"results":` + results + `}}`,
		`{"prf":{"results":` + results + `},"prf":{"enabled":false}}`,
		`{"prf":{"enabled":{"results":` + results + `}}}`,
		`{"Prf":{"results":` + results + `}}`,
		`{"prf":{"Results":` + results + `}}`,
		`{"prf":{"enabled":true}}` + results,
		`[{"prf":{"results":` + results + `}}]`,
		`"` + fakePRFOutput + `"`,
	} {
		err := platform.CheckClientExtensions([]byte(text))
		if !errors.Is(err, platform.ErrClientExtensions) {
			t.Errorf("%s: %v", text, err)
			continue
		}
		if strings.Contains(err.Error(), fakePRFOutput) || strings.Contains(err.Error(), "first") {
			t.Errorf("the refusal repeats what it refused")
		}
		if platform.ErrorCode(err) != "client_extensions" {
			t.Errorf("%s: error name %q", text, platform.ErrorCode(err))
		}
	}
}

func TestTheAllowlistRefusesEveryOtherShape(t *testing.T) {
	for _, text := range []string{
		``, ` `, `null`, `true`, `0`, `"{}"`, `[]`, `{`, `}`, `{}}`, `{}{}`, `{} {}`, `{},`,
		`{"prf":{"enabled":true},}`, `{"prf":{"enabled":true,}}`, `{,}`, `{"prf"}`, `{"prf":}`,
		`{'prf':{'enabled':true}}`, `{prf:{enabled:true}}`, `{"prf":{"enabled":True}}`,
		`{"prf":{"enabled":tru}}`, `{"prf":{"enabled":true}}/**/`, "\xef\xbb\xbf{}",
		`{"prf":{}}`, `{"credProps":{}}`, `{"prf":null}`, `{"credProps":null}`, `{"prf":[]}`,
		`{"prf":{"enabled":null}}`, `{"prf":{"enabled":"false"}}`, `{"prf":{"enabled":0}}`,
		`{"prf":{"enabled":[true]}}`, `{"credProps":{"rk":null}}`, `{"credProps":{"rk":1}}`,
		`{"credProps":{"rk":"true"}}`, `{"credProps":{"rk":true,"rk":true}}`,
		`{"credProps":{"rk":true},"credProps":{"rk":true}}`, `{"credProps":{"enabled":true}}`,
		`{"prf":{"rk":true}}`, `{"credProps":{"rk":true,"authenticatorDisplayName":"x"}}`,
		`{"largeBlob":{"supported":true}}`, `{"hmacCreateSecret":true}`, `{"appid":true}`,
		`{"credprops":{"rk":true}}`, `{"CredProps":{"rk":true}}`, `{"PRF":{"enabled":true}}`,
		`{"prf ":{"enabled":true}}`, `{"":{}}`, "{\"prf\x00\":{\"enabled\":true}}",
		"{\"prf\":{\"enabled\":true}}\xff", "{\"\xff\":1}",
	} {
		if err := platform.CheckClientExtensions([]byte(text)); !errors.Is(err, platform.ErrClientExtensions) {
			t.Errorf("%q: %v", text, err)
		}
	}
}

func TestMemberNamesAreReadAsEveryJSONReaderReadsThem(t *testing.T) {
	// An escape is the same name to every JSON reader, the WebAuthn
	// library's included, so it is the same name here: accepted alone, and
	// a repeat when the plain spelling is there too.
	escaped := `{"pr` + esc("0066") + `":{"en` + esc("0061") + `bled":true}}`
	if err := platform.CheckClientExtensions([]byte(escaped)); err != nil {
		t.Fatalf("an escaped name: %v", err)
	}
	repeat := `{"prf":{"enabled":true},"pr` + esc("0066") + `":{"enabled":true}}`
	if err := platform.CheckClientExtensions([]byte(repeat)); !errors.Is(err, platform.ErrClientExtensions) {
		t.Fatalf("a repeat spelled with an escape: %v", err)
	}
	// A lone surrogate decodes to U+FFFD, which names nothing allowed.
	if err := platform.CheckClientExtensions([]byte(`{"pr` + esc("d800") + `":{"enabled":true}}`)); !errors.Is(err, platform.ErrClientExtensions) {
		t.Fatalf("a lone surrogate in a name: %v", err)
	}
}

// esc returns the JSON escape of the code unit with hex digits h.
func esc(h string) string { return `\` + "u" + h }

func TestDeepNestingIsRefusedWithoutExhaustingTheStack(t *testing.T) {
	for _, depth := range []int{100, 20000} {
		deep := `{"prf":{"enabled":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}}`
		if err := platform.CheckClientExtensions([]byte(deep)); !errors.Is(err, platform.ErrClientExtensions) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
}
