package platform_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestStrictBase64urlHasOneSpellingPerValue(t *testing.T) {
	// 16 bytes are 22 characters whose last one carries 4 trailing bits.
	good := platform.EncodeB64(testBytes(16, 0xff))
	if got, err := platform.DecodeB64(good, 16); err != nil || !bytes.Equal(got, testBytes(16, 0xff)) {
		t.Fatalf("a good value: %v", err)
	}
	last := good[len(good)-1]
	trailing := good[:len(good)-1] + string(last+1) // same 2 data bits, a trailing bit set
	bad := map[string]struct {
		s string
		n int
	}{
		"padding":              {good + "==", 16},
		"a line break":         {good[:10] + "\n" + good[10:], 16},
		"a carriage return":    {good[:10] + "\r" + good[10:21], 16},
		"standard alphabet":    {strings.NewReplacer("-", "+", "_", "/").Replace(platform.EncodeB64(testBytes(16, 0xfb))), 16},
		"non-zero trailing":    {trailing, 16},
		"one byte short":       {platform.EncodeB64(testBytes(15, 0xff)), 16},
		"one byte long":        {platform.EncodeB64(testBytes(17, 0xff)), 16},
		"empty for 16":         {"", 16},
		"a space":              {" " + good[1:], 16},
		"a non-ASCII byte":     {"\u00e9" + good[2:], 16},
		"a negative length":    {"", -1},
		"an impossible length": {"A", 0},
	}
	for name, c := range bad {
		if _, err := platform.DecodeB64(c.s, c.n); !errors.Is(err, platform.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
		}
	}
	if got, err := platform.DecodeB64("", 0); err != nil || len(got) != 0 {
		t.Fatalf("zero bytes: %v", err)
	}
}

func TestJCSArrayMatchesEncodingJSONForAllowedElements(t *testing.T) {
	cases := [][]any{
		{},
		{"thehappie-id/root-wrap", 1, "password", testSub, 1},
		{"A-Za-z0-9._:/|@-", 0, 1 << 31, ""},
	}
	for _, c := range cases {
		got, err := platform.JCSArray(c...)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("JCSArray %s, encoding/json %s", got, want)
		}
	}
}

func TestJCSArrayRefusesWhatWouldNeedEscapingOrIsNotAnArrayElementWeAllow(t *testing.T) {
	for i, e := range []any{
		`"`, `\`, " ", "<", "\u00e9", "\x00", "a\nb", "+", "=", "%", "~",
		-1, 1<<31 + 1, int64(1), uint32(1), 1.0, true, nil, []any{}, map[string]any{},
	} {
		if _, err := platform.JCSArray("ok", e); !errors.Is(err, platform.ErrEncoding) {
			t.Errorf("element %d (%T): %v, want ErrEncoding", i, e, err)
		}
	}
}

func TestErrorCodeNamesEverySentinelAndNothingElse(t *testing.T) {
	want := map[error]string{
		platform.ErrPasswordInvalid:  "password_invalid",
		platform.ErrPasswordTooShort: "password_too_short",
		platform.ErrPasswordTooLong:  "password_too_long",
		platform.ErrKDFPolicy:        "kdf_policy",
		platform.ErrWrap:             "wrap",
		platform.ErrRecoveryCode:     "recovery_code",
		platform.ErrEmailInvalid:     "email",
		platform.ErrProductKey:       "product_key",
		platform.ErrBundle:           "bundle",
		platform.ErrKeyDelivery:      "key_delivery",
		platform.ErrPKCE:             "pkce",
		platform.ErrClientExtensions: "client_extensions",
		platform.ErrEncoding:         "encoding",
	}
	for err, code := range want {
		if got := platform.ErrorCode(fmt.Errorf("context: %w", err)); got != code {
			t.Errorf("%v: %q, want %q", err, got, code)
		}
	}
	if platform.ErrorCode(nil) != "" || platform.ErrorCode(errors.New("other")) != "" {
		t.Fatal("ErrorCode named an error that is not the package's")
	}
}

func TestRefusalsNeverRepeatTheRefusedValue(t *testing.T) {
	const marker = "zq7marker"
	checks := map[string]error{}
	_, checks["email"] = platform.NormalizeEmail(marker + "@@example.com")
	_, checks["password"] = platform.PrepareNewPassword(marker)
	_, checks["password with control"] = platform.PreparePassword(marker + "\x00")
	_, checks["recovery code"] = platform.CanonicalRecoveryCode(marker + "U")
	_, checks["base64url"] = platform.DecodeB64(marker+"=", 7)
	_, checks["sub"] = platform.AuthVerifier(marker, testBytes(32, 1))
	_, _, checks["product id"] = platform.ProductKey(testBytes(32, 1), marker+"|", 1)
	_, checks["bundle"] = platform.ParseKeyBundle([]byte(`{"` + marker + `":1}`))
	_, _, checks["bundle password"] = platform.OpenKeyBundle([]byte(`[]`), marker)
	_, checks["relying party id"] = platform.PRFSalt(marker + ".Example")
	_, checks["passkey wrap key"] = platform.PasskeyWrapKey(testBytes(32, 1), marker+":443")
	checks["client extensions"] = platform.CheckClientExtensions([]byte(`{"prf":{"results":{"first":"` + marker + `"}}}`))
	checks["client extension name"] = platform.CheckClientExtensions([]byte(`{"` + marker + `":true}`))
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: not refused", name)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error repeats the input", name)
		}
	}
}
