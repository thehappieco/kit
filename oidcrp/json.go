package oidcrp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// rawUserinfo is the userinfo answer as read, before its values are checked.
type rawUserinfo struct {
	Sub           string
	ClientID      string
	AuthTime      int64
	AMR           []string
	Email         string
	EmailVerified bool
	Locale        string
	Name          string
	ProductKey    string
	ProductKeyID  string
}

// errNotUserinfo is every refusal of the strict reader; the message says
// which rule, never a value.
func errNotUserinfo(why string) error { return fmt.Errorf("%w: %s", ErrUserinfo, why) }

// readUserinfo reads a userinfo answer strictly (SPEC section 11.15, step
// 3) over encoding/json's tokenizer: the bytes are valid UTF-8 (the
// tokenizer would replace invalid sequences silently); they hold one JSON
// object and nothing after it but whitespace; a member name, compared
// exactly after unescaping (encoding/json's Unmarshal would also match it in
// another case), appears at most once, known or not; the known members have
// their types (strings, auth_time an integer without fraction or exponent
// within 64 bits, amr an array of strings, email_verified a boolean, none of
// them null); and members it does not know are skipped, as OpenID Connect
// asks of a relying party.
func readUserinfo(body []byte) (*rawUserinfo, error) {
	if !utf8.Valid(body) {
		return nil, errNotUserinfo("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errNotUserinfo("not a JSON object")
	}
	var u rawUserinfo
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errNotUserinfo("not JSON")
		}
		name, ok := t.(string)
		if !ok {
			return nil, errNotUserinfo("not JSON")
		}
		if seen[name] {
			return nil, errNotUserinfo("a repeated member")
		}
		seen[name] = true
		switch name {
		case "sub":
			err = readString(dec, &u.Sub)
		case "client_id":
			err = readString(dec, &u.ClientID)
		case "email":
			err = readString(dec, &u.Email)
		case "locale":
			err = readString(dec, &u.Locale)
		case "name":
			err = readString(dec, &u.Name)
		case "product_key":
			err = readString(dec, &u.ProductKey)
		case "product_key_id":
			err = readString(dec, &u.ProductKeyID)
		case "auth_time":
			err = readInt(dec, &u.AuthTime)
		case "email_verified":
			err = readBool(dec, &u.EmailVerified)
		case "amr":
			err = readStrings(dec, &u.AMR)
		default:
			err = skipValue(dec)
		}
		if err != nil {
			return nil, err
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errNotUserinfo("not JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotUserinfo("something after the object")
	}
	return &u, nil
}

func readString(dec *json.Decoder, out *string) error {
	t, err := dec.Token()
	if err != nil {
		return errNotUserinfo("not JSON")
	}
	s, ok := t.(string)
	if !ok {
		return errNotUserinfo("a member is not a string")
	}
	*out = s
	return nil
}

func readInt(dec *json.Decoder, out *int64) error {
	t, err := dec.Token()
	if err != nil {
		return errNotUserinfo("not JSON")
	}
	n, ok := t.(json.Number)
	if !ok {
		return errNotUserinfo("auth_time is not a number")
	}
	// ParseInt refuses a fraction, an exponent and a value beyond 64 bits.
	v, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return errNotUserinfo("auth_time is not an integer")
	}
	*out = v
	return nil
}

func readBool(dec *json.Decoder, out *bool) error {
	t, err := dec.Token()
	if err != nil {
		return errNotUserinfo("not JSON")
	}
	b, ok := t.(bool)
	if !ok {
		return errNotUserinfo("email_verified is not a boolean")
	}
	*out = b
	return nil
}

func readStrings(dec *json.Decoder, out *[]string) error {
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return errNotUserinfo("amr is not an array")
	}
	list := []string{}
	for dec.More() {
		var s string
		if err := readString(dec, &s); err != nil {
			return err
		}
		list = append(list, s)
	}
	if t, err := dec.Token(); err != nil || t != json.Delim(']') {
		return errNotUserinfo("not JSON")
	}
	*out = list
	return nil
}

// skipValue reads one value of any type, nested ones included.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return errNotUserinfo("not JSON")
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}
