package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

// encoding/json is too forgiving for a file whose fields gate key material:
// it matches member names case-insensitively ("SUB" fills Sub), lets a
// repeated member overwrite the first, ignores members it does not know and
// reads null as the zero value. The readers here walk the token stream so
// every member is seen once and exactly as written (after unescaping), and
// the value readers accept only their own JSON type. They exist for the key
// bundle and for the allowlist of WebAuthn client extension results (section
// 11.16).

var (
	errNotObject     = errors.New("not a JSON object")
	errUnknownMember = errors.New("unknown member")
	errDuplicate     = errors.New("duplicate member")
	errMissing       = errors.New("missing member")
	errTrailing      = errors.New("data after the JSON value")
	errType          = errors.New("member of the wrong JSON type")
)

// readObject reads one JSON object whose members are exactly names, each
// once. It returns the raw values by name.
func readObject(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	out, err := readMembers(raw, names...)
	if err != nil {
		return nil, err
	}
	if len(out) != len(names) {
		return nil, errMissing
	}
	return out, nil
}

// readMembers reads one JSON object whose members are drawn from names, each
// at most once, and returns the raw values of those present by name. A name
// matches only as written, after JSON unescaping: "PRF" is not "prf", while
// "pr\u0066" is, as it is for every JSON reader.
func readMembers(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errNotObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errNotObject
	}
	out := make(map[string]json.RawMessage, len(names))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errNotObject
		}
		name, _ := tok.(string) // object member names are always strings
		if !slices.Contains(names, name) {
			return nil, errUnknownMember
		}
		if _, seen := out[name]; seen {
			return nil, errDuplicate
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errNotObject
		}
		out[name] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errNotObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errTrailing
	}
	return out, nil
}

// jsonString reads a JSON string, refusing null and every other type.
func jsonString(raw json.RawMessage) (string, error) {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 || raw[0] != '"' {
		return "", errType
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errType
	}
	return s, nil
}

// jsonInt reads a JSON integer written without a fraction or an exponent and
// within a signed 64-bit integer, refusing null and every other type.
func jsonInt(raw json.RawMessage) (int64, error) {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 || raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return 0, errType
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errType
	}
	return n, nil
}

// jsonBool reads the JSON literal true or false, refusing null and every
// other type.
func jsonBool(raw json.RawMessage) (bool, error) {
	switch string(bytes.Trim(raw, " \t\r\n")) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errType
}

// jsonArray reads a JSON array, refusing null and every other type.
func jsonArray(raw json.RawMessage) ([]json.RawMessage, error) {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errType
	}
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, errType
	}
	return a, nil
}
