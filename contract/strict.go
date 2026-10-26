package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// The settings part's strict reading (SPEC section 11.19). What an app sends
// the platform is read as the platform reads it: one JSON value of valid
// UTF-8, no escape of half a UTF-16 surrogate pair, no member twice in any
// object, and every member named exactly as the type names it, none it does
// not have, and every one present but those it marks omitempty or omitzero.
// encoding/json alone would match a name in any case, Unicode-folded ones
// included, take the last of two members of one name, read U+FFFD for a
// lone surrogate, and fill a missing member with its zero value.

// wellFormed reports whether raw is one JSON value of valid UTF-8, with no
// escape of half a surrogate pair and no member twice in any object.
func wellFormed(raw []byte) bool {
	if !utf8.Valid(raw) || loneSurrogate(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if !walkJSON(dec) {
		return false
	}
	_, err := dec.Token()
	return err == io.EOF
}

// walkJSON reads one value, refusing an object that names a member twice.
func walkJSON(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			name, ok := tok.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
			if !walkJSON(dec) {
				return false
			}
		}
		_, err := dec.Token()
		return err == nil
	case json.Delim('['):
		for dec.More() {
			if !walkJSON(dec) {
				return false
			}
		}
		_, err := dec.Token()
		return err == nil
	}
	return true
}

// loneSurrogate reports whether a string of the JSON text raw escapes half
// a UTF-16 surrogate pair. Only the strings are read, and in them a
// backslash always starts an escape.
func loneSurrogate(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			r, ok := escapedUnit(raw[i:])
			if !ok {
				i++
				continue
			}
			i += 5
			switch {
			case r >= 0xdc00 && r <= 0xdfff:
				return true
			case r >= 0xd800 && r <= 0xdbff:
				low, ok := escapedUnit(raw[i+1:])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return true
				}
				i += 6
			}
		}
	}
	return false
}

// escapedUnit reads the \uXXXX escape b starts with.
func escapedUnit(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range b[2:6] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// exactShape reports whether every object of raw that t's members reach
// names its members exactly as t names them, none it does not have, and
// every one present but those t marks omitempty or omitzero. A value of
// another shape than t's is left to the decoder, which refuses it; a value
// whose type decodes itself (json.Unmarshaler) or is kept raw is its own.
func exactShape(raw json.RawMessage, t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		if string(bytes.TrimSpace(raw)) == "null" {
			return true
		}
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) || t == reflect.TypeFor[json.RawMessage]() {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		if string(bytes.TrimSpace(raw)) == "null" {
			// Only a pointer may be null: a struct's null would read as
			// every member at its zero value.
			return false
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return true
		}
		type field struct {
			t        reflect.Type
			optional bool
		}
		fields := map[string]field{}
		for i := 0; i < t.NumField(); i++ {
			name, opts, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			fields[name] = field{t.Field(i).Type, strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")}
		}
		for name, v := range members {
			f, ok := fields[name]
			if !ok || !exactShape(v, f.t) {
				return false
			}
		}
		for name, f := range fields {
			if _, ok := members[name]; !ok && !f.optional {
				return false
			}
		}
	case reflect.Slice:
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) != nil {
			return true
		}
		for _, e := range elems {
			if !exactShape(e, t.Elem()) {
				return false
			}
		}
	}
	return true
}

// decodeExact decodes raw into dst, a pointer, as the platform reads what an
// app sends (wellFormed, exactShape), with no member dst does not have; raw
// is never null, which would leave dst as it was.
func decodeExact(raw []byte, dst any, what string) error {
	if !wellFormed(raw) {
		return invalid("%s: not one well-formed JSON value, or a member twice", what)
	}
	if !exactShape(raw, reflect.TypeOf(dst).Elem()) {
		return invalid("%s: a member missing, unknown or not named exactly", what)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid("%s", what)
	}
	return nil
}
