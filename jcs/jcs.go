// Package jcs writes RFC 8785 (JSON Canonicalization Scheme) text for the
// subset of JSON the kit's additional data and contract types use: null,
// booleans, strings, integers within ±(2^53−1), arrays and objects.
//
// Go's encoding/json cannot stand in for it: it escapes U+2028, U+2029 and,
// by default, <, > and &, which ECMAScript's JSON.stringify (and so RFC 8785)
// writes as they are. Two sides that hash a JSON AAD must agree on every
// byte, so both call this, or the TypeScript twin in js/src/jcs.ts.
//
// What it refuses: strings that are not valid UTF-8 (a lone surrogate has no
// UTF-8 form), numbers that are not integers or are outside the safe range,
// and any Go value that is not one of the types listed on Marshal.
// Non-integral numbers need ECMAScript number formatting and will be added,
// with vectors, when a contract needs them.
package jcs

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// maxSafe is 2^53−1, the largest integer every JSON implementation reads
// exactly.
const maxSafe = 1<<53 - 1

// Error is a value Marshal refuses.
type Error struct{ msg string }

func (e *Error) Error() string { return "jcs: " + e.msg }

// ErrUnsupported matches every refusal: errors.Is(err, ErrUnsupported).
var ErrUnsupported = errors.New("jcs: unsupported value")

func (e *Error) Is(target error) bool { return target == ErrUnsupported }

func refuse(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Marshal returns the canonical JSON text of v. It accepts nil, bool, string,
// every Go integer type, float32 and float64 holding an integer, json.Number
// holding an integer, []any, []string, map[string]any and map[string]string.
func Marshal(v any) ([]byte, error) {
	return appendValue(nil, v)
}

func appendValue(b []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, v), nil
	case string:
		return appendString(b, v)
	case int:
		return appendInt(b, int64(v))
	case int8:
		return appendInt(b, int64(v))
	case int16:
		return appendInt(b, int64(v))
	case int32:
		return appendInt(b, int64(v))
	case int64:
		return appendInt(b, v)
	case uint:
		return appendUint(b, uint64(v))
	case uint8:
		return appendUint(b, uint64(v))
	case uint16:
		return appendUint(b, uint64(v))
	case uint32:
		return appendUint(b, uint64(v))
	case uint64:
		return appendUint(b, v)
	case float32:
		return appendFloat(b, float64(v))
	case float64:
		return appendFloat(b, v)
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return nil, refuse("the number %s is not an integer within the safe range", v)
		}
		return appendInt(b, n)
	case []any:
		b = append(b, '[')
		for i, item := range v {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, item); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case []string:
		items := make([]any, len(v))
		for i, s := range v {
			items[i] = s
		}
		return appendValue(b, items)
	case map[string]any:
		return appendObject(b, v)
	case map[string]string:
		m := make(map[string]any, len(v))
		for k, s := range v {
			m[k] = s
		}
		return appendObject(b, m)
	}
	return nil, refuse("%T is not a JSON value this package writes", v)
}

func appendInt(b []byte, n int64) ([]byte, error) {
	if n > maxSafe || n < -maxSafe {
		return nil, refuse("the integer %d is outside ±(2^53−1)", n)
	}
	return strconv.AppendInt(b, n, 10), nil
}

func appendUint(b []byte, n uint64) ([]byte, error) {
	if n > maxSafe {
		return nil, refuse("the integer %d is outside ±(2^53−1)", n)
	}
	return strconv.AppendUint(b, n, 10), nil
}

func appendFloat(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > maxSafe {
		return nil, refuse("the number %v is not an integer within the safe range", f)
	}
	// -0 is written 0, as JSON.stringify writes it.
	return strconv.AppendInt(b, int64(f), 10), nil
}

func appendObject(b []byte, m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !utf8.ValidString(k) {
			return nil, refuse("an object key is not valid UTF-8")
		}
		keys = append(keys, k)
	}
	// RFC 8785 §3.2.3: by UTF-16 code units, which differs from Go's
	// byte order for characters above U+FFFF against U+E000–U+FFFF.
	slices.SortFunc(keys, func(a, c string) int {
		return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(c)))
	})
	b = append(b, '{')
	for i, k := range keys {
		if i > 0 {
			b = append(b, ',')
		}
		var err error
		if b, err = appendString(b, k); err != nil {
			return nil, err
		}
		b = append(b, ':')
		if b, err = appendValue(b, m[k]); err != nil {
			return nil, err
		}
	}
	return append(b, '}'), nil
}

// appendString writes a string with the escapes JSON.stringify uses: the two
// that must be escaped, the five short forms, \u00xx in lower-case hex for the
// other controls, and everything else as itself.
func appendString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, refuse("a string is not valid UTF-8")
	}
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			} else {
				b = append(b, c)
			}
		}
	}
	return append(b, '"'), nil
}
