package jcs_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/jcs"
	"github.com/thehappieco/kit/seal"
)

// parse reads a JSON text the way the Go side of a JSON AAD would: numbers
// as json.Number, so Marshal sees exactly what was written.
func parse(t *testing.T, text string) (any, error) {
	d := json.NewDecoder(bytes.NewReader([]byte(text)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// TestWappieBytesJCSVectors runs the cases of golden/bytes-jcs-ts.json that
// Go can run: RFC 8785 over strings and integers, the JCS texts Wappie's
// reader protocol hashes, and UUIDv5 against Wappie's TypeScript uuidV5.
func TestWappieBytesJCSVectors(t *testing.T) {
	for _, c := range vectest.Cases(t, "wappie/golden/bytes-jcs-ts.json", "kit/jcs-ts.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				JSON      string `json:"json"`
				Namespace string `json:"namespace"`
				Name      string `json:"name_b64"`
			}
			var out struct {
				JCS  string `json:"jcs"`
				UUID string `json:"uuid"`
			}
			vectest.Decode(t, c.In, &in)
			if c.Error == "" {
				vectest.Decode(t, c.Out, &out)
			}
			switch c.Op {
			case "jcs.canonical":
				v, err := parse(t, in.JSON)
				if err != nil {
					t.Fatal(err)
				}
				got, err := jcs.Marshal(v)
				if c.Error != "" {
					if !errors.Is(err, jcs.ErrUnsupported) {
						t.Errorf("accepted: %s", got)
					}
				} else if err != nil || string(got) != out.JCS {
					t.Errorf("got %s, want %s (%v)", got, out.JCS, err)
				}
			case "bytes.uuid_v5":
				if got := seal.Row(uuid.MustParse(in.Namespace), vectest.B64(t, in.Name)).String(); got != out.UUID {
					t.Errorf("uuid %s, want %s", got, out.UUID)
				}
			default:
				vectest.Unhandled(t, c)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	for name, v := range map[string]any{
		"invalid utf-8":        "\xed\xa0\x80",
		"invalid utf-8 key":    map[string]any{"\xff": 1},
		"fraction":             4.5,
		"NaN":                  math.NaN(),
		"infinity":             math.Inf(1),
		"beyond 2^53":          int64(1 << 53),
		"below -(2^53)":        int64(-(1 << 53)),
		"uint beyond 2^53":     uint64(1 << 53),
		"json.Number fraction": json.Number("4.50"),
		"json.Number exponent": json.Number("1E30"),
		"struct":               struct{}{},
		"nested":               []any{map[string]any{"a": 1.5}},
		"pointer":              new(int),
	} {
		if got, err := jcs.Marshal(v); !errors.Is(err, jcs.ErrUnsupported) {
			t.Errorf("%s: %s, %v", name, got, err)
		}
	}
}

func TestShapes(t *testing.T) {
	for want, v := range map[string]any{
		`null`:                           nil,
		`[true,false]`:                   []any{true, false},
		`0`:                              math.Copysign(0, -1),
		`9007199254740991`:               int64(1<<53 - 1),
		`-9007199254740991`:              json.Number("-9007199254740991"),
		`["a","b"]`:                      []string{"a", "b"},
		`{"a":"x","b":"y"}`:              map[string]string{"b": "y", "a": "x"},
		"\"\u2028\u2029<>&\u007f\"":      "\u2028\u2029<>&\u007f",
		`"\u0000\b\t\n\u000b\f\r\u001f"`: "\x00\b\t\n\x0b\f\r\x1f",
		// U+10000 sorts before U+E000 by UTF-16 code units, after it by bytes.
		"{\"\U00010000\":1,\"\ue000\":2}": map[string]any{"\ue000": 2, "\U00010000": 1},
		`[1,2,3,4,5,6,7,8,9,10,11]`:       []any{int8(1), int16(2), int32(3), uint(4), uint8(5), uint16(6), uint32(7), uint64(8), float32(9), 10.0, int(11)},
	} {
		got, err := jcs.Marshal(v)
		if err != nil || string(got) != want {
			t.Errorf("got %s, want %s (%v)", got, want, err)
		}
	}
}
