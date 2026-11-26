package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The strict reading's members against encoding/json's own (Mailie's
// review of 2026-11-26): for every shape below, DecodeStrict reads back
// what json.Marshal writes, and of the bodies made of any subset of those
// members it takes exactly those encoding/json reads and writes back the
// same, but for the shapes a struct tag makes unsure (unsureShapes).
//
// The types the corpus names are exported where encoding/json must set an
// embedded pointer to them. The shapes go vet refuses to declare (an
// unexported field with a json tag, one json name twice through two
// embedded values, a tag with a space) are built with reflect.StructOf.

// Mailie's 1: T8 is embedded twice at one depth, so its own members cancel,
// but S8, which it embeds through a pointer, is explored once: z stays.
type DiffS8 struct {
	Z int `json:"z"`
}
type DiffT8 struct{ *DiffS8 }
type DiffX8 struct{ DiffT8 }
type DiffY8 struct{ DiffT8 }
type DiffC8 struct {
	DiffX8
	DiffY8
	Q int `json:"q"`
}

// Mailie's 1, with the kit's type: EmailAccountsSettings' own members
// cancel, MailboxLinking's stay (DiffWW is built by StructOf).
type DiffW1 struct{ EmailAccountsSettings }
type DiffW2 struct{ EmailAccountsSettings }

// Mailie's 2 (DiffU13 and the tie are built by StructOf).
type DiffTA struct {
	X int `json:"x"`
}

// Mailie's 3: a struct embedding a pointer to itself, and two embedding
// pointers to each other, and three in a ring.
type DiffLoop struct {
	*DiffLoop
	X int `json:"x"`
}
type DiffMA struct {
	*DiffMB
	A int `json:"a"`
}
type DiffMB struct {
	*DiffMA
	B int `json:"b"`
}
type DiffR1 struct {
	*DiffR2
	R1 int `json:"r1"`
}
type DiffR2 struct {
	*DiffR3
	R2 int `json:"r2"`
}
type DiffR3 struct {
	*DiffR1
	R3 int `json:"r3"`
}

// Mailie's 4: an inner group present makes its outer group present.
type DiffInner5 struct {
	Z int `json:"z"`
	W int `json:"w"`
}
type DiffMid5 struct {
	Y int `json:"y"`
	*DiffInner5
}
type DiffC5 struct {
	*DiffMid5
	Top int `json:"top"`
}
type DiffEASPtrFirst struct {
	*EmailAccountsSettings
	Own int `json:"own"`
}
type DiffEASPtrLast struct {
	Own int `json:"own"`
	*EmailAccountsSettings
}
type DiffEASFirst struct {
	EmailAccountsSettings
	Own int `json:"own"`
}
type DiffEASLast struct {
	Own int `json:"own"`
	EmailAccountsSettings
}
type DiffEASItems struct {
	Items []string `json:"items"`
	EmailAccountsSettings
}
type DiffEASPtrItems struct {
	*EmailAccountsSettings
	Items []string `json:"items"`
}

// Mailie's 5: untagged members, and tags read as encoding/json reads them.
type DiffUntagged struct {
	N int
	M int `json:"m"`
}
type DiffDashComma struct {
	D int `json:"-,"`
	E int `json:"e"`
}
type DiffDash struct {
	D int `json:"-"`
	E int `json:"e"`
}
type DiffEmbedOption struct {
	Sub DiffTA `json:",embed"`
	Y   int    `json:"y"`
}
type DiffFormatOption struct {
	At time.Time `json:"at,format:RFC3339"`
}
type DiffCaseOption struct {
	X int `json:"x,case:ignore"`
}
type DiffOtherOption struct {
	X int `json:"x,inline"`
}
type DiffSymbolName struct {
	X int `json:"€"`
}
type DiffNames struct {
	A  int `json:"a"`
	B  int `json:"A"`
	C  int `json:"é"`
	D  int `json:"a-b.c"`
	E  int `json:"$x y"`
	F  int `json:",omitempty"`
	G  int `json:","`
	Hh int `json:""`
}

// omitempty, omitzero and string.
type DiffOptional struct {
	A int    `json:"a,omitempty"`
	B string `json:"b,omitzero"`
	C int    `json:"c"`
	D *int   `json:"d,omitempty"`
	E []int  `json:"e,omitempty"`
	F int    `json:"f,string"`
	G int    `json:"g,omitempty,string"`
}

// Tagged and untagged members of one name, at one depth and at two, of
// shapes apart, so that the strict reading holding a value to the wrong
// one shows.
type DiffUntaggedN struct{ N DiffS8 }
type DiffUntaggedN2 struct{ N DiffS8 }
type DiffTaggedN struct {
	X DiffTA `json:"N"`
}
type DiffTaggedWins struct {
	DiffUntaggedN
	DiffTaggedN
	K int `json:"k"`
}
type DiffUntaggedTie struct {
	DiffUntaggedN
	DiffUntaggedN2
	K int `json:"k"`
}
type DiffShallowUntaggedWins struct {
	N int
	DiffTaggedN
}
type DiffTaggedWinsOverTwo struct {
	DiffTaggedN
	DiffUntaggedN
	DiffUntaggedN2
}

// Unexported embedded fields.
type diffInner struct {
	A int `json:"a"`
	b int
}
type DiffUnexportedEmbed struct {
	diffInner
	Y int `json:"y"`
}
type diffInnerP struct {
	A int `json:"a"`
}
type DiffUnexportedNamedEmbed struct {
	diffInner `json:"in"`
	Y         int `json:"y"`
}
type DiffUnexportedEmbedPtr struct {
	*diffInnerP
	Y int `json:"y"`
}
type diffInt int
type DiffInt int
type DiffUnexportedNonStruct struct {
	diffInt
	Y int `json:"y"`
}
type DiffExportedNonStruct struct {
	DiffInt
	Y int `json:"y"`
}
type DiffExportedNonStructPtr struct {
	*DiffInt
	Y int `json:"y"`
}

// Embedded structs given a name are members.
type DiffNamedEmbed struct {
	DiffTA `json:"emb"`
	Y      int `json:"y"`
}
type DiffNamedEmbedPtr struct {
	*DiffTA `json:"emb"`
	Y       int `json:"y"`
}
type DiffEmbedOmitempty struct {
	DiffTA `json:",omitempty"`
	Y      int `json:"y"`
}

// Nested value embeds four deep, with shadowing at each depth.
type DiffV4 struct {
	D4 int `json:"d4"`
	S  int `json:"s"`
}
type DiffV3 struct {
	DiffV4
	D3 int `json:"d3"`
	S  int `json:"s"`
}
type DiffV2 struct {
	DiffV3
	D2 int `json:"d2"`
}
type DiffV1 struct {
	DiffV2
	D1 int `json:"d1"`
}
type DiffV0 struct {
	DiffV1
	S int `json:"t"`
}

// Nested pointer embeds four deep, each a group within the last.
type DiffP4 struct {
	D4 int  `json:"d4"`
	O4 *int `json:"o4,omitempty"`
}
type DiffP3 struct {
	*DiffP4
	D3 int `json:"d3"`
}
type DiffP2 struct {
	*DiffP3
	D2 int `json:"d2"`
}
type DiffP1 struct {
	*DiffP2
	D1 int `json:"d1"`
}
type DiffP0 struct {
	*DiffP1
	D0 int `json:"d0"`
}

// Value and pointer embeds alternating.
type DiffM3 struct {
	*DiffP4
	M3 int `json:"m3"`
}
type DiffM2 struct {
	DiffM3
	M2 int `json:"m2"`
}
type DiffM1 struct {
	*DiffM2
	M1 int `json:"m1"`
}
type DiffM0 struct {
	DiffM1
	M0 int `json:"m0"`
}

// One type at two depths, and at one depth through a value and a pointer.
type DiffMidTA struct{ DiffTA }
type DiffTwoDepths struct {
	DiffTA
	DiffMidTA
}
type DiffMidTAPtr struct{ *DiffTA }
type DiffValueAndPointer struct {
	DiffMidTA
	DiffMidTAPtr
	K int `json:"k"`
}

// A group of optional members only, and a group beside a shadowed name.
type DiffAllOptional struct {
	A int `json:"a,omitempty"`
	B int `json:"b,omitzero"`
}
type DiffOptionalGroup struct {
	*DiffAllOptional
	C int `json:"c"`
}
type DiffShadowedGroup struct {
	*DiffP4
	D4 string `json:"d4"`
}

// Members a list, an array, a map and an interface hold.
type DiffContainers struct {
	Rows  []DiffC5          `json:"rows"`
	Pair  [2]DiffC5         `json:"pair"`
	ByKey map[string]DiffC5 `json:"by_key"`
	Ints  map[string]int64  `json:"ints"`
	Any   any               `json:"any"`
	Raw   json.RawMessage   `json:"raw"`
	Bytes []byte            `json:"bytes"`
	At    Time              `json:"at"`
	When  *Time             `json:"when"`
}

// The review of 15e8b36 (2026-11-26): an array holds exactly its length,
// an interface may be null, a []byte given as a list is held to its
// elements, and a recursive type costs its body's length.
type DiffArray struct {
	V [2]int `json:"v"`
}
type DiffArrayOfStructs struct {
	A [2]DiffTA `json:"a"`
}
type DiffInterface struct {
	I any `json:"i"`
}
type DiffBytes struct {
	B []byte `json:"b"`
}
type DiffNode struct {
	N *DiffNode `json:"n"`
}
type DiffTree struct {
	C []DiffTree `json:"c"`
}

// Rings of pointer types, which hold nothing but null (fill cannot fill
// them, so they are not in the corpus).
type (
	DiffRingP  *DiffRingQ
	DiffRingQ  *DiffRingP
	DiffRing3A *DiffRing3B
	DiffRing3B *DiffRing3C
	DiffRing3C *DiffRing3A
)
type DiffHoldsRings struct {
	F DiffRingP  `json:"f"`
	G DiffRing3A `json:"g,omitempty"`
}

// The lattice's root.
type DiffLattice struct {
	*DiffLatA0
	*DiffLatB0
	Top int `json:"top"`
}

const kitPkg = "github.com/thehappieco/kit/contract"

// structOf builds a struct go vet would refuse to declare.
func structOf(fields ...reflect.StructField) reflect.Type { return reflect.StructOf(fields) }

func embedded(t reflect.Type) reflect.StructField {
	return reflect.StructField{Name: t.Name(), Type: t, Anonymous: true}
}

func field(name string, t reflect.Type, tag string) reflect.StructField {
	f := reflect.StructField{Name: name, Type: t, Tag: reflect.StructTag(tag)}
	if name[0] >= 'a' && name[0] <= 'z' {
		f.PkgPath = kitPkg
	}
	return f
}

var (
	intType    = reflect.TypeFor[int]()
	intPtrType = reflect.TypeFor[*int]()
	stringType = reflect.TypeFor[string]()
)

// differentialShape is one shape of the corpus. unsure, when not empty, is
// why the strict reading refuses every object of it.
type differentialShape struct {
	name   string
	t      reflect.Type
	unsure string
}

func differentialCorpus() []differentialShape {
	of := func(name string, t reflect.Type) differentialShape { return differentialShape{name: name, t: t} }
	unsure := func(name string, t reflect.Type, why string) differentialShape {
		return differentialShape{name: name, t: t, unsure: why}
	}
	return []differentialShape{
		of("1 a type twice at one depth, its pointer's members once", reflect.TypeFor[DiffC8]()),
		of("1 EmailAccountsSettings twice at one depth", structOf(embedded(reflect.TypeFor[DiffW1]()), embedded(reflect.TypeFor[DiffW2]()), field("Own", intType, `json:"own"`))),
		of("2 an unexported tagged field beside an embedded one of its name", structOf(field("x", intPtrType, `json:"x"`), embedded(reflect.TypeFor[DiffTA]()))),
		of("2 an unexported tagged field beside an exported one of its name", structOf(field("x", intType, `json:"x"`), field("X", intType, `json:"x"`))),
		of("3 a struct embedding a pointer to itself", reflect.TypeFor[DiffLoop]()),
		of("3 two structs embedding pointers to each other", reflect.TypeFor[DiffMA]()),
		of("3 three structs in a ring of pointers", reflect.TypeFor[DiffR1]()),
		of("4 a pointer group within a pointer group", reflect.TypeFor[DiffC5]()),
		of("4 *EmailAccountsSettings before an own member", reflect.TypeFor[DiffEASPtrFirst]()),
		of("4 *EmailAccountsSettings after an own member", reflect.TypeFor[DiffEASPtrLast]()),
		of("EmailAccountsSettings before an own member", reflect.TypeFor[DiffEASFirst]()),
		of("EmailAccountsSettings after an own member", reflect.TypeFor[DiffEASLast]()),
		of("an own items shadowing EmailAccountsSettings' items", reflect.TypeFor[DiffEASItems]()),
		of("an own items shadowing *EmailAccountsSettings' items", reflect.TypeFor[DiffEASPtrItems]()),
		of("5 an untagged member named by its Go name", reflect.TypeFor[DiffUntagged]()),
		of(`5 a tag "-," naming the member "-"`, reflect.TypeFor[DiffDashComma]()),
		of(`a tag "-" leaving the member out`, reflect.TypeFor[DiffDash]()),
		unsure(`5 the option embed`, reflect.TypeFor[DiffEmbedOption](), "Go 1.27's v2 inlines a field tagged embed; Go 1.26 reads it as a member"),
		unsure(`the option format`, reflect.TypeFor[DiffFormatOption](), "Go 1.27's v2 reads format (and refuses it in v1's calls); Go 1.26 ignores it"),
		unsure(`the option case`, reflect.TypeFor[DiffCaseOption](), "Go 1.27's v2 reads case; Go 1.26 ignores it"),
		unsure(`an option neither toolchain knows`, reflect.TypeFor[DiffOtherOption](), "an option the kit does not use: refused rather than kept in step with v2's grammar"),
		unsure(`5 a tag name with a backslash`, structOf(field("X", intType, `json:"a\\b"`)), `Go 1.26 names the member X (an invalid name); Go 1.27 names it "a"`),
		unsure(`5 a tag name with a quote`, structOf(field("X", intType, `json:"a'b"`)), "Go 1.26 names the member X; Go 1.27 may read a quoted name"),
		unsure(`5 a tag name with a symbol v1 refuses`, reflect.TypeFor[DiffSymbolName](), `Go 1.26 names the member X; Go 1.27 names it "€"`),
		unsure(`an option followed by a space`, structOf(field("X", intType, `json:"x,omitempty "`)), "Go 1.27's v2 reads omitempty; Go 1.26 reads the option \"omitempty \", which it ignores"),
		unsure(`an unexported embedded struct given a name`, reflect.TypeFor[DiffUnexportedNamedEmbed](), "Go 1.27 leaves such a member out when its type has a method of encoding/json's, Go 1.26 never does"),
		of("names v1 and v2 read alike, and empty tag names", reflect.TypeFor[DiffNames]()),
		of("omitempty, omitzero and string", reflect.TypeFor[DiffOptional]()),
		of("a tagged member wins over an untagged one at one depth", reflect.TypeFor[DiffTaggedWins]()),
		of("two untagged members at one depth cancel", reflect.TypeFor[DiffUntaggedTie]()),
		of("two tagged members at one depth cancel", structOf(embedded(reflect.TypeFor[DiffTA]()), embedded(reflect.TypeFor[DiffTaggedN]()), embedded(reflect.TypeFor[DiffS8]()), field("Z", intType, `json:"x"`))),
		of("a shallower untagged member wins over a deeper tagged one", reflect.TypeFor[DiffShallowUntaggedWins]()),
		of("a tagged member wins over two untagged ones", reflect.TypeFor[DiffTaggedWinsOverTwo]()),
		of("a tagged and an untagged member in one struct", structOf(field("N", intType, ""), field("M", intType, `json:"N"`))),
		of("an unexported embedded struct's exported members", reflect.TypeFor[DiffUnexportedEmbed]()),
		of("an unexported embedded pointer's members", reflect.TypeFor[DiffUnexportedEmbedPtr]()),
		of("an unexported embedded non-struct left out", reflect.TypeFor[DiffUnexportedNonStruct]()),
		of("an exported embedded non-struct named by its type", reflect.TypeFor[DiffExportedNonStruct]()),
		of("an exported embedded pointer to a non-struct", reflect.TypeFor[DiffExportedNonStructPtr]()),
		of("an embedded struct given a name", reflect.TypeFor[DiffNamedEmbed]()),
		of("an embedded pointer given a name", reflect.TypeFor[DiffNamedEmbedPtr]()),
		of("an embedded struct with only an option", reflect.TypeFor[DiffEmbedOmitempty]()),
		of("value embeds four deep", reflect.TypeFor[DiffV0]()),
		of("pointer embeds four deep", reflect.TypeFor[DiffP0]()),
		of("value and pointer embeds alternating", reflect.TypeFor[DiffM0]()),
		of("one type at two depths", reflect.TypeFor[DiffTwoDepths]()),
		of("one type at one depth through a value and a pointer", reflect.TypeFor[DiffValueAndPointer]()),
		of("a group of optional members only", reflect.TypeFor[DiffOptionalGroup]()),
		of("a group one of whose names is shadowed", reflect.TypeFor[DiffShadowedGroup]()),
		of("lists, arrays, maps, an interface, raw values and times", reflect.TypeFor[DiffContainers]()),
		of("a lattice of pointer embeds 22 deep", reflect.TypeFor[DiffLattice]()),
		of("an array of numbers", reflect.TypeFor[DiffArray]()),
		of("an array of structs", reflect.TypeFor[DiffArrayOfStructs]()),
		of("an interface", reflect.TypeFor[DiffInterface]()),
		of("a []byte", reflect.TypeFor[DiffBytes]()),
		of("a struct holding a pointer to itself", reflect.TypeFor[DiffNode]()),
	}
}

// fill gives every settable leaf of v a value of its own and allocates
// every pointer it can, but one to a struct type it is already filling.
func fill(v reflect.Value, n *int, filling map[reflect.Type]bool) {
	*n++
	if v.Type() == reflect.TypeFor[Time]() {
		v.Set(reflect.ValueOf(Time{time.Date(2026, 11, 26, 0, 0, *n, 0, time.UTC)}))
		return
	}
	if v.Type() == reflect.TypeFor[json.RawMessage]() {
		v.SetBytes([]byte(fmt.Sprintf(`{"raw":%d}`, *n)))
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(*n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(*n))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(*n) + 0.5)
	case reflect.String:
		v.SetString(fmt.Sprintf("s%d", *n))
	case reflect.Interface:
		if v.NumMethod() == 0 {
			v.Set(reflect.ValueOf(fmt.Sprintf("any%d", *n)))
		}
	case reflect.Pointer:
		if filling[v.Type().Elem()] {
			return
		}
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), n, filling)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), n, filling)
		v.Set(s)
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fill(v.Index(i), n, filling)
		}
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		e := reflect.New(v.Type().Elem()).Elem()
		fill(e, n, filling)
		m.SetMapIndex(reflect.ValueOf(fmt.Sprintf("k%d", *n)), e)
		v.Set(m)
	case reflect.Struct:
		filling[v.Type()] = true
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.CanSet() || f.Kind() == reflect.Struct {
				fill(f, n, filling)
			}
		}
		delete(filling, v.Type())
	}
}

// filled is a value of t (a pointer to it), filled.
func filled(t reflect.Type) any {
	p := reflect.New(t)
	n := 0
	fill(p.Elem(), &n, map[reflect.Type]bool{})
	return p.Interface()
}

// topMembers is the members of the JSON object raw, in order.
func topMembers(t *testing.T, raw []byte) (names []string, values []json.RawMessage) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		names, values = append(names, tok.(string)), append(values, v)
	}
	return names, values
}

func objectOf(names []string, values []json.RawMessage, mask uint64) ([]byte, []string) {
	var b bytes.Buffer
	var kept []string
	b.WriteByte('{')
	for i := range names {
		if mask&(1<<i) == 0 {
			continue
		}
		if len(kept) > 0 {
			b.WriteByte(',')
		}
		name, _ := json.Marshal(names[i])
		b.Write(name)
		b.WriteByte(':')
		b.Write(values[i])
		kept = append(kept, names[i])
	}
	b.WriteByte('}')
	return b.Bytes(), kept
}

// masks is every subset of n members up to 10, else 1024 chosen by a fixed
// sequence beside every one with a single member left out or kept.
func masks(n int) []uint64 {
	if n <= 10 {
		out := make([]uint64, 0, 1<<n)
		for m := uint64(0); m < 1<<n; m++ {
			out = append(out, m)
		}
		return out
	}
	all := uint64(1)<<n - 1
	out := []uint64{0, all}
	for i := 0; i < n; i++ {
		out = append(out, all&^(1<<i), 1<<i)
	}
	x := uint64(0x9e3779b97f4a7c15)
	for len(out) < 1024 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out = append(out, x&all)
	}
	return out
}

// oracle reports whether encoding/json reads body as a t with no unknown
// member, and writes back exactly the members body names.
func oracle(t reflect.Type, body []byte, names []string) (bool, []byte) {
	v := reflect.New(t)
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v.Interface()) != nil {
		return false, nil
	}
	back, err := json.Marshal(v.Interface())
	if err != nil {
		return false, nil
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(back, &members) != nil || len(members) != len(names) {
		return false, back
	}
	for _, name := range names {
		if _, ok := members[name]; !ok {
			return false, back
		}
	}
	return true, back
}

func TestTheStrictReadingTakesExactlyTheMembersEncodingJSONWritesAndReadsBack(t *testing.T) {
	for _, s := range differentialCorpus() {
		t.Run(s.name, func(t *testing.T) {
			if got := shapeOf(s.t).unsure; got != (s.unsure != "") {
				t.Fatalf("unsure is %v", got)
			}
			raw, err := json.Marshal(filled(s.t))
			if err != nil && s.unsure != "" {
				// Go 1.27 refuses to write the option format at all.
				if err := DecodeStrict([]byte(`{}`), reflect.New(s.t).Interface()); !errors.Is(err, ErrInvalid) {
					t.Errorf("an unsure shape's body was taken: {}")
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			full := reflect.New(s.t)
			err = DecodeStrict(raw, full.Interface())
			switch {
			case shapeOf(s.t).unsure:
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("an unsure shape's body was taken: %s", raw)
				}
			case err != nil:
				t.Fatalf("DecodeStrict refused what json.Marshal wrote, %s: %v", raw, err)
			default:
				if back, _ := json.Marshal(full.Interface()); !bytes.Equal(back, raw) {
					t.Fatalf("read back as %s, written as %s", back, raw)
				}
			}
			names, values := topMembers(t, raw)
			for _, m := range masks(len(names)) {
				body, kept := objectOf(names, values, m)
				want, wrote := oracle(s.t, body, kept)
				v := reflect.New(s.t)
				got := DecodeStrict(body, v.Interface()) == nil
				if shapeOf(s.t).unsure {
					if got {
						t.Errorf("an unsure shape's body was taken: %s", body)
					}
					continue
				}
				if got != want {
					t.Errorf("%s: DecodeStrict %v, encoding/json %v (wrote back %s)", body, got, want, wrote)
					continue
				}
				if got {
					if back, _ := json.Marshal(v.Interface()); !bytes.Equal(back, body) {
						t.Errorf("%s read back as %s", body, back)
					}
				}
			}
		})
	}
}

// Mailie's six cases of 2026-11-26, body by body.
func TestTheStrictReadingReadsMailiesShapesAsEncodingJSONDoes(t *testing.T) {
	ok := func(t *testing.T, v any, body string) {
		t.Helper()
		if err := DecodeStrict([]byte(body), v); err != nil {
			t.Errorf("%T refused %s: %v", v, body, err)
		}
	}
	refused := func(t *testing.T, v any, body string) {
		t.Helper()
		if err := DecodeStrict([]byte(body), v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%T took %s", v, body)
		}
	}
	t.Run("1 the tie counts a type once per depth", func(t *testing.T) {
		var c DiffC8
		ok(t, &c, `{"z":1,"q":2}`)
		if c.DiffX8.DiffS8 == nil || c.DiffX8.Z != 1 {
			t.Errorf("z went elsewhere: %+v", c)
		}
		ww := reflect.New(structOf(embedded(reflect.TypeFor[DiffW1]()), embedded(reflect.TypeFor[DiffW2]()), field("Own", intType, `json:"own"`))).Interface()
		ok(t, ww, `{"storage_paused":true,"can_link":false,"places_free":null,"own":1}`)
		refused(t, ww, `{"storage_paused":true,"can_link":false,"places_free":null,"own":1,"availability":"usable"}`)
	})
	t.Run("2 an unexported field is no member", func(t *testing.T) {
		u := reflect.New(structOf(field("x", intPtrType, `json:"x"`), embedded(reflect.TypeFor[DiffTA]()))).Interface()
		refused(t, u, `{"x":null}`)
		ok(t, u, `{"x":2}`)
		tie := reflect.New(structOf(field("x", intType, `json:"x"`), field("X", intType, `json:"x"`))).Interface()
		ok(t, tie, `{"x":2}`)
	})
	t.Run("3 a struct embedding a pointer to itself", func(t *testing.T) {
		ok(t, &DiffLoop{}, `{"x":1}`)
		refused(t, &DiffLoop{}, `{}`)
		ok(t, &DiffMA{}, `{"a":1,"b":2}`)
		refused(t, &DiffMA{}, `{"b":2}`)
		ok(t, &DiffMA{}, `{"a":1}`)
		ok(t, &DiffR1{}, `{"r1":1,"r2":2,"r3":3}`)
		refused(t, &DiffR1{}, `{"r1":1,"r3":3}`)
	})
	t.Run("4 an inner group present makes its outer group present", func(t *testing.T) {
		refused(t, &DiffC5{}, `{"top":1,"z":3,"w":4}`)
		ok(t, &DiffC5{}, `{"top":1,"y":2,"z":3,"w":4}`)
		ok(t, &DiffC5{}, `{"top":1,"y":2}`)
		ok(t, &DiffC5{}, `{"top":1}`)
		refused(t, &DiffC5{}, `{"top":1,"y":2,"z":3}`)
		refused(t, &DiffEASPtrFirst{}, `{"storage_paused":false,"can_link":true,"places_free":2,"own":1}`)
		ok(t, &DiffEASPtrFirst{}, `{"availability":"usable","link_min_role":null,"texts":{"team_sync":"r"},"storage_paused":false,"can_link":true,"places_free":2,"items":[],"own":1}`)
		ok(t, &DiffEASPtrFirst{}, `{"own":1}`)
	})
	t.Run("5 untagged members and tag names", func(t *testing.T) {
		ok(t, &DiffUntagged{}, `{"N":1,"m":2}`)
		refused(t, &DiffUntagged{}, `{"m":2}`)
		refused(t, &DiffUntagged{}, `{"n":1,"m":2}`)
		ok(t, &DiffDashComma{}, `{"-":1,"e":2}`)
		refused(t, &DiffDashComma{}, `{"D":1,"e":2}`)
		ok(t, &DiffDash{}, `{"e":2}`)
		refused(t, &DiffDash{}, `{"-":1,"e":2}`)
		refused(t, &DiffEmbedOption{}, `{"Sub":{"x":1},"y":2}`)
		refused(t, &DiffEmbedOption{}, `{"x":1,"y":2}`)
	})
}

// The review of 15e8b36's bodies: DecodeStrict takes a body exactly when
// encoding/json reads it and writes it back byte for byte, but the null a
// nil slice or map writes (nilNull), which it refuses as it refuses null
// for any list or object.
func TestTheStrictReadingTakesABodyOnlyWhenEncodingJSONWritesItBack(t *testing.T) {
	nilNull := map[string]bool{`{"b":null}`: true}
	for _, c := range []struct {
		t    reflect.Type
		body string
		want bool
	}{
		{reflect.TypeFor[DiffArray](), `{"v":[1,2]}`, true},
		{reflect.TypeFor[DiffArray](), `{"v":[1]}`, false},
		{reflect.TypeFor[DiffArray](), `{"v":[1,2,3]}`, false},
		{reflect.TypeFor[DiffArray](), `{"v":[]}`, false},
		{reflect.TypeFor[DiffArray](), `{"v":[1,null]}`, false},
		{reflect.TypeFor[DiffArray](), `{"v":null}`, false},
		{reflect.TypeFor[DiffArrayOfStructs](), `{"a":[{"x":1},{"x":2}]}`, true},
		{reflect.TypeFor[DiffArrayOfStructs](), `{"a":[{"x":1}]}`, false},
		{reflect.TypeFor[DiffArrayOfStructs](), `{"a":[{"x":1},{"x":2},{"x":3}]}`, false},
		{reflect.TypeFor[DiffArrayOfStructs](), `{"a":[{"x":1},{}]}`, false},
		{reflect.TypeFor[DiffInterface](), `{"i":null}`, true},
		{reflect.TypeFor[DiffInterface](), `{"i":"s"}`, true},
		{reflect.TypeFor[DiffInterface](), `{"i":{"a":[1,null]}}`, true},
		{reflect.TypeFor[DiffInterface](), `{"i":{"a":1,"a":2}}`, false},
		{reflect.TypeFor[DiffBytes](), `{"b":"AQA="}`, true},
		{reflect.TypeFor[DiffBytes](), `{"b":[1,null]}`, false},
		{reflect.TypeFor[DiffBytes](), `{"b":null}`, false},
		{reflect.TypeFor[DiffNode](), `{"n":null}`, true},
		{reflect.TypeFor[DiffNode](), `{"n":{"n":{"n":null}}}`, true},
		{reflect.TypeFor[DiffNode](), `{"n":{"n":{}}}`, false},
		{reflect.TypeFor[DiffTree](), `{"c":[{"c":[]},{"c":[{"c":[]}]}]}`, true},
		{reflect.TypeFor[DiffTree](), `{"c":[{"c":[]},{"c":[{}]}]}`, false},
		{reflect.TypeFor[DiffTree](), `{"c":[{"c":[]},{"c":[null]}]}`, false},
	} {
		v := reflect.New(c.t)
		got := DecodeStrict([]byte(c.body), v.Interface()) == nil
		if got != c.want {
			t.Errorf("%s %s: DecodeStrict took it: %v", c.t.Name(), c.body, got)
		}
		names, _ := topMembers(t, []byte(c.body))
		ok, back := oracle(c.t, []byte(c.body), names)
		if writesBack := ok && bytes.Equal(back, []byte(c.body)); writesBack != (c.want || nilNull[c.body]) {
			t.Errorf("%s %s: encoding/json writes it back: %v (%s)", c.t.Name(), c.body, writesBack, back)
		}
	}
}

// returnsWithin runs f and fails t unless it returns within d.
func returnsWithin(t *testing.T, d time.Duration, what string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- f() }()
	select {
	case err := <-done:
		if took := time.Since(start); took > d {
			t.Errorf("%s took %v", what, took)
		}
		return err
	case <-time.After(d + 5*time.Second):
		t.Fatalf("%s did not return", what)
		return nil
	}
}

func TestTheStrictReadingNeverLoopsOnARingOfPointerTypes(t *testing.T) {
	// Before, a ring of two pointer types never left exactShape's pointer
	// loop for a value other than null. encoding/json itself cannot read
	// these types (Go 1.26 never returns, Go 1.27's stack overflows), so
	// the strict reading refuses them before it.
	for _, c := range []struct {
		v    func() any
		body string
		want bool
	}{
		{func() any { return &DiffHoldsRings{} }, `{"f":1}`, false},
		{func() any { return &DiffHoldsRings{} }, `{"f":{}}`, false},
		{func() any { return &DiffHoldsRings{} }, `{"f":null,"g":[1]}`, false},
		{func() any { return &DiffHoldsRings{} }, `{"f":null}`, true},
		{func() any { return &DiffHoldsRings{} }, `{"f":null,"g":null}`, true},
		{func() any { return new(DiffRingP) }, `1`, false},
		{func() any { return new(DiffRing3B) }, `"s"`, false},
	} {
		err := returnsWithin(t, time.Second, c.body, func() error { return DecodeStrict([]byte(c.body), c.v()) })
		if (err == nil) != c.want {
			t.Errorf("%T %s: %v", c.v(), c.body, err)
		}
	}
}

func TestTheStrictReadingRefusesWhatEncodingJSONHoldsTooDeep(t *testing.T) {
	// encoding/json reads at most 10000 objects and lists deep, on Go 1.26
	// and on Go 1.27, but Go 1.26's Decoder.Token counts no depth: before,
	// a body of a few MiB of "[" overflowed the stack there, a fatal error.
	for _, c := range []struct {
		open, close string
		depth       int
		want        bool
	}{
		{"[", "]", maxDepth, true},
		{"[", "]", maxDepth + 1, false},
		{`{"a":`, "}", maxDepth, true},
		{`{"a":`, "}", maxDepth + 1, false},
		{"[", "]", 5 << 19, false},
		{`{"a":[`, "]}", maxDepth / 2, true},
		{`{"a":[`, "]}", maxDepth/2 + 1, false},
	} {
		leaf := ""
		if c.open[0] == '{' {
			leaf = "1"
		}
		body := []byte(strings.Repeat(c.open, c.depth) + leaf + strings.Repeat(c.close, c.depth))
		var v any
		err := returnsWithin(t, time.Second, fmt.Sprintf("%s %d deep", c.open, c.depth), func() error { return DecodeStrict(body, &v) })
		if (err == nil) != c.want {
			t.Errorf("%s %d deep: %v", c.open, c.depth, err)
		}
		if wellFormed(body) != c.want {
			t.Errorf("%s %d deep: wellFormed %v", c.open, c.depth, !c.want)
		}
		var w any
		if (json.Unmarshal(body, &w) == nil) != c.want {
			t.Errorf("%s %d deep: encoding/json differs", c.open, c.depth)
		}
	}
}

func TestTheStrictReadingCostsARecursiveTypesBodyItsLength(t *testing.T) {
	// Before, every level parsed its whole subtree again: a 54 KB body of
	// DiffNode 9000 deep took seconds.
	node := strings.Repeat(`{"n":`, 9000) + "null" + strings.Repeat(`}`, 9000)
	if err := returnsWithin(t, 2*time.Second, "DiffNode 9000 deep", func() error { return DecodeStrict([]byte(node), new(DiffNode)) }); err != nil {
		t.Error(err)
	}
	tree := strings.Repeat(`{"c":[`, 4000) + `{"c":[]}` + strings.Repeat(`]}`, 4000)
	if err := returnsWithin(t, 2*time.Second, "DiffTree 4000 deep", func() error { return DecodeStrict([]byte(tree), new(DiffTree)) }); err != nil {
		t.Error(err)
	}
	wide := `{"c":[` + strings.Repeat(`{"c":[{"c":[]}]},`, 20000) + `{"c":[]}]}`
	if err := returnsWithin(t, 2*time.Second, "DiffTree 20000 wide", func() error { return DecodeStrict([]byte(wide), new(DiffTree)) }); err != nil {
		t.Error(err)
	}
}

func TestTheStrictReadingNeverRecursesForeverOnATypeThatEmbedsItself(t *testing.T) {
	// Before, collecting DiffLoop's members embedded it again without end,
	// and the stack overflowed (a fatal error, which no recover catches).
	done := make(chan error, 1)
	go func() { done <- DecodeStrict([]byte(`{"x":1}`), &DiffLoop{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DecodeStrict did not return")
	}
	// A pointer type that points to itself holds only null.
	type selfPointer *selfPointer
	var p selfPointer
	if err := DecodeStrict([]byte(`1`), &p); !errors.Is(err, ErrInvalid) {
		t.Errorf("a self pointer took 1: %v", err)
	}
}

func TestTheStrictReadingWorksOutALatticeOfEmbeddedPointersAtOnce(t *testing.T) {
	// 2^22 embedding paths reach the lattice's bottom; encoding/json, and
	// now the strict reading, explore each type once.
	start := time.Now()
	shape := computeShape(reflect.TypeFor[DiffLattice]())
	for _, loop := range []reflect.Type{reflect.TypeFor[DiffLoop](), reflect.TypeFor[DiffMA](), reflect.TypeFor[DiffR1]()} {
		computeShape(loop)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v", took)
	}
	// Every type below the first level is embedded twice at its depth, so
	// its members cancel, the bottom's included: only the root's own stays.
	names := slices.Sorted(func(yield func(string) bool) {
		for name := range shape.fields {
			if !yield(name) {
				return
			}
		}
	})
	if !slices.Equal(names, []string{"top"}) {
		t.Errorf("members %v", names)
	}
	if err := DecodeStrict([]byte(`{"top":1}`), &DiffLattice{}); err != nil {
		t.Error(err)
	}
}

type DiffLatA0 struct {
	*DiffLatA1
	*DiffLatB1
}

type DiffLatB0 struct {
	*DiffLatA1
	*DiffLatB1
}

type DiffLatA1 struct {
	*DiffLatA2
	*DiffLatB2
}

type DiffLatB1 struct {
	*DiffLatA2
	*DiffLatB2
}

type DiffLatA2 struct {
	*DiffLatA3
	*DiffLatB3
}

type DiffLatB2 struct {
	*DiffLatA3
	*DiffLatB3
}

type DiffLatA3 struct {
	*DiffLatA4
	*DiffLatB4
}

type DiffLatB3 struct {
	*DiffLatA4
	*DiffLatB4
}

type DiffLatA4 struct {
	*DiffLatA5
	*DiffLatB5
}

type DiffLatB4 struct {
	*DiffLatA5
	*DiffLatB5
}

type DiffLatA5 struct {
	*DiffLatA6
	*DiffLatB6
}

type DiffLatB5 struct {
	*DiffLatA6
	*DiffLatB6
}

type DiffLatA6 struct {
	*DiffLatA7
	*DiffLatB7
}

type DiffLatB6 struct {
	*DiffLatA7
	*DiffLatB7
}

type DiffLatA7 struct {
	*DiffLatA8
	*DiffLatB8
}

type DiffLatB7 struct {
	*DiffLatA8
	*DiffLatB8
}

type DiffLatA8 struct {
	*DiffLatA9
	*DiffLatB9
}

type DiffLatB8 struct {
	*DiffLatA9
	*DiffLatB9
}

type DiffLatA9 struct {
	*DiffLatA10
	*DiffLatB10
}

type DiffLatB9 struct {
	*DiffLatA10
	*DiffLatB10
}

type DiffLatA10 struct {
	*DiffLatA11
	*DiffLatB11
}

type DiffLatB10 struct {
	*DiffLatA11
	*DiffLatB11
}

type DiffLatA11 struct {
	*DiffLatA12
	*DiffLatB12
}

type DiffLatB11 struct {
	*DiffLatA12
	*DiffLatB12
}

type DiffLatA12 struct {
	*DiffLatA13
	*DiffLatB13
}

type DiffLatB12 struct {
	*DiffLatA13
	*DiffLatB13
}

type DiffLatA13 struct {
	*DiffLatA14
	*DiffLatB14
}

type DiffLatB13 struct {
	*DiffLatA14
	*DiffLatB14
}

type DiffLatA14 struct {
	*DiffLatA15
	*DiffLatB15
}

type DiffLatB14 struct {
	*DiffLatA15
	*DiffLatB15
}

type DiffLatA15 struct {
	*DiffLatA16
	*DiffLatB16
}

type DiffLatB15 struct {
	*DiffLatA16
	*DiffLatB16
}

type DiffLatA16 struct {
	*DiffLatA17
	*DiffLatB17
}

type DiffLatB16 struct {
	*DiffLatA17
	*DiffLatB17
}

type DiffLatA17 struct {
	*DiffLatA18
	*DiffLatB18
}

type DiffLatB17 struct {
	*DiffLatA18
	*DiffLatB18
}

type DiffLatA18 struct {
	*DiffLatA19
	*DiffLatB19
}

type DiffLatB18 struct {
	*DiffLatA19
	*DiffLatB19
}

type DiffLatA19 struct {
	*DiffLatA20
	*DiffLatB20
}

type DiffLatB19 struct {
	*DiffLatA20
	*DiffLatB20
}

type DiffLatA20 struct {
	*DiffLatA21
	*DiffLatB21
}

type DiffLatB20 struct {
	*DiffLatA21
	*DiffLatB21
}

type DiffLatA21 struct {
	A21 int `json:"a21"`
}

type DiffLatB21 struct {
	B21 int `json:"b21"`
}
