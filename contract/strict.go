package contract

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"
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

// maxDepth is how many objects and lists one value may nest, encoding/json's
// own bound (its maxNestingDepth, on Go 1.26 and on Go 1.27): a deeper value
// is not well formed on either toolchain, so Go 1.26, whose Decoder.Token
// counts no depth, never walks it.
const maxDepth = 10000

// wellFormed reports whether raw is one JSON value of valid UTF-8, with no
// escape of half a surrogate pair, no member twice in any object, and at
// most maxDepth objects and lists deep.
func wellFormed(raw []byte) bool {
	formed, _ := readStrict(raw, nil)
	return formed
}

// exactShape reports whether raw, a well-formed value (wellFormed), is of
// t's exact shape (strictReader).
func exactShape(raw json.RawMessage, t reflect.Type) bool {
	formed, shaped := readStrict(raw, t)
	return formed && shaped
}

// readStrict reads raw once, from first byte to last: formed is wellFormed's
// answer, and shaped, when t is not nil, whether every value is of t's
// exact shape (strictReader). Each byte is parsed once, whatever t, so a
// body costs its length, a recursive type's included.
func readStrict(raw []byte, t reflect.Type) (formed, shaped bool) {
	if !utf8.Valid(raw) || loneSurrogate(raw) {
		return false, false
	}
	r := strictReader{dec: json.NewDecoder(bytes.NewReader(raw))}
	r.dec.UseNumber()
	if !r.value(t, 0) {
		return false, false
	}
	if _, err := r.dec.Token(); err != io.EOF {
		return false, false
	}
	return true, !r.misfit
}

// strictReader walks one JSON value's tokens, refusing an object that names
// a member twice and a value nested deeper than maxDepth, and holds each
// value to the type it is read into: every object a struct type reaches
// names its members exactly as the struct names them (shapeOf), none it
// does not have, and every one present but those it marks omitempty or
// omitzero, an embedded pointer's members present whole or not at all, as
// a nil one writes none (EmailAccountsSettings' MailboxLinking); a list's
// elements, a map's values and an array's elements are held to their type
// the same way, and an array holds exactly its length, as encoding/json
// writes it (it reads a shorter one with zeros and drops what a longer one
// has past its length). null is allowed only where the type holds a
// pointer, an interface, a raw value or a type that reads itself: encoding/
// json reads null into a bool, a number, a string, a list, a map or an
// object as its zero value, so a member that may not be null would pass as
// false, 0 or empty. A value whose type decodes itself (json.Unmarshaler),
// is kept raw or is an interface is its own; a value of another kind than
// its type's (an object for a number, a string for a []byte or a struct
// that reads text) is left to the decoder, which reads or refuses it.
type strictReader struct {
	dec *json.Decoder
	// misfit is set once a value is not of its type's shape; the walk goes
	// on, holding nothing more to a type, to tell a malformed text apart.
	misfit bool
}

// value reads one value, nested depth objects and lists deep, into t (nil
// for none), and reports whether it is well formed.
func (r *strictReader) value(t reflect.Type, depth int) bool {
	tok, err := r.dec.Token()
	if err != nil {
		return false
	}
	if t != nil && !r.misfit {
		t = r.hold(t, tok)
	}
	if r.misfit {
		t = nil
	}
	switch tok {
	case json.Delim('{'):
		return depth < maxDepth && r.object(t, depth+1)
	case json.Delim('['):
		return depth < maxDepth && r.list(t, depth+1)
	}
	return true
}

// hold judges the value whose first token is tok against t, and gives the
// type its members or elements are held to: a struct, a map, a slice or an
// array, or nil when nothing inside it is.
func (r *strictReader) hold(t reflect.Type, tok json.Token) reflect.Type {
	null := tok == nil
	var passed []reflect.Type
	for t.Kind() == reflect.Pointer {
		if null {
			return nil
		}
		if slices.Contains(passed, t) {
			// A ring of pointer types (type P *P, or type P *Q; type Q *P)
			// holds nothing but null.
			r.misfit = true
			return nil
		}
		passed = append(passed, t)
		t = t.Elem()
	}
	if t.Kind() == reflect.Interface || reflect.PointerTo(t).Implements(unmarshalerType) || t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	if null {
		r.misfit = true
		return nil
	}
	switch tok {
	case json.Delim('{'):
		if t.Kind() == reflect.Struct || t.Kind() == reflect.Map {
			return t
		}
	case json.Delim('['):
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			return t
		}
	}
	return nil
}

// object reads an object's members and its closing brace into t, a struct,
// a map or nil.
func (r *strictReader) object(t reflect.Type, depth int) bool {
	var s *shape
	var present []bool
	var elem reflect.Type
	switch {
	case t == nil:
	case t.Kind() == reflect.Map:
		elem = t.Elem()
	case shapeOf(t).unsure:
		r.misfit = true
	default:
		s = shapeOf(t)
		present = make([]bool, len(s.parents))
	}
	seen := map[string]bool{}
	for r.dec.More() {
		tok, err := r.dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		vt := elem
		if s != nil {
			f, ok := s.fields[name]
			if !ok {
				r.misfit = true
			}
			vt = f.t
			// A member present makes its group present, and every group
			// that encloses it: encoding/json writes an inner embedded
			// pointer's members only through its outer one.
			for g := f.group; g != 0 && !present[g]; g = s.parents[g] {
				present[g] = true
			}
		}
		if !r.value(vt, depth) {
			return false
		}
	}
	if _, err := r.dec.Token(); err != nil {
		return false
	}
	if s != nil {
		for name, f := range s.fields {
			// A member of an embedded pointer's group is required only
			// once the group is present.
			if !seen[name] && !f.optional && (f.group == 0 || present[f.group]) {
				r.misfit = true
			}
		}
	}
	return true
}

// list reads a list's elements and its closing bracket into t, a slice, an
// array or nil.
func (r *strictReader) list(t reflect.Type, depth int) bool {
	var elem reflect.Type
	if t != nil {
		elem = t.Elem()
	}
	n := 0
	for r.dec.More() {
		if !r.value(elem, depth) {
			return false
		}
		n++
	}
	if _, err := r.dec.Token(); err != nil {
		return false
	}
	if t != nil && t.Kind() == reflect.Array && n != t.Len() {
		r.misfit = true
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

// DecodeStrict decodes raw, one JSON value an app sends the platform, into
// v, a pointer, as the platform reads it (SPEC section 11.19): valid UTF-8
// with no escape of half a UTF-16 surrogate pair; no member twice in any
// object; at most 10000 objects and lists deep, as encoding/json reads;
// every member named exactly as v's type names it, none it does not have,
// and every one present but those it marks omitempty or omitzero; an array
// of exactly its length; and null only where the type holds a pointer, an
// interface, a raw value or a type that reads itself (strictReader). So it
// reads back every body json.Marshal writes of v's type but where a nil
// slice or map writes null, which it refuses as it refuses null for a list
// or an object. A raw value (a settings document's data) is the caller's
// to read, as Validate reads data. The body is parsed once for its shape,
// then once by the decoder. Any failure is ErrInvalid.
func DecodeStrict(raw []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer {
		return invalid("the destination is a pointer")
	}
	return decodeExact(raw, v, "body")
}

// decodeExact decodes raw into dst, a pointer, as the platform reads what an
// app sends (readStrict), with no member dst does not have; raw is never
// null, which would leave dst as it was.
func decodeExact(raw []byte, dst any, what string) error {
	formed, shaped := readStrict(raw, reflect.TypeOf(dst).Elem())
	if !formed {
		return invalid("%s: not one well-formed JSON value, or a member twice", what)
	}
	if !shaped {
		return invalid("%s: a member missing, unknown, not named exactly, or null where it may not be", what)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid("%s", what)
	}
	return nil
}

// shapeField is one member strictReader expects of an object: its type,
// whether it may be absent, and its group: 0 for a member reached through
// no embedded pointer, else the innermost embedded pointer it is reached
// through.
type shapeField struct {
	t        reflect.Type
	optional bool
	group    int
}

// shape is the members strictReader expects of a struct's object, by name,
// and its groups' parents: parents[g] is the group enclosing group g, 0
// for none (parents[0] is 0). unsure is a struct a field's json tag makes
// read apart by the toolchains the kit supports (plainTag), whose every
// object strictReader refuses.
type shape struct {
	fields  map[string]shapeField
	parents []int
	unsure  bool
}

// shapes caches shapeOf by struct type, so a type's members are worked out
// once, however many objects of it are read.
var shapes sync.Map // reflect.Type -> *shape

// shapeOf gives the members encoding/json writes and reads for the struct
// type t, chosen as its typeFields (Go 1.26) and its v2's makeStructFields
// (Go 1.27, which v1 calls) choose them:
//   - breadth first, one depth at a time, each struct type explored at
//     most once, at the shallowest depth it is embedded, through the first
//     embedding there; one a depth embeds twice gives its own members
//     twice, so that they cancel;
//   - an unexported field is left out, unless it embeds a struct or a
//     pointer to one, whose exported members still count; an embedded
//     field of another kind is a member named by its type, like an
//     exported field with no json name;
//   - a field tagged "-" is left out; a member is named by its tag's name,
//     else by its Go name; an embedded struct with no tag name is
//     embedded, one with a tag name is a member (an unexported one given a
//     name makes the struct unsure, as plainTag's tags do);
//   - of the members of one name, the shallowest wins, and at the same
//     depth the one named by its tag; two left level, both tagged or both
//     not, leave the name out altogether.
//
// Each embedding through a pointer opens a group: a nil pointer writes
// none of its members, its inner groups' included.
func shapeOf(t reflect.Type) *shape {
	if s, ok := shapes.Load(t); ok {
		return s.(*shape)
	}
	s, _ := shapes.LoadOrStore(t, computeShape(t))
	return s.(*shape)
}

// shapeMember is a member computeShape found, before dominance.
type shapeMember struct {
	name   string
	tagged bool
	index  []int
	field  shapeField
}

func computeShape(root reflect.Type) *shape {
	type embedded struct {
		t     reflect.Type
		index []int
		group int
	}
	s := &shape{fields: map[string]shapeField{}, parents: []int{0}}
	var found []shapeMember
	current, next := []embedded{}, []embedded{{t: root}}
	var count, nextCount map[reflect.Type]int
	visited := map[reflect.Type]bool{}
	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}
		for _, e := range current {
			if visited[e.t] {
				continue
			}
			visited[e.t] = true
			for i := 0; i < e.t.NumField(); i++ {
				sf := e.t.Field(i)
				inner := sf.Type
				if inner.Kind() == reflect.Pointer && inner.Name() == "" {
					inner = inner.Elem()
				}
				if sf.Anonymous {
					if !sf.IsExported() && inner.Kind() != reflect.Struct {
						continue
					}
				} else if !sf.IsExported() {
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, optional, ok := plainTag(tag)
				if !ok || name != "" && sf.Anonymous && !sf.IsExported() {
					// An unexported embedded struct given a name is a
					// member Go 1.27 leaves out when its type has a
					// method of encoding/json's, and Go 1.26 never does.
					s.unsure = true
					continue
				}
				index := append(append(make([]int, 0, len(e.index)+1), e.index...), i)
				if name != "" || !sf.Anonymous || inner.Kind() != reflect.Struct {
					m := shapeMember{name: name, tagged: name != "", index: index, field: shapeField{sf.Type, optional, e.group}}
					if name == "" {
						m.name = sf.Name
					}
					found = append(found, m)
					if count[e.t] > 1 {
						// Embedded twice at this depth: a second copy, so
						// that the name cancels below.
						found = append(found, m)
					}
					continue
				}
				nextCount[inner]++
				if nextCount[inner] == 1 {
					g := e.group
					if sf.Type.Kind() == reflect.Pointer {
						s.parents = append(s.parents, e.group)
						g = len(s.parents) - 1
					}
					next = append(next, embedded{inner, index, g})
				}
			}
		}
	}
	slices.SortFunc(found, func(a, b shapeMember) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		if c := cmp.Compare(len(a.index), len(b.index)); c != 0 {
			return c
		}
		if a.tagged != b.tagged {
			if a.tagged {
				return -1
			}
			return +1
		}
		return slices.Compare(a.index, b.index)
	})
	for i := 0; i < len(found); {
		n := 1
		for i+n < len(found) && found[i+n].name == found[i].name {
			n++
		}
		if n == 1 || len(found[i].index) != len(found[i+1].index) || found[i].tagged != found[i+1].tagged {
			s.fields[found[i].name] = found[i].field
		}
		i += n
	}
	return s
}

// plainTag reads a field's json tag, other than "-", as both toolchains
// read it: its name ("" for none) and whether it holds omitempty or
// omitzero. ok is false for a tag they may read apart, or that names more
// than a member's name and these: a name encoding/json v1 holds invalid
// (Go 1.26 then names the member by its Go name, where Go 1.27's v2 may
// take the name, or part of it), and an option other than omitempty,
// omitzero and string, or an empty one (v2 reads embed, format and case,
// and parses an option v1 never sees, as in "omitempty " or "a\b").
func plainTag(tag string) (name string, optional, ok bool) {
	name, opts, _ := strings.Cut(tag, ",")
	if name != "" && !validTagName(name) {
		return "", false, false
	}
	if opts == "" {
		return name, false, true
	}
	for _, opt := range strings.Split(opts, ",") {
		switch opt {
		case "omitempty", "omitzero":
			optional = true
		case "string", "":
			// "string" quotes a member's value, which the decoder reads;
			// an empty option is the trailing comma of a name such as
			// "-,", which both toolchains read as nothing.
		default:
			return "", false, false
		}
	}
	return name, optional, true
}

// validTagName is encoding/json v1's isValidTag: letters, digits and the
// punctuation it allows, none of which v2 reserves (a comma, a backslash,
// a quote, a backtick), so v2 reads the same name.
func validTagName(s string) bool {
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}
