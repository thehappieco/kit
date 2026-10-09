package mailie_test

// Mailie's own vectors of its key scheme (SPEC Appendix D), frozen byte for
// byte from github.com/thehappieco/mailie c9c79cf under
// vectors/mailie/key-scheme-v1 (vectors/PROVENANCE.md). Two tests:
//
//   - TestMailieKeySchemeVectors runs every case of the four files through
//     this package: what it computes, opens or refuses, every refusal with its
//     exact code and reason, on any toolchain;
//   - TestTheKitWritesMailiesKeySchemeVectorsAgain re-derives the four files
//     from this package with Mailie's generator (its
//     internal/keyscheme/vectors_test.go at c9c79cf, ported to the kit's
//     names below) and compares them with the frozen ones byte for byte: the
//     two that draw nothing random on any toolchain, and the two whose seals
//     ran under a seed, account-go.json and grant-go.json, only on the
//     toolchains ksReplayToolchains lists.
//
// Two of the scheme's values are Mailie's server's, not the kit's: how it
// normalises an address and the salt it hands out (Mailie's spec, sections 2
// and 5.3). Their cases run against the formulas of Mailie's spec, written
// here as test code (normaliseAddress, decoySalt), so the frozen bytes are
// checked while the kit exports neither.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/mailie"
	"github.com/thehappieco/kit/profiles/platform"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
	"github.com/thehappieco/kit/vectors"
)

// ksDir is where the kit carries Mailie's files.
const ksDir = "mailie/key-scheme-v1/"

// The files, with the module each names, its counts of cases and of
// must-fail cases (Mailie's spec, section 14), and whether any of its seals
// ran under a seed (testing/cryptotest.SetGlobalRandom).
var ksFiles = []struct {
	name, module    string
	cases, mustFail int
	seeded          bool
}{
	{"account-go.json", "account", 104, 60, true},
	{"grant-go.json", "seal", 107, 69, true},
	{"platform-wrap-go.json", "platformwrap", 31, 18, false},
	{"browser-vault-go.json", "browser_account", 6, 3, false},
}

// ksReplayToolchains are the toolchains on which the kit replays the seeded
// seals of Mailie's files byte for byte: the one that wrote them, go1.27.2,
// and those the kit checked the replay on (vectors/PROVENANCE.md), CI's
// go1.26.7 and go1.26.9 among them. How the standard library consumes
// randomness may change between Go versions (testing/cryptotest), so on any
// other toolchain the replay skips and says so, as Wappie's seeded replays
// do, and Mailie's own generator: TestMailieKeySchemeVectors still opens
// every seeded seal there. A toolchain joins the list only once the replay
// has passed on it.
var ksReplayToolchains = []string{"go1.26.7", "go1.26.9", "go1.27.1", "go1.27.2"}

// The header every file records: Mailie's generator, on Mailie's toolchain.
// The kit's re-derivation writes it as recorded.
const (
	ksFormat    = "thehappieco-kit-vectors/1"
	ksSource    = "github.com/thehappieco/mailie internal/keyscheme"
	ksToolchain = "go1.27.2"
	ksGenerator = "internal/keyscheme/vectors_test.go (go test ./internal/keyscheme -run TestTheVectorsAreWhatTheProfileWrites -update)"
)

type ksFile struct {
	Format      string           `json:"format"`
	Module      string           `json:"module"`
	Profile     string           `json:"profile"`
	GeneratedBy ksGeneratedBy    `json:"generated_by"`
	Note        string           `json:"note"`
	Keys        map[string]ksKey `json:"keys,omitempty"`
	Cases       []ksCase         `json:"cases"`
}

type ksGeneratedBy struct {
	Lang       string `json:"lang"`
	Source     string `json:"source"`
	Toolchain  string `json:"toolchain"`
	Randomness string `json:"randomness"`
	Generator  string `json:"generator"`
}

type ksKey struct {
	PrivateKey string `json:"private_key_b64"`
	PublicKey  string `json:"public_key_b64"`
}

type ksCase struct {
	ID     string         `json:"id"`
	Op     string         `json:"op"`
	Langs  []string       `json:"langs,omitempty"`
	In     map[string]any `json:"in"`
	Out    map[string]any `json:"out,omitempty"`
	Error  string         `json:"error,omitempty"`
	Reason string         `json:"reason,omitempty"`
}

func (c ksCase) forGo() bool { return len(c.Langs) == 0 || slices.Contains(c.Langs, "go") }

// ksDecode reads a file strictly: an unknown member of the file, of its
// header or of a key fails, as does a repeated id or a case with both or
// neither of out and error. A case's members are checked by the dispatcher,
// which fails on one it does not read.
func ksDecode(t testing.TB, name string, data []byte) *ksFile {
	t.Helper()
	var f ksFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if f.Format != ksFormat || f.Profile != "mailie" || f.GeneratedBy.Lang != "go" {
		t.Fatalf("%s: format %q, profile %q, lang %q", name, f.Format, f.Profile, f.GeneratedBy.Lang)
	}
	seen := map[string]bool{}
	for _, c := range f.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("%s: an empty or repeated case %q", name, c.ID)
		}
		seen[c.ID] = true
		if (c.Out == nil) == (c.Error == "") {
			t.Fatalf("%s: case %s has both or neither of out and error", name, c.ID)
		}
	}
	return &f
}

func ksLoad(t testing.TB, name string) ([]byte, *ksFile) {
	t.Helper()
	data, err := fs.ReadFile(vectors.FS, ksDir+name)
	if err != nil {
		t.Fatal(err)
	}
	return data, ksDecode(t, name, data)
}

// TestMailieKeySchemeVectors runs every case of Mailie's four files, all of
// which Go runs: the account scheme (profile, derivations at the floor,
// recovery codes, wraps and what must not open), the seal domain and grants
// (kinds, rows, infos, AADs, Go's seeded grants opened, refusals), the
// platform wrap under Mailie's binding, and the browser vault's AAD.
func TestMailieKeySchemeVectors(t *testing.T) {
	total, failing := 0, 0
	for _, want := range ksFiles {
		_, f := ksLoad(t, want.name)
		if f.Module != want.module || f.GeneratedBy.Source != ksSource || f.GeneratedBy.Toolchain != ksToolchain || f.GeneratedBy.Generator != ksGenerator {
			t.Errorf("%s: module %q, generated by %+v", want.name, f.Module, f.GeneratedBy)
		}
		ran, bad := 0, 0
		for _, c := range f.Cases {
			if !c.forGo() {
				continue
			}
			ran++
			if c.Error != "" {
				bad++
			}
			t.Run(want.name+"#"+c.ID, func(t *testing.T) { ksRun(t, want.name, f, c) })
		}
		if ran != want.cases || len(f.Cases) != want.cases || bad != want.mustFail {
			t.Errorf("%s: ran %d of %d cases, %d must fail; want %d and %d", want.name, ran, len(f.Cases), bad, want.cases, want.mustFail)
		}
		total += ran
		failing += bad
	}
	if total != 248 || failing != 150 {
		t.Errorf("%d cases, %d must fail; want 248 and 150", total, failing)
	}
}

// TestTheKitWritesMailiesKeySchemeVectorsAgain builds the four files again
// from this package and compares them with the frozen ones byte for byte.
// Every random draw of the files is either recorded (a nonce) or ran under
// testing/cryptotest.SetGlobalRandom with the seed its case records (an
// account wrap's nonce, a grant's ephemeral key), so the files are a pure
// function of the kit's code and of cryptotest's stream on a given
// toolchain. The two files without a seed are compared on every toolchain;
// the two with one only on ksReplayToolchains, and on any other their
// subtests skip with "replay needs".
func TestTheKitWritesMailiesKeySchemeVectorsAgain(t *testing.T) {
	built := ksBuildAll(t)
	for _, want := range ksFiles {
		t.Run(want.name, func(t *testing.T) {
			if want.seeded && !slices.Contains(ksReplayToolchains, runtime.Version()) {
				t.Skipf("replay needs one of %s (this is %s): TestMailieKeySchemeVectors opens its seeded seals rather than replaying them", strings.Join(ksReplayToolchains, ", "), runtime.Version())
			}
			frozen, err := fs.ReadFile(vectors.FS, ksDir+want.name)
			if err != nil {
				t.Fatal(err)
			}
			if got := ksEncode(t, built[want.name]); !bytes.Equal(got, frozen) {
				t.Errorf("%s: the kit writes other bytes than Mailie's file at c9c79cf (%d bytes, want %d)", want.name, len(got), len(frozen))
			}
		})
	}
	if len(built) != len(ksFiles) {
		t.Errorf("the generator builds %d files, want %d", len(built), len(ksFiles))
	}
}

// ---------------------------------------------------------------------------
// Mailie's server's values, as test code
// ---------------------------------------------------------------------------

// saltLabel keys the salt Mailie's server hands out: its server's label, not
// the kit's.
const saltLabel = "mailie/v1/kdf-salt"

// normaliseAddress is an address as Mailie's server stores it (Mailie's
// spec, section 2): Go's strings.TrimSpace, then strings.ToLower.
func normaliseAddress(address string) string { return strings.ToLower(strings.TrimSpace(address)) }

// decoySalt is the salt Mailie's server hands out for an address (Mailie's
// spec, section 5.3): the first 16 bytes of
// HMAC-SHA256(key, "mailie/v1/kdf-salt|" || normaliseAddress(address)).
func decoySalt(key []byte, address string) ([]byte, error) {
	if len(key) != mailie.KeyLen {
		return nil, fmt.Errorf("the salt key is %d bytes, not %d", len(key), mailie.KeyLen)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(saltLabel + "|" + normaliseAddress(address)))
	return mac.Sum(nil)[:mailie.SaltLen], nil
}

// ---------------------------------------------------------------------------
// The generator: Mailie's internal/keyscheme/vectors_test.go at c9c79cf,
// over this package. Every input is SHA-256 of a fixed label.
// ---------------------------------------------------------------------------

var std = base64.StdEncoding.EncodeToString

// digest is SHA-256 of a fixed label: every key, salt and nonce below.
func digest(label string) []byte {
	sum := sha256.Sum256([]byte("mailie key scheme vectors/" + label))
	return sum[:]
}

// uuid4 is a UUIDv4 made from a label's digest, as a browser or a server
// would draw one.
func uuid4(label string) string {
	b := digest(label)[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return uuid.UUID(b).String()
}

func public(t testing.TB, key []byte) []byte {
	t.Helper()
	pub, err := mailie.PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

func set(b []byte, i int, v byte) []byte {
	c := bytes.Clone(b)
	c[i] = v
	return c
}

func with(m map[string]any, kv ...any) map[string]any {
	c := make(map[string]any, len(m)+len(kv)/2)
	for k, v := range m {
		c[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		c[kv[i].(string)] = kv[i+1]
	}
	return c
}

func without(m map[string]any, keys ...string) map[string]any {
	c := with(m)
	for _, k := range keys {
		delete(c, k)
	}
	return c
}

// lowOrder are X25519 u-coordinates of low order, the kit's own list
// (internal/forge): every clamped scalar sends them to zero.
var lowOrder = []struct{ name, hex string }{
	{"zero", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"one", "0100000000000000000000000000000000000000000000000000000000000000"},
	{"order-8-a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	{"order-8-b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
	{"p-minus-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"zero-bit-255", "0000000000000000000000000000000000000000000000000000000000000080"},
}

// cp is one code point as a string: the generator spells every character
// outside ASCII by its number.
func cp(r rune) string { return string(r) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// The people and mailboxes of the vectors.
var (
	aliceSeal = uuid4("alice/seal id")
	bobSeal   = uuid4("bob/seal id")
	aliceKey  = digest("alice/account key")
	bobKey    = digest("bob/account key")
	namespace = uuid4("mailbox/namespace")
	otherNS   = uuid4("other mailbox/namespace")
	mailbox1  = digest("mailbox/key/epoch 1")
	mailbox2  = digest("mailbox/key/epoch 2")
	sub       = "019a8b2c-3d4e-7f60-8a71-b2c3d4e5f607" // id.'s sub, a UUIDv7
	// subV4 is a sub of version 4, which the platform does not refuse (it
	// does not check a sub's version nibble).
	subV4 = uuid4("alice/a version 4 sub")
	// Spellings no seal id or namespace has.
	upperID = strings.ToUpper(uuid4("alice/seal id"))
	v7ID    = "019a8b2c-3d4e-7f60-8a71-b2c3d4e5f608"
	nilID   = "00000000-0000-0000-0000-000000000000"
)

const (
	password = "correct horse battery staple"
	// passwordNFC and passwordNFD are one password, typed two ways: NFC with
	// spaces, and NFD with no-break spaces, which the preparation turns into
	// NFC with spaces.
	passwordNFC = "P\u00e3o de a\u00e7\u00facar \u00e0 noite"
	passwordNFD = "Pa\u0303o\u00a0de\u00a0ac\u0327u\u0301car\u00a0a\u0300\u00a0noite"
	// recoveryCode is the code of bytes 0 to 29, written as it is shown.
	recoveryCode = "01234-56789-ABCDE-FGHJK-MNPQR-STVWX"
	// recoveryTyped is the same code as somebody types it back.
	recoveryTyped = "o1234 56789 abcde fghjk mnpqr stvwx"
)

// inOrder ranges over a map in the order of its keys, so the files are the
// same every time they are built.
func inOrder[V any](m map[string]V) iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if !yield(k, m[k]) {
				return
			}
		}
	}
}

// accepted is the output of a check the value passes.
var accepted = map[string]any{"accepted": true}

func kdf(m, t, p int) map[string]any {
	return map[string]any{"alg": "argon2id", "m": m, "t": t, "p": p}
}

var defaultKDF = kdf(65536, 3, 1)

type builder struct {
	t     *testing.T
	cases []ksCase
	seed  uint64
}

func (b *builder) ok(id, op string, in, out map[string]any, langs ...string) {
	b.cases = append(b.cases, ksCase{ID: id, Op: op, In: in, Out: out, Langs: langs})
}

func (b *builder) refuse(id, op string, in map[string]any, code string, reason ...string) {
	c := ksCase{ID: id, Op: op, In: in, Error: code}
	if len(reason) > 0 {
		c.Reason = reason[0]
	}
	b.cases = append(b.cases, c)
}

func (b *builder) refuseIn(langs []string, id, op string, in map[string]any, code string, reason ...string) {
	b.refuse(id, op, in, code, reason...)
	b.cases[len(b.cases)-1].Langs = langs
}

// seeded runs f under a fresh deterministic random stream and returns the
// seed it used, for the case to record.
func (b *builder) seeded(f func()) uint64 {
	b.seed++
	cryptotest.SetGlobalRandom(b.t, b.seed)
	f()
	return b.seed
}

func (b *builder) file(module, note, randomness string, keys map[string]ksKey) *ksFile {
	return &ksFile{
		Format:  ksFormat,
		Module:  module,
		Profile: "mailie",
		GeneratedBy: ksGeneratedBy{
			Lang: "go", Source: ksSource, Toolchain: ksToolchain, Randomness: randomness, Generator: ksGenerator,
		},
		Note: note, Keys: keys, Cases: b.cases,
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func must2(t *testing.T) func(a, b []byte, err error) ([]byte, []byte) {
	return func(a, b []byte, err error) ([]byte, []byte) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a, b
	}
}

func buildAccount(t *testing.T) *ksFile {
	b := &builder{t: t, seed: 1000}
	p := mailie.Account()
	b.ok("mailie/account/profile", "mailie.account_profile", map[string]any{}, accountProfile())

	// An address as the server stores it, in both languages.
	for name, c := range inOrder(map[string][2]string{
		"already-normal":                   {"ana@example.com", "ana@example.com"},
		"ascii-capitals":                   {"Ana@Example.COM", "ana@example.com"},
		"surrounding-white-space":          {" \tana@example.com\r\n", "ana@example.com"},
		"no-break-and-ideographic-spaces":  {cp(0xa0) + "ana@example.com" + cp(0x3000), "ana@example.com"},
		"next-line-is-white-space":         {cp(0x85) + "ana@example.com" + cp(0x85), "ana@example.com"},
		"zero-width-no-break-space-is-not": {cp(0xfeff) + "ana@example.com", cp(0xfeff) + "ana@example.com"},
		"inner-white-space-is-kept":        {"ana @example.com", "ana @example.com"},
		"a-latin-capital":                  {cp(0xc4) + "nne@Example.com", cp(0xe4) + "nne@example.com"},
		"a-kelvin-sign-is-a-k":             {cp(0x212a) + "na@example.com", "kna@example.com"},
		"a-capital-i-with-a-dot-is-an-i":   {cp(0x130) + "lker@example.com", "ilker@example.com"},
		"capital-sigmas-are-each-sigma":    {cp(0x3a3) + cp(0x3a3) + "@example.com", cp(0x3c3) + cp(0x3c3) + "@example.com"},
	}) {
		b.ok("mailie/normalise-address/"+name, "mailie.normalise_address", map[string]any{"address": c[0]}, map[string]any{"address": c[1]})
	}

	// The server's salt for an address.
	saltKey := digest("server/salt key")
	salt := must[[]byte](t)(decoySalt(saltKey, "ana@example.com"))
	for name, address := range inOrder(map[string]string{"plain": "ana@example.com", "upper-case": "Ana@Example.COM", "spaces": "  ana@example.com\t"}) {
		b.ok("mailie/decoy-salt/"+name, "mailie.decoy_salt", map[string]any{"key_b64": std(saltKey), "address": address}, map[string]any{"salt_b64": std(salt)}, "go")
	}
	for _, group := range []struct {
		stored  string
		spelled map[string]string
	}{
		{cp(0xe4) + "nne@example.com", map[string]string{"non-ascii/stored": cp(0xe4) + "nne@example.com", "non-ascii/a-latin-capital": cp(0xc4) + "nne@Example.com"}},
		{"kna@example.com", map[string]string{"kelvin/the-letter-k": "kna@example.com", "kelvin/a-kelvin-sign": cp(0x212a) + "na@example.com"}},
	} {
		want := must[[]byte](t)(decoySalt(saltKey, group.stored))
		for name, address := range inOrder(group.spelled) {
			b.ok("mailie/decoy-salt/"+name, "mailie.decoy_salt", map[string]any{"key_b64": std(saltKey), "address": address}, map[string]any{"salt_b64": std(want)}, "go")
		}
	}
	b.ok("mailie/decoy-salt/another-address", "mailie.decoy_salt", map[string]any{"key_b64": std(saltKey), "address": "bo@example.com"},
		map[string]any{"salt_b64": std(must[[]byte](t)(decoySalt(saltKey, "bo@example.com")))}, "go")
	b.ok("mailie/decoy-salt/another-server", "mailie.decoy_salt", map[string]any{"key_b64": std(digest("other server/salt key")), "address": "ana@example.com"},
		map[string]any{"salt_b64": std(must[[]byte](t)(decoySalt(digest("other server/salt key"), "ana@example.com")))}, "go")

	// Derivations, at the profile's floor.
	derived := map[string]account.Derived{}
	deriveIn := func(pw string, s []byte, params map[string]any) map[string]any {
		return map[string]any{"password": pw, "salt_b64": std(s), "params": params}
	}
	for _, d := range []struct{ name, password string }{{"ascii", password}, {"nfc", passwordNFC}, {"nfd-with-no-break-spaces", passwordNFD}} {
		got := must[account.Derived](t)(account.DeriveBytes(p, d.password, salt, mailie.DefaultKDF))
		derived[d.name] = got
		b.ok("account/derive/"+d.name, "account.derive", deriveIn(d.password, salt, defaultKDF),
			map[string]any{"auth_b64": std(got.Auth), "auth_key": string(got.AuthText), "wrap_b64": std(got.Wrap)})
	}
	if !bytes.Equal(derived["nfc"].Wrap, derived["nfd-with-no-break-spaces"].Wrap) {
		t.Fatal("one password typed two ways derives two keys")
	}
	b.refuse("account/derive/refuses/control-character", "account.derive", deriveIn("correct horse\u0007battery staple", salt, defaultKDF), "password", "rejected")
	b.refuse("account/derive/refuses/257-code-points", "account.derive", deriveIn(strings.Repeat("a", 257), salt, defaultKDF), "password", "rejected")
	b.refuse("account/derive/refuses/m-32768", "account.derive", deriveIn(password, salt, kdf(32768, 3, 1)), "kdf", "out_of_bounds")
	b.refuse("account/derive/refuses/t-2", "account.derive", deriveIn(password, salt, kdf(65536, 2, 1)), "kdf", "out_of_bounds")
	b.refuse("account/derive/refuses/p-5", "account.derive", deriveIn(password, salt, kdf(65536, 3, 5)), "kdf", "out_of_bounds")
	b.refuse("account/derive/refuses/m-times-t-over-the-cap", "account.derive", deriveIn(password, salt, kdf(262144, 5, 1)), "kdf", "out_of_bounds")
	b.refuse("account/derive/refuses/argon2i", "account.derive", deriveIn(password, salt, map[string]any{"alg": "argon2i", "m": 65536, "t": 3, "p": 1}), "kdf", "unsupported_alg")
	b.refuse("account/derive/refuses/salt-15", "account.derive", deriveIn(password, salt[:15], defaultKDF), "kdf", "out_of_bounds")
	b.refuse("account/derive/refuses/salt-17", "account.derive", deriveIn(password, append(bytes.Clone(salt), 0), defaultKDF), "kdf", "out_of_bounds")

	// The recovery code.
	codeBytes := make([]byte, 30)
	for i := range codeBytes {
		codeBytes[i] = byte(i)
	}
	canonical := "0123456789ABCDEFGHJKMNPQRSTVWX"
	b.ok("mailie/recovery-code/counting", "mailie.recovery_code", map[string]any{"bytes_b64": std(codeBytes)}, map[string]any{"code": canonical, "display": recoveryCode})
	b.ok("mailie/recovery-code/all-ff", "mailie.recovery_code", map[string]any{"bytes_b64": std(bytes.Repeat([]byte{0xff}, 30))},
		map[string]any{"code": strings.Repeat("Z", 30), "display": "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ"})
	for name, typed := range inOrder(map[string]string{"display": recoveryCode, "typed-back": recoveryTyped, "i-and-l": "0IL34-56789-ABCDE-FGHJK-MNPQR-STVWX"}) {
		want := canonical
		if name == "i-and-l" {
			want = "011" + canonical[3:]
		}
		b.ok("account/normalise/"+name, "account.normalise_recovery_code", map[string]any{"code": typed}, map[string]any{"code": want})
	}
	for name, typed := range inOrder(map[string]string{
		"a-u":               "01234-56789-ABCDE-FGHJK-MNPQR-STVWU",
		"29-characters":     recoveryCode[:34],
		"31-characters":     recoveryCode + "0",
		"a-full-width-a":    "01234-56789-\uff21BCDE-FGHJK-MNPQR-STVWX",
		"a-no-break-space":  "01234\u00a056789-ABCDE-FGHJK-MNPQR-STVWX",
		"a-dotless-i":       "0\u0131234-56789-ABCDE-FGHJK-MNPQR-STVWX",
		"an-empty-string":   "",
		"a-vertical-tab":    "01234\v56789-ABCDE-FGHJK-MNPQR-STVWX",
		"a-plus-separator":  "01234+56789-ABCDE-FGHJK-MNPQR-STVWX",
		"lower-case-u-also": "01234-56789-abcde-fghjk-mnpqr-stvwu",
	}) {
		b.refuse("account/normalise/refuses/"+name, "account.normalise_recovery_code", map[string]any{"code": typed}, "recovery_code")
	}
	recoveryKey := must[[]byte](t)(account.RecoveryKey(p, recoveryCode))
	proof := must[string](t)(account.RecoveryProof(p, recoveryCode))
	for name, typed := range inOrder(map[string]string{"display": recoveryCode, "typed-back": recoveryTyped}) {
		b.ok("account/recovery-key/"+name, "account.recovery_key", map[string]any{"code": typed}, map[string]any{"key_b64": std(recoveryKey)})
		b.ok("account/recovery-proof/"+name, "account.recovery_proof", map[string]any{"code": typed}, map[string]any{"proof": proof})
	}
	b.refuse("account/recovery-key/refuses/a-u", "account.recovery_key", map[string]any{"code": "01234-56789-ABCDE-FGHJK-MNPQR-STVWU"}, "recovery_code")
	b.refuse("account/recovery-proof/refuses/29-characters", "account.recovery_proof", map[string]any{"code": recoveryCode[:34]}, "recovery_code")

	// The wrap's additional data.
	alicePub, bobPub := public(t, aliceKey), public(t, bobKey)
	aadIn := func(kind, seal string, pub []byte) map[string]any {
		return map[string]any{"kind": kind, "seal_id": seal, "account_public_key_b64": std(pub)}
	}
	for _, kind := range []mailie.WrapKind{mailie.WrapPassword, mailie.WrapRecovery} {
		aad := must[[]byte](t)(mailie.AccountWrapAAD(kind, aliceSeal, alicePub))
		b.ok("mailie/account-wrap-aad/"+string(kind), "mailie.account_wrap_aad", aadIn(string(kind), aliceSeal, alicePub), map[string]any{"aad_b64": std(aad)})
	}
	b.refuse("mailie/account-wrap-aad/refuses/kind-passkey", "mailie.account_wrap_aad", aadIn("passkey", aliceSeal, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/kind-in-upper-case", "mailie.account_wrap_aad", aadIn("PASSWORD", aliceSeal, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-in-upper-case", "mailie.account_wrap_aad", aadIn("password", upperID, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-a-uuidv7", "mailie.account_wrap_aad", aadIn("password", v7ID, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-the-nil-uuid", "mailie.account_wrap_aad", aadIn("password", nilID, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-in-braces", "mailie.account_wrap_aad", aadIn("password", "{"+aliceSeal+"}", alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-with-a-urn-prefix", "mailie.account_wrap_aad", aadIn("password", "urn:uuid:"+aliceSeal, alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/seal-id-an-address", "mailie.account_wrap_aad", aadIn("password", "ana@example.com", alicePub), "binding")
	b.refuse("mailie/account-wrap-aad/refuses/public-key-of-31-bytes", "mailie.account_wrap_aad", aadIn("password", aliceSeal, alicePub[:31]), "binding")

	// The wraps, sealed by the package under a seeded nonce.
	passwordKey := derived["ascii"].Wrap
	sealWrap := func(id string, kind mailie.WrapKind, wrapKey, key []byte, sealID string) []byte {
		var wrap []byte
		seed := b.seeded(func() { wrap = must[[]byte](t)(mailie.SealAccountWrap(kind, wrapKey, key, sealID)) })
		pub := public(t, key)
		b.ok(id, "mailie.account_wrap", map[string]any{
			"kind": string(kind), "seal_id": sealID, "wrap_key_b64": std(wrapKey), "account_key_b64": std(key),
			"nonce_b64": std(wrap[1:13]), "seed": seed,
		}, map[string]any{
			"account_public_key_b64": std(pub),
			"aad_b64":                std(must[[]byte](t)(mailie.AccountWrapAAD(kind, sealID, pub))),
			"wrap_b64":               std(wrap),
		})
		return wrap
	}
	pw := sealWrap("mailie/account-wrap/password", mailie.WrapPassword, passwordKey, aliceKey, aliceSeal)
	rw := sealWrap("mailie/account-wrap/recovery", mailie.WrapRecovery, recoveryKey, aliceKey, aliceSeal)
	zeroFirst := aliceKey
	for i := 0; zeroFirst[0] != 0; i++ {
		zeroFirst = digest(fmt.Sprintf("zero-first account key/%d", i))
	}
	sealWrap("mailie/account-wrap/account-key-with-a-zero-first-byte", mailie.WrapPassword, passwordKey, zeroFirst, bobSeal)
	sealIn := map[string]any{"kind": "password", "seal_id": aliceSeal, "wrap_key_b64": std(passwordKey), "account_key_b64": std(aliceKey)}
	b.refuse("mailie/account-wrap/refuses/account-key-of-31-bytes", "mailie.account_wrap", with(sealIn, "account_key_b64", std(aliceKey[:31])), "binding")
	b.refuse("mailie/account-wrap/refuses/seal-id-a-uuidv7", "mailie.account_wrap", with(sealIn, "seal_id", v7ID), "binding")
	b.refuse("mailie/account-wrap/refuses/kind-platform", "mailie.account_wrap", with(sealIn, "kind", "platform"), "binding")

	// Opening.
	open := map[string]any{"kind": "password", "seal_id": aliceSeal, "account_public_key_b64": std(alicePub), "wrap_b64": std(pw), "wrap_key_b64": std(passwordKey)}
	recovery := map[string]any{"kind": "recovery", "seal_id": aliceSeal, "account_public_key_b64": std(alicePub), "wrap_b64": std(rw), "recovery_code": recoveryTyped}
	aliceOut := map[string]any{"account_key_b64": std(aliceKey)}
	b.ok("mailie/account-unwrap/password/with-the-wrap-key", "mailie.account_unwrap", open, aliceOut)
	b.ok("mailie/account-unwrap/password/with-the-password", "mailie.account_unwrap",
		with(without(open, "wrap_key_b64"), "password", password, "salt_b64", std(salt), "params", defaultKDF), aliceOut)
	b.ok("mailie/account-unwrap/recovery/with-the-code-typed-back", "mailie.account_unwrap", recovery, aliceOut)
	b.ok("mailie/account-unwrap/recovery/with-the-recovery-key", "mailie.account_unwrap", with(without(recovery, "recovery_code"), "wrap_key_b64", std(recoveryKey)), aliceOut)
	foreign := func() []byte {
		// Authenticates under Alice's binding, around Bob's key.
		aad := must[[]byte](t)(mailie.AccountWrapAAD(mailie.WrapPassword, aliceSeal, alicePub))
		block, _ := aes.NewCipher(passwordKey)
		gcm, _ := cipher.NewGCM(block)
		nonce := digest("foreign/nonce")[:12]
		return gcm.Seal(append([]byte{mailie.AccountWrapHeader}, nonce...), nonce, bobKey, aad)
	}()
	for _, r := range []struct {
		name, reason string
		in           map[string]any
	}{
		{"another-seal-id", "wrong_key", with(open, "seal_id", bobSeal)},
		{"another-account-public-key", "wrong_key", with(open, "account_public_key_b64", std(bobPub))},
		{"another-wrap-key", "wrong_key", with(open, "wrap_key_b64", std(digest("another/wrap key")))},
		{"another-passwords-wrap-key", "wrong_key", with(open, "wrap_key_b64", std(derived["nfc"].Wrap))},
		{"the-password-wrap-opened-as-the-recovery-wrap", "wrong_key", with(open, "kind", "recovery")},
		{"the-recovery-wrap-opened-as-the-password-wrap", "wrong_key", with(recovery, "kind", "password")},
		{"the-recovery-wrap-in-the-password-column", "wrong_key", with(open, "wrap_b64", std(rw))},
		{"the-password-wrap-with-the-recovery-code", "wrong_key", with(without(open, "wrap_key_b64"), "recovery_code", recoveryCode)},
		{"header-0x03-the-platform-wraps", "wrong_key", with(open, "wrap_b64", std(set(pw, 0, 0x03)))},
		{"header-0x01", "wrong_key", with(open, "wrap_b64", std(set(pw, 0, 0x01)))},
		{"header-0x00", "wrong_key", with(open, "wrap_b64", std(set(pw, 0, 0x00)))},
		{"flipped-nonce", "wrong_key", with(open, "wrap_b64", std(flip(pw, 1)))},
		{"flipped-ciphertext", "wrong_key", with(open, "wrap_b64", std(flip(pw, 20)))},
		{"flipped-tag", "wrong_key", with(open, "wrap_b64", std(flip(pw, 60)))},
		{"extended-to-62-bytes", "wrong_key", with(open, "wrap_b64", std(append(bytes.Clone(pw), 0)))},
		{"truncated-to-60-bytes", "truncated", with(open, "wrap_b64", std(pw[:60]))},
		{"truncated-to-the-header", "truncated", with(open, "wrap_b64", std(pw[:1]))},
		{"empty", "truncated", with(open, "wrap_b64", "")},
		{"opens-to-another-accounts-key", "wrong_key", with(open, "wrap_b64", std(foreign))},
	} {
		b.refuse("mailie/account-unwrap/refuses/"+r.name, "mailie.account_unwrap", r.in, "wrap", r.reason)
	}
	b.refuseIn([]string{"go"}, "mailie/account-unwrap/refuses/wrap-key-of-31-bytes", "mailie.account_unwrap", with(open, "wrap_key_b64", std(passwordKey[:31])), "wrap", "bad_key")
	b.refuse("mailie/account-unwrap/refuses/seal-id-in-upper-case", "mailie.account_unwrap", with(open, "seal_id", upperID), "binding")
	b.refuse("mailie/account-unwrap/refuses/public-key-of-31-bytes", "mailie.account_unwrap", with(open, "account_public_key_b64", std(alicePub[:31])), "binding")
	b.refuse("mailie/account-unwrap/refuses/a-code-with-a-u", "mailie.account_unwrap", with(recovery, "recovery_code", "01234-56789-ABCDE-FGHJK-MNPQR-STVWU"), "recovery_code")

	// What the server checks of a wrap it is sent.
	b.ok("mailie/account-wrap-shape/password", "mailie.account_wrap_shape", map[string]any{"wrap_b64": std(pw)}, accepted)
	b.ok("mailie/account-wrap-shape/recovery", "mailie.account_wrap_shape", map[string]any{"wrap_b64": std(rw)}, accepted)
	for name, w := range inOrder(map[string][]byte{"60-bytes": pw[:60], "62-bytes": append(bytes.Clone(pw), 0), "header-0x03": set(pw, 0, 0x03), "empty": {}}) {
		b.refuse("mailie/account-wrap-shape/refuses/"+name, "mailie.account_wrap_shape", map[string]any{"wrap_b64": std(w)}, "shape")
	}

	return b.file("account", "Mailie's account scheme (docs/key-scheme.md section 5): its profile, an address as the server stores it, the server's salt, derivations at the profile's floor, "+
		"the recovery code in the platform's canonical form, the 61-byte password and recovery wraps of an account key with their additional data, "+
		"and what must not open. Errors are the kit's account codes with their reasons, the platform's recovery_code, and Mailie's binding and shape.",
		"each mailie.account_wrap ran under testing/cryptotest.SetGlobalRandom with its case's seed; nonce_b64 is the nonce it drew, which TypeScript injects to replay it", nil)
}

func accountProfile() map[string]any {
	b := platform.KDFBounds()
	return map[string]any{
		"auth_label": mailie.PasswordAuthLabel, "wrap_label": mailie.PasswordWrapLabel,
		"recovery_key_label": mailie.RecoveryWrapLabel, "recovery_proof_label": mailie.RecoveryAuthLabel,
		"wrap_header_b64": std([]byte{mailie.AccountWrapHeader}), "wrap_len": mailie.AccountWrapLen, "legacy_v1": false,
		"wrap_aad_tag": mailie.AccountWrapTag, "wrap_aad_version": mailie.AccountWrapVersion, "wrap_kinds": []any{"password", "recovery"},
		"encoding": "base64url", "password_preparation": mailie.PasswordPreparation, "recovery_normalisation": "platform-canonical",
		"kdf": map[string]any{"alg": mailie.DefaultKDF.Alg, "m": int(mailie.DefaultKDF.M), "t": int(mailie.DefaultKDF.T), "p": int(mailie.DefaultKDF.P)},
		"bounds": map[string]any{
			"min":          map[string]any{"m": int(b.Min.M), "t": int(b.Min.T), "p": int(b.Min.P)},
			"max":          map[string]any{"m": int(b.Max.M), "t": int(b.Max.T), "p": int(b.Max.P)},
			"max_cost":     int(b.MaxCost),
			"min_salt_len": b.MinSaltLen, "max_salt_len": b.MaxSaltLen,
		},
		"salt_label": saltLabel,
	}
}

func buildGrant(t *testing.T) *ksFile {
	b := &builder{t: t, seed: 2000}
	alicePub, bobPub := public(t, aliceKey), public(t, bobKey)
	m1Pub, m2Pub := public(t, mailbox1), public(t, mailbox2)
	keys := map[string]ksKey{
		"alice":     {std(aliceKey), std(alicePub)},
		"bob":       {std(bobKey), std(bobPub)},
		"mailbox-1": {std(mailbox1), std(m1Pub)},
		"mailbox-2": {std(mailbox2), std(m2Pub)},
	}
	b.ok("mailie/seal/profile", "mailie.seal_profile", map[string]any{}, sealProfile())
	// The named kinds, and 0x00, which is never named.
	for k := 0; k <= 0x0a; k++ {
		b.ok(fmt.Sprintf("seal/kind-name/%#x", k), "seal.kind_name", map[string]any{"kind": k}, map[string]any{"name": mailie.Kind(k).String()})
	}

	// What a server checks of a public key it stores and hands to others.
	alicePubHigh := bytes.Clone(alicePub)
	alicePubHigh[31] |= 0x80
	for name, pub := range inOrder(map[string][]byte{"alice": alicePub, "mailbox-1": m1Pub}) {
		b.ok("mailie/public-key-check/"+name, "mailie.public_key_check", map[string]any{"public_key_b64": std(pub)}, accepted, "go")
	}
	for name, pub := range inOrder(map[string][]byte{
		"31-bytes": alicePub[:31], "33-bytes": append(bytes.Clone(alicePub), 0), "empty": {}, "bit-255-set": alicePubHigh,
	}) {
		b.refuseIn([]string{"go"}, "mailie/public-key-check/refuses/"+name, "mailie.public_key_check", map[string]any{"public_key_b64": std(pub)}, "public_key")
	}
	for _, lo := range lowOrder {
		b.refuseIn([]string{"go"}, "mailie/public-key-check/refuses/low-order/"+lo.name, "mailie.public_key_check", map[string]any{"public_key_b64": std(unhex(lo.hex))}, "public_key")
	}

	rowIn := func(ns, seal string, epoch int) map[string]any {
		return map[string]any{"namespace": ns, "seal_id": seal, "epoch": epoch}
	}
	for _, r := range []struct {
		name string
		in   map[string]any
	}{
		{"alice/epoch-1", rowIn(namespace, aliceSeal, 1)},
		{"alice/epoch-2", rowIn(namespace, aliceSeal, 2)},
		{"bob/epoch-1", rowIn(namespace, bobSeal, 1)},
		{"alice/other-mailbox/epoch-1", rowIn(otherNS, aliceSeal, 1)},
		{"alice/epoch-65535", rowIn(namespace, aliceSeal, 65535)},
	} {
		row := must[uuid.UUID](t)(mailie.GrantRow(r.in["namespace"].(string), r.in["seal_id"].(string), r.in["epoch"].(int)))
		b.ok("mailie/grant-row/"+r.name, "mailie.grant_row", r.in, map[string]any{"row": row.String()})
		aad := must[[]byte](t)(mailie.GrantAAD(r.in["namespace"].(string), r.in["seal_id"].(string), r.in["epoch"].(int)))
		b.ok("mailie/grant-aad/"+r.name, "mailie.grant_aad", r.in, map[string]any{"aad_b64": std(aad)})
	}
	for _, r := range []struct {
		name string
		in   map[string]any
	}{
		{"epoch-0", rowIn(namespace, aliceSeal, 0)},
		{"epoch-65536", rowIn(namespace, aliceSeal, 65536)},
		{"namespace-in-upper-case", rowIn(strings.ToUpper(namespace), aliceSeal, 1)},
		{"namespace-a-uuidv7", rowIn(v7ID, aliceSeal, 1)},
		{"namespace-the-nil-uuid", rowIn(nilID, aliceSeal, 1)},
		{"seal-id-in-upper-case", rowIn(namespace, upperID, 1)},
	} {
		b.refuse("mailie/grant-row/refuses/"+r.name, "mailie.grant_row", r.in, "binding")
	}
	for _, e := range []int{1, 2, 65535} {
		info := must[[]byte](t)(mailie.GrantInfo(namespace, e))
		b.ok(fmt.Sprintf("mailie/grant-info/epoch-%d", e), "mailie.grant_info", map[string]any{"namespace": namespace, "epoch": e},
			map[string]any{"info_b64": std(info), "info": string(info)})
	}
	b.refuse("mailie/grant-info/refuses/epoch-0", "mailie.grant_info", map[string]any{"namespace": namespace, "epoch": 0}, "binding")

	// Grants, sealed by the package under a seeded ephemeral key.
	grants := map[string][]byte{}
	sealGrant := func(id, recipient string, recipientPub []byte, ns, sealID string, epoch int, key []byte) []byte {
		var g []byte
		seed := b.seeded(func() { g = must[[]byte](t)(mailie.SealGrant(recipientPub, ns, sealID, epoch, key)) })
		b.ok(id, "mailie.grant_seal", map[string]any{
			"recipient": recipient, "recipient_public_key_b64": std(recipientPub), "namespace": ns, "seal_id": sealID, "epoch": epoch,
			"mailbox_key_b64": std(key), "seed": seed,
		}, map[string]any{"grant_b64": std(g), "mailbox_public_key_b64": std(public(t, key))})
		grants[id] = g
		return g
	}
	g1 := sealGrant("mailie/grant/alice/epoch-1", "alice", alicePub, namespace, aliceSeal, 1, mailbox1)
	gBob := sealGrant("mailie/grant/bob/epoch-1", "bob", bobPub, namespace, bobSeal, 1, mailbox1)
	g2 := sealGrant("mailie/grant/alice/epoch-2", "alice", alicePub, namespace, aliceSeal, 2, mailbox2)
	sealGrant("mailie/grant/alice/epoch-65535", "alice", alicePub, namespace, aliceSeal, 65535, mailbox2)
	// A grant anyone holding Alice's public key could make: rightly bound,
	// around a key that is not the mailbox's.
	forged := sealGrant("mailie/grant/alice/epoch-1/a-key-the-sealer-chose", "alice", alicePub, namespace, aliceSeal, 1, digest("forger/key"))
	var otherKind, wappieGrant []byte
	row1 := must[uuid.UUID](t)(mailie.GrantRow(namespace, aliceSeal, 1))
	ns1 := uuid.MustParse(namespace)
	pubAlice := must[hpke.PublicKey](t)(hpke.ParsePublicKey(alicePub))
	otherKindSeed := b.seeded(func() {
		otherKind = must[[]byte](t)(seal.SealDirect(pubAlice, mailie.KindContentKey, ns1, row1, 1, mailbox1))
	})
	wappieSeed := b.seeded(func() {
		wappieGrant = must[[]byte](t)(seal.SealDirect(pubAlice, wappie.KindDeviceGrant, ns1, row1, 1, mailbox1))
	})
	sealIn := map[string]any{"recipient_public_key_b64": std(alicePub), "namespace": namespace, "seal_id": aliceSeal, "epoch": 1, "mailbox_key_b64": std(mailbox1)}
	for _, lo := range lowOrder {
		b.refuse("mailie/grant-seal/refuses/low-order-recipient/"+lo.name, "mailie.grant_seal", with(sealIn, "recipient_public_key_b64", std(unhex(lo.hex))), "invalid_key")
	}
	b.refuse("mailie/grant-seal/refuses/recipient-key-of-31-bytes", "mailie.grant_seal", with(sealIn, "recipient_public_key_b64", std(alicePub[:31])), "invalid_key")
	b.refuse("mailie/grant-seal/refuses/epoch-0", "mailie.grant_seal", with(sealIn, "epoch", 0), "binding")
	b.refuse("mailie/grant-seal/refuses/epoch-65536", "mailie.grant_seal", with(sealIn, "epoch", 65536), "binding")
	b.refuse("mailie/grant-seal/refuses/mailbox-key-of-31-bytes", "mailie.grant_seal", with(sealIn, "mailbox_key_b64", std(mailbox1[:31])), "binding")
	b.refuse("mailie/grant-seal/refuses/namespace-a-uuidv7", "mailie.grant_seal", with(sealIn, "namespace", v7ID), "binding")

	// Opening.
	openIn := func(key, ns, seal string, epoch int, mailboxPub, g []byte) map[string]any {
		return map[string]any{"key": key, "namespace": ns, "seal_id": seal, "epoch": epoch, "mailbox_public_key_b64": std(mailboxPub), "grant_b64": std(g)}
	}
	o1 := openIn("alice", namespace, aliceSeal, 1, m1Pub, g1)
	b.ok("mailie/grant-open/alice/epoch-1", "mailie.grant_open", o1, map[string]any{"mailbox_key_b64": std(mailbox1)})
	b.ok("mailie/grant-open/bob/epoch-1", "mailie.grant_open", openIn("bob", namespace, bobSeal, 1, m1Pub, gBob), map[string]any{"mailbox_key_b64": std(mailbox1)})
	b.ok("mailie/grant-open/alice/epoch-2", "mailie.grant_open", openIn("alice", namespace, aliceSeal, 2, m2Pub, g2), map[string]any{"mailbox_key_b64": std(mailbox2)})
	b.ok("mailie/grant-open/alice/epoch-65535", "mailie.grant_open",
		openIn("alice", namespace, aliceSeal, 65535, m2Pub, grants["mailie/grant/alice/epoch-65535"]), map[string]any{"mailbox_key_b64": std(mailbox2)})
	for _, r := range []struct {
		name, code string
		in         map[string]any
	}{
		{"another-user", "authentication", with(o1, "seal_id", bobSeal)},
		{"another-persons-key", "authentication", with(o1, "key", "bob")},
		{"bobs-grant-as-alices", "authentication", with(o1, "grant_b64", std(gBob))},
		{"another-namespace", "authentication", with(o1, "namespace", otherNS)},
		{"another-epoch", "authentication", with(o1, "epoch", 2, "mailbox_public_key_b64", std(m2Pub))},
		{"the-epoch-2-grant-at-epoch-1", "authentication", with(o1, "grant_b64", std(g2))},
		{"the-epoch-1-grant-at-epoch-2", "authentication", openIn("alice", namespace, aliceSeal, 2, m2Pub, g1)},
		{"header-epoch-rewritten", "authentication", with(o1, "grant_b64", std(set(g1, 6, 2)))},
		{"reserved-byte-set", "authentication", with(o1, "grant_b64", std(set(g1, 7, 1)))},
		{"another-kind-content-key", "authentication", with(o1, "grant_b64", std(otherKind))},
		{"a-key-the-sealer-chose", "authentication", with(o1, "grant_b64", std(forged))},
		{"another-mailboxs-public-key", "authentication", with(o1, "mailbox_public_key_b64", std(m2Pub))},
		{"flipped-encapsulated-key", "authentication", with(o1, "grant_b64", std(flip(g1, 10)))},
		{"flipped-ciphertext", "authentication", with(o1, "grant_b64", std(flip(g1, 50)))},
		{"flipped-tag", "authentication", with(o1, "grant_b64", std(flip(g1, 87)))},
		{"truncated-to-87-bytes", "authentication", with(o1, "grant_b64", std(g1[:87]))},
		{"extended-to-89-bytes", "authentication", with(o1, "grant_b64", std(append(bytes.Clone(g1), 0)))},
		{"truncated-to-55-bytes", "short", with(o1, "grant_b64", std(g1[:55]))},
		{"truncated-to-7-bytes", "short", with(o1, "grant_b64", std(g1[:7]))},
		{"wappies-magic", "magic", with(o1, "grant_b64", std(set(set(g1, 0, 'W'), 1, 'S')))},
		{"a-wappie-device-grant-of-the-same-binding", "magic", with(o1, "grant_b64", std(wappieGrant))},
		{"version-2", "version", with(o1, "grant_b64", std(set(g1, 2, 2)))},
		{"suite-2", "suite", with(o1, "grant_b64", std(set(g1, 3, 2)))},
		{"batch-mode", "mode", with(o1, "grant_b64", std(set(g1, 4, 2)))},
		{"mode-3", "mode", with(o1, "grant_b64", std(set(g1, 4, 3)))},
		{"seal-id-in-upper-case", "binding", with(o1, "seal_id", upperID)},
		{"epoch-0", "binding", with(o1, "epoch", 0)},
		{"mailbox-public-key-of-31-bytes", "binding", with(o1, "mailbox_public_key_b64", std(m1Pub[:31]))},
	} {
		b.refuse("mailie/grant-open/refuses/"+r.name, "mailie.grant_open", r.in, r.code)
	}

	// What a server checks of a grant it is sent.
	shapeIn := func(g []byte, epoch int) map[string]any { return map[string]any{"grant_b64": std(g), "epoch": epoch} }
	b.ok("mailie/grant-shape/epoch-1", "mailie.grant_shape", shapeIn(g1, 1), accepted)
	b.ok("mailie/grant-shape/epoch-2", "mailie.grant_shape", shapeIn(g2, 2), accepted)
	for name, in := range inOrder(map[string]map[string]any{
		"not-the-current-epoch": shapeIn(g1, 2),
		"87-bytes":              shapeIn(g1[:87], 1),
		"89-bytes":              shapeIn(append(bytes.Clone(g1), 0), 1),
		"wappies-magic":         shapeIn(wappieGrant, 1),
		"batch-mode":            shapeIn(set(g1, 4, 2), 1),
		"reserved-byte-set":     shapeIn(set(g1, 7, 1), 1),
		"version-2":             shapeIn(set(g1, 2, 2), 1),
		"suite-2":               shapeIn(set(g1, 3, 2), 1),
		"empty":                 shapeIn(nil, 1),
	}) {
		b.refuse("mailie/grant-shape/refuses/"+name, "mailie.grant_shape", in, "shape")
	}
	// The two envelopes that are not grants are recorded with the seeds
	// they were sealed under, in the cases that refuse them.
	for i := range b.cases {
		switch b.cases[i].ID {
		case "mailie/grant-open/refuses/another-kind-content-key":
			b.cases[i].In["seed"] = otherKindSeed
		case "mailie/grant-open/refuses/a-wappie-device-grant-of-the-same-binding":
			b.cases[i].In["seed"] = wappieSeed
		}
	}
	return b.file("seal", "Mailie's grants (docs/key-scheme.md sections 4, 9 and 10): the seal domain and kinds, the server's check of a public key, the grant's row, info and additional data, "+
		"88-byte grants of a mailbox's private key sealed to an account key, sealed by Go for TypeScript to open, and what must not open or be sealed. "+
		"Errors are the kit's seal codes and Mailie's binding, shape and public_key.",
		"each mailie.grant_seal, and the two other envelopes the refusals open, ran under testing/cryptotest.SetGlobalRandom with its case's seed, replayed only on the recorded toolchain; TypeScript opens them",
		keys)
}

func sealProfile() map[string]any {
	return map[string]any{
		"magic_b64": std(mailie.SealMagic[:]), "label": mailie.SealLabel,
		"grant_kind": int(mailie.KindMailboxGrant), "content_key_kind": int(mailie.KindContentKey),
		"grant_len": mailie.GrantLen, "min_epoch": mailie.MinEpoch, "max_epoch": mailie.MaxEpoch,
	}
}

func buildPlatformWrap(t *testing.T) *ksFile {
	b := &builder{t: t, seed: 3000}
	m := mailie.PlatformWrap()
	root := digest("alice/id. root")
	sk1, _ := must2(t)(platform.ProductKey(root, "mailie", 1))
	sk2, _ := must2(t)(platform.ProductKey(root, "mailie", 2))
	wsk, _ := must2(t)(platform.ProductKey(root, "wappie", 1))
	alicePub := public(t, aliceKey)
	for _, e := range []int{1, 2} {
		sk, pk := must2(t)(platform.ProductKey(root, "mailie", e))
		b.ok(fmt.Sprintf("mailie/product-key/epoch-%d", e), "mailie.product_key", map[string]any{"root_b64": std(root), "epoch": e},
			map[string]any{"product_key_b64": std(sk), "product_public_key_b64": std(pk), "product_key_id": platform.ProductKeyID("mailie", e)})
	}
	bindIn := func(seal, s string, e int, pub []byte) map[string]any {
		return map[string]any{"seal_id": seal, "sub": s, "product_key_epoch": e, "account_public_key_b64": std(pub)}
	}
	for _, e := range []int{1, 2} {
		b.ok(fmt.Sprintf("mailie/platform-wrap-binding/epoch-%d", e), "mailie.platform_wrap_binding", bindIn(aliceSeal, sub, e, alicePub),
			map[string]any{"user_id": aliceSeal, "sub": sub, "product_key_id": platform.ProductKeyID("mailie", e)})
	}
	b.refuse("mailie/platform-wrap-binding/refuses/seal-id-a-uuidv7", "mailie.platform_wrap_binding", bindIn(v7ID, sub, 1, alicePub), "binding")
	b.ok("mailie/platform-wrap-binding/a-uuidv4-sub", "mailie.platform_wrap_binding", bindIn(aliceSeal, subV4, 1, alicePub),
		map[string]any{"user_id": aliceSeal, "sub": subV4, "product_key_id": platform.ProductKeyID("mailie", 1)})
	b.refuse("mailie/platform-wrap-binding/refuses/seal-id-the-sub", "mailie.platform_wrap_binding", bindIn(subV4, subV4, 1, alicePub), "binding")
	b.refuse("mailie/platform-wrap-binding/refuses/epoch-0", "mailie.platform_wrap_binding", bindIn(aliceSeal, sub, 0, alicePub), "binding")

	binding := func(e int) (platformwrap.Binding, map[string]any) {
		bd := must[platformwrap.Binding](t)(mailie.PlatformWrapBinding(aliceSeal, sub, e, alicePub))
		return bd, map[string]any{"user_id": bd.UserID, "sub": bd.Sub, "product_key_id": bd.ProductKeyID, "account_public_key_b64": std(alicePub)}
	}
	wraps := map[int][]byte{}
	for _, e := range []int{1, 2} {
		bd, bi := binding(e)
		sk := sk1
		if e == 2 {
			sk = sk2
		}
		info := must[[]byte](t)(platformwrap.Info(m, bd))
		aad := must[[]byte](t)(platformwrap.AAD(m, bd))
		nonce := digest(fmt.Sprintf("platform wrap/epoch %d/nonce", e))[:12]
		wrap := must[[]byte](t)(platformwrap.Seal(m, bytes.NewReader(nonce), sk, aliceKey, bd))
		wraps[e] = wrap
		id := fmt.Sprintf("epoch-%d", e)
		b.ok("mailie/platform-wrap/info/"+id, "mailie.platform_wrap_info", bi, map[string]any{"info_b64": std(info)})
		b.ok("mailie/platform-wrap/aad/"+id, "mailie.platform_wrap_aad", bi, map[string]any{"aad_b64": std(aad)})
		b.ok("mailie/platform-wrap/seal/"+id, "mailie.platform_wrap_seal",
			with(bi, "product_key_b64", std(sk), "account_key_b64", std(aliceKey), "nonce_b64", std(nonce)),
			map[string]any{"wrap_b64": std(wrap), "k_pw_b64": std(kpwOf(t, sk, info))})
		b.ok("mailie/platform-wrap/open/"+id, "mailie.platform_wrap_open", with(bi, "product_key_b64", std(sk), "wrap_b64", std(wrap)),
			map[string]any{"account_key_b64": std(aliceKey)})
	}
	// Wappie's wrap of the same account key, for the same person and id.
	// account, under the kit's Wappie profile: never opens as Mailie's.
	wb := platformwrap.Binding{UserID: aliceSeal, Sub: sub, ProductKeyID: "wappie:1", AccountPublicKey: alicePub}
	wNonce := digest("platform wrap/wappie/nonce")[:12]
	wappieWrap := must[[]byte](t)(platformwrap.Seal(wappie.PlatformWrap(), bytes.NewReader(wNonce), wsk, aliceKey, wb))
	sameBytes := must[[]byte](t)(platformwrap.Seal(wappie.PlatformWrap(), bytes.NewReader(wNonce), sk1, aliceKey, wb))
	_, b1 := binding(1)
	o := with(b1, "product_key_b64", std(sk1), "wrap_b64", std(wraps[1]))
	for _, r := range []struct {
		name string
		in   map[string]any
	}{
		{"the-same-persons-wappie-wrap", with(o, "wrap_b64", std(wappieWrap), "product_key_b64", std(wsk))},
		{"a-wappie-wrap-under-the-same-key-bytes", with(o, "wrap_b64", std(sameBytes))},
		{"a-wappie-wrap-with-its-own-binding", with(o, "wrap_b64", std(wappieWrap), "product_key_b64", std(wsk), "product_key_id", "wappie:1")},
		{"another-seal-id", with(o, "user_id", bobSeal)},
		{"the-sub-as-the-user-id", with(o, "user_id", sub)},
		{"another-sub", with(o, "sub", "019a8b2c-3d4e-7f60-8a71-b2c3d4e5f609")},
		{"another-epoch", with(o, "product_key_id", "mailie:2")},
		{"the-epoch-2-wrap", with(o, "wrap_b64", std(wraps[2]))},
		{"another-account-public-key", with(o, "account_public_key_b64", std(public(t, bobKey)))},
		{"another-product-key", with(o, "product_key_b64", std(sk2))},
		{"header-0x02-an-account-wrap", with(o, "wrap_b64", std(set(wraps[1], 0, 0x02)))},
		{"flipped-tag", with(o, "wrap_b64", std(flip(wraps[1], 60)))},
		{"length-60", with(o, "wrap_b64", std(wraps[1][:60]))},
	} {
		b.refuse("mailie/platform-wrap/open/refuses/"+r.name, "mailie.platform_wrap_open", r.in, "platform_wrap")
	}
	b.refuse("mailie/platform-wrap/seal/refuses/a-wappie-product-key-id", "mailie.platform_wrap_seal",
		with(b1, "product_key_id", "wappie:1", "product_key_b64", std(sk1), "account_key_b64", std(aliceKey), "nonce_b64", std(wNonce)), "platform_wrap")
	b.refuse("mailie/platform-wrap/seal/refuses/account-key-not-the-public-keys", "mailie.platform_wrap_seal",
		with(b1, "product_key_b64", std(sk1), "account_key_b64", std(bobKey), "nonce_b64", std(wNonce)), "platform_wrap")
	return b.file("platformwrap", "Mailie's wrap of the account key under the product key sk_p (docs/key-scheme.md section 6): the kit's platform wrap "+
		"under the kit's Mailie profile, bound to the person's seal id as the product's user id, never the sub. The kit's own vectors of the construction "+
		"(vectors/mailie/golden/platform-wrap-go.json) are not repeated: the Go tests run them through this package's profile. "+
		"Every refusal is platform_wrap, but for Mailie's binding helper, which refuses with binding.",
		"none: every nonce is in its case", nil)
}

// kpwOf is K_pw, computed here with crypto/hkdf, apart from package
// platformwrap (SPEC section 6.8).
func kpwOf(t *testing.T, productKey, info []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, productKey, []byte(mailie.PlatformWrapSalt), string(info), mailie.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func buildBrowserVault(t *testing.T) *ksFile {
	b := &builder{t: t, seed: 4000}
	alicePub := public(t, aliceKey)
	b.ok("mailie/browser-vault/profile", "mailie.browser_vault_profile", map[string]any{},
		map[string]any{"tag": mailie.BrowserVaultTag, "version": mailie.BrowserVaultVersion})
	in := func(seal string, pub []byte) map[string]any {
		return map[string]any{"seal_id": seal, "account_public_key_b64": std(pub)}
	}
	for _, r := range []struct {
		name, seal string
		key        []byte
	}{{"alice", aliceSeal, aliceKey}, {"bob", bobSeal, bobKey}} {
		pub := public(t, r.key)
		b.ok("mailie/browser-vault/aad/"+r.name, "mailie.browser_vault_aad", in(r.seal, pub),
			map[string]any{"aad_b64": std(must[[]byte](t)(mailie.BrowserVaultAAD(r.seal, pub)))})
	}
	b.refuse("mailie/browser-vault/aad/refuses/seal-id-in-upper-case", "mailie.browser_vault_aad", in(upperID, alicePub), "binding")
	b.refuse("mailie/browser-vault/aad/refuses/seal-id-a-uuidv7", "mailie.browser_vault_aad", in(v7ID, alicePub), "binding")
	b.refuse("mailie/browser-vault/aad/refuses/public-key-of-31-bytes", "mailie.browser_vault_aad", in(aliceSeal, alicePub[:31]), "binding")
	return b.file("browser_account", "The browser vault (docs/key-scheme.md section 7): the kit's key at rest in the browser under Mailie's tag, "+
		"bound to the person's seal id. Its AES key is generated non-extractable and cannot be vectored; its additional data is, "+
		"and web/test/keyscheme.spec.ts seals and opens records with it.", "none", nil)
}

// ksBuildAll builds every file.
func ksBuildAll(t *testing.T) map[string]*ksFile {
	return map[string]*ksFile{
		"grant-go.json":         buildGrant(t),
		"account-go.json":       buildAccount(t),
		"platform-wrap-go.json": buildPlatformWrap(t),
		"browser-vault-go.json": buildBrowserVault(t),
	}
}

func ksEncode(t *testing.T, f *ksFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Running a case
// ---------------------------------------------------------------------------

// args reads a case's inputs and records which it read, so that a member no
// handler reads fails the case.
type args struct {
	t    *testing.T
	id   string
	m    map[string]any
	keys map[string]ksKey
	out  map[string]any
	read map[string]bool
}

func (a args) has(k string) bool { _, ok := a.m[k]; return ok }

func (a args) str(k string) string {
	a.read[k] = true
	v, ok := a.m[k].(string)
	if !ok {
		a.t.Fatalf("%s: %s is not a string", a.id, k)
	}
	return v
}

func (a args) num(k string) int {
	a.read[k] = true
	v, ok := a.m[k].(float64)
	if !ok || v != float64(int(v)) {
		a.t.Fatalf("%s: %s is not an integer", a.id, k)
	}
	return int(v)
}

func (a args) b64(k string) []byte {
	b, err := base64.StdEncoding.Strict().DecodeString(a.str(k))
	if err != nil {
		a.t.Fatalf("%s: %s: %v", a.id, k, err)
	}
	return b
}

func (a args) params(k string) account.KDFParams {
	a.read[k] = true
	p, ok := a.m[k].(map[string]any)
	if !ok {
		a.t.Fatalf("%s: %s is not an object", a.id, k)
	}
	q := args{a.t, a.id, p, nil, nil, map[string]bool{}}
	params := account.KDFParams{Alg: q.str("alg"), M: uint32(q.num("m")), T: uint32(q.num("t")), P: uint8(q.num("p"))}
	q.unread()
	return params
}

// seed reads a seal's recorded seed: Go's re-derivation replays it on the
// toolchains ksReplayToolchains lists
// (TestTheKitWritesMailiesKeySchemeVectorsAgain).
func (a args) seed() {
	if n := a.num("seed"); n < 1 {
		a.t.Fatalf("%s: seed %d", a.id, n)
	}
}

func (a args) privateKey(k string) hpke.PrivateKey {
	named, ok := a.keys[a.str(k)]
	if !ok {
		a.t.Fatalf("%s: no key %q", a.id, a.str(k))
	}
	priv, err := hpke.ParsePrivateKey(unb64(a.t, named.PrivateKey))
	if err != nil {
		a.t.Fatal(err)
	}
	if pub, err := priv.PublicKey(); err != nil || !bytes.Equal(pub.Bytes(), unb64(a.t, named.PublicKey)) {
		a.t.Fatalf("%s: key %q is not a key pair", a.id, a.str(k))
	}
	return priv
}

func (a args) unread() {
	for k := range a.m {
		if !a.read[k] {
			a.t.Errorf("%s: a member no handler reads: %s", a.id, k)
		}
	}
}

func unb64(t testing.TB, s string) []byte {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ksErrorCode is how the vectors name a Go error (Mailie's spec, section
// 13).
func ksErrorCode(err error) (code, reason string) {
	var ae *account.Error
	switch {
	case errors.Is(err, mailie.ErrBinding):
		return "binding", ""
	case errors.Is(err, mailie.ErrShape):
		return "shape", ""
	case errors.Is(err, mailie.ErrPublicKey):
		return "public_key", ""
	case errors.Is(err, platformwrap.ErrPlatformWrap):
		return "platform_wrap", ""
	case errors.Is(err, platform.ErrRecoveryCode):
		return "recovery_code", ""
	case errors.As(err, &ae):
		return ae.Code, ae.Reason
	case errors.Is(err, seal.ErrShort):
		return "short", ""
	case errors.Is(err, seal.ErrMagic):
		return "magic", ""
	case errors.Is(err, seal.ErrVersion):
		return "version", ""
	case errors.Is(err, seal.ErrSuite):
		return "suite", ""
	case errors.Is(err, seal.ErrMode):
		return "mode", ""
	case errors.Is(err, seal.ErrAuthentication):
		return "authentication", ""
	case errors.Is(err, seal.ErrInvalidKey):
		return "invalid_key", ""
	}
	return "unclassified: " + err.Error(), ""
}

// ksRun runs one case: the output must be exactly the case's, or the error
// its code and reason, with nothing returned.
func ksRun(t *testing.T, file string, f *ksFile, c ksCase) {
	a := args{t, file + "#" + c.ID, c.In, f.Keys, c.Out, map[string]bool{}}
	out, err := ksDispatch(a, c.Op)
	a.unread()
	if c.Error != "" {
		if err == nil {
			t.Fatalf("opened, want %s %s", c.Error, c.Reason)
		}
		if code, reason := ksErrorCode(err); code != c.Error || reason != c.Reason {
			t.Fatalf("%s %s (%v), want %s %s", code, reason, err, c.Error, c.Reason)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if got, want := roundTrip(t, out), roundTrip(t, c.Out); !reflect.DeepEqual(got, want) {
		t.Fatalf("\n got %v\nwant %v", got, want)
	}
}

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var back any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	return back
}

func ksDispatch(a args, op string) (map[string]any, error) {
	p := mailie.Account()
	switch op {
	case "mailie.account_profile":
		return accountProfile(), nil
	case "mailie.normalise_address":
		return map[string]any{"address": normaliseAddress(a.str("address"))}, nil
	case "mailie.public_key_check":
		return accepted, mailie.CheckPublicKey(a.b64("public_key_b64"))
	case "mailie.decoy_salt":
		s, err := decoySalt(a.b64("key_b64"), a.str("address"))
		return map[string]any{"salt_b64": std(s)}, err
	case "account.derive":
		d, err := account.DeriveBytes(p, a.str("password"), a.b64("salt_b64"), a.params("params"))
		if err != nil {
			return nil, err
		}
		defer d.Clear()
		return map[string]any{"auth_b64": std(d.Auth), "auth_key": string(d.AuthText), "wrap_b64": std(d.Wrap)}, nil
	case "mailie.recovery_code":
		code, err := platform.RecoveryCodeFromBytes(a.b64("bytes_b64"))
		if err != nil {
			return nil, err
		}
		display := make([]string, 0, 6)
		for i := 0; i < len(code); i += 5 {
			display = append(display, code[i:i+5])
		}
		return map[string]any{"code": code, "display": strings.Join(display, "-")}, nil
	case "account.normalise_recovery_code":
		code, err := p.NormaliseRecovery(a.str("code"))
		return map[string]any{"code": code}, err
	case "account.recovery_key":
		k, err := account.RecoveryKey(p, a.str("code"))
		return map[string]any{"key_b64": std(k)}, err
	case "account.recovery_proof":
		proof, err := account.RecoveryProof(p, a.str("code"))
		return map[string]any{"proof": proof}, err
	case "mailie.account_wrap_aad":
		aad, err := mailie.AccountWrapAAD(mailie.WrapKind(a.str("kind")), a.str("seal_id"), a.b64("account_public_key_b64"))
		return map[string]any{"aad_b64": std(aad)}, err
	case "mailie.account_wrap":
		return accountWrap(a)
	case "mailie.account_unwrap":
		return accountUnwrap(a, p)
	case "mailie.account_wrap_shape":
		return accepted, mailie.CheckAccountWrapShape(a.b64("wrap_b64"))
	case "mailie.seal_profile":
		return sealProfile(), nil
	case "seal.kind_name":
		return map[string]any{"name": mailie.Kind(a.num("kind")).String()}, nil
	case "mailie.grant_row":
		row, err := mailie.GrantRow(a.str("namespace"), a.str("seal_id"), a.num("epoch"))
		return map[string]any{"row": row.String()}, err
	case "mailie.grant_info":
		info, err := mailie.GrantInfo(a.str("namespace"), a.num("epoch"))
		return map[string]any{"info_b64": std(info), "info": string(info)}, err
	case "mailie.grant_aad":
		aad, err := mailie.GrantAAD(a.str("namespace"), a.str("seal_id"), a.num("epoch"))
		return map[string]any{"aad_b64": std(aad)}, err
	case "mailie.grant_seal":
		return grantSeal(a)
	case "mailie.grant_open":
		if a.has("seed") {
			a.seed()
		}
		key, err := mailie.OpenGrant(a.privateKey("key"), a.str("namespace"), a.str("seal_id"), a.num("epoch"), a.b64("mailbox_public_key_b64"), a.b64("grant_b64"))
		if err != nil && key != nil {
			a.t.Fatalf("%s: a refusal returned a key", a.id)
		}
		return map[string]any{"mailbox_key_b64": std(key)}, err
	case "mailie.grant_shape":
		return accepted, mailie.CheckGrantShape(a.b64("grant_b64"), a.num("epoch"))
	case "mailie.product_key":
		sk, pk, err := platform.ProductKey(a.b64("root_b64"), mailie.PlatformWrapProduct, a.num("epoch"))
		return map[string]any{"product_key_b64": std(sk), "product_public_key_b64": std(pk), "product_key_id": platform.ProductKeyID(mailie.PlatformWrapProduct, a.num("epoch"))}, err
	case "mailie.platform_wrap_binding":
		bd, err := mailie.PlatformWrapBinding(a.str("seal_id"), a.str("sub"), a.num("product_key_epoch"), a.b64("account_public_key_b64"))
		return map[string]any{"user_id": bd.UserID, "sub": bd.Sub, "product_key_id": bd.ProductKeyID}, err
	case "mailie.platform_wrap_info":
		info, err := platformwrap.Info(mailie.PlatformWrap(), wrapBinding(a))
		return map[string]any{"info_b64": std(info)}, err
	case "mailie.platform_wrap_aad":
		aad, err := platformwrap.AAD(mailie.PlatformWrap(), wrapBinding(a))
		return map[string]any{"aad_b64": std(aad)}, err
	case "mailie.platform_wrap_seal":
		return platformWrapSeal(a)
	case "mailie.platform_wrap_open":
		key, err := platformwrap.Open(mailie.PlatformWrap(), a.b64("product_key_b64"), a.b64("wrap_b64"), wrapBinding(a))
		if err != nil && key != nil {
			a.t.Fatalf("%s: a refusal returned a key", a.id)
		}
		return map[string]any{"account_key_b64": std(key)}, err
	case "mailie.browser_vault_profile":
		return map[string]any{"tag": mailie.BrowserVaultTag, "version": mailie.BrowserVaultVersion}, nil
	case "mailie.browser_vault_aad":
		aad, err := mailie.BrowserVaultAAD(a.str("seal_id"), a.b64("account_public_key_b64"))
		return map[string]any{"aad_b64": std(aad)}, err
	}
	a.t.Fatalf("%s: op %q is not handled by the Go tests", a.id, op)
	return nil, nil
}

// accountWrap replays a wrap: computed with the standard library from the
// recorded nonce, the format must be the wrap's bytes, which the package
// opens to the account key, and SealAccountWrap must seal it. A refusal
// records no nonce and is asked of SealAccountWrap.
func accountWrap(a args) (map[string]any, error) {
	kind, sealID, wrapKey, key := mailie.WrapKind(a.str("kind")), a.str("seal_id"), a.b64("wrap_key_b64"), a.b64("account_key_b64")
	if !a.has("nonce_b64") {
		w, err := mailie.SealAccountWrap(kind, wrapKey, key, sealID)
		if err != nil && w != nil {
			a.t.Fatalf("%s: a refusal returned a wrap", a.id)
		}
		return nil, err
	}
	a.seed()
	pub, err := mailie.PublicKey(key)
	if err != nil {
		return nil, err
	}
	aad, err := mailie.AccountWrapAAD(kind, sealID, pub)
	if err != nil {
		return nil, err
	}
	nonce := a.b64("nonce_b64")
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	wrap := gcm.Seal(append([]byte{mailie.AccountWrapHeader}, nonce...), nonce, key, aad)
	back, err := mailie.OpenAccountWrap(kind, wrapKey, wrap, sealID, pub)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(back, key) {
		return nil, errors.New("the wrap opens to another key")
	}
	fresh, err := mailie.SealAccountWrap(kind, wrapKey, key, sealID)
	if err != nil {
		return nil, err
	}
	if len(fresh) != mailie.AccountWrapLen || bytes.Equal(fresh[1:13], nonce) {
		return nil, errors.New("a fresh wrap does not draw a fresh nonce")
	}
	return map[string]any{"account_public_key_b64": std(pub), "aad_b64": std(aad), "wrap_b64": std(wrap)}, nil
}

func accountUnwrap(a args, p account.Profile) (map[string]any, error) {
	kind, wrap, sealID, pub := mailie.WrapKind(a.str("kind")), a.b64("wrap_b64"), a.str("seal_id"), a.b64("account_public_key_b64")
	var wrapKey []byte
	switch {
	case a.has("wrap_key_b64"):
		wrapKey = a.b64("wrap_key_b64")
	case a.has("recovery_code"):
		k, err := account.RecoveryKey(p, a.str("recovery_code"))
		if err != nil {
			return nil, err
		}
		wrapKey = k
	case a.has("password"):
		d, err := account.DeriveBytes(p, a.str("password"), a.b64("salt_b64"), a.params("params"))
		if err != nil {
			return nil, err
		}
		defer d.Clear()
		wrapKey = d.Wrap
	default:
		a.t.Fatalf("%s: no wrap key", a.id)
	}
	key, err := mailie.OpenAccountWrap(kind, wrapKey, wrap, sealID, pub)
	if err != nil && key != nil {
		a.t.Fatalf("%s: a refusal returned a key", a.id)
	}
	return map[string]any{"account_key_b64": std(key)}, err
}

// grantSeal opens the case's recorded grant with its recipient's private key
// and checks its shape, then seals a fresh one and opens that; a refusal is
// asked of SealGrant. The recorded bytes come from a seeded ephemeral key:
// TestTheKitWritesMailiesKeySchemeVectorsAgain replays it on the toolchains
// ksReplayToolchains lists.
func grantSeal(a args) (map[string]any, error) {
	pub, ns, sealID, epoch, key := a.b64("recipient_public_key_b64"), a.str("namespace"), a.str("seal_id"), a.num("epoch"), a.b64("mailbox_key_b64")
	if !a.has("recipient") {
		g, err := mailie.SealGrant(pub, ns, sealID, epoch, key)
		if err != nil && g != nil {
			a.t.Fatalf("%s: a refusal returned a grant", a.id)
		}
		return nil, err
	}
	a.seed()
	priv := a.privateKey("recipient")
	mailboxPub, err := mailie.PublicKey(key)
	if err != nil {
		return nil, err
	}
	recorded, ok := a.out["grant_b64"].(string)
	if !ok {
		a.t.Fatalf("%s: no recorded grant", a.id)
	}
	fresh, err := mailie.SealGrant(pub, ns, sealID, epoch, key)
	if err != nil {
		return nil, err
	}
	for _, g := range [][]byte{unb64(a.t, recorded), fresh} {
		if err := mailie.CheckGrantShape(g, epoch); err != nil {
			return nil, err
		}
		back, err := mailie.OpenGrant(priv, ns, sealID, epoch, mailboxPub, g)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(back, key) {
			return nil, errors.New("the grant opens to another key")
		}
	}
	return map[string]any{"grant_b64": recorded, "mailbox_public_key_b64": std(mailboxPub)}, nil
}

func wrapBinding(a args) platformwrap.Binding {
	return platformwrap.Binding{UserID: a.str("user_id"), Sub: a.str("sub"), ProductKeyID: a.str("product_key_id"), AccountPublicKey: a.b64("account_public_key_b64")}
}

// platformWrapSeal replays a seal from its nonce, and checks k_pw_b64 with
// crypto/hkdf; a refusal is asked of platformwrap.Seal.
func platformWrapSeal(a args) (map[string]any, error) {
	m := mailie.PlatformWrap()
	sk := a.b64("product_key_b64")
	b := wrapBinding(a)
	var nonce io.Reader // a refusal never draws one
	if a.has("nonce_b64") {
		nonce = bytes.NewReader(a.b64("nonce_b64"))
	}
	wrap, err := platformwrap.Seal(m, nonce, sk, a.b64("account_key_b64"), b)
	if err != nil {
		if wrap != nil {
			a.t.Fatalf("%s: a refusal returned a wrap", a.id)
		}
		return nil, err
	}
	info, err := platformwrap.Info(m, b)
	if err != nil {
		return nil, err
	}
	return map[string]any{"wrap_b64": std(wrap), "k_pw_b64": std(kpwOf(a.t, sk, info))}, nil
}
