package cross_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/profiles/platform"
)

// The alphabets of a relying party id's label (SPEC section 11.16).
const (
	rpIDEdge   = "abcdefghijklmnopqrstuvwxyz0123456789"
	rpIDMiddle = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// The relying parties the platform has, and some names at the limits.
var passkeyRPIDs = []string{"id.thehappie.co", "id.thehappie.localhost", "localhost"}

// randomLabel is one label of a relying party id of n bytes.
func randomLabel(t *testing.T, n int) string {
	t.Helper()
	if n == 1 {
		return randomFrom(t, rpIDEdge, 1)
	}
	return randomFrom(t, rpIDEdge, 1) + randomFrom(t, rpIDMiddle, n-2) + randomFrom(t, rpIDEdge, 1)
}

// randomRPID is a relying party id in its one spelling: one the platform
// has, one of exactly 253 bytes, or 1 to 4 random labels.
func randomRPID(t *testing.T) string {
	t.Helper()
	switch randomInt(t, 4) {
	case 0:
		return pick(t, passkeyRPIDs)
	case 1:
		return randomLabel(t, 63) + "." + randomLabel(t, 63) + "." + randomLabel(t, 63) + "." + randomLabel(t, 61)
	}
	for {
		labels := make([]string, 1+randomInt(t, 4))
		for i := range labels {
			n := 1 + int(randomInt(t, 12))
			if randomInt(t, 8) == 0 {
				n = 1 + int(randomInt(t, 63))
			}
			labels[i] = randomLabel(t, n)
		}
		last := labels[len(labels)-1]
		if strings.Trim(last, "0123456789") == "" {
			labels[len(labels)-1] = "x" + last[1:]
		}
		if s := strings.Join(labels, "."); len(s) <= 253 {
			return s
		}
	}
}

// breakRPID changes a relying party id to a spelling section 11.16 refuses,
// and says how.
func breakRPID(t *testing.T, rp string) (string, string) {
	t.Helper()
	insert := func(s, what string) string {
		at := int(randomInt(t, int64(len(s)+1)))
		return s[:at] + what + s[at:]
	}
	for {
		var broken, how string
		switch randomInt(t, 16) {
		case 0:
			broken, how = insert(rp, pick(t, []string{"A", "Z", "Q"})), "upper-case"
		case 1:
			broken, how = rp+pick(t, []string{":443", ":8290", ":"}), "port"
		case 2:
			broken, how = pick(t, []string{"https://", "http://", "//"})+rp, "scheme"
		case 3:
			broken, how = rp+".", "trailing-dot"
		case 4:
			broken, how = "."+rp, "leading-dot"
		case 5:
			broken, how = insert(rp, ".."), "empty-label"
		case 6:
			broken, how = "-"+rp, "leading-dash"
		case 7:
			broken, how = rp+"-", "trailing-dash"
		case 8:
			broken, how = randomLabel(t, 64)+"."+rp, "label-64"
		case 9:
			broken, how = randomLabel(t, 63)+"."+randomLabel(t, 63)+"."+randomLabel(t, 63)+"."+randomLabel(t, 62), "length-254"
		case 10:
			broken, how = fmt.Sprintf("%d.%d.%d.%d", randomInt(t, 256), randomInt(t, 256), randomInt(t, 256), randomInt(t, 256)), "ipv4"
		case 11:
			broken, how = rp+"."+randomFrom(t, "0123456789", 1+int(randomInt(t, 4))), "digits"
		case 12:
			broken, how = pick(t, []string{"[::1]", "::1", "[2001:db8::1]"}), "ipv6"
		case 13:
			broken, how = insert(rp, pick(t, []string{"_", " ", "/", "@", "|", "*", "\t", "\x00"})), "character"
		case 14:
			broken, how = insert(rp, pick(t, []string{"\u00e9", "\u0131", "\u0430", "\u00fc", "\u2028"})), "non-ascii"
		default:
			broken, how = "", "empty"
		}
		if !platform.ValidRPID(broken) {
			return broken, how
		}
	}
}

// randomCredentialID is the base64url of 1 to 1023 random bytes, the
// lengths WebAuthn allows: often a common one or a limit.
func randomCredentialID(t *testing.T) string {
	t.Helper()
	sizes := []int{1, 16, 32, 64, 1023}
	size := 1 + int(randomInt(t, 1023))
	if i := int(randomInt(t, int64(len(sizes)+1))); i < len(sizes) {
		size = sizes[i]
	}
	return platform.EncodeB64(randomBytes(t, size))
}

// The texts a mutation draws from: JSON's own characters, the allowlist's
// names and values in their spellings and others, escapes, byte order
// marks, line separators, NUL.
var (
	extensionSeeds = []string{
		`{}`, `{"credProps":{"rk":true}}`, `{"credProps":{"rk":false}}`, `{"prf":{"enabled":true}}`, `{"prf":{"enabled":false}}`,
		`{"credProps":{"rk":true},"prf":{"enabled":true}}`, `{"prf":{"enabled":false},"credProps":{"rk":true}}`,
		` {"pr\u0066" : {"en\u0061bled" : true}} `,
	}
	extensionPieces = []string{
		"{", "}", "[", "]", ":", ",", `"`, `\`, "u", "0", "6", "f", "t", "r", "e", "n", "l", "a", "s", " ", "\t", "\n", "\r",
		"\ufeff", "P", "R", "F", "k", "d", "b", "1", "-", ".", "\u00e9", "\x00", `\u0066`, `\u0000`, `\ud800`, `\/`,
		`"prf"`, `"credProps"`, `"rk"`, `"enabled"`, `"results"`, `"first"`, "true", "false", "null", "1.0", "1e0",
		`{"enabled":true}`, `{"rk":false}`, `"results":{}`, `"results":{"first":"EhJD599fFQOFAB7ZW0Br9KT5OkI77uQwiPBVpt38MNM"}`,
		"\u2028", "\u00a0", "\U0001f600",
	}
)

// mutateExtensions applies one to three random edits to a text.
func mutateExtensions(t *testing.T, s string) string {
	t.Helper()
	for k := 1 + randomInt(t, 3); k > 0; k-- {
		at := int(randomInt(t, int64(len(s)+1)))
		piece := pick(t, extensionPieces)
		switch randomInt(t, 4) {
		case 0, 1:
			s = s[:at] + piece + s[at:]
		case 2:
			if at < len(s) {
				s = s[:at] + s[at+1:]
			}
		default:
			if at < len(s) {
				s = s[:at] + piece + s[at+1:]
			}
		}
	}
	return s
}

// writePlatformPasskey writes platform-passkey-go.json: fresh cases of the
// platform profile's part 3 (SPEC section 11.16), for the TypeScript tests.
// Each case's outcome is first checked here.
func writePlatformPasskey(t *testing.T, dir string) {
	var cases []vcase
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	expect := func(id string, err error, want string) {
		t.Helper()
		if got := platform.ErrorCode(err); got != want || (err != nil && got == "") {
			t.Fatalf("%s: %q (%v), want %q", id, got, err, want)
		}
	}

	// The PRF salt of relying party ids, half of them broken.
	for i := range 200 {
		rp := randomRPID(t)
		id := fmt.Sprintf("platform/prf-salt/%d", i)
		if i%2 == 1 {
			var how string
			rp, how = breakRPID(t, rp)
			id += "/refuses/" + how
		}
		salt, err := platform.PRFSalt(rp)
		c := vcase{ID: id, Op: "platform.prf_salt", In: map[string]any{"rp_id": rp}}
		if i%2 == 1 {
			expect(id, err, "wrap")
			c.Error = "wrap"
		} else {
			must(err)
			c.Out = map[string]any{"prf_salt_b64": b64(salt)}
		}
		cases = append(cases, c)
	}

	// Fresh passkey wraps, each with the nonce it drew, then opened with one
	// thing changed at a time.
	for i := range 32 {
		prf, root := randomBytes(t, platform.PRFOutputLen), randomBytes(t, platform.KeyLen)
		b := platform.Binding{Sub: uuid.Must(uuid.NewV7()).String(), Epoch: randomEpoch(t), RPID: randomRPID(t), CredentialID: randomCredentialID(t)}
		var drawn bytes.Buffer
		w, err := platform.NewPasskeyWrap(io.TeeReader(rand.Reader, &drawn), prf, root, b)
		must(err)
		key, err := platform.PasskeyWrapKey(prf, b.RPID)
		must(err)
		aad, err := platform.WrapAAD(platform.WrapPasskey, b)
		must(err)
		id := fmt.Sprintf("platform/passkey-wrap/%d", i)
		if got, err := platform.OpenPasskeyWrap(prf, w, b); err != nil || !bytes.Equal(got, root) || drawn.Len() != 12 {
			t.Fatalf("%s: %v", id, err)
		}
		in := map[string]any{
			"rp_id": b.RPID, "prf_b64": b64(prf), "root_b64": b64(root), "sub": b.Sub, "epoch": b.Epoch,
			"credential_id": b.CredentialID, "nonce_b64": b64(drawn.Bytes()),
		}
		cases = append(cases, vcase{ID: id, Op: "platform.passkey_wrap", In: in, Out: map[string]any{"aad": string(aad), "wrap_b64": b64(w), "k_pk_b64": b64(key)}})

		open := func(what string, prf, wrap []byte, b platform.Binding) {
			t.Helper()
			_, err := platform.OpenPasskeyWrap(prf, wrap, b)
			expect(id+"/"+what, err, "wrap")
			cases = append(cases, vcase{ID: id + "/refuses/" + what, Op: "platform.open_passkey_wrap", In: map[string]any{
				"rp_id": b.RPID, "prf_b64": b64(prf), "sub": b.Sub, "epoch": b.Epoch, "credential_id": b.CredentialID, "wrap_b64": b64(wrap),
			}, Error: "wrap"})
		}
		flipped := bytes.Clone(w)
		bit := randomInt(t, int64(len(flipped)*8))
		flipped[bit/8] ^= 1 << (bit % 8)
		open(fmt.Sprintf("flipped-bit-%d", bit), prf, flipped, b)
		header := bytes.Clone(w)
		if randomInt(t, 2) == 0 {
			header[0] = byte(2 + randomInt(t, 254))
		} else {
			kinds := []byte{0x00, byte(platform.WrapPassword), byte(platform.WrapRecovery), 0x04, 0xff}
			header[1] = kinds[randomInt(t, int64(len(kinds)))]
		}
		open("header", prf, header, b)
		if randomInt(t, 2) == 0 {
			open("length", prf, w[:platform.WrapLen-1-int(randomInt(t, 3))], b)
		} else {
			open("length", prf, append(bytes.Clone(w), randomBytes(t, 1+int(randomInt(t, 3)))...), b)
		}
		open("other-prf", randomBytes(t, platform.PRFOutputLen), w, b)
		other := b
		for other.RPID == b.RPID {
			other.RPID = randomRPID(t)
		}
		open("other-rp-id", prf, w, other)
		other = b
		for other.CredentialID == b.CredentialID {
			other.CredentialID = randomCredentialID(t)
		}
		open("other-credential", prf, w, other)
		other = b
		other.Sub = uuid.Must(uuid.NewV7()).String()
		open("other-sub", prf, w, other)
		other = b
		if b.Epoch == platform.MaxEpoch {
			other.Epoch = b.Epoch - 1
		} else {
			other.Epoch = b.Epoch + 1
		}
		open("other-epoch", prf, w, other)
		clear(key)
	}

	// Client extension results edited at random from the allowed ones. Only
	// valid UTF-8 is written: a JSON file carries nothing else the same way
	// to both languages (the unit tests have the rest).
	accepted := 0
	for i := 0; i < 1000; {
		text := mutateExtensions(t, pick(t, extensionSeeds))
		if !utf8.ValidString(text) {
			continue
		}
		id := fmt.Sprintf("platform/check-client-extensions/%d", i)
		i++
		c := vcase{ID: id, Op: "platform.check_client_extensions", In: map[string]any{"text": text}}
		if err := platform.CheckClientExtensions([]byte(text)); err != nil {
			expect(id, err, "client_extensions")
			c.Error = "client_extensions"
		} else {
			c.Out = map[string]any{"accepted": true}
			accepted++
		}
		cases = append(cases, c)
	}
	if accepted == 0 {
		t.Fatal("no client extension text was accepted")
	}

	writeProfile(t, dir, "platform-passkey-go.json", "platform", "platform", "Fresh cases of the platform profile's part 3 (SPEC section 11.16) by the kit's Go, for the TypeScript tests: the PRF salt of 200 relying party ids, half of them in a spelling the protocol refuses; 32 fresh passkey wraps (random PRF output, root, account, epoch, relying party and a credential id of 1 to 1023 bytes) with the nonce each drew, its AAD and K_pk, each also opened with one thing changed (a bit, a header byte, the length, the PRF output, the relying party, the credential, the sub, the epoch); and 1000 client extension results edited at random from the allowed ones, with the allowlist's verdict.", nil, cases)
}
