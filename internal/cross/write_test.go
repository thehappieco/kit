// Package cross_test writes fresh vectors with the kit's Go code, for the
// TypeScript tests to open: the Go-to-TypeScript half of the cross-language
// check (js/test/cross.spec.ts writes the other half).
//
//	KIT_CROSS_OUT=/tmp/x go test ./internal/cross -run TestWriteCrossVectors
//
// Every run uses fresh keys and nonces. `make vectors-kit` runs it into
// vectors/kit at release time; the files written then are kept as golden for
// every later release.
package cross_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/jcs"
	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

type file struct {
	Format      string         `json:"format"`
	Module      string         `json:"module"`
	Profile     string         `json:"profile"`
	GeneratedBy map[string]any `json:"generated_by"`
	Note        string         `json:"note"`
	Keys        map[string]any `json:"keys,omitempty"`
	Cases       []vcase        `json:"cases"`
}

type vcase struct {
	ID     string         `json:"id"`
	Op     string         `json:"op"`
	In     map[string]any `json:"in"`
	Out    map[string]any `json:"out,omitempty"`
	Error  string         `json:"error,omitempty"`
	Reason string         `json:"reason,omitempty"`
	Note   string         `json:"note,omitempty"`
}

var b64 = base64.StdEncoding.EncodeToString

func source() string {
	rev := "unknown"
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		rev = strings.TrimSpace(string(out))
		// The files this writes are not part of the source they record.
		if st, err := exec.Command("git", "status", "--porcelain", "--", ".", ":(exclude)vectors/kit", ":(exclude)vectors/MANIFEST.sha256").Output(); err == nil && len(st) > 0 {
			rev += "+dirty"
		}
	}
	return "github.com/thehappieco/kit@" + rev
}

func write(t *testing.T, dir, name, module, note string, keys map[string]any, cases []vcase) {
	t.Helper()
	f := file{
		Format: "thehappieco-kit-vectors/1", Module: module, Profile: "wappie",
		GeneratedBy: map[string]any{
			"lang": "go", "source": source() + " " + module, "toolchain": runtime.Version(),
			"randomness": "crypto/rand; seals record what they drew where the format has room for it",
			"generator":  "internal/cross/write_test.go",
		},
		Note: note, Keys: keys, Cases: cases,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("refusing to overwrite a vector file: %v", err)
	}
	defer fh.Close()
	if _, err := fh.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// realDH returns an ephemeral public key and its X25519 output with pub: what
// an honest sender computes, for the forger's control cases.
func realDH(t *testing.T, pub hpke.PublicKey) (enc, dh []byte) {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().NewPublicKey(pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dh, err = ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	return ephemeral.PublicKey().Bytes(), dh
}

const forgedNote = "A forgery: the ciphertext is sealed under the secret DHKEM derives from an all-zero X25519 output, which anybody can compute for an encapsulated key of low order. A recipient that skips RFC 9180 §7.1.4's check opens it to forged_plaintext_b64; the forger-control case, built the same way from a real X25519 output, shows the construction is HPKE."

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestWriteCrossVectors(t *testing.T) {
	dir := os.Getenv("KIT_CROSS_OUT")
	if dir == "" {
		t.Skip("KIT_CROSS_OUT is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSeal(t, dir)
	writeHPKE(t, dir)
	writeAccount(t, dir)
	writePasskey(t, dir)
	writeRequestHMAC(t, dir)
	writeJCS(t, dir)
}

func writeSeal(t *testing.T, dir string) {
	pk, sk, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := sk.Bytes()
	keys := map[string]any{"archive": map[string]any{"private_key_b64": b64(raw), "public_key_b64": b64(pk.Bytes())}}
	tenant, device, user := uuid.New(), uuid.New(), uuid.New()
	var cases []vcase
	for _, epoch := range []uint16{0, 1, 65535} {
		row := seal.GrantRow(tenant, device, user, epoch)
		pt := bytes.Repeat([]byte{byte(epoch)}, 32)
		env, err := seal.SealDirect(pk, wappie.KindDeviceGrant, tenant, row, epoch, pt)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/direct/grant/epoch-%d", epoch), Op: "seal.seal_direct",
			In:  map[string]any{"key": "archive", "kind": int(wappie.KindDeviceGrant), "tenant": tenant.String(), "row": row.String(), "epoch": epoch, "plaintext_b64": b64(pt)},
			Out: map[string]any{"envelope_b64": b64(env)}})
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/grant-row/epoch-%d", epoch), Op: "seal.grant_row",
			In:  map[string]any{"tenant": tenant.String(), "device": device.String(), "user": user.String(), "epoch": epoch},
			Out: map[string]any{"row": row.String()}})
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/direct/grant/epoch-%d/other-user", epoch), Op: "seal.open_direct",
			In:    map[string]any{"key": "archive", "kind": int(wappie.KindDeviceGrant), "tenant": tenant.String(), "row": seal.GrantRow(tenant, device, uuid.New(), epoch).String(), "envelope_b64": b64(env)},
			Error: "authentication"})
	}
	for _, id := range []uint32{1, 1<<32 - 1} {
		ck, err := seal.NewContentKey[wappie.Kind](pk, tenant, device, 7, id)
		if err != nil {
			t.Fatal(err)
		}
		ref := map[string]any{"tenant": tenant.String(), "device": device.String(), "id": id, "sealed_b64": b64(ck.Sealed)}
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/content-key/id-%d", id), Op: "seal.open_content_key",
			In: map[string]any{"key": "archive", "tenant": tenant.String(), "device": device.String(), "id": id, "sealed_b64": b64(ck.Sealed)}, Out: map[string]any{"epoch": 7}})
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/content-key-row/id-%d", id), Op: "seal.content_key_row",
			In: map[string]any{"tenant": tenant.String(), "device": device.String(), "id": id}, Out: map[string]any{"row": seal.ContentKeyRow(tenant, device, id).String()}})
		for k := wappie.Kind(1); k <= 0x0f; k++ {
			row := uuid.New()
			pt := []byte(fmt.Sprintf("%s sealed by the kit's Go \u2014 a\u00e7\u00e3o \U0001f511", k))
			env, err := ck.Seal(k, tenant, row, pt)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, vcase{ID: fmt.Sprintf("seal/batch/id-%d/%s", id, k), Op: "seal.seal_batch",
				In:  map[string]any{"key": "archive", "content_key": ref, "kind": int(k), "tenant": tenant.String(), "row": row.String(), "plaintext_b64": b64(pt)},
				Out: map[string]any{"envelope_b64": b64(env)}})
			if k == wappie.KindBody {
				cases = append(cases, vcase{ID: fmt.Sprintf("seal/batch/id-%d/kind-swapped", id), Op: "seal.open_batch",
					In:    map[string]any{"key": "archive", "content_key": ref, "kind": int(wappie.KindPayload), "tenant": tenant.String(), "row": row.String(), "envelope_b64": b64(env)},
					Error: "authentication"})
				id2, epoch, _ := seal.ContentKeyID[wappie.Kind](env)
				cases = append(cases, vcase{ID: fmt.Sprintf("seal/content-key-id/id-%d", id), Op: "seal.content_key_id",
					In: map[string]any{"envelope_b64": b64(env)}, Out: map[string]any{"id": id2, "epoch": epoch}})
			}
		}
	}
	// Forged grants: a device key of the attacker's choosing, sealed to the
	// archive key under the all-zero secret of a low-order encapsulated key.
	// Plus one built the same way from a real X25519 output, which opens.
	const epoch = 1
	row := seal.GrantRow(tenant, device, user, epoch)
	magic := wappie.SealDomain().Magic
	hdr := []byte{magic[0], magic[1], seal.Version, seal.SuiteV1, seal.ModeDirect, 0, epoch, 0}
	info, aad := seal.Info(wappie.KindDeviceGrant, tenant, epoch), seal.AAD(wappie.KindDeviceGrant, tenant, row, hdr)
	chosen := bytes.Repeat([]byte{0x66}, 32)
	envelope := func(enc, ct []byte) []byte { return append(append(append([]byte(nil), hdr...), enc...), ct...) }
	enc, dh := realDH(t, pk)
	control := envelope(enc, forge.Seal(dh, enc, pk.Bytes(), info, aad, chosen))
	if got, err := seal.OpenDirect(sk, wappie.KindDeviceGrant, tenant, row, control); err != nil || !bytes.Equal(got, chosen) {
		t.Fatalf("the forger's control does not open: %v", err)
	}
	cases = append(cases, vcase{ID: "seal/direct/forger-control/grant", Op: "seal.open_direct",
		In:  map[string]any{"key": "archive", "kind": int(wappie.KindDeviceGrant), "tenant": tenant.String(), "row": row.String(), "envelope_b64": b64(control)},
		Out: map[string]any{"plaintext_b64": b64(chosen)}})
	for _, lo := range forge.LowOrder {
		forged := envelope(lo.Point, forge.Seal(make([]byte, 32), lo.Point, pk.Bytes(), info, aad, chosen))
		if _, err := seal.OpenDirect(sk, wappie.KindDeviceGrant, tenant, row, forged); !errors.Is(err, seal.ErrAuthentication) {
			t.Fatalf("%s: a forged grant opened: %v", lo.Name, err)
		}
		cases = append(cases, vcase{ID: "seal/direct/forged/grant/" + lo.Name, Op: "seal.open_direct",
			In:    map[string]any{"key": "archive", "kind": int(wappie.KindDeviceGrant), "tenant": tenant.String(), "row": row.String(), "envelope_b64": b64(forged), "forged_plaintext_b64": b64(chosen)},
			Error: "authentication", Note: forgedNote})
		bad, err := hpke.ParsePublicKey(lo.Point)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := seal.SealDirect(bad, wappie.KindDeviceGrant, tenant, row, epoch, chosen); !errors.Is(err, seal.ErrInvalidKey) {
			t.Fatalf("%s: sealed to a low-order key: %v", lo.Name, err)
		}
		cases = append(cases, vcase{ID: "seal/direct/refuses/low-order-key/" + lo.Name, Op: "seal.seal_direct",
			In:    map[string]any{"public_key_b64": b64(lo.Point), "kind": int(wappie.KindDeviceGrant), "tenant": tenant.String(), "row": row.String(), "epoch": epoch, "plaintext_b64": b64(chosen)},
			Error: "invalid_key"})
	}
	for k := range 0x11 {
		cases = append(cases, vcase{ID: fmt.Sprintf("seal/kind-name/%#x", k), Op: "seal.kind_name", In: map[string]any{"kind": k}, Out: map[string]any{"name": wappie.Kind(k).String()}})
	}
	write(t, dir, "seal-go.json", "seal", "Fresh envelopes sealed by the kit's Go with the Wappie profile, for the TypeScript tests to open, with forged grants that must not open and low-order keys that must not be sealed to.", keys, cases)
}

func writeHPKE(t *testing.T, dir string) {
	pk, sk, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := sk.Bytes()
	keys := map[string]any{"r1": map[string]any{"private_key_b64": b64(raw), "public_key_b64": b64(pk.Bytes())}}
	var cases []vcase
	for i, shape := range []struct{ info, aad, pt []byte }{
		{nil, nil, nil},
		{[]byte("thehappie-id/v1/key-delivery"), []byte(`["thehappie-id/key-delivery",1,"https://id.thehappie.co"]`), bytes.Repeat([]byte{7}, 32)},
		{bytes.Repeat([]byte{1}, 300), bytes.Repeat([]byte{2}, 1000), bytes.Repeat([]byte{3}, 5000)},
	} {
		enc, ct, err := hpke.Seal(pk, shape.info, shape.aad, shape.pt)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, vcase{ID: fmt.Sprintf("hpke/seal/%d", i), Op: "hpke.seal",
			In:  map[string]any{"key": "r1", "info_b64": b64(shape.info), "aad_b64": b64(shape.aad), "plaintext_b64": b64(shape.pt)},
			Out: map[string]any{"enc_b64": b64(enc), "ciphertext_b64": b64(ct)}})
		if i == 1 {
			cases = append(cases, vcase{ID: "hpke/open/other-aad", Op: "hpke.open",
				In:    map[string]any{"key": "r1", "enc_b64": b64(enc), "info_b64": b64(shape.info), "aad_b64": b64([]byte("x")), "ciphertext_b64": b64(ct)},
				Error: "open_failed"})
		}
	}
	for i := range 3 {
		_, k, _ := hpke.GenerateKeyPair()
		raw, _ := k.Bytes()
		pub, _ := k.PublicKey()
		cases = append(cases, vcase{ID: fmt.Sprintf("hpke/public-from-private/%d", i), Op: "hpke.public_from_private",
			In: map[string]any{"private_key_b64": b64(raw)}, Out: map[string]any{"public_key_b64": b64(pub.Bytes())}})
	}
	// RFC 9180 §7.1.4: forgeries under the all-zero secret must not open, and
	// a low-order public key must not be sealed to.
	info, aad, chosen := []byte("thehappie-id/v1/key-delivery"), []byte(`["thehappie-id/key-delivery",1]`), bytes.Repeat([]byte{0x66}, 32)
	enc, dh := realDH(t, pk)
	control := forge.Seal(dh, enc, pk.Bytes(), info, aad, chosen)
	if got, err := hpke.Open(sk, enc, info, aad, control); err != nil || !bytes.Equal(got, chosen) {
		t.Fatalf("the forger's control does not open: %v", err)
	}
	cases = append(cases, vcase{ID: "hpke/open/forger-control", Op: "hpke.open",
		In:  map[string]any{"key": "r1", "enc_b64": b64(enc), "info_b64": b64(info), "aad_b64": b64(aad), "ciphertext_b64": b64(control)},
		Out: map[string]any{"plaintext_b64": b64(chosen)}})
	for _, lo := range forge.LowOrder {
		forged := forge.Seal(make([]byte, 32), lo.Point, pk.Bytes(), info, aad, chosen)
		if _, err := hpke.Open(sk, lo.Point, info, aad, forged); !errors.Is(err, hpke.ErrOpen) {
			t.Fatalf("%s: a forgery opened: %v", lo.Name, err)
		}
		cases = append(cases, vcase{ID: "hpke/open/forged/" + lo.Name, Op: "hpke.open",
			In:    map[string]any{"key": "r1", "enc_b64": b64(lo.Point), "info_b64": b64(info), "aad_b64": b64(aad), "ciphertext_b64": b64(forged), "forged_plaintext_b64": b64(chosen)},
			Error: "open_failed", Note: forgedNote})
		bad, err := hpke.ParsePublicKey(lo.Point)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := hpke.Seal(bad, info, aad, chosen); !errors.Is(err, hpke.ErrInvalidKey) {
			t.Fatalf("%s: sealed to a low-order key: %v", lo.Name, err)
		}
		cases = append(cases, vcase{ID: "hpke/seal/refuses/low-order-key/" + lo.Name, Op: "hpke.seal",
			In:    map[string]any{"public_key_b64": b64(lo.Point), "info_b64": b64(info), "aad_b64": b64(aad), "plaintext_b64": b64(chosen)},
			Error: "invalid_key"})
	}
	write(t, dir, "hpke-go.json", "hpke", "Fresh HPKE seals by Go's crypto/hpke through the kit, for the TypeScript implementation to open, with forgeries under the all-zero secret that must not open and low-order keys that must not be sealed to.", keys, cases)
}

func writeAccount(t *testing.T, dir string) {
	p := wappie.Account()
	params := account.KDFParams{Alg: "argon2id", M: 16, T: 2, P: 1}
	salt := bytes.Repeat([]byte{0x5a}, 16)
	var cases []vcase
	var wrapKey []byte
	for i, pw := range []string{"senha do kit", "", "p\u00e4ssw\u00f6rd \U0001f511", strings.Repeat("\u00e7", 300)} {
		d, err := account.Derive(p, pw, salt, params)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			wrapKey = d.Wrap
		}
		cases = append(cases, vcase{ID: fmt.Sprintf("account/derive/%d", i), Op: "account.derive",
			In:  map[string]any{"password": pw, "salt_b64": b64(salt), "params": params},
			Out: map[string]any{"auth_key": d.AuthKey, "auth_b64": b64(d.Auth), "wrap_b64": b64(d.Wrap)}})
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	for i, email := range []string{"ana@example.com", " \u0130stanbul@EXAMPLE.com\ufeff", "\u039f\u0394\u03a5\u03a3\u03a3\u0395\u03a5\u03a3@x.gr"} {
		aad := wappie.AccountWrapAAD(email)
		blob, err := account.Wrap(p, wrapKey, key, aad)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, vcase{ID: fmt.Sprintf("account/wrap-aad/%d", i), Op: "account.wrap_aad", In: map[string]any{"email": email}, Out: map[string]any{"aad_b64": b64(aad)}})
		cases = append(cases, vcase{ID: fmt.Sprintf("account/wrap/%d", i), Op: "account.wrap",
			In:  map[string]any{"wrap_key_b64": b64(wrapKey), "private_key_b64": b64(key), "email": email, "nonce_b64": b64(blob[1:13])},
			Out: map[string]any{"blob_b64": b64(blob)}})
		cases = append(cases, vcase{ID: fmt.Sprintf("account/unwrap/%d/other-email", i), Op: "account.unwrap",
			In: map[string]any{"wrap_key_b64": b64(wrapKey), "blob_b64": b64(blob), "email": "bob@example.com"}, Error: "wrap", Reason: "wrong_key"})
	}
	for i := range 2 {
		code, err := account.NewRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
		cases = append(cases, vcase{ID: fmt.Sprintf("account/normalise/%d", i), Op: "account.normalise_recovery_code", In: map[string]any{"code": typed}, Out: map[string]any{"code": code}})
		cases = append(cases, vcase{ID: fmt.Sprintf("account/recovery-proof/%d", i), Op: "account.recovery_proof", In: map[string]any{"code": typed},
			Out: map[string]any{"proof": must[string](t)(account.RecoveryProof(p, typed))}})
		cases = append(cases, vcase{ID: fmt.Sprintf("account/recovery-key/%d", i), Op: "account.recovery_key", In: map[string]any{"code": code},
			Out: map[string]any{"key_b64": b64(must[[]byte](t)(account.RecoveryKey(p, code)))}})
	}
	// The Wappie profile has no bounds; these cases give it some, shaped like
	// the platform's policy (a salt of exactly 16 bytes), to pin the checks.
	bounds := &account.Bounds{Min: account.KDFParams{M: 8, T: 1, P: 1}, Max: account.KDFParams{M: 1024, T: 3, P: 1}, MaxCost: 2048, MinSaltLen: 16, MaxSaltLen: 16}
	bounded := p
	bounded.Bounds = bounds
	jsonBounds := map[string]any{"min": map[string]any{"m": 8, "t": 1, "p": 1}, "max": map[string]any{"m": 1024, "t": 3, "p": 1}, "max_cost": 2048, "min_salt_len": 16, "max_salt_len": 16}
	for _, b := range []struct {
		name   string
		salt   int
		params account.KDFParams
	}{
		{"salt-16", 16, params},
		{"refuses/salt-15", 15, params},
		{"refuses/salt-17", 17, params},
		{"refuses/salt-8", 8, params},
		{"refuses/m-2048", 16, account.KDFParams{Alg: "argon2id", M: 2048, T: 1, P: 1}},
		{"refuses/cost-3072", 16, account.KDFParams{Alg: "argon2id", M: 1024, T: 3, P: 1}},
	} {
		salt := bytes.Repeat([]byte{0x5b}, b.salt)
		c := vcase{ID: "account/derive/bounded/" + b.name, Op: "account.derive", In: map[string]any{"password": "senha do kit", "salt_b64": b64(salt), "params": b.params, "bounds": jsonBounds}}
		d, err := account.Derive(bounded, "senha do kit", salt, b.params)
		if strings.HasPrefix(b.name, "refuses/") {
			if !errors.Is(err, account.ErrOutOfBounds) {
				t.Fatalf("%s: %v", b.name, err)
			}
			c.Error, c.Reason = "kdf", "out_of_bounds"
		} else {
			if err != nil {
				t.Fatal(err)
			}
			c.Out = map[string]any{"auth_key": d.AuthKey, "auth_b64": b64(d.Auth), "wrap_b64": b64(d.Wrap)}
		}
		cases = append(cases, c)
	}
	write(t, dir, "account-go.json", "account", "Fresh derivations and wraps by the kit's Go account scheme with the Wappie profile, and derivations refused by KDF and salt bounds, for the TypeScript tests.", nil, cases)
}

func writePasskey(t *testing.T, dir string) {
	p := wappie.Passkey()
	var cases []vcase
	key, prf := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	for i, rp := range []string{"wappie.thehappie.co", "localhost"} {
		user, cred := uuid.NewString(), "Y3JlZGVudGlhbC0"+fmt.Sprint(i)
		aad := must[[]byte](t)(wappie.PasskeyAAD(rp, user, cred))
		env, err := passkey.Wrap(p, key, prf, rp, aad)
		if err != nil {
			t.Fatal(err)
		}
		salt := passkey.PRFSalt(p, rp)
		in := map[string]any{"rp_id": rp, "user_id": user, "credential_id": cred}
		cases = append(cases,
			vcase{ID: fmt.Sprintf("passkey/prf-salt/%d", i), Op: "passkey.prf_salt", In: map[string]any{"rp_id": rp}, Out: map[string]any{"salt_b64": b64(salt[:])}},
			vcase{ID: fmt.Sprintf("passkey/aad/%d", i), Op: "passkey.aad", In: in, Out: map[string]any{"aad_b64": b64(aad)}},
			vcase{ID: fmt.Sprintf("passkey/key/%d", i), Op: "passkey.key", In: map[string]any{"prf_b64": b64(prf), "rp_id": rp, "user_id": user, "credential_id": cred},
				Out: map[string]any{"key_b64": b64(must[[]byte](t)(passkey.Key(p, prf, rp)))}},
			vcase{ID: fmt.Sprintf("passkey/wrap/%d", i), Op: "passkey.wrap",
				In:  map[string]any{"private_key_b64": b64(key), "prf_b64": b64(prf), "rp_id": rp, "user_id": user, "credential_id": cred, "nonce_b64": b64(env[1:13])},
				Out: map[string]any{"envelope_b64": b64(env)}},
			vcase{ID: fmt.Sprintf("passkey/unwrap/%d/other-credential", i), Op: "passkey.unwrap",
				In: map[string]any{"envelope_b64": b64(env), "prf_b64": b64(prf), "rp_id": rp, "user_id": user, "credential_id": cred + "x"}, Error: "open_failed"},
		)
	}
	// Bindings that have no JSON text: a string that is not Unicode, given as
	// WTF-8 (in Go, invalid UTF-8; in TypeScript, a lone surrogate). The AAD
	// is refused rather than bound loosely. And a wrap bound to nothing.
	for _, r := range []struct {
		name, field string
		wtf8        []byte
	}{
		{"lone-high-surrogate-user", "user_id", []byte("user-\xed\xa0\x80")},
		{"lone-low-surrogate-credential", "credential_id", []byte("\xed\xb0\x80cred")},
	} {
		in := map[string]any{"rp_id": "wappie.thehappie.co", "user_id": "u", "credential_id": "c"}
		delete(in, r.field)
		in[r.field+"_wtf8_b64"] = b64(r.wtf8)
		rp, user, cred := "wappie.thehappie.co", "u", "c"
		if r.field == "user_id" {
			user = string(r.wtf8)
		} else {
			cred = string(r.wtf8)
		}
		if _, err := wappie.PasskeyAAD(rp, user, cred); !errors.Is(err, jcs.ErrUnsupported) {
			t.Fatalf("%s: %v", r.name, err)
		}
		cases = append(cases, vcase{ID: "passkey/aad/refuses/" + r.name, Op: "passkey.aad", In: in, Error: "jcs"})
	}
	env, err := passkey.Wrap(p, key, prf, "localhost", []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passkey.Wrap(p, key, prf, "localhost", nil); !errors.Is(err, passkey.ErrBadAAD) {
		t.Fatal(err)
	}
	if _, err := passkey.Unwrap(p, env, prf, "localhost", nil); !errors.Is(err, passkey.ErrBadAAD) {
		t.Fatal(err)
	}
	cases = append(cases,
		vcase{ID: "passkey/wrap/refuses/empty-aad", Op: "passkey.wrap",
			In: map[string]any{"private_key_b64": b64(key), "prf_b64": b64(prf), "rp_id": "localhost", "aad_b64": "", "nonce_b64": b64(make([]byte, 12))}, Error: "bad_aad"},
		vcase{ID: "passkey/unwrap/refuses/empty-aad", Op: "passkey.unwrap",
			In: map[string]any{"envelope_b64": b64(env), "prf_b64": b64(prf), "rp_id": "localhost", "aad_b64": ""}, Error: "bad_aad"},
	)
	write(t, dir, "passkey-go.json", "passkey", "Fresh passkey wraps by the kit's Go with the Wappie profile, for the TypeScript tests, with bindings that must be refused.", nil, cases)
}

func writeRequestHMAC(t *testing.T, dir string) {
	s := wappie.MCPHMAC()
	var cases []vcase
	for i, c := range []struct{ secret, method, target string }{
		{uuid.NewString(), "post", "/internal/requests/x/prepare"}, {"segredo-\u00e7\u00e3o-\U0001f511", "GET", "/v1/mcp/enclave/cimd?url=a%2Fb"}, {"", "DELETE", "/"},
	} {
		body := []byte(uuid.NewString())
		nonce := strings.Repeat(string(rune('A'+i)), 22)
		cases = append(cases, vcase{ID: fmt.Sprintf("reqhmac/signature/%d", i), Op: "reqhmac.signature",
			In: map[string]any{"secret": c.secret, "direction": wappie.DirectionToGo, "sender": "enclave", "method": c.method, "target": c.target,
				"timestamp": "1790300000", "nonce": nonce, "body_b64": b64(body)},
			Out: map[string]any{"signature": s.Signature(c.secret, wappie.DirectionToGo, "enclave", c.method, c.target, "1790300000", nonce, body),
				"canonical": s.Canonical(wappie.DirectionToGo, "enclave", c.method, c.target, "1790300000", nonce, body)}})
	}
	write(t, dir, "reqhmac-go.json", "reqhmac", "Signatures by the kit's Go with Wappie's scheme, for the TypeScript tests.", nil, cases)
}

func writeJCS(t *testing.T, dir string) {
	var cases []vcase
	for i, v := range []any{
		map[string]any{"z": []any{1, "two", nil, true}, "a": map[string]any{"\U0001f600": 1, "\ue000": 2, "<&>": "\u2028"}},
		[]any{"wappie/passkey-vault", 1, "wappie.thehappie.co", "a\"b\\c\x01", "\u2028\u00e9"},
		map[string]any{"max": int64(1<<53 - 1), "min": int64(-(1<<53 - 1)), "ctl": "\x00\x1f\x7f"},
	} {
		text, err := json.Marshal(v) // Go's own JSON: escapes differently, sorts by bytes
		if err != nil {
			t.Fatal(err)
		}
		out, err := jcs.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, vcase{ID: fmt.Sprintf("jcs/canonical/%d", i), Op: "jcs.canonical", In: map[string]any{"json": string(text)}, Out: map[string]any{"jcs": string(out)}})
	}
	ns := uuid.New()
	for i, name := range [][]byte{nil, []byte("a\u00e7\u00e3o"), bytes.Repeat([]byte{9}, 70)} {
		cases = append(cases, vcase{ID: fmt.Sprintf("bytes/uuid-v5/%d", i), Op: "bytes.uuid_v5",
			In: map[string]any{"namespace": ns.String(), "name_b64": b64(name)}, Out: map[string]any{"uuid": seal.Row(ns, name).String()}})
	}
	write(t, dir, "jcs-go.json", "bytes+jcs", "Canonical JSON and UUIDv5 by the kit's Go, for the TypeScript tests. Each input is Go's encoding/json text of the value.", nil, cases)
}
