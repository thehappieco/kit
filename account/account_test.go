package account_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/wappie"
)

var cheap = account.KDFParams{Alg: "argon2id", M: 8, T: 1, P: 1}

func errorCode(err error) (code, reason string) {
	var e *account.Error
	if errors.As(err, &e) {
		return e.Code, e.Reason
	}
	if err == nil {
		return "", ""
	}
	return "unclassified", err.Error()
}

// TestWappieAccountVectors reproduces every case Wappie's browser client
// wrote (golden/account-ts.json): the Go scheme is new code, and this is what
// makes it the same scheme.
func TestWappieAccountVectors(t *testing.T) {
	p := wappie.Account()
	for _, c := range vectest.Cases(t, "wappie/golden/account-ts.json", "kit/account-ts.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				Password string            `json:"password"`
				Salt     string            `json:"salt_b64"`
				Params   account.KDFParams `json:"params"`
				Bounds   *struct {
					Min        account.KDFParams `json:"min"`
					Max        account.KDFParams `json:"max"`
					MaxCost    uint64            `json:"max_cost"`
					MinSaltLen int               `json:"min_salt_len"`
					MaxSaltLen int               `json:"max_salt_len"`
				} `json:"bounds"`
				Email      string `json:"email"`
				WrapKey    string `json:"wrap_key_b64"`
				PrivateKey string `json:"private_key_b64"`
				Nonce      string `json:"nonce_b64"`
				Blob       string `json:"blob_b64"`
				Random     string `json:"random_b64"`
				Code       string `json:"code"`
			}
			var out struct {
				Params     account.KDFParams `json:"params"`
				AuthKey    string            `json:"auth_key"`
				Auth       string            `json:"auth_b64"`
				Wrap       string            `json:"wrap_b64"`
				AAD        string            `json:"aad_b64"`
				Blob       string            `json:"blob_b64"`
				PrivateKey string            `json:"private_key_b64"`
				Stale      bool              `json:"stale"`
				Code       string            `json:"code"`
				Key        string            `json:"key_b64"`
				Proof      string            `json:"proof"`
			}
			vectest.Decode(t, c.In, &in)
			if c.Error == "" {
				vectest.Decode(t, c.Out, &out)
			}
			b := func(s string) []byte { return vectest.B64(t, s) }
			wantErr := func(err error) {
				t.Helper()
				if code, reason := errorCode(err); code != c.Error || reason != c.Reason {
					t.Errorf("error %s/%s, want %s/%s", code, reason, c.Error, c.Reason)
				}
			}
			switch c.Op {
			case "account.default_kdf_params":
				if account.DefaultKDFParams != out.Params {
					t.Errorf("%+v", account.DefaultKDFParams)
				}
			case "account.derive":
				p := p
				if in.Bounds != nil {
					// Wappie's profile has no bounds; these cases give it some.
					p.Bounds = &account.Bounds{Min: in.Bounds.Min, Max: in.Bounds.Max, MaxCost: in.Bounds.MaxCost, MinSaltLen: in.Bounds.MinSaltLen, MaxSaltLen: in.Bounds.MaxSaltLen}
				}
				d, err := account.Derive(p, in.Password, b(in.Salt), in.Params)
				if c.Error != "" {
					wantErr(err)
					return
				}
				if err != nil || d.AuthKey != out.AuthKey || !bytes.Equal(d.Auth, b(out.Auth)) || !bytes.Equal(d.Wrap, b(out.Wrap)) {
					t.Errorf("derive: %v", err)
				}
				// The bytes form: the same text as bytes, and DeriveBytes
				// makes no string at all; Clear zeroes every byte.
				if string(d.AuthText) != out.AuthKey {
					t.Error("AuthText is not the auth key")
				}
				e, err := account.DeriveBytes(p, in.Password, b(in.Salt), in.Params)
				if err != nil || e.AuthKey != "" || string(e.AuthText) != out.AuthKey || !bytes.Equal(e.Auth, d.Auth) || !bytes.Equal(e.Wrap, d.Wrap) {
					t.Errorf("DeriveBytes: %v", err)
				}
				e.Clear()
				if !allZero(e.AuthText) || !allZero(e.Auth) || !allZero(e.Wrap) {
					t.Error("Clear left bytes")
				}
			case "account.wrap_aad":
				if got := wappie.AccountWrapAAD(in.Email); !bytes.Equal(got, b(out.AAD)) {
					t.Errorf("aad %q, want %q", got, b(out.AAD))
				}
			case "account.wrap":
				aad := wappie.AccountWrapAAD(in.Email)
				got, err := account.WrapWithNonce(p, b(in.WrapKey), b(in.Nonce), b(in.PrivateKey), aad)
				if err != nil || !bytes.Equal(got, b(out.Blob)) {
					t.Errorf("wrap %x: %v", got, err)
				}
				back, stale, err := account.Unwrap(p, b(in.WrapKey), b(out.Blob), aad)
				if err != nil || stale || !bytes.Equal(back, b(in.PrivateKey)) {
					t.Errorf("unwrap: %v", err)
				}
			case "account.unwrap":
				got, stale, err := account.Unwrap(p, b(in.WrapKey), b(in.Blob), wappie.AccountWrapAAD(in.Email))
				if c.Error != "" {
					wantErr(err)
				} else if err != nil || stale != out.Stale || !bytes.Equal(got, b(out.PrivateKey)) {
					t.Errorf("unwrap: stale %v %v", stale, err)
				}
			case "account.recovery_code":
				if got := account.RecoveryCodeFrom(b(in.Random)); got != out.Code {
					t.Errorf("code %s, want %s", got, out.Code)
				}
			case "account.normalise_recovery_code":
				got, err := account.NormaliseRecoveryCode(in.Code)
				if c.Error != "" {
					wantErr(err)
				} else if err != nil || got != out.Code {
					t.Errorf("normalised %q, want %q: %v", got, out.Code, err)
				}
			case "account.recovery_key":
				if got, err := account.RecoveryKey(p, in.Code); err != nil || !bytes.Equal(got, b(out.Key)) {
					t.Errorf("key: %v", err)
				}
			case "account.recovery_proof":
				got, err := account.RecoveryProof(p, in.Code)
				if c.Error != "" {
					wantErr(err)
				} else if err != nil || got != out.Proof {
					t.Errorf("proof %s: %v", got, err)
				}
			default:
				vectest.Unhandled(t, c)
			}
		})
	}
}

func TestRoundTrips(t *testing.T) {
	p := wappie.Account()
	salt := bytes.Repeat([]byte{1}, 16)
	d, err := account.Derive(p, "senha correta", salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.AuthKey) != 44 || bytes.Equal(d.Auth, d.Wrap) {
		t.Fatalf("auth key %q", d.AuthKey)
	}
	key := bytes.Repeat([]byte{9}, 32)
	blob, err := account.Wrap(p, d.Wrap, key, wappie.AccountWrapAAD("ana@example.com"))
	if err != nil || len(blob) != 61 || blob[0] != 0x02 {
		t.Fatalf("blob %x: %v", blob, err)
	}
	if back, stale, err := account.Unwrap(p, d.Wrap, blob, wappie.AccountWrapAAD(" ANA@example.com ")); err != nil || stale || !bytes.Equal(back, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, _, err := account.Unwrap(p, d.Wrap, blob, wappie.AccountWrapAAD("bob@example.com")); !errors.Is(err, account.ErrWrongKey) {
		t.Fatalf("other email: %v", err)
	}
	code, err := account.NewRecoveryCode()
	if err != nil || len(code) != 35 || strings.Count(code, "-") != 5 {
		t.Fatalf("code %q: %v", code, err)
	}
	if n, err := account.NormaliseRecoveryCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))); err != nil || n != code {
		t.Fatalf("normalise: %q %v", n, err)
	}
	other, _ := account.NewRecoveryCode()
	if code == other {
		t.Fatal("two recovery codes were equal")
	}
	if _, err := account.Wrap(p, d.Wrap[:31], key, nil); !errors.Is(err, account.ErrBadKey) {
		t.Fatalf("short wrap key: %v", err)
	}
}

// A profile shaped like the platform's draft (docs/design/2026-09-30/id-protocol-draft.md
// in thehappieco/platform): its own labels, a two-byte header, bounds,
// base64url text, no legacy form. Proves the parameters reach every step;
// the platform's real profile arrives with its vectors.
func TestAnotherProfile(t *testing.T) {
	p := account.Profile{
		AuthLabel: "test/v1/password/auth", WrapLabel: "test/v1/password/wrap",
		RecoveryKeyLabel: "test/v1/recovery/wrap", RecoveryProofLabel: "test/v1/recovery/auth",
		WrapHeader: []byte{0x01, 0x01},
		Prepare: func(pw string) ([]byte, error) {
			if len(pw) < 12 {
				return nil, errors.New("too short")
			}
			return []byte(pw), nil
		},
		Bounds:   &account.Bounds{Min: account.KDFParams{M: 8, T: 1, P: 1}, Max: account.KDFParams{M: 1024, T: 3, P: 1}, MaxCost: 2048},
		Encoding: base64.RawURLEncoding,
	}
	salt := bytes.Repeat([]byte{2}, 16)
	if _, err := account.Derive(p, "short", salt, cheap); !errors.Is(err, account.ErrPassword) {
		t.Errorf("a password the profile refuses: %v", err)
	}
	for _, params := range []account.KDFParams{{Alg: "argon2id", M: 4096, T: 1, P: 1}, {Alg: "argon2id", M: 1024, T: 3, P: 1}, {Alg: "argon2id", M: 8, T: 1, P: 2}} {
		if _, err := account.Derive(p, "long enough password", salt, params); !errors.Is(err, account.ErrOutOfBounds) {
			t.Errorf("%+v: %v", params, err)
		}
	}
	// The platform's policy fixes the salt at 16 bytes. Without the bound,
	// Argon2id would take any salt of 8 bytes or more.
	p.Bounds.MinSaltLen, p.Bounds.MaxSaltLen = 16, 16
	for _, n := range []int{8, 15, 17, 32} {
		if _, err := account.Derive(p, "long enough password", bytes.Repeat([]byte{2}, n), cheap); !errors.Is(err, account.ErrOutOfBounds) {
			t.Errorf("a %d-byte salt: %v", n, err)
		}
		if err := p.CheckSalt(make([]byte, n)); !errors.Is(err, account.ErrOutOfBounds) {
			t.Errorf("CheckSalt, %d bytes: %v", n, err)
		}
	}
	d, err := account.Derive(p, "long enough password", salt, cheap)
	if err != nil || len(d.AuthKey) != 43 {
		t.Fatalf("%q %v", d.AuthKey, err)
	}
	w, err := account.Derive(wappie.Account(), "long enough password", salt, cheap)
	if err != nil || bytes.Equal(w.Auth, d.Auth) {
		t.Fatal("two profiles' labels gave the same auth key")
	}
	root := bytes.Repeat([]byte{3}, 32)
	aad := []byte(`["test/root-wrap",1,"password","sub",1]`)
	blob, err := account.Wrap(p, d.Wrap, root, aad)
	if err != nil || len(blob) != 62 || !bytes.HasPrefix(blob, []byte{1, 1}) {
		t.Fatalf("blob %x: %v", blob, err)
	}
	if back, stale, err := account.Unwrap(p, d.Wrap, blob, aad); err != nil || stale || !bytes.Equal(back, root) {
		t.Fatalf("unwrap: %v", err)
	}
	headerless := blob[2:]
	if _, _, err := account.Unwrap(p, d.Wrap, headerless, aad); !errors.Is(err, account.ErrWrongKey) {
		t.Errorf("no legacy form: %v", err)
	}
	if _, _, err := account.Unwrap(p, d.Wrap, blob[:20], aad); !errors.Is(err, account.ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	proof, err := account.RecoveryProof(p, strings.Repeat("A", 30))
	if err != nil || len(proof) != 43 {
		t.Fatalf("proof %q: %v", proof, err)
	}
	p.NormaliseRecovery = func(code string) (string, error) { return code, nil }
	k1, _ := account.RecoveryKey(p, "x")
	k2, _ := account.RecoveryKey(wappie.Account(), strings.Repeat("A", 30))
	if len(k1) != 32 || bytes.Equal(k1, k2) {
		t.Fatal("custom normalisation was not used")
	}
}

// DerivePrepared is Derive without the profile's preparation: the same
// checks, in the same order, and the same keys from the same bytes. The
// prepared bytes stay the caller's.
func TestDerivePrepared(t *testing.T) {
	p := wappie.Account()
	salt := bytes.Repeat([]byte{4}, 16)
	want, err := account.Derive(p, "senha correta", salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	prepared := []byte("senha correta")
	got, err := account.DerivePrepared(p, prepared, salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthKey != want.AuthKey || !bytes.Equal(got.Auth, want.Auth) || !bytes.Equal(got.Wrap, want.Wrap) {
		t.Fatal("DerivePrepared and Derive differ on the same bytes")
	}
	if string(prepared) != "senha correta" {
		t.Fatal("DerivePrepared cleared the caller's bytes")
	}

	// A profile that prepares: Derive(password) is DerivePrepared(Prepare(password)),
	// and DerivePrepared does not prepare again.
	q := p
	q.Prepare = func(pw string) ([]byte, error) { return []byte(strings.ToUpper(pw)), nil }
	viaDerive, err := account.Derive(q, "senha correta", salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	viaPrepared, err := account.DerivePrepared(q, []byte("SENHA CORRETA"), salt, cheap)
	if err != nil || viaPrepared.AuthKey != viaDerive.AuthKey {
		t.Fatalf("DerivePrepared of the prepared bytes is not Derive: %v", err)
	}
	if again, _ := account.DerivePrepared(q, []byte("senha correta"), salt, cheap); again.AuthKey == viaDerive.AuthKey {
		t.Fatal("DerivePrepared ran the profile's preparation")
	}

	// The same refusals as Derive, before anything is derived.
	q.Bounds = &account.Bounds{Min: account.KDFParams{M: 8, T: 1, P: 1}, Max: account.KDFParams{M: 1024, T: 3, P: 1}, MaxCost: 2048, MinSaltLen: 16, MaxSaltLen: 16}
	for _, c := range []struct {
		salt   []byte
		params account.KDFParams
		want   error
	}{
		{salt, account.KDFParams{Alg: "argon2i", M: 8, T: 1, P: 1}, account.ErrUnsupportedAlg},
		{salt, account.KDFParams{Alg: "argon2id", M: 2048, T: 1, P: 1}, account.ErrOutOfBounds},
		{salt[:15], cheap, account.ErrOutOfBounds},
	} {
		_, errDerive := account.Derive(q, "x", c.salt, c.params)
		_, errPrepared := account.DerivePrepared(q, []byte("x"), c.salt, c.params)
		if !errors.Is(errDerive, c.want) || !errors.Is(errPrepared, c.want) {
			t.Errorf("%+v, %d-byte salt: Derive %v, DerivePrepared %v, want %v", c.params, len(c.salt), errDerive, errPrepared, c.want)
		}
	}
	if _, err := account.DerivePrepared(p, []byte("x"), bytes.Repeat([]byte{4}, 7), cheap); !errors.Is(err, account.ErrKDFFailed) {
		t.Errorf("a 7-byte salt: %v", err)
	}
}

// DeriveBytes and DerivePreparedBytes are Derive and DerivePrepared without
// the deprecated string: the same keys and the same text, as bytes, the same
// refusals, and the caller's prepared bytes left as they were.
func TestDeriveBytes(t *testing.T) {
	p := wappie.Account()
	salt := bytes.Repeat([]byte{4}, 16)
	want, err := account.Derive(p, "senha correta", salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	prepared := []byte("senha correta")
	for name, derive := range map[string]func() (account.Derived, error){
		"DeriveBytes":         func() (account.Derived, error) { return account.DeriveBytes(p, "senha correta", salt, cheap) },
		"DerivePreparedBytes": func() (account.Derived, error) { return account.DerivePreparedBytes(p, prepared, salt, cheap) },
	} {
		got, err := derive()
		if err != nil {
			t.Fatal(err)
		}
		if got.AuthKey != "" || string(got.AuthText) != want.AuthKey || string(want.AuthText) != want.AuthKey || !bytes.Equal(got.Auth, want.Auth) || !bytes.Equal(got.Wrap, want.Wrap) {
			t.Errorf("%s differs from Derive, or made a string", name)
		}
		got.Clear()
		if !allZero(got.AuthText) || !allZero(got.Auth) || !allZero(got.Wrap) {
			t.Errorf("%s: Clear left bytes", name)
		}
	}
	if string(prepared) != "senha correta" {
		t.Fatal("DerivePreparedBytes cleared the caller's bytes")
	}
	q := p
	q.Bounds = &account.Bounds{Min: account.KDFParams{M: 8, T: 1, P: 1}, Max: account.KDFParams{M: 1024, T: 3, P: 1}, MinSaltLen: 16, MaxSaltLen: 16}
	if _, err := account.DeriveBytes(q, "x", salt[:15], cheap); !errors.Is(err, account.ErrOutOfBounds) {
		t.Errorf("DeriveBytes, a 15-byte salt: %v", err)
	}
	if _, err := account.DerivePreparedBytes(q, []byte("x"), salt, account.KDFParams{Alg: "argon2i", M: 8, T: 1, P: 1}); !errors.Is(err, account.ErrUnsupportedAlg) {
		t.Errorf("DerivePreparedBytes, argon2i: %v", err)
	}
	q.Prepare = func(string) ([]byte, error) { return nil, errors.New("no") }
	_, err = account.DeriveBytes(q, "x", salt, cheap)
	if code, _ := errorCode(err); code != "password" {
		t.Errorf("DeriveBytes, a refused password: %v", err)
	}
	var nothing *account.Derived
	nothing.Clear()
}

// With a profile that prepares, Derive and DeriveBytes hold the password as
// bytes only in what Prepare returns: they clear it, on Prepare's error path
// too, and make no copy of their own, so they allocate exactly what
// DerivePreparedBytes does on the same prepared bytes.
func TestDerivePasswordCopiesOnce(t *testing.T) {
	salt := bytes.Repeat([]byte{4}, 16)
	// Long enough that a copy cannot live on the stack.
	password := strings.Repeat("senha correta ", 64)
	buf := make([]byte, len(password))
	var seen []string
	var returned []byte
	q := wappie.Account()
	q.Prepare = func(pw string) ([]byte, error) {
		seen = append(seen, pw)
		returned = buf[:copy(buf, pw)]
		return returned, nil
	}
	for name, derive := range map[string]func(account.Profile, string, []byte, account.KDFParams) (account.Derived, error){
		"Derive":      account.Derive,
		"DeriveBytes": account.DeriveBytes,
	} {
		seen = seen[:0]
		d, err := derive(q, password, salt, cheap)
		if err != nil {
			t.Fatal(err)
		}
		d.Clear()
		if len(seen) != 1 || seen[0] != password {
			t.Fatalf("%s: Prepare saw %d passwords", name, len(seen))
		}
		if !allZero(returned) {
			t.Errorf("%s left what Prepare returned", name)
		}
	}

	// Prepare refuses, after writing part of the password: that is cleared.
	r := q
	r.Prepare = func(pw string) ([]byte, error) {
		returned = buf[:copy(buf, pw)]
		return returned, errors.New("no")
	}
	if _, err := account.DeriveBytes(r, password, salt, cheap); err == nil {
		t.Fatal("a refused password derived")
	}
	if !allZero(returned) {
		t.Error("DeriveBytes left what a refusing Prepare returned")
	}

	q.Prepare = func(pw string) ([]byte, error) { return buf[:copy(buf, pw)], nil }
	viaPassword := testing.AllocsPerRun(20, func() {
		d, err := account.DeriveBytes(q, password, salt, cheap)
		if err != nil {
			t.Fatal(err)
		}
		d.Clear()
	})
	prepared := []byte(password)
	viaPrepared := testing.AllocsPerRun(20, func() {
		d, err := account.DerivePreparedBytes(q, prepared, salt, cheap)
		if err != nil {
			t.Fatal(err)
		}
		d.Clear()
	})
	if viaPassword > viaPrepared {
		t.Errorf("DeriveBytes allocates %v times, DerivePreparedBytes %v: it copies the password besides Prepare", viaPassword, viaPrepared)
	}
}

// RecoveryProofBytes is RecoveryProof before its text encoding: the bytes
// are the decoded proof, the proof is not the key, and a code of the wrong
// length is refused alike.
func TestRecoveryProofBytes(t *testing.T) {
	p := wappie.Account()
	code := "01234-56789-ABCDE-FGHJK-MNPQR-STVWX"
	raw, err := account.RecoveryProofBytes(p, code)
	if err != nil || len(raw) != account.KeyLen {
		t.Fatal(err)
	}
	text, err := account.RecoveryProof(p, code)
	if err != nil || text != base64.StdEncoding.EncodeToString(raw) {
		t.Fatalf("RecoveryProof is not RecoveryProofBytes encoded: %v", err)
	}
	key, err := account.RecoveryKey(p, code)
	if err != nil || bytes.Equal(key, raw) {
		t.Fatal("the key is the proof")
	}
	if _, err := account.RecoveryProofBytes(p, "01234"); !errors.Is(err, account.ErrRecoveryLength) {
		t.Fatalf("a short code: %v", err)
	}
}

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }
