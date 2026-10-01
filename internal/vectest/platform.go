package vectest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
	"github.com/thehappieco/kit/vectors"
)

// PlatformFormat is the platform's own vector format (vectors/README.md,
// "The platform's format"), in which vectors/platform/id-v1 is written.
const PlatformFormat = "thehappie-id/vectors"

// PlatformDir is where the platform's id-v1 files are in vectors.FS.
const PlatformDir = "platform/id-v1"

// PlatformCase is one case of a platform vector file: a name, and the error
// name it must be refused with ("" for a case with outputs).
type PlatformCase interface {
	CaseName() string
	CaseError() string
}

// Platform reads vectors/platform/id-v1/<kind>.json strictly: a member the
// case type does not declare fails the test (a member a runner ignores would
// test nothing), and so do a wrong header, a repeated or empty name, and a
// file without both good and must-fail cases.
func Platform[C PlatformCase](t testing.TB, kind string) []C {
	t.Helper()
	path := PlatformDir + "/" + kind + ".json"
	raw, err := fs.ReadFile(vectors.FS, path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Kind    string `json:"kind"`
		Cases   []C    `json:"cases"`
	}
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if f.Format != PlatformFormat || f.Version != 1 || f.Kind != kind {
		t.Fatalf("%s: header %q %d %q", path, f.Format, f.Version, f.Kind)
	}
	names := map[string]bool{}
	good, bad := 0, 0
	for _, c := range f.Cases {
		if c.CaseName() == "" || names[c.CaseName()] {
			t.Fatalf("%s: an empty or repeated case name", path)
		}
		names[c.CaseName()] = true
		if c.CaseError() == "" {
			good++
		} else {
			bad++
		}
	}
	if good == 0 || bad == 0 {
		t.Fatalf("%s: %d good and %d must-fail cases; every kind has both", path, good, bad)
	}
	return f.Cases
}

// B64URL decodes strict unpadded base64url of any length: a vector's inputs
// may be deliberately of the wrong length, never of the wrong spelling.
func B64URL(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		t.Fatal("a vector value is not strict base64url")
	}
	return b
}

// The case types of the platform's kinds, member for member as the
// platform's generator declares them.

// PasswordProfileCase is a password-profile case. A password that is not
// Unicode is given twice: PasswordUTF16, the code units TypeScript builds
// its string from, and PasswordUTF8, the bytes Go builds its string from.
type PasswordProfileCase struct {
	Name          string   `json:"name"`
	Password      *string  `json:"password,omitempty"`
	PasswordUTF16 []uint16 `json:"password_utf16,omitempty"`
	PasswordUTF8  string   `json:"password_utf8_b64url,omitempty"`
	New           bool     `json:"new"`
	Prepared      *string  `json:"prepared_b64url,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// KDFCase is a kdf case.
type KDFCase struct {
	Name     string       `json:"name"`
	Prepared string       `json:"prepared_b64url"`
	Salt     string       `json:"salt"`
	KDF      platform.KDF `json:"kdf"`
	KAuth    string       `json:"k_auth,omitempty"`
	KWrap    string       `json:"k_wrap,omitempty"`
	AuthKey  string       `json:"auth_key,omitempty"`
	Error    string       `json:"error,omitempty"`
}

// RootWrapCase is a root-wrap case.
type RootWrapCase struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Key          string `json:"key"`
	Nonce        string `json:"nonce,omitempty"`
	Root         string `json:"root,omitempty"`
	Sub          string `json:"sub"`
	Epoch        int    `json:"epoch"`
	RPID         string `json:"rp_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	AAD          string `json:"aad,omitempty"`
	Wrap         string `json:"wrap"`
	Error        string `json:"error,omitempty"`
}

// RecoveryCodeCase is a recovery-code case: exactly one of Bytes and Input.
type RecoveryCodeCase struct {
	Name         string  `json:"name"`
	Bytes        string  `json:"bytes,omitempty"`
	Input        *string `json:"input,omitempty"`
	Display      string  `json:"display,omitempty"`
	Canonical    string  `json:"canonical,omitempty"`
	KRWrap       string  `json:"k_rwrap,omitempty"`
	RecoveryAuth string  `json:"recovery_auth,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// ProductKeyCase is a product-key case.
type ProductKeyCase struct {
	Name         string `json:"name"`
	Root         string `json:"root"`
	Product      string `json:"product"`
	Epoch        int    `json:"epoch"`
	SK           string `json:"sk,omitempty"`
	Pub          string `json:"pub,omitempty"`
	ProductKeyID string `json:"product_key_id,omitempty"`
	Error        string `json:"error,omitempty"`
}

// VerifierCase is a verifier case: exactly one of KAuth and RProof.
type VerifierCase struct {
	Name             string `json:"name"`
	Sub              string `json:"sub"`
	KAuth            string `json:"k_auth,omitempty"`
	RProof           string `json:"r_proof,omitempty"`
	AuthVerifier     string `json:"auth_verifier,omitempty"`
	RecoveryVerifier string `json:"recovery_verifier,omitempty"`
	Error            string `json:"error,omitempty"`
}

// EmailCase is an email case.
type EmailCase struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	EmailNorm string `json:"email_norm,omitempty"`
	Error     string `json:"error,omitempty"`
}

// KeyBundleCase is a key-bundle case: exactly one of Bundle (the JSON value,
// as its bytes appear in the file) and BundleText (the exact text of a
// file), and exactly one of Password and RecoveryCode.
type KeyBundleCase struct {
	Name         string          `json:"name"`
	Password     *string         `json:"password,omitempty"`
	RecoveryCode *string         `json:"recovery_code,omitempty"`
	Bundle       json.RawMessage `json:"bundle,omitempty"`
	BundleText   *string         `json:"bundle_text,omitempty"`
	Root         string          `json:"root,omitempty"`
	Error        string          `json:"error,omitempty"`
}

func (c PasswordProfileCase) CaseName() string { return c.Name }
func (c KDFCase) CaseName() string             { return c.Name }
func (c RootWrapCase) CaseName() string        { return c.Name }
func (c RecoveryCodeCase) CaseName() string    { return c.Name }
func (c ProductKeyCase) CaseName() string      { return c.Name }
func (c VerifierCase) CaseName() string        { return c.Name }
func (c EmailCase) CaseName() string           { return c.Name }
func (c KeyBundleCase) CaseName() string       { return c.Name }

func (c PasswordProfileCase) CaseError() string { return c.Error }
func (c KDFCase) CaseError() string             { return c.Error }
func (c RootWrapCase) CaseError() string        { return c.Error }
func (c RecoveryCodeCase) CaseError() string    { return c.Error }
func (c ProductKeyCase) CaseError() string      { return c.Error }
func (c VerifierCase) CaseError() string        { return c.Error }
func (c EmailCase) CaseError() string           { return c.Error }
func (c KeyBundleCase) CaseError() string       { return c.Error }
