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

// PlatformCase is one case of a platform vector file: its id, and the error
// name it must be refused with ("" for a case with outputs). The id is the
// case's name, or op "/" name for a case that carries an op (KeyDeliveryCase,
// PasskeyCase): key-delivery.json gives five names to two cases each, one
// with op "open" and one with op "seal".
type PlatformCase interface {
	CaseName() string
	CaseError() string
}

// Platform reads vectors/platform/id-v1/<kind>.json strictly: a member the
// case type does not declare fails the test (a member a runner ignores would
// test nothing), and so do a wrong header, a repeated or empty case id, and
// a file without both good and must-fail cases.
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
			t.Fatalf("%s: an empty or repeated case id", path)
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

// KeyDeliveryCase is a key-delivery case. A good case has no Op and every
// member; a must-fail case's Op says which side refuses it: "open" (the
// relying party's inputs: AKDPriv, AKDSealed and the binding) or "seal" (the
// id. page's: Root, Product, Epoch, AKDPub and the binding). EphPriv, the
// sender's ephemeral key of a good case, is what lets a test replay its
// AKDSealed byte for byte. A binary member the generator left empty is
// absent and reads as "".
type KeyDeliveryCase struct {
	Name          string `json:"name"`
	Op            string `json:"op,omitempty"`
	Root          string `json:"root,omitempty"`
	Product       string `json:"product,omitempty"`
	Epoch         int    `json:"epoch,omitempty"`
	Iss           string `json:"iss"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Sub           string `json:"sub"`
	ProductKeyID  string `json:"product_key_id"`
	PKP           string `json:"pk_p"`
	CodeChallenge string `json:"code_challenge"`
	Nonce         string `json:"nonce"`
	AKDPriv       string `json:"akd_priv,omitempty"`
	AKDPub        string `json:"akd_pub,omitempty"`
	EphPriv       string `json:"eph_priv,omitempty"`
	AAD           string `json:"aad,omitempty"`
	AKDSealed     string `json:"akd_sealed,omitempty"`
	Error         string `json:"error,omitempty"`
}

// The ops of a key-delivery must-fail case.
const (
	KeyDeliveryOpOpen = "open"
	KeyDeliveryOpSeal = "seal"
)

// PKCECase is a pkce case.
type PKCECase struct {
	Name          string `json:"name"`
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	Error         string `json:"error,omitempty"`
}

// PasskeyCase is a passkey case (SPEC section 11.16). A good case has no Op
// and every member but Error. A must-fail case's Op says which step refuses
// it, always with "wrap": "salt" (RPID alone), "key" (RPID and PRF) or
// "open" (the binding, PRF and Wrap). RPID and PRF are pointers because an
// empty relying party id and an empty PRF output are written as "", which
// must not read as a missing one: a runner fails a case without rp_id, and a
// good, key or open case without prf.
type PasskeyCase struct {
	Name         string  `json:"name"`
	Op           string  `json:"op,omitempty"`
	RPID         *string `json:"rp_id"`
	PRF          *string `json:"prf,omitempty"`
	Root         string  `json:"root,omitempty"`
	Sub          string  `json:"sub,omitempty"`
	Epoch        int     `json:"epoch,omitempty"`
	CredentialID string  `json:"credential_id,omitempty"`
	Nonce        string  `json:"nonce,omitempty"`
	PRFSalt      string  `json:"prf_salt,omitempty"`
	KPK          string  `json:"k_pk,omitempty"`
	AAD          string  `json:"aad,omitempty"`
	Wrap         string  `json:"wrap,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// The ops of a passkey must-fail case.
const (
	PasskeyOpSalt = "salt"
	PasskeyOpKey  = "key"
	PasskeyOpOpen = "open"
)

// ClientExtensionsCase is a client-extensions case (SPEC section 11.16): the
// exact JSON text of a credential's clientExtensionResults, carried as a
// JSON string so that a repeated member, a byte order mark or trailing data
// can be expressed, and the error "client_extensions" when it is refused. The
// text is a pointer so that a missing member fails rather than reads as the
// empty text, which is a case of its own.
type ClientExtensionsCase struct {
	Name                   string  `json:"name"`
	ClientExtensionResults *string `json:"client_extension_results"`
	Error                  string  `json:"error,omitempty"`
}

// RPIDEndsInNumberCase is an rp-id-ends-in-number case (SPEC section
// 11.16): a relying party id, the answer of the WHATWG URL Standard's "ends
// in a number checker" on it, and either the PRF salt of an id the profile
// accepts or the error "wrap". RPID is a pointer so that a missing member
// fails rather than reads as the empty id, and EndsInANumber so that a
// missing answer fails rather than reads as false.
type RPIDEndsInNumberCase struct {
	Name          string  `json:"name"`
	RPID          *string `json:"rp_id"`
	EndsInANumber *bool   `json:"ends_in_a_number"`
	PRFSalt       string  `json:"prf_salt,omitempty"`
	Error         string  `json:"error,omitempty"`
}

// CaseName is op "/" name for a case with an op, its name otherwise, and ""
// for a case without a name.
func (c KeyDeliveryCase) CaseName() string {
	if c.Name == "" || c.Op == "" {
		return c.Name
	}
	return c.Op + "/" + c.Name
}

func (c PasswordProfileCase) CaseName() string { return c.Name }
func (c KDFCase) CaseName() string             { return c.Name }
func (c RootWrapCase) CaseName() string        { return c.Name }
func (c RecoveryCodeCase) CaseName() string    { return c.Name }
func (c ProductKeyCase) CaseName() string      { return c.Name }
func (c VerifierCase) CaseName() string        { return c.Name }
func (c EmailCase) CaseName() string           { return c.Name }
func (c KeyBundleCase) CaseName() string       { return c.Name }
func (c PKCECase) CaseName() string            { return c.Name }

// CaseName is op "/" name for a case with an op, its name otherwise, and ""
// for a case without a name.
func (c PasskeyCase) CaseName() string {
	if c.Name == "" || c.Op == "" {
		return c.Name
	}
	return c.Op + "/" + c.Name
}

func (c ClientExtensionsCase) CaseName() string { return c.Name }
func (c RPIDEndsInNumberCase) CaseName() string { return c.Name }

func (c PasskeyCase) CaseError() string          { return c.Error }
func (c ClientExtensionsCase) CaseError() string { return c.Error }
func (c RPIDEndsInNumberCase) CaseError() string { return c.Error }

func (c PasswordProfileCase) CaseError() string { return c.Error }
func (c KDFCase) CaseError() string             { return c.Error }
func (c RootWrapCase) CaseError() string        { return c.Error }
func (c RecoveryCodeCase) CaseError() string    { return c.Error }
func (c ProductKeyCase) CaseError() string      { return c.Error }
func (c VerifierCase) CaseError() string        { return c.Error }
func (c EmailCase) CaseError() string           { return c.Error }
func (c KeyBundleCase) CaseError() string       { return c.Error }
func (c KeyDeliveryCase) CaseError() string     { return c.Error }
func (c PKCECase) CaseError() string            { return c.Error }
