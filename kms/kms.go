// Package kms defines how tier-2 data keys are made and unwrapped (the
// platform's decision 0003; SPEC section 14), without saying who does it.
//
// A Wrapper hands out fresh 32-byte data keys together with a wrapped copy
// that only the wrapper can turn back into the key, and only under the same
// encryption Context. The envelope of package thcseal stores the wrapped
// copy and never the key. Two providers implement it:
//
//   - awskms, for production: AWS KMS with a pinned key ARN and credentials
//     from the instance role only;
//   - localkek, for development and tests: a local key-encryption key,
//     which compiles only with the build tag kitdevkek.
//
// The rule this package enforces is the shape of the encryption context:
// service, env and purpose are required, every field is short lowercase
// ASCII, and nothing in it is personal data. KMS writes the context to
// CloudTrail in clear and the key policy conditions on it, so it names what a
// secret is for, never whose it is.
//
// From the platform (github.com/thehappieco/platform), internal/kms at
// d32b663, unchanged in behaviour: only these comments differ
// (vectors/PROVENANCE.md).
package kms

import (
	"context"
	"errors"
	"fmt"
)

// Provider bytes, as written in byte 8 of a THCSEAL envelope. A wrapper only
// opens envelopes carrying its own byte, so a production AWS wrapper never
// opens an envelope sealed with a development key. 0x02 is reserved for the
// transitional host-key provider described in the platform's infrastructure
// draft (§2.6).
const (
	ProviderAWS   byte = 0x01
	ProviderLocal byte = 0x7F
)

// DataKeyLen is the size of every data key: AES-256.
const DataKeyLen = 32

// MaxFieldLen bounds each context field. KMS logs the context on every call,
// so it stays short; the bound also keeps the u16 length prefixes in the
// envelope's additional data far from overflowing.
const MaxFieldLen = 128

var (
	// ErrInvalidContext means a context field is missing, too long or uses a
	// character outside [a-z0-9._:/-].
	ErrInvalidContext = errors.New("kms: invalid encryption context")
	// ErrUnwrap means the wrapped data key did not unwrap: it was wrapped under
	// another key or another context, or it was altered. The cause is not
	// reported, so a caller cannot use it to probe which one it was.
	// Availability failures (KMS unreachable, access denied, cancelled
	// context) are reported as other errors, because they say nothing about
	// the envelope and the operator needs to see them.
	ErrUnwrap = errors.New("kms: the data key does not unwrap")
)

// Context is the encryption context a data key is bound to. It must be
// identical when sealing and opening.
//
// Service is the product ("platform"), Env the deployment ("prod", "dev",
// "test"), Purpose what the secret is ("config/stripe-secret-key",
// "serverkey/oidc-signing", "backup") and Ref which one (a kid, a secret name,
// a backup stamp). Ref may be empty. No field ever carries personal data.
type Context struct {
	Service string
	Env     string
	Purpose string
	Ref     string
}

// Validate reports whether c can be used as an encryption context. The error
// names the field but never echoes its value.
func (c Context) Validate() error {
	fields := [...]struct {
		name, value string
		required    bool
	}{
		{"service", c.Service, true},
		{"env", c.Env, true},
		{"purpose", c.Purpose, true},
		{"ref", c.Ref, false},
	}
	for _, f := range fields {
		if f.value == "" {
			if f.required {
				return fmt.Errorf("%w: %s is empty", ErrInvalidContext, f.name)
			}
			continue
		}
		if len(f.value) > MaxFieldLen {
			return fmt.Errorf("%w: %s is longer than %d bytes", ErrInvalidContext, f.name, MaxFieldLen)
		}
		for i := 0; i < len(f.value); i++ {
			if !allowed(f.value[i]) {
				return fmt.Errorf("%w: %s has a character outside [a-z0-9._:/-]", ErrInvalidContext, f.name)
			}
		}
	}
	return nil
}

// Map is the context as KMS takes it. An empty Ref is left out rather than
// sent as an empty value; since Ref is the only optional field, the mapping
// from Context to map stays one-to-one.
func (c Context) Map() map[string]string {
	m := map[string]string{
		"service": c.Service,
		"env":     c.Env,
		"purpose": c.Purpose,
	}
	if c.Ref != "" {
		m["ref"] = c.Ref
	}
	return m
}

func allowed(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', '0' <= b && b <= '9':
		return true
	case b == '.', b == '_', b == ':', b == '/', b == '-':
		return true
	}
	return false
}

// Wrapper makes and unwraps data keys.
//
// GenerateDataKey returns a fresh DataKeyLen-byte key and its wrapped form,
// bound to ec. The caller zeroes plaintext when done with it. Decrypt returns
// the key for a wrapped form produced under the same ec, or an error matching
// ErrUnwrap when it does not unwrap.
type Wrapper interface {
	// Provider is the byte written into envelopes this wrapper seals and
	// required on envelopes it opens.
	Provider() byte
	GenerateDataKey(ctx context.Context, ec Context) (plaintext, wrapped []byte, err error)
	Decrypt(ctx context.Context, wrapped []byte, ec Context) ([]byte, error)
}
