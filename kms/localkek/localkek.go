//go:build kitdevkek

// Package localkek is a kms.Wrapper backed by a local key-encryption key, for
// development and tests only.
//
// Production uses AWS KMS (the platform's decision 0003). This provider
// exists so that development and CI can seal and open THCSEAL envelopes with
// no AWS account. Its envelopes carry provider byte 0x7F, and package
// thcseal refuses to open them with any other wrapper, so a production
// wrapper never accepts one.
//
// The package compiles only with the build tag kitdevkek: a binary built
// without the tag cannot link it, and an import of it fails to build. No
// package of the kit imports it outside its tests (make imports-check, in
// CI). So a consumer passes -tags kitdevkek to the tests, vet and linters of
// every package whose tests use it, and to its development builds; its
// release builds go without the tag. A product gates it further where it
// selects a provider: the platform's code that does so compiles only with
// -tags dev, and its config refuses it when PLATFORM_ENV is prod. Do not
// import this package from anything that ships in a release binary.
//
// A wrapped data key is
//
//	nonce(12) || AES-256-GCM(KEK, dek(32), aad) || tag(16)
//
// with aad = "thcseal-localkek/v1\n" + service + "\n" + env + "\n" +
// purpose + "\n" + ref. It mirrors the KMS encryption context: a key wrapped
// for one purpose, ref, service or env does not unwrap for another. The
// context alphabet has no newline, so the separators are unambiguous.
//
// From the platform (github.com/thehappieco/platform), internal/kms/localkek
// at d32b663, unchanged in behaviour: only its build constraint, its import
// path and these comments differ (vectors/PROVENANCE.md).
package localkek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/thehappieco/kit/kms"
)

const (
	// KEKLen is the size of the key-encryption key: AES-256.
	KEKLen = 32
	// WrappedLen is the size of every wrapped data key.
	WrappedLen = nonceLen + kms.DataKeyLen + tagLen

	nonceLen  = 12
	tagLen    = 16
	aadPrefix = "thcseal-localkek/v1\n"
)

// ErrKEKLength means the key-encryption key is not KEKLen bytes.
var ErrKEKLength = errors.New("localkek: the key-encryption key must be 32 bytes")

// Wrapper wraps data keys under a local key-encryption key.
type Wrapper struct {
	aead cipher.AEAD
}

var _ kms.Wrapper = (*Wrapper)(nil)

// New returns a wrapper for kek. It keeps no reference to kek, so the caller
// may zero it afterwards.
func New(kek []byte) (*Wrapper, error) {
	if len(kek) != KEKLen {
		return nil, ErrKEKLength
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("localkek: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("localkek: %w", err)
	}
	return &Wrapper{aead: aead}, nil
}

// Provider is kms.ProviderLocal.
func (w *Wrapper) Provider() byte { return kms.ProviderLocal }

// GenerateDataKey returns a fresh random data key and its wrapped form.
func (w *Wrapper) GenerateDataKey(ctx context.Context, ec kms.Context) (plaintext, wrapped []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := ec.Validate(); err != nil {
		return nil, nil, err
	}
	dek := make([]byte, kms.DataKeyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("localkek: read random: %w", err)
	}
	out := make([]byte, nonceLen, WrappedLen)
	if _, err := rand.Read(out); err != nil {
		clear(dek)
		return nil, nil, fmt.Errorf("localkek: read random: %w", err)
	}
	return dek, w.aead.Seal(out, out[:nonceLen], dek, aad(ec)), nil
}

// Decrypt unwraps a data key. Every failure to unwrap, whatever the cause, is
// kms.ErrUnwrap.
func (w *Wrapper) Decrypt(ctx context.Context, wrapped []byte, ec kms.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	if len(wrapped) != WrappedLen {
		return nil, kms.ErrUnwrap
	}
	dek, err := w.aead.Open(nil, wrapped[:nonceLen], wrapped[nonceLen:], aad(ec))
	if err != nil {
		return nil, kms.ErrUnwrap
	}
	return dek, nil
}

func aad(ec kms.Context) []byte {
	out := make([]byte, 0, len(aadPrefix)+len(ec.Service)+len(ec.Env)+len(ec.Purpose)+len(ec.Ref)+3)
	out = append(out, aadPrefix...)
	out = append(out, ec.Service...)
	out = append(out, '\n')
	out = append(out, ec.Env...)
	out = append(out, '\n')
	out = append(out, ec.Purpose...)
	out = append(out, '\n')
	out = append(out, ec.Ref...)
	return out
}
