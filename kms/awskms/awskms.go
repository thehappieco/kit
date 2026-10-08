// Package awskms is the production kms.Wrapper: AWS KMS, one pinned key,
// credentials from the instance role only (the platform's decisions 0003 and
// 0020; SPEC section 14.3).
//
// The rules it enforces:
//
//   - Credentials come only from the EC2 instance role through IMDSv2, at the
//     fixed metadata address, with the IMDSv1 fallback off. Environment
//     variables, ~/.aws files and profiles are never read, so a stray
//     AWS_ACCESS_KEY_ID on the box cannot make the service act as someone
//     else, and AWS_ENDPOINT_URL* cannot redirect it. Proxy variables are
//     ignored too.
//   - The key is a full key ARN, never an alias, and every call names it. At
//     start, DescribeKey must show that exact ARN, enabled, SYMMETRIC_DEFAULT
//     and ENCRYPT_DECRYPT, or New refuses.
//   - Every response must name the same ARN and carry a 32-byte key.
//   - The encryption context is kms.Context.Map(), which the key policy
//     conditions on.
//
// RoleCredentials hands those same instance-role credentials to the other
// AWS client on the server, backup push's S3 upload, so nothing that runs
// there has a second way to find credentials.
//
// The one exception lives outside this package: backup open, which runs in
// the owner's AWS CloudShell and not on the server, passes NewWithAPI a
// client built on the owner's credentials (the platform's internal/backup,
// OwnerKMS), because only the account root decrypts backups (the platform's
// decision 0020).
//
// The SDK sits behind a three-method interface so tests can replace it. Of
// the kit's packages only this one imports the AWS SDK (make imports-check),
// so a module that does not import it compiles none of the SDK.
//
// From the platform (github.com/thehappieco/platform), internal/kms/awskms at
// d32b663, unchanged in behaviour: only its import path, its build
// constraint (the platform's file required go1.26) and these comments
// differ, and its tests are those of d3e8c6d, which name AWS's documentation
// placeholders instead of real identifiers (vectors/PROVENANCE.md).
package awskms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	kmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/thehappieco/kit/kms"
)

const (
	// HTTPTimeout bounds every HTTP request to KMS and to IMDS.
	HTTPTimeout = 5 * time.Second

	// IMDSEndpoint is the instance metadata service, the one source of
	// credentials on the server.
	IMDSEndpoint = "http://169.254.169.254"

	imdsEndpoint = IMDSEndpoint
)

var (
	// ErrKeyARN means the key is not given as a full KMS key ARN (an alias,
	// a bare key id, another service) or is in another region.
	ErrKeyARN = errors.New("awskms: not a KMS key ARN in this region")
	// ErrKeyRefused means DescribeKey showed a key this service must not use.
	ErrKeyRefused = errors.New("awskms: key refused")
	// ErrUnexpectedResponse means KMS answered for another key or with a key
	// of the wrong size. It never happens with the real service and a pinned
	// ARN, so it is worth an alert.
	ErrUnexpectedResponse = errors.New("awskms: unexpected response")
)

// api is the part of the KMS client this package uses.
type api interface {
	GenerateDataKey(context.Context, *kmssdk.GenerateDataKeyInput, ...func(*kmssdk.Options)) (*kmssdk.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kmssdk.DecryptInput, ...func(*kmssdk.Options)) (*kmssdk.DecryptOutput, error)
	DescribeKey(context.Context, *kmssdk.DescribeKeyInput, ...func(*kmssdk.Options)) (*kmssdk.DescribeKeyOutput, error)
}

// Wrapper wraps data keys with one pinned KMS key.
type Wrapper struct {
	api api
	arn string
}

var _ kms.Wrapper = (*Wrapper)(nil)

// New connects to KMS in region with the instance role's credentials and
// checks the key with DescribeKey. keyARN must be a full key ARN in region.
func New(ctx context.Context, region, keyARN string) (*Wrapper, error) {
	r, err := arnRegion(keyARN)
	if err != nil {
		return nil, err
	}
	if r != region {
		return nil, fmt.Errorf("%w: the key is in another region", ErrKeyARN)
	}
	return NewWithAPI(ctx, newClient(region, imdsEndpoint, ""), keyARN)
}

// NewWithAPI is New over a given client: the same DescribeKey checks, and
// the same checks on every response. It exists for tests and for backup
// open in the owner's CloudShell (the platform's internal/backup, OwnerKMS).
// Everything that runs on the server calls New, which is the only place
// server credentials are chosen.
func NewWithAPI(ctx context.Context, client api, keyARN string) (*Wrapper, error) {
	if client == nil {
		return nil, errors.New("awskms: no client")
	}
	if _, err := arnRegion(keyARN); err != nil {
		return nil, err
	}
	out, err := client.DescribeKey(ctx, &kmssdk.DescribeKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, fmt.Errorf("awskms: describe key: %w", err)
	}
	var md *types.KeyMetadata
	if out != nil {
		md = out.KeyMetadata
	}
	switch {
	case md == nil:
		return nil, fmt.Errorf("%w: no key metadata", ErrKeyRefused)
	case aws.ToString(md.Arn) != keyARN:
		return nil, fmt.Errorf("%w: KMS describes another key", ErrKeyRefused)
	case !md.Enabled || md.KeyState != types.KeyStateEnabled:
		return nil, fmt.Errorf("%w: state %s", ErrKeyRefused, md.KeyState)
	case md.KeySpec != types.KeySpecSymmetricDefault:
		return nil, fmt.Errorf("%w: key spec %s", ErrKeyRefused, md.KeySpec)
	case md.KeyUsage != types.KeyUsageTypeEncryptDecrypt:
		return nil, fmt.Errorf("%w: key usage %s", ErrKeyRefused, md.KeyUsage)
	}
	return &Wrapper{api: client, arn: keyARN}, nil
}

// Provider is kms.ProviderAWS.
func (w *Wrapper) Provider() byte { return kms.ProviderAWS }

// KeyARN is the pinned key, for startup logs and kms-check.
func (w *Wrapper) KeyARN() string { return w.arn }

// GenerateDataKey asks KMS for a fresh AES-256 data key bound to ec.
func (w *Wrapper) GenerateDataKey(ctx context.Context, ec kms.Context) (plaintext, wrapped []byte, err error) {
	if err := ec.Validate(); err != nil {
		return nil, nil, err
	}
	out, err := w.api.GenerateDataKey(ctx, &kmssdk.GenerateDataKeyInput{
		KeyId:             aws.String(w.arn),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: ec.Map(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("awskms: generate data key: %w", err)
	}
	if out == nil {
		return nil, nil, fmt.Errorf("%w: no output", ErrUnexpectedResponse)
	}
	if err := w.check(out.KeyId, out.Plaintext); err != nil {
		return nil, nil, err
	}
	if len(out.CiphertextBlob) == 0 {
		clear(out.Plaintext)
		return nil, nil, fmt.Errorf("%w: no ciphertext", ErrUnexpectedResponse)
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

// Decrypt asks KMS to unwrap a data key under the pinned key and ec. A
// ciphertext KMS rejects (another key, another context, altered bytes) is
// kms.ErrUnwrap; any other failure is returned as it is.
func (w *Wrapper) Decrypt(ctx context.Context, wrapped []byte, ec kms.Context) ([]byte, error) {
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	out, err := w.api.Decrypt(ctx, &kmssdk.DecryptInput{
		CiphertextBlob:      wrapped,
		KeyId:               aws.String(w.arn),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   ec.Map(),
	})
	if err != nil {
		var invalid *types.InvalidCiphertextException
		var incorrect *types.IncorrectKeyException
		if errors.As(err, &invalid) || errors.As(err, &incorrect) {
			return nil, kms.ErrUnwrap
		}
		return nil, fmt.Errorf("awskms: decrypt: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("%w: no output", ErrUnexpectedResponse)
	}
	if err := w.check(out.KeyId, out.Plaintext); err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// check verifies that a response names the pinned key and carries a data
// key of the right size. On failure it zeroes the key.
func (w *Wrapper) check(keyID *string, plaintext []byte) error {
	if aws.ToString(keyID) != w.arn {
		clear(plaintext)
		return fmt.Errorf("%w: answered for another key", ErrUnexpectedResponse)
	}
	if len(plaintext) != kms.DataKeyLen {
		clear(plaintext)
		return fmt.Errorf("%w: a %d-byte data key", ErrUnexpectedResponse, len(plaintext))
	}
	return nil
}

// arnRegion accepts arn:<partition>:kms:<region>:<12-digit account>:key/<id>
// and returns the region. The platform's config holds the stricter rule
// that pins the account (its decision 0020); this one keeps aliases and bare
// key ids out.
func arnRegion(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") || parts[2] != "kms" {
		return "", ErrKeyARN
	}
	region, account := parts[3], parts[4]
	if region == "" || !isAll(region, "abcdefghijklmnopqrstuvwxyz0123456789-") {
		return "", ErrKeyARN
	}
	if len(account) != 12 || !isAll(account, "0123456789") {
		return "", ErrKeyARN
	}
	id, ok := strings.CutPrefix(parts[5], "key/")
	if !ok || id == "" || !isAll(id, "abcdefghijklmnopqrstuvwxyz0123456789-") {
		return "", ErrKeyARN
	}
	return region, nil
}

func isAll(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

// newClient builds the KMS client. Nothing in it consults the environment:
// the region is the argument, the credentials come from IMDSv2 at
// imdsURL, and kmsURL (tests only; empty in production) is the only way to
// move the endpoint.
func newClient(region, imdsURL, kmsURL string) *kmssdk.Client {
	noProxy := func(t *http.Transport) { t.Proxy = nil }
	opts := kmssdk.Options{
		Region:      region,
		Credentials: RoleCredentials(imdsURL),
		HTTPClient:  awshttp.NewBuildableClient().WithTimeout(HTTPTimeout).WithTransportOptions(noProxy),
		RetryMode:   aws.RetryModeStandard,
	}
	if kmsURL != "" {
		opts.BaseEndpoint = aws.String(kmsURL)
	}
	return kmssdk.New(opts)
}

// RoleCredentials returns the EC2 instance role's credentials, fetched from
// the instance metadata service at imdsURL through IMDSv2 only (no IMDSv1
// fallback), with no proxy and HTTPTimeout per request, and cached until
// they near expiry. It reads no environment variable and no file.
// Production passes IMDSEndpoint; tests pass a fake.
func RoleCredentials(imdsURL string) aws.CredentialsProvider {
	noProxy := func(t *http.Transport) { t.Proxy = nil }
	metadata := imds.New(imds.Options{
		Endpoint:          imdsURL,
		ClientEnableState: imds.ClientEnabled,
		EnableFallback:    aws.FalseTernary,
		HTTPClient:        awshttp.NewBuildableClient().WithTimeout(HTTPTimeout).WithTransportOptions(noProxy),
	})
	return aws.NewCredentialsCache(ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = metadata
	}))
}
