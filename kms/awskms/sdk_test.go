//go:build kitdevkek

package awskms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/localkek"
	"github.com/thehappieco/kit/thcseal"
)

// These tests run the real SDK client against a fake instance metadata
// service and a fake KMS on loopback, to check what New wires up: where the
// credentials come from, what goes over the wire, and how KMS errors come
// back.

const (
	testARN       = "arn:aws:kms:eu-west-1:111122223333:key/0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e"
	roleName      = "example-instance-role"
	roleAccessKey = "ASIAROLEFROMIMDS0001"
	roleToken     = "role-session-token"
	imdsToken     = "imds-v2-token"
	envAccessKey  = "AKIAFROMENVIRONMENT0"
)

// fakeIMDS serves the role's credentials, only to callers holding a session
// token unless v1 is set.
type fakeIMDS struct {
	v1 bool

	mu          sync.Mutex
	tokens      int
	credsServed int
}

func (f *fakeIMDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
		if f.v1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		f.tokens++
		w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", r.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"))
		w.Write([]byte(imdsToken))
		return
	}
	if !f.v1 && r.Header.Get("X-Aws-Ec2-Metadata-Token") != imdsToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/latest/meta-data/iam/security-credentials/":
		w.Write([]byte(roleName))
	case "/latest/meta-data/iam/security-credentials/" + roleName:
		f.credsServed++
		json.NewEncoder(w).Encode(map[string]string{
			"Code": "Success", "Type": "AWS-HMAC",
			"AccessKeyId": roleAccessKey, "SecretAccessKey": "role-secret", "Token": roleToken,
			"Expiration":  time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339),
			"LastUpdated": time.Now().UTC().Format(time.RFC3339),
		})
	default:
		http.NotFound(w, r)
	}
}

// fakeKMS speaks enough of the KMS JSON protocol for DescribeKey,
// GenerateDataKey and Decrypt. It wraps data keys with a localkek under the
// request's encryption context, so a context mismatch fails as it would in
// KMS.
type fakeKMS struct {
	t     *testing.T
	inner *localkek.Wrapper

	mu       sync.Mutex
	calls    []string
	badAuth  []string
	contexts []map[string]string
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	target := r.Header.Get("X-Amz-Target")
	f.calls = append(f.calls, target)

	auth := r.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential="+roleAccessKey+"/") || !strings.Contains(auth, "/eu-west-1/kms/aws4_request") ||
		r.Header.Get("X-Amz-Security-Token") != roleToken {
		f.badAuth = append(f.badAuth, auth)
		kmsError(w, "UnrecognizedClientException")
		return
	}

	var in struct {
		KeyID               string `json:"KeyId"`
		KeySpec             string
		EncryptionAlgorithm string
		EncryptionContext   map[string]string
		CiphertextBlob      []byte
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		kmsError(w, "ValidationException")
		return
	}
	if in.KeyID != testARN {
		kmsError(w, "NotFoundException")
		return
	}
	ec := kms.Context{
		Service: in.EncryptionContext["service"], Env: in.EncryptionContext["env"],
		Purpose: in.EncryptionContext["purpose"], Ref: in.EncryptionContext["ref"],
	}

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch target {
	case "TrentService.DescribeKey":
		json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": map[string]any{
			"Arn": testARN, "KeyId": "0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e", "AWSAccountId": "111122223333",
			"Enabled": true, "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
		}})
	case "TrentService.GenerateDataKey":
		f.contexts = append(f.contexts, in.EncryptionContext)
		if in.KeySpec != "AES_256" {
			kmsError(w, "ValidationException")
			return
		}
		dek, wrapped, err := f.inner.GenerateDataKey(r.Context(), ec)
		if err != nil {
			kmsError(w, "ValidationException")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyId": testARN, "Plaintext": dek, "CiphertextBlob": wrapped})
	case "TrentService.Decrypt":
		f.contexts = append(f.contexts, in.EncryptionContext)
		if in.EncryptionAlgorithm != "SYMMETRIC_DEFAULT" {
			kmsError(w, "ValidationException")
			return
		}
		dek, err := f.inner.Decrypt(r.Context(), in.CiphertextBlob, ec)
		if err != nil {
			kmsError(w, "InvalidCiphertextException")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyId": testARN, "Plaintext": dek, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
	default:
		kmsError(w, "UnknownOperationException")
	}
}

func kmsError(w http.ResponseWriter, typ string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": typ})
}

func newFakeKMS(t *testing.T) *fakeKMS {
	inner, err := localkek.New(bytes.Repeat([]byte{9}, localkek.KEKLen))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{t: t, inner: inner}
}

// poisonEnvironment sets every variable and file the SDK's default chain
// would read, all pointing somewhere else.
func poisonEnvironment(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials")
	os.WriteFile(creds, []byte("[default]\naws_access_key_id = AKIAFROMSHAREDFILE00\naws_secret_access_key = file-secret\n"), 0o600)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("[default]\nregion = us-east-1\n[profile leak]\nregion = us-west-2\n"), 0o600)
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID":                 envAccessKey,
		"AWS_SECRET_ACCESS_KEY":             "env-secret",
		"AWS_SESSION_TOKEN":                 "env-token",
		"AWS_PROFILE":                       "leak",
		"AWS_REGION":                        "us-east-1",
		"AWS_DEFAULT_REGION":                "us-east-1",
		"AWS_SHARED_CREDENTIALS_FILE":       creds,
		"AWS_CONFIG_FILE":                   cfg,
		"AWS_ENDPOINT_URL":                  "http://127.0.0.1:1",
		"AWS_ENDPOINT_URL_KMS":              "http://127.0.0.1:1",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://127.0.0.1:1",
		"AWS_EC2_METADATA_DISABLED":         "true",
		"AWS_EC2_METADATA_V1_DISABLED":      "false",
	} {
		t.Setenv(k, v)
	}
}

func TestCredentialsComeFromTheInstanceRoleNeverFromTheEnvironment(t *testing.T) {
	poisonEnvironment(t)
	md := &fakeIMDS{}
	imdsSrv := httptest.NewServer(md)
	defer imdsSrv.Close()
	k := newFakeKMS(t)
	kmsSrv := httptest.NewServer(k)
	defer kmsSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := NewWithAPI(ctx, newClient("eu-west-1", imdsSrv.URL, kmsSrv.URL), testARN)
	if err != nil {
		t.Fatalf("NewWithAPI: %v", err)
	}

	ec := kms.Context{Service: "platform", Env: "prod", Purpose: "config/smtp-password", Ref: "smtp-password"}
	env, err := thcseal.Seal(ctx, w, ec, []byte("a tier-2 secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := thcseal.Open(ctx, w, ec, env)
	if err != nil || string(got) != "a tier-2 secret" {
		t.Fatalf("Open: %q, %v", got, err)
	}

	// KMS refuses the wrapped key under another context; that comes back
	// through the SDK as the one opaque seal error.
	other := ec
	other.Purpose = "config/stripe-secret-key"
	if _, err := thcseal.Open(ctx, w, other, env); !errors.Is(err, thcseal.ErrDecrypt) {
		t.Fatalf("another purpose: want thcseal.ErrDecrypt, got %v", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.badAuth) != 0 {
		t.Fatalf("KMS saw requests not signed by the instance role in eu-west-1: %q", k.badAuth)
	}
	want := []string{"TrentService.DescribeKey", "TrentService.GenerateDataKey", "TrentService.Decrypt", "TrentService.Decrypt"}
	if strings.Join(k.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v, want %v", k.calls, want)
	}
	if got := k.contexts[0]; len(got) != 4 || got["service"] != "platform" || got["env"] != "prod" ||
		got["purpose"] != "config/smtp-password" || got["ref"] != "smtp-password" {
		t.Fatalf("encryption context on the wire: %v", got)
	}
	md.mu.Lock()
	defer md.mu.Unlock()
	if md.tokens == 0 || md.credsServed == 0 {
		t.Fatalf("IMDS tokens %d, credentials served %d", md.tokens, md.credsServed)
	}
}

func TestTheInstanceRoleIsReadOnlyThroughIMDSv2(t *testing.T) {
	poisonEnvironment(t)
	// An instance metadata service that only speaks v1: no session tokens,
	// credentials to anyone who asks.
	md := &fakeIMDS{v1: true}
	imdsSrv := httptest.NewServer(md)
	defer imdsSrv.Close()
	k := newFakeKMS(t)
	kmsSrv := httptest.NewServer(k)
	defer kmsSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := NewWithAPI(ctx, newClient("eu-west-1", imdsSrv.URL, kmsSrv.URL), testARN); err == nil {
		t.Fatal("started with credentials that did not come through IMDSv2")
	}
	md.mu.Lock()
	defer md.mu.Unlock()
	if md.credsServed != 0 {
		t.Fatal("the client fell back to IMDSv1 for the role's credentials")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.calls) != 0 {
		t.Fatalf("KMS was called without role credentials: %v", k.calls)
	}
}

func TestTheClientHasAFiveSecondTimeoutAndNoProxy(t *testing.T) {
	opts := newClient("eu-west-1", imdsEndpoint, "").Options()
	hc, ok := opts.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("HTTP client %T", opts.HTTPClient)
	}
	if got := hc.GetTimeout(); got != 5*time.Second {
		t.Fatalf("timeout %v, want 5s", got)
	}
	if hc.GetTransport().Proxy != nil {
		t.Fatal("the transport takes a proxy from the environment")
	}
	if opts.Region != "eu-west-1" || opts.BaseEndpoint != nil {
		t.Fatalf("region %q, endpoint %v", opts.Region, opts.BaseEndpoint)
	}
}
