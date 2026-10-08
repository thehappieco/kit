package awskms_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/awskms"
)

const keyARN = "arn:aws:kms:eu-west-1:111122223333:key/0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e"

var bg = context.Background()

func ec() kms.Context {
	return kms.Context{Service: "platform", Env: "prod", Purpose: "serverkey/oidc-signing", Ref: "kid-1"}
}

// fake records what it is asked and answers what the test set.
type fake struct {
	md          *types.KeyMetadata
	describeErr error

	genOut *kmssdk.GenerateDataKeyOutput
	genErr error
	decOut *kmssdk.DecryptOutput
	decErr error

	describeIn *kmssdk.DescribeKeyInput
	genIn      *kmssdk.GenerateDataKeyInput
	decIn      *kmssdk.DecryptInput
}

func goodMetadata() *types.KeyMetadata {
	return &types.KeyMetadata{
		Arn:      aws.String(keyARN),
		Enabled:  true,
		KeyState: types.KeyStateEnabled,
		KeySpec:  types.KeySpecSymmetricDefault,
		KeyUsage: types.KeyUsageTypeEncryptDecrypt,
	}
}

func newFake() *fake {
	return &fake{
		md: goodMetadata(),
		genOut: &kmssdk.GenerateDataKeyOutput{
			KeyId: aws.String(keyARN), Plaintext: bytes.Repeat([]byte{7}, 32), CiphertextBlob: []byte("blob"),
		},
		decOut: &kmssdk.DecryptOutput{KeyId: aws.String(keyARN), Plaintext: bytes.Repeat([]byte{7}, 32)},
	}
}

func (f *fake) DescribeKey(_ context.Context, in *kmssdk.DescribeKeyInput, _ ...func(*kmssdk.Options)) (*kmssdk.DescribeKeyOutput, error) {
	f.describeIn = in
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &kmssdk.DescribeKeyOutput{KeyMetadata: f.md}, nil
}

func (f *fake) GenerateDataKey(_ context.Context, in *kmssdk.GenerateDataKeyInput, _ ...func(*kmssdk.Options)) (*kmssdk.GenerateDataKeyOutput, error) {
	f.genIn = in
	return f.genOut, f.genErr
}

func (f *fake) Decrypt(_ context.Context, in *kmssdk.DecryptInput, _ ...func(*kmssdk.Options)) (*kmssdk.DecryptOutput, error) {
	f.decIn = in
	return f.decOut, f.decErr
}

func wrapper(t *testing.T, f *fake) *awskms.Wrapper {
	t.Helper()
	w, err := awskms.NewWithAPI(bg, f, keyARN)
	if err != nil {
		t.Fatalf("NewWithAPI: %v", err)
	}
	return w
}

func TestOnlyAFullKeyARNIsAccepted(t *testing.T) {
	for _, arn := range []string{
		"",
		"alias/example-alias",
		"arn:aws:kms:eu-west-1:111122223333:alias/example-alias",
		"0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e",
		"arn:aws:s3:eu-west-1:111122223333:key/0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e",
		"arn:aws:kms:eu-west-1:11112222333:key/0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e",
		"arn:aws:kms:eu-west-1:111122223333:key/",
		"arn:aws:kms:eu-west-1:111122223333:key/0B9E3C1D-5A2F-4E8B-9C7D-1F2A3B4C5D6E",
		"arn:aws:kms:eu-west-1:111122223333:key/0b9e3c1d:extra",
		"arn:aws:kms::111122223333:key/0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e",
	} {
		f := newFake()
		if _, err := awskms.NewWithAPI(bg, f, arn); !errors.Is(err, awskms.ErrKeyARN) {
			t.Errorf("%q: want ErrKeyARN, got %v", arn, err)
		}
		if f.describeIn != nil {
			t.Errorf("%q: KMS was called before the ARN was checked", arn)
		}
		if _, err := awskms.New(bg, "eu-west-1", arn); !errors.Is(err, awskms.ErrKeyARN) {
			t.Errorf("New %q: want ErrKeyARN, got %v", arn, err)
		}
	}
}

func TestAKeyInAnotherRegionIsRefusedBeforeAnyCall(t *testing.T) {
	if _, err := awskms.New(bg, "us-east-1", keyARN); !errors.Is(err, awskms.ErrKeyARN) {
		t.Fatalf("want ErrKeyARN, got %v", err)
	}
}

func TestAMultiRegionKeyARNIsAccepted(t *testing.T) {
	arn := "arn:aws:kms:eu-west-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab"
	f := newFake()
	f.md.Arn = aws.String(arn)
	if _, err := awskms.NewWithAPI(bg, f, arn); err != nil {
		t.Fatalf("NewWithAPI: %v", err)
	}
}

func TestStartupDescribesThePinnedKey(t *testing.T) {
	f := newFake()
	w := wrapper(t, f)
	if got := aws.ToString(f.describeIn.KeyId); got != keyARN {
		t.Fatalf("DescribeKey asked about %q", got)
	}
	if w.Provider() != kms.ProviderAWS || w.KeyARN() != keyARN {
		t.Fatalf("provider %#x, key %q", w.Provider(), w.KeyARN())
	}
}

func TestAKeyThatIsNotAnEnabledSymmetricEncryptionKeyIsRefused(t *testing.T) {
	cases := map[string]func(*types.KeyMetadata){
		"disabled":           func(m *types.KeyMetadata) { m.Enabled, m.KeyState = false, types.KeyStateDisabled },
		"pending deletion":   func(m *types.KeyMetadata) { m.Enabled, m.KeyState = false, types.KeyStatePendingDeletion },
		"enabled flag only":  func(m *types.KeyMetadata) { m.KeyState = types.KeyStatePendingImport },
		"asymmetric":         func(m *types.KeyMetadata) { m.KeySpec = types.KeySpecRsa2048 },
		"hmac":               func(m *types.KeyMetadata) { m.KeySpec = types.KeySpecHmac256 },
		"signing":            func(m *types.KeyMetadata) { m.KeyUsage = types.KeyUsageTypeSignVerify },
		"mac":                func(m *types.KeyMetadata) { m.KeyUsage = types.KeyUsageTypeGenerateVerifyMac },
		"another key":        func(m *types.KeyMetadata) { m.Arn = aws.String(keyARN[:len(keyARN)-1] + "f") },
		"no arn in response": func(m *types.KeyMetadata) { m.Arn = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			edit(f.md)
			if _, err := awskms.NewWithAPI(bg, f, keyARN); !errors.Is(err, awskms.ErrKeyRefused) {
				t.Fatalf("want ErrKeyRefused, got %v", err)
			}
		})
	}

	f := newFake()
	f.md = nil
	if _, err := awskms.NewWithAPI(bg, f, keyARN); !errors.Is(err, awskms.ErrKeyRefused) {
		t.Fatalf("no metadata: want ErrKeyRefused, got %v", err)
	}
}

func TestAKeyThatCannotBeDescribedStopsStartup(t *testing.T) {
	down := errors.New("dial tcp: connection refused")
	f := newFake()
	f.describeErr = down
	if _, err := awskms.NewWithAPI(bg, f, keyARN); !errors.Is(err, down) {
		t.Fatalf("want the KMS error, got %v", err)
	}
}

func TestADataKeyIsAskedForWithThePinnedKeyAES256AndTheContext(t *testing.T) {
	f := newFake()
	w := wrapper(t, f)
	dek, wrapped, err := w.GenerateDataKey(bg, ec())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dek) != 32 || string(wrapped) != "blob" {
		t.Fatalf("got %x / %q", dek, wrapped)
	}
	in := f.genIn
	if aws.ToString(in.KeyId) != keyARN || in.KeySpec != types.DataKeySpecAes256 || in.NumberOfBytes != nil {
		t.Fatalf("request %+v", in)
	}
	if !maps.Equal(in.EncryptionContext, ec().Map()) {
		t.Fatalf("context %v", in.EncryptionContext)
	}
}

func TestADataKeyIsUnwrappedWithThePinnedKeyTheSymmetricAlgorithmAndTheContext(t *testing.T) {
	f := newFake()
	w := wrapper(t, f)
	if _, err := w.Decrypt(bg, []byte("blob"), ec()); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	in := f.decIn
	if aws.ToString(in.KeyId) != keyARN || in.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault ||
		string(in.CiphertextBlob) != "blob" || in.Recipient != nil {
		t.Fatalf("request %+v", in)
	}
	if !maps.Equal(in.EncryptionContext, ec().Map()) {
		t.Fatalf("context %v", in.EncryptionContext)
	}
}

func TestAResponseForAnotherKeyOrWithAWrongSizedKeyIsRefusedAndZeroed(t *testing.T) {
	other := aws.String(keyARN[:len(keyARN)-1] + "f")
	cases := map[string]struct {
		keyID *string
		n     int
	}{
		"another key": {other, 32},
		"no key id":   {nil, 32},
		"16-byte key": {aws.String(keyARN), 16},
		"empty key":   {aws.String(keyARN), 0},
		"64-byte key": {aws.String(keyARN), 64},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			w := wrapper(t, f)

			pt := bytes.Repeat([]byte{7}, c.n)
			f.genOut = &kmssdk.GenerateDataKeyOutput{KeyId: c.keyID, Plaintext: pt, CiphertextBlob: []byte("blob")}
			if _, _, err := w.GenerateDataKey(bg, ec()); !errors.Is(err, awskms.ErrUnexpectedResponse) {
				t.Fatalf("GenerateDataKey: want ErrUnexpectedResponse, got %v", err)
			}
			if !bytes.Equal(pt, make([]byte, c.n)) {
				t.Fatal("GenerateDataKey left the refused key in memory")
			}

			pt = bytes.Repeat([]byte{7}, c.n)
			f.decOut = &kmssdk.DecryptOutput{KeyId: c.keyID, Plaintext: pt}
			if _, err := w.Decrypt(bg, []byte("blob"), ec()); !errors.Is(err, awskms.ErrUnexpectedResponse) {
				t.Fatalf("Decrypt: want ErrUnexpectedResponse, got %v", err)
			}
			if !bytes.Equal(pt, make([]byte, c.n)) {
				t.Fatal("Decrypt left the refused key in memory")
			}
		})
	}
}

func TestADataKeyWithoutACiphertextIsRefused(t *testing.T) {
	f := newFake()
	w := wrapper(t, f)
	pt := bytes.Repeat([]byte{7}, 32)
	f.genOut = &kmssdk.GenerateDataKeyOutput{KeyId: aws.String(keyARN), Plaintext: pt}
	if _, _, err := w.GenerateDataKey(bg, ec()); !errors.Is(err, awskms.ErrUnexpectedResponse) {
		t.Fatalf("want ErrUnexpectedResponse, got %v", err)
	}
	if !bytes.Equal(pt, make([]byte, 32)) {
		t.Fatal("the refused key was left in memory")
	}
}

func TestACiphertextKMSRejectsIsAnUnwrapFailureAndAnOutageIsNot(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		unwrap bool
	}{
		{"invalid ciphertext", &types.InvalidCiphertextException{Message: aws.String("context mismatch")}, true},
		{"incorrect key", &types.IncorrectKeyException{Message: aws.String("other key")}, true},
		{"access denied", errors.New("AccessDeniedException: not authorized"), false},
		{"disabled", &types.DisabledException{Message: aws.String("disabled")}, false},
		{"unreachable", errors.New("dial tcp: i/o timeout"), false},
		{"cancelled", context.Canceled, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			w := wrapper(t, f)
			f.decOut, f.decErr = nil, c.err
			_, err := w.Decrypt(bg, []byte("blob"), ec())
			if got := errors.Is(err, kms.ErrUnwrap); got != c.unwrap {
				t.Fatalf("errors.Is(%v, ErrUnwrap) = %v, want %v", err, got, c.unwrap)
			}
			if !c.unwrap && !errors.Is(err, c.err) {
				t.Fatalf("the cause was lost: %v", err)
			}
		})
	}
}

func TestAnInvalidContextNeverReachesKMS(t *testing.T) {
	f := newFake()
	w := wrapper(t, f)
	bad := ec()
	bad.Ref = "Someone@Example.com"
	if _, _, err := w.GenerateDataKey(bg, bad); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("GenerateDataKey: want ErrInvalidContext, got %v", err)
	}
	if _, err := w.Decrypt(bg, []byte("blob"), bad); !errors.Is(err, kms.ErrInvalidContext) {
		t.Fatalf("Decrypt: want ErrInvalidContext, got %v", err)
	}
	if f.genIn != nil || f.decIn != nil {
		t.Fatal("KMS was called with an invalid context")
	}
}
