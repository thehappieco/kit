// Package wappie is the Wappie profile: the wire constants and AAD builders
// with which Wappie sealed, wrapped and signed its existing data. They are
// frozen; data already stored opens only with exactly these values.
//
// Only wire values are here. What each kind means to Wappie (which WhatsApp
// field is sealed under which kind) stays in Wappie.
package wappie

import (
	"fmt"
	"time"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/internal/ecma"
	"github.com/thehappieco/kit/jcs"
	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/reqhmac"
	"github.com/thehappieco/kit/seal"
)

// ---------------------------------------------------------------------------
// The sealed archive
// ---------------------------------------------------------------------------

// SealDomain is Wappie's envelope domain: magic "WS", label "wsv1".
func SealDomain() seal.Domain {
	return seal.Domain{Magic: [2]byte{0x57, 0x53}, Label: "wsv1"}
}

// Kind identifies what a sealed value is in Wappie's archive.
type Kind uint8

const (
	KindBody         Kind = 0x01 // message text or caption
	KindRawProto     Kind = 0x02 // the original protobuf
	KindMediaKey     Kind = 0x03 // the 32 bytes that make a stored blob readable
	KindThumbnail    Kind = 0x04
	KindContactName  Kind = 0x05
	KindContentKey   Kind = seal.KindContentKey // a content key sealed to a device archive key
	KindDeviceGrant  Kind = seal.KindGrant      // a device's archive key sealed to one user's key
	KindUserWrap     Kind = seal.KindUserWrap   // reserved; never sealed
	KindPayload      Kind = 0x09                // a message's structured content, as JSON
	KindPushName     Kind = 0x0A
	KindFullName     Kind = 0x0B
	KindBusinessName Kind = 0x0C
	KindAvatar       Kind = 0x0D
	KindMcpDraft     Kind = 0x0E // a draft an assistant made, sealed in the attested reader; 0x0F stays reserved
)

// String is the wire name, which goes into a direct envelope's HPKE info.
// Wappie also uses it as a metric label.
func (k Kind) String() string {
	switch k {
	case KindBody:
		return "body"
	case KindRawProto:
		return "raw_proto"
	case KindMediaKey:
		return "media_key"
	case KindThumbnail:
		return "thumbnail"
	case KindContactName:
		return "contact_name"
	case KindContentKey:
		return "content_key"
	case KindDeviceGrant:
		return "device_grant"
	case KindUserWrap:
		return "user_wrap"
	case KindPayload:
		return "payload"
	case KindPushName:
		return "push_name"
	case KindFullName:
		return "full_name"
	case KindBusinessName:
		return "business_name"
	case KindAvatar:
		return "avatar"
	case KindMcpDraft:
		return "mcp_draft"
	default:
		return fmt.Sprintf("kind(%#x)", byte(k))
	}
}

// Domain binds every Wappie kind to Wappie's envelope domain.
func (Kind) Domain() seal.Domain { return SealDomain() }

// ---------------------------------------------------------------------------
// The account
// ---------------------------------------------------------------------------

// Account is Wappie's account profile. It has no password preparation and no
// KDF bounds, as Wappie has always derived, and it still opens the version 1
// wraps written before the AAD binding.
func Account() account.Profile {
	return account.Profile{
		AuthLabel:          "whatserver2/auth",
		WrapLabel:          "whatserver2/wrap",
		RecoveryKeyLabel:   "whatserver2/recovery",
		RecoveryProofLabel: "whatserver2/recovery-auth",
		WrapHeader:         []byte{0x02},
		LegacyV1:           true,
	}
}

// AccountWrapAAD is the AAD of a version 2 wrap:
// UTF-8("whatserver2/usk|" + email.trim().toLowerCase()), with JavaScript's
// trim and toLowerCase, because the browser computes it.
func AccountWrapAAD(email string) []byte {
	return []byte("whatserver2/usk|" + ecma.ToLowerCase(ecma.Trim(email)))
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

// Passkey is Wappie's passkey profile.
func Passkey() passkey.Profile {
	return passkey.Profile{
		EvalPrefix: "wappie/passkey-vault/v1/",
		WrapInfo:   "wappie/passkey-wrap/v1",
		Header:     []byte{0x01},
	}
}

// PasskeyAAD is the AAD of a passkey wrap: the JSON array
// ["wappie/passkey-vault", 1, rpID, userID, credentialID].
func PasskeyAAD(rpID, userID, credentialID string) []byte {
	b, err := jcs.Marshal([]any{"wappie/passkey-vault", 1, rpID, userID, credentialID})
	if err != nil {
		// Only a string that is not valid UTF-8 fails, and such a string has
		// no JavaScript counterpart to agree with.
		return nil
	}
	return b
}

// ---------------------------------------------------------------------------
// The request HMAC between Wappie's server and its attested reader
// ---------------------------------------------------------------------------

// Directions, as they appear in the canonical string.
const (
	DirectionToReader = "to-reader"
	DirectionToGo     = "to-go"
)

// Replay cache sizing Wappie's server uses.
const (
	// ReplayLifetime is one second longer than any timestamp stays acceptable.
	ReplayLifetime = 61 * time.Second
	// ReplayCapacity bounds live nonces; a flood is answered with 503.
	ReplayCapacity = 100_000
)

// MCPHMAC is the wappie-mcp-hmac/v1 scheme.
func MCPHMAC() reqhmac.Scheme {
	return reqhmac.Scheme{
		Label: "wappie-mcp-hmac/v1",
		Headers: reqhmac.Headers{
			Sender:    "X-Wappie-Reader",
			Timestamp: "X-Wappie-Timestamp",
			Nonce:     "X-Wappie-Nonce",
			Signature: "X-Wappie-Signature",
		},
		Skew: 60 * time.Second,
	}
}
