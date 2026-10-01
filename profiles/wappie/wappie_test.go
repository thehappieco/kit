package wappie_test

import (
	"testing"

	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

func TestKinds(t *testing.T) {
	if err := seal.ValidateKinds[wappie.Kind](); err != nil {
		t.Fatal(err)
	}
	// Wappie labels a Prometheus metric with these, and seals with them.
	for k, want := range map[wappie.Kind]string{
		wappie.KindBody: "body", wappie.KindContentKey: "content_key", wappie.KindDeviceGrant: "device_grant",
		wappie.KindMcpDraft: "mcp_draft", 0x0f: "kind(0xf)", 0x00: "kind(0x0)",
	} {
		if k.String() != want {
			t.Errorf("%#x is %q, want %q", byte(k), k, want)
		}
	}
	if d := wappie.KindBody.Domain(); d.Magic != [2]byte{'W', 'S'} || d.Label != "wsv1" {
		t.Errorf("domain %+v", d)
	}
}

// The profile constructors hand out fresh values: a caller that edits one
// cannot change what the next caller gets.
func TestProfilesAreFresh(t *testing.T) {
	a := wappie.Account()
	a.WrapHeader[0] = 0xff
	a.AuthLabel = "x"
	if b := wappie.Account(); b.WrapHeader[0] != 0x02 || b.AuthLabel != "whatserver2/auth" {
		t.Error("Account() shares state")
	}
	p := wappie.Passkey()
	p.Header[0] = 9
	if wappie.Passkey().Header[0] != 1 {
		t.Error("Passkey() shares state")
	}
	if s := passkey.PRFSalt(wappie.Passkey(), "wappie.thehappie.co"); s == ([32]byte{}) {
		t.Error("no salt")
	}
	if h := wappie.MCPHMAC(); h.Label != "wappie-mcp-hmac/v1" || h.Headers.Sender != "X-Wappie-Reader" {
		t.Errorf("%+v", h)
	}
}
