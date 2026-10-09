package mailie_test

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/profiles/mailie"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// FuzzServerChecks holds what a Mailie server runs on what it is sent to
// store, and the openers a browser runs on what a server hands it, to their
// documented shapes: an account wrap passes CheckAccountWrapShape exactly
// when it is 61 bytes starting with 0x02; a grant passes CheckGrantShape at
// an epoch exactly when it is 88 bytes of Mailie's direct header at that
// epoch with a zero reserved byte; a seal id or a namespace is valid exactly
// in its one spelling; a public key a server accepts is 32 bytes with bit 255
// clear; and neither opener ever returns a key whose public half is not the
// bound one. Seeded from Mailie's vectors (vectors/mailie/key-scheme-v1).
func FuzzServerChecks(f *testing.F) {
	for _, name := range []string{"account-go.json", "grant-go.json"} {
		_, file := ksLoad(f, name)
		for _, c := range file.Cases {
			for _, k := range []string{"wrap_b64", "grant_b64", "public_key_b64"} {
				if s, ok := c.In[k].(string); ok {
					seal, _ := c.In["seal_id"].(string)
					epoch, _ := c.In["epoch"].(float64)
					f.Add(unb64(f, s), seal, uint16(epoch))
				}
			}
		}
	}
	account, mailbox := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{6}, 32)
	priv, err := hpke.ParsePrivateKey(account)
	if err != nil {
		f.Fatal(err)
	}
	accountPub, mailboxPub := public(f, account), public(f, mailbox)
	const ns, sealID = "9d035f2b-81d0-420e-90e2-bb16e950497b", "b8cbc8a8-0c90-48ac-9233-fbdace9d7bf4"
	f.Fuzz(func(t *testing.T, b []byte, s string, epoch uint16) {
		wantWrap := len(b) == mailie.AccountWrapLen && b[0] == mailie.AccountWrapHeader
		if got := mailie.CheckAccountWrapShape(b) == nil; got != wantWrap {
			t.Fatalf("CheckAccountWrapShape of %d bytes: %v", len(b), got)
		}
		wantGrant := len(b) == mailie.GrantLen && bytes.HasPrefix(b, []byte{'M', 'L', 1, 1, 1}) && binary.BigEndian.Uint16(b[5:7]) == epoch && b[7] == 0
		if got := mailie.CheckGrantShape(b, int(epoch)) == nil; got != wantGrant {
			t.Fatalf("CheckGrantShape of %d bytes at epoch %d: %v", len(b), epoch, got)
		}
		if mailie.ValidSealID(s) != uuidV4.MatchString(s) || mailie.ValidNamespace(s) != uuidV4.MatchString(s) {
			t.Fatalf("the spelling of %q", s)
		}
		if mailie.CheckPublicKey(b) == nil && (len(b) != 32 || b[31]&0x80 != 0) {
			t.Fatalf("a public key of %d bytes is accepted", len(b))
		}
		if key, err := mailie.OpenGrant(priv, ns, sealID, max(int(epoch), 1), mailboxPub, b); err == nil && !bytes.Equal(public(t, key), mailboxPub) {
			t.Fatal("a grant opened to another key")
		}
		if key, err := mailie.OpenAccountWrap(mailie.WrapPassword, mailbox, b, sealID, accountPub); err == nil && !bytes.Equal(public(t, key), accountPub) {
			t.Fatal("a wrap opened to another key")
		}
	})
}
