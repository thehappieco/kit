package seal_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

// The legacy files are byte-for-byte copies of Wappie's own fixtures at the
// commit recorded in vectors/PROVENANCE.md, in the shapes Wappie gave them.
// Each test below reads one the way Wappie's own test does, through the kit.

func privateKey(t *testing.T, b64 string) hpke.PrivateKey {
	t.Helper()
	priv, err := hpke.ParsePrivateKey(vectest.B64(t, b64))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// internal/crypto/seal/testdata/vectors.json: Go sealed, every reader opens.
func TestLegacySealVectors(t *testing.T) {
	var v struct {
		Tenant, Device string
		PrivateKey     string `json:"private_key"`
		PublicKey      string `json:"public_key"`
		ContentKey     struct {
			ID     uint32 `json:"id"`
			Epoch  uint16 `json:"epoch"`
			Sealed string `json:"sealed"`
		} `json:"content_key"`
		Batch, Direct []struct {
			Kind      byte   `json:"kind"`
			KindName  string `json:"kind_name"`
			Row       string `json:"row"`
			Sealed    string `json:"sealed"`
			Plaintext string `json:"plaintext"`
		}
		Grant struct {
			User      string `json:"user"`
			Epoch     uint16 `json:"epoch"`
			Sealed    string `json:"sealed"`
			DeviceKey string `json:"device_key"`
		} `json:"grant"`
		Negatives []struct {
			Why, Mode, Row, Sealed string
			Kind                   byte
		}
	}
	if err := json.Unmarshal(vectest.Raw(t, "wappie/legacy/seal-vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	tenant, device := vectest.UUID(t, v.Tenant), vectest.UUID(t, v.Device)
	priv := privateKey(t, v.PrivateKey)
	pub, _ := priv.PublicKey()
	if !bytes.Equal(pub.Bytes(), vectest.B64(t, v.PublicKey)) {
		t.Fatal("the fixture's public key is not its private key's")
	}
	ck, err := seal.OpenContentKey[wappie.Kind](priv, tenant, device, v.ContentKey.ID, vectest.B64(t, v.ContentKey.Sealed))
	if err != nil || ck.Epoch != v.ContentKey.Epoch {
		t.Fatalf("opening the content key: %v", err)
	}
	for _, want := range v.Batch {
		got, err := ck.Open(wappie.Kind(want.Kind), tenant, vectest.UUID(t, want.Row), vectest.B64(t, want.Sealed))
		if err != nil || !bytes.Equal(got, vectest.B64(t, want.Plaintext)) || wappie.Kind(want.Kind).String() != want.KindName {
			t.Errorf("batch %s: %q %v", want.KindName, got, err)
		}
	}
	for _, want := range v.Direct {
		got, err := seal.OpenDirect(priv, wappie.Kind(want.Kind), tenant, vectest.UUID(t, want.Row), vectest.B64(t, want.Sealed))
		if err != nil || !bytes.Equal(got, vectest.B64(t, want.Plaintext)) {
			t.Errorf("direct %s: %v", want.KindName, err)
		}
	}
	user := vectest.UUID(t, v.Grant.User)
	got, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, seal.GrantRow(tenant, device, user, v.Grant.Epoch), vectest.B64(t, v.Grant.Sealed))
	if err != nil || !bytes.Equal(got, vectest.B64(t, v.Grant.DeviceKey)) {
		t.Errorf("grant: %v", err)
	}
	if _, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, seal.GrantRow(tenant, device, uuid.New(), v.Grant.Epoch), vectest.B64(t, v.Grant.Sealed)); err == nil {
		t.Error("a grant opened as another account's")
	}
	if len(v.Negatives) == 0 {
		t.Fatal("no negatives")
	}
	for _, bad := range v.Negatives {
		var err error
		if bad.Mode == "direct" {
			_, err = seal.OpenDirect(priv, wappie.Kind(bad.Kind), tenant, vectest.UUID(t, bad.Row), vectest.B64(t, bad.Sealed))
		} else {
			_, err = ck.Open(wappie.Kind(bad.Kind), tenant, vectest.UUID(t, bad.Row), vectest.B64(t, bad.Sealed))
		}
		if err == nil {
			t.Errorf("%s: opened, and it must not", bad.Why)
		}
	}
}

type legacyDraftRow struct {
	Device     string  `json:"device"`
	Connection string  `json:"connection"`
	Draft      string  `json:"draft"`
	Reply      *string `json:"reply"`
	ChatKey    string  `json:"chat_key"`
	Row        string  `json:"row"`
	Note       string  `json:"note"`
}

func (r legacyDraftRow) derive(t *testing.T, tenant uuid.UUID) uuid.UUID {
	var reply *uuid.UUID
	if r.Reply != nil {
		id := vectest.UUID(t, *r.Reply)
		reply = &id
	}
	return draftRow(tenant, vectest.UUID(t, r.Device), vectest.UUID(t, r.Connection), vectest.UUID(t, r.Draft), reply, r.ChatKey)
}

// internal/crypto/seal/testdata/draft-vectors.json: Go derived the rows and
// sealed a draft; every reader rebuilds the rows and refuses the negatives.
func TestLegacyDraftVectors(t *testing.T) {
	var v struct {
		Tenant     string           `json:"tenant"`
		PrivateKey string           `json:"private_key"`
		Rows       []legacyDraftRow `json:"rows"`
		Draft      struct {
			legacyDraftRow
			Epoch     uint16 `json:"epoch"`
			Plaintext string `json:"plaintext"`
			Sealed    string `json:"sealed"`
		} `json:"draft"`
		Negatives []struct {
			Why  string `json:"why"`
			Kind byte   `json:"kind"`
			legacyDraftRow
		} `json:"negatives"`
	}
	if err := json.Unmarshal(vectest.Raw(t, "wappie/legacy/draft-vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	tenant := vectest.UUID(t, v.Tenant)
	for _, r := range v.Rows {
		if got := r.derive(t, tenant).String(); got != r.Row {
			t.Errorf("%s: %s, want %s", r.Note, got, r.Row)
		}
	}
	priv := privateKey(t, v.PrivateKey)
	row := v.Draft.derive(t, tenant)
	if row.String() != v.Draft.Row {
		t.Fatalf("draft row %s, want %s", row, v.Draft.Row)
	}
	got, err := seal.OpenDirect(priv, wappie.KindMcpDraft, tenant, row, vectest.B64(t, v.Draft.Sealed))
	if err != nil || string(got) != v.Draft.Plaintext {
		t.Fatalf("the draft: %q %v", got, err)
	}
	if len(v.Negatives) == 0 {
		t.Fatal("no negatives")
	}
	for _, bad := range v.Negatives {
		if _, err := seal.OpenDirect(priv, wappie.Kind(bad.Kind), tenant, bad.derive(t, tenant), vectest.B64(t, v.Draft.Sealed)); err == nil {
			t.Errorf("%s: the draft opened", bad.Why)
		}
	}
}

// packages/client/testdata/browser-grant.json: the browser sealed a grant.
func TestLegacyBrowserGrant(t *testing.T) {
	var g struct {
		Tenant, Device, User string
		Epoch                uint16
		AccountPrivateKey    string `json:"account_private_key"`
		AccountPublicKey     string `json:"account_public_key"`
		DeviceKey            string `json:"device_key"`
		GrantRow             string `json:"grant_row"`
		Sealed               string `json:"sealed"`
	}
	if err := json.Unmarshal(vectest.Raw(t, "wappie/legacy/browser-grant.json"), &g); err != nil {
		t.Fatal(err)
	}
	tenant, device, user := vectest.UUID(t, g.Tenant), vectest.UUID(t, g.Device), vectest.UUID(t, g.User)
	row := seal.GrantRow(tenant, device, user, g.Epoch)
	if row.String() != g.GrantRow {
		t.Fatalf("grant row %s, browser derived %s", row, g.GrantRow)
	}
	priv := privateKey(t, g.AccountPrivateKey)
	got, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, row, vectest.B64(t, g.Sealed))
	if err != nil || !bytes.Equal(got, vectest.B64(t, g.DeviceKey)) {
		t.Fatalf("the browser's grant: %v", err)
	}
	elsewhere := seal.GrantRow(tenant, uuid.MustParse("00000000-0000-4000-8000-0000000000bb"), user, g.Epoch)
	if _, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, elsewhere, vectest.B64(t, g.Sealed)); err == nil {
		t.Error("a grant opened under another device")
	}
	if _, err := seal.OpenDirect(priv, wappie.KindContentKey, tenant, row, vectest.B64(t, g.Sealed)); err == nil {
		t.Error("a grant opened as a content key")
	}
}

// packages/client/testdata/node-draft.json: Node sealed a draft, as the
// attested reader does.
func TestLegacyNodeDraft(t *testing.T) {
	var n struct {
		Tenant, Device, Connection, Draft string
		ReplyToUID                        *string `json:"reply_to_uid"`
		ChatKey                           string  `json:"chat_key"`
		PrivateKey                        string  `json:"archive_private_key"`
		DraftRow                          string  `json:"draft_row"`
		Plaintext                         string  `json:"plaintext"`
		Sealed                            string  `json:"sealed"`
	}
	if err := json.Unmarshal(vectest.Raw(t, "wappie/legacy/node-draft.json"), &n); err != nil {
		t.Fatal(err)
	}
	tenant, device, connection, draft := vectest.UUID(t, n.Tenant), vectest.UUID(t, n.Device), vectest.UUID(t, n.Connection), vectest.UUID(t, n.Draft)
	var reply *uuid.UUID
	if n.ReplyToUID != nil {
		r := vectest.UUID(t, *n.ReplyToUID)
		reply = &r
	}
	row := draftRow(tenant, device, connection, draft, reply, n.ChatKey)
	if row.String() != n.DraftRow {
		t.Fatalf("draft row %s, Node derived %s", row, n.DraftRow)
	}
	priv := privateKey(t, n.PrivateKey)
	got, err := seal.OpenDirect(priv, wappie.KindMcpDraft, tenant, row, vectest.B64(t, n.Sealed))
	if err != nil || string(got) != n.Plaintext {
		t.Fatalf("the Node draft: %v", err)
	}
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000cc")
	for why, moved := range map[string]uuid.UUID{
		"another chat":       draftRow(tenant, device, connection, draft, reply, n.ChatKey+"0"),
		"another reply":      draftRow(tenant, device, connection, draft, &other, n.ChatKey),
		"no reply":           draftRow(tenant, device, connection, draft, nil, n.ChatKey),
		"another connection": draftRow(tenant, device, other, draft, reply, n.ChatKey),
		"another draft":      draftRow(tenant, device, connection, other, reply, n.ChatKey),
		"another number":     draftRow(tenant, other, connection, draft, reply, n.ChatKey),
	} {
		if _, err := seal.OpenDirect(priv, wappie.KindMcpDraft, tenant, moved, vectest.B64(t, n.Sealed)); err == nil {
			t.Errorf("%s: the draft opened", why)
		}
	}
}

// internal/wsapi/testdata/frames.json: whole frames as Wappie's ingest
// pipeline sealed them, each field under the row and kind the reader uses.
func TestLegacyFrames(t *testing.T) {
	type media struct {
		MediaKey string `json:"media_key_sealed"`
		Thumb    string `json:"thumb_sealed"`
		FileName string `json:"filename_sealed"`
	}
	type message struct {
		UID          string `json:"uid"`
		ContentKeyID uint32 `json:"content_key_id"`
		Body         string `json:"body_sealed"`
		Payload      string `json:"payload_sealed"`
		Media        media  `json:"media"`
	}
	var f struct {
		Tenant, Device string
		PrivateKey     string `json:"private_key"`
		ContentKey     struct {
			ID     uint32 `json:"id"`
			Sealed string `json:"sealed"`
		} `json:"content_key"`
		Message  message `json:"message"`
		Expected struct {
			Body, Payload, Thumbnail string
			MediaKey                 string `json:"media_key"`
			FileName                 string `json:"file_name"`
		} `json:"expected"`
		Chat struct {
			UID       string `json:"uid"`
			NameKeyID uint32 `json:"name_key_id"`
			Name      string `json:"name_sealed"`
		} `json:"chat"`
		ChatName string `json:"chat_name"`
		Contact  struct {
			UID          string `json:"uid"`
			ContentKeyID uint32 `json:"content_key_id"`
			Push         string `json:"push_name_sealed"`
			Full         string `json:"full_name_sealed"`
			Business     string `json:"business_name_sealed"`
		} `json:"contact"`
		ContactNames struct{ Push, Full, Business string } `json:"contact_names"`
		Avatar       struct {
			UID    string `json:"uid"`
			KeyID  uint32 `json:"key_id"`
			Sealed string `json:"sealed"`
		} `json:"avatar"`
		AvatarBytes string  `json:"avatar_bytes"`
		Relocated   message `json:"relocated"`
	}
	if err := json.Unmarshal(vectest.Raw(t, "wappie/legacy/frames.json"), &f); err != nil {
		t.Fatal(err)
	}
	tenant, device := vectest.UUID(t, f.Tenant), vectest.UUID(t, f.Device)
	priv := privateKey(t, f.PrivateKey)
	ck, err := seal.OpenContentKey[wappie.Kind](priv, tenant, device, f.ContentKey.ID, vectest.B64(t, f.ContentKey.Sealed))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		keyID    uint32
		uid      string
		kind     wappie.Kind
		sealed   string
		want     []byte
		relocate bool
	}{
		{"body", f.Message.ContentKeyID, f.Message.UID, wappie.KindBody, f.Message.Body, []byte(f.Expected.Body), true},
		{"payload", f.Message.ContentKeyID, f.Message.UID, wappie.KindPayload, f.Message.Payload, []byte(f.Expected.Payload), true},
		{"media key", f.Message.ContentKeyID, f.Message.UID, wappie.KindMediaKey, f.Message.Media.MediaKey, vectest.B64(t, f.Expected.MediaKey), true},
		{"thumbnail", f.Message.ContentKeyID, f.Message.UID, wappie.KindThumbnail, f.Message.Media.Thumb, vectest.B64(t, f.Expected.Thumbnail), true},
		{"file name, under the contact-name kind", f.Message.ContentKeyID, f.Message.UID, wappie.KindContactName, f.Message.Media.FileName, []byte(f.Expected.FileName), true},
		{"chat name", f.Chat.NameKeyID, f.Chat.UID, wappie.KindContactName, f.Chat.Name, []byte(f.ChatName), false},
		{"push name", f.Contact.ContentKeyID, f.Contact.UID, wappie.KindPushName, f.Contact.Push, []byte(f.ContactNames.Push), false},
		{"full name", f.Contact.ContentKeyID, f.Contact.UID, wappie.KindFullName, f.Contact.Full, []byte(f.ContactNames.Full), false},
		{"business name", f.Contact.ContentKeyID, f.Contact.UID, wappie.KindBusinessName, f.Contact.Business, []byte(f.ContactNames.Business), false},
		{"avatar", f.Avatar.KeyID, f.Avatar.UID, wappie.KindAvatar, f.Avatar.Sealed, vectest.B64(t, f.AvatarBytes), false},
	} {
		if c.keyID != ck.ID {
			t.Fatalf("%s names content key %d", c.name, c.keyID)
		}
		got, err := ck.Open(c.kind, tenant, vectest.UUID(t, c.uid), vectest.B64(t, c.sealed))
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
		if c.relocate {
			// The same envelopes in a frame with another uid open nothing.
			if _, err := ck.Open(c.kind, tenant, vectest.UUID(t, f.Relocated.UID), vectest.B64(t, c.sealed)); err == nil {
				t.Errorf("%s opened after relocation", c.name)
			}
		}
	}
	if f.Relocated.Body != f.Message.Body {
		t.Fatal("the relocated frame should carry the same envelopes")
	}
}
