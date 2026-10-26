package contract

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/thehappieco/kit/jcs"
)

// The command's MAC (SPEC section 11.19; the platform's decision 0054: a
// command is signed with the app and the secret's generation), beside the
// signed feed answer that carries it, so that an app keeps each command
// with its own proof in its ledger:
//
//	mac = "v1=" + lowercase hex(HMAC-SHA256(key = the secret's 43-character text,
//	      msg = "thehappie-platform-command/v1" || "\n" || app || "\n" ||
//	            JCS(the command as received, without "mac")))
//
// The command is taken as received: decoded into generic JSON values, its
// mac member removed, and the rest canonicalized (RFC 8785, the kit's jcs),
// never a typed struct encoded again, so that a member a newer platform
// adds, at the top or in params, keeps the MAC whole, and every time stays
// the string it was (.120Z included).

// CommandMACLabel opens the message a command's MAC covers.
const CommandMACLabel = "thehappie-platform-command/v1"

// ErrCommandMAC is a command whose mac holds under none of the secrets an
// app holds, or that has none: the app does not run it, refuses it as
// invalid_command and writes it to its security log.
var ErrCommandMAC = errors.New("contract: the command's mac does not hold")

// canonicalCommand is the JCS text of raw, a command as received, without
// its mac member, and that member's value. raw must be one well-formed
// JSON object: valid UTF-8, no escape of half a surrogate pair, no member
// twice anywhere, and only what JCS writes (null, booleans, strings,
// integers within ±(2^53−1), arrays and objects).
func canonicalCommand(raw []byte) (canonical []byte, mac string, err error) {
	if !wellFormed(raw) {
		return nil, "", invalid("command: not one well-formed JSON object, or a member twice")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if dec.Decode(&v) != nil || v == nil {
		return nil, "", invalid("command: not a JSON object")
	}
	if m, ok := v["mac"]; ok {
		s, isString := m.(string)
		if !isString {
			return nil, "", invalid("command: mac")
		}
		mac = s
		delete(v, "mac")
	}
	canonical, err = jcs.Marshal(v)
	if err != nil {
		return nil, "", invalid("command: no canonical text")
	}
	return canonical, mac, nil
}

// commandMAC is the MAC of a canonical command for app under secret.
func commandMAC(canonical []byte, app, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(CommandMACLabel + "\n" + app + "\n"))
	h.Write(canonical)
	return "v1=" + hex.EncodeToString(h.Sum(nil))
}

// SignCommand returns the command raw, a JSON object, with its mac member
// set to the MAC of the rest under app and secret, as the JCS text of the
// whole: the platform's, each time it puts a command in a feed answer, with
// the secret it signs that answer with. A mac raw holds already is
// replaced. secret must be a secret (CheckSecrets), and app an app's id.
func SignCommand(raw []byte, app, secret string) ([]byte, error) {
	if !validSecret(secret) {
		return nil, ErrSecret
	}
	if !ValidApp(app) {
		return nil, invalid("app")
	}
	canonical, _, err := canonicalCommand(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	v["mac"] = commandMAC(canonical, app, secret)
	return jcs.Marshal(v)
}

// VerifyCommand checks the mac of raw, a command as received by app, with
// each secret the app holds (its current and next during a rotation): it
// never needs the command's secret member. A command whose mac holds under
// none, or that has none, is ErrCommandMAC, and so is every command under a
// list that holds a key that is not a secret, an empty one above all. One
// that is not a well-formed JSON object, or holds what JCS does not write
// (a fraction, an integer past 2^53−1), is ErrInvalid. A command that
// verifies is decoded as an app decodes what the platform sends: a member
// it does not know is ignored, and a member counts only named exactly as
// written; Validate, or ValidateIn once the app knows the workspace's
// kind, is the app's next step, and the feed item's cseq must be the
// command's own.
func VerifyCommand(raw []byte, app string, secrets []string) (Command, error) {
	if len(secrets) == 0 || !ValidApp(app) {
		return Command{}, ErrCommandMAC
	}
	for _, s := range secrets {
		if !validSecret(s) {
			return Command{}, ErrCommandMAC
		}
	}
	canonical, mac, err := canonicalCommand(raw)
	if err != nil {
		return Command{}, err
	}
	if !validMAC(mac) {
		return Command{}, ErrCommandMAC
	}
	ok := false
	for _, s := range secrets {
		if hmac.Equal([]byte(commandMAC(canonical, app, s)), []byte(mac)) {
			ok = true
		}
	}
	if !ok {
		return Command{}, ErrCommandMAC
	}
	var c Command
	if err := json.Unmarshal(exactOnly(raw, reflect.TypeFor[Command]()), &c); err != nil {
		return Command{}, invalid("command: it does not decode")
	}
	return c, nil
}
