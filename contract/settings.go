package contract

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The settings part's documents (SPEC section 11.19; the platform's
// decision 0054): what an app reports of its settings, per workspace
// section and per person, from which the console draws the app's settings
// pages. Each is absolute; the platform keeps the latest per (app,
// workspace, section) and per (app, sub).

// The values of a settings document.
const (
	SettingsV          = 1
	SettingsType       = "settings"
	PersonSettingsType = "person_settings"

	// SettingsBodyLimit is a section's call's body limit, and
	// PersonSettingsBodyLimit a person's.
	SettingsBodyLimit       = 1 << 20
	PersonSettingsBodyLimit = 256 << 10
)

// The sections (section) and their producers (producer).
const (
	SectionNumbers       = "numbers"
	SectionIntegrations  = "integrations"
	SectionMCP           = "mcp"
	SectionInstallations = "installations"
	SectionEmailAccounts = "email-accounts"
	SectionPermissions   = "permissions"
	// SectionPerson is a person's kinds' section; a person's document
	// names no section.
	SectionPerson = "person"

	ProducerWappie      = "wappie"
	ProducerWappieCloud = "wappie-cloud"
	ProducerMailie      = "mailie"
)

// sectionDef is one section of an app: who produces it, whether that
// producer sends access snapshots, the kinds it runs, and its data.
type sectionDef struct {
	producer string
	// noSnapshot: the producer sends no access snapshot, so its sections'
	// snapshot_seq is null (wappie-cloud).
	noSnapshot bool
	data       func() sectionData
}

// sectionData is a section's or a person's data, checked for one app.
type sectionData interface {
	validate(app string) error
}

var wappieSections = map[string]sectionDef{
	SectionNumbers:       {producer: ProducerWappie, data: func() sectionData { return new(NumbersSettings) }},
	SectionIntegrations:  {producer: ProducerWappie, data: func() sectionData { return new(IntegrationsSettings) }},
	SectionMCP:           {producer: ProducerWappie, data: func() sectionData { return new(MCPSettings) }},
	SectionInstallations: {producer: ProducerWappieCloud, noSnapshot: true, data: func() sectionData { return new(InstallationsSettings) }},
	SectionPerson:        {producer: ProducerWappie, data: func() sectionData { return new(WappiePersonSettings) }},
}

var mailieSections = map[string]sectionDef{
	SectionEmailAccounts: {producer: ProducerMailie, data: func() sectionData { return new(EmailAccountsSettings) }},
	SectionPermissions:   {producer: ProducerMailie, data: func() sectionData { return new(PermissionsSettings) }},
	SectionPerson:        {producer: ProducerMailie, data: func() sectionData { return new(MailiePersonSettings) }},
}

// ReferenceApp is the platform's reference app, in development
// (tools/fakeproduct). It has Wappie's sections, kinds and codes, each
// produced by the app itself under its own id, with snapshots. An app id
// other than wappie, mailie and this one has none.
const ReferenceApp = "fakeproduct"

// sectionsOf are app's sections, its person's under SectionPerson.
func sectionsOf(app string) map[string]sectionDef {
	switch app {
	case "wappie":
		return wappieSections
	case "mailie":
		return mailieSections
	case ReferenceApp:
	default:
		return nil
	}
	own := map[string]sectionDef{}
	for name, def := range wappieSections {
		own[name] = sectionDef{producer: app, data: def.data}
	}
	return own
}

// Sections are app's workspace sections, in no order: never SectionPerson,
// whose document is a person's. It returns a copy.
func Sections(app string) []string {
	var out []string
	for name := range sectionsOf(app) {
		if name != SectionPerson {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// SectionProducer is the producer of app's section (SectionPerson for a
// person's document), or "" for none.
func SectionProducer(app, section string) string { return sectionsOf(app)[section].producer }

// SettingsDoc is one section of one platform workspace, as one producer of
// an app measured it: PUT /contract/v1/workspaces/{id}/settings/{section}.
type SettingsDoc struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	App         string `json:"app"`
	Section     string `json:"section"`
	Producer    string `json:"producer"`
	WorkspaceID string `json:"workspace_id"`
	// StateSeq rises per (app, producer, workspace), and is shared with
	// that producer's access snapshots: the app's clock in milliseconds,
	// kept rising.
	StateSeq int64 `json:"state_seq"`
	// SnapshotSeq is the access snapshot it was measured with, or the
	// latest sent before it; null for a producer that sends none
	// (wappie-cloud).
	SnapshotSeq *int64 `json:"snapshot_seq"`
	MeasuredAt  Time   `json:"measured_at"`
	// Truncated: the producer cut a list to fit the call's limit.
	Truncated bool `json:"truncated"`
	// Accepts are the command kinds this producer runs now for this
	// section, a subset of the section's (CommandKinds).
	Accepts []string `json:"accepts"`
	// Data is the section's members (NumbersSettings, IntegrationsSettings,
	// MCPSettings, InstallationsSettings, EmailAccountsSettings,
	// PermissionsSettings), decoded strictly by Validate.
	Data json.RawMessage `json:"data"`
}

// PersonSettingsDoc is one person's own settings in an app, across
// workspaces: PUT /contract/v1/accounts/{sub}/settings.
type PersonSettingsDoc struct {
	V        int    `json:"v"`
	Type     string `json:"type"`
	App      string `json:"app"`
	Producer string `json:"producer"`
	Sub      string `json:"sub"`
	// StateSeq rises per (app, sub).
	StateSeq   int64    `json:"state_seq"`
	MeasuredAt Time     `json:"measured_at"`
	Truncated  bool     `json:"truncated"`
	Accepts    []string `json:"accepts"`
	// Data is the person's members (WappiePersonSettings,
	// MailiePersonSettings), decoded strictly by Validate.
	Data json.RawMessage `json:"data"`
}

// Validate checks every member of a section's document, and decodes its
// data strictly, as the platform decodes what an app sends, into the
// section's type, whose every member, list and code it checks too: an
// unknown code, a name with an @ or a run of digits, or a member missing,
// unknown or not named exactly refuses the whole document.
func (d SettingsDoc) Validate() error {
	sections := sectionsOf(d.App)
	def, ok := sections[d.Section]
	switch {
	case d.V != SettingsV:
		return invalid("v")
	case d.Type != SettingsType:
		return invalid("type")
	case sections == nil:
		return invalid("app")
	case !ok || d.Section == SectionPerson:
		return invalid("section is not one of the app's")
	case d.Producer != def.producer:
		return invalid("producer is not the section's")
	case !ValidUUID(d.WorkspaceID):
		return invalid("workspace_id")
	case d.StateSeq < 1:
		return invalid("state_seq")
	case def.noSnapshot && d.SnapshotSeq != nil:
		return invalid("snapshot_seq is null for a producer that sends no snapshot")
	case !def.noSnapshot && (d.SnapshotSeq == nil || *d.SnapshotSeq < 1):
		return invalid("snapshot_seq")
	case d.MeasuredAt.IsZero():
		return invalid("measured_at")
	}
	if err := checkAccepts(d.App, d.Section, d.Accepts); err != nil {
		return err
	}
	return validateData(d.App, def, d.Data)
}

// Validate checks every member of a person's document, and decodes its data
// strictly into the app's person type, as SettingsDoc.Validate does.
func (d PersonSettingsDoc) Validate() error {
	sections := sectionsOf(d.App)
	def := sections[SectionPerson]
	switch {
	case d.V != SettingsV:
		return invalid("v")
	case d.Type != PersonSettingsType:
		return invalid("type")
	case sections == nil:
		return invalid("app")
	case d.Producer != def.producer:
		return invalid("producer is not the app's")
	case !ValidUUID(d.Sub):
		return invalid("sub")
	case d.StateSeq < 1:
		return invalid("state_seq")
	case d.MeasuredAt.IsZero():
		return invalid("measured_at")
	}
	if err := checkAccepts(d.App, SectionPerson, d.Accepts); err != nil {
		return err
	}
	return validateData(d.App, def, d.Data)
}

// checkAccepts refuses a list that is null, or names a kind twice or a
// kind of another section.
func checkAccepts(app, section string, accepts []string) error {
	if accepts == nil {
		return invalid("accepts")
	}
	seen := map[string]bool{}
	for _, kind := range accepts {
		k, ok := commandKindsOf(app)[kind]
		if !ok || k.Section != section || seen[kind] {
			return invalid("accepts names a kind twice, or one of another section")
		}
		seen[kind] = true
	}
	return nil
}

// validateData decodes a document's data strictly and checks it.
func validateData(app string, def sectionDef, raw json.RawMessage) error {
	data := def.data()
	if err := decodeExact(raw, data, "data"); err != nil {
		return err
	}
	return data.validate(app)
}

// DecodeData decodes a valid document's data into the section's type: a
// *NumbersSettings, *IntegrationsSettings, *MCPSettings,
// *InstallationsSettings, *EmailAccountsSettings or *PermissionsSettings.
// It validates the document first.
func (d SettingsDoc) DecodeData() (any, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	data := sectionsOf(d.App)[d.Section].data()
	return data, decodeExact(d.Data, data, "data")
}

// DecodeData decodes a valid person's document's data into the app's type:
// a *WappiePersonSettings or *MailiePersonSettings.
func (d PersonSettingsDoc) DecodeData() (any, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	data := sectionsOf(d.App)[SectionPerson].data()
	return data, decodeExact(d.Data, data, "data")
}

// ---------------------------------------------------------------------------
// Values a document carries
// ---------------------------------------------------------------------------

// revisionRE is a text's revision, such as 2026-10-api-keys-2.
var revisionRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidRevision reports whether s names a text's revision: 1 to 64 of
// [A-Za-z0-9._-].
func ValidRevision(s string) bool { return revisionRE.MatchString(s) }

// hostLabelRE is one label of a host: lowercase ASCII letters, digits and
// hyphens, neither starting nor ending with a hyphen.
var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHost reports whether s is a host a document may name: a lowercase
// ASCII hostname of at most 253 bytes (A-labels), its labels of 1 to 63
// letters, digits and hyphens, no hyphen at either end of one, no trailing
// dot, and a last label that starts with a letter, so that no address
// passes for a name: neither one of digits nor one a WHATWG URL parser
// reads as a number (0x7f000001, 10.0.0.0x1).
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !hostLabelRE.MatchString(l) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return last[0] >= 'a' && last[0] <= 'z'
}

// ValidOrigin reports whether s is an installation's origin: https://, a
// host (ValidHost) or a public IPv4 address in dotted decimal, and an
// optional port of 1 to 65535 with no leading zero; no path, query,
// fragment or user information.
func ValidOrigin(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		return false
	}
	host, port, hasPort := strings.Cut(rest, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if ValidHost(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is4() && addr.String() == host && publicIPv4(addr)
}

// nonPublic are the IPv4 ranges that are no public address: this network,
// private, shared, loopback, link-local, the IETF's and the documentation
// ranges, benchmarking, multicast and reserved (RFC 6890).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(a netip.Addr) bool {
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// labelOrNull reports whether p is null or a label (ValidLabel).
func labelOrNull(p *string) bool { return p == nil || ValidLabel(*p) }

// subOrNull reports whether p is null or a sub.
func subOrNull(p *string) bool { return p == nil || ValidUUID(*p) }

// timeOrNull reports whether p is null or a time that decoded.
func timeOrNull(p *Time) bool { return p == nil || !p.IsZero() }

// codeOrNull reports whether p is null or one of set.
func codeOrNull(p *string, set []string) bool { return p == nil || oneOf(*p, set) }

// codesOnce reports whether every code of list is one of set, each once,
// and the list is not null.
func codesOnce(list, set []string) bool {
	if list == nil {
		return false
	}
	seen := map[string]bool{}
	for _, c := range list {
		if !oneOf(c, set) || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

// idsOnce reports whether list holds at most max ids, each once and each
// valid, and is not null.
func idsOnce(list []string, max int, valid func(string) bool) bool {
	if list == nil || len(list) > max {
		return false
	}
	seen := map[string]bool{}
	for _, id := range list {
		if !valid(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
