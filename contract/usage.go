package contract

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"
)

// The usage report (SPEC section 11.20): an app tells the platform, for one
// workspace, the bytes it stores for each hosted item, absolutely,
// PUT /contract/v1/workspaces/{id}/usage. Bytes per item cross the contract
// only here (a numbers row's bytes is deprecated). No figure of a report is
// ever logged: Usage's String, GoString and LogValue name its app,
// workspace, usage_seq and rule_version alone, and no error of this
// package carries a figure.

// The values and bounds of a usage report.
const (
	UsageV    = 1
	UsageType = "usage"
	// UsageReportBodyLimit is the body limit of the usage call
	// (UsageBodyLimit is the token part's usage call's).
	UsageReportBodyLimit = 1 << 20
	// MaxUsageItems is the most items one report lists.
	MaxUsageItems = 2000
	// MaxUsageMeasuredAhead is how far after the platform's clock a
	// report's measured_at may be.
	MaxUsageMeasuredAhead = 60 * time.Second
	// MaxUsageSeqAhead is how far ahead of the platform's clock, in
	// milliseconds, a report's usage_seq may be: a day.
	MaxUsageSeqAhead = 24 * time.Hour
	// RecentDays are the whole UTC days before the day of measured_at that
	// count as recent; the same days keep a trim's floor.
	RecentDays = 90
)

// usageStates are an item's states in a report, as in the snapshot.
var usageStates = []string{StateActive, StateSyncPaused, StateDeleted}

// UsageStates are a report item's states. It returns a copy.
func UsageStates() []string { return slices.Clone(usageStates) }

// ruleVersionRE is a measurement rule's name and version:
// wappie-storage/1, mailie-usage/1, fakeproduct-usage/1.
var ruleVersionRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}/[1-9][0-9]{0,5}$`)

// ValidRuleVersion reports whether s names a measurement rule and its
// version, ^[a-z][a-z0-9-]{0,31}/[1-9][0-9]{0,5}$. A new rule is a new
// version.
func ValidRuleVersion(s string) bool { return ruleVersionRE.MatchString(s) }

// Usage is an app's absolute report of one workspace: everything it stores
// there, by hosted item, live or deleted until its purge. A connected item
// is never listed. The platform reads it strictly (DecodeStrict), then
// ValidateAt on its own clock.
type Usage struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	App         string `json:"app"`
	WorkspaceID string `json:"workspace_id"`
	// UsageSeq is the app's clock in milliseconds when it measured, kept
	// rising across a restart and a restore. The platform keeps only a
	// report above the one it holds.
	UsageSeq int64 `json:"usage_seq"`
	// RuleVersion is the app's measurement rule (ValidRuleVersion).
	RuleVersion string `json:"rule_version"`
	// MeasuredAt is when the figures were read; freshness counts from it.
	MeasuredAt Time `json:"measured_at"`
	// TotalBytes is the sum of every item's Bytes and SharedBytes, exactly.
	TotalBytes int64 `json:"total_bytes"`
	// SharedBytes are bytes no single item owns (Wappie's objects several
	// numbers reference, and unassigned ones); 0 in Mailie.
	SharedBytes int64       `json:"shared_bytes"`
	Items       []UsageItem `json:"items"`
}

// UsageItem is one hosted item's bytes.
type UsageItem struct {
	// ID is the item's id, as in the access snapshot.
	ID string `json:"id"`
	// State is StateActive, StateSyncPaused or StateDeleted.
	State string `json:"state"`
	// PurgeAt is set exactly on StateDeleted.
	PurgeAt *Time `json:"purge_at"`
	// Bytes is everything the item stores, the parts below included.
	Bytes int64 `json:"bytes"`
	// RecentBytes are its bytes dated on or after RecentFrom(MeasuredAt).
	RecentBytes int64 `json:"recent_bytes"`
	// UndatedBytes are its messages with no date and what belongs to them;
	// 0 in Mailie. They count as the oldest at a trim.
	UndatedBytes int64 `json:"undated_bytes"`
	// FixedBytes are what keeps the item running and is no message; they
	// go only without a plan.
	FixedBytes int64 `json:"fixed_bytes"`
}

// Validate checks a report's types and bounds: its app (one the part
// knows), workspace, usage_seq, rule_version and measured_at; every
// integer from 0 to MaxSafeInteger; total_bytes the exact sum of the
// items' bytes and shared_bytes; at most MaxUsageItems items, each id once,
// each state of UsageStates, purge_at exactly on deleted, and
// recent_bytes + undated_bytes + fixed_bytes at most bytes; and, for
// Mailie, shared_bytes and every undated_bytes 0. An empty report (no
// items, totals 0) is valid. Its errors name the member, never a figure.
func (u Usage) Validate() error {
	_, known := AppItemKind(u.App)
	switch {
	case u.V != UsageV:
		return invalid("v")
	case u.Type != UsageType:
		return invalid("type")
	case !ValidApp(u.App) || !known:
		return invalid("app")
	case !ValidUUID(u.WorkspaceID):
		return invalid("workspace_id")
	case u.UsageSeq < 1 || u.UsageSeq > MaxSafeInteger:
		return invalid("usage_seq")
	case !ValidRuleVersion(u.RuleVersion):
		return invalid("rule_version")
	case u.MeasuredAt.IsZero():
		return invalid("measured_at")
	case !safeCount(u.TotalBytes) || !safeCount(u.SharedBytes):
		return invalid("total_bytes and shared_bytes are 0 to 2^53 - 1")
	case u.App == "mailie" && u.SharedBytes != 0:
		return invalid("shared_bytes is 0 in Mailie")
	case u.Items == nil || len(u.Items) > MaxUsageItems:
		return invalid("items")
	}
	sum := u.SharedBytes
	seen := make(map[string]bool, len(u.Items))
	for _, it := range u.Items {
		switch {
		case !ValidItemID(it.ID) || seen[it.ID]:
			return invalid("items[].id")
		case !oneOf(it.State, usageStates):
			return invalid("items[].state")
		case (it.PurgeAt != nil) != (it.State == StateDeleted):
			return invalid("items[].purge_at is set exactly on deleted")
		case it.PurgeAt != nil && it.PurgeAt.IsZero():
			return invalid("items[].purge_at")
		case !safeCount(it.Bytes) || !safeCount(it.RecentBytes) || !safeCount(it.UndatedBytes) || !safeCount(it.FixedBytes):
			return invalid("items[]: every figure is 0 to 2^53 - 1")
		case it.RecentBytes+it.UndatedBytes+it.FixedBytes > it.Bytes:
			return invalid("items[]: recent_bytes + undated_bytes + fixed_bytes is at most bytes")
		case u.App == "mailie" && it.UndatedBytes != 0:
			return invalid("items[].undated_bytes is 0 in Mailie")
		case it.Bytes > MaxSafeInteger-sum:
			return invalid("total_bytes is at most 2^53 - 1")
		}
		seen[it.ID] = true
		sum += it.Bytes
	}
	if sum != u.TotalBytes {
		return invalid("total_bytes is the sum of items[].bytes and shared_bytes")
	}
	return nil
}

// ValidateAt is Validate, and the platform's two checks on its own clock
// now: measured_at at most MaxUsageMeasuredAhead after it, and usage_seq
// no more than MaxUsageSeqAhead (in milliseconds) ahead of it. The app
// checks the same on its own clock before it sends (Client.PutUsage).
func (u Usage) ValidateAt(now time.Time) error {
	if err := u.Validate(); err != nil {
		return err
	}
	switch {
	case u.MeasuredAt.After(now.Add(MaxUsageMeasuredAhead)):
		return invalid("measured_at is at most %s after the platform's clock", MaxUsageMeasuredAhead)
	case u.UsageSeq > now.UnixMilli()+MaxUsageSeqAhead.Milliseconds():
		return invalid("usage_seq is at most a day ahead of the platform's clock")
	}
	return nil
}

// String names the report's app, workspace, usage_seq and rule_version,
// and no figure.
func (u Usage) String() string {
	return fmt.Sprintf("contract.Usage{App: %q, WorkspaceID: %q, UsageSeq: %d, RuleVersion: %q, Items: %s}",
		u.App, u.WorkspaceID, u.UsageSeq, u.RuleVersion, Ellipsis)
}

// GoString is String, for %#v.
func (u Usage) GoString() string { return u.String() }

// LogValue is the report's app, workspace, usage_seq and rule_version: what
// the platform and the app may log of a report, never a figure.
func (u Usage) LogValue() slog.Value {
	return slog.GroupValue(slog.String("app", u.App), slog.String("workspace_id", u.WorkspaceID),
		slog.Int64("usage_seq", u.UsageSeq), slog.String("rule_version", u.RuleVersion))
}

// UsageAnswer is the platform's signed 200 to a usage report: exactly
// {"accepted": true, "kept": bool}. Kept is true when, after the request,
// the platform holds a report of this usage_seq with this body (a retry of
// the held report is answered as its first send), and false otherwise:
// while the platform only validates, for a lower usage_seq or an equal one
// with another body, for a closed personal workspace, and for a closed team
// past its 30 days. It never tells which. The app treats either as
// delivered.
type UsageAnswer struct {
	Accepted bool `json:"accepted"`
	Kept     bool `json:"kept"`
}

// usageAnswerWire is UsageAnswer without its own UnmarshalJSON.
type usageAnswerWire UsageAnswer

// UnmarshalJSON reads the answer strictly: exactly its two members, each a
// boolean, none null. Validate checks that it is accepted.
func (a *UsageAnswer) UnmarshalJSON(b []byte) error {
	var w usageAnswerWire
	if err := decodeExact(b, &w, "usage answer"); err != nil {
		return err
	}
	*a = UsageAnswer(w)
	return nil
}

// Validate checks that the answer is accepted: a usage report is never
// refused in a 200.
func (a UsageAnswer) Validate() error {
	if !a.Accepted {
		return invalid("accepted")
	}
	return nil
}

// The date rule (SPEC section 11.20): both apps date bytes the same way,
// for recent_bytes and for a trim's floor. Which date a row takes (a
// message's, a receipt's own, Mailie's internal_date in UTC, an object's
// newest referencing message on that number) is the app's; the kit gives
// the day arithmetic both share.

// RecentFrom is the first instant whose bytes are recent in a report
// measured at measuredAt: 00:00 UTC of the UTC date of measuredAt, less
// RecentDays whole days. A date on or after it is recent.
func RecentFrom(measuredAt time.Time) time.Time {
	y, m, d := measuredAt.UTC().Date()
	return time.Date(y, m, d-RecentDays, 0, 0, 0, 0, time.UTC)
}

// IsRecent reports whether bytes dated at date are recent in a report
// measured at measuredAt. A date after measuredAt counts as measuredAt, so
// a future-dated row is recent, never taken before older ones. Undated
// bytes are never recent: the caller counts them apart, as the oldest.
func IsRecent(date, measuredAt time.Time) bool {
	if date.After(measuredAt) {
		date = measuredAt
	}
	return !date.Before(RecentFrom(measuredAt))
}

// TrimFloor is a trim order's floor for an order issued at issuedAt, as
// YYYY-MM-DD: the same day RecentFrom gives for issuedAt. An order with a
// plan never deletes a row dated on or after 00:00 UTC of that day.
func TrimFloor(issuedAt time.Time) string { return RecentFrom(issuedAt).Format(time.DateOnly) }
