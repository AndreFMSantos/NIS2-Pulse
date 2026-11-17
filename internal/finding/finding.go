// Package finding defines the result of a single check. Its JSON form is the
// stable contract between the engine, scoring, reporting and (later) the
// monitoring daemon: human-readable text lives in the report catalog keyed by
// Finding.ID, never here.
package finding

// Area groups findings for per-area scoring.
type Area string

// Areas reported by nis2-pulse.
const (
	AreaEmail     Area = "email"
	AreaDNS       Area = "dns"
	AreaTransport Area = "transport"
	AreaRouting   Area = "routing"
)

// Tier says how a check obtains its data. Active checks open connections to
// the target's own servers and only run when the user passes --active.
type Tier string

// Check tiers.
const (
	TierPassive Tier = "passive"
	TierActive  Tier = "active"
)

// Status is the outcome of a check.
type Status string

// Statuses. Unknown and Info are excluded from scoring; the report shows
// coverage (how many checks produced a verdict).
const (
	StatusPass    Status = "pass"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
	StatusInfo    Status = "info"
)

// Severity is the impact if the check fails. It is empty for findings that
// carry no verdict about impact (typically unknown and info).
type Severity string

// Severities.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Fixer says who can usually correct a finding. An RPKI ROA, for example, is
// normally created by the network provider, not by the domain owner.
type Fixer string

// Fixers.
const (
	FixerOrganization Fixer = "organization"
	FixerProvider     Fixer = "provider"
	FixerUnknown      Fixer = "unknown"
)

// Finding is one verdict about one externally observable property.
type Finding struct {
	// ID is a stable dotted identifier such as "email.dmarc.policy".
	ID       string   `json:"id"`
	Area     Area     `json:"area"`
	Tier     Tier     `json:"tier"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity,omitempty"`
	Fixer    Fixer    `json:"fixer,omitempty"`
	// Evidence is the raw observation (for example a TXT record) so a human
	// can verify what the tool saw.
	Evidence []string `json:"evidence,omitempty"`
	// Detail explains why a status is unknown, or adds machine-oriented context.
	Detail string `json:"detail,omitempty"`
}

// Unknown builds a finding for a check that could not reach a verdict.
func Unknown(id string, area Area, tier Tier, detail string) Finding {
	return Finding{ID: id, Area: area, Tier: tier, Status: StatusUnknown, Detail: detail}
}
