package checks

import (
	"context"
	"sort"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// idMXProfile is the finding produced by the MX check.
const idMXProfile = "email.mx.profile"

// mailProfile describes whether a domain receives email, as far as its MX
// records say. Receiving is not sending: a domain without MX may still send,
// so the profile only softens how a MISSING SPF or DMARC record is judged.
type mailProfile struct {
	known  bool     // the MX lookup succeeded
	hosts  []string // MX host names, lowercase, no trailing dot
	nullMX bool     // an explicit null MX (RFC 7505): "this domain receives no mail"
	err    error
}

// detectMail looks up the MX records of domain. A failed lookup leaves the
// profile unknown, and callers then keep their strict verdict.
func detectMail(ctx context.Context, r dnsx.Resolver, domain string) mailProfile {
	hosts, nullMX, err := lookupMX(ctx, r, domain)
	return mailProfile{known: err == nil, hosts: hosts, nullMX: nullMX, err: err}
}

// noMail reports that the domain is known not to receive email: either it
// declares a null MX, or it has no MX at all.
func (m mailProfile) noMail() bool { return m.known && len(m.hosts) == 0 }

// MX describes how the domain receives email (RFC 5321 §5.1, RFC 7505).
type MX struct{}

// ID implements engine.Check.
func (MX) ID() string { return "email.mx" }

// Area implements engine.Check.
func (MX) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (MX) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (MX) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	m := detectMail(ctx, d.DNS, t.Domain)
	f := finding.Finding{ID: idMXProfile, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityLow, Fixer: finding.FixerOrganization}

	switch {
	case !m.known:
		return []finding.Finding{finding.Unknown(idMXProfile, finding.AreaEmail, finding.TierPassive, m.err.Error())}
	case len(m.hosts) > 0:
		hosts := append([]string(nil), m.hosts...)
		sort.Strings(hosts)
		f.Status, f.Severity, f.Evidence = finding.StatusInfo, "", hosts
		f.Detail = "the domain receives email, so SPF, DMARC and MTA-STS matter for it"
		return []finding.Finding{f, mxResolvesFinding(ctx, d.DNS, hosts)}
	case m.nullMX:
		f.Status = finding.StatusPass
		f.Detail = "the domain declares with a null MX (RFC 7505) that it does not receive email"
	default:
		f.Status = finding.StatusWarn
		f.Detail = "no MX record: senders fall back to the A/AAAA record of the domain (RFC 5321 §5.1). " +
			"If the domain does not receive email, publish a null MX (MX 0 .) to say so"
	}
	return []finding.Finding{f}
}
