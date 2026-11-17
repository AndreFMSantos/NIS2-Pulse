package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// idSubdomainsMX is the finding about the subdomains the user asked to examine.
const idSubdomainsMX = "email.subdomains.mx"

// MaxSubdomains bounds how many subdomains one scan may examine.
const MaxSubdomains = 20

// MailSubdomains examines the MX records of subdomains that the user names. A
// scan of the apex never sees the mail setup of a subdomain, and the names cannot
// be listed from DNS, so the user supplies them (--subdomain), like DKIM
// selectors; nothing is guessed. Only DNS is read, so it is passive.
type MailSubdomains struct {
	Names []string
}

// ID implements engine.Check.
func (MailSubdomains) ID() string { return "email.subdomains" }

// Area implements engine.Check.
func (MailSubdomains) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (MailSubdomains) Tier() finding.Tier { return finding.TierPassive }

// NormalizeSubdomains turns the names given by the user into fully qualified names
// under domain. A name may be relative ("blog" or "mail.blog") or already end with
// the domain; case, spaces and a trailing dot are ignored and duplicates dropped.
// Names that are not valid host names, or that are the domain itself, are errors.
func NormalizeSubdomains(domain string, in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if s == "" {
			continue
		}
		if s == domain {
			return nil, fmt.Errorf("%q is the domain itself: list only subdomains", raw)
		}
		if _, err := netip.ParseAddr(s); err == nil {
			return nil, fmt.Errorf("%q is an IP address: list subdomain names", raw)
		}
		if !strings.HasSuffix(s, "."+domain) {
			s += "." + domain
		}
		target, err := engine.ParseTarget(s)
		if err != nil {
			return nil, fmt.Errorf("invalid subdomain %q: %w", raw, err)
		}
		if !seen[target.Domain] {
			seen[target.Domain] = true
			out = append(out, target.Domain)
		}
	}
	if len(out) > MaxSubdomains {
		return nil, fmt.Errorf("at most %d subdomains per scan, got %d", MaxSubdomains, len(out))
	}
	return out, nil
}

// Run implements engine.Check.
func (c MailSubdomains) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	names, err := NormalizeSubdomains(t.Domain, c.Names)
	if err != nil {
		return []finding.Finding{finding.Unknown(idSubdomainsMX, finding.AreaEmail, finding.TierPassive, err.Error())}
	}

	var (
		evidence               []string
		withMail, lookupFailed int
		worst                  finding.Finding // the worst resolution result among subdomains with MX
		rank                   = -1
	)
	for _, name := range names {
		hosts, nullMX, err := lookupMX(ctx, d.DNS, name)
		switch {
		case err != nil:
			lookupFailed++
			evidence = append(evidence, name+": the MX lookup failed")
		case len(hosts) == 0 && nullMX:
			evidence = append(evidence, name+": null MX (declares it receives no mail)")
		case len(hosts) == 0:
			evidence = append(evidence, name+": no MX record")
		default:
			withMail++
			f := mxResolvesFinding(ctx, d.DNS, hosts)
			evidence = append(evidence, fmt.Sprintf("%s: MX %s, %s", name, strings.Join(hosts, ", "), statusWord(f.Status)))
			for _, e := range f.Evidence {
				evidence = append(evidence, "  "+name+" -> "+e)
			}
			if r := statusRank(f.Status); r > rank {
				rank, worst = r, f
			}
		}
	}

	out := finding.Finding{ID: idSubdomainsMX, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Fixer: finding.FixerOrganization, Evidence: evidence}
	switch {
	case withMail == 0 && lookupFailed == len(names):
		return []finding.Finding{finding.Unknown(idSubdomainsMX, finding.AreaEmail, finding.TierPassive,
			"the MX lookups of the subdomains failed")}
	case withMail == 0:
		out.Status = finding.StatusInfo
		out.Detail = "none of the subdomains examined declares an MX record"
	case worst.Status == finding.StatusUnknown:
		return []finding.Finding{finding.Unknown(idSubdomainsMX, finding.AreaEmail, finding.TierPassive,
			"the mail hosts of the subdomains could not be resolved")}
	default:
		out.Status, out.Severity = worst.Status, worst.Severity
		switch worst.Status {
		case finding.StatusFail:
			out.Detail = "a subdomain declares an MX whose mail hosts do not resolve: mail sent to it cannot be delivered"
		case finding.StatusWarn:
			out.Detail = "a subdomain declares an MX with a mail host that does not resolve or is an alias (CNAME)"
		default:
			out.Detail = "the mail hosts of every subdomain with an MX resolve to an address"
		}
	}
	return []finding.Finding{out}
}

func statusRank(s finding.Status) int {
	switch s {
	case finding.StatusFail:
		return 3
	case finding.StatusWarn:
		return 2
	case finding.StatusUnknown:
		return 1
	default:
		return 0
	}
}

func statusWord(s finding.Status) string {
	switch s {
	case finding.StatusFail:
		return "its hosts do not resolve"
	case finding.StatusWarn:
		return "problem with a host"
	case finding.StatusUnknown:
		return "could not be checked"
	default:
		return "its hosts resolve"
	}
}
