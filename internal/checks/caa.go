package checks

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the CAA check.
const (
	idCAAPresent = "dns.caa.present"
	idCAAIssue   = "dns.caa.issue"
	idCAAIodef   = "dns.caa.iodef"
)

// CAA checks Certification Authority Authorization records (RFC 8659), which
// tell public CAs whether they may issue certificates for the domain.
//
// The lookup climbs the tree from the domain upward and stops at the first
// name that has a CAA RRset, or after the organisational domain: it never asks
// for the TLD or any other public suffix.
type CAA struct{}

// ID implements engine.Check.
func (CAA) ID() string { return "dns.caa" }

// Area implements engine.Check.
func (CAA) Area() finding.Area { return finding.AreaDNS }

// Tier implements engine.Check.
func (CAA) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (CAA) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	unknown := func(err error) []finding.Finding {
		var out []finding.Finding
		for _, id := range []string{idCAAPresent, idCAAIssue, idCAAIodef} {
			out = append(out, finding.Unknown(id, finding.AreaDNS, finding.TierPassive, err.Error()))
		}
		return out
	}

	var records []*dns.CAA
	foundAt := ""
	for _, name := range climb(t.Domain) {
		resp, err := d.DNS.Query(ctx, name, dns.TypeCAA)
		if err != nil {
			return unknown(err)
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			return unknown(fmt.Errorf("resolver returned rcode %d for %s CAA", resp.Rcode, name))
		}
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				records = append(records, c)
			}
		}
		if len(records) > 0 {
			foundAt = name
			break
		}
	}

	if len(records) == 0 {
		return []finding.Finding{{
			ID: idCAAPresent, Area: finding.AreaDNS, Tier: finding.TierPassive,
			Status: finding.StatusWarn, Severity: finding.SeverityLow, Fixer: finding.FixerOrganization,
			Detail: "no CAA record: any certificate authority may issue certificates for this domain",
		}}
	}

	present := caaFinding(idCAAPresent, finding.StatusPass, nil)
	if foundAt != t.Domain {
		present.Detail = fmt.Sprintf("CAA RRset found at %s and inherited by %s", foundAt, t.Domain)
	}
	return []finding.Finding{present, caaIssueFinding(records), caaIodefFinding(records)}
}

// climb lists the names to query: the domain and its ancestors up to and
// including the organisational domain.
func climb(domain string) []string {
	names := []string{domain}
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return names
	}
	for cur := domain; cur != org; {
		_, rest, ok := strings.Cut(cur, ".")
		if !ok {
			break
		}
		cur = rest
		names = append(names, cur)
	}
	return names
}

func caaFinding(id string, status finding.Status, evidence []string) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaDNS, Tier: finding.TierPassive,
		Status: status, Severity: finding.SeverityLow, Fixer: finding.FixerOrganization, Evidence: evidence}
}

func present(c *dns.CAA) string { return fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value) }

func caaIssueFinding(records []*dns.CAA) finding.Finding {
	var restricting, all []string
	var issue int
	allForbid := true
	for _, c := range records {
		all = append(all, present(c))
		switch strings.ToLower(c.Tag) {
		case "issue":
			issue++
			restricting = append(restricting, present(c))
			// The value is "[domain] [; parameters]"; an empty domain forbids issuance.
			if ca, _, _ := strings.Cut(c.Value, ";"); strings.TrimSpace(ca) != "" {
				allForbid = false
			}
		case "issuewild":
			restricting = append(restricting, present(c))
		}
	}

	switch {
	case issue == 0:
		f := caaFinding(idCAAIssue, finding.StatusWarn, all)
		f.Detail = "no issue property: the records do not restrict which CAs may issue certificates"
		return f
	case allForbid:
		f := caaFinding(idCAAIssue, finding.StatusInfo, restricting)
		f.Detail = "no CA is authorised to issue certificates for this domain"
		return f
	default:
		return caaFinding(idCAAIssue, finding.StatusPass, restricting)
	}
}

func caaIodefFinding(records []*dns.CAA) finding.Finding {
	var iodef []string
	for _, c := range records {
		if strings.EqualFold(c.Tag, "iodef") {
			iodef = append(iodef, present(c))
		}
	}
	if len(iodef) == 0 {
		f := caaFinding(idCAAIodef, finding.StatusInfo, nil)
		f.Detail = "no iodef contact: CAs cannot report certificate requests that violate the policy"
		return f
	}
	return caaFinding(idCAAIodef, finding.StatusPass, iodef)
}
