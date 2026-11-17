package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// idMXResolves is the finding about whether the mail hosts named by the MX
// records exist.
const idMXResolves = "email.mx.resolves"

// maxResolveHosts bounds how many MX hosts are looked up (two queries each).
const maxResolveHosts = 10

// hostState is what the A and AAAA lookups of one mail host showed.
type hostState struct {
	host     string
	address  bool // at least one A or AAAA record
	alias    bool // the answer went through a CNAME (forbidden for MX targets)
	nxdomain bool
	failed   bool // a lookup errored or answered SERVFAIL: nothing can be said
}

func lookupHostState(ctx context.Context, r dnsx.Resolver, host string) hostState {
	s := hostState{host: host}
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.Query(ctx, host, qt)
		if err != nil {
			s.failed = true
			continue
		}
		switch resp.Rcode {
		case dns.RcodeSuccess:
		case dns.RcodeNameError:
			s.nxdomain = true
			continue
		default:
			s.failed = true
			continue
		}
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.A, *dns.AAAA:
				s.address = true
			case *dns.CNAME:
				s.alias = true
			}
		}
	}
	return s
}

// mxResolvesFinding checks that every MX host resolves to an address and is not
// an alias. A mail host that does not exist is invisible in the MX record itself
// and in a scan of the domain, but senders bounce or queue the message.
func mxResolvesFinding(ctx context.Context, r dnsx.Resolver, hosts []string) finding.Finding {
	hosts = append([]string(nil), hosts...)
	sort.Strings(hosts)
	var ev []string
	if len(hosts) > maxResolveHosts {
		hosts = hosts[:maxResolveHosts]
		ev = append(ev, fmt.Sprintf("only the first %d MX hosts were examined", maxResolveHosts))
	}

	var okCount, brokenCount, aliasCount, unknownCount int
	for _, h := range hosts {
		s := lookupHostState(ctx, r, h)
		switch {
		case s.address && s.alias:
			okCount++
			aliasCount++
			ev = append(ev, h+": resolves, but through a CNAME (alias)")
		case s.address:
			okCount++
		case s.failed && !s.nxdomain && !s.alias:
			unknownCount++
			ev = append(ev, h+": the lookup failed, so nothing can be said")
		case s.alias:
			brokenCount++
			aliasCount++
			ev = append(ev, h+": a CNAME (alias) that leads to no address")
		case s.nxdomain:
			brokenCount++
			ev = append(ev, h+": the name does not exist (NXDOMAIN)")
		default:
			brokenCount++
			ev = append(ev, h+": no A or AAAA record")
		}
	}

	f := finding.Finding{ID: idMXResolves, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization, Evidence: ev}
	switch {
	case unknownCount == len(hosts):
		return finding.Unknown(idMXResolves, finding.AreaEmail, finding.TierPassive,
			"the A and AAAA lookups of the mail hosts failed")
	case okCount == 0 && brokenCount > 0:
		f.Status = finding.StatusFail
		f.Detail = "none of the mail hosts named by the MX records resolves to an address: senders cannot deliver mail to this domain (RFC 5321 §5.1)"
	case brokenCount > 0:
		f.Status, f.Severity = finding.StatusWarn, finding.SeverityMedium
		f.Detail = "some mail hosts named by the MX records do not resolve: mail still arrives through the others, but redundancy is lost and senders may queue or bounce messages"
	case aliasCount > 0:
		f.Status, f.Severity = finding.StatusWarn, finding.SeverityMedium
		f.Detail = "an MX record points to an alias (CNAME), which RFC 2181 §10.3 forbids; many servers cope, some do not"
	case unknownCount > 0:
		return finding.Unknown(idMXResolves, finding.AreaEmail, finding.TierPassive,
			"the A and AAAA lookups of "+strings.Join(failedHosts(ev), ", ")+" failed")
	default:
		f.Status = finding.StatusPass
		f.Detail = "every mail host named by the MX records resolves to an address"
	}
	return f
}

// failedHosts returns the hosts whose evidence line says the lookup failed.
func failedHosts(ev []string) []string {
	var out []string
	for _, e := range ev {
		if h, ok := strings.CutSuffix(e, ": the lookup failed, so nothing can be said"); ok {
			out = append(out, h)
		}
	}
	return out
}
