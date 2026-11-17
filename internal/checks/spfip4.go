package checks

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// idSPFIP4 is the informational finding about ip4/ip6 terms that match no
// address of the domain itself or of its mail hosts.
const idSPFIP4 = "email.spf.ip4"

// lookupAddrs returns the A and AAAA addresses of name. Errors and unusual
// response codes yield no addresses: the caller only uses them as a comparison.
func lookupAddrs(ctx context.Context, r dnsx.Resolver, name string) []netip.Addr {
	var out []netip.Addr
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.Query(ctx, name, qt)
		if err != nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.Addr)
			case *dns.AAAA:
				out = append(out, v.Addr)
			}
		}
	}
	return out
}

// spfIP4Finding lists the ip4/ip6 terms of a self-contained record (no include,
// redirect, exists or ptr, which could authorise the real sender) that contain
// no address of the domain itself or of its MX hosts. The typical cause is a
// typo or an outdated address, for example the web server instead of the mail
// server. It is information only: mail may legitimately leave from elsewhere.
func spfIP4Finding(ctx context.Context, r dnsx.Resolver, domain, rec string) (finding.Finding, bool) {
	var nets []netip.Prefix
	for _, t := range parseSPF(rec) {
		if t.modifier {
			if t.name == "redirect" {
				return finding.Finding{}, false
			}
			continue
		}
		switch t.name {
		case "include", "exists", "ptr":
			return finding.Finding{}, false
		case "ip4", "ip6":
			if p, ok := parsePrefix(t.arg); ok {
				nets = append(nets, p)
			}
		}
	}
	if len(nets) == 0 {
		return finding.Finding{}, false
	}

	// Only now, with something to compare, ask for the MX hosts.
	own := lookupAddrs(ctx, r, domain)
	hosts := append([]string(nil), detectMail(ctx, r, domain).hosts...)
	sort.Strings(hosts)
	if len(hosts) > maxResolveHosts {
		hosts = hosts[:maxResolveHosts]
	}
	for _, h := range hosts {
		own = append(own, lookupAddrs(ctx, r, h)...)
	}
	if len(own) == 0 {
		return finding.Finding{}, false
	}

	var unmatched []string
	for _, p := range nets {
		matched := false
		for _, a := range own {
			if p.Contains(a) {
				matched = true
				break
			}
		}
		if !matched {
			unmatched = append(unmatched, "ip4/ip6 term "+p.String()+" contains no address of "+domain+" or of its MX hosts")
		}
	}
	if len(unmatched) == 0 {
		return finding.Finding{}, false
	}
	return finding.Finding{ID: idSPFIP4, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: finding.StatusInfo, Fixer: finding.FixerOrganization, Evidence: unmatched,
		Detail: "this is correct if mail leaves through another server, and a mistake if it was meant to be the mail server of the domain: confirm the real sending address in the headers of a message you sent"}, true
}

// parsePrefix reads the argument of an ip4/ip6 term: an address with an
// optional prefix length.
func parsePrefix(arg string) (netip.Prefix, bool) {
	if !strings.Contains(arg, "/") {
		a, err := netip.ParseAddr(arg)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(arg)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}
