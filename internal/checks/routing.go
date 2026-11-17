package checks

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
)

// Finding IDs produced by the routing check.
const (
	idRoutingOrigin = "routing.origin"
	idRoutingROA    = "routing.rpki.roa"
	idRoutingGeo    = "routing.geo"
)

// MaxRoutingAddresses bounds how many of the domain's addresses are sent to
// RIPEstat. The cap keeps the number of calls to a third party predictable
// (at most three per address) and is disclosed in the report when it applies.
const MaxRoutingAddresses = 12

// maxRoutingMX bounds the mail hosts whose addresses are included.
const maxRoutingMX = 10

// Routing looks at the Internet routing of the addresses behind the domain
// (its own A/AAAA and those of its MX hosts): which AS originates the
// covering prefix, whether RPKI authorises that origin (RFC 6811) and which
// countries a geolocation database associates with the addresses.
//
// It is a passive check: it never connects to the audited servers. The data
// comes from RIPEstat, a third party that is told only public addresses, ASNs
// and prefixes of the audited domain. Addresses that are not public are never
// sent. The check is informative about who must act: a ROA is created by the
// holder of the prefix, usually the network or hosting provider.
type Routing struct{}

// ID implements engine.Check.
func (Routing) ID() string { return "routing" }

// Area implements engine.Check.
func (Routing) Area() finding.Area { return finding.AreaRouting }

// Tier implements engine.Check.
func (Routing) Tier() finding.Tier { return finding.TierPassive }

// Timeout implements engine.Timeouter: up to three sequential calls per
// address, to a public API.
func (Routing) Timeout() time.Duration { return 60 * time.Second }

// Run implements engine.Check.
func (Routing) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	unknownAll := func(detail string) []finding.Finding {
		var out []finding.Finding
		for _, id := range []string{idRoutingOrigin, idRoutingROA, idRoutingGeo} {
			out = append(out, finding.Unknown(id, finding.AreaRouting, finding.TierPassive, detail))
		}
		return out
	}
	if d.RIPE == nil {
		return unknownAll("skipped: routing data source disabled (--no-routing)")
	}

	addrs, skipped, truncated, err := routingAddresses(ctx, t.Domain, d)
	if err != nil {
		return unknownAll(err.Error())
	}
	if len(addrs) == 0 {
		detail := "the domain has no public A or AAAA address to look up"
		if skipped > 0 {
			detail += fmt.Sprintf(" (%d non-public address(es) were not sent to RIPEstat)", skipped)
		}
		return unknownAll(detail)
	}

	var (
		originEv, geoEv []string
		failures        []string
		pairs           = map[string]routePair{} // "AS|prefix"
	)
	for _, a := range addrs {
		ip := a.String()
		nw, err := d.RIPE.NetworkInfo(ctx, ip)
		switch {
		case err != nil:
			failures = append(failures, ip+": "+err.Error())
		case len(nw.ASNs) == 0 || nw.Prefix == "":
			originEv = append(originEv, ip+" not announced in BGP")
		default:
			var as []string
			for _, n := range nw.ASNs {
				as = append(as, "AS"+n)
				pairs["AS"+n+"|"+nw.Prefix] = routePair{asn: n, prefix: nw.Prefix}
			}
			originEv = append(originEv, fmt.Sprintf("%s -> %s via %s", ip, strings.Join(as, ","), nw.Prefix))
		}

		countries, err := d.RIPE.Geo(ctx, ip)
		switch {
		case err != nil:
			failures = append(failures, ip+" geo: "+err.Error())
		case len(countries) == 0:
			geoEv = append(geoEv, ip+" no location in the database")
		default:
			geoEv = append(geoEv, ip+" "+strings.Join(countries, ","))
		}
	}

	note := ""
	if truncated {
		note = fmt.Sprintf("limited to the first %d public addresses", MaxRoutingAddresses)
	}
	if skipped > 0 {
		note = strings.TrimSpace(note + fmt.Sprintf(" %d non-public address(es) were not sent to RIPEstat.", skipped))
	}

	origin := finding.Finding{ID: idRoutingOrigin, Area: finding.AreaRouting, Tier: finding.TierPassive,
		Status: finding.StatusInfo, Evidence: originEv, Detail: note}
	if len(originEv) == 0 {
		origin = finding.Unknown(idRoutingOrigin, finding.AreaRouting, finding.TierPassive, joinDetail(note, failures))
	}
	geo := finding.Finding{ID: idRoutingGeo, Area: finding.AreaRouting, Tier: finding.TierPassive,
		Status: finding.StatusInfo, Evidence: geoEv,
		Detail: "approximate (MaxMind GeoLite through RIPEstat); it says where an address is registered or routed, not where data is stored"}
	if len(geoEv) == 0 {
		geo = finding.Unknown(idRoutingGeo, finding.AreaRouting, finding.TierPassive, joinDetail(note, failures))
	}

	roa := roaFinding(ctx, d.RIPE, pairs, failures)
	return []finding.Finding{origin, roa, geo}
}

type routePair struct{ asn, prefix string }

// routingAddresses returns the distinct public addresses of the domain and of
// its MX hosts, sorted, at most MaxRoutingAddresses. skipped counts the
// non-public ones that were dropped.
func routingAddresses(ctx context.Context, domain string, d engine.Deps) (addrs []netip.Addr, skipped int, truncated bool, err error) {
	names := []string{domain}
	if hosts, _, mxErr := lookupMX(ctx, d.DNS, domain); mxErr == nil {
		if len(hosts) > maxRoutingMX {
			hosts = hosts[:maxRoutingMX]
		}
		names = append(names, hosts...)
	}
	seen := map[netip.Addr]bool{}
	var failed int
	for _, name := range names {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp, qerr := d.DNS.Query(ctx, name, qt)
			if qerr != nil || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
				failed++
				continue
			}
			for _, rr := range resp.Answer {
				var a netip.Addr
				switch v := rr.(type) {
				case *dns.A:
					a = v.Addr
				case *dns.AAAA:
					a = v.Addr
				default:
					continue
				}
				a = a.Unmap()
				if seen[a] {
					continue
				}
				seen[a] = true
				if !safenet.IsPublic(a) {
					skipped++
					continue
				}
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 && failed > 0 {
		return nil, skipped, false, fmt.Errorf("could not resolve the addresses of the domain (%d failed DNS lookup(s))", failed)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	if len(addrs) > MaxRoutingAddresses {
		addrs, truncated = addrs[:MaxRoutingAddresses], true
	}
	return addrs, skipped, truncated, nil
}

// roaFinding validates every (origin AS, prefix) pair and keeps the worst
// verdict. An incomplete run (some call failed) never produces a pass.
func roaFinding(ctx context.Context, c *ripestat.Client, pairs map[string]routePair, failures []string) finding.Finding {
	base := finding.Finding{ID: idRoutingROA, Area: finding.AreaRouting, Tier: finding.TierPassive}
	if len(pairs) == 0 {
		return finding.Unknown(idRoutingROA, base.Area, base.Tier, joinDetail("no announced prefix to validate", failures))
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var invalid, notFound, valid []string
	for _, k := range keys {
		p := pairs[k]
		v, err := c.RPKI(ctx, p.asn, p.prefix)
		if err != nil {
			failures = append(failures, "AS"+p.asn+" "+p.prefix+": "+err.Error())
			continue
		}
		line := fmt.Sprintf("AS%s %s %s", p.asn, p.prefix, v.State)
		switch v.State {
		case ripestat.StateValid:
			valid = append(valid, line)
		case ripestat.StateUnknown:
			notFound = append(notFound, line)
		default:
			invalid = append(invalid, line)
		}
	}
	evidence := append(append(append([]string{}, invalid...), notFound...), valid...)
	base.Evidence = evidence
	base.Fixer = finding.FixerProvider

	switch {
	case len(invalid) > 0:
		base.Status, base.Severity = finding.StatusFail, finding.SeverityHigh
	case len(notFound) > 0:
		base.Status, base.Severity = finding.StatusWarn, finding.SeverityLow
	case len(valid) > 0 && len(failures) == 0:
		base.Status, base.Fixer = finding.StatusPass, ""
	default:
		return finding.Unknown(idRoutingROA, base.Area, base.Tier, joinDetail("RPKI validation incomplete", failures))
	}
	if len(failures) > 0 {
		base.Detail = joinDetail("incomplete: some lookups failed", failures)
	}
	return base
}

func joinDetail(msg string, failures []string) string {
	if len(failures) == 0 {
		return msg
	}
	if len(failures) > 3 {
		failures = append(failures[:3:3], fmt.Sprintf("and %d more", len(failures)-3))
	}
	return strings.TrimSpace(msg + ": " + strings.Join(failures, "; "))
}
