// Package checks implements the individual verifications run by the engine.
// Every check takes its collaborators from engine.Deps, so unit tests use a
// fake resolver and never touch the network.
package checks

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

// lookupMX returns the mail exchanger host names of domain (lowercase, no
// trailing dot). nullMX is true when the domain publishes a null MX (RFC 7505:
// preference 0 and host "."), which states that it does not receive mail.
// Errors are reported like lookupTXT: NXDOMAIN and NODATA mean "no MX".
func lookupMX(ctx context.Context, r dnsx.Resolver, domain string) (hosts []string, nullMX bool, err error) {
	resp, err := r.Query(ctx, domain, dns.TypeMX)
	if err != nil {
		return nil, false, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, false, fmt.Errorf("resolver returned rcode %d for %s MX", resp.Rcode, domain)
	}
	for _, rr := range resp.Answer {
		mx, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(mx.Mx, "."))
		if host == "" {
			nullMX = true
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts, nullMX && len(hosts) == 0, nil
}

// lookupTXT returns the TXT records at name. The character-strings of each
// record are concatenated without separators (RFC 7208 §3.3). A missing name
// (NXDOMAIN) or type (NODATA) is a valid empty answer; transport errors and
// other response codes such as SERVFAIL are returned as errors so callers
// report "unknown" instead of guessing.
func lookupTXT(ctx context.Context, r dnsx.Resolver, name string) ([]string, error) {
	resp, err := r.Query(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("resolver returned rcode %d for %s TXT", resp.Rcode, name)
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}
