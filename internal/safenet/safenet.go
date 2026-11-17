// Package safenet is the only way active checks may open network connections.
//
// An active check connects to a host whose address is decided by the DNS of
// the domain being audited. Left to the standard dialer, an attacker who
// controls that DNS could point the host at 127.0.0.1, a private network or a
// cloud metadata address (169.254.169.254) and make the machine running
// nis2-pulse connect to internal services (SSRF). A Dialer therefore:
//
//   - resolves host names itself, through the same resolver as the scan, so
//     --resolver is honoured and the addresses can be vetted before dialing;
//   - refuses to connect when ANY resolved address is not a public address;
//   - vets IP literals the same way.
package safenet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

// ErrNonPublicAddress is returned when a host resolves to an address that is
// not on the public Internet. The dialer never connects in that case.
var ErrNonPublicAddress = errors.New("refusing to connect to a non-public address")

// Dialer opens TCP connections to public addresses only.
type Dialer struct {
	// Resolver resolves host names (A and AAAA). Required.
	Resolver dnsx.Resolver
	// Timeout bounds one connection attempt; zero means 5 seconds.
	Timeout time.Duration

	// AllowNonPublic disables the public-address check so that tests can reach
	// a loopback server. NEVER set it in production code: a test fails if any
	// non-test file other than this package and safehttp mentions it.
	AllowNonPublic bool
}

// DialContext has the signature of net.Dialer.DialContext, so it can be used
// as an http.Transport dialer and as a raw TCP dial function.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if !d.AllowNonPublic {
		for _, ip := range ips {
			if !IsPublic(ip) {
				return nil, ErrNonPublicAddress
			}
		}
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	nd := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, ip := range ips {
		conn, err := nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// resolve returns the A and AAAA addresses of host. An IP literal is returned
// as is, and still goes through the public-address check.
func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	var out []netip.Addr
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := d.Resolver.Query(ctx, host, qtype)
		if err != nil {
			return nil, err
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
	return out, nil
}

// nonPublic lists ranges that IsGlobalUnicast and IsPrivate do not exclude but
// that are not routable on the public Internet.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, overlay VPNs
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (TEST-NET-1)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// IsPublic reports whether a is a public, globally routable address.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap() // ::ffff:127.0.0.1 is loopback, not a public IPv6 address
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
