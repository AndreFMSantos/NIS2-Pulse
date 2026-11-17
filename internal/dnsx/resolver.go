package dnsx

import (
	"context"
	"fmt"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// DefaultResolver is used when the user does not pass --resolver. Queries for
// the audited domain go to this resolver, so the CLI documents the choice and
// lets users point it at a resolver they trust.
const DefaultResolver = "1.1.1.1:53"

// Client queries a recursive resolver over TCP. TCP is used throughout:
// DNSKEY and large TXT answers often exceed UDP limits, and it avoids a
// truncation/retry path in the first version.
//
// A Client is safe for concurrent use because it holds no per-query state.
type Client struct {
	addr string
}

// NewClient returns a Client for addr ("host" or "host:port").
func NewClient(addr string) *Client {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &Client{addr: addr}
}

// Query implements the Resolver interface. The DNSSEC OK bit is always set.
func (c *Client) Query(ctx context.Context, name string, qtype uint16) (*Response, error) {
	return c.query(ctx, name, qtype, false)
}

// QueryCD implements the Resolver interface with the CD bit set.
func (c *Client) QueryCD(ctx context.Context, name string, qtype uint16) (*Response, error) {
	return c.query(ctx, name, qtype, true)
}

// query uses the package-level dns.Exchange, which builds a fresh dns.Client
// per call. A shared dns.Client is not safe for overlapping Exchange calls:
// each Exchange clears the client's in-flight ID map on return, so a
// concurrent query then fails with "ID mismatch". The engine runs checks in
// parallel, so sharing one dns.Client broke real scans.
func (c *Client) query(ctx context.Context, name string, qtype uint16, cd bool) (*Response, error) {
	m := dns.NewMsg(dnsutil.Fqdn(name), qtype)
	m.Security = true
	m.CheckingDisabled = cd
	reply, err := dns.Exchange(ctx, m, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("query %s %s via %s: %w", name, dnsutil.TypeToString(qtype), c.addr, err)
	}
	return &Response{Rcode: int(reply.Rcode), Answer: reply.Answer, Authority: reply.Ns}, nil
}
