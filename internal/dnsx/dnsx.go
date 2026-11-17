// Package dnsx abstracts DNS lookups so that checks never touch the network
// directly and tests can use a fake resolver.
package dnsx

import (
	"context"

	"codeberg.org/miekg/dns"
)

// Response is the part of a DNS reply that checks need. The DNSSEC OK bit is
// always set on queries, so RRSIG records are included when the zone is signed.
type Response struct {
	Rcode     int
	Answer    []dns.RR
	Authority []dns.RR
}

// Resolver answers a single question.
type Resolver interface {
	// Query asks a recursive resolver. A validating resolver answers SERVFAIL
	// for names whose DNSSEC chain is broken.
	Query(ctx context.Context, name string, qtype uint16) (*Response, error)

	// QueryCD is Query with the CD ("checking disabled") bit set: the resolver
	// returns the data and signatures even when its own validation fails.
	// DNSSEC diagnosis needs it, because otherwise a broken chain only ever
	// shows up as SERVFAIL, with no hint of which link is broken.
	QueryCD(ctx context.Context, name string, qtype uint16) (*Response, error)
}
