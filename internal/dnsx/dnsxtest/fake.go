// Package dnsxtest provides an in-memory dnsx.Resolver for tests, plus small
// constructors for the record types the checks consume.
package dnsxtest

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

type key struct {
	name  string
	qtype uint16
}

// Fake is a scriptable resolver. A question with no scripted answer returns
// NODATA (success with an empty answer section).
type Fake struct {
	mu      sync.Mutex
	rrs     map[key][]dns.RR
	rcodes  map[key]int
	errs    map[key]error
	queries []string
}

// New returns an empty Fake.
func New() *Fake {
	return &Fake{rrs: map[key][]dns.RR{}, rcodes: map[key]int{}, errs: map[key]error{}}
}

// Add scripts rr as part of the answer for its owner name and type.
func (f *Fake) Add(rr dns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key{dnsutil.Canonical(rr.Header().Name), dns.RRToType(rr)}
	f.rrs[k] = append(f.rrs[k], rr)
}

// SetRcode scripts a response code (for example dns.RcodeNameError).
func (f *Fake) SetRcode(name string, qtype uint16, rcode int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rcodes[key{dnsutil.Canonical(name), qtype}] = rcode
}

// SetError scripts a transport-level failure for a question.
func (f *Fake) SetError(name string, qtype uint16, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[key{dnsutil.Canonical(name), qtype}] = err
}

// Queries returns the questions asked so far, as "name./TYPE".
func (f *Fake) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// AddFor scripts rrs as part of the answer to the question (name, qtype),
// whatever their own types are. A real DNSKEY or DS answer carries the RRset
// together with its RRSIG, which has a different type.
func (f *Fake) AddFor(name string, qtype uint16, rrs ...dns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key{dnsutil.Canonical(name), qtype}
	f.rrs[k] = append(f.rrs[k], rrs...)
}

// Query implements dnsx.Resolver.
func (f *Fake) Query(_ context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	return f.answer(name, qtype, "")
}

// QueryCD implements dnsx.Resolver. It serves the same data as Query and is
// logged with a "+CD" suffix so tests can assert which queries used the bit.
func (f *Fake) QueryCD(_ context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	return f.answer(name, qtype, "+CD")
}

func (f *Fake) answer(name string, qtype uint16, logSuffix string) (*dnsx.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key{dnsutil.Canonical(name), qtype}
	f.queries = append(f.queries, fmt.Sprintf("%s/%s%s", k.name, dnsutil.TypeToString(qtype), logSuffix))
	if err, ok := f.errs[k]; ok {
		return nil, err
	}
	return &dnsx.Response{
		Rcode:  f.rcodes[k],
		Answer: append([]dns.RR(nil), f.rrs[k]...),
	}, nil
}

func hdr(name string) dns.Header {
	return dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300}
}

// TXT builds a TXT record whose character-strings are txt.
func TXT(name string, txt ...string) dns.RR {
	return &dns.TXT{Hdr: hdr(name), TXT: rdata.TXT{Txt: txt}}
}

// CAA builds a CAA record.
func CAA(name string, flag uint8, tag, value string) dns.RR {
	return &dns.CAA{Hdr: hdr(name), CAA: rdata.CAA{Flag: flag, Tag: tag, Value: value}}
}

// MX builds an MX record.
func MX(name string, pref uint16, host string) dns.RR {
	return &dns.MX{Hdr: hdr(name), MX: rdata.MX{Preference: pref, Mx: dnsutil.Fqdn(host)}}
}

// A builds an A record; ip must be an IPv4 address.
func A(name, ip string) dns.RR {
	return &dns.A{Hdr: hdr(name), A: rdata.A{Addr: netip.MustParseAddr(ip)}}
}

// AAAA builds an AAAA record; ip must be an IPv6 address.
func AAAA(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: hdr(name), AAAA: rdata.AAAA{Addr: netip.MustParseAddr(ip)}}
}

// NS builds an NS record.
func NS(name, host string) dns.RR {
	return &dns.NS{Hdr: hdr(name), NS: rdata.NS{Ns: dnsutil.Fqdn(host)}}
}

// CNAME builds a CNAME record.
func CNAME(name, target string) dns.RR {
	return &dns.CNAME{Hdr: hdr(name), CNAME: rdata.CNAME{Target: dnsutil.Fqdn(target)}}
}

// TLSA builds a TLSA record; certHex is the certificate association data as hex.
func TLSA(name string, usage, selector, matchingType uint8, certHex string) dns.RR {
	return &dns.TLSA{Hdr: hdr(name), TLSA: rdata.TLSA{Usage: usage, Selector: selector, MatchingType: matchingType, Certificate: certHex}}
}
