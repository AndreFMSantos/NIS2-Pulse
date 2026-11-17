// Package dnssectest builds small DNSSEC-signed DNS hierarchies (root, TLD,
// registrable domain...) with real keys and real RRSIGs, served by a
// dnsxtest.Fake. Options introduce one specific defect at a time so tests can
// check each failure mode of the validator.
package dnssectest

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

// Options select defects. Maps are keyed by zone name with a trailing dot,
// for example "example.pt.".
type Options struct {
	NoDS           map[string]bool // parent publishes no DS: insecure delegation
	WrongDS        map[string]bool // DS digest matches no DNSKEY of the zone
	NoDNSKEY       map[string]bool // zone publishes no DNSKEY at all
	NoKeySig       map[string]bool // DNSKEY RRset has no RRSIG
	ExpiredKeySig  map[string]bool // DNSKEY RRSIG expired yesterday
	FutureKeySig   map[string]bool // DNSKEY RRSIG not yet valid
	TamperedKeySig map[string]bool // DNSKEY RRSIG does not cover the published RRset
	ExpiredDSSig   map[string]bool // parent's RRSIG over this zone's DS expired
	// OpaqueAlgZone makes one zone use a DNSSEC algorithm this library cannot verify.
	OpaqueAlgZone string
	BadAnchor     bool          // trust anchors match no root key
	Lifetime      time.Duration // signature validity after Now; default 14 days
}

// World is a scripted hierarchy.
type World struct {
	Fake    *dnsxtest.Fake
	Now     time.Time
	Anchors []*dns.DS // trust anchors for the test root

	zones map[string]*zone
}

// RRsetDefect selects one defect for SignRRset.
type RRsetDefect int

// Defects of a published RRset.
const (
	RRsetOK       RRsetDefect = iota
	RRsetUnsigned             // no RRSIG at all
	RRsetExpired              // RRSIG expired yesterday
	RRsetTampered             // RRSIG signs a different RRset than the one published
)

// SignRRset publishes rrs (one RRset: same owner and type) in zone zoneName,
// signed by that zone's ZSK, with the chosen defect.
func (w *World) SignRRset(t testing.TB, zoneName string, defect RRsetDefect, rrs ...dns.RR) {
	t.Helper()
	z, ok := w.zones[zoneName]
	if !ok {
		t.Fatalf("no zone %q in the test world", zoneName)
	}
	answer := append([]dns.RR(nil), rrs...)
	if defect != RRsetUnsigned {
		inc, exp := w.window(Options{Lifetime: 14 * 24 * time.Hour}, defect == RRsetExpired, false)
		sig := w.sig(t, z.zskKey, z.zsk, zoneName, rrs, inc, exp)
		if defect == RRsetTampered {
			// The signature is genuine, but the published data was changed afterwards.
			answer = nil
			for _, rr := range rrs {
				c := rr.Clone()
				tl, ok := c.(*dns.TLSA)
				if !ok {
					t.Fatalf("RRsetTampered only supports TLSA records, got %T", rr)
				}
				tl.Certificate = "ff" + tl.Certificate[2:]
				answer = append(answer, c)
			}
		}
		answer = append(answer, sig)
	}
	w.Fake.AddFor(rrs[0].Header().Name, dns.RRToType(rrs[0]), answer...)
}

type zone struct {
	name           string
	ksk, zsk       *dns.DNSKEY
	kskKey, zskKey crypto.Signer
}

// New builds a hierarchy: the root plus the given zone names, top-down, for
// example New(t, Options{}, "pt.", "example.pt.").
func New(t testing.TB, o Options, names ...string) *World {
	t.Helper()
	w := &World{Fake: dnsxtest.New(), Now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	if o.Lifetime == 0 {
		o.Lifetime = 14 * 24 * time.Hour
	}

	w.zones = map[string]*zone{}
	var zones []*zone
	for _, n := range append([]string{"."}, names...) {
		z := newZone(t, n, n == o.OpaqueAlgZone)
		zones = append(zones, z)
		w.zones[n] = z
	}

	for i, z := range zones {
		w.publishKeys(t, z, o)
		if i == 0 {
			continue
		}
		w.Fake.AddFor(z.name, dns.TypeNS, dnsxtest.NS(z.name, "ns1."+z.name))
		w.publishDS(t, zones[i-1], z, o)
	}

	anchor := zones[0].ksk.ToDS(dns.SHA256)
	if o.BadAnchor {
		anchor.Digest = strings.Repeat("00", 32)
	}
	anchor.Hdr.Name = "."
	w.Anchors = []*dns.DS{anchor}
	return w
}

func newZone(t testing.TB, name string, opaque bool) *zone {
	t.Helper()
	z := &zone{name: name}
	z.ksk, z.kskKey = newKey(t, name, 257, opaque)
	z.zsk, z.zskKey = newKey(t, name, 256, opaque)
	return z
}

// maxKeyDraws bounds the redraws in newKey; 20 tag-0 keys in a row has probability 65536^-20.
const maxKeyDraws = 20

// generateKey draws a new Ed25519 key into k. Tests replace it to force a tag-0 draw.
var generateKey = func(k *dns.DNSKEY) (crypto.PrivateKey, error) { return k.Generate(256) }

func newKey(t testing.TB, name string, flags uint16, opaque bool) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:    dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: flags, Protocol: 3, Algorithm: dns.ED25519},
	}
	if opaque {
		k.Algorithm = dns.PRIVATEDNS
		k.PublicKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
		return k, nil
	}
	// Key tag 0 (about 1 key in 65536) makes dns.RRSIG.Sign fail with "dns: bad key",
	// which used to break a random test run now and then: draw again.
	var priv crypto.PrivateKey
	for attempt := 0; ; attempt++ {
		if attempt == maxKeyDraws {
			t.Fatalf("generate key for %s: %d draws in a row had key tag 0", name, maxKeyDraws)
		}
		var err error
		priv, err = generateKey(k)
		if err != nil {
			t.Fatalf("generate key for %s: %v", name, err)
		}
		if k.KeyTag() != 0 {
			break
		}
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key for %s is not a crypto.Signer", name)
	}
	return k, signer
}

func (w *World) sig(t testing.TB, signer crypto.Signer, key *dns.DNSKEY, zoneName string, rrset []dns.RR, inc, exp time.Time) *dns.RRSIG {
	t.Helper()
	s := dns.NewRRSIG(zoneName, key.Algorithm, key.KeyTag(), uint32(inc.Unix()), uint32(exp.Unix()))
	if signer == nil { // opaque algorithm: a syntactically valid but meaningless signature
		s.Hdr = dns.Header{Name: rrset[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
		s.TypeCovered = dns.RRToType(rrset[0])
		s.Labels = uint8(strings.Count(strings.TrimSuffix(rrset[0].Header().Name, "."), ".") + 1)
		s.OrigTTL = 3600
		s.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		return s
	}
	if err := s.Sign(signer, rrset, &dns.SignOption{}); err != nil {
		t.Fatalf("sign %s: %v", zoneName, err)
	}
	return s
}

func (w *World) window(o Options, expired, future bool) (time.Time, time.Time) {
	switch {
	case expired:
		return w.Now.Add(-30 * 24 * time.Hour), w.Now.Add(-24 * time.Hour)
	case future:
		return w.Now.Add(24 * time.Hour), w.Now.Add(30 * 24 * time.Hour)
	}
	return w.Now.Add(-time.Hour), w.Now.Add(o.Lifetime)
}

func (w *World) publishKeys(t testing.TB, z *zone, o Options) {
	t.Helper()
	if o.NoDNSKEY[z.name] {
		return
	}
	rrset := []dns.RR{z.ksk, z.zsk}
	answer := append([]dns.RR(nil), rrset...)
	if !o.NoKeySig[z.name] {
		signed := rrset
		if o.TamperedKeySig[z.name] {
			signed = []dns.RR{z.ksk} // the signature will not match the published two-key set
		}
		inc, exp := w.window(o, o.ExpiredKeySig[z.name], o.FutureKeySig[z.name])
		answer = append(answer, w.sig(t, z.kskKey, z.ksk, z.name, signed, inc, exp))
	}
	w.Fake.AddFor(z.name, dns.TypeDNSKEY, answer...)
}

func (w *World) publishDS(t testing.TB, parent, child *zone, o Options) {
	t.Helper()
	if o.NoDS[child.name] {
		return
	}
	ds := child.ksk.ToDS(dns.SHA256)
	if o.WrongDS[child.name] {
		ds.Digest = strings.Repeat("00", 32)
	}
	rrset := []dns.RR{ds}
	inc, exp := w.window(o, o.ExpiredDSSig[child.name], false)
	sig := w.sig(t, parent.zskKey, parent.zsk, parent.name, rrset, inc, exp)
	w.Fake.AddFor(child.name, dns.TypeDS, ds, sig)
}
