// Package dnssec validates the DNSSEC chain of trust of a domain, from the
// root zone's trust anchors down to the zone that contains the domain
// (RFC 4033-4035).
//
// All queries are sent with the CD bit, so a broken chain is diagnosed link by
// link instead of surfacing as an opaque SERVFAIL from a validating resolver.
//
// Scope of this version: it authenticates DNSKEY and DS RRsets. It does not
// validate the domain's own records, and a missing DS is reported as an
// insecure delegation without NSEC/NSEC3 proof of non-existence.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

// Status is the overall outcome of a validation.
type Status string

// Statuses.
const (
	// StatusSecure: an unbroken chain from the trust anchors to the zone.
	StatusSecure Status = "secure"
	// StatusInsecure: a delegation without DS; the zone below is unsigned.
	StatusInsecure Status = "insecure"
	// StatusBogus: the chain is broken at the TLD or below.
	StatusBogus Status = "bogus"
	// StatusIndeterminate: no verdict about the domain is possible (resolver
	// errors, an algorithm we cannot verify, or a problem at the root).
	StatusIndeterminate Status = "indeterminate"
)

// Code is a stable machine-readable reason.
type Code string

// Reason codes.
const (
	CodeDSMissing            Code = "ds_missing"
	CodeDSMismatch           Code = "ds_mismatch"
	CodeAnchorMismatch       Code = "anchor_mismatch"
	CodeDNSKEYMissing        Code = "dnskey_missing"
	CodeSigMissing           Code = "sig_missing"
	CodeSigInvalid           Code = "sig_invalid"
	CodeSigExpired           Code = "sig_expired"
	CodeSigNotYetValid       Code = "sig_not_yet_valid"
	CodeUnsupportedAlgorithm Code = "unsupported_algorithm"
	CodeQueryFailed          Code = "query_failed"
)

// KeyInfo describes one DNSKEY of a validated zone.
type KeyInfo struct {
	Tag       uint16
	Algorithm uint8
	SEP       bool // secure entry point flag, usually a KSK
}

// ZoneInfo describes a zone whose keys were authenticated.
type ZoneInfo struct {
	Name string // with trailing dot; "." is the root
	Keys []KeyInfo
	// Expires is the earliest expiry among the RRSIGs that authenticated this
	// zone's DNSKEY RRset and its DS RRset.
	Expires time.Time
}

// Result is the outcome of Validate.
type Result struct {
	Status Status
	Code   Code   // set unless Status is StatusSecure
	Zone   string // zone at which validation stopped or failed
	Detail string // English explanation for humans
	Err    error  // underlying error for StatusIndeterminate with CodeQueryFailed
	// Zones are the zones authenticated before validation stopped, top-down.
	Zones []ZoneInfo
	// DSDigestTypes are the digest types of the DS RRset authenticating the
	// last validated zone.
	DSDigestTypes []uint8
}

// Validator walks a chain of trust.
type Validator struct {
	Resolver dnsx.Resolver
	// Anchors are the trusted root DS records; nil means RootAnchors().
	Anchors []*dns.DS
	// Now returns the validation time; nil means time.Now.
	Now func() time.Time
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

type zoneState struct {
	info ZoneInfo
	keys []*dns.DNSKEY
}

// Validate authenticates the chain of trust for domain.
func (v *Validator) Validate(ctx context.Context, domain string) Result {
	res, _ := v.validate(ctx, domain)
	return res
}

// RRsetResult is the outcome of ValidateRRset.
type RRsetResult struct {
	// Result describes the chain of trust to the zone and, when that chain is
	// secure, the signature over the RRset: Status is StatusSecure only if the
	// RRset itself was authenticated.
	Result
	// Records are the RRs found at the owner name (without RRSIGs), whether or
	// not they could be authenticated. Empty means the name has none. Absence is
	// not proven: no NSEC/NSEC3 denial is checked.
	Records []dns.RR
}

// ValidateRRset authenticates the RRset of type qtype at owner. chainName is a
// name in the same zone (typically the host that owner belongs to, for example
// "mail.example.pt" for "_25._tcp.mail.example.pt"): the chain is walked for
// it, which saves querying every underscore label as a possible zone cut. An
// owner inside a delegation below chainName's zone cannot be authenticated and
// would be reported as unsigned.
func (v *Validator) ValidateRRset(ctx context.Context, chainName, owner string, qtype uint16) RRsetResult {
	res, zs := v.validate(ctx, chainName)

	rrs, err := v.fetch(ctx, owner, qtype)
	if err != nil {
		return RRsetResult{Result: withZones(queryFailed(owner, err), res.Zones)}
	}
	owner = dnsutil.Canonical(owner)
	set, sigs := split(rrs, owner, qtype)
	if len(set) == 0 || res.Status != StatusSecure {
		return RRsetResult{Result: res, Records: set}
	}
	what := dnsutil.TypeToString(qtype) + " RRset of " + owner
	if code, _ := verifyAny(set, sigs, zs.keys, zs.info.Name, v.now()); code != "" {
		return RRsetResult{Result: withZones(*failure(zs.info.Name, code, describe(code, what)), res.Zones), Records: set}
	}
	return RRsetResult{Result: res, Records: set}
}

// validate is Validate, and also returns the state of the deepest zone it
// authenticated (nil unless the chain is secure).
func (v *Validator) validate(ctx context.Context, domain string) (Result, *zoneState) {
	now := v.now()
	anchors := v.Anchors
	if anchors == nil {
		anchors = RootAnchors()
	}
	names := chainNames(domain)

	var res Result
	cur, fail := v.validateZone(ctx, ".", anchors, time.Time{}, now)
	if fail != nil {
		return *fail, nil
	}
	res.Zones = append(res.Zones, cur.info)

	for _, name := range names[1:] {
		dsRRs, err := v.fetch(ctx, name, dns.TypeDS)
		if err != nil {
			return withZones(queryFailed(name, err), res.Zones), nil
		}
		dsSet, dsSigs := split(dsRRs, name, dns.TypeDS)

		if len(dsSet) == 0 {
			// No DS: either this name is not a zone cut, or it is an unsigned delegation.
			nsRRs, err := v.fetch(ctx, name, dns.TypeNS)
			if err != nil {
				return withZones(queryFailed(name, err), res.Zones), nil
			}
			if ns, _ := split(nsRRs, name, dns.TypeNS); len(ns) > 0 {
				return Result{
					Status: StatusInsecure, Code: CodeDSMissing, Zone: name, Zones: res.Zones,
					Detail: fmt.Sprintf("%s publishes no DS record for %s: the delegation is not signed", cur.info.Name, name),
				}, nil
			}
			continue
		}

		code, dsExpiry := verifyAny(dsSet, dsSigs, cur.keys, cur.info.Name, now)
		if code != "" {
			return withZones(*failure(name, code, describe(code, "DS RRset of "+name)), res.Zones), nil
		}

		var ds []*dns.DS
		var digestTypes []uint8
		for _, rr := range dsSet {
			if d, ok := rr.(*dns.DS); ok {
				ds = append(ds, d)
				digestTypes = append(digestTypes, d.DigestType)
			}
		}

		child, fail := v.validateZone(ctx, name, ds, dsExpiry, now)
		if fail != nil {
			return withZones(*fail, res.Zones), nil
		}
		res.Zones = append(res.Zones, child.info)
		res.DSDigestTypes = digestTypes
		cur = child
	}

	res.Status, res.Zone = StatusSecure, cur.info.Name
	return res, cur
}

// validateZone authenticates the DNSKEY RRset of zone against trusted DS
// records (the parent's DS set, or the trust anchors for the root).
func (v *Validator) validateZone(ctx context.Context, name string, trusted []*dns.DS, dsExpiry time.Time, now time.Time) (*zoneState, *Result) {
	rrs, err := v.fetch(ctx, name, dns.TypeDNSKEY)
	if err != nil {
		r := queryFailed(name, err)
		return nil, &r
	}
	set, sigs := split(rrs, name, dns.TypeDNSKEY)

	var keys []*dns.DNSKEY
	for _, rr := range set {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		detail := fmt.Sprintf("a DS record exists for %s but the zone publishes no DNSKEY", name)
		if name == "." {
			detail = "the resolver returned no DNSKEY for the root zone; use a DNSSEC-aware resolver (--resolver)"
		}
		return nil, failure(name, CodeDNSKEYMissing, detail)
	}

	// The secure entry points: DNSKEYs that the trusted DS records vouch for.
	var entries []*dns.DNSKEY
	for _, k := range keys {
		if k.Flags&dns.FlagZONE == 0 {
			continue
		}
		for _, ds := range trusted {
			if matches(k, ds) {
				entries = append(entries, k)
				break
			}
		}
	}
	if len(entries) == 0 {
		if name == "." {
			return nil, failure(name, CodeAnchorMismatch,
				"none of the root DNSKEY records matches the built-in trust anchors; nis2-pulse may be out of date")
		}
		return nil, failure(name, CodeDSMismatch,
			fmt.Sprintf("none of the DNSKEY records of %s matches a DS record published by its parent", name))
	}

	code, keyExpiry := verifyAny(set, sigs, entries, name, now)
	if code != "" {
		return nil, failure(name, code, describe(code, "DNSKEY RRset of "+name))
	}

	info := ZoneInfo{Name: name, Expires: keyExpiry}
	if !dsExpiry.IsZero() && dsExpiry.Before(keyExpiry) {
		info.Expires = dsExpiry
	}
	for _, k := range keys {
		info.Keys = append(info.Keys, KeyInfo{Tag: k.KeyTag(), Algorithm: k.Algorithm, SEP: k.Flags&dns.FlagSEP != 0})
	}
	return &zoneState{info: info, keys: keys}, nil
}

// fetch asks for (name, qtype) with the CD bit. NXDOMAIN and NODATA are valid
// empty answers; anything else that is not success is an error.
func (v *Validator) fetch(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	resp, err := v.Resolver.QueryCD(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return resp.Answer, nil
	default:
		return nil, fmt.Errorf("resolver returned rcode %d for %s %s", resp.Rcode, name, dnsutil.TypeToString(qtype))
	}
}

// chainNames lists the names to walk, top-down: ".", "pt.", "example.pt.".
func chainNames(domain string) []string {
	labels := strings.Split(strings.TrimSuffix(dnsutil.Canonical(domain), "."), ".")
	names := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		names = append(names, strings.Join(labels[i:], ".")+".")
	}
	return names
}

// split separates the RRs of type qtype owned by owner from the RRSIGs that
// cover that type.
func split(rrs []dns.RR, owner string, qtype uint16) (set []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range rrs {
		if !dns.EqualName(rr.Header().Name, owner) {
			continue
		}
		if s, ok := rr.(*dns.RRSIG); ok {
			if s.TypeCovered == qtype {
				sigs = append(sigs, s)
			}
			continue
		}
		if dns.RRToType(rr) == qtype {
			set = append(set, rr)
		}
	}
	return set, sigs
}

// matches reports whether ds vouches for key k.
func matches(k *dns.DNSKEY, ds *dns.DS) bool {
	if ds.KeyTag != k.KeyTag() || ds.Algorithm != k.Algorithm {
		return false
	}
	computed := k.ToDS(ds.DigestType)
	return computed != nil && strings.EqualFold(computed.Digest, ds.Digest)
}

// verifyAny reports whether at least one RRSIG by one of keys (signed by the
// zone named signer) validates rrset at time now. On success it returns the
// expiry of that signature. On failure it returns the most informative code.
func verifyAny(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, signer string, now time.Time) (Code, time.Time) {
	worst := CodeSigMissing
	for _, sig := range sigs {
		if !dns.EqualName(sig.SignerName, signer) {
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			// RFC 4034 sections 2.1.1 and 2.1.2: a key without the Zone Key bit, or with a
			// Protocol other than 3, MUST NOT verify an RRSIG. It is not a candidate at all,
			// so it can never turn into an accusation of an invalid signature.
			if !usableForRRSIG(k) {
				continue
			}
			code := tryVerify(sig, k, rrset, now)
			if code == "" {
				return "", time.Unix(int64(sig.Expiration), 0).UTC()
			}
			if rank(code) > rank(worst) {
				worst = code
			}
		}
	}
	return worst, time.Time{}
}

// usableForRRSIG reports whether k may be used to verify an RRSIG over a zone's data.
func usableForRRSIG(k *dns.DNSKEY) bool {
	return k.Flags&dns.FlagZONE != 0 && k.Protocol == 3
}

// rank orders failure codes by how much they explain: an algorithm we cannot
// verify says nothing about the domain, an invalid signature is the strongest
// evidence of breakage, then expiry, then "not yet valid", then "no RRSIG".
func rank(c Code) int {
	switch c {
	case CodeUnsupportedAlgorithm:
		return 5
	case CodeSigInvalid:
		return 4
	case CodeSigExpired:
		return 3
	case CodeSigNotYetValid:
		return 2
	default:
		return 1
	}
}

func tryVerify(sig *dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR, now time.Time) Code {
	if !sig.ValidPeriod(now) {
		if now.Before(time.Unix(int64(sig.Inception), 0)) {
			return CodeSigNotYetValid
		}
		return CodeSigExpired
	}
	// Verify sorts the RRset in place and rewrites names and TTLs while it
	// canonicalises, so it must work on copies.
	s, ok := sig.Clone().(*dns.RRSIG)
	if !ok {
		return CodeSigInvalid
	}
	cp := make([]dns.RR, len(rrset))
	for i, rr := range rrset {
		cp[i] = rr.Clone()
	}
	switch err := s.Verify(key, cp, &dns.SignOption{}); {
	case err == nil:
		return ""
	case errors.Is(err, dns.ErrAlg):
		return CodeUnsupportedAlgorithm
	default:
		return CodeSigInvalid
	}
}

func describe(code Code, what string) string {
	switch code {
	case CodeSigExpired:
		return "the RRSIG over the " + what + " has expired"
	case CodeSigNotYetValid:
		return "the RRSIG over the " + what + " is not yet valid"
	case CodeSigInvalid:
		return "the RRSIG signature over the " + what + " does not verify"
	case CodeUnsupportedAlgorithm:
		return "the " + what + " is signed with an algorithm nis2-pulse cannot verify"
	default:
		return "no usable RRSIG over the " + what + " by a key the parent vouches for"
	}
}

// failure builds a failed Result. Problems that cannot be attributed to the
// audited domain are indeterminate, never bogus: an algorithm we cannot
// verify, and anything at the root (a stale binary after a KSK rollover, or a
// resolver that strips DNSSEC records).
func failure(zone string, code Code, detail string) *Result {
	status := StatusBogus
	if code == CodeUnsupportedAlgorithm || code == CodeQueryFailed || zone == "." {
		status = StatusIndeterminate
	}
	return &Result{Status: status, Code: code, Zone: zone, Detail: detail}
}

func queryFailed(zone string, err error) Result {
	r := failure(zone, CodeQueryFailed, fmt.Sprintf("DNS query for %s failed: %v", zone, err))
	r.Err = err
	return *r
}

func withZones(r Result, zones []ZoneInfo) Result {
	r.Zones = zones
	return r
}
