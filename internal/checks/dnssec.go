package checks

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the DNSSEC check.
const (
	idDNSSECChain     = "dns.dnssec.chain"
	idDNSSECAlgorithm = "dns.dnssec.algorithm"
	idDNSSECExpiry    = "dns.dnssec.expiry"
)

// expiryWarning is how close to expiry the signatures of the domain's zone may
// get before the check warns. Zones normally re-sign long before this.
const expiryWarning = 48 * time.Hour

// DNSSEC validates the chain of trust from the root down to the domain's zone
// (RFC 4033-4035). It only reads public DNS data, so it is a passive check.
type DNSSEC struct {
	// Anchors are the trusted root DS records; nil means the built-in IANA anchors.
	Anchors []*dns.DS
}

// ID implements engine.Check.
func (DNSSEC) ID() string { return "dns.dnssec" }

// Area implements engine.Check.
func (DNSSEC) Area() finding.Area { return finding.AreaDNS }

// Tier implements engine.Check.
func (DNSSEC) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (c DNSSEC) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	v := &dnssec.Validator{Resolver: d.DNS, Anchors: c.Anchors, Now: now}
	res := v.Validate(ctx, t.Domain)

	out := []finding.Finding{chainFinding(res)}
	if res.Status != dnssec.StatusSecure {
		return out
	}

	last := res.Zones[len(res.Zones)-1]
	var algs []uint8
	for _, k := range last.Keys {
		if !slices.Contains(algs, k.Algorithm) {
			algs = append(algs, k.Algorithm)
		}
	}
	return append(out, AssessAlgorithms(algs, res.DSDigestTypes), expiryFinding(last, now()))
}

func chainFinding(res dnssec.Result) finding.Finding {
	f := finding.Finding{ID: idDNSSECChain, Area: finding.AreaDNS, Tier: finding.TierPassive}
	// Problems in the root or in a TLD are not something the domain owner can fix.
	fixer := finding.FixerOrganization
	if zoneDepth(res.Zone) <= 1 {
		fixer = finding.FixerProvider
	}

	switch res.Status {
	case dnssec.StatusSecure:
		f.Status, f.Severity, f.Fixer = finding.StatusPass, finding.SeverityHigh, finding.FixerOrganization
		f.Detail = "chain of trust validated from the root trust anchors"
		for _, z := range res.Zones {
			f.Evidence = append(f.Evidence, z.Name+" keys: "+describeKeys(z.Keys))
		}
	case dnssec.StatusInsecure:
		if zoneDepth(res.Zone) <= 1 {
			f.Status, f.Fixer = finding.StatusInfo, finding.FixerProvider
			f.Detail = "the TLD " + res.Zone + " is not DNSSEC-signed, so no domain below it can be: " + res.Detail
		} else {
			f.Status, f.Severity, f.Fixer = finding.StatusFail, finding.SeverityMedium, finding.FixerOrganization
			f.Detail = res.Detail
		}
	case dnssec.StatusBogus:
		f.Status, f.Severity, f.Fixer = finding.StatusFail, finding.SeverityCritical, fixer
		f.Detail = fmt.Sprintf("%s: %s", res.Code, res.Detail)
	default:
		return finding.Unknown(idDNSSECChain, finding.AreaDNS, finding.TierPassive, fmt.Sprintf("%s: %s", res.Code, res.Detail))
	}
	return f
}

// zoneDepth is the number of labels of a zone name; the root has depth 0.
func zoneDepth(zone string) int {
	z := strings.TrimSuffix(zone, ".")
	if z == "" {
		return 0
	}
	return strings.Count(z, ".") + 1
}

func describeKeys(keys []dnssec.KeyInfo) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		role := "ZSK"
		if k.SEP {
			role = "KSK"
		}
		parts = append(parts, fmt.Sprintf("%d/%s/%s", k.Tag, algName(k.Algorithm), role))
	}
	return strings.Join(parts, " ")
}

func algName(a uint8) string {
	if n, ok := dns.AlgorithmToString[a]; ok {
		return n
	}
	return fmt.Sprintf("ALG%d", a)
}

// AssessAlgorithms judges the signing algorithms of the domain's zone and the
// digest types of the DS records that vouch for it. SHA-1 based signature
// algorithms (RSASHA1, RSASHA1-NSEC3-SHA1) are not recommended (RFC 9904), and
// a DS set with only a SHA-1 digest is weak because SHA-1 is collision-prone.
func AssessAlgorithms(algs, digests []uint8) finding.Finding {
	f := finding.Finding{ID: idDNSSECAlgorithm, Area: finding.AreaDNS, Tier: finding.TierPassive,
		Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization}
	var names, problems []string
	for _, a := range algs {
		names = append(names, algName(a))
		if a == dns.RSASHA1 || a == dns.RSASHA1NSEC3SHA1 {
			problems = append(problems, algName(a)+" uses SHA-1 and is not recommended (RFC 9904)")
		}
	}
	for _, h := range digests {
		if n, ok := dns.HashToString[h]; ok {
			names = append(names, "DS digest "+n)
		}
	}
	if len(digests) > 0 && !slices.ContainsFunc(digests, func(h uint8) bool { return h != dns.SHA1 }) {
		problems = append(problems, "the DS record uses only a SHA-1 digest")
	}

	f.Evidence = names
	if len(problems) > 0 {
		f.Status, f.Detail = finding.StatusWarn, strings.Join(problems, "; ")
		return f
	}
	f.Status = finding.StatusPass
	return f
}

func expiryFinding(z dnssec.ZoneInfo, now time.Time) finding.Finding {
	f := finding.Finding{ID: idDNSSECExpiry, Area: finding.AreaDNS, Tier: finding.TierPassive,
		Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization,
		Evidence: []string{z.Name + " earliest signature expiry " + z.Expires.UTC().Format(time.RFC3339)}}
	remaining := z.Expires.Sub(now)
	if remaining < expiryWarning {
		f.Status = finding.StatusWarn
		f.Detail = fmt.Sprintf("signatures expire in %s: if the zone is not re-signed soon, validating resolvers will reject the domain", remaining.Round(time.Minute))
		return f
	}
	f.Status = finding.StatusPass
	f.Detail = fmt.Sprintf("signatures valid for another %d days", int(remaining.Hours()/24))
	return f
}
