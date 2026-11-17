package checks

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the DKIM check.
const (
	idDKIMKey      = "email.dkim.key"
	idDKIMStrength = "email.dkim.strength"
)

// MaxDKIMSelectors bounds how many selectors one scan may query.
const MaxDKIMSelectors = 10

// DKIM checks the public keys that verify DKIM signatures (RFC 6376). The
// selectors of a domain cannot be listed from DNS, so the user supplies them
// (--dkim-selector); without a selector the result is unknown, never a failure.
type DKIM struct {
	Selectors []string
}

// ID implements engine.Check.
func (DKIM) ID() string { return "email.dkim" }

// Area implements engine.Check.
func (DKIM) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (DKIM) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (c DKIM) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	selectors := normalizeSelectors(c.Selectors)
	if len(selectors) == 0 {
		return []finding.Finding{finding.Unknown(idDKIMKey, finding.AreaEmail, finding.TierPassive,
			"no DKIM selector given (--dkim-selector): selectors cannot be discovered from DNS, "+
				"find yours in the s= tag of the DKIM-Signature header of a message the domain sent")}
	}

	if len(selectors) > MaxDKIMSelectors {
		return []finding.Finding{finding.Unknown(idDKIMKey, finding.AreaEmail, finding.TierPassive,
			fmt.Sprintf("too many DKIM selectors (%d): at most %d are checked per scan", len(selectors), MaxDKIMSelectors))}
	}

	var out []finding.Finding
	for _, sel := range selectors {
		out = append(out, c.checkSelector(ctx, t, d, sel)...)
	}
	return out
}

// normalizeSelectors lowercases, trims and deduplicates selectors, dropping
// empty ones. Invalid selectors are kept so they can be reported.
func normalizeSelectors(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// validSelector reports whether s is a valid selector: dot-separated labels of
// letters, digits and inner hyphens (RFC 6376 §3.1). Anything else is never
// sent to the resolver.
func validSelector(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func dkimFinding(id string, status finding.Status, sev finding.Severity, selector, detail string, evidence ...string) finding.Finding {
	f := finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: status, Severity: sev, Detail: detail,
		Evidence: append([]string{"selector=" + selector}, evidence...)}
	if status != finding.StatusUnknown {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

func (DKIM) checkSelector(ctx context.Context, t engine.Target, d engine.Deps, sel string) []finding.Finding {
	unknown := func(detail string) []finding.Finding {
		return []finding.Finding{dkimFinding(idDKIMKey, finding.StatusUnknown, "", sel, detail)}
	}
	fail := func(detail string, evidence ...string) []finding.Finding {
		return []finding.Finding{dkimFinding(idDKIMKey, finding.StatusFail, finding.SeverityHigh, sel, detail, evidence...)}
	}

	if !validSelector(sel) {
		return unknown(fmt.Sprintf("invalid selector %q: use letters, digits, hyphens and dots", sel))
	}
	name := sel + "._domainkey." + t.Domain

	recs, err := lookupTXT(ctx, d.DNS, name)
	if err != nil {
		return unknown(err.Error())
	}
	switch len(recs) {
	case 0:
		return fail("no DKIM key published at " + name + ": mail signed with this selector cannot be verified")
	case 1:
	default:
		return fail("several TXT records at "+name+": a DKIM key must be a single record", recs...)
	}
	rec := recs[0]
	tags := parseDKIM(rec)

	if v, ok := tags["v"]; ok && v != "DKIM1" {
		return fail(fmt.Sprintf("the v tag is %q, expected DKIM1", v), rec)
	}
	keyType := strings.ToLower(tags["k"])
	if keyType == "" {
		keyType = "rsa" // RFC 6376 §3.6.1: the default key type
	}
	if keyType != "rsa" && keyType != "ed25519" {
		return fail(fmt.Sprintf("unsupported key type k=%s (expected rsa or ed25519)", keyType), rec)
	}

	p, ok := tags["p"]
	if !ok {
		return fail("the record has no p tag, so it carries no public key", rec)
	}
	if p == "" {
		return fail("the key is revoked (empty p tag): mail signed with it fails verification", rec)
	}
	raw, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return fail("the p tag is not valid base64", rec)
	}

	strength, err := assessKey(keyType, raw, sel)
	if err != nil {
		return fail(err.Error(), rec)
	}

	key := dkimFinding(idDKIMKey, finding.StatusPass, finding.SeverityHigh, sel, "", rec)
	switch {
	case onlySHA1(tags["h"]):
		key.Status = finding.StatusFail
		key.Detail = "h=" + tags["h"] + " allows only SHA-1, which receivers must not accept (RFC 8301)"
	case strings.Contains(strings.ToLower(tags["t"]), "y"):
		key.Status, key.Severity = finding.StatusWarn, finding.SeverityMedium
		key.Detail = "t=y marks the key as being tested: verifiers must not treat a failed signature as an error, so it protects nothing yet"
	}
	return []finding.Finding{key, strength}
}

// parseDKIM returns the tag-value pairs of a key record (RFC 6376 §3.2).
// Tag names are lowercased; whitespace inside the p tag is removed because
// long keys are folded.
func parseDKIM(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := tags[k]; dup {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "p" {
			v = strings.Join(strings.Fields(v), "")
		}
		tags[k] = v
	}
	return tags
}

// onlySHA1 reports whether an h tag lists algorithms but none of them is sha256.
func onlySHA1(h string) bool {
	if strings.TrimSpace(h) == "" {
		return false
	}
	for _, alg := range strings.Split(h, ":") {
		if strings.EqualFold(strings.TrimSpace(alg), "sha256") {
			return false
		}
	}
	return true
}

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// assessKey measures the key and judges its strength. RSA keys are read with
// encoding/asn1 on purpose: crypto/x509 refuses RSA keys under 1024 bits, which
// would turn exactly the weak keys we want to report into parse errors.
func assessKey(keyType string, raw []byte, selector string) (finding.Finding, error) {
	f := dkimFinding(idDKIMStrength, finding.StatusPass, finding.SeverityMedium, selector, "")

	if keyType == "ed25519" {
		f.Evidence = append(f.Evidence, "ed25519")
		if len(raw) != 32 {
			f.Status, f.Severity = finding.StatusFail, finding.SeverityHigh
			f.Detail = fmt.Sprintf("an Ed25519 public key is 32 bytes (RFC 8463), this one is %d", len(raw))
		}
		return f, nil
	}

	bits, err := rsaModulusBits(raw)
	if err != nil {
		return f, err
	}
	f.Evidence = append(f.Evidence, fmt.Sprintf("rsa %d bits", bits))
	switch {
	case bits < 1024:
		f.Status, f.Severity = finding.StatusFail, finding.SeverityHigh
		f.Detail = fmt.Sprintf("the RSA modulus is %d bits: keys under 1024 bits can be broken and receivers must not accept them (RFC 8301)", bits)
	case bits < 2048:
		f.Status = finding.StatusWarn
		f.Detail = fmt.Sprintf("the RSA modulus is %d bits: acceptable but below the recommended 2048 bits", bits)
	}
	return f, nil
}

// rsaModulusBits returns the size of the modulus of an RSA public key in
// SubjectPublicKeyInfo form.
func rsaModulusBits(der []byte) (int, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &spki); err != nil || len(rest) > 0 {
		return 0, errors.New("the p tag is not a valid SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSAEncryption) {
		return 0, errors.New("the p tag does not hold an RSA public key although k=rsa")
	}
	var pub struct {
		N *big.Int
		E *big.Int
	}
	if rest, err := asn1.Unmarshal(spki.PublicKey.RightAlign(), &pub); err != nil || len(rest) > 0 || pub.N == nil || pub.N.Sign() <= 0 {
		return 0, errors.New("the p tag holds a malformed RSA public key")
	}
	return pub.N.BitLen(), nil
}
