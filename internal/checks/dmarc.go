package checks

import (
	"context"
	"strconv"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the DMARC check.
const (
	idDMARCPresent     = "email.dmarc.present"
	idDMARCPolicy      = "email.dmarc.policy"
	idDMARCEnforcement = "email.dmarc.enforcement"
	idDMARCReporting   = "email.dmarc.reporting"
)

// DMARC checks the DMARC policy record (RFC 9989, which obsoletes RFC 7489) published at
// _dmarc.<domain>, falling back to the policy record found by the DNS Tree Walk (RFC 9989
// section 4.10) as receivers do.
type DMARC struct{}

// ID implements engine.Check.
func (DMARC) ID() string { return "email.dmarc" }

// Area implements engine.Check.
func (DMARC) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (DMARC) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (DMARC) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	unknown := func(err error) []finding.Finding {
		var out []finding.Finding
		for _, id := range []string{idDMARCPresent, idDMARCPolicy, idDMARCEnforcement, idDMARCReporting} {
			out = append(out, finding.Unknown(id, finding.AreaEmail, finding.TierPassive, err.Error()))
		}
		return out
	}

	found, multiple, err := discoverDMARC(ctx, d.DNS, t.Domain)
	if err != nil {
		return unknown(err)
	}
	if multiple != nil {
		return []finding.Finding{dmarcFail(idDMARCPresent, finding.SeverityHigh, multiple,
			"multiple DMARC records: receivers discard them all (RFC 9989 section 4.10)")}
	}
	if found == nil {
		return []finding.Finding{missingDMARC(detectMail(ctx, d.DNS, t.Domain))}
	}
	owner, inherited := found.owner, found.owner != t.Domain

	rec := found.raw
	tags := parseDMARC(rec)

	present := finding.Finding{ID: idDMARCPresent, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: finding.StatusPass, Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization,
		Evidence: []string{rec}}
	if inherited {
		present.Detail = "inherited from " + owner + " (found by the DNS Tree Walk, RFC 9989 section 4.10)"
	}

	return []finding.Finding{
		present,
		dmarcPolicy(rec, tags, inherited),
		dmarcEnforcement(rec, tags),
		dmarcReporting(rec, tags),
	}
}

// missingDMARC judges the absence of a DMARC record, like missingSPF.
func missingDMARC(m mailProfile) finding.Finding {
	if m.noMail() {
		return finding.Finding{ID: idDMARCPresent, Area: finding.AreaEmail, Tier: finding.TierPassive,
			Status: finding.StatusWarn, Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization,
			Detail: `the domain does not receive email and publishes no DMARC record: publish "v=DMARC1; p=reject;" so that mail claiming to come from it is rejected`}
	}
	return dmarcFail(idDMARCPresent, finding.SeverityHigh, nil, "no DMARC record published")
}

func dmarcFail(id string, sev finding.Severity, evidence []string, detail string) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: finding.StatusFail, Severity: sev, Fixer: finding.FixerOrganization,
		Evidence: evidence, Detail: detail}
}

// dmarcRecords keeps the TXT records whose first tag is v=DMARC1.
func dmarcRecords(recs []string) []string {
	var out []string
	for _, r := range recs {
		first, _, _ := strings.Cut(r, ";")
		k, v, ok := strings.Cut(first, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), "DMARC1") {
			out = append(out, r)
		}
	}
	return out
}

// parseDMARC returns the tag-value pairs of a record. Tag names are lowercased.
func parseDMARC(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := tags[k]; !dup {
			tags[k] = strings.TrimSpace(v)
		}
	}
	return tags
}

func validPolicy(p string) bool { return p == "none" || p == "quarantine" || p == "reject" }

func dmarcPolicy(rec string, tags map[string]string, inherited bool) finding.Finding {
	f := finding.Finding{ID: idDMARCPolicy, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization, Evidence: []string{rec}}

	pol := strings.ToLower(tags["p"])
	src := "p"
	if sp := strings.ToLower(tags["sp"]); inherited && validPolicy(sp) {
		// RFC 9989 section 4.7: sp governs existing subdomains of the domain that published the record.
		pol, src = sp, "sp"
	}
	switch {
	case !validPolicy(pol):
		f.Status, f.Detail = finding.StatusFail, "the p tag is missing or has an invalid value"
	case pol == "none":
		f.Status, f.Severity = finding.StatusWarn, finding.SeverityMedium
		f.Detail = src + "=none: monitoring only, spoofed mail is still delivered"
	default:
		f.Status, f.Detail = finding.StatusPass, src+"="+pol
	}
	return f
}

// dmarcEnforcement judges whether the policy is applied in full. RFC 9989 removed pct (appendix A.6)
// and added the t tag (section 4.7): t=y asks receivers not to apply the policy while the owner tests.
func dmarcEnforcement(rec string, tags map[string]string) finding.Finding {
	f := finding.Finding{ID: idDMARCEnforcement, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityLow, Fixer: finding.FixerOrganization, Evidence: []string{rec}}
	pol := strings.ToLower(tags["p"])

	if strings.EqualFold(tags["t"], "y") && (pol == "quarantine" || pol == "reject") {
		f.Status = finding.StatusWarn
		f.Detail = "t=y: test mode, receivers are asked to apply one level below p=" + pol + " (RFC 9989 section 4.7); remove it when the rollout is over"
		return f
	}
	raw, ok := tags["pct"]
	if !ok {
		f.Status, f.Detail = finding.StatusPass, "the policy applies to every message that fails DMARC"
		return f
	}
	const removed = "RFC 9989 removed the pct tag, so receivers that follow it ignore it, while older ones still apply it"
	n, err := strconv.Atoi(raw)
	switch {
	case err != nil || n < 0 || n > 100:
		f.Status, f.Detail = finding.StatusWarn, "pct has an invalid value: "+raw+"; "+removed
	case n < 100:
		f.Status, f.Detail = finding.StatusWarn, "pct="+raw+": policy applies to only "+raw+"% of messages on receivers that still honour it; "+removed+" (use t=y for testing)"
	default:
		f.Status, f.Detail = finding.StatusPass, "pct=100 is the default; "+removed
	}
	return f
}

func dmarcReporting(rec string, tags map[string]string) finding.Finding {
	f := finding.Finding{ID: idDMARCReporting, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityLow, Fixer: finding.FixerOrganization, Evidence: []string{rec}}
	if rua := tags["rua"]; rua != "" {
		f.Status, f.Evidence = finding.StatusPass, []string{"rua=" + rua}
		return f
	}
	f.Status, f.Detail = finding.StatusWarn, "no aggregate reports (rua) requested, so spoofing attempts stay invisible"
	return f
}

// dmarcFound is a DMARC policy record and the domain that published it.
type dmarcFound struct {
	owner string
	raw   string
}

const (
	maxDMARCLabels   = 8 // RFC 9989 section 4.10: no walk makes more than eight queries
	shortcutKeepsFor = 7 // names with more labels are shortened to this many before walking up
)

// discoverDMARC implements policy discovery (RFC 9989 section 4.10.1). It returns the record to apply,
// or the raw records when the Author Domain itself publishes several (all discarded by receivers).
// A nil record with no error means no valid record exists.
func discoverDMARC(ctx context.Context, r dnsx.Resolver, domain string) (*dmarcFound, []string, error) {
	recs, err := lookupTXT(ctx, r, "_dmarc."+domain)
	if err != nil {
		return nil, nil, err
	}
	switch own := dmarcRecords(recs); len(own) {
	case 1:
		return &dmarcFound{domain, own[0]}, nil, nil
	case 0:
	default:
		return nil, own, nil
	}

	// DNS Tree Walk: start at the parent (or, for names with more than eight labels, at the seven
	// right-most labels) and climb one label at a time to the top, stopping at a record with psd=n|y.
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	start := labels[1:]
	if len(labels) > maxDMARCLabels {
		start = labels[len(labels)-shortcutKeepsFor:]
	}
	var walk []dmarcFound // closest first
	for cur := start; len(cur) >= 1; cur = cur[1:] {
		name := strings.Join(cur, ".")
		recs, err := lookupTXT(ctx, r, "_dmarc."+name)
		if err != nil {
			return nil, nil, err
		}
		// Several records at one name are all discarded and the walk goes on (step 6).
		single := dmarcRecords(recs)
		if len(single) != 1 {
			continue
		}
		walk = append(walk, dmarcFound{name, single[0]})
		if psd := strings.ToLower(parseDMARC(single[0])["psd"]); psd == "n" || psd == "y" {
			break
		}
	}
	if len(walk) == 0 {
		return nil, nil, nil
	}

	// Organisational Domain selection (section 4.10.2): psd=n is the organisational domain; below a
	// psd=y record the organisational domain is the name one label under it (its record, if any,
	// applies, otherwise the PSD's); otherwise the record with the fewest labels.
	top := walk[len(walk)-1]
	if strings.EqualFold(parseDMARC(top.raw)["psd"], "y") && len(walk) >= 2 {
		below := walk[len(walk)-2]
		if strings.Count(below.owner, ".") == strings.Count(top.owner, ".")+1 {
			return &below, nil, nil
		}
	}
	return &top, nil, nil
}
