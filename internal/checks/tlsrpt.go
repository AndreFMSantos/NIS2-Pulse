package checks

import (
	"context"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// idTLSRPTRecord is the finding produced by the TLS-RPT check.
const idTLSRPTRecord = "email.tlsrpt.record"

// TLSRPT checks the SMTP TLS reporting record (RFC 8460) at _smtp._tls.<domain>.
// It is the companion of MTA-STS: reports are how a domain learns that senders
// could not deliver mail securely, which is what makes it safe to move an
// MTA-STS policy from testing to enforce.
type TLSRPT struct{}

// ID implements engine.Check.
func (TLSRPT) ID() string { return "email.tlsrpt" }

// Area implements engine.Check.
func (TLSRPT) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (TLSRPT) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (TLSRPT) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	one := func(status finding.Status, evidence []string, detail string) []finding.Finding {
		f := finding.Finding{ID: idTLSRPTRecord, Area: finding.AreaEmail, Tier: finding.TierPassive,
			Status: status, Evidence: evidence, Detail: detail}
		if status == finding.StatusPass || status == finding.StatusWarn || status == finding.StatusFail {
			f.Severity, f.Fixer = finding.SeverityLow, finding.FixerOrganization
		}
		return []finding.Finding{f}
	}
	unknown := func(err error) []finding.Finding {
		return []finding.Finding{finding.Unknown(idTLSRPTRecord, finding.AreaEmail, finding.TierPassive, err.Error())}
	}

	if m := detectMail(ctx, d.DNS, t.Domain); !m.known {
		return unknown(m.err)
	} else if m.noMail() {
		return one(finding.StatusInfo, nil, "the domain does not receive email, so TLS reports do not apply")
	}

	recs, err := lookupTXT(ctx, d.DNS, "_smtp._tls."+t.Domain)
	if err != nil {
		return unknown(err)
	}
	rpt := tlsrptRecords(recs)

	switch len(rpt) {
	case 0:
		sts, err := lookupTXT(ctx, d.DNS, "_mta-sts."+t.Domain)
		if err != nil {
			return unknown(err)
		}
		if len(stsRecords(sts)) > 0 {
			return one(finding.StatusWarn, nil,
				"MTA-STS is published but there is no TLS-RPT record: you will not learn when the policy blocks or fails to protect mail")
		}
		return one(finding.StatusInfo, nil, "no TLS-RPT record; it becomes useful together with MTA-STS")
	case 1:
	default:
		return one(finding.StatusWarn, rpt, "multiple TLS-RPT records: senders ignore them all (RFC 8460 §3)")
	}

	if !validRUA(rpt[0]) {
		return one(finding.StatusFail, rpt,
			"the record needs a rua tag with at least one mailto: or https: destination")
	}
	return one(finding.StatusPass, rpt, "")
}

// tlsrptRecords keeps the TXT records whose first field is v=TLSRPTv1.
func tlsrptRecords(recs []string) []string {
	var out []string
	for _, r := range recs {
		first, _, _ := strings.Cut(r, ";")
		k, v, ok := strings.Cut(first, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), "TLSRPTv1") {
			out = append(out, r)
		}
	}
	return out
}

// validRUA reports whether the record carries a rua tag whose destinations are
// all mailto: or https: URIs with something after the scheme.
func validRUA(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "rua") {
			continue
		}
		dests := strings.Split(strings.TrimSpace(v), ",")
		for _, dest := range dests {
			dest = strings.ToLower(strings.TrimSpace(dest))
			rest, okM := strings.CutPrefix(dest, "mailto:")
			if !okM {
				rest, okM = strings.CutPrefix(dest, "https:")
			}
			if !okM || strings.Trim(rest, "/") == "" {
				return false
			}
		}
		return true
	}
	return false
}
