package checks

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the DANE check.
const (
	idDANETLSA   = "email.dane.tlsa"
	idDANEParams = "email.dane.params"

	// maxDANEHosts bounds the number of MX hosts examined (each costs a DNSSEC
	// chain walk). Real domains have a handful.
	maxDANEHosts = 10
)

// DANE examines the TLSA records that pin the certificates of the domain's mail
// servers (RFC 7672, SMTP security via opportunistic DANE; RFC 6698). It only
// reads DNS, so it is passive. Whether the certificate a server actually
// presents matches its TLSA records is judged by the active STARTTLS check.
//
// A TLSA record only counts when it is authenticated by DNSSEC (RFC 7672 §2.2):
// published in an unsigned zone it is ignored by senders, and published with a
// broken signature it makes compliant senders hold the mail back.
type DANE struct {
	// Anchors are the trusted root DS records; nil means the built-in IANA anchors.
	Anchors []*dns.DS
}

// ID implements engine.Check.
func (DANE) ID() string { return "email.dane" }

// Area implements engine.Check.
func (DANE) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (DANE) Tier() finding.Tier { return finding.TierPassive }

type daneState int

const (
	daneAbsent        daneState = iota // no TLSA records published
	daneAuthenticated                  // records, DNSSEC-authenticated
	daneIgnored                        // records, but the zone is not signed: senders ignore them
	daneBogus                          // records, but DNSSEC validation fails
	daneUnknown                        // we could not tell
)

// hostDANE is what was found for one MX host.
type hostDANE struct {
	host    string
	state   daneState
	records []*dns.TLSA
	detail  string
}

func daneFinding(id string, status finding.Status, sev finding.Severity, ev []string, detail string) finding.Finding {
	f := finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: status, Severity: sev, Evidence: ev, Detail: detail}
	if status == finding.StatusPass || status == finding.StatusWarn || status == finding.StatusFail {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

// Run implements engine.Check.
func (c DANE) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	hosts, _, err := lookupMX(ctx, d.DNS, t.Domain) // a null MX comes back as no hosts
	if err != nil {
		return []finding.Finding{daneFinding(idDANETLSA, finding.StatusUnknown, "", nil, err.Error())}
	}
	if len(hosts) == 0 {
		return []finding.Finding{daneFinding(idDANETLSA, finding.StatusInfo, "", nil,
			"the domain does not receive email, so DANE for SMTP does not apply")}
	}
	sort.Strings(hosts)
	hosts = uniq(hosts)
	capped := len(hosts) > maxDANEHosts
	if capped {
		hosts = hosts[:maxDANEHosts]
	}

	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	v := &dnssec.Validator{Resolver: d.DNS, Anchors: c.Anchors, Now: now}

	results := make([]hostDANE, 0, len(hosts))
	for _, h := range hosts {
		results = append(results, examineHost(ctx, v, h))
	}
	out := []finding.Finding{aggregateDANE(results, capped)}
	if p := paramsFinding(results); p != nil {
		out = append(out, *p)
	}
	return out
}

func uniq(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func examineHost(ctx context.Context, v *dnssec.Validator, host string) hostDANE {
	res := v.ValidateRRset(ctx, host, "_25._tcp."+host, dns.TypeTLSA)
	h := hostDANE{host: host}
	for _, rr := range res.Records {
		if tl, ok := rr.(*dns.TLSA); ok {
			h.records = append(h.records, tl)
		}
	}
	switch {
	case res.Status == dnssec.StatusIndeterminate && res.Code == dnssec.CodeQueryFailed:
		h.state, h.detail = daneUnknown, res.Detail
	case len(h.records) == 0:
		h.state = daneAbsent
	case res.Status == dnssec.StatusSecure:
		h.state = daneAuthenticated
	case res.Status == dnssec.StatusInsecure:
		h.state, h.detail = daneIgnored, "the zone of "+host+" is not DNSSEC-signed: "+res.Detail
	case res.Status == dnssec.StatusBogus:
		h.state, h.detail = daneBogus, res.Detail
	default:
		h.state, h.detail = daneUnknown, res.Detail
	}
	return h
}

func tlsaTriple(r *dns.TLSA) string {
	return fmt.Sprintf("%d %d %d", r.Usage, r.Selector, r.MatchingType)
}

// countedTriples lists the distinct "usage selector matching" triples with how
// many records use each ("3 1 1 x6"), so six rollover records do not fill the
// report with six identical words.
func countedTriples(rs []*dns.TLSA) []string {
	var order []string
	n := map[string]int{}
	for _, r := range rs {
		k := tlsaTriple(r)
		if n[k] == 0 {
			order = append(order, k)
		}
		n[k]++
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		if n[k] > 1 {
			k = fmt.Sprintf("%s x%d", k, n[k])
		}
		out = append(out, k)
	}
	return out
}

func hostEvidence(h hostDANE) string {
	switch h.state {
	case daneAbsent:
		return h.host + ": no TLSA record"
	case daneUnknown:
		return h.host + ": not determined (" + h.detail + ")"
	}
	triples := countedTriples(h.records)
	status := map[daneState]string{
		daneAuthenticated: "DNSSEC-authenticated",
		daneIgnored:       "NOT authenticated (unsigned zone)",
		daneBogus:         "DNSSEC validation FAILS",
	}[h.state]
	return fmt.Sprintf("%s: %d TLSA record(s) (%s), %s", h.host, len(h.records), strings.Join(triples, ", "), status)
}

func aggregateDANE(rs []hostDANE, capped bool) finding.Finding {
	var ev []string
	count := map[daneState]int{}
	var bogusDetail, ignoredDetail string
	for _, h := range rs {
		ev = append(ev, hostEvidence(h))
		count[h.state]++
		switch h.state {
		case daneBogus:
			bogusDetail = h.host + ": " + h.detail
		case daneIgnored:
			ignoredDetail = h.detail
		}
	}
	if capped {
		ev = append(ev, fmt.Sprintf("only the first %d MX hosts were examined", maxDANEHosts))
	}
	switch {
	case count[daneBogus] > 0:
		return daneFinding(idDANETLSA, finding.StatusFail, finding.SeverityHigh, ev,
			"DNSSEC validation of the TLSA records fails ("+bogusDetail+"): senders that support DANE must not deliver mail to this server until it is fixed")
	case count[daneIgnored] > 0:
		return daneFinding(idDANETLSA, finding.StatusWarn, finding.SeverityMedium, ev,
			"TLSA records are published but the zone is not DNSSEC-signed, so senders ignore them and they protect nothing ("+ignoredDetail+")")
	case count[daneUnknown] > 0:
		return daneFinding(idDANETLSA, finding.StatusUnknown, "", ev, "the TLSA records of at least one MX host could not be examined")
	case count[daneAuthenticated] == 0:
		return daneFinding(idDANETLSA, finding.StatusInfo, "", ev,
			"no MX host publishes TLSA records: DANE is not used (it is optional; MTA-STS is the alternative for receiving TLS-protected mail)")
	case count[daneAbsent] > 0:
		return daneFinding(idDANETLSA, finding.StatusWarn, finding.SeverityMedium, ev,
			"only some MX hosts publish TLSA records: a sender can be steered to a host without DANE, so protection is only as strong as the weakest MX")
	}
	return daneFinding(idDANETLSA, finding.StatusPass, finding.SeverityMedium, ev, "every MX host publishes DNSSEC-authenticated TLSA records")
}

// tlsaProblem explains why senders could not use r, or returns "" when it is
// usable for SMTP (RFC 7672 §3.1; data lengths from RFC 6698 §2.1.3).
func tlsaProblem(r *dns.TLSA) string {
	switch r.Usage {
	case 2, 3:
	case 0, 1:
		return fmt.Sprintf("%s: certificate usage %d (PKIX) is not for SMTP; use 3 (DANE-EE) or 2 (DANE-TA), RFC 7672 §3.1.3", tlsaTriple(r), r.Usage)
	default:
		return fmt.Sprintf("%s: unknown certificate usage %d", tlsaTriple(r), r.Usage)
	}
	if r.Selector > 1 {
		return fmt.Sprintf("%s: unknown selector %d (0 = whole certificate, 1 = public key)", tlsaTriple(r), r.Selector)
	}
	data, err := hex.DecodeString(r.Certificate)
	if err != nil || len(data) == 0 {
		return tlsaTriple(r) + ": the association data is empty or not valid hex"
	}
	switch r.MatchingType {
	case 0:
	case 1:
		if len(data) != 32 {
			return fmt.Sprintf("%s: a SHA-256 digest must be 32 bytes, this one has %d", tlsaTriple(r), len(data))
		}
	case 2:
		if len(data) != 64 {
			return fmt.Sprintf("%s: a SHA-512 digest must be 64 bytes, this one has %d", tlsaTriple(r), len(data))
		}
	default:
		return fmt.Sprintf("%s: unknown matching type %d (0 = full, 1 = SHA-256, 2 = SHA-512)", tlsaTriple(r), r.MatchingType)
	}
	return ""
}

// paramsFinding judges the parameters of the records senders actually use. It
// returns nil when no host has authenticated records.
func paramsFinding(rs []hostDANE) *finding.Finding {
	var ev, problems []string
	usable, total := 0, 0
	for _, h := range rs {
		if h.state != daneAuthenticated {
			continue
		}
		for _, r := range h.records {
			total++
			if p := tlsaProblem(r); p != "" {
				problems = append(problems, h.host+": "+p)
				continue
			}
			usable++
		}
		var good []*dns.TLSA
		for _, r := range h.records {
			if tlsaProblem(r) == "" {
				good = append(good, r)
			}
		}
		if len(good) > 0 {
			ev = append(ev, fmt.Sprintf("%s: %s", h.host, strings.Join(countedTriples(good), ", ")))
		}
	}
	if total == 0 {
		return nil
	}
	ev = append(ev, problems...)
	var f finding.Finding
	switch {
	case usable == 0:
		f = daneFinding(idDANEParams, finding.StatusFail, finding.SeverityMedium, ev,
			"no TLSA record is usable: senders will insist on TLS but cannot authenticate the server, so DANE gives no protection (RFC 7672 §2.2)")
	case len(problems) > 0:
		f = daneFinding(idDANEParams, finding.StatusWarn, finding.SeverityLow, ev,
			"some TLSA records are unusable and should be removed or corrected")
	default:
		f = daneFinding(idDANEParams, finding.StatusPass, finding.SeverityLow, ev, "")
	}
	return &f
}
