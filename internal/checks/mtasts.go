package checks

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safehttp"
)

// Finding IDs produced by the MTA-STS checks.
const (
	idMTASTSRecord = "email.mtasts.record"
	idMTASTSFetch  = "email.mtasts.fetch"
	idMTASTSMode   = "email.mtasts.mode"
	idMTASTSMX     = "email.mtasts.mx"
	idMTASTSMaxAge = "email.mtasts.maxage"
)

const (
	// policyMaxBytes is the largest policy body we read (RFC 8461 §3.3 allows
	// senders to refuse larger ones).
	policyMaxBytes = 64 << 10
	// shortMaxAge is the policy lifetime below which downgrade protection is
	// negligible: senders cache the policy for max_age seconds.
	shortMaxAge = 24 * 60 * 60
)

// MTASTSRecord checks the _mta-sts TXT record (RFC 8461 §3.1). Reading it is a
// plain DNS lookup, so this check is passive.
type MTASTSRecord struct{}

// ID implements engine.Check.
func (MTASTSRecord) ID() string { return "email.mtasts.record" }

// Area implements engine.Check.
func (MTASTSRecord) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (MTASTSRecord) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (MTASTSRecord) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	mk := func(status finding.Status, sev finding.Severity, evidence []string, detail string) []finding.Finding {
		return []finding.Finding{{ID: idMTASTSRecord, Area: finding.AreaEmail, Tier: finding.TierPassive,
			Status: status, Severity: sev, Fixer: finding.FixerOrganization, Evidence: evidence, Detail: detail}}
	}
	unknown := func(err error) []finding.Finding {
		return []finding.Finding{finding.Unknown(idMTASTSRecord, finding.AreaEmail, finding.TierPassive, err.Error())}
	}

	hosts, nullMX, err := lookupMX(ctx, d.DNS, t.Domain)
	if err != nil {
		return unknown(err)
	}
	if len(hosts) == 0 || nullMX {
		return mk(finding.StatusInfo, "", nil, "the domain does not receive email, so MTA-STS does not apply")
	}

	recs, err := lookupTXT(ctx, d.DNS, "_mta-sts."+t.Domain)
	if err != nil {
		return unknown(err)
	}
	sts := stsRecords(recs)
	switch len(sts) {
	case 0:
		return mk(finding.StatusWarn, finding.SeverityMedium, nil,
			"no MTA-STS record: mail delivered to this domain can be downgraded to unencrypted SMTP by an attacker on the network")
	case 1:
	default:
		return mk(finding.StatusFail, finding.SeverityMedium, sts,
			"multiple MTA-STS records: senders ignore them all (RFC 8461 §3.1)")
	}
	if !validSTSID(sts[0]) {
		return mk(finding.StatusFail, finding.SeverityMedium, sts,
			"the record has a missing or invalid id (1 to 32 letters or digits)")
	}
	return mk(finding.StatusPass, finding.SeverityMedium, sts, "")
}

// MTASTSPolicy fetches and checks the MTA-STS policy file (RFC 8461 §3.2-3.3).
// It connects to mta-sts.<domain> over HTTPS, so it is an ACTIVE check and only
// runs with --active.
//
// Safeguards: it connects only when the domain publishes exactly one MTA-STS
// record and receives mail; it makes a single request; the HTTP client
// (safehttp) refuses non-public addresses, never follows redirects and always
// verifies the certificate.
type MTASTSPolicy struct{}

// ID implements engine.Check.
func (MTASTSPolicy) ID() string { return "email.mtasts.policy" }

// Area implements engine.Check.
func (MTASTSPolicy) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (MTASTSPolicy) Tier() finding.Tier { return finding.TierActive }

// Run implements engine.Check.
func (MTASTSPolicy) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	one := func(status finding.Status, sev finding.Severity, evidence []string, detail string) []finding.Finding {
		return []finding.Finding{fetchFinding(status, sev, evidence, detail)}
	}
	if d.HTTP == nil {
		return one(finding.StatusUnknown, "", nil, "no HTTP client available")
	}

	hosts, nullMX, err := lookupMX(ctx, d.DNS, t.Domain)
	if err != nil {
		return one(finding.StatusUnknown, "", nil, err.Error())
	}
	if len(hosts) == 0 || nullMX {
		return one(finding.StatusInfo, "", nil, "the domain does not receive email: policy not fetched")
	}

	recs, err := lookupTXT(ctx, d.DNS, "_mta-sts."+t.Domain)
	if err != nil {
		return one(finding.StatusUnknown, "", nil, err.Error())
	}
	if n := len(stsRecords(recs)); n != 1 {
		return one(finding.StatusInfo, "", nil,
			fmt.Sprintf("the domain publishes %d MTA-STS records: policy not fetched (see %s)", n, idMTASTSRecord))
	}

	url := "https://mta-sts." + t.Domain + "/.well-known/mta-sts.txt"
	// fetchPolicy returns either a failure finding (no body) or a body, possibly
	// with a warning finding about it.
	body, fetch := fetchPolicy(ctx, d.HTTP, url, t.Domain)
	if body == nil {
		return []finding.Finding{*fetch}
	}
	policy, err := parsePolicy(string(body))
	if err != nil {
		return one(finding.StatusFail, finding.SeverityHigh, policyEvidence(url, body), "invalid policy: "+err.Error())
	}

	var out []finding.Finding
	if fetch != nil { // fetched, but with a warning (for example the wrong content type)
		fetch.Evidence = policyEvidence(url, body)
		out = append(out, *fetch)
	} else {
		out = append(out, fetchFinding(finding.StatusPass, finding.SeverityHigh, policyEvidence(url, body), "policy fetched and valid"))
	}
	out = append(out, modeFinding(policy))
	if policy.mode != "none" {
		out = append(out, mxFinding(policy, hosts))
	}
	return append(out, maxAgeFinding(policy))
}

func fetchFinding(status finding.Status, sev finding.Severity, evidence []string, detail string) finding.Finding {
	f := finding.Finding{ID: idMTASTSFetch, Area: finding.AreaEmail, Tier: finding.TierActive,
		Status: status, Severity: sev, Evidence: evidence, Detail: detail}
	if status == finding.StatusFail || status == finding.StatusWarn || status == finding.StatusPass {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

// fetchPolicy performs the single HTTPS request. It returns the body when one
// was read and, separately, a finding when the fetch failed (body == nil) or
// succeeded with a warning (body != nil).
func fetchPolicy(ctx context.Context, c *http.Client, url, domain string) ([]byte, *finding.Finding) {
	fail := func(sev finding.Severity, detail string) ([]byte, *finding.Finding) {
		f := fetchFinding(finding.StatusFail, sev, []string{"GET " + url}, detail)
		return nil, &f
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f := fetchFinding(finding.StatusUnknown, "", nil, err.Error())
		return nil, &f
	}
	req.Header.Set("User-Agent", "nis2-pulse")
	req.Header.Set("Accept", "text/plain")

	resp, err := c.Do(req)
	if err != nil {
		status, detail := classifyFetchError(err, "mta-sts."+domain)
		f := fetchFinding(status, severityFor(status), []string{"GET " + url}, detail)
		return nil, &f
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fail(finding.SeverityHigh, fmt.Sprintf("the server answered with a redirect (HTTP %d); policies must be served directly, redirects are not allowed (RFC 8461 §3.3)", resp.StatusCode))
	case resp.StatusCode != http.StatusOK:
		return fail(finding.SeverityHigh, fmt.Sprintf("the policy URL answered HTTP %d instead of 200", resp.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, policyMaxBytes+1))
	if err != nil {
		f := fetchFinding(finding.StatusUnknown, "", nil, "reading the policy failed: "+err.Error())
		return nil, &f
	}
	if len(body) > policyMaxBytes {
		return fail(finding.SeverityHigh, fmt.Sprintf("the policy is larger than 64 KiB (%d bytes read before stopping)", len(body)))
	}

	if ct := resp.Header.Get("Content-Type"); !isTextPlain(ct) {
		f := fetchFinding(finding.StatusWarn, finding.SeverityLow, nil,
			fmt.Sprintf("the policy is served as %q instead of text/plain", ct))
		return body, &f
	}
	return body, nil
}

func isTextPlain(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "text/plain"
}

func severityFor(status finding.Status) finding.Severity {
	if status == finding.StatusFail {
		return finding.SeverityHigh
	}
	return ""
}

// classifyFetchError turns a transport error into a verdict. Problems that are
// the domain's (certificate, nothing listening, name not resolving) are fails;
// anything that only says something about our network is unknown.
func classifyFetchError(err error, host string) (finding.Status, string) {
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certErr     x509.CertificateInvalidError
		dnsErr      *net.DNSError
		netErr      net.Error
	)
	switch {
	case errors.Is(err, safehttp.ErrNonPublicAddress):
		return finding.StatusUnknown, host + " resolves to a non-public address, so nis2-pulse refused to connect (safety rule)"
	case errors.As(err, &unknownAuth):
		return finding.StatusFail, "the certificate of " + host + " is not issued by a trusted authority"
	case errors.As(err, &hostErr):
		return finding.StatusFail, "the certificate is not valid for " + host
	case errors.As(err, &certErr):
		switch {
		case certErr.Reason == x509.Expired && strings.Contains(certErr.Detail, "is before"):
			return finding.StatusFail, "the certificate of " + host + " is not yet valid"
		case certErr.Reason == x509.Expired:
			return finding.StatusFail, "the certificate of " + host + " has expired"
		default:
			return finding.StatusFail, "the certificate of " + host + " is invalid: " + certErr.Detail
		}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return finding.StatusFail, host + " does not resolve (no A or AAAA record) although the domain publishes an MTA-STS record"
	case errors.Is(err, syscall.ECONNREFUSED):
		return finding.StatusFail, "connection refused on port 443 of " + host + " although the domain publishes an MTA-STS record"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return finding.StatusUnknown, "the request to " + host + " timed out"
	default:
		return finding.StatusUnknown, "could not fetch the policy: " + err.Error()
	}
}

// stsRecords keeps the TXT records whose first field is v=STSv1.
func stsRecords(recs []string) []string {
	var out []string
	for _, r := range recs {
		first, _, _ := strings.Cut(r, ";")
		k, v, ok := strings.Cut(first, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), "STSv1") {
			out = append(out, r)
		}
	}
	return out
}

// validSTSID reports whether the record carries an id of 1 to 32 letters or digits.
func validSTSID(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "id") {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 32 {
			return false
		}
		for _, r := range v {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
				return false
			}
		}
		return true
	}
	return false
}

type stsPolicy struct {
	mode   string
	mx     []string
	maxAge int64
	lines  []string
}

// parsePolicy parses "key: value" lines (RFC 8461 §3.2). Unknown keys are
// ignored; version, mode and max_age are required, and mx is required unless
// the mode is none.
func parsePolicy(body string) (stsPolicy, error) {
	var p stsPolicy
	var version string
	maxAgeSet := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p.lines = append(p.lines, line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		switch key {
		case "version":
			version = val
		case "mode":
			p.mode = strings.ToLower(val)
		case "mx":
			p.mx = append(p.mx, val)
		case "max_age":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n < 0 {
				return p, fmt.Errorf("max_age %q is not a non-negative number of seconds", val)
			}
			p.maxAge, maxAgeSet = n, true
		}
	}
	switch {
	case version != "STSv1":
		return p, fmt.Errorf("version is %q, expected STSv1", version)
	case p.mode != "enforce" && p.mode != "testing" && p.mode != "none":
		return p, fmt.Errorf("mode is %q, expected enforce, testing or none", p.mode)
	case !maxAgeSet:
		return p, errors.New("max_age is missing")
	case p.mode != "none" && len(p.mx) == 0:
		return p, errors.New("no mx entries (required unless mode is none)")
	}
	return p, nil
}

func policyEvidence(url string, body []byte) []string {
	ev := []string{"GET " + url + " -> HTTP 200"}
	for i, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if i == 12 {
			ev = append(ev, "...")
			break
		}
		ev = append(ev, strings.TrimSpace(line))
	}
	return ev
}

func modeFinding(p stsPolicy) finding.Finding {
	f := finding.Finding{ID: idMTASTSMode, Area: finding.AreaEmail, Tier: finding.TierActive,
		Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization, Evidence: []string{"mode: " + p.mode}}
	switch p.mode {
	case "enforce":
		f.Status = finding.StatusPass
	case "testing":
		f.Status, f.Detail = finding.StatusWarn, "testing mode only reports failures; senders still deliver over unauthenticated or unencrypted connections"
	default:
		f.Status, f.Detail = finding.StatusWarn, "mode none disables the policy: it protects nothing"
	}
	return f
}

func mxFinding(p stsPolicy, hosts []string) finding.Finding {
	f := finding.Finding{ID: idMTASTSMX, Area: finding.AreaEmail, Tier: finding.TierActive,
		Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization}
	var uncovered []string
	for _, h := range hosts {
		covered := false
		for _, pattern := range p.mx {
			if mxMatches(pattern, h) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, h)
		}
	}
	if len(uncovered) == 0 {
		f.Status, f.Evidence = finding.StatusPass, []string{"mx hosts covered: " + strings.Join(hosts, ", ")}
		return f
	}
	f.Evidence = []string{"mx hosts NOT covered by the policy: " + strings.Join(uncovered, ", ")}
	if p.mode == "enforce" {
		f.Status = finding.StatusFail
		f.Detail = "in enforce mode senders refuse to deliver to MX hosts the policy does not list, so mail to them is lost"
	} else {
		f.Status, f.Severity = finding.StatusWarn, finding.SeverityMedium
		f.Detail = "these MX hosts would be refused as soon as the policy moves to enforce mode"
	}
	return f
}

// mxMatches implements the host matching of RFC 8461 §4.1: an exact match, or
// a wildcard pattern "*.example.com" that matches exactly one extra label.
func mxMatches(pattern, host string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }
	pattern, host = norm(pattern), norm(host)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		label, rest, found := strings.Cut(host, ".")
		return found && label != "" && rest == suffix
	}
	return pattern == host
}

func maxAgeFinding(p stsPolicy) finding.Finding {
	f := finding.Finding{ID: idMTASTSMaxAge, Area: finding.AreaEmail, Tier: finding.TierActive,
		Severity: finding.SeverityLow, Fixer: finding.FixerOrganization,
		Evidence: []string{"max_age: " + strconv.FormatInt(p.maxAge, 10)}}
	if p.maxAge < shortMaxAge {
		f.Status = finding.StatusWarn
		f.Detail = "max_age is under one day: senders cache the policy that long, so protection lapses quickly (weeks are typical)"
		return f
	}
	f.Status = finding.StatusPass
	return f
}
