package checks_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	webService = "transport.http.service"
	webHSTS    = "transport.hsts.header"
	webCSP     = "transport.csp.header"
)

func hourAgo() time.Time  { return time.Now().Add(-time.Hour) }
func inAnHour() time.Time { return time.Now().Add(time.Hour) }

func byID(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestAssessWebHSTS(t *testing.T) {
	const hsts = "Strict-Transport-Security"
	tests := []struct {
		name   string
		h      http.Header
		status finding.Status
		sev    finding.Severity
	}{
		{"absent", hdr(), finding.StatusWarn, finding.SeverityMedium},
		{"two years with subdomains", hdr(hsts, "max-age=63072000; includeSubDomains; preload"), finding.StatusPass, finding.SeverityMedium},
		{"exactly one year", hdr(hsts, "max-age=31536000"), finding.StatusPass, finding.SeverityMedium},
		{"one second under a year", hdr(hsts, "max-age=31535999"), finding.StatusWarn, finding.SeverityLow},
		{"one day", hdr(hsts, "max-age=86400"), finding.StatusWarn, finding.SeverityLow},
		{"zero switches HSTS off", hdr(hsts, "max-age=0"), finding.StatusWarn, finding.SeverityMedium},
		{"no max-age", hdr(hsts, "includeSubDomains"), finding.StatusWarn, finding.SeverityMedium},
		{"max-age not a number", hdr(hsts, "max-age=abc"), finding.StatusWarn, finding.SeverityMedium},
		{"negative max-age", hdr(hsts, "max-age=-5"), finding.StatusWarn, finding.SeverityMedium},
		{"absurdly large max-age is still a number", hdr(hsts, "max-age=99999999999999999999"), finding.StatusPass, finding.SeverityMedium},
		{"quoted value is allowed", hdr(hsts, `max-age="31536000"`), finding.StatusPass, finding.SeverityMedium},
		{"directive names are case-insensitive", hdr(hsts, "MAX-AGE=31536000; INCLUDESUBDOMAINS"), finding.StatusPass, finding.SeverityMedium},
		{"spaces around the equals sign", hdr(hsts, "max-age = 31536000"), finding.StatusPass, finding.SeverityMedium},
		{"duplicate max-age is invalid (RFC 6797 §6.1)", hdr(hsts, "max-age=31536000; max-age=10"), finding.StatusWarn, finding.SeverityMedium},
		{"two header lines: only the first counts", hdr(hsts, "max-age=31536000", hsts, "max-age=10"), finding.StatusWarn, finding.SeverityLow},
		{"empty value", hdr(hsts, ""), finding.StatusWarn, finding.SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := byID(checks.AssessWebHeaders(tc.h), webHSTS)
			if f == nil {
				t.Fatalf("no %s finding", webHSTS)
			}
			if f.Status != tc.status || f.Severity != tc.sev {
				t.Fatalf("got %s/%s, want %s/%s (detail %q)", f.Status, f.Severity, tc.status, tc.sev, f.Detail)
			}
			if f.Fixer != finding.FixerOrganization {
				t.Fatalf("fixer = %q", f.Fixer)
			}
		})
	}
}

func TestAssessWebHSTSEvidenceShowsTheHeader(t *testing.T) {
	f := byID(checks.AssessWebHeaders(hdr("Strict-Transport-Security", "max-age=63072000; includeSubDomains")), webHSTS)
	if len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0], "max-age=63072000") {
		t.Fatalf("evidence %v does not show the header", f.Evidence)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "includeSubDomains") {
		t.Fatalf("evidence %v should show includeSubDomains", f.Evidence)
	}
}

func TestAssessWebHSTSMentionsMissingIncludeSubDomains(t *testing.T) {
	with := byID(checks.AssessWebHeaders(hdr("Strict-Transport-Security", "max-age=63072000; includeSubDomains")), webHSTS)
	without := byID(checks.AssessWebHeaders(hdr("Strict-Transport-Security", "max-age=63072000")), webHSTS)
	if strings.Contains(with.Detail, "includeSubDomains") {
		t.Fatalf("includeSubDomains is set, but the detail complains: %q", with.Detail)
	}
	if !strings.Contains(without.Detail, "includeSubDomains") {
		t.Fatalf("detail should say includeSubDomains is missing: %q", without.Detail)
	}
	if without.Status != finding.StatusPass {
		t.Fatalf("a missing includeSubDomains is advice, not a failure: %s", without.Status)
	}
}

func TestAssessWebCSP(t *testing.T) {
	const csp = "Content-Security-Policy"
	tests := []struct {
		name   string
		h      http.Header
		status finding.Status
	}{
		{"absent", hdr(), finding.StatusWarn},
		{"report-only is not enforced", hdr("Content-Security-Policy-Report-Only", "default-src 'self'"), finding.StatusWarn},
		{"strict policy", hdr(csp, "default-src 'self'; script-src 'self'"), finding.StatusPass},
		{"unsafe-inline in script-src", hdr(csp, "script-src 'self' 'unsafe-inline'"), finding.StatusWarn},
		{"unsafe-eval in script-src", hdr(csp, "script-src 'self' 'unsafe-eval'"), finding.StatusWarn},
		{"unsafe-inline inherited from default-src", hdr(csp, "default-src 'self' 'unsafe-inline'"), finding.StatusWarn},
		{"script-src overrides an unsafe default-src", hdr(csp, "default-src 'unsafe-inline'; script-src 'self'"), finding.StatusPass},
		{"unsafe-inline only for styles is not the script problem", hdr(csp, "default-src 'self'; style-src 'self' 'unsafe-inline'"), finding.StatusPass},
		{"a nonce makes unsafe-inline inert", hdr(csp, "script-src 'nonce-abc123' 'unsafe-inline'"), finding.StatusPass},
		{"a hash makes unsafe-inline inert", hdr(csp, "script-src 'sha256-abc=' 'unsafe-inline'"), finding.StatusPass},
		{"directive names are case-insensitive", hdr(csp, "SCRIPT-SRC 'self' 'UNSAFE-INLINE'"), finding.StatusWarn},
		{"wildcard source in script-src", hdr(csp, "script-src *"), finding.StatusWarn},
		{"empty policy", hdr(csp, ""), finding.StatusWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := byID(checks.AssessWebHeaders(tc.h), webCSP)
			if f == nil {
				t.Fatalf("no %s finding", webCSP)
			}
			if f.Status != tc.status {
				t.Fatalf("got %s, want %s (detail %q)", f.Status, tc.status, f.Detail)
			}
			if f.Severity != finding.SeverityLow {
				t.Fatalf("severity = %q, a missing CSP is never more than low", f.Severity)
			}
		})
	}
}

func TestAssessWebCSPFirstDuplicateDirectiveWins(t *testing.T) {
	f := byID(checks.AssessWebHeaders(hdr("Content-Security-Policy", "script-src 'self'; script-src 'unsafe-inline'")), webCSP)
	if f.Status != finding.StatusPass {
		t.Fatalf("browsers use the first script-src, which is safe: %s (%s)", f.Status, f.Detail)
	}
}

func TestAssessWebCSPReportOnlyIsExplained(t *testing.T) {
	f := byID(checks.AssessWebHeaders(hdr("Content-Security-Policy-Report-Only", "default-src 'self'")), webCSP)
	if !strings.Contains(f.Detail, "Report-Only") || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "default-src") {
		t.Fatalf("detail %q evidence %v", f.Detail, f.Evidence)
	}
}

func runWeb(t *testing.T, client *http.Client) []finding.Finding {
	t.Helper()
	c := checks.Web{}
	if c.Tier() != finding.TierActive {
		t.Fatal("the web check connects to the target, so it must be active")
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{HTTP: client})
}

func TestWebMakesExactlyOneGETAndReadsHeaders(t *testing.T) {
	pki := newPKI(t)
	ps := startPolicy(t, pki.leaf(t, []string{"example.com"}, hourAgo(), inAnHour()), pki.pool,
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			_, _ = w.Write([]byte("hello"))
		})
	fs := runWeb(t, ps.client)
	if n := ps.hits.Load(); n != 1 {
		t.Fatalf("%d requests, want exactly 1", n)
	}
	host, path, method := ps.request()
	if host != "example.com" || path != "/" || method != http.MethodGet {
		t.Fatalf("request was %s https://%s%s", method, host, path)
	}
	if f := byID(fs, webHSTS); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("hsts finding: %+v", f)
	}
	if f := byID(fs, webCSP); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("csp finding: %+v", f)
	}
	if f := byID(fs, webService); f == nil || f.Status != finding.StatusInfo {
		t.Fatalf("service finding: %+v", f)
	}
}

func TestWebDoesNotFollowRedirectsButReadsHSTSFromThem(t *testing.T) {
	pki := newPKI(t)
	ps := startPolicy(t, pki.leaf(t, []string{"example.com"}, hourAgo(), inAnHour()), pki.pool,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
		})
	fs := runWeb(t, ps.client)
	if n := ps.hits.Load(); n != 1 {
		t.Fatalf("%d requests: the redirect must not be followed", n)
	}
	if f := byID(fs, webHSTS); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("HSTS on a redirect response still applies (RFC 6797): %+v", f)
	}
}

func TestWebServerErrorSaysNothingAboutTheHeaders(t *testing.T) {
	pki := newPKI(t)
	for _, code := range []int{500, 503, 525} {
		ps := startPolicy(t, pki.leaf(t, []string{"example.com"}, hourAgo(), inAnHour()), pki.pool,
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000")
				w.WriteHeader(code)
			})
		fs := runWeb(t, ps.client)
		svc, hsts, csp := byID(fs, webService), byID(fs, webHSTS), byID(fs, webCSP)
		if svc == nil || svc.Status != finding.StatusWarn || svc.Severity != finding.SeverityLow {
			t.Fatalf("HTTP %d: service finding %+v", code, svc)
		}
		if hsts == nil || hsts.Status != finding.StatusUnknown || csp == nil || csp.Status != finding.StatusUnknown {
			t.Fatalf("HTTP %d: header findings must be unknown: %+v %+v", code, hsts, csp)
		}
	}
	// A client error (403, 404) is still the site answering: its headers count.
	ps := startPolicy(t, pki.leaf(t, []string{"example.com"}, hourAgo(), inAnHour()), pki.pool,
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			w.WriteHeader(404)
		})
	if f := byID(runWeb(t, ps.client), webHSTS); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("a 404 still carries HSTS: %+v", f)
	}
}

func TestWebCertificateProblemIsUnknownNotAHSTSVerdict(t *testing.T) {
	other := newPKI(t) // the client trusts a different CA
	signer := newPKI(t)
	ps := startPolicy(t, signer.leaf(t, []string{"example.com"}, hourAgo(), inAnHour()), other.pool,
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		})
	fs := runWeb(t, ps.client)
	if len(fs) != 1 || fs[0].ID != webService || fs[0].Status != finding.StatusUnknown {
		t.Fatalf("got %+v", fs)
	}
	if !strings.Contains(fs[0].Detail, "transport.cert") {
		t.Fatalf("detail should point to the certificate findings: %q", fs[0].Detail)
	}
}

func TestWebCertificateErrorsOfEveryKindAreUnknown(t *testing.T) {
	pki := newPKI(t)
	tests := []struct {
		name  string
		names []string
		from  time.Time
		to    time.Time
	}{
		{"wrong host name", []string{"other.example.net"}, hourAgo(), inAnHour()},
		{"expired", []string{"example.com"}, time.Now().Add(-3 * time.Hour), time.Now().Add(-2 * time.Hour)},
		{"not yet valid", []string{"example.com"}, time.Now().Add(2 * time.Hour), time.Now().Add(3 * time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := startPolicy(t, pki.leaf(t, tc.names, tc.from, tc.to), pki.pool, func(http.ResponseWriter, *http.Request) {})
			fs := runWeb(t, ps.client)
			if len(fs) != 1 || fs[0].Status != finding.StatusUnknown || !strings.Contains(fs[0].Detail, "transport.cert") {
				t.Fatalf("got %+v", fs)
			}
		})
	}
}

func TestWebConnectionProblems(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status finding.Status
	}{
		{"connection refused means no HTTPS service", syscall.ECONNREFUSED, finding.StatusInfo},
		{"non-public address is refused by the safety rule", errNonPublic(), finding.StatusUnknown},
		{"timeout says nothing about the domain", context.DeadlineExceeded, finding.StatusUnknown},
		{"anything else is unknown", errors.New("boom"), finding.StatusUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, tc.err })}
			fs := runWeb(t, client)
			if len(fs) != 1 || fs[0].ID != webService || fs[0].Status != tc.status {
				t.Fatalf("got %+v, want one %s %s finding", fs, webService, tc.status)
			}
		})
	}
}

func TestWebWithoutHTTPClientIsUnknown(t *testing.T) {
	fs := checks.Web{}.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{})
	if len(fs) != 1 || fs[0].Status != finding.StatusUnknown {
		t.Fatalf("got %+v", fs)
	}
}

func TestWebIsRegisteredAndSkippedWithoutActive(t *testing.T) {
	var web engine.Check
	for _, c := range checks.Default(checks.Options{}) {
		if _, ok := c.(checks.Web); ok {
			web = c
		}
	}
	if web == nil {
		t.Fatal("Web is not in checks.Default")
	}
	calls := 0
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not be called") })}
	fs := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{web}, engine.Deps{HTTP: client}, engine.Options{})
	if calls != 0 {
		t.Fatalf("the HTTP client was used without --active (%d calls)", calls)
	}
	if len(fs) != 1 || fs[0].Status != finding.StatusUnknown || !strings.Contains(fs[0].Detail, "--active") {
		t.Fatalf("got %+v", fs)
	}
}
