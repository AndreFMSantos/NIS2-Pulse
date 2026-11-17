package checks

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the web check.
const (
	idWebService = "transport.http.service"
	idWebHSTS    = "transport.hsts.header"
	idWebCSP     = "transport.csp.header"

	// hstsMinAge is one year, the minimum the HSTS preload list asks for and
	// the figure Mozilla's server-side TLS guidelines recommend as a floor
	// (they suggest two years).
	hstsMinAge = 31536000
)

// Web reads the security headers of https://<domain>/.
//
// It is ACTIVE and makes exactly one GET request through the safe HTTP client
// (no redirects, certificates always verified). The body is never read. HSTS
// is judged on whatever response comes back, redirects included, because RFC
// 6797 §8.1 applies the header to any HTTPS response. Subdomains such as www
// and the plain-HTTP port are not contacted: a second request is a second
// connection to the target, and the first one already shows the header.
type Web struct{}

// ID implements engine.Check.
func (Web) ID() string { return "transport.web" }

// Area implements engine.Check.
func (Web) Area() finding.Area { return finding.AreaTransport }

// Tier implements engine.Check.
func (Web) Tier() finding.Tier { return finding.TierActive }

// Run implements engine.Check.
func (Web) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	if d.HTTP == nil {
		return []finding.Finding{serviceFinding(idWebService, finding.StatusUnknown, "no HTTP client available")}
	}
	url := "https://" + t.Domain + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return []finding.Finding{serviceFinding(idWebService, finding.StatusUnknown, err.Error())}
	}
	req.Header.Set("User-Agent", "nis2-pulse")

	resp, err := d.HTTP.Do(req)
	if err != nil {
		return []finding.Finding{webProblem(err, t.Domain)}
	}
	_ = resp.Body.Close() // headers only: the body is never read

	svc := finding.Finding{
		ID: idWebService, Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusInfo,
		Evidence: []string{fmt.Sprintf("GET %s -> HTTP %d", url, resp.StatusCode)},
	}
	if resp.StatusCode >= 500 {
		// The page of a failing server (or of a CDN that cannot reach it, such as
		// Cloudflare's 5xx pages) is not the site: its headers prove nothing.
		svc.Status, svc.Severity, svc.Fixer = finding.StatusWarn, finding.SeverityLow, finding.FixerOrganization
		svc.Detail = fmt.Sprintf("the server answered HTTP %d, an error: the site is not working properly, and the headers of an error page say nothing about the real site", resp.StatusCode)
		const why = "not judged: the server answered with an error"
		return []finding.Finding{svc,
			finding.Unknown(idWebHSTS, finding.AreaTransport, finding.TierActive, why),
			finding.Unknown(idWebCSP, finding.AreaTransport, finding.TierActive, why)}
	}
	return append([]finding.Finding{svc}, AssessWebHeaders(resp.Header)...)
}

// webProblem explains a failed request. A certificate error means the browser
// would not get as far as reading headers, so no header verdict is given; the
// certificate findings carry the real message.
func webProblem(err error, domain string) finding.Finding {
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certErr     x509.CertificateInvalidError
	)
	if errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &certErr) {
		return serviceFinding(idWebService, finding.StatusUnknown,
			"the certificate of "+domain+" is not valid, so the headers could not be read (see the transport.cert findings)")
	}
	return connectionProblem(idWebService, err, domain+":443")
}

// AssessWebHeaders judges the security headers of one response. It is exported
// so header combinations that are awkward to serve can be tested directly.
func AssessWebHeaders(h http.Header) []finding.Finding {
	return []finding.Finding{hstsFinding(h), cspFinding(h)}
}

func webFinding(id string, status finding.Status, sev finding.Severity, evidence []string, detail string) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaTransport, Tier: finding.TierActive,
		Status: status, Severity: sev, Fixer: finding.FixerOrganization, Evidence: evidence, Detail: detail}
}

// hstsDirectives parses the value of a Strict-Transport-Security header (RFC
// 6797 §6.1). Names are case-insensitive, values may be quoted, and a directive
// that appears twice makes the whole header invalid.
func hstsDirectives(v string) (maxAge int64, haveMaxAge, includeSub bool, err error) {
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.Trim(strings.TrimSpace(val), `"`)
		if seen[name] {
			return 0, false, false, fmt.Errorf("the directive %q appears more than once", name)
		}
		seen[name] = true
		switch name {
		case "max-age":
			n, perr := strconv.ParseUint(val, 10, 64)
			if perr != nil {
				var ne *strconv.NumError
				if errors.As(perr, &ne) && errors.Is(ne.Err, strconv.ErrRange) {
					n = ^uint64(0) >> 1 // larger than anything we judge: treat as the maximum
				} else {
					return 0, false, false, fmt.Errorf("max-age %q is not a non-negative number", val)
				}
			}
			maxAge, haveMaxAge = int64(n), true
		case "includesubdomains":
			includeSub = true
		}
	}
	if !haveMaxAge {
		return 0, false, false, errors.New("the mandatory max-age directive is missing")
	}
	return maxAge, true, includeSub, nil
}

func hstsFinding(h http.Header) finding.Finding {
	vals := h.Values("Strict-Transport-Security")
	if len(vals) == 0 {
		return webFinding(idWebHSTS, finding.StatusWarn, finding.SeverityMedium, nil,
			"no Strict-Transport-Security header: browsers are not told to always use HTTPS for this site, so the first visit (or a stripped link) can still be downgraded to plain HTTP")
	}
	ev := []string{"Strict-Transport-Security: " + vals[0]}
	maxAge, _, includeSub, err := hstsDirectives(vals[0])
	if err != nil {
		return webFinding(idWebHSTS, finding.StatusWarn, finding.SeverityMedium, ev,
			"the header is invalid, so browsers ignore it: "+err.Error())
	}
	if maxAge == 0 {
		return webFinding(idWebHSTS, finding.StatusWarn, finding.SeverityMedium, ev,
			"max-age=0 tells browsers to forget HSTS for this site")
	}
	if len(vals) > 1 {
		// RFC 6797 §8.1: the browser processes only the first header field.
		ev = append(ev, fmt.Sprintf("%d Strict-Transport-Security headers were sent; only the first counts", len(vals)))
		return webFinding(idWebHSTS, finding.StatusWarn, finding.SeverityLow, ev,
			"the server sends more than one Strict-Transport-Security header; browsers use only the first (often a proxy and the application both add it)")
	}
	if maxAge < hstsMinAge {
		return webFinding(idWebHSTS, finding.StatusWarn, finding.SeverityLow, ev,
			fmt.Sprintf("max-age is %d seconds; use at least %d (one year), ideally 63072000 (two years)", maxAge, hstsMinAge))
	}
	detail := ""
	if !includeSub {
		detail = "includeSubDomains is not set: subdomains are not covered (set it only once every subdomain serves HTTPS)"
	}
	return webFinding(idWebHSTS, finding.StatusPass, finding.SeverityMedium, ev, detail)
}

// cspDirectives splits a policy into directive name -> source list. Names are
// lowercased; when a directive repeats, the first one wins (CSP3 §2.2.1).
func cspDirectives(v string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(v, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, dup := out[name]; dup {
			continue
		}
		out[name] = fields[1:]
	}
	return out
}

// scriptProblem names what makes the script sources of a policy weak, or "".
// 'unsafe-inline' is ignored by browsers when a nonce or hash is present, so it
// is only a problem without one.
func scriptProblem(dirs map[string][]string) string {
	srcs, ok := dirs["script-src"]
	if !ok {
		srcs, ok = dirs["default-src"]
	}
	if !ok {
		return ""
	}
	var unsafeInline, unsafeEval, wildcard, protected bool
	for _, s := range srcs {
		l := strings.ToLower(s)
		switch {
		case l == "'unsafe-inline'":
			unsafeInline = true
		case l == "'unsafe-eval'":
			unsafeEval = true
		case l == "*":
			wildcard = true
		case strings.HasPrefix(l, "'nonce-") || strings.HasPrefix(l, "'sha256-") ||
			strings.HasPrefix(l, "'sha384-") || strings.HasPrefix(l, "'sha512-"):
			protected = true
		}
	}
	switch {
	case unsafeInline && !protected:
		return "scripts may run inline ('unsafe-inline'), which defeats the main protection of CSP"
	case unsafeEval:
		return "scripts may use eval ('unsafe-eval')"
	case wildcard:
		return "scripts may be loaded from any host (*)"
	}
	return ""
}

func cspFinding(h http.Header) finding.Finding {
	vals := h.Values("Content-Security-Policy")
	if len(vals) == 0 {
		detail := "no Content-Security-Policy header: the browser has no second line of defence if the site has a cross-site scripting flaw"
		var ev []string
		if ro := h.Values("Content-Security-Policy-Report-Only"); len(ro) > 0 {
			ev = []string{"Content-Security-Policy-Report-Only: " + ro[0]}
			detail = "only a Report-Only policy is sent: violations are reported but nothing is blocked"
		}
		return webFinding(idWebCSP, finding.StatusWarn, finding.SeverityLow, ev, detail)
	}
	ev := []string{"Content-Security-Policy: " + vals[0]}
	dirs := cspDirectives(vals[0])
	if len(dirs) == 0 {
		return webFinding(idWebCSP, finding.StatusWarn, finding.SeverityLow, ev, "the policy is empty, so it restricts nothing")
	}
	if p := scriptProblem(dirs); p != "" {
		return webFinding(idWebCSP, finding.StatusWarn, finding.SeverityLow, ev, p)
	}
	return webFinding(idWebCSP, finding.StatusPass, finding.SeverityLow, ev, "")
}
