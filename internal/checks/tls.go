package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/tlsprobe"
)

// Finding IDs produced by the TLS check.
const (
	idTLSService  = "transport.tls.service"
	idTLSLegacy   = "transport.tls.legacy"
	idTLSModern   = "transport.tls.modern"
	idTLSWeak     = "transport.tls.weakciphers"
	idTLSDiscour  = "transport.tls.discouraged"
	idTLSFS       = "transport.tls.forwardsecrecy"
	idTLSInv      = "transport.tls.inventory"
	evidenceLines = 20
)

// DefaultTLSDelay is the pause between consecutive probes of one server.
const DefaultTLSDelay = 20 * time.Millisecond

// TLS enumerates the protocol versions and cipher suites the HTTPS port of the
// domain accepts, with its own ClientHello (package tlsprobe), and judges them.
//
// It is ACTIVE: it opens about 20 connections to port 443 of the domain,
// sequentially and through the safe dialer, and sends nothing but ClientHello
// messages: it never completes a handshake and never sends application data.
type TLS struct {
	// Delay is the pause between probes: zero means DefaultTLSDelay, negative none.
	Delay time.Duration
}

// ID implements engine.Check.
func (TLS) ID() string { return "transport.tls" }

// Area implements engine.Check.
func (TLS) Area() finding.Area { return finding.AreaTransport }

// Tier implements engine.Check.
func (TLS) Tier() finding.Tier { return finding.TierActive }

// Timeout implements engine.Timeouter: the probe makes many connections in series.
func (TLS) Timeout() time.Duration { return 90 * time.Second }

// Run implements engine.Check.
func (c TLS) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	if d.Dial == nil {
		return []finding.Finding{tlsService(finding.StatusUnknown, "no dialer available")}
	}
	delay := c.Delay
	switch {
	case delay == 0:
		delay = DefaultTLSDelay
	case delay < 0:
		delay = 0
	}
	addr := net.JoinHostPort(t.Domain, "443")
	s := &tlsprobe.Session{
		Dial:       func(ctx context.Context) (net.Conn, error) { return d.Dial(ctx, "tcp", addr) },
		ServerName: t.Domain,
		Delay:      delay,
	}

	rep, err := tlsprobe.Scan(ctx, s)
	if rep == nil {
		return []finding.Finding{connectionProblem(idTLSService, err, addr)}
	}
	// A cancelled or timed-out scan still returns what it found, marked incomplete.
	if rep.NotTLS != "" {
		return []finding.Finding{tlsService(finding.StatusInfo, "port 443 answered with something that is not TLS: "+rep.NotTLS)}
	}
	if len(rep.Supported()) == 0 {
		return []finding.Finding{tlsService(finding.StatusUnknown,
			"the server accepted none of the protocol versions and suites offered; it may require a specific host name (SNI) or a client certificate, so no verdict is given")}
	}
	return AssessTLSReport(rep)
}

func tlsService(status finding.Status, detail string) finding.Finding {
	return serviceFinding(idTLSService, status, detail)
}

func serviceFinding(id string, status finding.Status, detail string) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaTransport, Tier: finding.TierActive, Status: status, Detail: detail}
}

// isTimeout reports a deadline or a network timeout, which says something about
// our network or the server's speed, not about the domain.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// connectionProblem turns the error of a first connection into a finding with
// the given ID. Only what the domain itself causes is a statement about it;
// everything that says something about our network or our safety rules is unknown.
func connectionProblem(id string, err error, addr string) finding.Finding {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, safenet.ErrNonPublicAddress):
		return serviceFinding(id, finding.StatusUnknown, addr+" resolves to a non-public address, so nis2-pulse refused to connect (safety rule)")
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return serviceFinding(id, finding.StatusInfo, "the name has no address, so there is no HTTPS service to test")
	case errors.Is(err, syscall.ECONNREFUSED):
		return serviceFinding(id, finding.StatusInfo, "nothing listens on port 443: the domain has no HTTPS service")
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return serviceFinding(id, finding.StatusUnknown, "the network is unreachable from here, so port 443 could not be tested")
	case isTimeout(err):
		return serviceFinding(id, finding.StatusUnknown, "the connection to "+addr+" timed out")
	}
	return serviceFinding(id, finding.StatusUnknown, "could not test "+addr+": "+err.Error())
}

// AssessTLSReport turns a scan into findings. It is exported so that the
// verdicts can be tested with reports no real server can produce (SSLv3, NULL
// or anonymous suites).
//
// A scan that could not finish proves nothing about what it did not reach, so
// on an incomplete report every "pass" becomes "unknown". Weaknesses that were
// found remain failures.
func AssessTLSReport(rep *tlsprobe.Report) []finding.Finding {
	var pairs []accepted
	for _, vr := range rep.Versions {
		for _, id := range vr.Ciphers {
			s, ok := tlsprobe.SuiteByID(id)
			if !ok {
				s = tlsprobe.Suite{ID: id, Name: fmt.Sprintf("unknown suite 0x%04X", id)}
			}
			pairs = append(pairs, accepted{version: vr.Version, suite: s, assessment: tlsprobe.Assess(s)})
		}
	}

	out := []finding.Finding{
		legacyFinding(rep),
		modernFinding(rep),
		weakFinding(pairs),
		discouragedFinding(pairs),
	}
	if fs, ok := forwardSecrecyFinding(pairs); ok {
		out = append(out, fs)
	}

	if rep.Incomplete {
		for i := range out {
			if out[i].Status == finding.StatusPass {
				out[i].Status = finding.StatusUnknown
				out[i].Severity, out[i].Fixer = "", ""
				out[i].Detail = "scan incomplete: the connection budget or a timeout stopped it before every suite was tried, so a clean result cannot be claimed"
			}
		}
	}
	return append(out, inventoryFinding(rep))
}

type accepted struct {
	version    uint16
	suite      tlsprobe.Suite
	assessment tlsprobe.Assessment
}

func tlsFinding(id string, status finding.Status, sev finding.Severity, evidence []string, detail string) finding.Finding {
	f := finding.Finding{ID: id, Area: finding.AreaTransport, Tier: finding.TierActive,
		Status: status, Severity: sev, Evidence: capEvidence(evidence), Detail: detail}
	if status == finding.StatusPass || status == finding.StatusWarn || status == finding.StatusFail {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

// capEvidence keeps a report readable when a server accepts dozens of suites.
func capEvidence(lines []string) []string {
	if len(lines) <= evidenceLines {
		return lines
	}
	out := append([]string(nil), lines[:evidenceLines]...)
	return append(out, fmt.Sprintf("... and %d more", len(lines)-evidenceLines))
}

func supports(rep *tlsprobe.Report, v uint16) bool {
	for _, vr := range rep.Versions {
		if vr.Version == v && vr.Supported {
			return true
		}
	}
	return false
}

func legacyFinding(rep *tlsprobe.Report) finding.Finding {
	var names []string
	sev := finding.SeverityHigh
	var reasons []string
	for _, v := range []uint16{tlsprobe.VersionSSL30, tlsprobe.VersionTLS10, tlsprobe.VersionTLS11} {
		if !supports(rep, v) {
			continue
		}
		names = append(names, tlsprobe.VersionName(v))
		if v == tlsprobe.VersionSSL30 {
			sev = finding.SeverityCritical
			reasons = append(reasons, "SSLv3 is broken (POODLE) and was prohibited by RFC 7568")
		} else {
			reasons = append(reasons, tlsprobe.VersionName(v)+" was deprecated by RFC 8996")
		}
	}
	if len(names) == 0 {
		return tlsFinding(idTLSLegacy, finding.StatusPass, finding.SeverityHigh, nil, "")
	}
	return tlsFinding(idTLSLegacy, finding.StatusFail, sev, names, strings.Join(reasons, "; "))
}

func modernFinding(rep *tlsprobe.Report) finding.Finding {
	has12, has13 := supports(rep, tlsprobe.VersionTLS12), supports(rep, tlsprobe.VersionTLS13)
	var ev []string
	if has12 {
		ev = append(ev, "TLS 1.2")
	}
	if has13 {
		ev = append(ev, "TLS 1.3")
	}
	switch {
	case !has12 && !has13:
		return tlsFinding(idTLSModern, finding.StatusFail, finding.SeverityHigh, nil, "the server accepts neither TLS 1.2 nor TLS 1.3")
	case !has13:
		return tlsFinding(idTLSModern, finding.StatusWarn, finding.SeverityLow, ev,
			"TLS 1.3 (RFC 8446) is not supported: it is faster and removes the legacy options TLS 1.2 still allows")
	}
	return tlsFinding(idTLSModern, finding.StatusPass, finding.SeverityHigh, ev, "")
}

func weakFinding(pairs []accepted) finding.Finding {
	var ev, reasons []string
	worst := tlsprobe.LevelOK
	seen := map[string]bool{}
	for _, p := range pairs {
		if p.assessment.Level < tlsprobe.LevelMedium {
			continue
		}
		ev = append(ev, tlsprobe.VersionName(p.version)+": "+p.suite.Name)
		if p.assessment.Level > worst {
			worst = p.assessment.Level
		}
		for _, r := range p.assessment.Reasons {
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
		}
	}
	if len(ev) == 0 {
		return tlsFinding(idTLSWeak, finding.StatusPass, finding.SeverityHigh, nil, "")
	}
	sev := map[tlsprobe.Level]finding.Severity{
		tlsprobe.LevelMedium: finding.SeverityMedium, tlsprobe.LevelHigh: finding.SeverityHigh, tlsprobe.LevelCritical: finding.SeverityCritical,
	}[worst]
	return tlsFinding(idTLSWeak, finding.StatusFail, sev, ev, strings.Join(reasons, "; "))
}

func discouragedFinding(pairs []accepted) finding.Finding {
	var ev []string
	for _, p := range pairs {
		if p.assessment.Level == tlsprobe.LevelNote {
			ev = append(ev, tlsprobe.VersionName(p.version)+": "+p.suite.Name)
		}
	}
	if len(ev) == 0 {
		return tlsFinding(idTLSDiscour, finding.StatusPass, finding.SeverityLow, nil, "")
	}
	return tlsFinding(idTLSDiscour, finding.StatusWarn, finding.SeverityLow, ev,
		"the IANA TLS registry marks these suites as discouraged; most use a static RSA key exchange, which gives no forward secrecy")
}

func forwardSecrecyFinding(pairs []accepted) (finding.Finding, bool) {
	if len(pairs) == 0 {
		return finding.Finding{}, false
	}
	var nonFS []string
	seen := map[string]bool{}
	fs := 0
	for _, p := range pairs {
		if p.assessment.ForwardSecret {
			fs++
			continue
		}
		line := tlsprobe.VersionName(p.version) + ": " + p.suite.Name
		if !seen[line] {
			seen[line] = true
			nonFS = append(nonFS, line)
		}
	}
	switch {
	case fs == 0:
		return tlsFinding(idTLSFS, finding.StatusFail, finding.SeverityMedium, nonFS,
			"no accepted suite gives forward secrecy: anyone who later obtains the server key can decrypt recorded traffic"), true
	case len(nonFS) > 0:
		sort.Strings(nonFS)
		return tlsFinding(idTLSFS, finding.StatusWarn, finding.SeverityLow, nonFS,
			"the server also accepts suites without forward secrecy, and a client can be steered towards them"), true
	}
	return tlsFinding(idTLSFS, finding.StatusPass, finding.SeverityMedium, nil, ""), true
}

func inventoryFinding(rep *tlsprobe.Report) finding.Finding {
	var lines []string
	for _, vr := range rep.Versions {
		if !vr.Supported {
			continue
		}
		var names []string
		for _, id := range vr.Ciphers {
			if s, ok := tlsprobe.SuiteByID(id); ok {
				names = append(names, s.Name)
			} else {
				names = append(names, fmt.Sprintf("0x%04X", id))
			}
		}
		noun := "suites"
		if len(names) == 1 {
			noun = "suite"
		}
		shown := names
		if len(shown) > 30 {
			shown = append(append([]string(nil), names[:30]...), fmt.Sprintf("... and %d more", len(names)-30))
		}
		lines = append(lines, fmt.Sprintf("%s: %d %s: %s", tlsprobe.VersionName(vr.Version), len(names), noun, strings.Join(shown, ", ")))
	}
	return finding.Finding{ID: idTLSInv, Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusInfo,
		Evidence: lines, Detail: fmt.Sprintf("%d connections used", rep.Conns)}
}
