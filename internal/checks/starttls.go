package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/certinspect"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/smtpprobe"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/tlsprobe"
)

// Finding IDs produced by the STARTTLS check.
const (
	idSTService = "email.starttls.service"
	idSTOffered = "email.starttls.offered"
	idSTTLS     = "email.starttls.tls"
	idSTCert    = "email.starttls.cert"
	idDANEMatch = "email.dane.match"

	// DefaultEHLOName identifies the scanner in the SMTP dialogue. The .invalid
	// top-level domain is reserved (RFC 2606) and can never be a real host.
	DefaultEHLOName = "nis2-pulse.invalid"

	maxMXHosts = maxDANEHosts
)

// StartTLS connects to the domain's MX hosts on port 25, asks for STARTTLS and
// inspects the certificate each one presents (RFC 5321, RFC 3207, RFC 7672).
//
// It is ACTIVE, and it is the most delicate check in the tool, so its limits
// are strict and tested:
//
//   - only the MX hosts the domain publishes are contacted, at most ten, one
//     connection each, one after the other; a domain without MX (or with a null
//     MX) is not contacted at all;
//   - the dialogue is EHLO, STARTTLS, TLS handshake, then QUIT inside the
//     tunnel. Never MAIL, RCPT, DATA, VRFY, EXPN or AUTH: no mail is created and
//     no address is probed (see package smtpprobe);
//   - a connection that cannot be made (outbound port 25 is blocked by many
//     ISPs and clouds), a refused greeting or an odd reply is "unknown", never a
//     verdict about the domain.
//
// Certificate problems on an MX host are warnings, not failures: most senders
// use opportunistic TLS and accept any certificate. They become hard failures
// when the domain publishes MTA-STS in enforce mode or DANE records, and the
// DANE case is judged here (email.dane.match).
type StartTLS struct {
	// Roots is the trust store; nil means the system roots.
	Roots *x509.CertPool
	// Anchors are the trusted root DS records for the DANE lookups; nil means
	// the built-in IANA anchors.
	Anchors []*dns.DS
	// EHLOName is the name announced in EHLO; empty means DefaultEHLOName.
	EHLOName string
}

// ID implements engine.Check.
func (StartTLS) ID() string { return "email.starttls" }

// Area implements engine.Check.
func (StartTLS) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (StartTLS) Tier() finding.Tier { return finding.TierActive }

// Timeout implements engine.Timeouter: up to ten hosts, in series.
func (StartTLS) Timeout() time.Duration { return 150 * time.Second }

type probeOutcome int

const (
	outNotTested probeOutcome = iota // could not talk SMTP: says nothing about the domain
	outNoTLS                         // EHLO answered, STARTTLS not offered
	outRefused                       // STARTTLS offered but the command was refused
	outHandshake                     // STARTTLS accepted but the handshake failed
	outInspected                     // handshake done, certificate read
)

type hostProbe struct {
	host    string
	outcome probeOutcome
	reason  string // why not tested, or the failure detail
	res     *certinspect.Result
	dane    hostDANE
}

// tested reports whether the SMTP dialogue got far enough to say something.
func (h hostProbe) tested() bool { return h.outcome != outNotTested }

type stepError struct {
	connect bool
	err     error
}

func (e *stepError) Error() string { return e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

var errNoSTARTTLS = errors.New("the server does not offer STARTTLS")

func stFinding(id string, status finding.Status, sev finding.Severity, ev []string, detail string) finding.Finding {
	f := finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierActive,
		Status: status, Severity: sev, Evidence: ev, Detail: detail}
	if status == finding.StatusPass || status == finding.StatusWarn || status == finding.StatusFail {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

// Run implements engine.Check.
func (c StartTLS) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	one := func(status finding.Status, detail string) []finding.Finding {
		return []finding.Finding{stFinding(idSTService, status, "", nil, detail)}
	}
	if d.Dial == nil {
		return one(finding.StatusUnknown, "no dialer available")
	}
	ehlo := c.EHLOName
	if ehlo == "" {
		ehlo = DefaultEHLOName
	}
	if !smtpprobe.ValidName(ehlo) {
		return one(finding.StatusUnknown, fmt.Sprintf("%q is not a valid EHLO name, so no connection was made", ehlo))
	}
	hosts, _, err := lookupMX(ctx, d.DNS, t.Domain) // a null MX comes back as no hosts
	if err != nil {
		return one(finding.StatusUnknown, err.Error())
	}
	if len(hosts) == 0 {
		return one(finding.StatusInfo, "the domain does not receive email: no mail server was contacted")
	}
	sort.Strings(hosts)
	hosts = uniq(hosts)
	capped := len(hosts) > maxMXHosts
	if capped {
		hosts = hosts[:maxMXHosts]
	}

	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	v := &dnssec.Validator{Resolver: d.DNS, Anchors: c.Anchors, Now: now}

	probes := make([]hostProbe, 0, len(hosts))
	for _, h := range hosts {
		hp := c.probeHost(ctx, d, h, ehlo, now)
		hp.dane = examineHost(ctx, v, h)
		probes = append(probes, hp)
	}
	return assembleSTARTTLS(probes, t.Domain, capped, now())
}

func (c StartTLS) probeHost(ctx context.Context, d engine.Deps, host, ehlo string, now func() time.Time) hostProbe {
	hp := hostProbe{host: host}
	dial := func(ctx context.Context) (net.Conn, error) {
		conn, err := d.Dial(ctx, "tcp", net.JoinHostPort(host, "25"))
		if err != nil {
			return nil, &stepError{connect: true, err: err}
		}
		neg, err := smtpprobe.Negotiate(ctx, conn, ehlo)
		if err != nil {
			_ = conn.Close()
			return nil, &stepError{err: err}
		}
		if !neg.StartTLS {
			_ = conn.Close()
			return nil, errNoSTARTTLS
		}
		return conn, nil
	}
	res, err := certinspect.Inspect(ctx, certinspect.Options{
		Dial: dial, ServerName: host, Roots: c.Roots, Now: now,
		Farewell: []byte("QUIT\r\n"), Timeout: 20 * time.Second,
	})
	if err == nil {
		hp.outcome, hp.res = outInspected, res
		return hp
	}

	var (
		se *stepError
		re *smtpprobe.ReplyError
		he *certinspect.HandshakeError
	)
	switch {
	case errors.Is(err, errNoSTARTTLS):
		hp.outcome = outNoTLS
	case errors.As(err, &he):
		hp.outcome, hp.reason = outHandshake, he.Err.Error()
	case errors.As(err, &re) && re.Stage == "STARTTLS":
		hp.outcome, hp.reason = outRefused, re.Error()
	case errors.As(err, &se) && se.connect:
		hp.reason = connectReason(se.err)
	default:
		hp.reason = smtpReason(err)
	}
	return hp
}

// connectReason explains a failed connection to port 25 in terms an
// administrator can act on.
func connectReason(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, safenet.ErrNonPublicAddress):
		return "the host resolves to a non-public address, so nis2-pulse refused to connect (safety rule)"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "the MX host name does not resolve to any address"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused on port 25 (the server does not accept mail, or port 25 is filtered)"
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return "the network is unreachable from here"
	case isTimeout(err):
		return "the connection timed out: outbound port 25 is blocked by many ISPs and cloud providers, so this may say nothing about the server"
	}
	return "could not connect to port 25: " + err.Error()
}

func smtpReason(err error) string {
	var re *smtpprobe.ReplyError
	var pe *smtpprobe.ProtocolError
	switch {
	case errors.As(err, &re):
		return re.Error() + " (a refusing or busy server is not a verdict on its TLS)"
	case errors.As(err, &pe):
		return "the server did not speak SMTP: " + pe.Error()
	case isTimeout(err):
		return "the server did not answer in time"
	}
	return "SMTP dialogue failed: " + err.Error()
}

func inDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// fixerFor says who must act on problems found on hosts: the domain's owner
// when at least one of them is the domain's own, the mail provider otherwise.
func fixerFor(hosts []string, domain string) finding.Fixer {
	for _, h := range hosts {
		if inDomain(h, domain) {
			return finding.FixerOrganization
		}
	}
	return finding.FixerProvider
}

func assembleSTARTTLS(ps []hostProbe, domain string, capped bool, now time.Time) []finding.Finding {
	var out []finding.Finding

	// service
	var ev []string
	tested := 0
	for _, p := range ps {
		if p.tested() {
			tested++
			ev = append(ev, p.host+": tested")
			continue
		}
		ev = append(ev, p.host+": not tested ("+p.reason+")")
	}
	if capped {
		ev = append(ev, fmt.Sprintf("only the first %d MX hosts were examined", maxMXHosts))
	}
	if tested == 0 {
		return []finding.Finding{stFinding(idSTService, finding.StatusUnknown, "", ev,
			"no MX host could be tested, so nothing is known about STARTTLS: "+ps[0].reason)}
	}
	detail := ""
	if tested < len(ps) {
		detail = fmt.Sprintf("%d of %d MX hosts could not be tested", len(ps)-tested, len(ps))
	}
	out = append(out, stFinding(idSTService, finding.StatusInfo, "", ev, detail))

	out = append(out, offeredFinding(ps, domain))
	if f := tlsVersionFinding(ps, domain); f != nil {
		out = append(out, *f)
	}
	if f := certificateFinding(ps, domain, now); f != nil {
		out = append(out, *f)
	}
	if f := daneMatchFinding(ps); f != nil {
		out = append(out, *f)
	}
	return out
}

func offeredFinding(ps []hostProbe, domain string) finding.Finding {
	var ev, bad, why []string
	for _, p := range ps {
		switch p.outcome {
		case outNoTLS:
			ev = append(ev, p.host+": STARTTLS not offered")
			bad = append(bad, p.host)
			why = append(why, p.host+" does not offer STARTTLS")
		case outRefused:
			ev = append(ev, p.host+": STARTTLS offered but refused ("+p.reason+")")
			bad = append(bad, p.host)
			why = append(why, p.host+" advertises STARTTLS but refuses it ("+p.reason+")")
		case outHandshake, outInspected:
			ev = append(ev, p.host+": STARTTLS offered")
		}
	}
	if len(bad) == 0 {
		return stFinding(idSTOffered, finding.StatusPass, finding.SeverityHigh, ev, "")
	}
	f := stFinding(idSTOffered, finding.StatusFail, finding.SeverityHigh, ev,
		strings.Join(why, "; ")+": mail is delivered to it without encryption (or not at all), and senders that require TLS cannot deliver")
	f.Fixer = fixerFor(bad, domain)
	return f
}

func tlsVersionFinding(ps []hostProbe, domain string) *finding.Finding {
	var ev, old, failed []string
	for _, p := range ps {
		switch {
		case p.outcome == outHandshake:
			ev = append(ev, p.host+": TLS handshake failed ("+p.reason+")")
			failed = append(failed, p.host)
		case p.res != nil:
			ev = append(ev, fmt.Sprintf("%s: %s %s", p.host, tlsprobe.VersionName(p.res.TLSVersion), cipherName(p.res.CipherSuite)))
			if p.res.TLSVersion < tlsprobe.VersionTLS12 {
				old = append(old, p.host)
			}
		}
	}
	if len(ev) == 0 {
		return nil
	}
	var f finding.Finding
	switch {
	case len(old) > 0:
		f = stFinding(idSTTLS, finding.StatusFail, finding.SeverityHigh, ev,
			"the best protocol "+strings.Join(old, ", ")+" negotiated is older than TLS 1.2 (obsolete since RFC 8996)")
		f.Fixer = fixerFor(old, domain)
	case len(failed) > 0:
		f = stFinding(idSTTLS, finding.StatusWarn, finding.SeverityMedium, ev,
			"the TLS handshake failed after STARTTLS on "+strings.Join(failed, ", ")+": the server may support only protocols or suites that current clients refuse")
		f.Fixer = fixerFor(failed, domain)
	default:
		f = stFinding(idSTTLS, finding.StatusPass, finding.SeverityMedium, ev, "")
	}
	return &f
}

func certificateFinding(ps []hostProbe, domain string, now time.Time) *finding.Finding {
	var ev, bad []string
	for _, p := range ps {
		if p.res == nil {
			continue
		}
		problems := certProblems(p.res, p.host, now)
		if len(problems) == 0 {
			leaf := p.res.Chain[0]
			ev = append(ev, fmt.Sprintf("%s: trusted chain, name matches, valid until %s (%d days)",
				p.host, leaf.NotAfter.UTC().Format("2006-01-02"), int(leaf.NotAfter.Sub(now)/day)))
			continue
		}
		bad = append(bad, p.host)
		ev = append(ev, p.host+": "+strings.Join(problems, "; "))
	}
	if len(ev) == 0 {
		return nil
	}
	if len(bad) == 0 {
		f := stFinding(idSTCert, finding.StatusPass, finding.SeverityMedium, ev, "")
		return &f
	}
	f := stFinding(idSTCert, finding.StatusWarn, finding.SeverityMedium, ev,
		"most senders accept this (opportunistic TLS), but a sender that enforces MTA-STS or DANE will refuse to deliver to these hosts")
	f.Fixer = fixerFor(bad, domain)
	return &f
}

// certProblems lists what is wrong with the certificate an MX host presents.
func certProblems(res *certinspect.Result, host string, now time.Time) []string {
	var out []string
	leaf := res.Chain[0]
	if res.Trust.Kind != certinspect.TrustOK {
		out = append(out, fmt.Sprintf("the chain is not trusted (%s: %s)", res.Trust.Kind, res.Trust.Detail))
	}
	if res.Hostname != nil {
		out = append(out, "the certificate is not valid for "+host)
	}
	if tp := res.Time; tp != nil {
		if tp.Expired {
			out = append(out, fmt.Sprintf("the certificate of %q expired on %s", tp.Subject, tp.NotAfter.UTC().Format("2006-01-02")))
		} else {
			out = append(out, fmt.Sprintf("the certificate of %q is not yet valid (starts %s)", tp.Subject, tp.NotBefore.UTC().Format("2006-01-02")))
		}
	} else if remaining := leaf.NotAfter.Sub(now); remaining < 14*day {
		out = append(out, fmt.Sprintf("the certificate expires in %d days", int(remaining/day)))
	}
	if k := certKeyFinding(leaf); k.Status == finding.StatusFail {
		out = append(out, k.Detail)
	}
	if s := certSignatureFinding(res.Chain); s.Status == finding.StatusFail {
		out = append(out, "weak signature: "+strings.Join(s.Evidence, ", "))
	}
	return out
}

func cipherName(id uint16) string {
	for _, s := range tlsprobe.Suites {
		if s.ID == id {
			return s.Name
		}
	}
	return fmt.Sprintf("0x%04x", id)
}

// daneMatchFinding judges, for hosts whose TLSA records are DNSSEC-authenticated,
// whether the certificate presented matches one of them. It returns nil when
// no host has both usable authenticated records and an inspected certificate.
func daneMatchFinding(ps []hostProbe) *finding.Finding {
	var ev, bad []string
	for _, p := range ps {
		if p.dane.state != daneAuthenticated || p.res == nil {
			continue
		}
		var usable []*dns.TLSA
		for _, r := range p.dane.records {
			if tlsaProblem(r) == "" {
				usable = append(usable, r)
			}
		}
		if len(usable) == 0 {
			continue
		}
		matched := false
		for _, r := range usable {
			if tlsaMatches(r, p.res.Chain, p.host) {
				matched = true
				ev = append(ev, fmt.Sprintf("%s: matches TLSA record %s", p.host, tlsaTriple(r)))
				break
			}
		}
		if !matched {
			ev = append(ev, fmt.Sprintf("%s: the certificate matches none of its %d TLSA record(s)", p.host, len(usable)))
			bad = append(bad, p.host)
		}
	}
	if len(ev) == 0 {
		return nil
	}
	if len(bad) == 0 {
		f := stFinding(idDANEMatch, finding.StatusPass, finding.SeverityHigh, ev, "")
		return &f
	}
	f := stFinding(idDANEMatch, finding.StatusFail, finding.SeverityHigh, ev,
		"senders that use DANE will refuse to deliver mail to "+strings.Join(bad, ", ")+" until the TLSA records and the certificate agree (often a certificate was renewed without updating DNS)")
	return &f
}

// tlsaMatches implements the matching of RFC 6698 §2.1 for the two usages that
// SMTP uses (RFC 7672 §3.1): DANE-EE (3) pins the end-entity certificate and
// ignores names and dates; DANE-TA (2) pins a certificate of the presented
// chain that really signed the certificates below it, and still needs the
// host name to match.
func tlsaMatches(r *dns.TLSA, chain []*x509.Certificate, host string) bool {
	want, err := hex.DecodeString(r.Certificate)
	if err != nil || len(chain) == 0 {
		return false
	}
	switch r.Usage {
	case 3:
		return bytes.Equal(tlsaData(chain[0], r.Selector, r.MatchingType), want)
	case 2:
		if chain[0].VerifyHostname(host) != nil {
			return false
		}
		for i, c := range chain {
			if !bytes.Equal(tlsaData(c, r.Selector, r.MatchingType), want) {
				continue
			}
			if chainLinked(chain[:i+1]) {
				return true
			}
		}
	}
	return false
}

// chainLinked reports whether every certificate of chain is signed by the next.
func chainLinked(chain []*x509.Certificate) bool {
	for i := 0; i+1 < len(chain); i++ {
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return false
		}
	}
	return true
}

func tlsaData(c *x509.Certificate, selector, matching uint8) []byte {
	var data []byte
	switch selector {
	case 0:
		data = c.Raw
	case 1:
		data = c.RawSubjectPublicKeyInfo
	default:
		return nil
	}
	switch matching {
	case 0:
		return data
	case 1:
		sum := sha256.Sum256(data)
		return sum[:]
	case 2:
		sum := sha512.Sum512(data)
		return sum[:]
	}
	return nil
}
