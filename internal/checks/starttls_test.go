package checks_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec/dnssectest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
)

const (
	stService = "email.starttls.service"
	stOffered = "email.starttls.offered"
	stTLS     = "email.starttls.tls"
	stCert    = "email.starttls.cert"
	stDANE    = "email.dane.match"
)

// mxOpts scripts one fake mail server.
type mxOpts struct {
	greeting      string // default "220 mx ESMTP ready"
	noSTARTTLS    bool
	startTLSCode  string // reply to STARTTLS; default "220 2.0.0 Ready to start TLS"
	hangUpAfterOK bool   // say 220 to STARTTLS, then close without a handshake
	cert          *tls.Certificate
	minVer        uint16
	maxVer        uint16
}

// mxServer is a fake SMTP server that really upgrades to TLS.
type mxServer struct {
	addr string

	mu       sync.Mutex
	commands []string // plaintext commands
	tlsData  []string // lines received inside the tunnel
	conns    int
}

func (m *mxServer) plain() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.commands...)
}

func (m *mxServer) inside() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.tlsData...)
}

func (m *mxServer) connections() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns
}

func startMX(t *testing.T, o mxOpts) *mxServer {
	t.Helper()
	if o.greeting == "" {
		o.greeting = "220 mx ESMTP ready"
	}
	if o.startTLSCode == "" {
		o.startTLSCode = "220 2.0.0 Ready to start TLS"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	m := &mxServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			m.mu.Lock()
			m.conns++
			m.mu.Unlock()
			go m.handle(c, o)
		}
	}()
	return m
}

func (m *mxServer) handle(c net.Conn, o mxOpts) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	write := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	write(o.greeting)
	if !strings.HasPrefix(o.greeting, "220") {
		return
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		m.mu.Lock()
		m.commands = append(m.commands, line)
		m.mu.Unlock()
		switch u := strings.ToUpper(line); {
		case strings.HasPrefix(u, "EHLO"):
			if o.noSTARTTLS {
				write("250-mx\r\n250 SIZE 1000")
			} else {
				write("250-mx\r\n250-SIZE 1000\r\n250 STARTTLS")
			}
		case strings.HasPrefix(u, "STARTTLS"):
			write(o.startTLSCode)
			if !strings.HasPrefix(o.startTLSCode, "220") {
				continue
			}
			if o.hangUpAfterOK {
				return
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{*o.cert}, MinVersion: o.minVer, MaxVersion: o.maxVer}
			tc := tls.Server(c, cfg)
			if tc.Handshake() != nil {
				return
			}
			tr := bufio.NewReader(tc)
			for {
				l, err := tr.ReadString('\n')
				if l != "" {
					m.mu.Lock()
					m.tlsData = append(m.tlsData, strings.TrimRight(l, "\r\n"))
					m.mu.Unlock()
				}
				if err != nil {
					return
				}
			}
		case strings.HasPrefix(u, "QUIT"):
			write("221 bye")
			return
		default:
			write("502 not implemented")
		}
	}
}

// mxDialer routes "<host>:25" to fake servers and records every address asked for.
type mxDialer struct {
	mu     sync.Mutex
	routes map[string]string // host:25 -> local address
	asked  []string
	err    error // returned for every dial when set
}

func (d *mxDialer) dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.asked = append(d.asked, addr)
	local, ok := d.routes[addr]
	err := d.err
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("test dialer: no route for %s", addr)
	}
	return net.Dial(network, local)
}

func (d *mxDialer) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.asked...)
}

func newMXDialer(routes map[string]*mxServer) *mxDialer {
	d := &mxDialer{routes: map[string]string{}}
	for host, s := range routes {
		d.routes[host+":25"] = s.addr
	}
	return d
}

func runStartTLS(t *testing.T, w *dnssectest.World, pki *testPKI, d *mxDialer, ehlo string) []finding.Finding {
	t.Helper()
	c := checks.StartTLS{Anchors: w.Anchors, EHLOName: ehlo}
	if pki != nil {
		c.Roots = pki.pool
	}
	if c.Tier() != finding.TierActive {
		t.Fatal("STARTTLS connects to mail servers, so it must be active")
	}
	var dial func(context.Context, string, string) (net.Conn, error)
	if d != nil {
		dial = d.dial
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.pt"},
		engine.Deps{DNS: w.Fake, Dial: dial, Now: func() time.Time { return w.Now }})
}

// stNow is the clock of the signed test world (dnssectest). Certificates are
// issued relative to it, never to the real clock, so the tests do not start
// failing when the world's signatures would have expired in real time.
var stNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// mxPKI is a CA that is valid at stNow.
func mxPKI(t *testing.T) *testPKI { return newPKIFrom(t, stNow.Add(-48*time.Hour)) }

func mxCert(t *testing.T, pki *testPKI, names ...string) *tls.Certificate {
	t.Helper()
	c := pki.leaf(t, names, stNow.Add(-time.Hour), stNow.Add(90*24*time.Hour))
	return &c
}

// tlsaFor builds a TLSA record for host that matches cert (usage 3, SPKI, SHA-256).
func tlsaFor(t *testing.T, host string, cert *tls.Certificate) dns.RR {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return dnsxtest.TLSA(tlsaName(host), 3, 1, 1, hex.EncodeToString(sum[:]))
}

// mxWorld is a signed hierarchy whose domain has the given MX hosts.
func mxWorld(t *testing.T, hosts ...string) *dnssectest.World {
	t.Helper()
	w := daneWorld(t, dnssectest.Options{}, hosts...)
	if !w.Now.Equal(stNow) {
		t.Fatalf("the signed world's clock is %s, not %s: update stNow", w.Now, stNow)
	}
	return w
}

func TestStartTLSHappyPath(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "mail.example.pt")})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})

	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, "")

	for id, want := range map[string]finding.Status{
		stService: finding.StatusInfo, stOffered: finding.StatusPass, stTLS: finding.StatusPass, stCert: finding.StatusPass,
	} {
		if f := byID(fs, id); f == nil || f.Status != want {
			t.Fatalf("%s = %+v, want %s (all: %+v)", id, f, want, fs)
		}
	}
	if byID(fs, stDANE) != nil {
		t.Fatal("no TLSA record: there is nothing to match")
	}
	if got := d.addrs(); len(got) != 1 || got[0] != "mail.example.pt:25" {
		t.Fatalf("dialled %v, want only mail.example.pt:25", got)
	}
	time.Sleep(100 * time.Millisecond)
	if n := srv.connections(); n != 1 {
		t.Fatalf("%d connections to the server, want exactly 1", n)
	}
	if got := strings.Join(srv.plain(), "|"); got != "EHLO nis2-pulse.invalid|STARTTLS" {
		t.Fatalf("plaintext commands %q", got)
	}
	if got := strings.Join(srv.inside(), "|"); got != "QUIT" {
		t.Fatalf("inside the tunnel the client sent %q, want only QUIT", got)
	}
}

func TestStartTLSUsesTheConfiguredEHLOName(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "mail.example.pt")})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, "scanner.example.org")
	if got := srv.plain(); len(got) == 0 || got[0] != "EHLO scanner.example.org" {
		t.Fatalf("commands %v", got)
	}
}

func TestStartTLSNoMailMeansNoConnections(t *testing.T) {
	for _, name := range []string{"no MX", "null MX"} {
		t.Run(name, func(t *testing.T) {
			w := mxWorld(t)
			if name == "null MX" {
				w.Fake.Add(dnsxtest.MX("example.pt", 0, "."))
			}
			d := newMXDialer(nil)
			fs := runStartTLS(t, w, nil, d, "")
			if len(fs) != 1 || fs[0].ID != stService || fs[0].Status != finding.StatusInfo {
				t.Fatalf("got %+v", fs)
			}
			if len(d.addrs()) != 0 {
				t.Fatalf("dialled %v for a domain that receives no mail", d.addrs())
			}
		})
	}
}

func TestStartTLSMXLookupFailureIsUnknown(t *testing.T) {
	w := mxWorld(t, "mail.example.pt")
	w.Fake.SetRcode("example.pt", dns.TypeMX, dns.RcodeServerFailure)
	d := newMXDialer(nil)
	fs := runStartTLS(t, w, nil, d, "")
	if len(fs) != 1 || fs[0].Status != finding.StatusUnknown || len(d.addrs()) != 0 {
		t.Fatalf("got %+v dialled %v", fs, d.addrs())
	}
}

func TestStartTLSNotOffered(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{noSTARTTLS: true, cert: mxCert(t, pki, "mail.example.pt")})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, "")
	f := byID(fs, stOffered)
	if f == nil || f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("got %+v", f)
	}
	if byID(fs, stTLS) != nil || byID(fs, stCert) != nil {
		t.Fatal("without STARTTLS there is no TLS to assess")
	}
}

func TestStartTLSAdvertisedButRefused(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{startTLSCode: "454 4.7.0 TLS not available due to local problem", cert: mxCert(t, pki, "mail.example.pt")})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	f := byID(runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, ""), stOffered)
	if f == nil || f.Status != finding.StatusFail || !strings.Contains(f.Detail, "454") {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSHandshakeFailsAfterTheServerSaidGoAhead(t *testing.T) {
	srv := startMX(t, mxOpts{hangUpAfterOK: true})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), nil, d, "")
	f := byID(fs, stTLS)
	if f == nil || f.Status != finding.StatusWarn || f.Severity != finding.SeverityMedium {
		t.Fatalf("got %+v", f)
	}
	if o := byID(fs, stOffered); o == nil || o.Status != finding.StatusPass {
		t.Fatalf("the server did offer STARTTLS: %+v", o)
	}
}

func TestStartTLSNothingTestedIsUnknown(t *testing.T) {
	tests := []struct {
		name string
		err  error
		srv  *mxOpts
	}{
		{"connection refused", syscall.ECONNREFUSED, nil},
		{"timeout", context.DeadlineExceeded, nil},
		{"non-public address", safenet.ErrNonPublicAddress, nil},
		{"network unreachable", syscall.ENETUNREACH, nil},
		{"greeting refuses", nil, &mxOpts{greeting: "554 5.7.1 go away"}},
		{"greeting asks to come back later", nil, &mxOpts{greeting: "421 4.3.2 busy"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newMXDialer(nil)
			if tc.srv != nil {
				srv := startMX(t, *tc.srv)
				d = newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
			} else {
				d.err = tc.err
			}
			fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), nil, d, "")
			if len(fs) != 1 || fs[0].ID != stService || fs[0].Status != finding.StatusUnknown {
				t.Fatalf("got %+v", fs)
			}
		})
	}
}

func TestStartTLSPortBlockedDetailMentionsOutboundFiltering(t *testing.T) {
	d := newMXDialer(nil)
	d.err = context.DeadlineExceeded
	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), nil, d, "")
	if !strings.Contains(fs[0].Detail, "port 25") {
		t.Fatalf("detail %q should explain that outbound port 25 is often blocked", fs[0].Detail)
	}
}

func TestStartTLSCertificateProblems(t *testing.T) {
	pki := mxPKI(t)
	other := mxPKI(t)
	mk := func(c tls.Certificate) *tls.Certificate { return &c }
	tests := []struct {
		name string
		cert *tls.Certificate
		want string // substring of the evidence
	}{
		{"expired", mk(pki.leaf(t, []string{"mail.example.pt"}, stNow.Add(-3*time.Hour), stNow.Add(-2*time.Hour))), "expired"},
		{"wrong name", mxCert(t, pki, "other.example.net"), "mail.example.pt"},
		{"untrusted issuer", mxCert(t, other, "mail.example.pt"), "trusted"},
		{"expires in a week", mk(pki.leaf(t, []string{"mail.example.pt"}, stNow.Add(-time.Hour), stNow.Add(7*24*time.Hour))), "expires"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startMX(t, mxOpts{cert: tc.cert})
			d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
			f := byID(runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, ""), stCert)
			if f == nil || f.Status != finding.StatusWarn || f.Severity != finding.SeverityMedium {
				t.Fatalf("got %+v", f)
			}
			if !strings.Contains(strings.Join(f.Evidence, " "), tc.want) {
				t.Fatalf("evidence %v should mention %q", f.Evidence, tc.want)
			}
			if f.Fixer != finding.FixerOrganization {
				t.Fatalf("fixer %q: the MX host is inside the domain", f.Fixer)
			}
		})
	}
}

func TestStartTLSCertificateProblemOnAProviderHostIsTheProvidersToFix(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "other.example.net")}) // wrong name
	w := mxWorld(t, "mx.provider.example")
	d := newMXDialer(map[string]*mxServer{"mx.provider.example": srv})
	f := byID(runStartTLS(t, w, pki, d, ""), stCert)
	if f == nil || f.Status != finding.StatusWarn || f.Fixer != finding.FixerProvider {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSOldProtocolOnly(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "mail.example.pt"), minVer: tls.VersionTLS10, maxVer: tls.VersionTLS11})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	f := byID(runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, ""), stTLS)
	if f == nil || f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSTLS12IsAccepted(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "mail.example.pt"), minVer: tls.VersionTLS12, maxVer: tls.VersionTLS12})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	if f := byID(runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, ""), stTLS); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSDANEMatch(t *testing.T) {
	pki := mxPKI(t)
	cert := mxCert(t, pki, "mail.example.pt")
	srv := startMX(t, mxOpts{cert: cert})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})

	t.Run("record matches the certificate", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsaFor(t, "mail.example.pt", cert))
		f := byID(runStartTLS(t, w, pki, d, ""), stDANE)
		if f == nil || f.Status != finding.StatusPass {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("record matches another certificate", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsaFor(t, "mail.example.pt", mxCert(t, pki, "mail.example.pt")))
		f := byID(runStartTLS(t, w, pki, d, ""), stDANE)
		if f == nil || f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
			t.Fatalf("got %+v", f)
		}
		if !strings.Contains(f.Detail, "refuse") {
			t.Fatalf("detail %q should say that DANE senders will refuse to deliver", f.Detail)
		}
	})
	t.Run("a stale record next to the current one is fine (rollover)", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK,
			tlsaFor(t, "mail.example.pt", mxCert(t, pki, "mail.example.pt")), tlsaFor(t, "mail.example.pt", cert))
		if f := byID(runStartTLS(t, w, pki, d, ""), stDANE); f == nil || f.Status != finding.StatusPass {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("unauthenticated record is ignored, as senders ignore it", func(t *testing.T) {
		w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")
		w.Fake.Add(dnsxtest.MX("example.pt", 10, "mail.example.pt"))
		w.Fake.AddFor(tlsaName("mail.example.pt"), dns.TypeTLSA, dnsxtest.TLSA(tlsaName("mail.example.pt"), 3, 1, 1, sha256Hex))
		if f := byID(runStartTLS(t, w, pki, d, ""), stDANE); f != nil {
			t.Fatalf("unexpected %+v", f)
		}
	})
	t.Run("only unusable records: nothing to match", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), 1, 1, 1, sha256Hex))
		if f := byID(runStartTLS(t, w, pki, d, ""), stDANE); f != nil {
			t.Fatalf("unexpected %+v (email.dane.params already reports unusable records)", f)
		}
	})
}

func TestStartTLSDANEWithTrustAnchorUsage(t *testing.T) {
	pki := mxPKI(t)
	leaf := pki.leaf(t, []string{"mail.example.pt"}, stNow.Add(-time.Hour), stNow.Add(90*24*time.Hour))
	chain := leaf
	chain.Certificate = append(append([][]byte(nil), leaf.Certificate...), pki.ca.Raw) // the server sends leaf + CA
	srv := startMX(t, mxOpts{cert: &chain})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	caSum := sha256.Sum256(pki.ca.Raw)
	ta := dnsxtest.TLSA(tlsaName("mail.example.pt"), 2, 0, 1, hex.EncodeToString(caSum[:]))

	t.Run("CA in the chain matches", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, ta)
		if f := byID(runStartTLS(t, w, pki, d, ""), stDANE); f == nil || f.Status != finding.StatusPass {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("another CA does not", func(t *testing.T) {
		w := mxWorld(t, "mail.example.pt")
		otherSum := sha256.Sum256(mxPKI(t).ca.Raw)
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), 2, 0, 1, hex.EncodeToString(otherSum[:])))
		if f := byID(runStartTLS(t, w, pki, d, ""), stDANE); f == nil || f.Status != finding.StatusFail {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("a matching CA that did not sign the leaf does not count", func(t *testing.T) {
		stranger := mxPKI(t)
		bad := leaf
		bad.Certificate = [][]byte{leaf.Certificate[0], stranger.ca.Raw} // chain that does not link
		badSrv := startMX(t, mxOpts{cert: &bad})
		bd := newMXDialer(map[string]*mxServer{"mail.example.pt": badSrv})
		sum := sha256.Sum256(stranger.ca.Raw)
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), 2, 0, 1, hex.EncodeToString(sum[:])))
		if f := byID(runStartTLS(t, w, pki, bd, ""), stDANE); f == nil || f.Status != finding.StatusFail {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("DANE-TA still needs the host name to match", func(t *testing.T) {
		wrong := pki.leaf(t, []string{"other.example.net"}, stNow.Add(-time.Hour), stNow.Add(90*24*time.Hour))
		wrong.Certificate = append(wrong.Certificate, pki.ca.Raw)
		wrongSrv := startMX(t, mxOpts{cert: &wrong})
		wd := newMXDialer(map[string]*mxServer{"mail.example.pt": wrongSrv})
		w := mxWorld(t, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, ta)
		if f := byID(runStartTLS(t, w, pki, wd, ""), stDANE); f == nil || f.Status != finding.StatusFail {
			t.Fatalf("got %+v", f)
		}
	})
}

func TestStartTLSDANEEEIgnoresNamesAndExpiry(t *testing.T) {
	// RFC 7672 §3.1.1: with DANE-EE the TLSA record, not the certificate's names
	// or dates, is what vouches for the server.
	pki := mxPKI(t)
	expiredWrongName := pki.leaf(t, []string{"other.example.net"}, stNow.Add(-3*time.Hour), stNow.Add(-2*time.Hour))
	srv := startMX(t, mxOpts{cert: &expiredWrongName})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	w := mxWorld(t, "mail.example.pt")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsaFor(t, "mail.example.pt", &expiredWrongName))
	fs := runStartTLS(t, w, pki, d, "")
	if f := byID(fs, stDANE); f == nil || f.Status != finding.StatusPass {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSExaminesEachHostOnceAndAtMostTen(t *testing.T) {
	pki := mxPKI(t)
	var names []string
	routes := map[string]*mxServer{}
	for i := 0; i < 12; i++ {
		h := fmt.Sprintf("mx%02d.example.pt", i)
		names = append(names, h)
		routes[h] = startMX(t, mxOpts{cert: mxCert(t, pki, h)})
	}
	names = append(names, "mx00.example.pt") // duplicate
	d := newMXDialer(routes)
	fs := runStartTLS(t, mxWorld(t, names...), pki, d, "")
	if got := d.addrs(); len(got) != 10 {
		t.Fatalf("%d connections: %v, want 10 (cap, and no duplicates)", len(got), got)
	}
	seen := map[string]bool{}
	for _, a := range d.addrs() {
		if seen[a] {
			t.Fatalf("%s contacted twice", a)
		}
		seen[a] = true
	}
	if f := byID(fs, stService); f == nil || !strings.Contains(strings.Join(f.Evidence, " "), "first 10") {
		t.Fatalf("the cap must be reported: %+v", f)
	}
}

func TestStartTLSWithoutDialerIsUnknown(t *testing.T) {
	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), nil, nil, "")
	if len(fs) != 1 || fs[0].Status != finding.StatusUnknown {
		t.Fatalf("got %+v", fs)
	}
}

func TestStartTLSRejectsAnUnsafeEHLONameWithoutConnecting(t *testing.T) {
	d := newMXDialer(nil)
	fs := runStartTLS(t, mxWorld(t, "mail.example.pt"), nil, d, "evil\r\nMAIL FROM:<a@b>")
	if len(d.addrs()) != 0 || len(fs) != 1 || fs[0].Status != finding.StatusUnknown {
		t.Fatalf("got %+v dialled %v", fs, d.addrs())
	}
}

func TestStartTLSIsRegisteredAndSkippedWithoutActive(t *testing.T) {
	var st engine.Check
	for _, c := range checks.Default(checks.Options{}) {
		if _, ok := c.(checks.StartTLS); ok {
			st = c
		}
	}
	if st == nil {
		t.Fatal("StartTLS is not in checks.Default")
	}
	d := newMXDialer(nil)
	w := mxWorld(t, "mail.example.pt")
	fs := engine.Run(context.Background(), engine.Target{Domain: "example.pt"}, []engine.Check{st},
		engine.Deps{DNS: w.Fake, Dial: d.dial}, engine.Options{})
	if len(d.addrs()) != 0 {
		t.Fatalf("dialled %v without --active", d.addrs())
	}
	if len(fs) != 1 || fs[0].Status != finding.StatusUnknown || !strings.Contains(fs[0].Detail, "--active") {
		t.Fatalf("got %+v", fs)
	}
}

func TestStartTLSAsksForMoreTimeThanTheDefault(t *testing.T) {
	if tm, ok := any(checks.StartTLS{}).(engine.Timeouter); !ok || tm.Timeout() <= engine.DefaultCheckTimeout {
		t.Fatal("up to ten hosts in series need more than the default timeout")
	}
}

func TestStartTLSReportsHowManyHostsCouldNotBeTested(t *testing.T) {
	pki := mxPKI(t)
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "mx1.example.pt")})
	d := newMXDialer(map[string]*mxServer{"mx1.example.pt": srv}) // mx2 has no route: connection error
	f := byID(runStartTLS(t, mxWorld(t, "mx1.example.pt", "mx2.example.pt"), pki, d, ""), stService)
	if f == nil || f.Status != finding.StatusInfo || !strings.Contains(f.Detail, "1 of 2") {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSOnlyHostsInsideTheDomainAreTheDomainsToFix(t *testing.T) {
	pki := mxPKI(t)
	// "mail.notexample.pt" ends with "example.pt" but is not inside it.
	srv := startMX(t, mxOpts{cert: mxCert(t, pki, "other.example.net")})
	w := mxWorld(t, "mail.notexample.pt")
	d := newMXDialer(map[string]*mxServer{"mail.notexample.pt": srv})
	f := byID(runStartTLS(t, w, pki, d, ""), stCert)
	if f == nil || f.Fixer != finding.FixerProvider {
		t.Fatalf("got %+v", f)
	}
}

func TestStartTLSDANEEEMatchingParameters(t *testing.T) {
	pki := mxPKI(t)
	cert := mxCert(t, pki, "mail.example.pt")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	s256 := func(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
	s512 := func(b []byte) string { x := sha512.Sum512(b); return hex.EncodeToString(x[:]) }
	tests := []struct {
		name         string
		sel, mtype   uint8
		data         string
		wantMatching bool
	}{
		{"cert, full", 0, 0, hex.EncodeToString(leaf.Raw), true},
		{"cert, sha256", 0, 1, s256(leaf.Raw), true},
		{"cert, sha512", 0, 2, s512(leaf.Raw), true},
		{"spki, full", 1, 0, hex.EncodeToString(leaf.RawSubjectPublicKeyInfo), true},
		{"spki, sha256", 1, 1, s256(leaf.RawSubjectPublicKeyInfo), true},
		{"spki, sha512", 1, 2, s512(leaf.RawSubjectPublicKeyInfo), true},
		{"selector 1 with a digest of the whole certificate", 1, 1, s256(leaf.Raw), false},
		{"selector 0 with a digest of the key", 0, 1, s256(leaf.RawSubjectPublicKeyInfo), false},
		{"sha512 with a sha256 of the right data", 1, 2, s256(leaf.RawSubjectPublicKeyInfo) + s256(leaf.RawSubjectPublicKeyInfo), false},
		{"mixed-case hex still matches", 1, 1, strings.ToUpper(s256(leaf.RawSubjectPublicKeyInfo)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startMX(t, mxOpts{cert: cert})
			d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
			w := mxWorld(t, "mail.example.pt")
			w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), 3, tc.sel, tc.mtype, tc.data))
			f := byID(runStartTLS(t, w, pki, d, ""), stDANE)
			want := finding.StatusFail
			if tc.wantMatching {
				want = finding.StatusPass
			}
			if f == nil || f.Status != want {
				t.Fatalf("got %+v, want %s", f, want)
			}
		})
	}
}

func rsaWeakLeaf(t *testing.T, pki *testPKI, host string, bits int) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: stNow.Add(-time.Hour), NotAfter: stNow.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.ca, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestStartTLSWeakKeyIsAProblem(t *testing.T) {
	pki := mxPKI(t)
	weak := rsaWeakLeaf(t, pki, "mail.example.pt", 1024)
	srv := startMX(t, mxOpts{cert: &weak})
	d := newMXDialer(map[string]*mxServer{"mail.example.pt": srv})
	f := byID(runStartTLS(t, mxWorld(t, "mail.example.pt"), pki, d, ""), stCert)
	if f == nil || f.Status != finding.StatusWarn || !strings.Contains(strings.Join(f.Evidence, " "), "1024") {
		t.Fatalf("got %+v", f)
	}
}
