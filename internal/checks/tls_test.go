package checks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/tlsprobe"
)

const (
	tlsLegacy  = "transport.tls.legacy"
	tlsModern  = "transport.tls.modern"
	tlsWeak    = "transport.tls.weakciphers"
	tlsDiscour = "transport.tls.discouraged"
	tlsFS      = "transport.tls.forwardsecrecy"
	tlsInv     = "transport.tls.inventory"
	tlsService = "transport.tls.service"
)

// report builds a tlsprobe.Report from suites accepted per version.
func report(accepted map[uint16][]uint16) *tlsprobe.Report {
	r := &tlsprobe.Report{}
	for _, v := range []uint16{tlsprobe.VersionSSL30, tlsprobe.VersionTLS10, tlsprobe.VersionTLS11, tlsprobe.VersionTLS12, tlsprobe.VersionTLS13} {
		r.Versions = append(r.Versions, tlsprobe.VersionResult{Version: v, Supported: len(accepted[v]) > 0, Ciphers: accepted[v]})
	}
	r.Conns = 20
	return r
}

func suiteID(t *testing.T, name string) uint16 {
	t.Helper()
	for _, s := range tlsprobe.Suites {
		if s.Name == name {
			return s.ID
		}
	}
	t.Fatalf("no suite named %s", name)
	return 0
}

func ids(t *testing.T, names ...string) []uint16 {
	var out []uint16
	for _, n := range names {
		out = append(out, suiteID(t, n))
	}
	return out
}

func status(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	return get(t, fs, id)
}

const (
	gcmECDHE  = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	chachaFS  = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	tls13AES  = "TLS_AES_128_GCM_SHA256"
	rsa3DES   = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	rsaRC4    = "TLS_RSA_WITH_RC4_128_SHA"
	rsaNULL   = "TLS_RSA_WITH_NULL_SHA"
	anonDH    = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
	exportRC4 = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
	cbcECDHE  = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	staticGCM = "TLS_RSA_WITH_AES_128_GCM_SHA256"
)

func TestAssessTLSReport(t *testing.T) {
	v12, v13, v10, v11, v3 := tlsprobe.VersionTLS12, tlsprobe.VersionTLS13, tlsprobe.VersionTLS10, tlsprobe.VersionTLS11, tlsprobe.VersionSSL30

	tests := []struct {
		name     string
		accepted map[uint16][]uint16
		want     map[string]finding.Status
		severity map[string]finding.Severity
	}{
		{
			name:     "modern: TLS 1.2 and 1.3, AEAD with forward secrecy only",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, chachaFS), v13: ids(t, tls13AES)},
			want:     map[string]finding.Status{tlsLegacy: finding.StatusPass, tlsModern: finding.StatusPass, tlsWeak: finding.StatusPass, tlsDiscour: finding.StatusPass, tlsFS: finding.StatusPass, tlsInv: finding.StatusInfo},
		},
		{
			name:     "TLS 1.3 only",
			accepted: map[uint16][]uint16{v13: ids(t, tls13AES)},
			want:     map[string]finding.Status{tlsLegacy: finding.StatusPass, tlsModern: finding.StatusPass, tlsFS: finding.StatusPass, tlsWeak: finding.StatusPass},
		},
		{
			name:     "TLS 1.2 only: fine, but 1.3 is missing",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE)},
			want:     map[string]finding.Status{tlsModern: finding.StatusWarn, tlsLegacy: finding.StatusPass},
			severity: map[string]finding.Severity{tlsModern: finding.SeverityLow},
		},
		{
			name:     "SSLv3 is critical",
			accepted: map[uint16][]uint16{v3: ids(t, rsa3DES), v12: ids(t, gcmECDHE)},
			want:     map[string]finding.Status{tlsLegacy: finding.StatusFail},
			severity: map[string]finding.Severity{tlsLegacy: finding.SeverityCritical},
		},
		{
			name:     "TLS 1.0 and 1.1 are high",
			accepted: map[uint16][]uint16{v10: ids(t, cbcECDHE), v11: ids(t, cbcECDHE), v12: ids(t, gcmECDHE)},
			want:     map[string]finding.Status{tlsLegacy: finding.StatusFail},
			severity: map[string]finding.Severity{tlsLegacy: finding.SeverityHigh},
		},
		{
			name:     "only legacy versions: nothing modern",
			accepted: map[uint16][]uint16{v10: ids(t, cbcECDHE)},
			want:     map[string]finding.Status{tlsModern: finding.StatusFail, tlsLegacy: finding.StatusFail},
			severity: map[string]finding.Severity{tlsModern: finding.SeverityHigh},
		},
		{
			name:     "NULL encryption accepted",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, rsaNULL)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusFail},
			severity: map[string]finding.Severity{tlsWeak: finding.SeverityCritical},
		},
		{
			name:     "anonymous and export suites",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, anonDH), v10: ids(t, exportRC4)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusFail},
			severity: map[string]finding.Severity{tlsWeak: finding.SeverityCritical},
		},
		{
			name:     "RC4 is high",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, rsaRC4)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusFail},
			severity: map[string]finding.Severity{tlsWeak: finding.SeverityHigh},
		},
		{
			name:     "3DES alone is medium",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, rsa3DES)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusFail},
			severity: map[string]finding.Severity{tlsWeak: finding.SeverityMedium},
		},
		{
			name:     "static RSA key exchange: discouraged by IANA, not broken, and no forward secrecy",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, cbcECDHE, staticGCM)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusPass, tlsDiscour: finding.StatusWarn, tlsFS: finding.StatusWarn},
			severity: map[string]finding.Severity{tlsDiscour: finding.SeverityLow, tlsFS: finding.SeverityLow},
		},
		{
			name:     "a weak suite is reported once, as weak, not again as merely discouraged",
			accepted: map[uint16][]uint16{v12: ids(t, gcmECDHE, rsaRC4)},
			want:     map[string]finding.Status{tlsWeak: finding.StatusFail, tlsDiscour: finding.StatusPass},
		},
		{
			name:     "no forward secrecy at all",
			accepted: map[uint16][]uint16{v12: ids(t, staticGCM)},
			want:     map[string]finding.Status{tlsFS: finding.StatusFail},
			severity: map[string]finding.Severity{tlsFS: finding.SeverityMedium},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checks.AssessTLSReport(report(tt.accepted))
			wantStatuses(t, got, tt.want)
			for id, sev := range tt.severity {
				if f := get(t, got, id); f.Severity != sev {
					t.Errorf("%s severity = %q, want %q (%+v)", id, f.Severity, sev, f)
				}
			}
		})
	}
}

func TestAssessTLSReportEvidenceNamesTheOffendingSuites(t *testing.T) {
	r := report(map[uint16][]uint16{tlsprobe.VersionTLS12: ids(t, gcmECDHE, rsaRC4, rsa3DES, exportRC4)})

	got := checks.AssessTLSReport(r)

	weak := status(t, got, tlsWeak)
	ev := strings.Join(weak.Evidence, "\n")
	for _, want := range []string{rsaRC4, rsa3DES, exportRC4, "TLS 1.2"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence should list %q, got:\n%s", want, ev)
		}
	}
	if strings.Contains(ev, gcmECDHE) {
		t.Errorf("a good suite must not be listed as weak:\n%s", ev)
	}
	if !strings.Contains(weak.Detail, "RC4") || !strings.Contains(weak.Detail, "export") {
		t.Errorf("detail should explain why (RC4, export): %q", weak.Detail)
	}
	if weak.Fixer != finding.FixerOrganization {
		t.Errorf("fixer = %q", weak.Fixer)
	}
}

func TestAssessTLSReportInventory(t *testing.T) {
	r := report(map[uint16][]uint16{tlsprobe.VersionTLS12: ids(t, gcmECDHE, chachaFS), tlsprobe.VersionTLS13: ids(t, tls13AES)})

	inv := status(t, checks.AssessTLSReport(r), tlsInv)

	if len(inv.Evidence) != 2 || !strings.HasPrefix(inv.Evidence[0], "TLS 1.2: 2 suites") || !strings.Contains(inv.Evidence[0], gcmECDHE) {
		t.Fatalf("one line per accepted version, with the suite names, got %v", inv.Evidence)
	}
	if !strings.HasPrefix(inv.Evidence[1], "TLS 1.3: 1 suite") {
		t.Errorf("got %v", inv.Evidence)
	}
}

func TestAssessTLSReportEvidenceIsBounded(t *testing.T) {
	var all []uint16
	for _, s := range tlsprobe.Suites {
		if !tlsprobe.IsSCSV(s) && !tlsprobe.IsTLS13(s) && tlsprobe.Assess(s).Level >= tlsprobe.LevelMedium {
			all = append(all, s.ID)
		}
	}
	if len(all) < 40 {
		t.Fatalf("test needs many weak suites, found %d", len(all))
	}

	weak := status(t, checks.AssessTLSReport(report(map[uint16][]uint16{tlsprobe.VersionTLS12: all})), tlsWeak)

	if len(weak.Evidence) > 25 || !strings.Contains(strings.Join(weak.Evidence, " "), "more") {
		t.Fatalf("evidence must be capped and say how many were left out; got %d lines", len(weak.Evidence))
	}
}

// A scan that could not finish proves nothing about what it did not reach, so
// it may never end in "pass".
func TestIncompleteScansNeverClaimAPass(t *testing.T) {
	r := report(map[uint16][]uint16{tlsprobe.VersionTLS12: ids(t, gcmECDHE), tlsprobe.VersionTLS13: ids(t, tls13AES)})
	r.Incomplete = true

	got := checks.AssessTLSReport(r)

	for _, id := range []string{tlsLegacy, tlsModern, tlsWeak, tlsDiscour, tlsFS} {
		f := get(t, got, id)
		if f.Status != finding.StatusUnknown || !strings.Contains(f.Detail, "incomplete") {
			t.Errorf("%s = %+v: on an incomplete scan a pass must become unknown, with the reason", id, f)
		}
	}
}

func TestIncompleteScansStillReportWhatTheyFound(t *testing.T) {
	r := report(map[uint16][]uint16{tlsprobe.VersionTLS12: ids(t, gcmECDHE, rsaRC4)})
	r.Incomplete = true

	got := checks.AssessTLSReport(r)

	if f := get(t, got, tlsWeak); f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("a weakness that WAS found stays a failure on an incomplete scan, got %+v", f)
	}
}

// ---- Run, against real TLS servers --------------------------------------

var (
	rsaOnce sync.Once
	rsaCert tls.Certificate
)

func rsaCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		rsaCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	})
	return rsaCert
}

func serve(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handler(c)
			}()
		}
	}()
	return l.Addr().String()
}

func tlsServer(t *testing.T, cfg *tls.Config) string {
	return serve(t, func(c net.Conn) { _ = tls.Server(c, cfg).Handshake() })
}

type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// dialTo returns an engine.Deps.Dial that records the requested address and
// connects to the local test server instead.
func dialTo(local string, log *dialLog) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if log != nil {
			log.mu.Lock()
			log.addrs = append(log.addrs, addr)
			log.mu.Unlock()
		}
		return (&net.Dialer{}).DialContext(ctx, network, local)
	}
}

func runTLS(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) []finding.Finding {
	t.Helper()
	c := checks.TLS{Delay: -1}
	if c.Tier() != finding.TierActive {
		t.Fatal("probing a server's TLS connects to it, so the check must be active")
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{DNS: dnsxtest.New(), Dial: dial})
}

func TestTLSCheckAgainstAModernServer(t *testing.T) {
	ec, rsaC := leafECDSA(t), rsaCertificate(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ec, rsaC}, MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9}})
	log := &dialLog{}

	got := runTLS(t, dialTo(addr, log))

	wantStatuses(t, got, map[string]finding.Status{tlsLegacy: finding.StatusPass, tlsModern: finding.StatusPass, tlsWeak: finding.StatusPass,
		tlsDiscour: finding.StatusPass, tlsFS: finding.StatusPass})
	for _, a := range log.seen() {
		if a != "example.com:443" {
			t.Fatalf("the check must connect to the domain on port 443 through the supplied dialer, got %q", a)
		}
	}
	if n := len(log.seen()); n < 10 || n > 40 {
		t.Errorf("a modern server takes about 20 connections, used %d", n)
	}
}

func TestTLSCheckAgainstALegacyServer(t *testing.T) {
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{rsaCertificate(t)}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{0x000A, 0x0005, 0x002F, 0xC013, 0xC02F}})

	got := runTLS(t, dialTo(addr, nil))

	wantStatuses(t, got, map[string]finding.Status{tlsLegacy: finding.StatusFail, tlsModern: finding.StatusWarn, tlsWeak: finding.StatusFail,
		tlsDiscour: finding.StatusWarn, tlsFS: finding.StatusWarn})
	if f := get(t, got, tlsLegacy); f.Severity != finding.SeverityHigh {
		t.Errorf("TLS 1.0/1.1 is high, got %+v", f)
	}
	weak := get(t, got, tlsWeak)
	if weak.Severity != finding.SeverityHigh || !strings.Contains(strings.Join(weak.Evidence, " "), rsaRC4) {
		t.Errorf("RC4 must make it high and be named, got %+v", weak)
	}
}

func TestTLSCheckConnectionProblems(t *testing.T) {
	tests := []struct {
		name   string
		dial   func(context.Context, string, string) (net.Conn, error)
		status finding.Status
		detail string
	}{
		{"nothing listens", func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED },
			finding.StatusInfo, "no HTTPS"},
		{"the name does not resolve", func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
		}, finding.StatusInfo, "no address"},
		{"non-public address is refused", func(context.Context, string, string) (net.Conn, error) { return nil, safenet.ErrNonPublicAddress },
			finding.StatusUnknown, "non-public"},
		{"network unreachable is our problem", func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ENETUNREACH },
			finding.StatusUnknown, "unreachable"},
		{"timeout says nothing about the domain", func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded },
			finding.StatusUnknown, "timed out"},
		{"anything else is unknown", func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("boom") },
			finding.StatusUnknown, "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runTLS(t, tt.dial)

			if len(got) != 1 || got[0].ID != tlsService || got[0].Status != tt.status {
				t.Fatalf("want a single %s finding with status %s, got %+v", tlsService, tt.status, got)
			}
			if !strings.Contains(strings.ToLower(got[0].Detail), strings.ToLower(tt.detail)) {
				t.Errorf("detail %q should mention %q", got[0].Detail, tt.detail)
			}
		})
	}
}

func TestTLSCheckPortThatIsNotTLS(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
	})

	got := runTLS(t, dialTo(addr, nil))

	if len(got) != 1 || got[0].ID != tlsService || got[0].Status != finding.StatusInfo || !strings.Contains(got[0].Detail, "not TLS") {
		t.Fatalf("got %+v", got)
	}
}

func TestTLSCheckServerThatAcceptsNothingWeOffer(t *testing.T) {
	addr := serve(t, func(c net.Conn) {}) // accepts and closes

	got := runTLS(t, dialTo(addr, nil))

	if len(got) != 1 || got[0].Status != finding.StatusUnknown || !strings.Contains(got[0].Detail, "host name") {
		t.Fatalf("a server that refuses every offer may need a specific name or client certificate: that is unknown, not a verdict, got %+v", got)
	}
}

func TestTLSCheckWithoutADialer(t *testing.T) {
	got := checks.TLS{Delay: -1}.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{})
	if len(got) != 1 || got[0].Status != finding.StatusUnknown {
		t.Fatalf("got %+v", got)
	}
}

func TestTLSCheckAsksForMoreTimeThanTheDefault(t *testing.T) {
	// The probe makes many connections in series; the default 10 s is not enough.
	var c engine.Check = checks.TLS{}
	tc, ok := c.(engine.Timeouter)
	if !ok || tc.Timeout() < 60*time.Second {
		t.Fatalf("TLS must implement engine.Timeouter with at least 60s, ok=%v", ok)
	}
}

func TestTLSCheckPausesBetweenConnectionsByDefault(t *testing.T) {
	// Not a timing test: the default delay is part of being polite to servers.
	if d := fmt.Sprint(checks.DefaultTLSDelay); d != "20ms" {
		t.Fatalf("default pause between probes = %s, want 20ms", d)
	}
}

// leafECDSA is a throwaway ECDSA certificate; the probe never validates it.
func leafECDSA(t *testing.T) tls.Certificate {
	t.Helper()
	return newPKI(t).leaf(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}
