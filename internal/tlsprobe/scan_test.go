package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	certOnce           sync.Once
	rsaCert, ecdsaCert tls.Certificate
	certErr            error
)

// testCerts returns a self-signed RSA and ECDSA certificate. The probe never
// validates certificates, so self-signed ones are enough.
func testCerts(t *testing.T) (tls.Certificate, tls.Certificate) {
	t.Helper()
	certOnce.Do(func() {
		mk := func(pub, priv any) (tls.Certificate, error) {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
				DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
			if err != nil {
				return tls.Certificate{}, err
			}
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
		}
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			certErr = err
			return
		}
		if rsaCert, certErr = mk(&rk.PublicKey, rk); certErr != nil {
			return
		}
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			certErr = err
			return
		}
		ecdsaCert, certErr = mk(&ek.PublicKey, ek)
	})
	if certErr != nil {
		t.Fatal(certErr)
	}
	return rsaCert, ecdsaCert
}

// serve runs handler for every connection of a local listener.
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

// tlsServer is a real Go TLS server with the given configuration.
func tlsServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	return serve(t, func(c net.Conn) { _ = tls.Server(c, cfg).Handshake() })
}

func session(addr string) *Session {
	return &Session{
		Dial:       func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) },
		ServerName: "example.com",
		Timeout:    2 * time.Second,
		Sleep:      func(context.Context, time.Duration) error { return nil },
	}
}

func scan(t *testing.T, addr string) *Report {
	t.Helper()
	r, err := Scan(context.Background(), session(addr))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return r
}

func ids(vs []uint16) []uint16 {
	out := append([]uint16(nil), vs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func equal(a, b []uint16) bool {
	a, b = ids(a), ids(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func versionResult(t *testing.T, r *Report, v uint16) VersionResult {
	t.Helper()
	for _, vr := range r.Versions {
		if vr.Version == v {
			return vr
		}
	}
	t.Fatalf("no result for %s in %+v", VersionName(v), r.Versions)
	return VersionResult{}
}

func supportedVersions(r *Report) []uint16 {
	var out []uint16
	for _, vr := range r.Versions {
		if vr.Supported {
			out = append(out, vr.Version)
		}
	}
	return out
}

func TestScanModernServer(t *testing.T) {
	rsaC, ecC := testCerts(t)
	suites := []uint16{0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9}
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC, rsaC}, MinVersion: tls.VersionTLS12, CipherSuites: suites})

	r := scan(t, addr)

	if got := supportedVersions(r); !equal(got, []uint16{VersionTLS12, VersionTLS13}) {
		t.Fatalf("supported versions = %x, want TLS 1.2 and 1.3", got)
	}
	if got := versionResult(t, r, VersionTLS12).Ciphers; !equal(got, suites) {
		t.Errorf("TLS 1.2 suites = %x, want exactly %x", ids(got), ids(suites))
	}
	if got := versionResult(t, r, VersionTLS13).Ciphers; !equal(got, []uint16{0x1301, 0x1302, 0x1303}) {
		t.Errorf("TLS 1.3 suites = %x, want the three Go implements", ids(got))
	}
	for _, v := range []uint16{VersionSSL30, VersionTLS10, VersionTLS11} {
		if versionResult(t, r, v).Supported {
			t.Errorf("%s must not be reported as supported", VersionName(v))
		}
	}
	if r.Incomplete || r.NotTLS != "" {
		t.Errorf("a normal scan is complete and TLS: %+v", r)
	}
	if r.Conns < 10 || r.Conns > 40 {
		t.Errorf("a modern server needs about 20 connections, used %d", r.Conns)
	}
}

func TestScanLegacyServerWithWeakSuites(t *testing.T) {
	rsaC, _ := testCerts(t)
	const (
		rsa3DES = 0x000A
		rsaRC4  = 0x0005
		rsaAES  = 0x002F
		ecdheCB = 0xC013
		ecdheGC = 0xC02F
	)
	addr := tlsServer(t, &tls.Config{
		Certificates: []tls.Certificate{rsaC}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{rsa3DES, rsaRC4, rsaAES, ecdheCB, ecdheGC},
	})

	r := scan(t, addr)

	if got := supportedVersions(r); !equal(got, []uint16{VersionTLS10, VersionTLS11, VersionTLS12}) {
		t.Fatalf("supported versions = %x, want TLS 1.0, 1.1 and 1.2", got)
	}
	// GCM suites do not exist before TLS 1.2.
	old := []uint16{rsa3DES, rsaRC4, rsaAES, ecdheCB}
	for _, v := range []uint16{VersionTLS10, VersionTLS11} {
		if got := versionResult(t, r, v).Ciphers; !equal(got, old) {
			t.Errorf("%s suites = %x, want %x", VersionName(v), ids(got), ids(old))
		}
	}
	if got := versionResult(t, r, VersionTLS12).Ciphers; !equal(got, append(old, ecdheGC)) {
		t.Errorf("TLS 1.2 suites = %x", ids(got))
	}
	if versionResult(t, r, VersionSSL30).Supported || versionResult(t, r, VersionTLS13).Supported {
		t.Error("SSLv3 and TLS 1.3 are not enabled on this server")
	}
}

func TestScanOnlyTLS13(t *testing.T) {
	_, ecC := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC}, MinVersion: tls.VersionTLS13})

	r := scan(t, addr)

	if got := supportedVersions(r); !equal(got, []uint16{VersionTLS13}) {
		t.Fatalf("supported versions = %x, want only TLS 1.3", got)
	}
	if len(versionResult(t, r, VersionTLS12).Ciphers) != 0 {
		t.Error("no TLS 1.2 suite may be reported for a TLS 1.3-only server")
	}
}

func TestScanOnlyStaticRSA(t *testing.T) {
	rsaC, _ := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{rsaC}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{0x009C}})

	r := scan(t, addr)

	if got := versionResult(t, r, VersionTLS12).Ciphers; !equal(got, []uint16{0x009C}) {
		t.Fatalf("TLS 1.2 suites = %x, want only TLS_RSA_WITH_AES_128_GCM_SHA256", got)
	}
}

// A server that only speaks TLS 1.0 answers a TLS 1.2 hello with a TLS 1.0
// ServerHello. That must not be mistaken for TLS 1.2 support.
func TestScanServerThatAnswersWithAnOlderVersion(t *testing.T) {
	rsaC, _ := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{rsaC}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
		CipherSuites: []uint16{0x002F, 0x0035}})

	r := scan(t, addr)

	if got := supportedVersions(r); !equal(got, []uint16{VersionTLS10}) {
		t.Fatalf("supported versions = %x, want only TLS 1.0: an older answer to a newer offer is a refusal of the newer version", got)
	}
	if got := versionResult(t, r, VersionTLS10).Ciphers; !equal(got, []uint16{0x002F, 0x0035}) {
		t.Errorf("TLS 1.0 suites = %x", ids(got))
	}
}

func TestScanPortThatIsNotTLS(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	})

	r := scan(t, addr)

	if r.NotTLS == "" {
		t.Fatalf("an HTTP reply must be reported as not TLS: %+v", r)
	}
	if len(supportedVersions(r)) != 0 {
		t.Errorf("no version can be supported: %+v", r.Versions)
	}
	if r.Conns != 1 {
		t.Errorf("a port that does not speak TLS must stop the scan after one connection, used %d", r.Conns)
	}
}

func TestScanServerThatClosesWithoutAnswer(t *testing.T) {
	addr := serve(t, func(c net.Conn) {})

	r := scan(t, addr)

	if len(supportedVersions(r)) != 0 || r.NotTLS != "" {
		t.Fatalf("a closed connection is a 'no' for every version, got %+v", r)
	}
	if r.Conns != 5 {
		t.Errorf("every version is asked once, used %d connections", r.Conns)
	}
}

func TestScanConnectionRefusedIsAnError(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()

	_, err := Scan(context.Background(), session(addr))

	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want connection refused", err)
	}
	var pe *ProbeError
	if !errors.As(err, &pe) || pe.Phase != "connect" {
		t.Errorf("a failed connection is a connect-phase ProbeError, got %v", err)
	}
}

func TestScanSilentServerTimesOut(t *testing.T) {
	addr := serve(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	s := session(addr)
	s.Timeout = 150 * time.Millisecond

	_, err := Scan(context.Background(), s)

	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestScanConnectionBudget(t *testing.T) {
	rsaC, ecC := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC, rsaC}, MinVersion: tls.VersionTLS12})
	s := session(addr)
	s.MaxConns = 3

	r, err := Scan(context.Background(), s)

	if err != nil {
		t.Fatal(err)
	}
	if !r.Incomplete || r.Conns != 3 {
		t.Fatalf("Incomplete=%v Conns=%d, want an incomplete scan that stopped at the budget of 3", r.Incomplete, r.Conns)
	}
}

func TestScanPausesBetweenProbes(t *testing.T) {
	rsaC, ecC := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC, rsaC}, MinVersion: tls.VersionTLS12})
	s := session(addr)
	s.Delay = 25 * time.Millisecond
	var sleeps []time.Duration
	s.Sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }

	r, err := Scan(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	if len(sleeps) != r.Conns-1 {
		t.Fatalf("slept %d times for %d connections, want one pause between consecutive probes", len(sleeps), r.Conns)
	}
	for _, d := range sleeps {
		if d != 25*time.Millisecond {
			t.Fatalf("pause = %s", d)
		}
	}
}

func TestScanStopsWhenTheContextIsCancelled(t *testing.T) {
	rsaC, ecC := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC, rsaC}, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithCancel(context.Background())
	s := session(addr)
	probes := 0
	dial := s.Dial
	s.Dial = func(ctx context.Context) (net.Conn, error) {
		probes++
		if probes == 3 {
			cancel()
		}
		return dial(ctx)
	}

	r, err := Scan(ctx, s)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if r == nil || !r.Incomplete || probes > 4 {
		t.Fatalf("a cancelled scan returns what it has, marked incomplete, and stops probing (probes=%d, report=%+v)", probes, r)
	}
}

func TestProbeBuildsAValidTLS13ClientHelloWithARealKeyShare(t *testing.T) {
	_, ecC := testCerts(t)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecC}, MinVersion: tls.VersionTLS13})

	resp, err := session(addr).Probe(context.Background(), Spec{Version: VersionTLS13, Ciphers: TLS13Suites()})

	if err != nil || resp.Kind != KindServerHello || resp.Version != VersionTLS13 {
		t.Fatalf("got %+v, %v: Go's server must accept our TLS 1.3 hello", resp, err)
	}
}

// A broken or hostile server may "choose" a suite that was never offered. The
// probe must not trust that answer, and above all must not keep asking: the
// naive loop (remove the chosen suite, ask again) would run until the budget.
func TestScanServerThatChoosesASuiteThatWasNotOffered(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(hdr[3])<<8|int64(hdr[4]))
		hello := serverHelloMsg(VersionTLS12, [32]byte{1}, nil, 0xFEED, nil)
		_, _ = c.Write(record(22, VersionTLS12, hello))
	})

	r := scan(t, addr)

	if !r.Incomplete {
		t.Error("an answer outside the offer must make the report incomplete")
	}
	if r.Conns > 5 {
		t.Fatalf("used %d connections: the scan kept asking a server that answers nonsense", r.Conns)
	}
	if len(supportedVersions(r)) != 0 {
		t.Errorf("nothing may be reported as supported on the strength of a bogus answer: %+v", r.Versions)
	}
}
