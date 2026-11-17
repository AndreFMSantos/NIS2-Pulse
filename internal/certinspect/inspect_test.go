package certinspect

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var serial atomic.Int64

// authority is a test CA.
type authority struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRoot(t *testing.T, cn string) *authority {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &authority{c, k, der}
}

func (a *authority) intermediate(t *testing.T, cn string) *authority {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &k.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &authority{c, k, der}
}

type leafSpec struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	rsaBits   int // 0 means ECDSA P-256
}

func goodLeaf() leafSpec {
	return leafSpec{names: []string{"example.com"}, notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(60 * 24 * time.Hour)}
}

// issue signs a leaf and returns it as a tls.Certificate whose chain is the
// leaf followed by extra.
func (a *authority) issue(t *testing.T, s leafSpec, extra ...[]byte) tls.Certificate {
	t.Helper()
	var priv crypto.Signer
	var pub crypto.PublicKey
	if s.rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, s.rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, &k.PublicKey
	} else {
		k := newKey(t)
		priv, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: s.names[0]}, DNSNames: s.names,
		NotBefore: s.notBefore, NotAfter: s.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, pub, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: append([][]byte{der}, extra...), PrivateKey: priv}
}

func selfSignedLeaf(t *testing.T, s leafSpec) tls.Certificate {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: s.names[0]}, DNSNames: s.names,
		NotBefore: s.notBefore, NotAfter: s.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func pool(as ...*authority) *x509.CertPool {
	p := x509.NewCertPool()
	for _, a := range as {
		p.AddCert(a.cert)
	}
	return p
}

// server runs a real Go TLS server presenting cert. appData reports how many
// application-data bytes the client sent after the handshake.
type server struct {
	addr    string
	appData atomic.Int64
	done    chan struct{}
}

func serve(t *testing.T, cert tls.Certificate) *server {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s := &server{addr: l.Addr().String(), done: make(chan struct{}, 16)}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				tc := tls.Server(c, cfg)
				if tc.Handshake() != nil {
					return
				}
				n, _ := io.Copy(io.Discard, tc) // returns when the client closes
				s.appData.Add(n)
				s.done <- struct{}{}
			}()
		}
	}()
	return s
}

func (s *server) options(roots *x509.CertPool) Options {
	return Options{
		Dial:       func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", s.addr) },
		ServerName: "example.com",
		Roots:      roots,
		Timeout:    3 * time.Second,
	}
}

func inspect(t *testing.T, s *server, roots *x509.CertPool) *Result {
	t.Helper()
	r, err := Inspect(context.Background(), s.options(roots))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return r
}

func TestValidChain(t *testing.T) {
	root := newRoot(t, "Test Root")
	inter := root.intermediate(t, "Test Intermediate")
	s := serve(t, inter.issue(t, goodLeaf(), inter.der))

	r := inspect(t, s, pool(root))

	if r.Trust.Kind != TrustOK || r.Time != nil || r.Hostname != nil {
		t.Fatalf("a valid chain must verify: trust=%+v time=%+v hostname=%v", r.Trust, r.Time, r.Hostname)
	}
	if len(r.Chain) != 2 || r.Chain[0].Subject.CommonName != "example.com" || r.Chain[1].Subject.CommonName != "Test Intermediate" {
		t.Errorf("chain as presented (leaf first) = %v", subjects(r.Chain))
	}
	if r.TLSVersion == 0 || r.CipherSuite == 0 {
		t.Errorf("the negotiated version and suite should be recorded: %x %x", r.TLSVersion, r.CipherSuite)
	}
}

func subjects(cs []*x509.Certificate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func TestTimeProblemsAreSeparateFromTrust(t *testing.T) {
	root := newRoot(t, "Test Root")
	for _, tt := range []struct {
		name    string
		spec    func() leafSpec
		expired bool
	}{
		{"expired", func() leafSpec {
			s := goodLeaf()
			s.notBefore, s.notAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
			return s
		}, true},
		{"not yet valid", func() leafSpec {
			s := goodLeaf()
			s.notBefore, s.notAfter = time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)
			return s
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := serve(t, root.issue(t, tt.spec()))

			r := inspect(t, s, pool(root))

			if r.Time == nil || r.Time.Expired != tt.expired || r.Time.Subject != "example.com" {
				t.Fatalf("Time = %+v, want the leaf reported as expired=%v", r.Time, tt.expired)
			}
			// The chain is trusted: the time problem must not hide that, nor be reported as a trust failure.
			if r.Trust.Kind != TrustOK {
				t.Fatalf("an expired or premature certificate from a trusted CA is a time problem, not an untrusted chain: %+v", r.Trust)
			}
		})
	}
}

// The certificate that is out of date is the one the report must name, even
// when it is not the leaf: that tells the administrator what to renew.
func TestAnExpiredIntermediateIsNamed(t *testing.T) {
	root := newRoot(t, "Test Root")
	inter := root.intermediate(t, "Old Intermediate")    // valid for 24 hours
	s := serve(t, inter.issue(t, goodLeaf(), inter.der)) // the leaf is valid for 60 days
	o := s.options(pool(root))
	o.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }

	r, err := Inspect(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	if r.Time == nil || !r.Time.Expired || r.Time.Subject != "Old Intermediate" {
		t.Fatalf("Time = %+v, want the expired intermediate named (the leaf is still valid)", r.Time)
	}
}

func TestHostnameIsJudgedIndependentlyOfTrust(t *testing.T) {
	root := newRoot(t, "Test Root")
	spec := goodLeaf()
	spec.names = []string{"www.other.example"}
	s := serve(t, root.issue(t, spec))

	r := inspect(t, s, pool(root))

	if r.Trust.Kind != TrustOK {
		t.Errorf("the chain is fine: %+v", r.Trust)
	}
	var he x509.HostnameError
	if !errors.As(r.Hostname, &he) {
		t.Fatalf("Hostname = %v, want a hostname error", r.Hostname)
	}
}

func TestWildcardCoversOneLabel(t *testing.T) {
	root := newRoot(t, "Test Root")
	spec := goodLeaf()
	spec.names = []string{"*.example.com"}
	s := serve(t, root.issue(t, spec))
	o := s.options(pool(root))
	o.ServerName = "www.example.com"

	r, err := Inspect(context.Background(), o)
	if err != nil || r.Hostname != nil {
		t.Fatalf("*.example.com covers www.example.com: err=%v hostname=%v", err, r.Hostname)
	}
}

func TestTrustFailures(t *testing.T) {
	root := newRoot(t, "Test Root")
	other := newRoot(t, "Untrusted Root")
	otherInter := other.intermediate(t, "Untrusted Intermediate")
	inter := root.intermediate(t, "Test Intermediate")

	tests := []struct {
		name   string
		cert   tls.Certificate
		want   TrustKind
		detail string
	}{
		{"self-signed leaf", selfSignedLeaf(t, goodLeaf()), TrustSelfSigned, "self-signed"},
		{"the server sends a root that is not trusted", other.issue(t, goodLeaf(), other.der), TrustUntrustedRoot, "Untrusted Root"},
		{"the issuer is unknown: untrusted CA, root not sent", otherInter.issue(t, goodLeaf(), otherInter.der), TrustUnknownIssuer, "issuer"},
		{"missing intermediate: only the leaf is sent", inter.issue(t, goodLeaf()), TrustUnknownIssuer, "intermediate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := serve(t, tt.cert)

			r := inspect(t, s, pool(root))

			if r.Trust.Kind != tt.want {
				t.Fatalf("trust = %+v, want kind %s", r.Trust, tt.want)
			}
			if !strings.Contains(r.Trust.Detail, tt.detail) {
				t.Errorf("detail %q should mention %q", r.Trust.Detail, tt.detail)
			}
		})
	}
}

func TestOtherTrustProblemsAreStillReported(t *testing.T) {
	// A leaf that may not be used for TLS servers: the chain does not verify,
	// and whatever the reason, it must be reported, never swallowed.
	root := newRoot(t, "Test Root")
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // wrong purpose
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &k.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k})

	r := inspect(t, s, pool(root))

	if r.Trust.Kind != TrustOther || r.Trust.Detail == "" {
		t.Fatalf("a chain that fails for another reason is TrustOther with an explanation, got %+v", r.Trust)
	}
}

// The exception to "never skip verification" is only acceptable if the
// connection is used for nothing but reading the certificate.
func TestInspectNeverSendsApplicationData(t *testing.T) {
	root := newRoot(t, "Test Root")
	s := serve(t, root.issue(t, goodLeaf()))

	_ = inspect(t, s, pool(root))

	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the server never saw the client close the connection")
	}
	if n := s.appData.Load(); n != 0 {
		t.Fatalf("the inspector sent %d bytes of application data; it may only read the certificate", n)
	}
}

func TestInspectSendsOnlyTheFarewellWhenGiven(t *testing.T) {
	root := newRoot(t, "Test Root")
	s := serve(t, root.issue(t, goodLeaf()))
	o := s.options(pool(root))
	o.Farewell = []byte("QUIT\r\n")

	if _, err := Inspect(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the server never saw the client close the connection")
	}
	if n := s.appData.Load(); n != int64(len("QUIT\r\n")) {
		t.Fatalf("the server received %d bytes of application data, want exactly the farewell (6)", n)
	}
}

func TestInspectAlsoReadsCertificatesThatFailVerification(t *testing.T) {
	// This is the reason for the exception: a verifying client would refuse to
	// connect and we would learn nothing about the broken certificate.
	s := serve(t, selfSignedLeaf(t, goodLeaf()))

	r := inspect(t, s, x509.NewCertPool())

	if len(r.Chain) != 1 || r.Chain[0].Subject.CommonName != "example.com" {
		t.Fatalf("the unverifiable certificate must still be read, got %v", subjects(r.Chain))
	}
	if r.Trust.Kind == TrustOK {
		t.Fatal("reading a certificate must never imply trusting it")
	}
}

func TestInspectErrors(t *testing.T) {
	t.Run("not a TLS server", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		defer func() { _ = l.Close() }()
		go func() {
			c, err := l.Accept()
			if err == nil {
				_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
				_ = c.Close()
			}
		}()
		o := Options{Dial: func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
		}, ServerName: "example.com"}

		if r, err := Inspect(context.Background(), o); err == nil || r != nil {
			t.Fatalf("a handshake that cannot complete is an error, got %+v, %v", r, err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		_ = l.Close()
		o := Options{Dial: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) }, ServerName: "example.com"}

		if _, err := Inspect(context.Background(), o); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("no dialer", func(t *testing.T) {
		if _, err := Inspect(context.Background(), Options{ServerName: "example.com"}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestInspectHonoursTheContext(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(2 * time.Second); _ = c.Close() }() // accepts, never answers
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	o := Options{Dial: func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}, ServerName: "example.com"}

	start := time.Now()
	_, err := Inspect(ctx, o)

	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("a silent server must not hold the inspector beyond its context (err=%v after %s)", err, time.Since(start))
	}
}

// InsecureSkipVerify is allowed in exactly one production file, once. This is
// the guard that keeps the exception from spreading.
func TestInsecureSkipVerifyIsConfinedToTheInspector(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := filepath.Join("internal", "certinspect", "inspect.go")
	var inInspector int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "bin") {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		n := strings.Count(string(src), "InsecureSkipVerify")
		rel, _ := filepath.Rel(root, path)
		switch {
		case rel == allowed:
			inInspector = n
		case n > 0:
			t.Errorf("%s mentions InsecureSkipVerify: only the certificate inspector may skip verification", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// One assignment, plus the comment that explains it; never more than two mentions.
	if inInspector < 1 || inInspector > 2 {
		t.Fatalf("inspect.go mentions InsecureSkipVerify %d times, want 1 or 2 (the assignment and its comment)", inInspector)
	}
}
