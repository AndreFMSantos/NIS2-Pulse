package checks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/certinspect"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	certChain   = "transport.cert.chain"
	certHost    = "transport.cert.hostname"
	certValid   = "transport.cert.validity"
	certLife    = "transport.cert.lifetime"
	certKey     = "transport.cert.key"
	certSig     = "transport.cert.signature"
	certInv     = "transport.cert.inventory"
	certService = "transport.cert.service"
)

var certNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// fakeCert builds a certificate struct with exactly the fields the assessment
// reads. It is not signed: the pure assessment never verifies signatures, and
// building it by hand lets the tests cover keys and signature algorithms that
// Go refuses to generate (1024-bit RSA is allowed, P-224 and SHA-1 are not).
type certOpts struct {
	cn        string
	names     []string
	notBefore time.Time
	notAfter  time.Time
	key       any // *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
	sig       x509.SignatureAlgorithm
	issuer    string
}

func rsaPub(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

func ecPub(c elliptic.Curve) *ecdsa.PublicKey { return &ecdsa.PublicKey{Curve: c} }

func fakeCert(o certOpts) *x509.Certificate {
	if o.cn == "" {
		o.cn = "example.com"
	}
	if o.names == nil {
		o.names = []string{o.cn}
	}
	if o.notBefore.IsZero() {
		o.notBefore = certNow.Add(-30 * 24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = certNow.Add(60 * 24 * time.Hour)
	}
	if o.key == nil {
		o.key = ecPub(elliptic.P256())
	}
	if o.sig == 0 {
		o.sig = x509.ECDSAWithSHA256
	}
	if o.issuer == "" {
		o.issuer = "Test Intermediate"
	}
	c := &x509.Certificate{
		Subject: pkix.Name{CommonName: o.cn}, Issuer: pkix.Name{CommonName: o.issuer}, DNSNames: o.names,
		NotBefore: o.notBefore, NotAfter: o.notAfter, PublicKey: o.key, SignatureAlgorithm: o.sig,
		Raw: []byte(o.cn + "|" + o.issuer),
	}
	switch o.key.(type) {
	case *rsa.PublicKey:
		c.PublicKeyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		c.PublicKeyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		c.PublicKeyAlgorithm = x509.Ed25519
	}
	return c
}

// result builds a certinspect.Result around chain with a healthy verdict.
func result(chain ...*x509.Certificate) *certinspect.Result {
	return &certinspect.Result{
		ServerName: "example.com", Chain: chain, Trust: certinspect.Trust{Kind: certinspect.TrustOK},
		TLSVersion: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	}
}

func healthy() *certinspect.Result {
	return result(fakeCert(certOpts{}), fakeCert(certOpts{cn: "Test Intermediate", issuer: "Test Root", sig: x509.SHA256WithRSA}))
}

func assess(r *certinspect.Result) []finding.Finding { return checks.AssessCertificate(r, certNow) }

func TestAssessCertificateHealthy(t *testing.T) {
	got := assess(healthy())

	wantStatuses(t, got, map[string]finding.Status{certChain: finding.StatusPass, certHost: finding.StatusPass, certValid: finding.StatusPass,
		certLife: finding.StatusPass, certKey: finding.StatusPass, certSig: finding.StatusPass, certInv: finding.StatusInfo})
}

func TestAssessCertificateTrust(t *testing.T) {
	for _, tt := range []struct {
		kind   certinspect.TrustKind
		detail string
	}{
		{certinspect.TrustSelfSigned, "self-signed"},
		{certinspect.TrustUntrustedRoot, "root"},
		{certinspect.TrustUnknownIssuer, "intermediate"},
		{certinspect.TrustOther, "usage"},
	} {
		t.Run(string(tt.kind), func(t *testing.T) {
			r := healthy()
			r.Trust = certinspect.Trust{Kind: tt.kind, Detail: "explanation mentioning " + tt.detail}

			f := get(t, assess(r), certChain)

			if f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh || f.Fixer != finding.FixerOrganization {
				t.Fatalf("an untrusted chain is a high-severity failure for the organisation, got %+v", f)
			}
			if !strings.Contains(f.Detail, tt.detail) {
				t.Errorf("detail %q should carry the explanation", f.Detail)
			}
		})
	}
}

func TestAssessCertificateLifetimeIsOnlyJudgedForTrustedChains(t *testing.T) {
	r := healthy()
	r.Trust = certinspect.Trust{Kind: certinspect.TrustSelfSigned, Detail: "x"}

	for _, f := range assess(r) {
		if f.ID == certLife {
			t.Fatalf("the 398-day rule is for publicly trusted certificates; it says nothing about a self-signed one: %+v", f)
		}
	}
}

func TestAssessCertificateValidity(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name   string
		after  time.Time
		before time.Time
		time   *certinspect.TimeProblem
		want   finding.Status
		sev    finding.Severity
		detail string
	}{
		{"plenty of time", certNow.Add(90 * day), time.Time{}, nil, finding.StatusPass, finding.SeverityHigh, "days"},
		{"exactly 30 days", certNow.Add(30 * day), time.Time{}, nil, finding.StatusPass, finding.SeverityHigh, ""},
		{"29 days left", certNow.Add(29 * day), time.Time{}, nil, finding.StatusWarn, finding.SeverityMedium, "29"},
		{"13 days left", certNow.Add(13 * day), time.Time{}, nil, finding.StatusWarn, finding.SeverityHigh, "13"},
		{"two days left", certNow.Add(2 * day), time.Time{}, nil, finding.StatusWarn, finding.SeverityHigh, "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := result(fakeCert(certOpts{notAfter: tt.after}))

			f := get(t, assess(r), certValid)

			if f.Status != tt.want || f.Severity != tt.sev || !strings.Contains(f.Detail, tt.detail) {
				t.Fatalf("got %+v, want %s/%s mentioning %q", f, tt.want, tt.sev, tt.detail)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		r := result(fakeCert(certOpts{}))
		r.Time = &certinspect.TimeProblem{Subject: "example.com", Expired: true, NotAfter: certNow.Add(-3 * day)}

		f := get(t, assess(r), certValid)

		if f.Status != finding.StatusFail || f.Severity != finding.SeverityCritical || !strings.Contains(f.Detail, "expired") || !strings.Contains(f.Detail, "3 days ago") {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		r := result(fakeCert(certOpts{}))
		r.Time = &certinspect.TimeProblem{Subject: "example.com", Expired: false, NotBefore: certNow.Add(2 * day)}

		f := get(t, assess(r), certValid)

		if f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh || !strings.Contains(f.Detail, "not yet valid") {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("an expired intermediate is named", func(t *testing.T) {
		r := healthy()
		r.Time = &certinspect.TimeProblem{Subject: "Test Intermediate", Expired: true, NotAfter: certNow.Add(-day)}

		f := get(t, assess(r), certValid)

		if !strings.Contains(f.Detail, "Test Intermediate") {
			t.Fatalf("the administrator must be told WHICH certificate to renew, got %q", f.Detail)
		}
	})
}

func TestAssessCertificateHostname(t *testing.T) {
	r := result(fakeCert(certOpts{names: []string{"www.other.example", "other.example"}}))
	r.Hostname = x509.HostnameError{Certificate: r.Chain[0], Host: "example.com"}

	f := get(t, assess(r), certHost)

	if f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("got %+v", f)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "www.other.example") || !strings.Contains(f.Detail, "example.com") {
		t.Errorf("the finding must say which names the certificate covers and which was requested: %+v", f)
	}
}

func TestAssessCertificateLifetime(t *testing.T) {
	day := 24 * time.Hour
	d := func(y int, m time.Month, dd int) time.Time { return time.Date(y, m, dd, 0, 0, 0, 0, time.UTC) }
	// CA/Browser Forum Baseline Requirements 6.3.2: the maximum validity of a
	// publicly trusted certificate depends on the date it was issued.
	tests := []struct {
		name   string
		before time.Time
		days   int
		want   finding.Status
	}{
		{"90 days", d(2026, 6, 1), 90, finding.StatusPass},
		{"an old long-lived certificate is exempt", d(2019, 1, 1), 800, finding.StatusPass},
		{"398 days is the limit before 2026-03-15", d(2026, 3, 14), 398, finding.StatusPass},
		{"399 days before 2026-03-15", d(2026, 3, 14), 399, finding.StatusWarn},
		{"398 days issued on 2020-09-01", d(2020, 9, 1), 398, finding.StatusPass},
		{"399 days issued on 2020-09-01", d(2020, 9, 1), 399, finding.StatusWarn},
		{"200 days is the limit from 2026-03-15", d(2026, 3, 15), 200, finding.StatusPass},
		{"201 days from 2026-03-15", d(2026, 3, 15), 201, finding.StatusWarn},
		{"398 days issued in June 2026 is too long", d(2026, 6, 1), 398, finding.StatusWarn},
		{"100 days is the limit from 2027-03-15", d(2027, 3, 15), 100, finding.StatusPass},
		{"101 days from 2027-03-15", d(2027, 3, 15), 101, finding.StatusWarn},
		{"200 days from 2027-03-15 is too long", d(2027, 4, 1), 200, finding.StatusWarn},
		{"47 days is the limit from 2029-03-15", d(2029, 3, 15), 47, finding.StatusPass},
		{"48 days from 2029-03-15", d(2029, 3, 15), 48, finding.StatusWarn},
		{"two years", d(2026, 6, 1), 730, finding.StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := result(fakeCert(certOpts{notBefore: tt.before, notAfter: tt.before.Add(time.Duration(tt.days) * day)}))

			f := get(t, assess(r), certLife)

			if f.Status != tt.want {
				t.Fatalf("got %+v, want %s", f, tt.want)
			}
			if tt.want == finding.StatusWarn && f.Severity != finding.SeverityLow {
				t.Errorf("severity = %s, want low", f.Severity)
			}
			if tt.want == finding.StatusWarn && !strings.Contains(f.Detail, "days") {
				t.Errorf("the finding must state the limit that applies: %q", f.Detail)
			}
		})
	}
}

func TestAssessCertificateKey(t *testing.T) {
	tests := []struct {
		name string
		key  any
		want finding.Status
		text string
	}{
		{"RSA 4096", rsaPub(4096), finding.StatusPass, "RSA 4096"},
		{"RSA 3072", rsaPub(3072), finding.StatusPass, "RSA 3072"},
		{"RSA 2048", rsaPub(2048), finding.StatusPass, "RSA 2048"},
		{"RSA 2047", rsaPub(2047), finding.StatusFail, "2047"},
		{"RSA 1024", rsaPub(1024), finding.StatusFail, "1024"},
		{"RSA 512", rsaPub(512), finding.StatusFail, "512"},
		{"ECDSA P-256", ecPub(elliptic.P256()), finding.StatusPass, "P-256"},
		{"ECDSA P-384", ecPub(elliptic.P384()), finding.StatusPass, "P-384"},
		{"ECDSA P-521", ecPub(elliptic.P521()), finding.StatusPass, "P-521"},
		{"ECDSA P-224", ecPub(elliptic.P224()), finding.StatusFail, "224"},
		{"Ed25519", ed25519.PublicKey(make([]byte, 32)), finding.StatusPass, "Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := get(t, assess(result(fakeCert(certOpts{key: tt.key}))), certKey)

			if f.Status != tt.want {
				t.Fatalf("got %+v, want %s", f, tt.want)
			}
			if tt.want == finding.StatusFail && f.Severity != finding.SeverityHigh {
				t.Errorf("a weak key is high severity, got %s", f.Severity)
			}
			if !strings.Contains(strings.Join(f.Evidence, " ")+f.Detail, tt.text) {
				t.Errorf("the finding should state the key (%q): %+v", tt.text, f)
			}
		})
	}
}

func TestAssessCertificateSignature(t *testing.T) {
	good := fakeCert(certOpts{sig: x509.SHA256WithRSA})
	sha1Leaf := fakeCert(certOpts{sig: x509.SHA1WithRSA})
	sha1Inter := fakeCert(certOpts{cn: "Weak Intermediate", issuer: "Test Root", sig: x509.SHA1WithRSA})
	md5Inter := fakeCert(certOpts{cn: "MD5 Intermediate", issuer: "Test Root", sig: x509.MD5WithRSA})
	// A self-signed root presented by the server: its own signature proves nothing, so it is not judged.
	sha1Root := fakeCert(certOpts{cn: "Old Root", issuer: "Old Root", sig: x509.SHA1WithRSA})

	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  finding.Status
		named string
	}{
		{"sha256 everywhere", []*x509.Certificate{good, fakeCert(certOpts{cn: "I", issuer: "R", sig: x509.SHA384WithRSA})}, finding.StatusPass, ""},
		{"ECDSA with SHA-256", []*x509.Certificate{fakeCert(certOpts{sig: x509.ECDSAWithSHA256})}, finding.StatusPass, ""},
		{"RSA-PSS", []*x509.Certificate{fakeCert(certOpts{sig: x509.SHA256WithRSAPSS})}, finding.StatusPass, ""},
		{"Ed25519", []*x509.Certificate{fakeCert(certOpts{sig: x509.PureEd25519})}, finding.StatusPass, ""},
		{"SHA-1 leaf", []*x509.Certificate{sha1Leaf}, finding.StatusFail, "example.com"},
		{"SHA-1 intermediate", []*x509.Certificate{good, sha1Inter}, finding.StatusFail, "Weak Intermediate"},
		{"MD5 intermediate", []*x509.Certificate{good, md5Inter}, finding.StatusFail, "MD5 Intermediate"},
		{"ECDSA with SHA-1", []*x509.Certificate{fakeCert(certOpts{sig: x509.ECDSAWithSHA1})}, finding.StatusFail, "example.com"},
		{"a SHA-1 self-signed root is not judged", []*x509.Certificate{good, sha1Root}, finding.StatusPass, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := get(t, assess(result(tt.chain...)), certSig)

			if f.Status != tt.want {
				t.Fatalf("got %+v, want %s", f, tt.want)
			}
			if tt.named != "" && !strings.Contains(strings.Join(f.Evidence, " "), tt.named) {
				t.Errorf("the offending certificate %q must be named: %+v", tt.named, f)
			}
			if tt.want == finding.StatusFail && f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %s, want high", f.Severity)
			}
		})
	}
}

func TestAssessCertificateInventory(t *testing.T) {
	leaf := fakeCert(certOpts{cn: "example.com", names: []string{"example.com", "www.example.com"}, key: rsaPub(2048), sig: x509.SHA256WithRSA})
	inter := fakeCert(certOpts{cn: "Test Intermediate", issuer: "Test Root"})

	inv := get(t, assess(result(leaf, inter)), certInv)

	ev := strings.Join(inv.Evidence, "\n")
	for _, want := range []string{"example.com", "www.example.com", "Test Intermediate", "RSA 2048", "SHA256-RSA", "TLS 1.3", "sha256:"} {
		if !strings.Contains(ev, want) {
			t.Errorf("inventory should show %q:\n%s", want, ev)
		}
	}
}

func TestAssessCertificateInventoryBoundsLongNameLists(t *testing.T) {
	var names []string
	for i := 0; i < 200; i++ {
		names = append(names, "host"+strings.Repeat("x", i%5)+".example.com")
	}
	inv := get(t, assess(result(fakeCert(certOpts{names: names}))), certInv)

	if n := len(strings.Join(inv.Evidence, "\n")); n > 3000 {
		t.Fatalf("a certificate with 200 names must not produce a %d-byte inventory", n)
	}
	if !strings.Contains(strings.Join(inv.Evidence, " "), "more") {
		t.Error("the inventory should say how many names were left out")
	}
}

// ---- Run, against real TLS servers --------------------------------------

func certServer(t *testing.T, cert tls.Certificate) string {
	return tlsServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
}

func runCert(t *testing.T, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error)) []finding.Finding {
	t.Helper()
	c := checks.Cert{Roots: roots}
	if c.Tier() != finding.TierActive {
		t.Fatal("completing a TLS handshake connects to the server, so the check must be active")
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{DNS: dnsxtest.New(), Dial: dial})
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestCertCheckAgainstAValidServer(t *testing.T) {
	pki := newPKI(t)
	addr := certServer(t, pki.leaf(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))
	log := &dialLog{}

	got := runCert(t, pki.pool, dialTo(addr, log))

	wantStatuses(t, got, map[string]finding.Status{certChain: finding.StatusPass, certHost: finding.StatusPass, certValid: finding.StatusPass,
		certKey: finding.StatusPass, certSig: finding.StatusPass})
	if seen := log.seen(); len(seen) != 1 || seen[0] != "example.com:443" {
		t.Fatalf("one connection to the domain on port 443, got %v", seen)
	}
}

func TestCertCheckAgainstBrokenServers(t *testing.T) {
	pki, other := newPKIFrom(t, time.Now().Add(-1000*time.Hour)), newPKI(t)
	now := time.Now()

	tests := []struct {
		name string
		cert tls.Certificate
		want map[string]finding.Status
	}{
		{"expired", pki.leaf(t, []string{"example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
			map[string]finding.Status{certValid: finding.StatusFail, certChain: finding.StatusPass, certHost: finding.StatusPass}},
		{"expires in 10 days", pki.leaf(t, []string{"example.com"}, now.Add(-time.Hour), now.Add(10*24*time.Hour)),
			map[string]finding.Status{certValid: finding.StatusWarn, certChain: finding.StatusPass}},
		{"issued for another name", pki.leaf(t, []string{"www.other.example"}, now.Add(-time.Hour), now.Add(60*24*time.Hour)),
			map[string]finding.Status{certHost: finding.StatusFail, certChain: finding.StatusPass}},
		{"self-signed", selfSigned(t),
			map[string]finding.Status{certChain: finding.StatusFail, certHost: finding.StatusPass}},
		{"issued by an authority we do not trust", other.leaf(t, []string{"example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour)),
			map[string]finding.Status{certChain: finding.StatusFail}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCert(t, pki.pool, dialTo(certServer(t, tt.cert), nil))

			wantStatuses(t, got, tt.want)
		})
	}
}

func TestCertCheckConnectionProblems(t *testing.T) {
	t.Run("nothing listens", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		_ = l.Close()

		got := runCert(t, nil, dialTo(addr, nil))

		if len(got) != 1 || got[0].ID != certService || got[0].Status != finding.StatusInfo {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a port that does not speak TLS", func(t *testing.T) {
		addr := serve(t, func(c net.Conn) {
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		})

		got := runCert(t, nil, dialTo(addr, nil))

		if len(got) != 1 || got[0].ID != certService || got[0].Status != finding.StatusUnknown || !strings.Contains(got[0].Detail, "certificate could not be read") {
			t.Fatalf("an incomplete handshake is unknown, and the message must say that the certificate could not be read; got %+v", got)
		}
	})
	t.Run("no dialer", func(t *testing.T) {
		got := checks.Cert{}.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{})
		if len(got) != 1 || got[0].Status != finding.StatusUnknown {
			t.Fatalf("got %+v", got)
		}
	})
}
