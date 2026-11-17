package checks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safehttp"
)

// testPKI is a throwaway certificate authority.
type testPKI struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newPKI(t *testing.T) *testPKI { return newPKIFrom(t, time.Now().Add(-time.Hour)) }

// newPKIFrom creates a CA that is valid from notBefore, so tests can issue
// certificates that started (and even expired) well before "now" without the
// impossible situation of a certificate older than its own issuer.
func newPKIFrom(t *testing.T, notBefore time.Time) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nis2-pulse test CA"},
		NotBefore:             notBefore,
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &testPKI{ca: ca, caKey: key, pool: pool}
}

// leaf issues a server certificate for the given DNS names.
func (p *testPKI) leaf(t *testing.T, names []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (p *testPKI) validLeaf(t *testing.T) tls.Certificate {
	return p.leaf(t, []string{"mta-sts.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// policyServer is a local HTTPS server standing in for mta-sts.<domain>.
type policyServer struct {
	client *http.Client
	hits   atomic.Int32

	mu                     sync.Mutex
	host, path, method, ua string
}

func (ps *policyServer) request() (host, path, method string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.host, ps.path, ps.method
}

// startPolicy serves h over TLS with cert. The returned client dials the local
// server whatever host it is asked for, and trusts only pool; hostnames and
// certificates are therefore verified exactly as in production.
func startPolicy(t *testing.T, cert tls.Certificate, pool *x509.CertPool, h http.HandlerFunc) *policyServer {
	t.Helper()
	ps := &policyServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.hits.Add(1)
		ps.mu.Lock()
		ps.host, ps.path, ps.method, ps.ua = r.Host, r.URL.Path, r.Method, r.UserAgent()
		ps.mu.Unlock()
		h(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ps.client = clientTo(srv.Listener.Addr().String(), pool)
	return ps
}

func clientTo(addr string, pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}
}

// roundTripperFunc lets a test make the HTTP client fail in a chosen way.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errNonPublic is the error the real safehttp client returns when a host
// resolves to a non-public address.
func errNonPublic() error { return safehttp.ErrNonPublicAddress }

// policyBody serves a text/plain MTA-STS policy.
func policyBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}
}

const goodPolicy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"

// mtastsDNS scripts a domain that receives mail and publishes an MTA-STS record.
func mtastsDNS() *dnsxtest.Fake {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=20261106"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	return f
}

// runPolicy runs the active MTA-STS policy check for example.com.
func runPolicy(t *testing.T, f *dnsxtest.Fake, client *http.Client) []finding.Finding {
	t.Helper()
	c := checks.MTASTSPolicy{}
	if c.Tier() != finding.TierActive {
		t.Fatal("fetching the policy connects to the target's server, so the check must be active")
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.com"}, engine.Deps{DNS: f, HTTP: client})
}
