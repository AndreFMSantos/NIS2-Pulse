package safehttp

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

func get(t *testing.T, c *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req)
}

func TestRefusesNonPublicAddresses(t *testing.T) {
	// An attacker controls the DNS of the audited domain and points the policy
	// host at an internal address: the client must never connect.
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1"} {
		f := dnsxtest.New()
		if netip.MustParseAddr(ip).Is4() {
			f.Add(dnsxtest.A("mta-sts.evil.example", ip))
		} else {
			f.Add(dnsxtest.AAAA("mta-sts.evil.example", ip))
		}
		c := New(Options{Resolver: f, Timeout: 2 * time.Second})

		_, err := get(t, c, "https://mta-sts.evil.example/.well-known/mta-sts.txt")

		if !errors.Is(err, ErrNonPublicAddress) {
			t.Errorf("%s: err = %v, want ErrNonPublicAddress", ip, err)
		}
	}
}

func TestRefusesWhenAnyAddressIsNonPublic(t *testing.T) {
	// A mix of public and private answers is suspicious (rebinding tricks):
	// refuse instead of picking the public one.
	f := dnsxtest.New()
	f.Add(dnsxtest.A("mta-sts.evil.example", "8.8.8.8"))
	f.Add(dnsxtest.A("mta-sts.evil.example", "10.0.0.5"))
	c := New(Options{Resolver: f, Timeout: 2 * time.Second})

	_, err := get(t, c, "https://mta-sts.evil.example/")

	if !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("err = %v, want ErrNonPublicAddress", err)
	}
}

func TestUnresolvableHostIsNotFound(t *testing.T) {
	c := New(Options{Resolver: dnsxtest.New(), Timeout: 2 * time.Second})

	_, err := get(t, c, "https://mta-sts.nowhere.example/")

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("err = %v, want a *net.DNSError with IsNotFound", err)
	}
}

func TestResolverErrorsPropagate(t *testing.T) {
	boom := errors.New("resolver down")
	f := dnsxtest.New()
	f.SetError("mta-sts.example.com", 1 /* A */, boom)
	c := New(Options{Resolver: f, Timeout: 2 * time.Second})

	if _, err := get(t, c, "https://mta-sts.example.com/"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the resolver error", err)
	}
}

// testClient builds a client that is allowed to reach the loopback address of
// an httptest server, trusting only that server's certificate.
func testClient(t *testing.T, srv *httptest.Server, hostToServe string) (*http.Client, string) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	f := dnsxtest.New()
	f.Add(dnsxtest.A(hostToServe, "127.0.0.1"))
	c := New(Options{Resolver: f, Timeout: 3 * time.Second, allowNonPublic: true, rootCAs: pool})

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c, "https://" + hostToServe + ":" + u.Port()
}

func TestConnectsUsingOurResolver(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.Host)
	}))
	defer srv.Close()
	// httptest's certificate is valid for example.com.
	c, base := testClient(t, srv, "example.com")

	resp, err := get(t, c, base+"/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 || string(body) != "hello "+"example.com"+base[len("https://example.com"):] {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "https://example.com/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	c, base := testClient(t, srv, "example.com")

	resp, err := get(t, c, base+"/")
	if err != nil {
		t.Fatalf("a redirect must be returned as a response, not an error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound || hits != 1 {
		t.Fatalf("status=%d hits=%d, want the 302 itself and exactly one request", resp.StatusCode, hits)
	}
}

func TestRejectsUntrustedCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, base := testClient(t, srv, "example.com")

	// A client built without the test CA must not trust the server.
	f := dnsxtest.New()
	f.Add(dnsxtest.A("example.com", "127.0.0.1"))
	c := New(Options{Resolver: f, Timeout: 3 * time.Second, allowNonPublic: true})

	_, err := get(t, c, base+"/")

	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want an unknown-authority error: certificate errors must never be ignored", err)
	}
}
