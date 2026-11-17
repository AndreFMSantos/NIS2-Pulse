package safenet

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

func TestIsPublic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true},
		{"2606:4700:4700::1111", true},

		{"127.0.0.1", false},        // loopback
		{"::1", false},              // loopback v6
		{"10.0.0.1", false},         // RFC 1918
		{"172.16.5.4", false},       // RFC 1918
		{"192.168.1.1", false},      // RFC 1918
		{"169.254.169.254", false},  // link-local: cloud metadata services
		{"100.64.0.1", false},       // carrier-grade NAT, also used by overlay VPNs
		{"0.0.0.0", false},          // unspecified
		{"224.0.0.1", false},        // multicast
		{"255.255.255.255", false},  // broadcast
		{"240.0.0.1", false},        // reserved
		{"fe80::1", false},          // link-local v6
		{"fd00::1", false},          // unique local v6
		{"::ffff:127.0.0.1", false}, // IPv4-mapped loopback must not slip through
		{"::ffff:10.1.2.3", false},  // IPv4-mapped private
		{"192.0.2.9", false},        // documentation
		{"198.51.100.9", false},     // documentation
		{"203.0.113.9", false},      // documentation
		{"2001:db8::1", false},      // documentation v6
		{"198.18.0.1", false},       // benchmarking
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := IsPublic(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Fatalf("IsPublic(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func dial(t *testing.T, d *Dialer, addr string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return d.DialContext(ctx, "tcp", addr)
}

func TestRefusesNonPublicAddresses(t *testing.T) {
	// An attacker controls the DNS of the audited domain and points a host at
	// an internal address: the dialer must never connect.
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1"} {
		f := dnsxtest.New()
		if netip.MustParseAddr(ip).Is4() {
			f.Add(dnsxtest.A("mx.evil.example", ip))
		} else {
			f.Add(dnsxtest.AAAA("mx.evil.example", ip))
		}

		_, err := dial(t, &Dialer{Resolver: f}, "mx.evil.example:25")

		if !errors.Is(err, ErrNonPublicAddress) {
			t.Errorf("%s: err = %v, want ErrNonPublicAddress", ip, err)
		}
	}
}

func TestRefusesWhenAnyAddressIsNonPublic(t *testing.T) {
	// A mix of public and private answers is suspicious (rebinding tricks):
	// refuse instead of picking the public one.
	f := dnsxtest.New()
	f.Add(dnsxtest.A("mx.evil.example", "8.8.8.8"))
	f.Add(dnsxtest.A("mx.evil.example", "10.0.0.5"))

	if _, err := dial(t, &Dialer{Resolver: f}, "mx.evil.example:25"); !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("err = %v, want ErrNonPublicAddress", err)
	}
}

func TestIPLiteralsAreVettedToo(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:25", "[::1]:25", "169.254.169.254:80", "[::ffff:10.0.0.1]:443"} {
		if _, err := dial(t, &Dialer{Resolver: dnsxtest.New()}, addr); !errors.Is(err, ErrNonPublicAddress) {
			t.Errorf("%s: err = %v, want ErrNonPublicAddress", addr, err)
		}
	}
}

func TestUnresolvableHostIsNotFound(t *testing.T) {
	_, err := dial(t, &Dialer{Resolver: dnsxtest.New()}, "nowhere.example:443")

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("err = %v, want a *net.DNSError with IsNotFound", err)
	}
}

func TestResolverErrorsPropagate(t *testing.T) {
	boom := errors.New("resolver down")
	f := dnsxtest.New()
	f.SetError("mx.example.com", 1 /* A */, boom)

	if _, err := dial(t, &Dialer{Resolver: f}, "mx.example.com:25"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the resolver error", err)
	}
}

func TestMalformedAddress(t *testing.T) {
	if _, err := dial(t, &Dialer{Resolver: dnsxtest.New()}, "no-port"); err == nil {
		t.Fatal("an address without a port must be an error")
	}
}

func TestConnectsUsingOurResolver(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan struct{})
	go func() {
		if c, err := l.Accept(); err == nil {
			close(accepted)
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())

	f := dnsxtest.New()
	f.Add(dnsxtest.A("mx.example.test", "127.0.0.1"))
	conn, err := dial(t, &Dialer{Resolver: f, AllowNonPublic: true}, "mx.example.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the server never saw the connection")
	}
	if q := f.Queries(); len(q) != 2 || q[0] != "mx.example.test./A" || q[1] != "mx.example.test./AAAA" {
		t.Fatalf("the name must be resolved through the supplied resolver (A then AAAA), got %v", q)
	}
}

// AllowNonPublic exists only so tests can reach a loopback server. This test
// fails if any production code outside this package and safehttp's
// pass-through of its own unexported test option starts using it.
func TestProductionCodeNeverAllowsNonPublicAddresses(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "safenet", "safenet.go"):   true,
		filepath.Join("internal", "safehttp", "safehttp.go"): true,
	}
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
		rel, _ := filepath.Rel(root, path)
		if allowed[rel] {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "AllowNonPublic") {
			t.Errorf("%s mentions AllowNonPublic: production code must never disable the public-address check", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
