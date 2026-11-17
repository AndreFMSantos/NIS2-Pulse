//go:build integration

package dnsx_test

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

// TestResolverIsSafeForConcurrentUse is a regression test: the engine runs
// checks in parallel on one Client. miekg's Client.Exchange clears the shared
// in-flight ID map when it returns, which made overlapping queries fail with
// "ID mismatch".
func TestResolverIsSafeForConcurrentUse(t *testing.T) {
	r := dnsx.NewClient(dnsx.DefaultResolver)
	names := []string{"example.com", "example.org", "example.net", "iana.org", "ietf.org"}

	const workers = 20
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		name := names[i%len(names)]
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, err := r.Query(ctx, name, dns.TypeTXT)
			errs <- err
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent query failed: %v", err)
		}
	}
}

// TestResolverRootDNSKEY needs outbound TCP/53 to the default resolver.
// Run with: go test -tags=integration ./internal/dnsx
func TestResolverRootDNSKEY(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := dnsx.NewClient(dnsx.DefaultResolver)
	resp, err := r.Query(ctx, ".", dns.TypeDNSKEY)
	if err != nil {
		t.Fatal(err)
	}
	var keys, sigs int
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.DNSKEY:
			keys++
		case *dns.RRSIG:
			sigs++
		}
	}
	if resp.Rcode != dns.RcodeSuccess || keys == 0 || sigs == 0 {
		t.Fatalf("want DNSKEYs and RRSIGs for the root, got rcode=%d keys=%d sigs=%d", resp.Rcode, keys, sigs)
	}
}
