package dnsxtest_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

func TestFakeReturnsRecordsForNameAndType(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	f.Add(dnsxtest.TXT("example.com", "other"))
	f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))

	r, err := f.Query(context.Background(), "Example.COM", dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 2 {
		t.Fatalf("want 2 TXT answers, got rcode=%d answers=%d", r.Rcode, len(r.Answer))
	}

	r, _ = f.Query(context.Background(), "example.com.", dns.TypeCAA)
	if len(r.Answer) != 1 {
		t.Fatalf("want 1 CAA answer, got %d", len(r.Answer))
	}
}

func TestFakeDefaultsToNoData(t *testing.T) {
	f := dnsxtest.New()
	r, err := f.Query(context.Background(), "nothing.example.com", dns.TypeTXT)
	if err != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("want NODATA (success, empty), got %+v err=%v", r, err)
	}
}

func TestFakeRcodeAndError(t *testing.T) {
	f := dnsxtest.New()
	f.SetRcode("gone.example.com", dns.TypeTXT, dns.RcodeNameError)
	boom := errors.New("network down")
	f.SetError("flaky.example.com", dns.TypeTXT, boom)

	r, err := f.Query(context.Background(), "gone.example.com", dns.TypeTXT)
	if err != nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN, got %+v err=%v", r, err)
	}
	if _, err := f.Query(context.Background(), "flaky.example.com", dns.TypeTXT); !errors.Is(err, boom) {
		t.Fatalf("want injected error, got %v", err)
	}
}

func TestFakeRecordsQueries(t *testing.T) {
	f := dnsxtest.New()
	_, _ = f.Query(context.Background(), "a.example.com", dns.TypeTXT)
	_, _ = f.Query(context.Background(), "b.example.com", dns.TypeCAA)
	got := f.Queries()
	if len(got) != 2 || got[0] != "a.example.com./TXT" || got[1] != "b.example.com./CAA" {
		t.Fatalf("unexpected query log: %v", got)
	}
}
