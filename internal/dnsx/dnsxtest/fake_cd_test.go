package dnsxtest_test

import (
	"context"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

func TestFakeQueryCDSharesDataAndIsLogged(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "hello"))

	r, err := f.QueryCD(context.Background(), "example.com", dns.TypeTXT)
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("QueryCD should serve the same data as Query, got %+v err=%v", r, err)
	}
	if _, err := f.Query(context.Background(), "example.com", dns.TypeTXT); err != nil {
		t.Fatal(err)
	}

	got := f.Queries()
	if len(got) != 2 || got[0] != "example.com./TXT+CD" || got[1] != "example.com./TXT" {
		t.Fatalf("CD queries must be distinguishable in the log, got %v", got)
	}
}

func TestFakeAddForServesMixedTypesUnderOneQuestion(t *testing.T) {
	// A real DNSKEY answer carries the DNSKEY RRset and its RRSIG together.
	f := dnsxtest.New()
	f.AddFor("example.com", dns.TypeDNSKEY, dnsxtest.TXT("example.com", "stand-in 1"), dnsxtest.TXT("example.com", "stand-in 2"))

	r, _ := f.QueryCD(context.Background(), "example.com", dns.TypeDNSKEY)
	if len(r.Answer) != 2 {
		t.Fatalf("AddFor must serve records under the given question, got %d", len(r.Answer))
	}
	r, _ = f.QueryCD(context.Background(), "example.com", dns.TypeTXT)
	if len(r.Answer) != 0 {
		t.Fatal("AddFor must not leak into the record's own type")
	}
}

func TestFakeNSBuilder(t *testing.T) {
	rr := dnsxtest.NS("example.com", "ns1.example.com")
	if dns.RRToType(rr) != dns.TypeNS || !strings.HasSuffix(rr.Header().Name, ".") {
		t.Fatalf("unexpected NS record: %v", rr)
	}
}
