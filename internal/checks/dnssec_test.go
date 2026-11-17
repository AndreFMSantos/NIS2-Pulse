package checks_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec/dnssectest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	dsChain  = "dns.dnssec.chain"
	dsAlg    = "dns.dnssec.algorithm"
	dsExpiry = "dns.dnssec.expiry"
)

func runDNSSEC(t *testing.T, w *dnssectest.World, domain string) []finding.Finding {
	t.Helper()
	c := checks.DNSSEC{Anchors: w.Anchors}
	if c.Tier() != finding.TierPassive {
		t.Fatal("DNSSEC check must be passive: it only reads public DNS data")
	}
	return c.Run(context.Background(), engine.Target{Domain: domain},
		engine.Deps{DNS: w.Fake, Now: func() time.Time { return w.Now }})
}

func TestDNSSECSecure(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")

	got := runDNSSEC(t, w, "example.pt")

	wantStatuses(t, got, map[string]finding.Status{dsChain: finding.StatusPass, dsAlg: finding.StatusPass, dsExpiry: finding.StatusPass})
	ev := get(t, got, dsChain).Evidence
	if len(ev) != 3 || !strings.HasPrefix(ev[2], "example.pt.") || !strings.Contains(ev[2], "ED25519") {
		t.Errorf("evidence should list each validated zone with its keys, got %v", ev)
	}
}

func TestDNSSECInsecureDomain(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")

	got := runDNSSEC(t, w, "example.pt")

	chain := get(t, got, dsChain)
	if chain.Status != finding.StatusFail || chain.Severity != finding.SeverityMedium || chain.Fixer != finding.FixerOrganization {
		t.Fatalf("an unsigned domain is a medium finding for the organisation, got %+v", chain)
	}
	if len(got) != 1 {
		t.Errorf("algorithm/expiry findings need a signed zone, got %+v", got)
	}
}

func TestDNSSECInsecureTLDIsInformational(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"xx.": true}}, "xx.", "example.xx.")

	chain := get(t, runDNSSEC(t, w, "example.xx"), dsChain)

	if chain.Status != finding.StatusInfo || chain.Fixer != finding.FixerProvider {
		t.Fatalf("an unsigned TLD is not something the domain owner can fix, got %+v", chain)
	}
}

func TestDNSSECBogus(t *testing.T) {
	t.Run("in the domain's own zone", func(t *testing.T) {
		w := dnssectest.New(t, dnssectest.Options{WrongDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")

		chain := get(t, runDNSSEC(t, w, "example.pt"), dsChain)

		if chain.Status != finding.StatusFail || chain.Severity != finding.SeverityCritical || chain.Fixer != finding.FixerOrganization {
			t.Fatalf("got %+v", chain)
		}
		if !strings.Contains(chain.Detail, "ds_mismatch") {
			t.Errorf("detail should carry the stable reason code, got %q", chain.Detail)
		}
	})
	t.Run("in the TLD", func(t *testing.T) {
		w := dnssectest.New(t, dnssectest.Options{ExpiredKeySig: map[string]bool{"pt.": true}}, "pt.", "example.pt.")

		chain := get(t, runDNSSEC(t, w, "example.pt"), dsChain)

		if chain.Status != finding.StatusFail || chain.Fixer != finding.FixerProvider {
			t.Fatalf("a broken TLD is the registry's problem, got %+v", chain)
		}
	})
}

func TestDNSSECIndeterminateIsUnknown(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{BadAnchor: true}, "pt.", "example.pt.")

	got := runDNSSEC(t, w, "example.pt")

	chain := get(t, got, dsChain)
	if chain.Status != finding.StatusUnknown || chain.Severity != "" {
		t.Fatalf("root problems must be unknown, never a verdict on the domain, got %+v", chain)
	}
	if !strings.Contains(chain.Detail, "anchor") {
		t.Errorf("detail should explain the cause, got %q", chain.Detail)
	}
}

func TestDNSSECExpiryWarning(t *testing.T) {
	soon := dnssectest.New(t, dnssectest.Options{Lifetime: 24 * time.Hour}, "pt.", "example.pt.")
	if got := get(t, runDNSSEC(t, soon, "example.pt"), dsExpiry); got.Status != finding.StatusWarn {
		t.Errorf("signatures expiring in 24h should warn, got %+v", got)
	}

	fine := dnssectest.New(t, dnssectest.Options{Lifetime: 10 * 24 * time.Hour}, "pt.", "example.pt.")
	if got := get(t, runDNSSEC(t, fine, "example.pt"), dsExpiry); got.Status != finding.StatusPass {
		t.Errorf("signatures valid for 10 days should pass, got %+v", got)
	}
}

func TestAlgorithmAssessment(t *testing.T) {
	tests := []struct {
		name    string
		algs    []uint8
		digests []uint8
		want    finding.Status
	}{
		{"modern", []uint8{dns.ED25519}, []uint8{dns.SHA256}, finding.StatusPass},
		{"ecdsa", []uint8{dns.ECDSAP256SHA256}, []uint8{dns.SHA256, dns.SHA384}, finding.StatusPass},
		{"rsa sha256", []uint8{dns.RSASHA256}, []uint8{dns.SHA256}, finding.StatusPass},
		{"rsa sha1", []uint8{dns.RSASHA1}, []uint8{dns.SHA256}, finding.StatusWarn},
		{"rsa sha1 nsec3", []uint8{dns.RSASHA1NSEC3SHA1}, []uint8{dns.SHA256}, finding.StatusWarn},
		{"mixed with sha1 key", []uint8{dns.RSASHA256, dns.RSASHA1}, []uint8{dns.SHA256}, finding.StatusWarn},
		{"only sha1 digest", []uint8{dns.ED25519}, []uint8{dns.SHA1}, finding.StatusWarn},
		{"sha1 digest next to sha256", []uint8{dns.ED25519}, []uint8{dns.SHA1, dns.SHA256}, finding.StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := checks.AssessAlgorithms(tt.algs, tt.digests)
			if f.ID != dsAlg || f.Status != tt.want {
				t.Fatalf("got %+v, want status %s", f, tt.want)
			}
		})
	}
}
