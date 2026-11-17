package checks_test

import (
	"context"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// run executes one check against a fake resolver for domain.
func run(t *testing.T, c engine.Check, f *dnsxtest.Fake, domain string) []finding.Finding {
	t.Helper()
	if c.Tier() != finding.TierPassive {
		t.Fatalf("%s is expected to be a passive check", c.ID())
	}
	return c.Run(context.Background(), engine.Target{Domain: domain}, engine.Deps{DNS: f})
}

// withMail scripts an MX record, i.e. a domain that receives (and so
// presumably sends) email. Missing SPF or DMARC on such a domain is a failure.
func withMail(f *dnsxtest.Fake, domain string) {
	f.Add(dnsxtest.MX(domain, 10, "mail."+domain))
}

// get returns the finding with the given ID, failing the test if absent.
func get(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %q not found in %+v", id, fs)
	return finding.Finding{}
}

// wantStatuses asserts the status of each listed finding ID.
func wantStatuses(t *testing.T, fs []finding.Finding, want map[string]finding.Status) {
	t.Helper()
	for id, st := range want {
		if got := get(t, fs, id); got.Status != st {
			t.Errorf("%s: status = %q, want %q (detail=%q evidence=%v)", id, got.Status, st, got.Detail, got.Evidence)
		}
	}
}
