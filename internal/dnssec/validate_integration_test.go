//go:build integration

package dnssec_test

import (
	"context"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
)

// These tests use the real root trust anchors and the public DNS, and were
// cross-checked against ISC's delv. They can legitimately fail if a domain is
// re-configured or the root KSK rolls over; that is a signal to look, not a
// flaky test. Run with: go test -tags=integration ./internal/dnssec
func realValidate(t *testing.T, domain string) dnssec.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v := &dnssec.Validator{Resolver: dnsx.NewClient(dnsx.DefaultResolver)}
	return v.Validate(ctx, domain)
}

// example.com is reserved by IANA for documentation and is DNSSEC-signed.
func TestRealSecureDomain(t *testing.T) {
	r := realValidate(t, "example.com")
	if r.Status != dnssec.StatusSecure {
		t.Fatalf("status=%s code=%s zone=%s detail=%q", r.Status, r.Code, r.Zone, r.Detail)
	}
	if len(r.Zones) != 3 || r.Zones[0].Name != "." || r.Zones[2].Name != "example.com." {
		t.Errorf("zones = %+v, want . / com. / example.com.", r.Zones)
	}
}

// dnssec-failed.org is a public test domain whose DS record is deliberately
// wrong; validating resolvers answer SERVFAIL for it.
func TestRealBogusDomain(t *testing.T) {
	r := realValidate(t, "dnssec-failed.org")
	if r.Status != dnssec.StatusBogus || r.Code != dnssec.CodeDSMismatch || r.Zone != "dnssec-failed.org." {
		t.Fatalf("want bogus ds_mismatch at dnssec-failed.org., got status=%s code=%s zone=%s detail=%q", r.Status, r.Code, r.Zone, r.Detail)
	}
}
