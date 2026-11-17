package finding_test

import (
	"encoding/json"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

func TestFindingJSONIsStable(t *testing.T) {
	f := finding.Finding{
		ID:       "email.dmarc.policy",
		Area:     finding.AreaEmail,
		Tier:     finding.TierPassive,
		Status:   finding.StatusWarn,
		Severity: finding.SeverityMedium,
		Fixer:    finding.FixerOrganization,
		Evidence: []string{"v=DMARC1; p=none"},
		Detail:   "policy is monitoring only",
	}
	got, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"email.dmarc.policy","area":"email","tier":"passive","status":"warn","severity":"medium","fixer":"organization","evidence":["v=DMARC1; p=none"],"detail":"policy is monitoring only"}`
	if string(got) != want {
		t.Fatalf("json mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestOptionalFieldsAreOmitted(t *testing.T) {
	f := finding.Unknown("dns.caa", finding.AreaDNS, finding.TierPassive, "resolver timeout")
	got, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"dns.caa","area":"dns","tier":"passive","status":"unknown","detail":"resolver timeout"}`
	if string(got) != want {
		t.Fatalf("json mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestUnknownHasNoSeverity(t *testing.T) {
	f := finding.Unknown("x", finding.AreaEmail, finding.TierActive, "d")
	if f.Status != finding.StatusUnknown || f.Severity != "" || f.Tier != finding.TierActive {
		t.Fatalf("unexpected unknown finding: %+v", f)
	}
}
