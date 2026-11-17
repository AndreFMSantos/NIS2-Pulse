package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

func res(domain string, fs ...finding.Finding) report.Result {
	return report.Result{Tool: "nis2-pulse", Version: "x", Target: domain, ScannedAt: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), Findings: fs}
}

func fnd(id string, area finding.Area, st finding.Status, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, Area: area, Tier: finding.TierPassive, Status: st, Severity: sev, Fixer: finding.FixerOrganization}
}

func suppliers() report.SuppliersResult {
	good := res("good.example", fnd("email.dmarc.policy", finding.AreaEmail, finding.StatusPass, finding.SeverityHigh))
	bad := res("bad.example",
		fnd("email.dmarc.present", finding.AreaEmail, finding.StatusFail, finding.SeverityHigh),
		fnd("email.spf.policy", finding.AreaEmail, finding.StatusWarn, finding.SeverityMedium))
	return report.SuppliersResult{
		Tool: "nis2-pulse", Version: "x", ScannedAt: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), Resolver: "1.1.1.1:53",
		Suppliers: []report.Supplier{
			report.NewSupplier("Good Ltd", good),
			report.NewSupplier("Bad SA", bad),
			report.FailedSupplier("Gone", "gone.example", "domain gone.example does not exist (NXDOMAIN)"),
		},
	}
}

func TestSupplierSummaryCountsAndPenalty(t *testing.T) {
	s := report.NewSupplier("Bad SA", res("bad.example",
		fnd("email.dmarc.present", finding.AreaEmail, finding.StatusFail, finding.SeverityHigh),
		fnd("email.spf.policy", finding.AreaEmail, finding.StatusWarn, finding.SeverityMedium)))
	if s.Fail != 1 || s.Warn != 1 || s.Domain != "bad.example" || s.Name != "Bad SA" {
		t.Fatalf("%+v", s)
	}
	if s.Penalty != 25+6 {
		t.Errorf("penalty = %d, want 31 (fail high 25 + warn medium 6)", s.Penalty)
	}
	if len(s.Attention) != 2 || s.Attention[0].ID != "email.dmarc.present" {
		t.Errorf("attention must list failures first: %+v", s.Attention)
	}
}

func TestSuppliersMarkdownOrdersByNeedAndExplainsTheLimits(t *testing.T) {
	var b bytes.Buffer
	if err := report.WriteSuppliersMarkdown(&b, suppliers(), catalog.PT); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	iBad, iGood, iGone := strings.Index(out, "Bad SA"), strings.Index(out, "Good Ltd"), strings.Index(out, "Gone")
	if iBad < 0 || iBad >= iGood {
		t.Errorf("the supplier that needs attention most must come before the clean one:\n%s", out)
	}
	if iGone < iGood {
		t.Errorf("suppliers that could not be scanned go last:\n%s", out)
	}
	for _, want := range []string{"não é uma auditoria", "GR.CA-7", "NXDOMAIN", "passivo", "n/d"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cumpre o") && !strings.Contains(out, "não") {
		t.Error("never claim compliance")
	}
}

func TestSuppliersMarkdownEnglish(t *testing.T) {
	var b bytes.Buffer
	if err := report.WriteSuppliersMarkdown(&b, suppliers(), catalog.EN); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"not an audit", "GR.CA-7", "Supplier", "Bad SA"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestSuppliersJSONShape(t *testing.T) {
	var b bytes.Buffer
	if err := report.WriteSuppliersJSON(&b, suppliers()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Suppliers []struct {
			Name, Domain, Error string
			Fail, Warn, Penalty int
			Attention           []struct{ ID, Status string }
		} `json:"suppliers"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suppliers) != 3 || got.Suppliers[2].Error == "" {
		t.Fatalf("%+v", got.Suppliers)
	}
}

func TestSuppliersMarkdownEscapesNames(t *testing.T) {
	r := suppliers()
	r.Suppliers[0].Name = "x | <script>[a](http://evil)"
	var b bytes.Buffer
	if err := report.WriteSuppliersMarkdown(&b, r, catalog.PT); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// The name is a code span with the pipe escaped, so neither the table nor the markup can break.
	if !strings.Contains(out, "`x \\| <script>[a](http://evil)`") {
		t.Errorf("a supplier name must be a code span with the pipe escaped:\n%s", out)
	}
	if strings.Contains(out, "x | <script>") {
		t.Errorf("an unescaped pipe would break the table:\n%s", out)
	}
}
