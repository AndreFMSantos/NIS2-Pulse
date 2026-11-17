package report_test

import (
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

func tlsResult(p *catalog.Profile) report.Result {
	return report.Result{
		Tool: "nis2-pulse", Version: "x", Target: "example.pt", ScannedAt: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC),
		Profile: p,
		Findings: []finding.Finding{
			{ID: "transport.tls.modern", Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusFail,
				Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization, Evidence: []string{"TLS 1.3 not offered"}},
		},
	}
}

func TestReportWithoutProfileShowsEverythingAndSaysSo(t *testing.T) {
	out := render(t, tlsResult(nil))
	if !strings.Contains(out, "anexo III, nível") || !strings.Contains(out, "anexo IV, grupo") {
		t.Errorf("no profile must keep every legal reference:\n%s", out)
	}
	if !strings.Contains(out, "Sem perfil de entidade") {
		t.Errorf("the report must say that no profile was given:\n%s", out)
	}
}

func TestReportWithAPublicProfileDropsTheEssentialAndImportantAnnex(t *testing.T) {
	out := render(t, tlsResult(&catalog.Profile{Entity: "public"}))
	if strings.Contains(out, "anexo III, nível") || !strings.Contains(out, "anexo IV, grupo") {
		t.Errorf("public profile:\n%s", out)
	}
	if !strings.Contains(out, "entidade pública relevante") {
		t.Errorf("the profile used must be stated in the notes:\n%s", out)
	}
}

func TestReportEnglishNotesStateTheProfile(t *testing.T) {
	out := renderIn(t, tlsResult(&catalog.Profile{Entity: "eei", Reg2690: "no"}), catalog.EN)
	if strings.Contains(out, "annex IV, group") || strings.Contains(out, "point 6.7.2") || strings.Contains(out, "point 9.2") {
		t.Errorf("eei + reg2690=no must hide annex IV and the Implementing Regulation:\n%s", out)
	}
	if !strings.Contains(out, "essential or important entity") {
		t.Errorf("the English notes must state the profile:\n%s", out)
	}
}
