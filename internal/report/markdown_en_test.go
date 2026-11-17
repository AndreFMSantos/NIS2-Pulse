package report_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

func renderEN(t *testing.T, r report.Result) string { return renderIn(t, r, catalog.EN) }

func TestEnglishReportHasTheExpectedSections(t *testing.T) {
	out := renderEN(t, sample())
	for _, want := range []string{
		"# External technical evidence report", "`example.pt`", "2026-11-09 12:30 UTC", "Mode: passive",
		"> **Notice.**", "It is not an audit", "## Summary by area", "## Items to fix", "## Positive results",
		"## Information", "## Could not be verified", "## Notes and limits",
		"| Email | 69 |", "| DNS | 100 |", "| Transport (TLS and HTTP) | n/a |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestEnglishReportExplainsEachItem(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "email.dmarc.present", Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityHigh, Fixer: finding.FixerProvider, Evidence: []string{"none"}},
		{ID: "transport.tls.legacy", Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusFail, Severity: finding.SeverityHigh},
	}}
	out := renderEN(t, r)
	for _, want := range []string{
		"**Why:**", "**How to fix:**", "**Example:**", "**How to verify:**", "**Sources:**", "**Observed evidence:**",
		"**European guidance (non-binding):**", "**Legal framing**", "does not mean that the entity complies",
		"Who fixes it: provider", "severity high", "Failure ·", "_dmarc.example.pt",
		"Decree-Law no. 125/2025, art. 27(1)(g)", "only for the entities it covers", "ENISA, Technical Implementation Guidance",
		"Implementing Regulation (EU) 2024/2690 applies directly",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// No leftover Portuguese labels or section names.
	for _, bad := range []string{"**Porquê:**", "**Como corrigir:**", "Falha ·", "Pontos a corrigir", "Quem corrige", "gravidade ", "Resumo por área", "Aviso", "Evidência observada", "Exemplo:", "Fontes:", "Enquadramento"} {
		if strings.Contains(out, bad) {
			t.Errorf("Portuguese label %q in the English report", bad)
		}
	}
}

// Everything a reader sees outside quotations of Portuguese law must be English.
func TestEnglishReportContainsNoPortugueseProse(t *testing.T) {
	var all []finding.Finding
	for _, id := range catalog.IDs(catalog.EN) {
		all = append(all, finding.Finding{ID: id, Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization})
	}
	out := renderEN(t, report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: all})
	// Lines that are quotations of the Portuguese official text are allowed to be Portuguese.
	quoted := regexp.MustCompile(`«[^»]*»`)
	accents := regexp.MustCompile(`[ãõçáéíóúâêôàÃÕÇÁÉÍÓÚÂÊÔ]`)
	for _, line := range strings.Split(out, "\n") {
		stripped := quoted.ReplaceAllString(line, "")
		if accents.MatchString(stripped) {
			t.Errorf("Portuguese letters outside a quotation: %q", line)
		}
	}
}

func TestEnglishReportNeverClaimsCompliance(t *testing.T) {
	out := strings.ToLower(renderEN(t, sample()))
	for _, bad := range []string{"is compliant", "are compliant", "fully compliant", "% compliance", "compliance score", "certified", "passes nis2", "meets nis2"} {
		if strings.Contains(out, bad) {
			t.Errorf("the English report contains %q", bad)
		}
	}
}

func TestEnglishReportHasNoGlobalNote(t *testing.T) {
	out := renderEN(t, sample())
	for _, bad := range []string{"overall score", "global score", "Global", "Overall"} {
		if strings.Contains(out, bad) {
			t.Errorf("there must be no global note, found %q", bad)
		}
	}
}

func TestBothLanguagesListTheSameFindings(t *testing.T) {
	ptOut, enOut := render(t, sample()), renderEN(t, sample())
	id := regexp.MustCompile("`((?:email|dns|transport|routing)(?:\\.[a-z0-9]+)+)`")
	collect := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, x := range id.FindAllStringSubmatch(s, -1) {
			m[x[1]] = true
		}
		return m
	}
	a, b := collect(ptOut), collect(enOut)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("finding IDs differ: PT %d, EN %d", len(a), len(b))
	}
	for k := range a {
		if !b[k] {
			t.Errorf("%s is in the Portuguese report only", k)
		}
	}
}

func TestEnglishActiveModeAndExample(t *testing.T) {
	r := sample()
	r.Active = true
	if !strings.Contains(renderEN(t, r), "Mode: active") {
		t.Error("active mode must be stated in English")
	}
	spf := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "email.spf.present", Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityHigh},
	}}
	out := renderEN(t, spf)
	if !strings.Contains(out, "**Example:**\n\n```\n; domain that sends email\n") || !strings.Contains(out, `example.pt. IN TXT "v=spf1`) {
		t.Errorf("the English example must be a code block with the domain filled in:\n%s", out)
	}
}

func TestReportsExplainTheComplianceLevels(t *testing.T) {
	pt, en := render(t, sample()), renderEN(t, sample())
	if !strings.Contains(pt, "Básico, Substancial e Elevado") || !strings.Contains(pt, "cumulativos") {
		t.Errorf("the Portuguese notes must explain the levels of Regulamento 756/2026:\n%s", pt)
	}
	if !strings.Contains(en, "Basic, Substantial and High") || !strings.Contains(en, "cumulative") {
		t.Errorf("the English notes must explain the levels of Regulation 756/2026:\n%s", en)
	}
}

func scanAt(day time.Time) report.Result {
	r := sample()
	r.ScannedAt = day
	return r
}

func TestReportsStateWhenTheLegalSourcesWereLastChecked(t *testing.T) {
	checked := catalog.SourcesCheckedAt.Format("2006-01-02")
	fresh := catalog.SourcesCheckedAt.AddDate(0, 0, 30)
	for lang, want := range map[catalog.Lang]string{catalog.PT: "verificadas em " + checked, catalog.EN: "checked on " + checked} {
		out := renderIn(t, scanAt(fresh), lang)
		if !strings.Contains(out, want) {
			t.Errorf("%s: the date of the last verification is missing (want %q)", lang, want)
		}
		for _, bad := range []string{"desatualizadas", "may be out of date"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: a recent verification must not warn about stale sources", lang)
			}
		}
	}
}

func TestReportsWarnWhenTheLegalSourcesAreOld(t *testing.T) {
	old := catalog.SourcesCheckedAt.AddDate(0, 0, 181)
	if out := render(t, scanAt(old)); !strings.Contains(out, "desatualizadas") {
		t.Errorf("Portuguese report must warn after 180 days:\n%s", out)
	}
	if out := renderEN(t, scanAt(old)); !strings.Contains(out, "may be out of date") {
		t.Errorf("English report must warn after 180 days:\n%s", out)
	}
	exactly := catalog.SourcesCheckedAt.AddDate(0, 0, 180)
	if out := render(t, scanAt(exactly)); strings.Contains(out, "desatualizadas") {
		t.Error("the warning starts after 180 days, not at 180")
	}
	// A scan dated before the check (clock skew) never warns.
	if out := render(t, scanAt(catalog.SourcesCheckedAt.AddDate(0, 0, -10))); strings.Contains(out, "desatualizadas") {
		t.Error("a scan earlier than the verification must not warn")
	}
}
