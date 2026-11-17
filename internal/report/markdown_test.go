package report_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

func sample() report.Result {
	return report.Result{
		Tool: "nis2-pulse", Version: "1.2.3", Target: "example.pt",
		ScannedAt: time.Date(2026, 11, 9, 12, 30, 0, 0, time.UTC), Resolver: "1.1.1.1:53", Active: false,
		Findings: []finding.Finding{
			{ID: "email.spf.policy", Area: finding.AreaEmail, Tier: finding.TierPassive, Status: finding.StatusWarn, Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization, Evidence: []string{"v=spf1 ~all"}},
			{ID: "email.dmarc.present", Area: finding.AreaEmail, Tier: finding.TierPassive, Status: finding.StatusFail, Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization},
			{ID: "dns.caa.present", Area: finding.AreaDNS, Tier: finding.TierPassive, Status: finding.StatusPass},
			{ID: "routing.rpki.roa", Area: finding.AreaRouting, Tier: finding.TierPassive, Status: finding.StatusFail, Severity: finding.SeverityHigh, Fixer: finding.FixerProvider, Evidence: []string{"AS13335 103.21.244.0/24 invalid_length"}},
			{ID: "routing.origin", Area: finding.AreaRouting, Tier: finding.TierPassive, Status: finding.StatusInfo, Evidence: []string{"103.21.244.8 -> AS13335 via 103.21.244.0/24"}},
			{ID: "transport.tls.legacy", Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusUnknown, Detail: "skipped: requires --active"},
		},
	}
}

func render(t *testing.T, r report.Result) string { return renderIn(t, r, catalog.PT) }

func renderIn(t *testing.T, r report.Result, lang catalog.Lang) string {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, r, lang); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestMarkdownHasTheExpectedSections(t *testing.T) {
	out := render(t, sample())
	for _, want := range []string{
		"# Relatório de evidência técnica externa", "`example.pt`", "2026-11-09 12:30 UTC",
		"Não é uma auditoria", "## Resumo por área", "## Pontos a corrigir", "## Resultados positivos",
		"## Informação", "## Não foi possível verificar", "## Notas e limites",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMarkdownNeverClaimsCompliance(t *testing.T) {
	out := strings.ToLower(render(t, sample()))
	// The disclaimer itself may say "não afirma ... conformidade"; what is forbidden is a claim.
	for _, bad := range []string{"em conformidade", "compliant", "% de conformidade", "cumpre a nis2", "aprovado", "certificado de conformidade"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report contains %q", bad)
		}
	}
}

func TestSummaryTableShowsNotesPerAreaAndNoGlobalNote(t *testing.T) {
	out := render(t, sample())
	// email: warn medium (6) + fail high (25) -> 69; dns: pass -> 100; transport: only unknown -> no note.
	for _, want := range []string{"| Correio eletrónico | 69 |", "| DNS | 100 |", "| Transporte (TLS e HTTP) | n/d |"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"nota global", "pontuação global", "Global"} {
		if strings.Contains(out, bad) {
			t.Errorf("there must be no global note, found %q", bad)
		}
	}
}

func TestFindingsToFixAreOrderedBySeverityAndExplained(t *testing.T) {
	out := render(t, sample())
	a, b := strings.Index(out, "email.dmarc.present"), strings.Index(out, "email.spf.policy")
	if a < 0 || b < 0 || a > b {
		t.Fatalf("a high failure must come before a medium warning (%d, %d)", a, b)
	}
	sec := out[strings.Index(out, "## Pontos a corrigir"):strings.Index(out, "## Resultados positivos")]
	for _, want := range []string{
		"**Porquê:**", "**Como corrigir:**", "**Como verificar:**", "**Fontes:**", "_dmarc.example.pt", "RFC 9989",
		"v=spf1 ~all", "Quem corrige: fornecedor",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("fix section lacks %q", want)
		}
	}
}

func TestSourcesAreQuoted(t *testing.T) {
	out := render(t, sample())
	// email.dmarc.present cites RFC 9989 with a verbatim phrase.
	if !strings.Contains(out, "<https://www.rfc-editor.org/rfc/rfc9989#section-4.10.1>") {
		t.Errorf("the RFC link must be printed:\n%s", out)
	}
	if !strings.Contains(out, "The DMARC Policy Record to be applied to an email message will be the record found at any of the following locations") {
		t.Errorf("the verbatim quote must be printed:\n%s", out)
	}
}

func TestLegalFramingIsCarefullyWorded(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "transport.tls.legacy", Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusFail, Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization},
	}}
	out := render(t, r)
	for _, want := range []string{"Enquadramento", "art. 27.º, n.º 1, al. g)", "evidência técnica", "não significa"} {
		if !strings.Contains(out, want) {
			t.Errorf("legal framing lacks %q:\n%s", want, out)
		}
	}
}

func TestUnknownShowsTheReason(t *testing.T) {
	out := render(t, sample())
	sec := out[strings.Index(out, "## Não foi possível verificar"):strings.Index(out, "## Notas e limites")]
	if !strings.Contains(sec, "transport.tls.legacy") || !strings.Contains(sec, "skipped: requires --active") {
		t.Errorf("unknown section = %q", sec)
	}
}

func TestMarkdownIsDeterministic(t *testing.T) {
	first, second := render(t, sample()), render(t, sample())
	if first != second {
		t.Fatal("the same result must render identically")
	}
}

// Evidence comes from DNS records and HTTP headers chosen by whoever runs the
// audited domain. It must never be able to add headings, links, HTML or close
// the code block that holds it.
func TestHostileEvidenceCannotBreakTheDocument(t *testing.T) {
	for lang, detailLabel := range map[catalog.Lang]string{catalog.PT: "**Detalhe:** ", catalog.EN: "**Detail:** "} {
		t.Run(string(lang), func(t *testing.T) { hostileEvidence(t, lang, detailLabel) })
	}
}

func hostileEvidence(t *testing.T, lang catalog.Lang, detailLabel string) {
	hostile := []string{
		"```\n# Injected heading\n[click](javascript:alert(1))\n```",
		"<script>alert(1)</script> <img src=x onerror=alert(1)>",
		"line1\r\nline2\x00\x1b[31mred",
		"````````` just backticks",
		"```",
		"````",
		"~~~",
		strings.Repeat("A", 5000),
	}
	r := sample()
	r.Findings = []finding.Finding{{
		ID: "email.spf.policy", Area: finding.AreaEmail, Tier: finding.TierPassive, Status: finding.StatusFail,
		Severity: finding.SeverityHigh, Evidence: hostile, Detail: "`` ` ``\n## Injected from detail",
	}}
	out := renderIn(t, r, lang)
	if strings.Contains(out, "\n# Injected heading") || strings.Contains(out, "\n## Injected from detail") {
		t.Fatalf("hostile text became structure:\n%s", out)
	}
	if strings.ContainsAny(out, "\x00\x1b\r") {
		t.Error("control characters survived")
	}
	if strings.Contains(out, strings.Repeat("A", 1000)) {
		t.Error("an oversized evidence line was not truncated")
	}
	// Parse the document the way CommonMark does: a fence closes only on a line made of
	// the same character, at least as long, with nothing else on it. The hostile text
	// must stay inside exactly one block and nothing may be left open.
	opening := regexp.MustCompile("^(`{3,}|~{3,})([^`]*)$")
	var open string // the opening fence, or ""
	blocks := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimRight(line, " ")
		if open != "" {
			if trimmed != "" && strings.Trim(trimmed, string(open[0])) == "" && len(trimmed) >= len(open) {
				open = ""
			}
			continue
		}
		if m := opening.FindStringSubmatch(trimmed); m != nil {
			open = m[1]
			blocks++
			continue
		}
		// The detail is rendered inside a code span on the "**Detalhe:**" line, which is safe.
		if strings.HasPrefix(line, detailLabel) {
			span := strings.TrimPrefix(line, detailLabel)
			if !validCodeSpan(span) {
				t.Errorf("the detail is not one well-formed code span: %q", line)
			}
			continue
		}
		if strings.Contains(line, "Injected") || strings.Contains(line, "javascript:") || strings.Contains(line, "<script") {
			t.Errorf("hostile text escaped its block: %q", line)
		}
	}
	if open != "" {
		t.Error("a code block was left open")
	}
	if blocks != 2 {
		t.Errorf("code blocks = %d, want exactly 2 (the evidence and the verification commands)", blocks)
	}
}

func TestUnknownIDStillRendersSafely(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "email.future.thing", Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityLow},
	}}
	out := render(t, r)
	if !strings.Contains(out, "email.future.thing") {
		t.Errorf("a finding without a catalog entry must still be listed:\n%s", out)
	}
}

func TestUnsupportedLanguage(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, sample(), catalog.Lang("fr")); err == nil {
		t.Fatal("an unsupported language must be an error, not a report in another language")
	}
	if buf.Len() != 0 {
		t.Error("nothing may be written for an unsupported language")
	}
}

func TestActiveModeIsStated(t *testing.T) {
	r := sample()
	if !strings.Contains(render(t, r), "Modo: passivo") {
		t.Error("passive mode must be stated")
	}
	r.Active = true
	if !strings.Contains(render(t, r), "Modo: ativo") {
		t.Error("active mode must be stated")
	}
}

func TestAttentionOrderIsFailuresFirstThenBySeverity(t *testing.T) {
	mk := func(id string, st finding.Status, sev finding.Severity) finding.Finding {
		return finding.Finding{ID: id, Area: finding.AreaEmail, Status: st, Severity: sev}
	}
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		mk("email.aaa.warnhigh", finding.StatusWarn, finding.SeverityHigh),
		mk("email.bbb.faillow", finding.StatusFail, finding.SeverityLow),
		mk("email.ccc.failcritical", finding.StatusFail, finding.SeverityCritical),
		mk("email.ddd.warnlow", finding.StatusWarn, finding.SeverityLow),
		mk("email.eee.failmedium", finding.StatusFail, finding.SeverityMedium),
	}}
	out := render(t, r)
	order := []string{"email.ccc.failcritical", "email.eee.failmedium", "email.bbb.faillow", "email.aaa.warnhigh", "email.ddd.warnlow"}
	last := -1
	for _, id := range order {
		i := strings.Index(out, "### "+id)
		if i < 0 {
			i = strings.Index(out, id)
		}
		if i < 0 || i < last {
			t.Fatalf("%s is out of order (position %d after %d):\n%s", id, i, last, out)
		}
		last = i
	}
}

// validCodeSpan reports whether s is exactly one CommonMark code span: an opening
// run of n backticks, a closing run of n backticks, and no run of exactly n
// backticks inside (which would end the span early).
func validCodeSpan(s string) bool {
	n := len(s) - len(strings.TrimLeft(s, "`"))
	if n == 0 || len(s) < 2*n+1 || !strings.HasSuffix(s, strings.Repeat("`", n)) {
		return false
	}
	if len(s)-len(strings.TrimRight(s, "`")) != n {
		return false
	}
	inner := s[n : len(s)-n]
	run := 0
	for _, r := range inner + "x" {
		if r == '`' {
			run++
			continue
		}
		if run == n {
			return false
		}
		run = 0
	}
	return true
}

func TestVerifyCommandsAreOneBlockWithOneCommandPerLine(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "dns.dnssec.chain", Area: finding.AreaDNS, Status: finding.StatusFail, Severity: finding.SeverityMedium},
	}}
	out := render(t, r)
	want := "**Como verificar:**\n\n```\ndig +dnssec DS example.pt\ndelv example.pt @1.1.1.1\n```\n"
	if !strings.Contains(out, want) {
		t.Errorf("commands must be listed one per line in a code block, want:\n%s\nin:\n%s", want, out)
	}
}

func TestExampleIsACodeBlockWithTheDomainFilledIn(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "email.spf.present", Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityHigh},
	}}
	out := render(t, r)
	if !strings.Contains(out, "**Exemplo:**\n\n```\n") || !strings.Contains(out, `example.pt. IN TXT "v=spf1`) {
		t.Errorf("the example must be a code block with the domain filled in:\n%s", out)
	}
	// The explanation comes before the example, the example before the verification commands.
	a, b, c := strings.Index(out, "**Como corrigir:**"), strings.Index(out, "**Exemplo:**"), strings.Index(out, "**Como verificar:**")
	if a < 0 || a >= b || b >= c {
		t.Errorf("order must be fix, example, verify (%d, %d, %d)", a, b, c)
	}
}

func TestNoExampleMeansNoExampleHeading(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "routing.rpki.roa", Area: finding.AreaRouting, Status: finding.StatusFail, Severity: finding.SeverityHigh},
	}}
	if out := render(t, r); strings.Contains(out, "**Exemplo:**") {
		t.Errorf("an entry without an example must not print an empty heading:\n%s", out)
	}
}

func TestGuidanceIsLabelledNonBindingAndLegalScopeIsExplained(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "email.dmarc.present", Area: finding.AreaEmail, Status: finding.StatusFail, Severity: finding.SeverityHigh},
	}}
	out := render(t, r)
	for _, want := range []string{
		"**Orientação europeia (não vinculativa):**", "ENISA", "ponto 6.7.2, al. k)", "só para as entidades por ele abrangidas",
		"DNS-based authentication of named entities (DANE)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Regulamento de Execução (UE) 2024/2690 aplica-se diretamente") {
		t.Errorf("the notes must explain to whom Regulation 2024/2690 applies:\n%s", out)
	}
}

func TestEntriesWithoutAnyProvisionHaveNoFramingBlock(t *testing.T) {
	r := report.Result{Target: "example.pt", ScannedAt: time.Now(), Findings: []finding.Finding{
		{ID: "dns.caa.present", Area: finding.AreaDNS, Status: finding.StatusWarn, Severity: finding.SeverityLow},
	}}
	out := render(t, r)
	if strings.Contains(out, "**Enquadramento**") || strings.Contains(out, "**Orientação europeia") {
		t.Errorf("CAA has no provision that names it; the report must not invent one:\n%s", out)
	}
}
