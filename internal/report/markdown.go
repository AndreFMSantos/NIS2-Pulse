package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/score"
)

// maxEvidenceRune bounds one line of evidence or detail in the document.
// staleAfterDays is how long the legal sources are trusted without a new check.
const staleAfterDays = 180

const maxEvidenceRune = 400

// WriteMarkdown writes the human report of r in lang (Portuguese or English). Any
// other language is an error and nothing is written (a report in the wrong
// language is worse than none).
//
// Everything that comes from the network (evidence, detail) is untrusted: it is
// cleaned of control characters, truncated, and only ever placed in a code
// span or a code block whose fence is longer than any backtick run inside, so
// it cannot add headings, links, HTML or close its own block.
func WriteMarkdown(w io.Writer, r Result, lang catalog.Lang) error {
	ui, ok := uiTexts[lang]
	if !ok {
		return fmt.Errorf("report language %q is not available (supported: %q, %q)", lang, catalog.PT, catalog.EN)
	}
	var b bytes.Buffer
	render(&b, r, lang, ui)
	_, err := w.Write(b.Bytes())
	return err
}

// ui holds every word of the report that is not catalog text.
type ui struct {
	title, disclaimer                                        string
	domain, date, mode, modePassive, modeActive, tool        string
	resolver                                                 string
	summary, tableHead, tableNote, notAvailable              string
	withVerdict, of                                          string
	toFix, noneToFix, positives, none, information           string
	unknown, allDecided, noDetail                            string
	notes                                                    string
	noteScope, notePassive, noteActive, noteRIPE, noteQuotes string
	noteChecked, noteStale                                   string
	noteNoProfile, noteProfile                               string
	profileEEI, profilePublic, profileReg, profileNoReg      string
	noEntry, observed, detail                                string
	why, howToFix, example, howToVerify, sources             string
	guidance, framing                                        string
	failure, warning, severity, whoFixes                     string
	areas                                                    map[finding.Area]string
	severities                                               map[finding.Severity]string
	fixers                                                   map[finding.Fixer]string
}

var uiTexts = map[catalog.Lang]ui{
	catalog.PT: {
		title:        "Relatório de evidência técnica externa",
		disclaimer:   "> **Aviso.** Este relatório reúne evidência técnica observável a partir do exterior. **Não é uma auditoria nem uma certificação** e não afirma que a entidade cumpre ou não cumpre o Decreto-Lei n.º 125/2025 ou a Diretiva NIS2: a conformidade depende de medidas organizacionais que esta ferramenta não vê. As notas são indicadores de higiene técnica por área, não percentagens de conformidade.",
		domain:       "Domínio",
		date:         "Data",
		mode:         "Modo",
		modePassive:  "passivo",
		modeActive:   "ativo",
		tool:         "Ferramenta",
		resolver:     "Resolvedor DNS",
		summary:      "Resumo por área",
		tableHead:    "| Área | Nota (0–100) | Com veredito | Falhas | Avisos | Sem veredito |\n|---|---|---|---|---|---|\n",
		tableNote:    "_n/d: nenhuma verificação da área chegou a um veredito. A nota parte de 100 e desconta por cada falha ou aviso conforme a gravidade; verificações sem veredito não contam._",
		notAvailable: "n/d",
		withVerdict:  "", of: "de",
		toFix:         "Pontos a corrigir",
		noneToFix:     "Nenhuma falha ou aviso nas verificações que chegaram a um veredito.",
		positives:     "Resultados positivos",
		none:          "Nenhum.",
		information:   "Informação",
		unknown:       "Não foi possível verificar",
		allDecided:    "Todas as verificações chegaram a um veredito.",
		noDetail:      "sem detalhe",
		notes:         "Notas e limites",
		noteScope:     "- Só foi observado o que é público ou o que o domínio responde a pedidos normais. Não foi feita nenhuma análise de portas, de vulnerabilidades ou de exploração.",
		noteActive:    "- Neste relatório correram verificações **ativas**: ligações diretas aos servidores indicados pelo DNS do domínio, com autorização do titular.",
		notePassive:   "- Foi usado o modo **passivo**: verificações que dependem de ligações aos servidores (TLS, certificados, cabeçalhos HTTP, STARTTLS, política MTA-STS) não correram e aparecem como «sem veredito».",
		noteRIPE:      "- A verificação de encaminhamento consulta o RIPEstat (RIPE NCC), um terceiro, que fica a saber os endereços públicos do domínio; `--no-routing` evita-o.",
		noteQuotes:    "- O Regulamento (CNCS) n.º 756/2026 (anexo III) fixa as medidas mínimas obrigatórias das entidades essenciais e importantes em três níveis de conformidade, Básico, Substancial e Elevado, que são cumulativos (art. 30.º); o nível aplicável a cada entidade resulta da matriz de risco do CNCS (anexo II) e um varrimento externo não o consegue determinar. Este relatório só fornece evidência técnica para os controlos citados.\n- O Regulamento de Execução (UE) 2024/2690 aplica-se diretamente às entidades que o seu artigo 1.º enumera (por exemplo prestadores de serviços DNS, de computação em nuvem, de centros de dados, de redes de distribuição de conteúdos, serviços geridos e serviços de confiança). Para as restantes entidades serve de referência europeia; as orientações da ENISA não são vinculativas.\n- As citações são frases literais das fontes indicadas. Os artigos de lei indicam o enquadramento da evidência e não significam que a entidade cumpre ou incumpre a disposição.",
		noteChecked:   "- As fontes legais e de orientação foram verificadas em %s.",
		noteNoProfile: "- Sem perfil de entidade (`--entity`, `--reg2690`): mostram-se todas as referências legais possíveis; algumas só se aplicam a certos tipos de entidade, como cada referência indica.",
		noteProfile:   "- Perfil indicado por quem pediu o relatório (a ferramenta não o verifica): %s. As referências legais mostradas foram filtradas em conformidade.",
		profileEEI:    "entidade essencial ou importante (anexo III do Regulamento 756/2026)",
		profilePublic: "entidade pública relevante (anexo IV do Regulamento 756/2026)",
		profileReg:    "abrangida diretamente pelo Regulamento de Execução (UE) 2024/2690",
		profileNoReg:  "não abrangida pelo Regulamento de Execução (UE) 2024/2690",
		noteStale:     "- **Atenção:** passaram mais de %d dias desde essa verificação; a legislação, o QNRCS e as instruções do CNCS mudam, por isso as referências abaixo podem estar desatualizadas e devem ser confirmadas nas fontes oficiais.",
		noEntry:       "_Ainda não existe explicação para este achado no catálogo._",
		observed:      "Evidência observada",
		detail:        "Detalhe",
		why:           "Porquê", howToFix: "Como corrigir", example: "Exemplo", howToVerify: "Como verificar", sources: "Fontes",
		guidance: "Orientação europeia (não vinculativa)",
		framing:  "**Enquadramento** (evidência técnica relacionada com estas disposições; não significa que a entidade cumpra ou incumpra):",
		failure:  "Falha", warning: "Aviso", severity: "gravidade", whoFixes: "Quem corrige",
		areas: map[finding.Area]string{
			finding.AreaEmail: "Correio eletrónico", finding.AreaDNS: "DNS",
			finding.AreaTransport: "Transporte (TLS e HTTP)", finding.AreaRouting: "Encaminhamento (BGP/RPKI)",
		},
		severities: map[finding.Severity]string{
			finding.SeverityCritical: "crítica", finding.SeverityHigh: "alta", finding.SeverityMedium: "média", finding.SeverityLow: "baixa",
		},
		fixers: map[finding.Fixer]string{
			finding.FixerOrganization: "a própria organização", finding.FixerProvider: "fornecedor", finding.FixerUnknown: "indeterminado",
		},
	},
	catalog.EN: {
		title:         "External technical evidence report",
		disclaimer:    "> **Notice.** This report gathers technical evidence that can be observed from the outside. **It is not an audit and not a certification**, and it does not state that the entity complies or does not comply with Decree-Law no. 125/2025 or the NIS2 Directive: compliance depends on organisational measures that this tool cannot see. The notes are technical hygiene indicators per area, not compliance percentages.",
		domain:        "Domain",
		date:          "Date",
		mode:          "Mode",
		modePassive:   "passive",
		modeActive:    "active",
		tool:          "Tool",
		resolver:      "DNS resolver",
		summary:       "Summary by area",
		tableHead:     "| Area | Note (0–100) | With verdict | Failures | Warnings | No verdict |\n|---|---|---|---|---|---|\n",
		tableNote:     "_n/a: no check of the area reached a verdict. The note starts at 100 and loses points for each failure or warning according to severity; checks without a verdict do not count._",
		notAvailable:  "n/a",
		of:            "of",
		toFix:         "Items to fix",
		noneToFix:     "No failures or warnings among the checks that reached a verdict.",
		positives:     "Positive results",
		none:          "None.",
		information:   "Information",
		unknown:       "Could not be verified",
		allDecided:    "Every check reached a verdict.",
		noDetail:      "no detail",
		notes:         "Notes and limits",
		noteScope:     "- Only what is public, or what the domain answers to ordinary requests, was observed. No port scanning, vulnerability probing or exploitation was done.",
		noteActive:    "- **Active** checks ran in this report: direct connections to the servers named by the domain's DNS, with the holder's authorisation.",
		notePassive:   "- **Passive** mode was used: checks that need connections to the servers (TLS, certificates, HTTP headers, STARTTLS, MTA-STS policy) did not run and appear as \"no verdict\".",
		noteRIPE:      "- The routing check queries RIPEstat (RIPE NCC), a third party, which learns the public addresses of the domain; `--no-routing` avoids it.",
		noteQuotes:    "- CNCS Regulation no. 756/2026 (annex III) sets the mandatory minimum measures of essential and important entities in three compliance levels, Basic, Substantial and High, which are cumulative (art. 30); the level that applies to each entity comes from the CNCS risk matrix (annex II) and an external scan cannot determine it. This report only supplies technical evidence for the controls cited.\n- Implementing Regulation (EU) 2024/2690 applies directly to the entities listed in its article 1 (for example DNS service providers, cloud computing, data centre and content delivery network providers, managed services and trust services). For other entities it is a European reference; ENISA guidance is not binding.\n- Quotations are literal phrases from the sources given. The legal provisions indicate the framing of the evidence and do not mean that the entity complies or fails to comply with them. Quotations of Portuguese law are in the original language.",
		noteChecked:   "- The legal and guidance sources were checked on %s.",
		noteNoProfile: "- No entity profile (`--entity`, `--reg2690`): every possible legal reference is shown; some apply only to certain kinds of entity, as each reference says.",
		noteProfile:   "- Profile declared by whoever asked for the report (the tool does not verify it): %s. The legal references shown were filtered accordingly.",
		profileEEI:    "essential or important entity (annex III of Regulation 756/2026)",
		profilePublic: "public relevant entity (annex IV of Regulation 756/2026)",
		profileReg:    "directly covered by Implementing Regulation (EU) 2024/2690",
		profileNoReg:  "not covered by Implementing Regulation (EU) 2024/2690",
		noteStale:     "- **Warning:** more than %d days have passed since that check; legislation, the national framework and CNCS instructions change, so the references in this report may be out of date and should be confirmed against the official sources.",
		noEntry:       "_There is no explanation for this finding in the catalog yet._",
		observed:      "Observed evidence",
		detail:        "Detail",
		why:           "Why", howToFix: "How to fix", example: "Example", howToVerify: "How to verify", sources: "Sources",
		guidance: "European guidance (non-binding)",
		framing:  "**Legal framing** (technical evidence related to these provisions; it does not mean that the entity complies or fails to comply):",
		failure:  "Failure", warning: "Warning", severity: "severity", whoFixes: "Who fixes it",
		areas: map[finding.Area]string{
			finding.AreaEmail: "Email", finding.AreaDNS: "DNS",
			finding.AreaTransport: "Transport (TLS and HTTP)", finding.AreaRouting: "Routing (BGP/RPKI)",
		},
		severities: map[finding.Severity]string{
			finding.SeverityCritical: "critical", finding.SeverityHigh: "high", finding.SeverityMedium: "medium", finding.SeverityLow: "low",
		},
		fixers: map[finding.Fixer]string{
			finding.FixerOrganization: "the organisation itself", finding.FixerProvider: "provider", finding.FixerUnknown: "undetermined",
		},
	},
}

var severityRank = map[finding.Severity]int{
	finding.SeverityCritical: 4, finding.SeverityHigh: 3, finding.SeverityMedium: 2, finding.SeverityLow: 1,
}

func render(b *bytes.Buffer, r Result, lang catalog.Lang, u ui) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	var profile catalog.Profile
	if r.Profile != nil {
		profile = *r.Profile
	}

	mode := u.modePassive
	if r.Active {
		mode = u.modeActive
	}
	p("# %s\n\n%s\n\n", u.title, u.disclaimer)
	p("- %s: %s\n", u.domain, inline(r.Target))
	p("- %s: %s\n", u.date, r.ScannedAt.UTC().Format("2006-01-02 15:04 UTC"))
	p("- %s: %s\n", u.mode, mode)
	p("- %s: %s %s\n", u.tool, inline(r.Tool), inline(r.Version))
	p("- %s: %s\n\n", u.resolver, inline(r.Resolver))

	p("## %s\n\n%s", u.summary, u.tableHead)
	for _, a := range score.Compute(r.Findings) {
		note := u.notAvailable
		if a.Score != nil {
			note = fmt.Sprint(*a.Score)
		}
		p("| %s | %s | %d %s %d | %d | %d | %d |\n", areaName(u, a.Area), note, a.Decided, u.of, a.Total, a.Fail, a.Warn, a.Unknown)
	}
	p("\n%s\n\n", u.tableNote)

	var attention, passed, info, unknown []finding.Finding
	for _, f := range r.Findings {
		switch f.Status {
		case finding.StatusFail, finding.StatusWarn:
			attention = append(attention, f)
		case finding.StatusPass:
			passed = append(passed, f)
		case finding.StatusInfo:
			info = append(info, f)
		default:
			unknown = append(unknown, f)
		}
	}
	sort.SliceStable(attention, func(i, j int) bool {
		a, c := attention[i], attention[j]
		if (a.Status == finding.StatusFail) != (c.Status == finding.StatusFail) {
			return a.Status == finding.StatusFail
		}
		if severityRank[a.Severity] != severityRank[c.Severity] {
			return severityRank[a.Severity] > severityRank[c.Severity]
		}
		return a.ID < c.ID
	})
	sortByID(passed)
	sortByID(info)
	sortByID(unknown)

	p("## %s\n\n", u.toFix)
	if len(attention) == 0 {
		p("%s\n\n", u.noneToFix)
	}
	for _, f := range attention {
		renderAttention(b, f, r.Target, lang, u, profile)
	}

	p("## %s\n\n", u.positives)
	if len(passed) == 0 {
		p("%s\n\n", u.none)
	}
	for _, f := range passed {
		p("- %s (%s)\n", titleOf(lang, f.ID, r.Target), inline(f.ID))
	}
	p("\n## %s\n\n", u.information)
	if len(info) == 0 {
		p("%s\n\n", u.none)
	}
	for _, f := range info {
		p("- %s (%s)\n", titleOf(lang, f.ID, r.Target), inline(f.ID))
		if len(f.Evidence) > 0 {
			p("\n%s\n", codeBlock(f.Evidence))
		}
		if f.Detail != "" {
			p("  %s\n", inline(f.Detail))
		}
	}

	p("\n## %s\n\n", u.unknown)
	if len(unknown) == 0 {
		p("%s\n\n", u.allDecided)
	}
	for _, f := range unknown {
		reason := f.Detail
		if reason == "" {
			reason = u.noDetail
		}
		p("- %s (%s): %s\n", titleOf(lang, f.ID, r.Target), inline(f.ID), inline(reason))
	}

	p("\n## %s\n\n%s\n", u.notes, u.noteScope)
	if r.Active {
		p("%s\n", u.noteActive)
	} else {
		p("%s\n", u.notePassive)
	}
	p("%s\n%s\n", u.noteRIPE, u.noteQuotes)
	p(u.noteChecked+"\n", catalog.SourcesCheckedAt.Format("2006-01-02"))
	if profile.IsZero() {
		p("%s\n", u.noteNoProfile)
	} else {
		var parts []string
		switch profile.Entity {
		case "eei":
			parts = append(parts, u.profileEEI)
		case "public":
			parts = append(parts, u.profilePublic)
		}
		switch profile.Reg2690 {
		case "yes":
			parts = append(parts, u.profileReg)
		case "no":
			parts = append(parts, u.profileNoReg)
		}
		p(u.noteProfile+"\n", strings.Join(parts, "; "))
	}
	if r.ScannedAt.After(catalog.SourcesCheckedAt.AddDate(0, 0, staleAfterDays)) {
		p(u.noteStale+"\n", staleAfterDays)
	}
}

func renderAttention(b *bytes.Buffer, f finding.Finding, domain string, lang catalog.Lang, u ui, profile catalog.Profile) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	e, hasEntry := catalog.Lookup(lang, f.ID)
	if hasEntry {
		e = catalog.Render(e, domain).ForProfile(profile)
	}
	title := f.ID
	if hasEntry {
		title = e.Title
	}
	state := u.warning
	if f.Status == finding.StatusFail {
		state = u.failure
	}
	p("### %s\n\n", text(title))
	line := fmt.Sprintf("%s · %s", state, inline(f.ID))
	if s, ok := u.severities[f.Severity]; ok {
		line += " · " + u.severity + " " + s
	}
	if x, ok := u.fixers[f.Fixer]; ok {
		line += " · " + u.whoFixes + ": " + x
	}
	p("%s\n\n", line)
	if len(f.Evidence) > 0 {
		p("**%s:**\n\n%s\n\n", u.observed, codeBlock(f.Evidence))
	}
	if f.Detail != "" {
		p("**%s:** %s\n\n", u.detail, inline(f.Detail))
	}
	if !hasEntry {
		p("%s\n\n", u.noEntry)
		return
	}
	p("**%s:** %s\n\n**%s:** %s\n\n", u.why, text(e.Why), u.howToFix, text(e.Fix))
	if strings.TrimSpace(e.Example) != "" {
		p("**%s:**\n\n%s\n\n", u.example, commandBlock(e.Example))
	}
	p("**%s:**\n\n%s\n\n", u.howToVerify, commandBlock(e.Verify))
	if len(e.Sources) > 0 {
		p("**%s:**\n\n", u.sources)
		for _, s := range e.Sources {
			p("- %s: <%s>%s\n", text(s.Label(lang)), s.URL, quote(s.Quote))
		}
		p("\n")
	}
	if len(e.Guidance) > 0 {
		p("**%s:**\n\n", u.guidance)
		for _, s := range e.Guidance {
			p("- %s: <%s>%s\n", text(s.Label(lang)), s.URL, quote(s.Quote))
		}
		p("\n")
	}
	if len(e.Legal) > 0 {
		p("%s\n\n", u.framing)
		for _, s := range e.Legal {
			p("- %s: <%s>%s\n", text(s.Label(lang)), s.URL, quote(s.Quote))
		}
		p("\n")
	}
}

func quote(q string) string {
	if q == "" {
		return ""
	}
	return " — «" + text(q) + "»"
}

func areaName(u ui, a finding.Area) string {
	if n, ok := u.areas[a]; ok {
		return n
	}
	return string(a)
}

func titleOf(lang catalog.Lang, id, domain string) string {
	if e, ok := catalog.Lookup(lang, id); ok {
		return text(catalog.Render(e, domain).Title)
	}
	return inline(id)
}

func sortByID(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
}

// clean removes control characters (keeping nothing that can move the cursor
// or recolour a terminal), turns line breaks into spaces and truncates.
func clean(s string) string {
	var sb strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\ufeff':
			continue
		}
		if n >= maxEvidenceRune {
			sb.WriteString("…")
			break
		}
		sb.WriteRune(r)
		n++
	}
	return strings.TrimSpace(sb.String())
}

// fence returns a backtick run longer than any run in s (at least n).
func fence(s string, n int) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	if longest+1 > n {
		n = longest + 1
	}
	return strings.Repeat("`", n)
}

// inline renders untrusted text as a code span that cannot be closed from inside.
func inline(s string) string {
	s = clean(s)
	if s == "" {
		return "``"
	}
	f := fence(s, 1)
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return f + pad + s + pad + f
}

// codeBlock renders untrusted lines as a fenced block that cannot be closed from inside.
func codeBlock(lines []string) string {
	var cleaned []string
	for _, l := range lines {
		cleaned = append(cleaned, clean(l))
	}
	body := strings.Join(cleaned, "\n")
	f := fence(body, 3)
	return f + "\n" + body + "\n" + f
}

// commandBlock renders the trusted lines of a catalog Verify entry as a code
// block that keeps one command per line, so the reader can paste it.
func commandBlock(v string) string {
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(v, "\r", ""), "\n") {
		if l = strings.TrimRight(l, " \t"); l != "" {
			lines = append(lines, l)
		}
	}
	body := strings.Join(lines, "\n")
	f := fence(body, 3)
	return f + "\n" + body + "\n" + f
}

// text renders trusted catalog text. It still goes through clean so a future
// edit cannot slip a control character into the output.
func text(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
}
