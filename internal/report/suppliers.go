package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/score"
)

// SupplierIssue is a finding that needs attention, without its text (the catalog supplies it per language).
type SupplierIssue struct {
	ID       string           `json:"id"`
	Status   finding.Status   `json:"status"`
	Severity finding.Severity `json:"severity,omitempty"`
}

// SupplierArea is the note of one area of a supplier.
type SupplierArea struct {
	Area    finding.Area `json:"area"`
	Score   *int         `json:"score"`
	Fail    int          `json:"fail"`
	Warn    int          `json:"warn"`
	Unknown int          `json:"unknown"`
}

// Supplier is the comparable summary of one supplier domain.
type Supplier struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	// Error is set when the domain could not be scanned; every other field is then empty.
	Error     string          `json:"error,omitempty"`
	Areas     []SupplierArea  `json:"areas,omitempty"`
	Fail      int             `json:"fail"`
	Warn      int             `json:"warn"`
	Unknown   int             `json:"unknown"`
	Penalty   int             `json:"penalty"`
	Attention []SupplierIssue `json:"attention,omitempty"`
}

// SuppliersResult is the output of one supplier run.
type SuppliersResult struct {
	Tool      string     `json:"tool"`
	Version   string     `json:"version"`
	ScannedAt time.Time  `json:"scanned_at"`
	Resolver  string     `json:"resolver"`
	Active    bool       `json:"active"`
	Suppliers []Supplier `json:"suppliers"`
}

var statusRank = map[finding.Status]int{finding.StatusFail: 0, finding.StatusWarn: 1}

// NewSupplier summarises a scan. Penalty is the sum of the points the findings take off, the measure of
// how much the supplier needs attention; it is not a grade.
func NewSupplier(name string, r Result) Supplier {
	if name == "" {
		name = r.Target
	}
	s := Supplier{Name: name, Domain: r.Target}
	for _, a := range score.Compute(r.Findings) {
		s.Areas = append(s.Areas, SupplierArea{Area: a.Area, Score: a.Score, Fail: a.Fail, Warn: a.Warn, Unknown: a.Unknown})
		s.Fail += a.Fail
		s.Warn += a.Warn
		s.Unknown += a.Unknown
	}
	for _, f := range r.Findings {
		s.Penalty += score.Penalty(f.Status, f.Severity)
		if f.Status == finding.StatusFail || f.Status == finding.StatusWarn {
			s.Attention = append(s.Attention, SupplierIssue{ID: f.ID, Status: f.Status, Severity: f.Severity})
		}
	}
	sort.SliceStable(s.Attention, func(i, j int) bool {
		a, c := s.Attention[i], s.Attention[j]
		if statusRank[a.Status] != statusRank[c.Status] {
			return statusRank[a.Status] < statusRank[c.Status]
		}
		if severityRank[a.Severity] != severityRank[c.Severity] {
			return severityRank[a.Severity] > severityRank[c.Severity]
		}
		return a.ID < c.ID
	})
	return s
}

// FailedSupplier records a supplier that could not be scanned.
func FailedSupplier(name, domain, reason string) Supplier {
	if name == "" {
		name = domain
	}
	return Supplier{Name: name, Domain: domain, Error: reason}
}

// ordered returns the suppliers that need attention most first; the ones that could not be scanned go last.
func ordered(in []Supplier) []Supplier {
	out := append([]Supplier(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if (a.Error != "") != (c.Error != "") {
			return a.Error == ""
		}
		if a.Penalty != c.Penalty {
			return a.Penalty > c.Penalty
		}
		return a.Domain < c.Domain
	})
	return out
}

// WriteSuppliersJSON writes r with the suppliers in report order.
func WriteSuppliersJSON(w io.Writer, r SuppliersResult) error {
	r.Suppliers = ordered(r.Suppliers)
	if r.Suppliers == nil {
		r.Suppliers = []Supplier{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type supplierUI struct {
	title, disclaimer, domain, date, mode, tool, resolver, count string
	passive                                                      string
	compare, tableHead, fix, unverifiable, notes                 string
	failure, warning, severity, none                             string
	noteScores, noteTransport, noteScope, noteFraming            string
	areas                                                        map[finding.Area]string
	severities                                                   map[finding.Severity]string
	unavailable                                                  string
}

var supplierTexts = map[catalog.Lang]supplierUI{
	catalog.PT: {
		title:      "Relatório de evidência técnica sobre fornecedores",
		disclaimer: "> **Aviso.** Este relatório compara evidência técnica pública (DNS, correio eletrónico, encaminhamento) de vários domínios de fornecedores. **Não é uma auditoria nem uma certificação** e não afirma que um fornecedor, ou a entidade que o contrata, cumpre ou não cumpre qualquer norma. É uma entrada para a avaliação de fornecedores, não a avaliação.",
		domain:     "Domínio", date: "Data", mode: "Modo", tool: "Ferramenta", resolver: "Resolvedor DNS", count: "Fornecedores",
		passive: "passivo (só consultas DNS e RIPEstat, nunca ligações aos servidores dos fornecedores)",
		compare: "Comparação", tableHead: "| Fornecedor | Domínio | Correio | DNS | Transporte | Encaminhamento | Falhas | Avisos | Sem veredito |\n|---|---|---|---|---|---|---|---|---|\n",
		fix: "Pontos a corrigir por fornecedor", unverifiable: "Não foi possível verificar", notes: "Notas e limites",
		failure: "Falha", warning: "Aviso", severity: "gravidade", none: "Nenhum.",
		unavailable:   "n/d",
		noteScores:    "- As notas (0 a 100) são por área e indicam higiene técnica; **não há nota global**, porque os pesos entre áreas seriam arbitrários. Um fornecedor aparece antes de outro quando a soma dos pontos retirados pelos seus achados é maior. «n/d»: nenhuma verificação da área chegou a um veredito.",
		noteTransport: "- **Transporte (TLS e HTTP) aparece sempre «n/d»** neste relatório: essas verificações ligam-se aos servidores do domínio e só se fazem com a autorização do titular (`scan --active`). Não são feitas a fornecedores.",
		noteScope:     "- Só se observou o domínio indicado. A ferramenta não sabe que serviços o fornecedor presta, se usa outros domínios para eles, nem o que diz o contrato: um domínio limpo não prova que o serviço contratado é seguro.",
		noteFraming:   "- Enquadramento (evidência técnica relacionada com esta disposição; não significa que a entidade cumpre ou incumpre):",
		areas:         map[finding.Area]string{finding.AreaEmail: "Correio", finding.AreaDNS: "DNS", finding.AreaTransport: "Transporte", finding.AreaRouting: "Encaminhamento"},
		severities:    map[finding.Severity]string{finding.SeverityCritical: "crítica", finding.SeverityHigh: "alta", finding.SeverityMedium: "média", finding.SeverityLow: "baixa"},
	},
	catalog.EN: {
		title:      "Technical evidence report on suppliers",
		disclaimer: "> **Notice.** This report compares public technical evidence (DNS, email, routing) of several supplier domains. It is **not an audit and not a certification** and does not say that a supplier, or the entity that hires it, complies or fails to comply with any standard. It is an input to the assessment of suppliers, not the assessment.",
		domain:     "Domain", date: "Date", mode: "Mode", tool: "Tool", resolver: "DNS resolver", count: "Suppliers",
		passive: "passive (only DNS and RIPEstat queries, never connections to the suppliers' servers)",
		compare: "Comparison", tableHead: "| Supplier | Domain | Email | DNS | Transport | Routing | Failures | Warnings | No verdict |\n|---|---|---|---|---|---|---|---|---|\n",
		fix: "Points to fix by supplier", unverifiable: "Could not be verified", notes: "Notes and limits",
		failure: "Failure", warning: "Warning", severity: "severity", none: "None.",
		unavailable:   "n/a",
		noteScores:    "- Scores (0 to 100) are per area and indicate technical hygiene; there is **no global score**, because the weights between areas would be arbitrary. A supplier comes before another when the sum of the points its findings take off is larger. \"n/a\": no check of the area reached a verdict.",
		noteTransport: "- **Transport (TLS and HTTP) is always \"n/a\"** in this report: those checks connect to the domain's servers and are only run with the owner's permission (`scan --active`). They are not run against suppliers.",
		noteScope:     "- Only the domain given was observed. The tool does not know which services the supplier provides, whether it uses other domains for them, or what the contract says: a clean domain does not prove that the contracted service is secure.",
		noteFraming:   "- Framing (technical evidence related to this provision; it does not mean that the entity complies or fails to comply):",
		areas:         map[finding.Area]string{finding.AreaEmail: "Email", finding.AreaDNS: "DNS", finding.AreaTransport: "Transport", finding.AreaRouting: "Routing"},
		severities:    map[finding.Severity]string{finding.SeverityCritical: "critical", finding.SeverityHigh: "high", finding.SeverityMedium: "medium", finding.SeverityLow: "low"},
	},
}

// cell makes a user-supplied string safe inside a table cell: a code span with the pipe escaped.
func cell(s string) string { return strings.ReplaceAll(inline(s), "|", "\\|") }

// WriteSuppliersMarkdown writes the comparative report.
func WriteSuppliersMarkdown(w io.Writer, r SuppliersResult, lang catalog.Lang) error {
	u, ok := supplierTexts[lang]
	if !ok {
		return fmt.Errorf("report language %q is not available (supported: %q, %q)", lang, catalog.PT, catalog.EN)
	}
	var b bytes.Buffer
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	sups := ordered(r.Suppliers)

	p("# %s\n\n%s\n\n", u.title, u.disclaimer)
	p("- %s: %s\n", u.date, r.ScannedAt.UTC().Format("2006-01-02 15:04 UTC"))
	p("- %s: %s\n", u.mode, u.passive)
	p("- %s: %s %s\n", u.tool, inline(r.Tool), inline(r.Version))
	p("- %s: %s\n", u.resolver, inline(r.Resolver))
	p("- %s: %d\n\n", u.count, len(sups))

	score := func(s Supplier, area finding.Area) string {
		for _, a := range s.Areas {
			if a.Area == area && a.Score != nil {
				return fmt.Sprint(*a.Score)
			}
		}
		return u.unavailable
	}
	p("## %s\n\n%s", u.compare, u.tableHead)
	for _, s := range sups {
		if s.Error != "" {
			p("| %s | %s | %s | %s | %s | %s | — | — | — |\n", cell(s.Name), cell(s.Domain),
				u.unavailable, u.unavailable, u.unavailable, u.unavailable)
			continue
		}
		p("| %s | %s | %s | %s | %s | %s | %d | %d | %d |\n", cell(s.Name), cell(s.Domain),
			score(s, finding.AreaEmail), score(s, finding.AreaDNS), score(s, finding.AreaTransport), score(s, finding.AreaRouting),
			s.Fail, s.Warn, s.Unknown)
	}

	p("\n## %s\n\n", u.fix)
	listed := false
	for _, s := range sups {
		if s.Error != "" || len(s.Attention) == 0 {
			continue
		}
		listed = true
		p("### %s (%s)\n\n", cell(s.Name), cell(s.Domain))
		for _, f := range s.Attention {
			state := u.warning
			if f.Status == finding.StatusFail {
				state = u.failure
			}
			line := fmt.Sprintf("- %s · %s (%s)", state, titleOf(lang, f.ID, s.Domain), inline(f.ID))
			if sev, ok := u.severities[f.Severity]; ok {
				line += " · " + u.severity + " " + sev
			}
			p("%s\n", line)
		}
		p("\n")
	}
	if !listed {
		p("%s\n\n", u.none)
	}

	p("## %s\n\n", u.unverifiable)
	failed := false
	for _, s := range sups {
		if s.Error != "" {
			failed = true
			p("- %s (%s): %s\n", cell(s.Name), cell(s.Domain), inline(s.Error))
		}
	}
	if !failed {
		p("%s\n", u.none)
	}

	src := catalog.SupplierAssessmentSource
	p("\n## %s\n\n%s\n%s\n%s\n%s\n", u.notes, u.noteScores, u.noteTransport, u.noteScope, u.noteFraming)
	p("  - %s: <%s>%s\n", text(src.Label(lang)), src.URL, quote(src.Quote))
	_, err := w.Write(b.Bytes())
	return err
}
