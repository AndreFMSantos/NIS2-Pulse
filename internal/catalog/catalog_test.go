package catalog_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
)

var idPattern = regexp.MustCompile(`^(email|dns|transport|routing)(\.[a-z0-9]+)+$`)

// codeIDs returns every finding or check ID the code can emit: the string
// literals shaped like an ID in the non-test files of internal/checks, plus
// the ID of every registered check (the engine reports a skipped, slow or
// panicking check under the check's own ID).
func codeIDs(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	files, err := filepath.Glob("../checks/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot list ../checks/*.go: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil && idPattern.MatchString(s) {
					set[s] = true
				}
			}
			return true
		})
	}
	for _, c := range checks.Default(checks.Options{}) {
		set[c.ID()] = true
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func TestEveryIDInTheCodeHasACompleteEntry(t *testing.T) {
	ids := codeIDs(t)
	if len(ids) < 50 {
		t.Fatalf("found only %d IDs in the code: the scan is broken", len(ids))
	}
	for _, id := range ids {
		e, ok := catalog.Lookup(catalog.PT, id)
		if !ok {
			t.Errorf("no catalog entry for %q: add it to internal/catalog/pt.go", id)
			continue
		}
		for name, v := range map[string]string{"Title": e.Title, "Why": e.Why, "Fix": e.Fix, "Verify": e.Verify} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty", id, name)
			}
		}
	}
}

func TestNoEntryForAnIDThatNoLongerExists(t *testing.T) {
	code := map[string]bool{}
	for _, id := range codeIDs(t) {
		code[id] = true
	}
	for _, id := range catalog.IDs(catalog.PT) {
		if !code[id] {
			t.Errorf("catalog entry %q has no matching ID in the code: remove it", id)
		}
	}
}

func TestRenderSubstitutesTheDomainEverywhere(t *testing.T) {
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		r := catalog.Render(e, "example.pt")
		for name, v := range map[string]string{"Title": r.Title, "Why": r.Why, "Fix": r.Fix, "Verify": r.Verify} {
			if strings.Contains(v, "{{") || strings.Contains(v, "}}") {
				t.Errorf("%s.%s still has a placeholder after Render: %q", id, name, v)
			}
		}
	}
	e := catalog.Entry{Title: "t", Why: "w {{domain}}", Fix: "f {{domain}} {{domain}}", Verify: "v"}
	if got := catalog.Render(e, "example.pt"); got.Why != "w example.pt" || got.Fix != "f example.pt example.pt" {
		t.Errorf("Render = %+v", got)
	}
}

func TestRenderRejectsAHostileDomain(t *testing.T) {
	e := catalog.Entry{Title: "t", Why: "w", Fix: "dig {{domain}}", Verify: "v"}
	for _, bad := range []string{"", "a b", "x;rm -rf /", "$(id).example.pt", "a`b`.pt", "ex ample.pt", "a\nb.pt", "-flag.pt"} {
		got := catalog.Render(e, bad)
		if strings.Contains(got.Fix, bad) && bad != "" {
			t.Errorf("Render pasted an unsafe domain %q into %q", bad, got.Fix)
		}
		if !strings.Contains(got.Fix, "<domínio>") {
			t.Errorf("Render(%q).Fix = %q, want the neutral <domínio>", bad, got.Fix)
		}
	}
}

// The report speaks of evidence, never of compliance (CLAUDE.md rule 6).
func TestEntriesNeverClaimCompliance(t *testing.T) {
	forbidden := []string{"em conformidade", "compliant", "conformidade total", "cumpre a nis2", "cumpre o dl", "certificado de conformidade", "certificação nis2", "% de conformidade"}
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		text := strings.ToLower(e.Title + " " + e.Why + " " + e.Fix + " " + e.Verify)
		for _, w := range forbidden {
			if strings.Contains(text, w) {
				t.Errorf("%s uses %q: the report must speak of evidence, not of compliance", id, w)
			}
		}
	}
}

func TestUnknownIDAndLanguage(t *testing.T) {
	if _, ok := catalog.Lookup(catalog.PT, "email.nope.nothing"); ok {
		t.Error("an unknown ID must not have an entry")
	}
	if _, ok := catalog.Lookup(catalog.Lang("xx"), "email.spf.policy"); ok {
		t.Error("an unknown language must not have entries")
	}
}

// Entries that only report plumbing or an inventory have no standard behind
// them; every other explicit entry must cite at least one source.
var noSourceNeeded = map[string]bool{
	"transport.tls.service":    true,
	"transport.cert.service":   true,
	"transport.cert.inventory": true,
	"transport.http.service":   true,
}

func explicitIDs() []string {
	var out []string
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !strings.HasPrefix(e.Title, "Verificação não concluída") {
			out = append(out, id)
		}
	}
	return out
}

func TestEveryExplicitEntryCitesASource(t *testing.T) {
	if len(explicitIDs()) < 45 {
		t.Fatalf("only %d explicit entries: the helper is broken", len(explicitIDs()))
	}
	for _, id := range explicitIDs() {
		e, _ := catalog.Lookup(catalog.PT, id)
		if len(e.Sources) == 0 && !noSourceNeeded[id] {
			t.Errorf("%s cites no source: add one in sources.go (verbatim quote) or list it in noSourceNeeded with a reason", id)
		}
	}
}

func TestSourcesAreWellFormed(t *testing.T) {
	allowed := []string{
		"https://www.rfc-editor.org/rfc/rfc", "https://www.iana.org/", "https://ssl-config.mozilla.org/",
		"https://cabforum.org/", "https://www.w3.org/", "https://stat.ripe.net/", "https://www.team-cymru.com/",
		"https://diariodarepublica.pt/", "https://eur-lex.europa.eu/", "https://www.enisa.europa.eu/",
	}
	check := func(id string, s catalog.Source) {
		if strings.TrimSpace(s.Ref) == "" {
			t.Errorf("%s: a source has no Ref", id)
		}
		ok := false
		for _, p := range allowed {
			ok = ok || strings.HasPrefix(s.URL, p)
		}
		if !ok {
			t.Errorf("%s: source %q has a URL outside the allowed hosts: %q", id, s.Ref, s.URL)
		}
		if strings.HasPrefix(s.URL, "https://www.rfc-editor.org/") {
			if s.Manual || strings.TrimSpace(s.Quote) == "" {
				t.Errorf("%s: RFC source %q must carry a verbatim quote that the test can check", id, s.Ref)
			}
			if !strings.HasPrefix(s.Ref, "RFC ") {
				t.Errorf("%s: RFC source Ref %q should start with \"RFC \"", id, s.Ref)
			}
		}
		if !s.Manual && strings.TrimSpace(s.Quote) == "" {
			t.Errorf("%s: source %q has neither a quote nor Manual", id, s.Ref)
		}
	}
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		for _, s := range e.Sources {
			check(id, s)
		}
		for _, s := range e.Guidance {
			check(id, s)
		}
		for _, s := range e.Legal {
			check(id, s)
			if !s.Manual {
				t.Errorf("%s: a legal source %q is only valid if it was checked by hand against the official text (Manual)", id, s.Ref)
			}
			if strings.TrimSpace(s.Quote) == "" {
				t.Errorf("%s: legal source %q needs the quoted provision", id, s.Ref)
			}
		}
	}
}

// Legal framing is only offered for findings about the use of cryptography,
// because only the cryptography provision was read and mapped from the official text.
func TestLegalFramingOnlyForExplicitEntries(t *testing.T) {
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		if len(e.Legal) > 0 && strings.HasPrefix(e.Title, "Verificação não concluída") {
			t.Errorf("%s: a generated check entry must not carry legal framing", id)
		}
	}
}

// TestRFCQuotesExist proves that every RFC citation is real: the quote must
// appear in the RFC text and the cited section must exist. It needs the RFC
// texts, so it only runs with NIS2_CHECK_SOURCES=1. Set NIS2_RFC_DIR to a
// directory with rfcNNNN.txt files to avoid the network; otherwise the texts
// come from rfc-editor.org.
func TestRFCQuotesExist(t *testing.T) {
	if os.Getenv("NIS2_CHECK_SOURCES") != "1" {
		t.Skip("set NIS2_CHECK_SOURCES=1 to verify RFC quotes (reads RFC texts)")
	}
	cache := map[string]string{}
	load := func(num string) string {
		if txt, ok := cache[num]; ok {
			return txt
		}
		var raw []byte
		var err error
		if dir := os.Getenv("NIS2_RFC_DIR"); dir != "" {
			raw, err = os.ReadFile(filepath.Join(dir, "rfc"+num+".txt"))
		}
		if raw == nil {
			resp, herr := http.Get("https://www.rfc-editor.org/rfc/rfc" + num + ".txt") //nolint:gosec,noctx // opt-in test, fixed host
			if herr != nil {
				t.Fatalf("RFC %s: %v", num, herr)
			}
			defer func() { _ = resp.Body.Close() }()
			raw, err = io.ReadAll(resp.Body)
		}
		if err != nil || len(raw) == 0 {
			t.Fatalf("RFC %s: cannot read the text (%v)", num, err)
		}
		cache[num] = string(raw)
		return cache[num]
	}
	rfcRef := regexp.MustCompile(`^RFC (\d+)(?: §(.+))?$`)
	words := regexp.MustCompile(`\s+`)
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		for _, s := range e.Sources {
			m := rfcRef.FindStringSubmatch(s.Ref)
			if m == nil || s.Manual {
				continue
			}
			txt := load(m[1])
			// Words separated by any whitespace, tolerating an RFC page break in between.
			parts := words.Split(strings.TrimSpace(s.Quote), -1)
			for i := range parts {
				parts[i] = regexp.QuoteMeta(parts[i])
			}
			sep := `(?:\s+|\s+\S[^\n]*\[Page \d+\]\s+RFC \d+[^\n]*\s+)`
			re := regexp.MustCompile(strings.Join(parts, sep))
			loc := re.FindStringIndex(txt)
			if loc == nil {
				t.Errorf("%s: quote not found in RFC %s: %q", id, m[1], s.Quote)
				continue
			}
			if m[2] != "" {
				head := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(m[2]) + `\.\s+\S`)
				if !head.MatchString(txt[:loc[0]]) {
					t.Errorf("%s: section %s of RFC %s does not precede the quote", id, m[2], m[1])
				}
			}
		}
	}
}

// Verify is meant to be pasted into a terminal: every line is a command from a
// short list, or a "#" comment. Prose glued to a command ("... e dig ...") breaks it.
func TestVerifyLinesAreCopyPasteable(t *testing.T) {
	commands := []string{"dig ", "delv ", "openssl ", "curl "}
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		lines := strings.Split(e.Verify, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ok := false
			for _, c := range commands {
				ok = ok || strings.HasPrefix(line, c)
			}
			if !ok {
				t.Errorf("%s: Verify line is not a known command or a # comment: %q", id, line)
			}
			for _, glue := range []string{" e dig ", " e curl ", " e delv ", " e openssl ", " ou dig ", " (deve ", " (veja ", " (copie ", " (o seletor", " (a diferença"} {
				if strings.Contains(line, glue) {
					t.Errorf("%s: prose glued to a command (%q): %q", id, glue, line)
				}
			}
		}
	}
}

// Records and configuration belong in Example, which the report prints as a code
// block; Fix is prose. A record left inside the prose cannot be copied reliably.
func TestFixIsProseAndExamplesAreCode(t *testing.T) {
	forbidden := []string{"v=spf1", "v=DKIM1", "v=DMARC1", "v=STSv1", "v=TLSRPTv1", " IN TXT ", " IN CAA ", " IN TLSA ", " IN MX ", "ssl_", "Strict-Transport-Security:", "Content-Security-Policy:"}
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		for _, f := range forbidden {
			if strings.Contains(e.Fix, f) {
				t.Errorf("%s: Fix contains %q: move the record or configuration to Example", id, f)
			}
		}
		if e.Example != strings.TrimSpace(e.Example) {
			t.Errorf("%s: Example has leading or trailing whitespace", id)
		}
		if strings.Contains(strings.ToLower(e.Example), "exemplo:") {
			t.Errorf("%s: Example must be the code only, without a label", id)
		}
	}
}

func TestEntriesThatNeedAnExample(t *testing.T) {
	need := []string{
		"email.mx.profile", "email.spf.present", "email.dkim.key", "email.dmarc.present", "email.mtasts.record",
		"email.tlsrpt.record", "email.dane.tlsa", "dns.caa.present", "dns.caa.iodef", "transport.tls.legacy",
		"transport.tls.modern", "transport.tls.weakciphers", "transport.hsts.header", "transport.csp.header",
	}
	for _, id := range need {
		e, ok := catalog.Lookup(catalog.PT, id)
		if !ok || strings.TrimSpace(e.Example) == "" {
			t.Errorf("%s needs an Example (a record or a configuration block)", id)
		}
	}
}

func hasRef(ss []catalog.Source, part string) bool {
	for _, s := range ss {
		if strings.Contains(s.Ref, part) {
			return true
		}
	}
	return false
}

// Which findings may carry which provision. Only provisions that were read in the
// official text and that name the subject (email standards, DNS, routing) are
// mapped; everything else stays unmapped on purpose.
func TestLegalMappingScope(t *testing.T) {
	email6k := []string{
		"email.spf.present", "email.spf.policy", "email.spf.lookups", "email.dkim.key", "email.dkim.strength",
		"email.dmarc.present", "email.dmarc.policy", "email.dmarc.enforcement", "email.dmarc.reporting",
		"email.mtasts.record", "email.mtasts.fetch", "email.mtasts.mode", "email.mtasts.mx", "email.mtasts.maxage",
		"email.tlsrpt.record", "email.dane.tlsa", "email.dane.params", "email.dane.match",
		"email.starttls.service", "email.starttls.offered", "email.starttls.tls", "email.starttls.cert",
	}
	dnsRouting6l := []string{"dns.dnssec.chain", "dns.dnssec.algorithm", "dns.dnssec.expiry", "routing.rpki.roa", "routing.origin"}
	for _, id := range email6k {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !hasRef(e.Legal, "ponto 6.7.2, al. k)") || len(e.Guidance) == 0 {
			t.Errorf("%s should cite Regulamento 2024/2690 6.7.2 k) and the ENISA guidance", id)
		}
	}
	for _, id := range dnsRouting6l {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !hasRef(e.Legal, "ponto 6.7.2, al. l)") || len(e.Guidance) == 0 {
			t.Errorf("%s should cite Regulamento 2024/2690 6.7.2 l) and the ENISA guidance", id)
		}
	}
	// No provision names these subjects, so none may be attached.
	for _, id := range []string{"email.mx.profile", "dns.caa.present", "dns.caa.issue", "dns.caa.iodef", "routing.geo", "transport.http.service"} {
		e, _ := catalog.Lookup(catalog.PT, id)
		if len(e.Legal) > 0 || len(e.Guidance) > 0 {
			t.Errorf("%s has no provision that names it, but carries legal framing: %+v", id, e.Legal)
		}
	}
	// 6.7.2 k) is about email, l) about DNS and routing: never the other way round.
	for _, id := range append(append([]string{}, email6k...), dnsRouting6l...) {
		e, _ := catalog.Lookup(catalog.PT, id)
		isEmail := strings.HasPrefix(id, "email.")
		if isEmail && hasRef(e.Legal, "al. l)") || !isEmail && hasRef(e.Legal, "al. k)") {
			t.Errorf("%s cites the wrong paragraph of point 6.7.2", id)
		}
	}
}

func TestGuidanceIsNonBindingAndQuoted(t *testing.T) {
	n := 0
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		for _, g := range e.Guidance {
			n++
			if !g.Manual || strings.TrimSpace(g.Quote) == "" || !strings.HasPrefix(g.URL, "https://www.enisa.europa.eu/") {
				t.Errorf("%s: guidance %q must be an ENISA document with a quote checked by hand", id, g.Ref)
			}
			if !strings.Contains(strings.ToLower(g.Ref), "não vinculativa") {
				t.Errorf("%s: guidance %q must say that it is non-binding", id, g.Ref)
			}
		}
	}
	if n == 0 {
		t.Fatal("no guidance sources found")
	}
}

func TestRegulation2690ReferencesSayWhoTheyApplyTo(t *testing.T) {
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		for _, s := range e.Legal {
			if strings.Contains(s.Ref, "2024/2690") && !strings.Contains(s.Ref, "só para as entidades por ele abrangidas") {
				t.Errorf("%s: %q must say that it only applies to the entities it covers", id, s.Ref)
			}
		}
	}
}

// Regulamento CNCS n.º 756/2026, anexo III (art. 30.º: medidas mínimas obrigatórias, por nível de
// conformidade). PR.SD-2 is about protecting data in transit; PR.SP-1 (nível Elevado) about
// disabling unnecessary protocols. Only findings about the cryptographic protection of
// connections carry them.
func TestCNCSAnnexIIIMapping(t *testing.T) {
	transit := []string{
		"transport.tls.legacy", "transport.tls.modern", "transport.tls.weakciphers", "transport.tls.discouraged",
		"transport.tls.forwardsecrecy", "transport.cert.chain", "transport.cert.hostname", "transport.cert.validity",
		"transport.cert.lifetime", "transport.cert.key", "transport.cert.signature", "transport.hsts.header",
		"email.starttls.offered", "email.starttls.tls", "email.starttls.cert", "email.mtasts.mode", "email.mtasts.fetch",
		"email.dane.tlsa", "email.dane.match",
	}
	for _, id := range transit {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !hasRef(e.Legal, "756/2026, anexo III, nível Básico, controlo PR.SD-2") || !hasRef(e.Legal, "756/2026, anexo III, nível Elevado, controlo PR.SD-2") {
			t.Errorf("%s should cite PR.SD-2 at both levels of Regulamento 756/2026", id)
		}
		// Legal quotes carry a verifiable page.
		for _, s := range e.Legal {
			if strings.Contains(s.Ref, "756/2026") && !regexp.MustCompile(`\(p\. \d+;`).MatchString(s.Ref) {
				t.Errorf("%s: %q must give the page of the PDF", id, s.Ref)
			}
		}
	}
	// Not about data in transit, or no provision names them.
	for _, id := range []string{
		"email.spf.present", "email.spf.policy", "email.dmarc.present", "email.dkim.key", "email.tlsrpt.record", "dns.caa.present",
		"dns.dnssec.chain", "routing.rpki.roa", "routing.origin", "transport.csp.header", "transport.http.service", "email.mx.profile",
	} {
		e, _ := catalog.Lookup(catalog.PT, id)
		if hasRef(e.Legal, "756/2026, anexo III") {
			t.Errorf("%s must not carry an Annex III control of Regulamento 756/2026", id)
		}
	}
	for _, id := range catalog.IDs(catalog.PT) {
		e, _ := catalog.Lookup(catalog.PT, id)
		if hasRef(e.Legal, "controlo PR.SP-1") != (id == "transport.tls.legacy") {
			t.Errorf("%s: PR.SP-1 (protocols) belongs to the legacy-TLS finding only", id)
		}
	}
}

// The level that applies (Básico, Substancial, Elevado) comes from the entity's risk matrix, which an
// external scan cannot know: every reference to the annex must say so.
func TestCNCSReferencesSaySomethingAboutTheLevel(t *testing.T) {
	n := 0
	for _, lang := range []catalog.Lang{catalog.PT, catalog.EN} {
		want := "depende da matriz de risco"
		if lang == catalog.EN {
			want = "depends on the entity's risk matrix"
		}
		for _, id := range catalog.IDs(lang) {
			e, _ := catalog.Lookup(lang, id)
			for _, s := range e.Legal {
				// Annex IV (public relevant entities) is graded by group, not by level.
				if strings.Contains(s.Label(lang), "756/2026") && strings.Contains(s.Label(lang), "controlo PR.") || strings.Contains(s.Label(lang), "756/2026") && strings.Contains(s.Label(lang), "control PR.") {
					n++
					if !strings.Contains(s.Label(lang), want) {
						t.Errorf("%s (%s): %q must say that the level %s", id, lang, s.Label(lang), want)
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no Regulamento 756/2026 reference found")
	}
}

func TestSourcesCheckedAtIsADateNotInTheFuture(t *testing.T) {
	if catalog.SourcesCheckedAt.IsZero() || catalog.SourcesCheckedAt.After(time.Now().AddDate(0, 0, 1)) {
		t.Fatalf("SourcesCheckedAt = %v", catalog.SourcesCheckedAt)
	}
	if catalog.SourcesCheckedAt.Hour() != 0 {
		t.Error("it is a date, not a time")
	}
}

// Annex IV of Regulamento 756/2026 (public relevant entities, groups B and A) has T.PEW, which names
// email authentication, secure protocols and certificates; group A adds the security headers of web pages.
// It does not apply to the private essential and important entities of annex III, and the references say so.
func TestCNCSAnnexIVTPEWMapping(t *testing.T) {
	groupB := []string{
		"email.spf.present", "email.spf.policy", "email.dkim.key", "email.dmarc.present", "email.dmarc.policy",
		"transport.tls.legacy", "transport.tls.modern", "transport.cert.chain", "transport.cert.validity",
	}
	for _, id := range groupB {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !hasRef(e.Legal, "anexo IV, grupo B, controlo T.PEW") || !hasRef(e.Legal, "anexo IV, grupo A, controlo T.PEW") {
			t.Errorf("%s should cite T.PEW of annex IV, groups B and A", id)
		}
	}
	for _, id := range []string{"transport.hsts.header", "transport.csp.header"} {
		e, _ := catalog.Lookup(catalog.PT, id)
		if !hasRef(e.Legal, "anexo IV, grupo A, controlo T.PEW") {
			t.Errorf("%s: security headers belong to group A", id)
		}
		if hasRef(e.Legal, "anexo IV, grupo B, controlo T.PEW") {
			t.Errorf("%s: group B does not mention security headers", id)
		}
	}
	for _, id := range catalog.IDs(catalog.PT) {
		for _, lang := range []catalog.Lang{catalog.PT, catalog.EN} {
			e, _ := catalog.Lookup(lang, id)
			for _, s := range e.Legal {
				if !strings.Contains(s.Ref, "controlo T.PEW") {
					continue
				}
				if !strings.Contains(s.Label(lang), map[catalog.Lang]string{catalog.PT: "entidades públicas relevantes", catalog.EN: "public relevant entities"}[lang]) {
					t.Errorf("%s (%s): T.PEW reference must say it is for public relevant entities", id, lang)
				}
				if !regexp.MustCompile(`\(p\. \d+`).MatchString(s.Label(lang)) {
					t.Errorf("%s (%s): T.PEW reference must give the page", id, lang)
				}
			}
		}
	}
	// Findings with nothing to do with mail authentication, web protocols or certificates.
	for _, id := range []string{"dns.dnssec.chain", "dns.caa.present", "routing.rpki.roa", "email.mx.profile", "email.tlsrpt.record"} {
		e, _ := catalog.Lookup(catalog.PT, id)
		if hasRef(e.Legal, "controlo T.PEW") {
			t.Errorf("%s must not carry T.PEW", id)
		}
	}
}
