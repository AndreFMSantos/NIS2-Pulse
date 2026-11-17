package catalog_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
)

func TestEnglishCoversEveryIDAndNothingElse(t *testing.T) {
	code := map[string]bool{}
	for _, id := range codeIDs(t) {
		code[id] = true
		e, ok := catalog.Lookup(catalog.EN, id)
		if !ok {
			t.Errorf("no English entry for %q", id)
			continue
		}
		for name, v := range map[string]string{"Title": e.Title, "Why": e.Why, "Fix": e.Fix, "Verify": e.Verify} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: English %s is empty", id, name)
			}
		}
	}
	for _, id := range catalog.IDs(catalog.EN) {
		if !code[id] {
			t.Errorf("English entry %q has no matching ID in the code", id)
		}
	}
	if len(catalog.IDs(catalog.EN)) != len(catalog.IDs(catalog.PT)) {
		t.Errorf("English has %d entries, Portuguese %d", len(catalog.IDs(catalog.EN)), len(catalog.IDs(catalog.PT)))
	}
}

// The two languages must describe the same thing: same examples where one exists, same
// sources, same legal framing, same verification commands (modulo comments and placeholders).
func TestEnglishMatchesPortugueseStructurally(t *testing.T) {
	for _, id := range catalog.IDs(catalog.PT) {
		p, _ := catalog.Lookup(catalog.PT, id)
		e, ok := catalog.Lookup(catalog.EN, id)
		if !ok {
			continue
		}
		if (p.Example == "") != (e.Example == "") {
			t.Errorf("%s: the example exists in only one language", id)
		}
		if len(p.Sources) != len(e.Sources) || len(p.Legal) != len(e.Legal) || len(p.Guidance) != len(e.Guidance) {
			t.Errorf("%s: sources/legal/guidance differ between languages", id)
		}
		if commands(p.Verify) != commands(e.Verify) {
			t.Errorf("%s: verification commands differ:\nPT: %q\nEN: %q", id, commands(p.Verify), commands(e.Verify))
		}
		// Titles may coincide (HSTS, Content-Security-Policy are names), the explanation may not.
		if p.Why == e.Why || p.Fix == e.Fix {
			t.Errorf("%s: the English explanation is identical to the Portuguese one (untranslated?)", id)
		}
	}
}

// commands keeps the executable lines of a Verify block with placeholders normalised,
// so that "<seletor>" and "<selector>" count as the same command.
func commands(v string) string {
	ph := regexp.MustCompile(`<[^>]*>`)
	var out []string
	for _, l := range strings.Split(v, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, ph.ReplaceAllString(l, "<>"))
	}
	return strings.Join(out, "\n")
}

func TestEnglishTextIsEnglish(t *testing.T) {
	// Accented letters of Portuguese never appear in English prose or placeholders.
	accents := regexp.MustCompile(`[ãõçáéíóúâêôàÃÕÇÁÉÍÓÚÂÊÔ]`)
	for _, id := range catalog.IDs(catalog.EN) {
		e, _ := catalog.Lookup(catalog.EN, id)
		for name, v := range map[string]string{"Title": e.Title, "Why": e.Why, "Fix": e.Fix, "Example": e.Example, "Verify": e.Verify} {
			if accents.MatchString(v) {
				t.Errorf("%s.%s has Portuguese letters: %q", id, name, v)
			}
		}
		for _, w := range []string{" não ", " para ", " deve ", " domínio", "publique", "verificação"} {
			if strings.Contains(strings.ToLower(" "+e.Why+" "+e.Fix+" "), w) {
				t.Errorf("%s: Portuguese word %q in English text", id, w)
			}
		}
	}
}

func TestEnglishRenderFillsDomainAndFallsBackToAnEnglishNeutralName(t *testing.T) {
	for _, id := range catalog.IDs(catalog.EN) {
		e, _ := catalog.Lookup(catalog.EN, id)
		r := catalog.Render(e, "example.pt")
		for name, v := range map[string]string{"Title": r.Title, "Why": r.Why, "Fix": r.Fix, "Example": r.Example, "Verify": r.Verify} {
			if strings.Contains(v, "{{") {
				t.Errorf("%s.%s has a placeholder after Render", id, name)
			}
		}
	}
	e, _ := catalog.Lookup(catalog.EN, "email.dmarc.present")
	if got := catalog.Render(e, "x;rm -rf /").Verify; !strings.Contains(got, "<domain>") || strings.Contains(got, "rm -rf") {
		t.Errorf("hostile domain in English = %q, want the neutral <domain>", got)
	}
}

func TestEnglishNeverClaimsCompliance(t *testing.T) {
	forbidden := []string{"is compliant", "are compliant", "complies with", "fully compliant", "% compliance", "compliance score", "certified", "passes nis2", "meets nis2", "meets the requirements"}
	for _, id := range catalog.IDs(catalog.EN) {
		e, _ := catalog.Lookup(catalog.EN, id)
		text := strings.ToLower(e.Title + " " + e.Why + " " + e.Fix + " " + e.Example + " " + e.Verify)
		for _, w := range forbidden {
			if strings.Contains(text, w) {
				t.Errorf("%s uses %q: the report speaks of evidence, not of compliance", id, w)
			}
		}
	}
}

func TestEnglishFixIsProseAndEnglishVerifyIsCopyPasteable(t *testing.T) {
	forbidden := []string{" IN TXT ", " IN CAA ", " IN TLSA ", " IN MX ", "ssl_", "v=spf1", "v=DKIM1", "v=DMARC1", "v=STSv1", "v=TLSRPTv1", "Strict-Transport-Security:", "Content-Security-Policy:"}
	for _, id := range catalog.IDs(catalog.EN) {
		e, _ := catalog.Lookup(catalog.EN, id)
		for _, f := range forbidden {
			if strings.Contains(e.Fix, f) {
				t.Errorf("%s: English Fix contains %q: move it to Example", id, f)
			}
		}
		for _, line := range strings.Split(e.Verify, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ok := false
			for _, c := range []string{"dig ", "delv ", "openssl ", "curl "} {
				ok = ok || strings.HasPrefix(line, c)
			}
			if !ok || strings.Contains(line, " and dig ") || strings.Contains(line, " or dig ") {
				t.Errorf("%s: English Verify line is not a clean command: %q", id, line)
			}
		}
	}
}

func TestEnglishReferencesKeepTheScopeCaveat(t *testing.T) {
	for _, id := range catalog.IDs(catalog.EN) {
		e, _ := catalog.Lookup(catalog.EN, id)
		for _, s := range e.Legal {
			if strings.Contains(s.Label(catalog.EN), "2024/2690") && !strings.Contains(s.Label(catalog.EN), "only for the entities it covers") {
				t.Errorf("%s: %q must say whom the regulation applies to", id, s.Label(catalog.EN))
			}
			if strings.Contains(s.Label(catalog.EN), "ó ") || regexp.MustCompile(`[ãõçáéíóú]`).MatchString(s.Label(catalog.EN)) {
				t.Errorf("%s: English label has Portuguese letters: %q", id, s.Label(catalog.EN))
			}
		}
		for _, g := range e.Guidance {
			if !strings.Contains(strings.ToLower(g.Label(catalog.EN)), "non-binding") {
				t.Errorf("%s: English guidance label must say non-binding: %q", id, g.Label(catalog.EN))
			}
		}
	}
}

func TestSourceLabelFallsBackToRef(t *testing.T) {
	s := catalog.Source{Ref: "RFC 7208 §3.2"}
	if s.Label(catalog.EN) != "RFC 7208 §3.2" || s.Label(catalog.PT) != "RFC 7208 §3.2" {
		t.Error("a source without RefEN uses Ref in every language")
	}
	s.RefEN = "English ref"
	if s.Label(catalog.EN) != "English ref" || s.Label(catalog.PT) != "RFC 7208 §3.2" {
		t.Error("RefEN is used only for English")
	}
}
