package catalog_test

import (
	"strings"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
)

func legalRefs(e catalog.Entry) string {
	var refs []string
	for _, s := range e.Legal {
		refs = append(refs, s.Ref)
	}
	return strings.Join(refs, " | ")
}

func entry(t *testing.T, id string) catalog.Entry {
	t.Helper()
	e, ok := catalog.Lookup(catalog.PT, id)
	if !ok {
		t.Fatalf("no entry for %s", id)
	}
	return e
}

func TestParseProfile(t *testing.T) {
	for _, tt := range []struct {
		entity, reg string
		ok          bool
	}{
		{"", "", true}, {"eei", "", true}, {"public", "", true}, {"", "yes", true}, {"", "no", true},
		{"EEI", "YES", true}, {"public", "no", true},
		{"private", "", false}, {"", "maybe", false}, {"annex3", "", false},
	} {
		_, err := catalog.ParseProfile(tt.entity, tt.reg)
		if (err == nil) != tt.ok {
			t.Errorf("ParseProfile(%q, %q) err = %v, want ok=%v", tt.entity, tt.reg, err, tt.ok)
		}
	}
}

func TestProfileZeroValueKeepsEverything(t *testing.T) {
	e := entry(t, "transport.tls.modern")
	if got := e.ForProfile(catalog.Profile{}); len(got.Legal) != len(e.Legal) {
		t.Fatalf("an empty profile filtered %d -> %d sources", len(e.Legal), len(got.Legal))
	}
	if !(catalog.Profile{}).IsZero() {
		t.Error("the zero Profile must report IsZero")
	}
}

// T.PEW (annex IV) is only for public relevant entities; PR.SD-2 (annex III) only for the
// essential and important entities (their own Ref says so).
func TestProfileEntityPicksTheAnnex(t *testing.T) {
	e := entry(t, "transport.tls.modern")
	all := legalRefs(e)
	if !strings.Contains(all, "anexo III, nível") || !strings.Contains(all, "anexo IV, grupo") {
		t.Fatalf("the unfiltered entry must carry both annexes, got: %s", all)
	}
	eei := legalRefs(e.ForProfile(catalog.Profile{Entity: "eei"}))
	if !strings.Contains(eei, "anexo III, nível") || strings.Contains(eei, "anexo IV, grupo") {
		t.Errorf("eei must keep annex III and drop annex IV, got: %s", eei)
	}
	pub := legalRefs(e.ForProfile(catalog.Profile{Entity: "public"}))
	if strings.Contains(pub, "anexo III, nível") || !strings.Contains(pub, "anexo IV, grupo") {
		t.Errorf("public must keep annex IV and drop annex III, got: %s", pub)
	}
}

func TestProfileReg2690(t *testing.T) {
	e := entry(t, "transport.tls.modern")
	if !strings.Contains(legalRefs(e), "2024/2690") {
		t.Fatal("precondition: the entry cites Regulation 2024/2690")
	}
	if strings.Contains(legalRefs(e.ForProfile(catalog.Profile{Reg2690: "no"})), "2024/2690") {
		t.Error("reg2690=no must drop Regulation 2024/2690")
	}
	if !strings.Contains(legalRefs(e.ForProfile(catalog.Profile{Reg2690: "yes"})), "2024/2690") {
		t.Error("reg2690=yes must keep Regulation 2024/2690")
	}
	if !strings.Contains(legalRefs(e.ForProfile(catalog.Profile{Entity: "eei"})), "2024/2690") {
		t.Error("an unset reg2690 must not remove it")
	}
}

func TestProfileKeepsTheLawsThatApplyToEveryone(t *testing.T) {
	e := entry(t, "transport.tls.modern")
	got := legalRefs(e.ForProfile(catalog.Profile{Entity: "public", Reg2690: "no"}))
	if !strings.Contains(got, "125/2025") {
		t.Errorf("the base law must survive any profile, got: %s", got)
	}
}

func TestProfileDoesNotChangeTheCatalogTables(t *testing.T) {
	e := entry(t, "transport.tls.modern")
	n := len(e.Legal)
	_ = e.ForProfile(catalog.Profile{Entity: "public", Reg2690: "no"})
	if again := entry(t, "transport.tls.modern"); len(again.Legal) != n {
		t.Fatalf("filtering mutated the shared table: %d -> %d", n, len(again.Legal))
	}
}

// Every legal source must carry the scope its own Ref states, so a future source cannot
// silently escape the filter.
func TestEveryLegalSourceHasTheScopeItsRefStates(t *testing.T) {
	for _, id := range catalog.IDs(catalog.PT) {
		e := entry(t, id)
		for _, s := range e.Legal {
			switch {
			case strings.Contains(s.Ref, "anexo IV, grupo") && s.Scope != catalog.ScopePublic:
				t.Errorf("%s: %q must have scope public", id, s.Ref)
			case strings.Contains(s.Ref, "anexo III, nível") && s.Scope != catalog.ScopeEEI:
				t.Errorf("%s: %q must have scope eei", id, s.Ref)
			case strings.Contains(s.Ref, "2024/2690") && s.Scope != catalog.ScopeReg2690:
				t.Errorf("%s: %q must have scope reg2690", id, s.Ref)
			}
		}
	}
}
