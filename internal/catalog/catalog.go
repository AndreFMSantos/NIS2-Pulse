// Package catalog holds the human explanation of every finding: why it
// matters, how to fix it and how to verify it by hand. Findings carry only a
// stable ID (see package finding); the report looks the text up here.
//
// Texts are written per language and never claim compliance: they describe
// technical evidence. A test scans the code for every finding and check ID
// and fails when one has no entry, or when an entry outlives its ID.
package catalog

import (
	"regexp"
	"sort"
	"strings"
)

// Lang is a report language.
type Lang string

// Languages.
const (
	PT Lang = "pt"
	EN Lang = "en"
)

// Entry explains one finding. Fix and Verify may contain the placeholder
// {{domain}}, replaced by Render.
type Entry struct {
	// Title is a short name for the finding.
	Title string
	// Why says why the property matters, in plain language.
	Why string
	// Fix says how to correct it, with an example that uses {{domain}}.
	Fix string
	// Example is a record or configuration block (code, not prose) that applies
	// the fix, with {{domain}} filled in by Render. It may be empty.
	Example string
	// Verify gives a command the reader can run to check the result by hand.
	Verify string
	// Sources are the technical standards behind the check, with verbatim
	// quotes, so the reader can confirm that the text is not invented.
	Sources []Source
	// Legal says which legal provision the finding supplies technical evidence
	// for. It never means that the domain complies with it.
	Legal []Source
	// Guidance cites non-binding European guidance (ENISA) that mentions the
	// subject of the finding.
	Guidance []Source

	lang Lang // set by Lookup; picks the neutral name Render uses for an unsafe domain
}

var tables = map[Lang]map[string]Entry{PT: pt, EN: en}

// Lookup returns the entry of a finding ID.
func Lookup(lang Lang, id string) (Entry, bool) {
	e, ok := tables[lang][id]
	if ok {
		e.lang = lang
		e.Sources = sources[id]
		e.Legal = legal[id]
		e.Guidance = guidance[id]
	}
	return e, ok
}

// IDs returns the IDs that have an entry in lang, sorted.
func IDs(lang Lang) []string {
	ids := make([]string, 0, len(tables[lang]))
	for id := range tables[lang] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// domainOK accepts what engine.ParseTarget produces: lower-case LDH labels.
// Anything else is never pasted into a command the reader may copy.
var domainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// neutralDomain replaces {{domain}} when the real name cannot be used safely.
var neutralDomain = map[Lang]string{PT: "<domínio>", EN: "<domain>"}

// Render returns e with {{domain}} replaced by domain. A domain that is not a
// plain host name is replaced by "<domínio>", so a text that ends up in a
// shell command can never carry shell syntax.
func Render(e Entry, domain string) Entry {
	d := strings.ToLower(domain)
	if !domainOK.MatchString(d) {
		d = neutralDomain[e.lang]
		if d == "" {
			d = neutralDomain[PT]
		}
	}
	sub := func(s string) string { return strings.ReplaceAll(s, "{{domain}}", d) }
	return Entry{Title: sub(e.Title), Why: sub(e.Why), Fix: sub(e.Fix), Example: sub(e.Example), Verify: sub(e.Verify), Sources: e.Sources, Legal: e.Legal, Guidance: e.Guidance, lang: e.lang}
}
