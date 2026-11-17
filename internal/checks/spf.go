package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Finding IDs produced by the SPF check.
const (
	idSPFPresent = "email.spf.present"
	idSPFPolicy  = "email.spf.policy"
	idSPFLookups = "email.spf.lookups"
)

// spfLookupLimit is the maximum number of DNS-querying terms per evaluation
// (RFC 7208 §4.6.4).
const spfLookupLimit = 10

// SPF checks the Sender Policy Framework record (RFC 7208): that exactly one
// exists, that it ends in a restrictive default policy, and that evaluating it
// stays within the 10-lookup limit.
type SPF struct{}

// ID implements engine.Check.
func (SPF) ID() string { return "email.spf" }

// Area implements engine.Check.
func (SPF) Area() finding.Area { return finding.AreaEmail }

// Tier implements engine.Check.
func (SPF) Tier() finding.Tier { return finding.TierPassive }

// Run implements engine.Check.
func (SPF) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	s := &spfEval{ctx: ctx, r: d.DNS, cache: map[string]txtResult{}}

	recs, err := s.txt(t.Domain)
	if err != nil {
		return spfUnknown(err)
	}
	var spfs []string
	for _, r := range recs {
		if isSPF(r) {
			spfs = append(spfs, r)
		}
	}

	switch len(spfs) {
	case 0:
		return []finding.Finding{missingSPF(detectMail(ctx, d.DNS, t.Domain))}
	case 1:
	default:
		return []finding.Finding{spfFail(idSPFPresent, finding.SeverityHigh, spfs,
			"multiple SPF records: receivers must treat this as a permanent error (RFC 7208 §4.5)")}
	}

	rec := spfs[0]
	out := []finding.Finding{
		{ID: idSPFPresent, Area: finding.AreaEmail, Tier: finding.TierPassive,
			Status: finding.StatusPass, Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization,
			Evidence: []string{rec}},
		s.policyFinding(t.Domain, rec),
		s.lookupsFinding(t.Domain, rec),
	}
	if f, ok := spfIP4Finding(ctx, d.DNS, t.Domain, rec); ok {
		out = append(out, f)
	}
	return out
}

// missingSPF judges the absence of an SPF record. A domain that receives mail
// fails with high severity. A domain that is known not to receive mail gets a
// recommendation: it can still be spoofed, but we cannot tell whether it also
// sends mail, so the verdict is softer.
func missingSPF(m mailProfile) finding.Finding {
	if m.noMail() {
		return finding.Finding{ID: idSPFPresent, Area: finding.AreaEmail, Tier: finding.TierPassive,
			Status: finding.StatusWarn, Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization,
			Detail: `the domain does not receive email and publishes no SPF record: publish "v=spf1 -all" so that nobody can send mail in its name`}
	}
	return spfFail(idSPFPresent, finding.SeverityHigh, nil, "no SPF record published")
}

func spfUnknown(err error) []finding.Finding {
	var out []finding.Finding
	for _, id := range []string{idSPFPresent, idSPFPolicy, idSPFLookups} {
		out = append(out, finding.Unknown(id, finding.AreaEmail, finding.TierPassive, err.Error()))
	}
	return out
}

func spfFail(id string, sev finding.Severity, evidence []string, detail string) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Status: finding.StatusFail, Severity: sev, Fixer: finding.FixerOrganization,
		Evidence: evidence, Detail: detail}
}

// isSPF reports whether a TXT record is an SPF record: it starts with the
// version "v=spf1" (case-insensitive) followed by a space or the end.
func isSPF(rec string) bool {
	if len(rec) < 6 || !strings.EqualFold(rec[:6], "v=spf1") {
		return false
	}
	return len(rec) == 6 || rec[6] == ' '
}

type spfTerm struct {
	modifier bool
	name     string // modifier name, or mechanism name; lowercase
	qual     byte   // mechanisms only: '+', '-', '~' or '?'
	arg      string // domain-spec for include, a, mx, exists, redirect
}

// parseSPF splits a record into terms. Unknown terms are kept as mechanisms
// with an unknown name; they cost no lookups.
func parseSPF(rec string) []spfTerm {
	fields := strings.Fields(rec)
	if len(fields) == 0 {
		return nil
	}
	var terms []spfTerm
	for _, f := range fields[1:] {
		if i := strings.IndexAny(f, "=:/"); i > 0 && f[i] == '=' {
			terms = append(terms, spfTerm{modifier: true, name: strings.ToLower(f[:i]), arg: f[i+1:]})
			continue
		}
		qual := byte('+')
		if strings.IndexByte("+-~?", f[0]) >= 0 {
			qual, f = f[0], f[1:]
		}
		name, arg := f, ""
		if i := strings.IndexAny(f, ":/"); i >= 0 {
			name = f[:i]
			if f[i] == ':' {
				arg = f[i+1:]
			}
		}
		terms = append(terms, spfTerm{name: strings.ToLower(name), qual: qual, arg: arg})
	}
	return terms
}

type txtResult struct {
	recs []string
	err  error
}

// spfEval evaluates one SPF record tree. TXT lookups are cached, so the policy
// and lookup-count passes never ask the same question twice.
type spfEval struct {
	ctx   context.Context
	r     dnsx.Resolver
	cache map[string]txtResult
}

func (s *spfEval) txt(name string) ([]string, error) {
	if c, ok := s.cache[name]; ok {
		return c.recs, c.err
	}
	recs, err := lookupTXT(s.ctx, s.r, name)
	s.cache[name] = txtResult{recs, err}
	return recs, err
}

type spfStatus int

const (
	spfOK spfStatus = iota
	spfNone
	spfMultiple
)

// spfRecord fetches the single SPF record published at name.
func (s *spfEval) spfRecord(name string) (string, spfStatus, error) {
	recs, err := s.txt(name)
	if err != nil {
		return "", spfNone, err
	}
	var spfs []string
	for _, r := range recs {
		if isSPF(r) {
			spfs = append(spfs, r)
		}
	}
	switch len(spfs) {
	case 0:
		return "", spfNone, nil
	case 1:
		return spfs[0], spfOK, nil
	default:
		return "", spfMultiple, nil
	}
}

// policyFinding classifies the default policy: the "all" mechanism of the top
// record, or of its redirect target when the top record has no "all".
func (s *spfEval) policyFinding(domain, rec string) finding.Finding {
	qual, found, err := s.policyAll(rec, map[string]bool{domain: true})
	if err != nil {
		return finding.Unknown(idSPFPolicy, finding.AreaEmail, finding.TierPassive, err.Error())
	}
	f := finding.Finding{ID: idSPFPolicy, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityHigh, Fixer: finding.FixerOrganization, Evidence: []string{rec}}
	switch {
	case !found:
		f.Status, f.Severity, f.Detail = finding.StatusFail, finding.SeverityMedium, "no default policy: the record has no \"all\" mechanism"
	case qual == '-':
		f.Status, f.Detail = finding.StatusPass, "hard fail (-all)"
	case qual == '~':
		f.Status, f.Severity, f.Detail = finding.StatusWarn, finding.SeverityLow, "soft fail (~all): unauthorised senders are only marked"
	case qual == '?':
		f.Status, f.Severity, f.Detail = finding.StatusFail, finding.SeverityMedium, "neutral (?all): the record states no policy"
	default:
		f.Status, f.Severity, f.Detail = finding.StatusFail, finding.SeverityCritical, "+all (or bare all): every sender is authorised"
	}
	return f
}

// policyAll returns the qualifier of the "all" mechanism that decides the
// default policy. RFC 7208 §6.1: redirect is ignored when "all" is present.
func (s *spfEval) policyAll(rec string, seen map[string]bool) (qual byte, found bool, err error) {
	redirect := ""
	for _, tm := range parseSPF(rec) {
		if !tm.modifier && tm.name == "all" {
			return tm.qual, true, nil
		}
		if tm.modifier && tm.name == "redirect" {
			redirect = normalizeName(tm.arg)
		}
	}
	if redirect == "" || strings.Contains(redirect, "%") || seen[redirect] {
		return 0, false, nil
	}
	seen[redirect] = true
	target, st, err := s.spfRecord(redirect)
	if err != nil {
		return 0, false, err
	}
	if st != spfOK {
		return 0, false, nil
	}
	return s.policyAll(target, seen)
}

func normalizeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
}

// lookupsFinding walks include/redirect targets counting DNS-querying terms
// (RFC 7208 §4.6.4) and stops querying as soon as the limit is exceeded.
func (s *spfEval) lookupsFinding(domain, rec string) finding.Finding {
	w := &spfWalk{s: s}
	w.walk(rec, map[string]bool{domain: true})

	f := finding.Finding{ID: idSPFLookups, Area: finding.AreaEmail, Tier: finding.TierPassive,
		Severity: finding.SeverityMedium, Fixer: finding.FixerOrganization, Evidence: []string{rec}}
	switch {
	case w.err != nil:
		return finding.Unknown(idSPFLookups, finding.AreaEmail, finding.TierPassive, w.err.Error())
	case w.exceeded:
		f.Status = finding.StatusFail
		f.Detail = fmt.Sprintf("more than %d DNS lookups: receivers must treat this as a permanent error (RFC 7208 §4.6.4)", spfLookupLimit)
	case w.permerr != "":
		f.Status, f.Detail = finding.StatusFail, w.permerr
	case w.hasPtr:
		f.Status, f.Severity = finding.StatusWarn, finding.SeverityLow
		f.Detail = "the ptr mechanism is deprecated and slow (RFC 7208 §5.5)"
	default:
		f.Status = finding.StatusPass
		f.Detail = fmt.Sprintf("%d of %d DNS lookups", w.lookups, spfLookupLimit)
	}
	return f
}

type spfWalk struct {
	s        *spfEval
	lookups  int
	exceeded bool
	hasPtr   bool
	permerr  string
	err      error
}

func (w *spfWalk) count() bool {
	w.lookups++
	if w.lookups > spfLookupLimit {
		w.exceeded = true
		return false
	}
	return true
}

// walk reports whether evaluation may continue.
func (w *spfWalk) walk(rec string, path map[string]bool) bool {
	hasAll, redirect := false, ""
	for _, tm := range parseSPF(rec) {
		if tm.modifier {
			if tm.name == "redirect" {
				redirect = tm.arg
			}
			continue
		}
		switch tm.name {
		case "all":
			hasAll = true
		case "a", "mx", "exists":
			if !w.count() {
				return false
			}
		case "ptr":
			w.hasPtr = true
			if !w.count() {
				return false
			}
		case "include":
			if !w.follow(tm.arg, path) {
				return false
			}
		}
	}
	if !hasAll && redirect != "" {
		return w.follow(redirect, path)
	}
	return true
}

// follow counts one lookup and descends into an include or redirect target.
func (w *spfWalk) follow(target string, path map[string]bool) bool {
	if !w.count() {
		return false
	}
	target = normalizeName(target)
	if target == "" || strings.Contains(target, "%") {
		return true // macros cannot be expanded without a sender; count only
	}
	if path[target] {
		w.permerr = "include/redirect loop via " + target
		return false
	}
	rec, st, err := w.s.spfRecord(target)
	switch {
	case err != nil:
		w.err = err
		return false
	case st == spfNone:
		w.permerr = target + " has no SPF record (permanent error, RFC 7208 §5.2)"
		return false
	case st == spfMultiple:
		w.permerr = target + " publishes multiple SPF records (permanent error)"
		return false
	}
	path[target] = true
	ok := w.walk(rec, path)
	delete(path, target)
	return ok
}
