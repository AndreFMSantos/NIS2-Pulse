// Package watch is the logic behind monitoring: it compares one scan with the
// previous one and decides what is worth a notification. It performs no network
// access; sending is the job of package ntfy and scheduling that of the command.
//
// The rules are deliberately conservative, because a monitor that cries wolf is
// switched off:
//
//   - the first scan (and the first one after switching between passive and
//     active mode) is a silent baseline;
//   - only a change for the worse is news; an unchanged failure is not repeated;
//   - checks that exist only because the tool was upgraded join the baseline;
//   - a check that stops producing a verdict is reported only after it has been
//     blind for three scans in a row, and once;
//   - the notification carries identifiers and catalog titles, never text taken
//     from the network.
package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/score"
)

// SchemaVersion is the version of the state file.
const SchemaVersion = 1

// MaxBody bounds a notification body (ntfy accepts 4096 bytes).
const MaxBody = 3500

const (
	lostVisibilityAfter = 3 // consecutive scans without a verdict
	failureAlertAfter   = 3 // consecutive scans that could not run
	maxStateBytes       = 1 << 20
)

// Entry is what the state remembers about one finding.
type Entry struct {
	Status   finding.Status   `json:"status"`
	Severity finding.Severity `json:"severity,omitempty"`
	Area     finding.Area     `json:"area"`
	// Verdict is the last status that carried information (pass, warn, fail or
	// info), with its severity, so that a blind scan in the middle does not erase
	// what was known.
	Verdict         finding.Status   `json:"verdict,omitempty"`
	VerdictSeverity finding.Severity `json:"verdict_severity,omitempty"`
	// UnknownStreak counts consecutive scans without a verdict.
	UnknownStreak int `json:"unknown_streak,omitempty"`
}

// State is the memory of the monitor for one domain.
type State struct {
	SchemaVersion int              `json:"schema_version"`
	Domain        string           `json:"domain"`
	Version       string           `json:"version"`
	Active        bool             `json:"active"`
	UpdatedAt     time.Time        `json:"updated_at"`
	Findings      map[string]Entry `json:"findings"`
	ScanFailures  int              `json:"scan_failures,omitempty"`
}

// Options tune what counts as news.
type Options struct {
	// NotifyResolved also reports findings that got better.
	NotifyResolved bool
}

// Snapshot is a status with its severity.
type Snapshot struct {
	Status   finding.Status
	Severity finding.Severity
}

// Change is one finding that changed between two scans.
type Change struct {
	ID       string
	Area     finding.Area
	From, To Snapshot // From.Status is empty for a finding that is new
}

// Changes is the result of comparing two scans.
type Changes struct {
	// Baseline is true when there was nothing comparable (first scan, or the
	// mode changed): nothing is reported.
	Baseline       bool
	Degraded       []Change
	Improved       []Change
	LostVisibility []Change

	notifyResolved bool
}

// Alert reports whether anything deserves a notification.
func (c Changes) Alert() bool {
	if c.Baseline {
		return false
	}
	return len(c.Degraded) > 0 || len(c.LostVisibility) > 0 || (c.notifyResolved && len(c.Improved) > 0)
}

func isVerdict(s finding.Status) bool {
	return s == finding.StatusPass || s == finding.StatusWarn || s == finding.StatusFail || s == finding.StatusInfo
}

// Compare compares a scan with the previous state and returns the new state.
// prev may be nil (first scan). The returned state is what must be saved once
// the notification, if any, has been delivered.
func Compare(prev *State, r report.Result, o Options) (State, Changes) {
	next := State{
		SchemaVersion: SchemaVersion, Domain: r.Target, Version: r.Version, Active: r.Active,
		UpdatedAt: r.ScannedAt.UTC(), Findings: make(map[string]Entry, len(r.Findings)),
	}
	ch := Changes{notifyResolved: o.NotifyResolved}
	baseline := prev == nil || prev.Active != r.Active
	upgraded := prev != nil && prev.Version != r.Version
	ch.Baseline = baseline

	for _, f := range r.Findings {
		e := Entry{Status: f.Status, Severity: f.Severity, Area: f.Area}
		old, known := Entry{}, false
		if !baseline {
			old, known = prev.Findings[f.ID]
		}
		if isVerdict(f.Status) {
			e.Verdict, e.VerdictSeverity = f.Status, f.Severity
		} else if known {
			e.Verdict, e.VerdictSeverity = old.Verdict, old.VerdictSeverity
		}
		switch {
		case baseline:
			if !isVerdict(f.Status) {
				e.UnknownStreak = 1
			}
		case !known:
			// New to the monitor. After an upgrade it is the tool that changed, not the domain.
			if !upgraded && score.Penalty(f.Status, f.Severity) > 0 {
				ch.Degraded = append(ch.Degraded, Change{ID: f.ID, Area: f.Area, To: Snapshot{f.Status, f.Severity}})
			}
			if !isVerdict(f.Status) {
				e.UnknownStreak = 1
			}
		case isVerdict(f.Status):
			oldBad := score.Penalty(old.Verdict, old.VerdictSeverity)
			curBad := score.Penalty(f.Status, f.Severity)
			from := Snapshot{old.Verdict, old.VerdictSeverity}
			c := Change{ID: f.ID, Area: f.Area, From: from, To: Snapshot{f.Status, f.Severity}}
			switch {
			case curBad > oldBad:
				ch.Degraded = append(ch.Degraded, c)
			case curBad < oldBad:
				ch.Improved = append(ch.Improved, c)
			}
		default: // unknown now
			e.UnknownStreak = old.UnknownStreak + 1
			if (old.Verdict == finding.StatusPass || old.Verdict == finding.StatusWarn || old.Verdict == finding.StatusFail) &&
				e.UnknownStreak == lostVisibilityAfter {
				ch.LostVisibility = append(ch.LostVisibility, Change{
					ID: f.ID, Area: f.Area, From: Snapshot{old.Verdict, old.VerdictSeverity}, To: Snapshot{Status: finding.StatusUnknown},
				})
			}
		}
		next.Findings[f.ID] = e
	}
	sortChanges(ch.Degraded)
	sortChanges(ch.Improved)
	sortChanges(ch.LostVisibility)
	return next, ch
}

func sortChanges(cs []Change) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := score.Penalty(cs[i].To.Status, cs[i].To.Severity), score.Penalty(cs[j].To.Status, cs[j].To.Severity)
		if a != b {
			return a > b
		}
		return cs[i].ID < cs[j].ID
	})
}

// RecordFailure registers a scan that could not run (resolver unreachable,
// domain gone). It returns the state to save and whether this failure, the third
// in a row, deserves a notification. Findings are left untouched.
func RecordFailure(prev *State, domain string, at time.Time) (State, bool) {
	st := State{SchemaVersion: SchemaVersion, Domain: domain, Findings: map[string]Entry{}}
	if prev != nil {
		st = *prev
		st.Findings = make(map[string]Entry, len(prev.Findings))
		for k, v := range prev.Findings {
			st.Findings[k] = v
		}
	}
	st.ScanFailures++
	st.UpdatedAt = at.UTC()
	return st, st.ScanFailures == failureAlertAfter
}

// ---- messages ----

// Msg is a notification.
type Msg struct {
	Title    string
	Body     string
	Priority int // ntfy priority 1 (min) to 5 (max)
	Tags     []string
}

type words struct {
	worsened, resolved, blind, more, newOne string
	status                                  map[finding.Status]string
	severity                                map[finding.Severity]string
	was                                     string
	title                                   func(domain string, degraded, blind, resolved int) string
	failTitle, failBody                     string
}

var texts = map[catalog.Lang]words{
	catalog.PT: {
		worsened: "Piorou", resolved: "Resolvido", blind: "Sem veredito há 3 verificações seguidas", more: "e mais %d", newOne: "novo", was: "antes",
		status: map[finding.Status]string{
			finding.StatusPass: "passou", finding.StatusWarn: "aviso", finding.StatusFail: "falha",
			finding.StatusInfo: "info", finding.StatusUnknown: "sem veredito",
		},
		severity: map[finding.Severity]string{
			finding.SeverityCritical: "crítica", finding.SeverityHigh: "alta", finding.SeverityMedium: "média", finding.SeverityLow: "baixa",
		},
		title: func(d string, deg, bl, res int) string {
			switch {
			case deg > 0:
				return fmt.Sprintf("nis2-pulse: %s: %d a piorar", d, deg)
			case bl > 0:
				return fmt.Sprintf("nis2-pulse: %s: %d sem veredito", d, bl)
			default:
				return fmt.Sprintf("nis2-pulse: %s: %d resolvido(s)", d, res)
			}
		},
		failTitle: "nis2-pulse: %s: a verificação não corre",
		failBody:  "%d verificações seguidas não conseguiram correr (resolvedor inacessível ou domínio inexistente). O estado anterior foi mantido.",
	},
	catalog.EN: {
		worsened: "Worsened", resolved: "Resolved", blind: "No verdict for 3 scans in a row", more: "and %d more", newOne: "new", was: "was",
		status: map[finding.Status]string{
			finding.StatusPass: "passed", finding.StatusWarn: "warning", finding.StatusFail: "failure",
			finding.StatusInfo: "info", finding.StatusUnknown: "no verdict",
		},
		severity: map[finding.Severity]string{
			finding.SeverityCritical: "critical", finding.SeverityHigh: "high", finding.SeverityMedium: "medium", finding.SeverityLow: "low",
		},
		title: func(d string, deg, bl, res int) string {
			switch {
			case deg > 0:
				return fmt.Sprintf("nis2-pulse: %s: %d worsened", d, deg)
			case bl > 0:
				return fmt.Sprintf("nis2-pulse: %s: %d without a verdict", d, bl)
			default:
				return fmt.Sprintf("nis2-pulse: %s: %d resolved", d, res)
			}
		},
		failTitle: "nis2-pulse: %s: the check is not running",
		failBody:  "%d scans in a row could not run (resolver unreachable or domain gone). The previous state was kept.",
	},
}

var idOK = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9]+)*$`)

// Message builds the notification for ch. It uses only identifiers, catalog
// titles and fixed words: evidence and details come from the network and never
// go into a notification.
func Message(lang catalog.Lang, domain string, ch Changes) Msg {
	w, ok := texts[lang]
	if !ok {
		w = texts[catalog.EN]
		lang = catalog.EN
	}
	line := func(c Change) string {
		title := c.ID
		if e, ok := catalog.Lookup(lang, c.ID); ok {
			title = e.Title
		}
		id := c.ID
		if !idOK.MatchString(id) {
			id = "?"
		}
		now := w.status[c.To.Status]
		if s, ok := w.severity[c.To.Severity]; ok && (c.To.Status == finding.StatusFail || c.To.Status == finding.StatusWarn) {
			now += ", " + s
		}
		was := w.newOne
		if c.From.Status != "" {
			was = w.was + ": " + w.status[c.From.Status]
		}
		return fmt.Sprintf("- %s (%s): %s (%s)", title, id, now, was)
	}
	var body strings.Builder
	left := 0
	section := func(head string, cs []Change) {
		if len(cs) == 0 {
			return
		}
		h := head + ":\n"
		if body.Len() > 0 {
			h = "\n" + h
		}
		if body.Len()+len(h) > MaxBody-60 {
			left += len(cs)
			return
		}
		body.WriteString(h)
		for i, c := range cs {
			l := line(c) + "\n"
			if body.Len()+len(l) > MaxBody-60 {
				left += len(cs) - i
				return
			}
			body.WriteString(l)
		}
	}
	section(w.worsened, ch.Degraded)
	section(w.blind, ch.LostVisibility)
	if ch.notifyResolved {
		section(w.resolved, ch.Improved)
	}
	if left > 0 {
		body.WriteString("… " + fmt.Sprintf(w.more, left) + "\n")
	}

	worst := 0
	for _, c := range ch.Degraded {
		if p := score.Penalty(c.To.Status, c.To.Severity); p > worst {
			worst = p
		}
	}
	m := Msg{Title: w.title(domain, len(ch.Degraded), len(ch.LostVisibility), len(ch.Improved)), Body: strings.TrimRight(body.String(), "\n")}
	switch {
	case worst >= 40:
		m.Priority, m.Tags = 5, []string{"rotating_light"}
	case worst >= 25:
		m.Priority, m.Tags = 4, []string{"warning"}
	case len(ch.Degraded) > 0 || len(ch.LostVisibility) > 0:
		m.Priority, m.Tags = 3, []string{"warning"}
	default:
		m.Priority, m.Tags = 2, []string{"white_check_mark"}
	}
	return m
}

// FailureMessage is the notification for a scan that keeps failing.
func FailureMessage(lang catalog.Lang, domain string, failures int) Msg {
	w, ok := texts[lang]
	if !ok {
		w = texts[catalog.EN]
	}
	return Msg{Title: fmt.Sprintf(w.failTitle, domain), Body: fmt.Sprintf(w.failBody, failures), Priority: 3, Tags: []string{"warning"}}
}

// ---- state file ----

var domainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func validDomain(d string) bool { return len(d) <= 253 && domainOK.MatchString(d) }

// StatePath returns the state file of domain inside dir.
func StatePath(dir, domain string) string { return filepath.Join(dir, domain+".json") }

// Load reads the state of domain. A missing file is a first run: it returns nil
// and no error. A damaged, foreign or newer file is an error and the caller
// decides what to do; it is never silently replaced.
func Load(dir, domain string) (*State, error) {
	if !validDomain(domain) {
		return nil, fmt.Errorf("watch: %q is not a plain domain name", domain)
	}
	f, err := os.Open(StatePath(dir, domain))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxStateBytes {
		return nil, fmt.Errorf("watch: state file for %s is larger than %d bytes", domain, maxStateBytes)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("watch: state file for %s is damaged: %w", domain, err)
	}
	switch {
	case st.SchemaVersion != SchemaVersion:
		return nil, fmt.Errorf("watch: state file for %s has schema version %d, this build reads %d", domain, st.SchemaVersion, SchemaVersion)
	case st.Domain != domain:
		return nil, fmt.Errorf("watch: state file for %s belongs to %q", domain, st.Domain)
	}
	if st.Findings == nil {
		st.Findings = map[string]Entry{}
	}
	return &st, nil
}

// Save writes st atomically (temporary file, then rename) with mode 0600 in a
// directory created with mode 0700.
func Save(dir string, st State) error {
	if !validDomain(st.Domain) {
		return fmt.Errorf("watch: %q is not a plain domain name", st.Domain)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, StatePath(dir, st.Domain)); err != nil {
		cleanup()
		return err
	}
	return nil
}
