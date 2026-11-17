package watch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/watch"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func f(id string, st finding.Status, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive, Status: st, Severity: sev}
}

func scan(version string, active bool, fs ...finding.Finding) report.Result {
	return report.Result{Tool: "nis2-pulse", Version: version, Target: "example.pt", ScannedAt: t0, Active: active, Findings: fs}
}

func opts() watch.Options { return watch.Options{} }

// run compares prev with the scan and returns the next state and the changes.
func run(prev *watch.State, r report.Result, o watch.Options) (watch.State, watch.Changes) {
	return watch.Compare(prev, r, o)
}

func TestFirstRunIsASilentBaseline(t *testing.T) {
	st, ch := run(nil, scan("1", false, f("email.dmarc.present", finding.StatusFail, finding.SeverityHigh)), opts())
	if !ch.Baseline || ch.Alert() {
		t.Fatalf("first run: baseline=%v alert=%v, want a silent baseline", ch.Baseline, ch.Alert())
	}
	if st.Findings["email.dmarc.present"].Status != finding.StatusFail || st.Domain != "example.pt" || st.SchemaVersion != watch.SchemaVersion {
		t.Errorf("state = %+v", st)
	}
}

func TestNothingChangedNothingToSay(t *testing.T) {
	r := scan("1", false, f("a.b", finding.StatusFail, finding.SeverityHigh), f("c.d", finding.StatusPass, ""))
	st, _ := run(nil, r, opts())
	_, ch := run(&st, r, opts())
	if ch.Alert() || len(ch.Degraded)+len(ch.Improved)+len(ch.LostVisibility) != 0 {
		t.Fatalf("an unchanged failure must not alert again: %+v", ch)
	}
}

func TestDegradationsAlert(t *testing.T) {
	cases := []struct {
		name     string
		from, to finding.Finding
	}{
		{"pass to fail", f("email.spf.policy", finding.StatusPass, ""), f("email.spf.policy", finding.StatusFail, finding.SeverityHigh)},
		{"pass to warn", f("email.spf.policy", finding.StatusPass, ""), f("email.spf.policy", finding.StatusWarn, finding.SeverityLow)},
		{"warn to fail", f("email.spf.policy", finding.StatusWarn, finding.SeverityMedium), f("email.spf.policy", finding.StatusFail, finding.SeverityMedium)},
		{"severity goes up", f("email.spf.policy", finding.StatusFail, finding.SeverityLow), f("email.spf.policy", finding.StatusFail, finding.SeverityCritical)},
		{"info to fail", f("email.spf.policy", finding.StatusInfo, ""), f("email.spf.policy", finding.StatusFail, finding.SeverityMedium)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, _ := run(nil, scan("1", false, c.from), opts())
			_, ch := run(&st, scan("1", false, c.to), opts())
			if !ch.Alert() || len(ch.Degraded) != 1 || ch.Degraded[0].ID != "email.spf.policy" {
				t.Fatalf("changes = %+v", ch)
			}
			if ch.Degraded[0].From.Status != c.from.Status || ch.Degraded[0].To.Status != c.to.Status {
				t.Errorf("from/to = %+v", ch.Degraded[0])
			}
		})
	}
}

func TestImprovementsDoNotAlertUnlessAsked(t *testing.T) {
	bad := scan("1", false, f("x.y", finding.StatusFail, finding.SeverityHigh))
	good := scan("1", false, f("x.y", finding.StatusPass, ""))
	st, _ := run(nil, bad, opts())
	_, ch := run(&st, good, opts())
	if ch.Alert() || len(ch.Improved) != 1 {
		t.Fatalf("a fix is recorded but is not an alert by default: %+v", ch)
	}
	_, ch = run(&st, good, watch.Options{NotifyResolved: true})
	if !ch.Alert() {
		t.Fatal("with NotifyResolved a fix must be sent")
	}
	// A less severe failure is also an improvement, never a degradation.
	st2, _ := run(nil, scan("1", false, f("x.y", finding.StatusFail, finding.SeverityCritical)), opts())
	_, ch = run(&st2, scan("1", false, f("x.y", finding.StatusFail, finding.SeverityLow)), opts())
	if len(ch.Degraded) != 0 || len(ch.Improved) != 1 {
		t.Fatalf("fail critical -> fail low: %+v", ch)
	}
}

func TestNewFindingsAlertOnlyWhenTheToolDidNotChange(t *testing.T) {
	prev, _ := run(nil, scan("1", false, f("a.b", finding.StatusPass, "")), opts())
	next := scan("1", false, f("a.b", finding.StatusPass, ""), f("c.d", finding.StatusFail, finding.SeverityHigh))
	if _, ch := run(&prev, next, opts()); !ch.Alert() || ch.Degraded[0].ID != "c.d" {
		t.Fatalf("a new failing finding with the same version must alert: %+v", ch)
	}
	// After an upgrade the tool has checks the previous version did not: they are baseline, not news.
	next.Version = "2"
	st, ch := run(&prev, next, opts())
	if ch.Alert() {
		t.Fatalf("a check that only exists because the tool was upgraded must not alert: %+v", ch)
	}
	if st.Findings["c.d"].Status != finding.StatusFail || st.Version != "2" {
		t.Errorf("the new check must enter the baseline: %+v", st)
	}
	// ...but a degradation of a known finding still alerts after the upgrade.
	st, _ = run(&prev, scan("2", false, f("a.b", finding.StatusPass, "")), opts())
	if _, ch := run(&st, scan("2", false, f("a.b", finding.StatusFail, finding.SeverityHigh)), opts()); !ch.Alert() {
		t.Fatal("a degradation after an upgrade must alert")
	}
}

func TestSwitchingBetweenPassiveAndActiveResetsTheBaseline(t *testing.T) {
	passive := scan("1", false, f("transport.tls.legacy", finding.StatusUnknown, ""))
	active := scan("1", true, f("transport.tls.legacy", finding.StatusFail, finding.SeverityHigh))
	st, _ := run(nil, passive, opts())
	st2, ch := run(&st, active, opts())
	if ch.Alert() || !ch.Baseline {
		t.Fatalf("the first active scan after passive ones is a new baseline: %+v", ch)
	}
	// And back: the active verdict becoming "skipped" must not read as lost visibility.
	_, ch = run(&st2, passive, opts())
	if ch.Alert() || !ch.Baseline {
		t.Fatalf("going back to passive is a new baseline: %+v", ch)
	}
}

func TestLostVisibilityNeedsThreeScansInARowAndAlertsOnce(t *testing.T) {
	good := scan("1", false, f("a.b", finding.StatusPass, ""))
	blind := scan("1", false, f("a.b", finding.StatusUnknown, ""))
	st, _ := run(nil, good, opts())
	var alerts int
	for i := 1; i <= 5; i++ {
		var ch watch.Changes
		st, ch = run(&st, blind, opts())
		if ch.Alert() {
			alerts++
			if i != 3 || len(ch.LostVisibility) != 1 {
				t.Errorf("the alert must come at the third blind scan, came at %d: %+v", i, ch)
			}
		}
	}
	if alerts != 1 {
		t.Errorf("alerts = %d, want exactly 1", alerts)
	}
	// Visibility back resets the streak: two blind scans then a good one then two blind ones is still silent.
	st, _ = run(nil, good, opts())
	for _, r := range []report.Result{blind, blind, good, blind, blind} {
		var ch watch.Changes
		st, ch = run(&st, r, opts())
		if ch.Alert() {
			t.Fatalf("an interrupted streak must not alert: %+v", ch)
		}
	}
}

func TestAFindingThatWasNeverVisibleIsNotLostVisibility(t *testing.T) {
	blind := scan("1", false, f("transport.tls.legacy", finding.StatusUnknown, ""))
	st, _ := run(nil, blind, opts())
	for i := 0; i < 6; i++ {
		var ch watch.Changes
		st, ch = run(&st, blind, opts())
		if ch.Alert() {
			t.Fatalf("scan %d: something that never had a verdict (skipped by design) must stay silent: %+v", i, ch)
		}
	}
}

func TestComparisonUsesTheLastVerdictAcrossAnUnknown(t *testing.T) {
	st, _ := run(nil, scan("1", false, f("a.b", finding.StatusPass, "")), opts())
	st, _ = run(&st, scan("1", false, f("a.b", finding.StatusUnknown, "")), opts())
	_, ch := run(&st, scan("1", false, f("a.b", finding.StatusFail, finding.SeverityHigh)), opts())
	if !ch.Alert() || len(ch.Degraded) != 1 {
		t.Fatalf("pass -> unknown -> fail is a degradation: %+v", ch)
	}
	// Still failing the same way after a blind scan: no new alert.
	st, _ = run(nil, scan("1", false, f("a.b", finding.StatusFail, finding.SeverityHigh)), opts())
	st, _ = run(&st, scan("1", false, f("a.b", finding.StatusUnknown, "")), opts())
	if _, ch := run(&st, scan("1", false, f("a.b", finding.StatusFail, finding.SeverityHigh)), opts()); ch.Alert() {
		t.Fatalf("the same failure after a blind scan is not news: %+v", ch)
	}
}

func TestScanFailuresAlertOnceAtTheThirdAndResetOnSuccess(t *testing.T) {
	st, _ := run(nil, scan("1", false, f("a.b", finding.StatusPass, "")), opts())
	var alerts int
	for i := 1; i <= 6; i++ {
		var alert bool
		st, alert = watch.RecordFailure(&st, "example.pt", t0)
		if alert {
			alerts++
			if i != 3 {
				t.Errorf("the failure alert must come at the third failure, came at %d", i)
			}
		}
	}
	if alerts != 1 {
		t.Errorf("failure alerts = %d, want 1", alerts)
	}
	st, ch := run(&st, scan("1", false, f("a.b", finding.StatusPass, "")), opts())
	if st.ScanFailures != 0 || ch.Alert() {
		t.Errorf("a successful scan resets the failures silently: %+v %+v", st, ch)
	}
	// Failures before any success also count (no baseline yet).
	fresh, alert := watch.RecordFailure(nil, "example.pt", t0)
	if alert || fresh.ScanFailures != 1 || fresh.Domain != "example.pt" {
		t.Errorf("first failure without a state: %+v alert=%v", fresh, alert)
	}
}

func TestMessageHasTitlesAndIDsButNeverNetworkText(t *testing.T) {
	hostile := f("email.dmarc.present", finding.StatusFail, finding.SeverityHigh)
	hostile.Detail = "HOSTILE-DETAIL <script>alert(1)</script>"
	hostile.Evidence = []string{"HOSTILE-EVIDENCE v=spf1 -all"}
	st, _ := run(nil, scan("1", false, f("email.dmarc.present", finding.StatusPass, "")), opts())
	_, ch := run(&st, scan("1", false, hostile), opts())
	m := watch.Message(catalog.PT, "example.pt", ch)
	if !strings.Contains(m.Title, "example.pt") || !strings.Contains(m.Body, "email.dmarc.present") || !strings.Contains(m.Body, "Registo DMARC existe") {
		t.Errorf("message = %+v", m)
	}
	if strings.Contains(m.Body+m.Title, "HOSTILE") {
		t.Errorf("text from the network leaked into the notification: %+v", m)
	}
	en := watch.Message(catalog.EN, "example.pt", ch)
	if !strings.Contains(en.Body, "DMARC record exists") || strings.Contains(en.Body, "Registo") {
		t.Errorf("English message = %+v", en)
	}
}

func TestMessagePriorityFollowsTheWorstDegradation(t *testing.T) {
	mk := func(sev finding.Severity, st finding.Status) watch.Changes {
		prev, _ := run(nil, scan("1", false, f("a.b", finding.StatusPass, "")), opts())
		_, ch := run(&prev, scan("1", false, f("a.b", st, sev)), opts())
		return ch
	}
	if p := watch.Message(catalog.EN, "example.pt", mk(finding.SeverityCritical, finding.StatusFail)).Priority; p != 5 {
		t.Errorf("critical failure priority = %d, want 5", p)
	}
	if p := watch.Message(catalog.EN, "example.pt", mk(finding.SeverityHigh, finding.StatusFail)).Priority; p != 4 {
		t.Errorf("high failure priority = %d, want 4", p)
	}
	if p := watch.Message(catalog.EN, "example.pt", mk(finding.SeverityLow, finding.StatusWarn)).Priority; p != 3 {
		t.Errorf("low warning priority = %d, want 3", p)
	}
}

func TestMessageIsBoundedAndSaysHowMuchWasLeftOut(t *testing.T) {
	var prevF, nextF []finding.Finding
	for i := 0; i < 120; i++ {
		id := "email.spf.policy" + strings.Repeat("x", 40) + string(rune('a'+i%26)) + strings.Repeat("y", i)
		prevF = append(prevF, f(id, finding.StatusPass, ""))
		nextF = append(nextF, f(id, finding.StatusFail, finding.SeverityHigh))
	}
	st, _ := run(nil, scan("1", false, prevF...), opts())
	_, ch := run(&st, scan("1", false, nextF...), opts())
	m := watch.Message(catalog.EN, "example.pt", ch)
	if len(m.Body) > watch.MaxBody {
		t.Errorf("body is %d bytes, over the limit %d", len(m.Body), watch.MaxBody)
	}
	if !strings.Contains(m.Body, "more") {
		t.Errorf("a truncated message must say that items were left out: %q", m.Body[len(m.Body)-80:])
	}
}

func TestResolvedMessage(t *testing.T) {
	st, _ := run(nil, scan("1", false, f("email.dmarc.present", finding.StatusFail, finding.SeverityHigh)), opts())
	_, ch := run(&st, scan("1", false, f("email.dmarc.present", finding.StatusPass, "")), watch.Options{NotifyResolved: true})
	m := watch.Message(catalog.EN, "example.pt", ch)
	if !strings.Contains(strings.ToLower(m.Title+m.Body), "resolved") || m.Priority > 3 {
		t.Errorf("a resolved-only message is low priority and says so: %+v", m)
	}
}

func TestStateRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, _ := run(nil, scan("1", false, f("a.b", finding.StatusFail, finding.SeverityHigh)), opts())
	if err := watch.Save(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := watch.Load(dir, "example.pt")
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.Findings["a.b"].Status != finding.StatusFail || got.Domain != "example.pt" {
		t.Errorf("round trip lost data: %+v", got)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("state directory mode = %v, want 0700", di.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the directory has %d entries (a temporary file was left behind?)", len(entries))
	}
	fi, _ := entries[0].Info()
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLoadWithoutAFileIsAFirstRun(t *testing.T) {
	st, err := watch.Load(t.TempDir(), "example.pt")
	if err != nil || st != nil {
		t.Fatalf("no file: state=%v err=%v, want nil and nil", st, err)
	}
}

func TestLoadRefusesCorruptOrForeignOrNewerState(t *testing.T) {
	dir := t.TempDir()
	path := watch.StatePath(dir, "example.pt")
	for name, content := range map[string]string{
		"not json":        "{{{",
		"other domain":    `{"schema_version":1,"domain":"other.pt","findings":{}}`,
		"newer schema":    `{"schema_version":99,"domain":"example.pt","findings":{}}`,
		"missing version": `{"domain":"example.pt","findings":{}}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if st, err := watch.Load(dir, "example.pt"); err == nil || st != nil {
			t.Errorf("%s: state=%v err=%v, want an error and no state", name, st, err)
		}
	}
}

func TestStatePathCannotEscapeTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../x", "a/b", `a\b`, "", "..", "a b", "x;y", "a\x00b"} {
		if _, err := watch.Load(dir, bad); err == nil {
			t.Errorf("Load(%q) must refuse an unsafe domain", bad)
		}
		if err := watch.Save(dir, watch.State{SchemaVersion: watch.SchemaVersion, Domain: bad}); err == nil {
			t.Errorf("Save(%q) must refuse an unsafe domain", bad)
		}
	}
	if p := watch.StatePath(dir, "example.pt"); filepath.Dir(p) != dir || !strings.HasSuffix(p, ".json") {
		t.Errorf("state path = %s", p)
	}
}
