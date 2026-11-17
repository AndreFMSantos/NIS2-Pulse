package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ntfy"
)

const secretTopic = "https://ntfy.example.org/very-secret-topic-77"

type fakeNotifier struct {
	mu   sync.Mutex
	sent []ntfy.Message
	err  error
}

func (n *fakeNotifier) Send(_ context.Context, m ntfy.Message) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.sent = append(n.sent, m)
	return nil
}

// watchApp builds an app whose notifier, state directory and environment are fake.
func watchApp(t *testing.T, f *dnsxtest.Fake, n *fakeNotifier, env map[string]string) (*app, string) {
	t.Helper()
	a, _, _ := newTestApp(f, nil)
	dir := filepath.Join(t.TempDir(), "state")
	a.stateDir = func() string { return dir }
	a.getenv = func(k string) string { return env[k] }
	a.newNotifier = func(url string) (notifier, error) {
		if _, err := ntfy.New(url); err != nil {
			return nil, err
		}
		return n, nil
	}
	return a, dir
}

// healthyMail is a domain with a mail server, SPF and a strict DMARC policy.
func healthyMail() *dnsxtest.Fake {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	return f
}

// degraded is healthyMail without DMARC so the DMARC finding fails.
func degraded() *dnsxtest.Fake {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	return f
}

func rerun(t *testing.T, dir string, f *dnsxtest.Fake, n *fakeNotifier, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	a, out, errb := newTestApp(f, nil)
	a.stateDir = func() string { return dir }
	a.getenv = func(k string) string { return env[k] }
	a.newNotifier = func(url string) (notifier, error) { return n, nil }
	code := a.run(append([]string{"watch"}, args...))
	return code, out.String(), errb.String()
}

var withURL = map[string]string{"NIS2_PULSE_NTFY_URL": secretTopic}

func TestWatchFirstRunIsASilentBaseline(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	var out, errb strings.Builder
	a.stdout, a.stderr = &out, &errb
	if code := a.run([]string{"watch", "example.com"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if len(n.sent) != 0 {
		t.Errorf("the baseline must not notify: %+v", n.sent)
	}
	if _, err := os.Stat(filepath.Join(dir, "example.com.json")); err != nil {
		t.Errorf("the state was not saved: %v", err)
	}
	if !strings.Contains(out.String(), "baseline") {
		t.Errorf("stdout = %q, want it to say baseline", out.String())
	}
}

func TestWatchNotifiesADegradationOnceAndOnlyOnce(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	if code := a.run([]string{"watch", "example.com"}); code != 0 {
		t.Fatal("baseline failed")
	}
	// The DMARC record disappears.
	code, out, errb := rerun(t, dir, degraded(), n, withURL, "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if len(n.sent) != 1 {
		t.Fatalf("notifications = %d, want 1: %+v", len(n.sent), n.sent)
	}
	m := n.sent[0]
	if !strings.Contains(m.Title, "example.com") || !strings.Contains(m.Body, "email.dmarc.present") || m.Priority < 3 {
		t.Errorf("message = %+v", m)
	}
	if !strings.Contains(out, "notification sent") {
		t.Errorf("stdout = %q", out)
	}
	// Same state again: nothing new to say.
	if code, _, _ := rerun(t, dir, degraded(), n, withURL, "example.com"); code != 0 || len(n.sent) != 1 {
		t.Errorf("an unchanged failure was notified again: exit %d, %d notifications", code, len(n.sent))
	}
	// And a later improvement is not notified by default.
	if code, _, _ := rerun(t, dir, healthyMail(), n, withURL, "example.com"); code != 0 || len(n.sent) != 1 {
		t.Errorf("a fix must not notify by default: exit %d, %d notifications", code, len(n.sent))
	}
}

func TestWatchNotifiesResolvedOnRequest(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, degraded(), n, withURL)
	_ = a.run([]string{"watch", "example.com"})
	if code, _, _ := rerun(t, dir, healthyMail(), n, withURL, "--notify-resolved", "example.com"); code != 0 || len(n.sent) != 1 {
		t.Fatalf("exit %d, %d notifications, want 1", code, len(n.sent))
	}
}

func TestWatchDoesNotAdvanceTheStateWhenDeliveryFails(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	_ = a.run([]string{"watch", "example.com"})
	n.err = errors.New("ntfy: ntfy.example.org answered HTTP 503")
	code, _, errb := rerun(t, dir, degraded(), n, withURL, "example.com")
	if code != 1 || !strings.Contains(errb, "503") {
		t.Fatalf("a failed notification is an error: exit %d, stderr %q", code, errb)
	}
	// The ntfy server is back: the same degradation must be notified now, because the state did not move.
	n.err = nil
	if code, _, _ := rerun(t, dir, degraded(), n, withURL, "example.com"); code != 0 || len(n.sent) != 1 {
		t.Fatalf("the change must be retried: exit %d, %d notifications", code, len(n.sent))
	}
}

func TestWatchWithoutAnURLPrintsTheMessageInstead(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, nil)
	var out, errb strings.Builder
	a.stdout, a.stderr = &out, &errb
	_ = a.run([]string{"watch", "example.com"})
	if !strings.Contains(errb.String(), "no ntfy URL") {
		t.Errorf("the operator must be told that nothing will be pushed: %q", errb.String())
	}
	code, out2, _ := rerun(t, dir, degraded(), n, nil, "example.com")
	if code != 0 || len(n.sent) != 0 || !strings.Contains(out2, "email.dmarc.present") {
		t.Errorf("without a URL the change is printed, not sent: exit %d, sent %d, stdout %q", code, len(n.sent), out2)
	}
}

func TestWatchReadsTheURLFromAFileAndTheFileWins(t *testing.T) {
	n := &fakeNotifier{}
	a, _ := watchApp(t, healthyMail(), n, map[string]string{"NIS2_PULSE_NTFY_URL": "https://env.example.org/envtopic"})
	file := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(file, []byte("https://file.example.org/filetopic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	a.newNotifier = func(url string) (notifier, error) { got = append(got, url); return n, nil }
	if code := a.run([]string{"watch", "--ntfy-url-file", file, "example.com"}); code != 0 {
		t.Fatal("watch failed")
	}
	if len(got) != 1 || got[0] != "https://file.example.org/filetopic" {
		t.Errorf("notifier built from %v, want the file's URL (trimmed)", got)
	}
}

func TestWatchRefusesTheURLAsAnArgumentAndNeverPrintsIt(t *testing.T) {
	n := &fakeNotifier{}
	a, _ := watchApp(t, healthyMail(), n, nil)
	var out, errb strings.Builder
	a.stdout, a.stderr = &out, &errb
	if code := a.run([]string{"watch", "--ntfy-url", secretTopic, "example.com"}); code != 2 {
		t.Errorf("a URL on the command line is visible in the process list: exit %d, want 2", code)
	}
	// A bad URL in the environment must not be echoed.
	a2, _ := watchApp(t, healthyMail(), n, map[string]string{"NIS2_PULSE_NTFY_URL": "ftp://user:hunter2@host/very-secret-topic-77"})
	var o2, e2 strings.Builder
	a2.stdout, a2.stderr = &o2, &e2
	if code := a2.run([]string{"watch", "example.com"}); code != 2 {
		t.Errorf("a bad URL is a usage error: exit %d", code)
	}
	for _, s := range []string{out.String() + errb.String(), o2.String() + e2.String()} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "very-secret-topic-77") {
			t.Errorf("the secret was printed: %q", s)
		}
	}
}

func TestWatchWarnsAboutAReadableURLFile(t *testing.T) {
	n := &fakeNotifier{}
	a, _ := watchApp(t, healthyMail(), n, nil)
	file := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(file, []byte(secretTopic), 0o644); err != nil {
		t.Fatal(err)
	}
	var errb strings.Builder
	a.stderr = &errb
	_ = a.run([]string{"watch", "--ntfy-url-file", file, "example.com"})
	if !strings.Contains(errb.String(), "readable by other users") {
		t.Errorf("a world-readable secret file deserves a warning: %q", errb.String())
	}
}

func TestWatchIntervalLimits(t *testing.T) {
	n := &fakeNotifier{}
	for name, args := range map[string][]string{
		"too short":             {"--interval", "30m"},
		"active needs 6h":       {"--interval", "2h", "--active"},
		"negative":              {"--interval", "-1h"},
		"unknown domain syntax": {"--interval", "24h", "https://example.com"},
	} {
		a, _ := watchApp(t, healthyMail(), n, withURL)
		if code := a.run(append([]string{"watch"}, append(args, "example.com")...)); code != 2 && name != "unknown domain syntax" {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

func TestWatchLoopRunsUntilCancelledAndKeepsItsState(t *testing.T) {
	n := &fakeNotifier{}
	a, _ := watchApp(t, healthyMail(), n, withURL)
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	sleeps := 0
	a.sleep = func(ctx context.Context, d time.Duration) error {
		sleeps++
		if d < time.Hour {
			t.Errorf("sleep of %s: the interval is at least one hour", d)
		}
		if sleeps == 3 {
			cancel()
		}
		return ctx.Err()
	}
	var out strings.Builder
	a.stdout = &out
	if code := a.run([]string{"watch", "--interval", "24h", "example.com"}); code != 0 {
		t.Fatalf("a cancelled loop is a clean exit, got %d", code)
	}
	if sleeps != 3 {
		t.Errorf("sleeps = %d, want 3", sleeps)
	}
	if got := strings.Count(out.String(), "baseline"); got != 1 {
		t.Errorf("baseline lines = %d, want exactly 1 (the state must carry over between cycles):\n%s", got, out.String())
	}
}

func TestWatchAlertsAfterThreeFailedScansAndKeepsTheState(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	_ = a.run([]string{"watch", "example.com"})
	gone := dnsxtest.New()
	gone.SetRcode("example.com", 1, 3) // NXDOMAIN for the pre-flight A query
	for i := 1; i <= 4; i++ {
		code, _, _ := rerun(t, dir, gone, n, withURL, "example.com")
		if code != 1 {
			t.Errorf("run %d: a scan that cannot run is exit 1, got %d", i, code)
		}
		want := 0
		if i >= 3 {
			want = 1
		}
		if len(n.sent) != want {
			t.Errorf("after failure %d: %d notifications, want %d", i, len(n.sent), want)
		}
	}
	// The findings from before are still remembered: coming back healthy is not a new baseline.
	if code, out, _ := rerun(t, dir, healthyMail(), n, withURL, "example.com"); code != 0 || strings.Contains(out, "baseline") {
		t.Errorf("after the outage: exit %d, stdout %q (it must compare with the old state)", code, out)
	}
}

func TestWatchRefusesADamagedStateFileAndLeavesItAlone(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "example.com.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errb strings.Builder
	a.stderr = &errb
	if code := a.run([]string{"watch", "example.com"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "{not json" {
		t.Error("a damaged state file must be left for the operator to look at, not overwritten")
	}
	if !strings.Contains(errb.String(), "damaged") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestWatchTestNotify(t *testing.T) {
	n := &fakeNotifier{}
	a, _ := watchApp(t, healthyMail(), n, withURL)
	if code := a.run([]string{"watch", "--test-notify", "example.com"}); code != 0 || len(n.sent) != 1 {
		t.Fatalf("exit %d, sent %d", code, len(n.sent))
	}
	if !strings.Contains(n.sent[0].Title, "example.com") {
		t.Errorf("test message = %+v", n.sent[0])
	}
	a2, _ := watchApp(t, healthyMail(), n, nil)
	if code := a2.run([]string{"watch", "--test-notify", "example.com"}); code != 2 {
		t.Errorf("--test-notify without a URL is a usage error, got %d", code)
	}
}

func TestWatchLanguage(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	_ = a.run([]string{"watch", "--lang", "en", "example.com"})
	if code, _, _ := rerun(t, dir, degraded(), n, withURL, "--lang", "en", "example.com"); code != 0 || len(n.sent) != 1 {
		t.Fatal("expected one notification")
	}
	if !strings.Contains(n.sent[0].Body, "DMARC record exists") {
		t.Errorf("English body = %q", n.sent[0].Body)
	}
	if code := a.run([]string{"watch", "--lang", "fr", "example.com"}); code != 2 {
		t.Errorf("unsupported language: exit %d, want 2", code)
	}
}

func TestWatchStatePassiveToActiveIsANewBaseline(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	_ = a.run([]string{"watch", "example.com"})
	code, out, _ := rerun(t, dir, healthyMail(), n, withURL, "--active", "example.com")
	if code != 0 || !strings.Contains(out, "baseline") || len(n.sent) != 0 {
		t.Errorf("exit %d, stdout %q, sent %d", code, out, len(n.sent))
	}
}

// If the failure alert cannot be delivered, the failure counter must not move on, so the
// alert is attempted again at the next failure instead of being lost.
func TestWatchRetriesAFailureAlertThatCouldNotBeDelivered(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	_ = a.run([]string{"watch", "example.com"})
	gone := dnsxtest.New()
	gone.SetRcode("example.com", 1, 3)
	for i := 0; i < 2; i++ {
		rerun(t, dir, gone, n, withURL, "example.com")
	}
	n.err = errors.New("ntfy: ntfy.example.org answered HTTP 502")
	if code, _, _ := rerun(t, dir, gone, n, withURL, "example.com"); code != 1 || len(n.sent) != 0 {
		t.Fatalf("third failure with ntfy down: exit %d, sent %d", code, len(n.sent))
	}
	n.err = nil
	if _, _, _ = rerun(t, dir, gone, n, withURL, "example.com"); len(n.sent) != 1 {
		t.Fatalf("the failure alert must be retried once ntfy is back: %d notifications", len(n.sent))
	}
}

func TestWatchLoopStopsAtOnceOnADamagedStateFile(t *testing.T) {
	n := &fakeNotifier{}
	a, dir := watchApp(t, healthyMail(), n, withURL)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	sleeps := 0
	a.sleep = func(ctx context.Context, d time.Duration) error {
		sleeps++
		if sleeps > 20 { // a loop that does not stop must end the test, not hang it
			return context.Canceled
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.ctx = ctx
	if code := a.run([]string{"watch", "--interval", "24h", "example.com"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if sleeps != 0 {
		t.Errorf("the loop went on after the state file was found unusable (%d sleeps)", sleeps)
	}
}
