package engine_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// fakeCheck is a configurable engine.Check used to exercise the engine.
type fakeCheck struct {
	id    string
	tier  finding.Tier
	run   func(ctx context.Context) []finding.Finding
	calls atomic.Int32
}

func (f *fakeCheck) ID() string         { return f.id }
func (f *fakeCheck) Area() finding.Area { return finding.AreaEmail }
func (f *fakeCheck) Tier() finding.Tier { return f.tier }
func (f *fakeCheck) Run(ctx context.Context, _ engine.Target, _ engine.Deps) []finding.Finding {
	f.calls.Add(1)
	return f.run(ctx)
}

func passing(id string) func(context.Context) []finding.Finding {
	return func(context.Context) []finding.Finding {
		return []finding.Finding{{ID: id, Area: finding.AreaEmail, Tier: finding.TierPassive, Status: finding.StatusPass}}
	}
}

func TestActiveCheckIsNeverRunWithoutActiveFlag(t *testing.T) {
	c := &fakeCheck{id: "transport.tls", tier: finding.TierActive, run: passing("transport.tls")}

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{c}, engine.Deps{}, engine.Options{Active: false})

	if n := c.calls.Load(); n != 0 {
		t.Fatalf("active check ran %d times without --active; this is the legal safety guarantee", n)
	}
	if len(got) != 1 || got[0].Status != finding.StatusUnknown || got[0].ID != "transport.tls" {
		t.Fatalf("expected one unknown finding for the skipped check, got %+v", got)
	}
	if !strings.Contains(got[0].Detail, "--active") {
		t.Errorf("detail should mention --active, got %q", got[0].Detail)
	}
	if got[0].Tier != finding.TierActive {
		t.Errorf("skipped finding must keep the check's tier, got %q", got[0].Tier)
	}
}

func TestActiveCheckRunsWhenEnabled(t *testing.T) {
	c := &fakeCheck{id: "transport.tls", tier: finding.TierActive, run: passing("transport.tls")}

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{c}, engine.Deps{}, engine.Options{Active: true})

	if c.calls.Load() != 1 || len(got) != 1 || got[0].Status != finding.StatusPass {
		t.Fatalf("active check should have run once and passed, calls=%d got=%+v", c.calls.Load(), got)
	}
}

func TestPanickingCheckBecomesUnknownAndOthersStillRun(t *testing.T) {
	bad := &fakeCheck{id: "bad", tier: finding.TierPassive, run: func(context.Context) []finding.Finding { panic("boom") }}
	good := &fakeCheck{id: "good", tier: finding.TierPassive, run: passing("good")}

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{bad, good}, engine.Deps{}, engine.Options{})

	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %+v", got)
	}
	if got[0].ID != "bad" || got[0].Status != finding.StatusUnknown || !strings.Contains(got[0].Detail, "boom") {
		t.Errorf("panic should be an unknown finding mentioning the panic, got %+v", got[0])
	}
	if got[1].ID != "good" || got[1].Status != finding.StatusPass {
		t.Errorf("healthy check must be unaffected, got %+v", got[1])
	}
}

func TestSlowCheckTimesOut(t *testing.T) {
	slow := &fakeCheck{id: "slow", tier: finding.TierPassive, run: func(ctx context.Context) []finding.Finding {
		<-ctx.Done()
		return nil
	}}

	start := time.Now()
	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{slow}, engine.Deps{}, engine.Options{CheckTimeout: 30 * time.Millisecond})

	if time.Since(start) > 2*time.Second {
		t.Fatal("engine did not honour the per-check timeout")
	}
	if len(got) != 1 || got[0].Status != finding.StatusUnknown || !strings.Contains(got[0].Detail, "timed out") {
		t.Fatalf("want one timed-out unknown finding, got %+v", got)
	}
}

func TestCheckReturningNothingBecomesUnknown(t *testing.T) {
	c := &fakeCheck{id: "empty", tier: finding.TierPassive, run: func(context.Context) []finding.Finding { return nil }}

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{c}, engine.Deps{}, engine.Options{})

	if len(got) != 1 || got[0].Status != finding.StatusUnknown || got[0].ID != "empty" {
		t.Fatalf("want an unknown finding for an empty result, got %+v", got)
	}
}

func TestChecksRunConcurrently(t *testing.T) {
	// Each check waits until BOTH have started. If the engine ran them
	// serially this would deadlock and hit the timeout.
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	mk := func(id string) *fakeCheck {
		return &fakeCheck{id: id, tier: finding.TierPassive, run: func(ctx context.Context) []finding.Finding {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return passing(id)(ctx)
		}}
	}
	a, b := mk("a"), mk("b")

	go func() {
		<-arrived
		<-arrived
		close(release)
	}()

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{a, b}, engine.Deps{}, engine.Options{CheckTimeout: 2 * time.Second})

	if len(got) != 2 || got[0].Status != finding.StatusPass || got[1].Status != finding.StatusPass {
		t.Fatalf("both checks should pass when run concurrently, got %+v", got)
	}
}

func TestResultOrderFollowsCheckOrder(t *testing.T) {
	delays := []time.Duration{30 * time.Millisecond, 0, 15 * time.Millisecond}
	var checks []engine.Check
	for i, d := range delays {
		id := string(rune('a' + i))
		checks = append(checks, &fakeCheck{id: id, tier: finding.TierPassive, run: func(ctx context.Context) []finding.Finding {
			time.Sleep(d)
			return passing(id)(ctx)
		}})
	}

	got := engine.Run(context.Background(), engine.Target{Domain: "example.com"}, checks, engine.Deps{}, engine.Options{})

	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("results must follow check order for deterministic reports, got %v", ids)
	}
}

// slowCheck declares through engine.Timeouter that it needs more time than the default.
type slowCheck struct {
	*fakeCheck
	want time.Duration
}

func (s slowCheck) Timeout() time.Duration { return s.want }

// deadlineOf runs one check and returns how long its context would last.
func deadlineOf(t *testing.T, c engine.Check, o engine.Options) time.Duration {
	t.Helper()
	got := make(chan time.Duration, 1)
	fc := &fakeCheck{id: "probe", tier: finding.TierPassive, run: func(ctx context.Context) []finding.Finding {
		dl, ok := ctx.Deadline()
		if !ok {
			got <- -1
		} else {
			got <- time.Until(dl)
		}
		return passing("probe")(ctx)
	}}
	if sc, ok := c.(slowCheck); ok {
		sc.fakeCheck = fc
		c = sc
	} else {
		c = fc
	}
	engine.Run(context.Background(), engine.Target{Domain: "example.com"}, []engine.Check{c}, engine.Deps{}, o)
	return <-got
}

func TestTimeouterExtendsTheDefaultTimeout(t *testing.T) {
	// A check that connects many times in series cannot live inside the 10 s default.
	slow := slowCheck{fakeCheck: &fakeCheck{id: "slow", tier: finding.TierPassive}, want: 40 * time.Second}

	if d := deadlineOf(t, slow, engine.Options{}); d < 35*time.Second || d > 40*time.Second {
		t.Fatalf("deadline in %s, want about 40s: the check asked for it through Timeout()", d)
	}
}

func TestTimeouterNeverShortensTheDefault(t *testing.T) {
	short := slowCheck{fakeCheck: &fakeCheck{id: "short", tier: finding.TierPassive}, want: time.Second}

	if d := deadlineOf(t, short, engine.Options{}); d < 9*time.Second {
		t.Fatalf("deadline in %s: a hint below the default must not shorten it", d)
	}
}

func TestExplicitTimeoutOverridesEveryCheck(t *testing.T) {
	slow := slowCheck{fakeCheck: &fakeCheck{id: "slow", tier: finding.TierPassive}, want: 40 * time.Second}

	if d := deadlineOf(t, slow, engine.Options{CheckTimeout: 2 * time.Second}); d > 2*time.Second {
		t.Fatalf("deadline in %s, want at most 2s: the user's --timeout wins over a check's own hint", d)
	}
}

func TestPlainChecksGetTheDefaultTimeout(t *testing.T) {
	plain := &fakeCheck{id: "plain", tier: finding.TierPassive}

	d := deadlineOf(t, plain, engine.Options{})

	if d < 9*time.Second || d > engine.DefaultCheckTimeout {
		t.Fatalf("deadline in %s, want about %s", d, engine.DefaultCheckTimeout)
	}
}
