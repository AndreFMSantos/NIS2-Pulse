package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ntfy"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/smtpprobe"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/watch"
)

// notifier delivers a notification. In production it is an *ntfy.Client.
type notifier interface {
	Send(ctx context.Context, m ntfy.Message) error
}

const (
	minIntervalPassive = time.Hour
	minIntervalActive  = 6 * time.Hour // active checks connect to the servers: be considerate
	urlEnv             = "NIS2_PULSE_NTFY_URL"
	deliveryTimeout    = 30 * time.Second
)

func defaultStateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "nis2-pulse")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "state", "nis2-pulse")
	}
	return filepath.Join(os.TempDir(), "nis2-pulse-state")
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// watch runs scans of one domain and notifies when something gets worse.
//
// Exit codes: 0 ok (also after a clean stop of the loop), 1 a scan could not
// run, a notification could not be delivered, or the state is unusable, 2 usage
// error.
func (a *app) watch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var selectors stringList
	active := fs.Bool("active", false, "also run active checks that connect directly to the target's servers (recommended only with owner consent; interval >= 6h)")
	resolver := fs.String("resolver", dnsx.DefaultResolver, "recursive resolver used for DNS queries (host or host:port)")
	timeout := fs.Duration("timeout", 0, "time limit for every check (default: each check uses its own)")
	noRouting := fs.Bool("no-routing", false, "do not query RIPEstat")
	ehlo := fs.String("ehlo-name", "", "host name announced to mail servers by the STARTTLS check")
	fs.Var(&selectors, "dkim-selector", "DKIM selector to check; repeat or separate with commas (at most 10)")
	var subdomains stringList
	fs.Var(&subdomains, "subdomain", "subdomain whose MX records to examine; repeat or separate with commas (at most 20)")
	interval := fs.Duration("interval", 0, "repeat every interval (at least 1h, 6h with --active); 0 runs once, for cron or a systemd timer")
	stateDir := fs.String("state-dir", "", "where the monitor remembers the last scan (default $XDG_STATE_HOME/nis2-pulse or ~/.local/state/nis2-pulse)")
	urlFile := fs.String("ntfy-url-file", "", "file with the ntfy topic URL (otherwise the environment variable "+urlEnv+"); never pass the URL as an argument")
	lang := fs.String("lang", "pt", "language of the notifications: pt or en")
	notifyResolved := fs.Bool("notify-resolved", false, "also notify when something gets better")
	testNotify := fs.Bool("test-notify", false, "send one test notification and exit")

	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	if len(positional) != 1 {
		a.printf(a.stderr, "nis2-pulse: usage: nis2-pulse watch [flags] <domain>\n")
		return 2
	}
	if n := len(distinct(selectors)); n > checks.MaxDKIMSelectors {
		a.printf(a.stderr, "nis2-pulse: at most %d DKIM selectors, got %d\n", checks.MaxDKIMSelectors, n)
		return 2
	}
	if *ehlo != "" && !smtpprobe.ValidName(*ehlo) {
		a.printf(a.stderr, "nis2-pulse: invalid --ehlo-name %q (letters, digits, dots and hyphens only)\n", *ehlo)
		return 2
	}
	target, err := engine.ParseTarget(positional[0])
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 2
	}
	subs, err := checks.NormalizeSubdomains(target.Domain, subdomains)
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: --subdomain: %v\n", err)
		return 2
	}
	nl := catalog.Lang(strings.ToLower(*lang))
	if nl != catalog.PT && nl != catalog.EN {
		a.printf(a.stderr, "nis2-pulse: unsupported language %q (supported: pt, en)\n", *lang)
		return 2
	}
	minInterval := minIntervalPassive
	if *active {
		minInterval = minIntervalActive
	}
	if *interval < 0 || (*interval > 0 && *interval < minInterval) {
		a.printf(a.stderr, "nis2-pulse: --interval must be 0 (run once) or at least %s\n", minInterval)
		return 2
	}

	n, code := a.openNotifier(*urlFile)
	if code != 0 {
		return code
	}
	if *testNotify {
		if n == nil {
			a.printf(a.stderr, "nis2-pulse: --test-notify needs the ntfy URL (%s or --ntfy-url-file)\n", urlEnv)
			return 2
		}
		ctx, cancel := context.WithTimeout(a.context(), deliveryTimeout)
		defer cancel()
		msg := ntfy.Message{Title: "nis2-pulse: " + target.Domain + ": test", Body: "Test notification. Monitoring of " + target.Domain + " will send alerts here.", Priority: 3, Tags: []string{"white_check_mark"}}
		if err := n.Send(ctx, msg); err != nil {
			a.printf(a.stderr, "nis2-pulse: %v\n", err)
			return 1
		}
		a.printf(a.stdout, "test notification sent\n")
		return 0
	}
	if n == nil {
		a.printf(a.stderr, "nis2-pulse: no ntfy URL configured (%s or --ntfy-url-file): changes are only printed\n", urlEnv)
	}

	dir := *stateDir
	if dir == "" {
		dir = a.stateDirectory()
	}
	w := &watcher{
		app: a, dir: dir, notifier: n, lang: nl, opts: watch.Options{NotifyResolved: *notifyResolved},
		settings: scanSettings{target: target, resolver: *resolver, active: *active, timeout: *timeout, noRouting: *noRouting, ehlo: *ehlo, selectors: selectors, subdomains: subs},
	}
	ctx := a.context()
	for {
		exit, fatal := w.once(ctx)
		if *interval == 0 || fatal {
			return exit
		}
		if err := a.sleepFn(ctx, *interval); err != nil {
			return 0 // cancelled: a clean stop
		}
	}
}

// openNotifier builds the notifier from the file or the environment. A nil
// notifier with code 0 means that none is configured. The URL is never printed.
func (a *app) openNotifier(file string) (notifier, int) {
	url := ""
	if file != "" {
		fi, err := os.Stat(file)
		if err != nil {
			a.printf(a.stderr, "nis2-pulse: cannot read the ntfy URL file: %v\n", errors.Unwrap(err))
			return nil, 2
		}
		if fi.Mode().Perm()&0o077 != 0 {
			a.printf(a.stderr, "nis2-pulse: warning: the ntfy URL file is readable by other users; run chmod 600 on it\n")
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			a.printf(a.stderr, "nis2-pulse: cannot read the ntfy URL file\n")
			return nil, 2
		}
		url = strings.TrimSpace(string(raw))
	} else {
		url = strings.TrimSpace(a.getenvFn()(urlEnv))
	}
	if url == "" {
		return nil, 0
	}
	n, err := a.newNotifierFn()(url)
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return nil, 2
	}
	return n, 0
}

// watcher is the state shared by the cycles of one watch command.
type watcher struct {
	app      *app
	dir      string
	notifier notifier
	lang     catalog.Lang
	opts     watch.Options
	settings scanSettings
}

// once runs one cycle. fatal means that looping would not help (the state file
// is unusable).
func (w *watcher) once(ctx context.Context) (exit int, fatal bool) {
	a := w.app
	domain := w.settings.target.Domain
	stamp := a.now().UTC().Format(time.RFC3339)
	st, err := watch.Load(w.dir, domain)
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 1, true
	}

	res, err := a.collect(ctx, w.settings)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false
		}
		a.printf(a.stderr, "nis2-pulse: %s: %v\n", stamp, err)
		next, alert := watch.RecordFailure(st, domain, a.now())
		if alert {
			if code := w.deliver(ctx, watch.FailureMessage(w.lang, domain, next.ScanFailures)); code != 0 {
				return code, false // keep the old state so that the alert is retried
			}
		}
		if err := watch.Save(w.dir, next); err != nil {
			a.printf(a.stderr, "nis2-pulse: cannot save the state: %v\n", err)
		}
		return 1, false
	}

	next, ch := watch.Compare(st, res, w.opts)
	summary := ""
	switch {
	case ch.Baseline:
		summary = fmt.Sprintf("baseline (%d findings)", len(res.Findings))
	case ch.Alert():
		if code := w.deliver(ctx, watch.Message(w.lang, domain, ch)); code != 0 {
			return code, false // the state stays where it was: the change is notified next time
		}
		summary = fmt.Sprintf("%d worsened, %d without a verdict, %d resolved; notification sent", len(ch.Degraded), len(ch.LostVisibility), len(ch.Improved))
		if w.notifier == nil {
			summary = fmt.Sprintf("%d worsened, %d without a verdict, %d resolved", len(ch.Degraded), len(ch.LostVisibility), len(ch.Improved))
		}
	default:
		summary = fmt.Sprintf("no changes (%d findings", len(res.Findings))
		if len(ch.Improved) > 0 {
			summary += fmt.Sprintf(", %d resolved", len(ch.Improved))
		}
		summary += ")"
	}
	if err := watch.Save(w.dir, next); err != nil {
		a.printf(a.stderr, "nis2-pulse: cannot save the state: %v\n", err)
		return 1, false
	}
	a.printf(a.stdout, "%s %s: %s\n", stamp, domain, summary)
	return 0, false
}

// deliver sends the message, or prints it when no notifier is configured. It
// returns a non-zero exit code if the delivery failed.
func (w *watcher) deliver(ctx context.Context, m watch.Msg) int {
	a := w.app
	if w.notifier == nil {
		a.printf(a.stdout, "%s\n%s\n", m.Title, m.Body)
		return 0
	}
	dctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	if err := w.notifier.Send(dctx, ntfy.Message{Title: m.Title, Body: m.Body, Priority: m.Priority, Tags: m.Tags}); err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 1
	}
	return 0
}
