// Command nis2-pulse is an external network-surface and cryptographic
// hygiene auditor for domains in scope of the EU NIS2 Directive.
//
// It produces evidence related to technical security measures; it is NOT
// an audit or a certification of NIS2 / Decreto-Lei 125/2025 compliance.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ntfy"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safehttp"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/smtpprobe"
)

// Version is overridden at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := newApp(os.Stdout, os.Stderr)
	a.ctx = ctx
	code := a.run(os.Args[1:])
	stop()
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	return newApp(stdout, stderr).run(args)
}

// app holds the collaborators of the CLI so tests can replace the resolver
// and the clock.
type app struct {
	// ctx is cancelled on SIGINT/SIGTERM; nil means context.Background().
	ctx            context.Context
	stdout, stderr io.Writer
	now            func() time.Time
	newResolver    func(addr string) dnsx.Resolver
	// newHTTP builds the client active checks use. It must come from safehttp
	// in production: checks never create their own HTTP clients.
	newHTTP func(r dnsx.Resolver, timeout time.Duration) *http.Client
	// newDial builds the raw TCP dial function for active checks that speak
	// their own protocol. In production it must come from safenet.
	newDial func(r dnsx.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error)
	// newRIPE builds the RIPEstat client of the routing check. In production
	// it wraps a safehttp client. Nil means no routing data.
	newRIPE func(r dnsx.Resolver, timeout time.Duration) *ripestat.Client

	// The collaborators of the watch command; nil means the production default.
	stateDir    func() string
	getenv      func(string) string
	newNotifier func(url string) (notifier, error)
	sleep       func(ctx context.Context, d time.Duration) error
}

func (a *app) stateDirectory() string {
	if a.stateDir != nil {
		return a.stateDir()
	}
	return defaultStateDir()
}

func (a *app) getenvFn() func(string) string {
	if a.getenv != nil {
		return a.getenv
	}
	return os.Getenv
}

func (a *app) newNotifierFn() func(string) (notifier, error) {
	if a.newNotifier != nil {
		return a.newNotifier
	}
	return func(url string) (notifier, error) { return ntfy.New(url) }
}

func (a *app) sleepFn(ctx context.Context, d time.Duration) error {
	if a.sleep != nil {
		return a.sleep(ctx, d)
	}
	return sleepContext(ctx, d)
}

func newApp(stdout, stderr io.Writer) *app {
	return &app{
		stdout: stdout,
		stderr: stderr,
		now:    time.Now,
		newResolver: func(addr string) dnsx.Resolver {
			return dnsx.NewClient(addr)
		},
		newHTTP: func(r dnsx.Resolver, timeout time.Duration) *http.Client {
			return safehttp.New(safehttp.Options{Resolver: r, Timeout: timeout})
		},
		newDial: func(r dnsx.Resolver) func(context.Context, string, string) (net.Conn, error) {
			return (&safenet.Dialer{Resolver: r}).DialContext
		},
		newRIPE: func(r dnsx.Resolver, timeout time.Duration) *ripestat.Client {
			return &ripestat.Client{HTTP: safehttp.New(safehttp.Options{Resolver: r, Timeout: timeout})}
		},
	}
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		a.usage()
		return 2
	}
	switch args[0] {
	case "version":
		a.printf(a.stdout, "nis2-pulse %s\n", Version)
		return 0
	case "scan":
		return a.scan(args[1:])
	case "watch":
		return a.watch(args[1:])
	case "suppliers":
		return a.suppliers(args[1:])
	default:
		a.printf(a.stderr, "nis2-pulse: unknown command %q\n", args[0])
		a.usage()
		return 2
	}
}

// Exit codes: 0 scan completed (findings never change the exit code in this
// version), 1 runtime failure (resolver unreachable, domain does not exist),
// 2 usage error.
func (a *app) scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	active := fs.Bool("active", false, "also run checks that connect directly to the target's servers (recommended only with owner consent)")
	resolver := fs.String("resolver", dnsx.DefaultResolver, "recursive resolver used for DNS queries (host or host:port)")
	format := fs.String("format", "json", "output format: json, or md for the human report")
	lang := fs.String("lang", "pt", "report language for --format md: pt or en")
	timeout := fs.Duration("timeout", 0, "time limit for every check (default: each check uses its own, normally 10s)")
	noRouting := fs.Bool("no-routing", false, "do not query RIPEstat (a third party) for ASN, RPKI and geolocation of the domain's public addresses")
	ehlo := fs.String("ehlo-name", "", "host name announced to mail servers by the STARTTLS check (default "+checks.DefaultEHLOName+")")
	entity := fs.String("entity", "", "kind of entity, to choose the legal references shown: eei (essential or important entity, annex III) or public (public relevant entity, annex IV); empty shows all")
	reg2690 := fs.String("reg2690", "", "whether Implementing Regulation (EU) 2024/2690 covers the entity directly: yes or no; empty shows it with its own caveat")
	var selectors stringList
	fs.Var(&selectors, "dkim-selector", "DKIM selector to check; repeat the flag or separate with commas (at most 10)")
	var subdomains stringList
	fs.Var(&subdomains, "subdomain", "subdomain whose MX records to examine (relative like blog, or full); repeat or separate with commas (at most 20)")

	// The flag package stops at the first non-flag argument; loop so that
	// flags may also follow the domain ("scan example.pt --active").
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

	switch len(positional) {
	case 0:
		a.printf(a.stderr, "nis2-pulse: missing domain (usage: nis2-pulse scan [flags] <domain>)\n")
		return 2
	case 1:
	default:
		a.printf(a.stderr, "nis2-pulse: expected exactly one domain, got %d\n", len(positional))
		return 2
	}
	if *ehlo != "" && !smtpprobe.ValidName(*ehlo) {
		a.printf(a.stderr, "nis2-pulse: invalid --ehlo-name %q (letters, digits, dots and hyphens only)\n", *ehlo)
		return 2
	}
	if *format != "json" && *format != "md" {
		a.printf(a.stderr, "nis2-pulse: unsupported format %q (supported: json, md)\n", *format)
		return 2
	}
	reportLang := catalog.Lang(strings.ToLower(*lang))
	if *format == "md" {
		switch reportLang {
		case catalog.PT, catalog.EN:
		default:
			a.printf(a.stderr, "nis2-pulse: unsupported report language %q (supported: pt, en)\n", *lang)
			return 2
		}
	}

	profile, err := catalog.ParseProfile(*entity, *reg2690)
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 2
	}

	if n := len(distinct(selectors)); n > checks.MaxDKIMSelectors {
		a.printf(a.stderr, "nis2-pulse: at most %d DKIM selectors per scan, got %d\n", checks.MaxDKIMSelectors, n)
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

	result, err := a.collect(a.context(), scanSettings{
		target: target, resolver: *resolver, active: *active, timeout: *timeout,
		noRouting: *noRouting, ehlo: *ehlo, selectors: selectors, subdomains: subs,
	})
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 1
	}
	if !profile.IsZero() {
		result.Profile = &profile
	}
	if *format == "md" {
		err = report.WriteMarkdown(a.stdout, result, reportLang)
	} else {
		err = report.WriteJSON(a.stdout, result)
	}
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: writing report: %v\n", err)
		return 1
	}
	return 0
}

// scanSettings is everything one scan needs, whether it comes from `scan` or `watch`.
type scanSettings struct {
	target    engine.Target
	resolver  string
	active    bool
	timeout   time.Duration
	noRouting bool
	ehlo      string
	selectors []string
	// subdomains are already normalised (checks.NormalizeSubdomains).
	subdomains []string
}

// collect runs one scan and returns its result. The error text is meant for the
// user: a resolver that cannot be reached, or a domain that does not exist.
func (a *app) collect(ctx context.Context, s scanSettings) (report.Result, error) {
	res := a.newResolver(s.resolver)

	// Pre-flight: fail fast with a clear message instead of a report where
	// every check is "unknown". Only NXDOMAIN aborts; SERVFAIL is allowed
	// through because a validating resolver also answers SERVFAIL for
	// domains with a broken DNSSEC chain, which is exactly what we must report.
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	resp, err := res.Query(pctx, s.target.Domain, dns.TypeA)
	cancel()
	if err != nil {
		return report.Result{}, fmt.Errorf("cannot query resolver %s: %v", s.resolver, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return report.Result{}, fmt.Errorf("domain %s does not exist (NXDOMAIN)", s.target.Domain)
	}

	httpTimeout := s.timeout
	if httpTimeout <= 0 {
		httpTimeout = engine.DefaultCheckTimeout
	}
	deps := engine.Deps{DNS: res, HTTP: a.newHTTP(res, httpTimeout), Dial: a.newDial(res), Now: a.now}
	if !s.noRouting && a.newRIPE != nil {
		deps.RIPE = a.newRIPE(res, httpTimeout)
	}
	findings := engine.Run(ctx, s.target, checks.Default(checks.Options{DKIMSelectors: s.selectors, EHLOName: s.ehlo, Subdomains: s.subdomains}), deps,
		engine.Options{Active: s.active, CheckTimeout: s.timeout})
	return report.Result{
		Tool:      "nis2-pulse",
		Version:   Version,
		Target:    s.target.Domain,
		ScannedAt: a.now().UTC(),
		Resolver:  s.resolver,
		Active:    s.active,
		Findings:  findings,
	}, nil
}

// context returns the context of the run (cancelled by SIGINT/SIGTERM in production).
func (a *app) context() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

// stringList is a flag.Value that collects repeated and comma-separated values.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		*s = append(*s, strings.TrimSpace(part))
	}
	return nil
}

// distinct returns the non-empty values of in, lowercased and without repeats.
func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (a *app) usage() {
	a.printf(a.stderr, "Usage:\n  nis2-pulse scan [flags] <domain>\n  nis2-pulse watch [flags] <domain>\n  nis2-pulse suppliers [flags] <file>\n  nis2-pulse version\n")
}

// printf writes to a CLI output stream. A failed write to stdout/stderr has
// no useful recovery, so the error is discarded deliberately.
func (a *app) printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// dnsxDefault is the default resolver address, shared by every command.
func dnsxDefault() string { return dnsx.DefaultResolver }
