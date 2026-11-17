package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

const (
	maxSuppliers       = 50
	defaultSupplierJob = 3
	maxSupplierJobs    = 8
)

// supplierEntry is one line of the supplier list.
type supplierEntry struct {
	Domain string
	Name   string
}

// parseSupplierList reads one supplier per line, "domain" or "domain;name". Blank lines and lines that
// start with # are ignored; repeated domains keep the first. Every line is validated like a scan target.
func parseSupplierList(r io.Reader) ([]supplierEntry, error) {
	var out []supplierEntry
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain, name, _ := strings.Cut(line, ";")
		target, err := engine.ParseTarget(domain)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		if seen[target.Domain] {
			continue
		}
		seen[target.Domain] = true
		out = append(out, supplierEntry{Domain: target.Domain, Name: strings.TrimSpace(name)})
		if len(out) > maxSuppliers {
			return nil, fmt.Errorf("line %d: at most %d suppliers per run", n, maxSuppliers)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the supplier list has no domains")
	}
	return out, nil
}

// suppliers scans every domain of a list passively and prints one comparative report.
// There is deliberately no --active: the checks that connect to a server need the owner's permission.
func (a *app) suppliers(args []string) int {
	fs := flag.NewFlagSet("suppliers", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	resolver := fs.String("resolver", dnsxDefault(), "recursive resolver used for DNS queries (host or host:port)")
	format := fs.String("format", "md", "output format: md for the human report, or json")
	lang := fs.String("lang", "pt", "report language for --format md: pt or en")
	timeout := fs.Duration("timeout", 0, "time limit for every check (default: each check uses its own, normally 10s)")
	noRouting := fs.Bool("no-routing", false, "do not query RIPEstat (a third party) for ASN, RPKI and geolocation of the suppliers' public addresses")
	jobs := fs.Int("concurrency", defaultSupplierJob, fmt.Sprintf("suppliers scanned at the same time (1 to %d)", maxSupplierJobs))

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
		a.printf(a.stderr, "nis2-pulse: usage: nis2-pulse suppliers [flags] <file with one domain per line, or domain;name>\n")
		return 2
	}
	if *format != "md" && *format != "json" {
		a.printf(a.stderr, "nis2-pulse: unsupported format %q (supported: md, json)\n", *format)
		return 2
	}
	reportLang := catalog.Lang(strings.ToLower(*lang))
	if reportLang != catalog.PT && reportLang != catalog.EN {
		a.printf(a.stderr, "nis2-pulse: unsupported report language %q (supported: pt, en)\n", *lang)
		return 2
	}
	if *jobs < 1 || *jobs > maxSupplierJobs {
		a.printf(a.stderr, "nis2-pulse: --concurrency must be between 1 and %d\n", maxSupplierJobs)
		return 2
	}
	f, err := os.Open(positional[0])
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %v\n", err)
		return 2
	}
	defer func() { _ = f.Close() }()
	entries, err := parseSupplierList(f)
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: %s: %v\n", positional[0], err)
		return 2
	}

	ctx := a.context()
	results := make([]report.Supplier, len(entries))
	var ok int
	var okMu sync.Mutex
	sem := make(chan struct{}, *jobs)
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			target, _ := engine.ParseTarget(e.Domain) // validated by parseSupplierList
			res, err := a.collect(ctx, scanSettings{target: target, resolver: *resolver, timeout: *timeout, noRouting: *noRouting})
			if err != nil {
				results[i] = report.FailedSupplier(e.Name, e.Domain, err.Error())
				return
			}
			results[i] = report.NewSupplier(e.Name, res)
			okMu.Lock()
			ok++
			okMu.Unlock()
		}()
	}
	wg.Wait()

	if ok == 0 {
		a.printf(a.stderr, "nis2-pulse: no supplier could be scanned: %s\n", results[0].Error)
		return 1
	}
	out := report.SuppliersResult{
		Tool: "nis2-pulse", Version: Version, ScannedAt: a.now().UTC(), Resolver: *resolver, Suppliers: results,
	}
	if *format == "md" {
		err = report.WriteSuppliersMarkdown(a.stdout, out, reportLang)
	} else {
		err = report.WriteSuppliersJSON(a.stdout, out)
	}
	if err != nil {
		a.printf(a.stderr, "nis2-pulse: writing report: %v\n", err)
		return 1
	}
	return 0
}
