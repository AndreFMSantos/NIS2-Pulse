package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
)

type scanOutput struct {
	Tool      string `json:"tool"`
	Version   string `json:"version"`
	Target    string `json:"target"`
	ScannedAt string `json:"scanned_at"`
	Resolver  string `json:"resolver"`
	Active    bool   `json:"active"`
	Findings  []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"findings"`
}

// httpAttempts counts requests that reach the HTTP transport used by the app
// under test. dialed records the raw connections requested through the safe
// dialer. A scan test must never touch the real network.
var (
	httpAttempts atomic.Int32
	dialMu       sync.Mutex
	dialed       []string
)

func dialedAddrs() []string {
	dialMu.Lock()
	defer dialMu.Unlock()
	return append([]string(nil), dialed...)
}

var (
	httpURLsMu sync.Mutex
	httpURLs   []string
)

func requestedURLs() []string {
	httpURLsMu.Lock()
	defer httpURLsMu.Unlock()
	return append([]string(nil), httpURLs...)
}

type countingTransport struct{}

func (countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	httpAttempts.Add(1)
	httpURLsMu.Lock()
	httpURLs = append(httpURLs, r.URL.String())
	httpURLsMu.Unlock()
	return nil, errors.New("tests must not use the network")
}

func newTestApp(f *dnsxtest.Fake, gotAddr *string) (*app, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	httpAttempts.Store(0)
	httpURLsMu.Lock()
	httpURLs = nil
	httpURLsMu.Unlock()
	dialMu.Lock()
	dialed = nil
	dialMu.Unlock()
	return &app{
		stdout: &out,
		stderr: &errb,
		now:    func() time.Time { return time.Date(2026, 11, 6, 18, 0, 0, 0, time.UTC) },
		newResolver: func(addr string) dnsx.Resolver {
			if gotAddr != nil {
				*gotAddr = addr
			}
			return f
		},
		newHTTP: func(dnsx.Resolver, time.Duration) *http.Client {
			return &http.Client{Transport: countingTransport{}}
		},
		newDial: func(dnsx.Resolver) func(context.Context, string, string) (net.Conn, error) {
			return func(_ context.Context, _, addr string) (net.Conn, error) {
				dialMu.Lock()
				dialed = append(dialed, addr)
				dialMu.Unlock()
				return nil, errors.New("tests must not use the network")
			}
		},
	}, &out, &errb
}

func healthyFake() *dnsxtest.Fake {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"))
	return f
}

func statusOf(o scanOutput, id string) string {
	for _, f := range o.Findings {
		if f.ID == id {
			return f.Status
		}
	}
	return "<missing>"
}

func TestScanWritesJSON(t *testing.T) {
	a, out, errb := newTestApp(healthyFake(), nil)

	code := a.run([]string{"scan", "Example.COM"})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}

	var got scanOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if got.Tool != "nis2-pulse" || got.Target != "example.com" || got.Active || got.ScannedAt != "2026-11-06T18:00:00Z" {
		t.Errorf("unexpected header: %+v", got)
	}
	if got.Resolver != dnsx.DefaultResolver {
		t.Errorf("resolver = %q, want default %q", got.Resolver, dnsx.DefaultResolver)
	}
	if s := statusOf(got, "email.spf.policy"); s != "pass" {
		t.Errorf("email.spf.policy = %s, want pass", s)
	}
	if s := statusOf(got, "email.dmarc.policy"); s != "pass" {
		t.Errorf("email.dmarc.policy = %s, want pass", s)
	}
}

func findingOf(t *testing.T, out []byte, id string) (status, detail string) {
	t.Helper()
	var got struct {
		Findings []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	for _, f := range got.Findings {
		if f.ID == id {
			return f.Status, f.Detail
		}
	}
	t.Fatalf("finding %q not in output:\n%s", id, out)
	return "", ""
}

func TestScanWithoutActiveSkipsActiveChecksAndStaysOffTheNetwork(t *testing.T) {
	f := healthyFake()
	// The domain publishes everything MTA-STS needs: only --active prevents the fetch.
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
	a, out, errb := newTestApp(f, nil)

	if code := a.run([]string{"scan", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}

	status, detail := findingOf(t, out.Bytes(), "email.mtasts.policy")
	if status != "unknown" || !strings.Contains(detail, "--active") {
		t.Errorf("active check = %s %q, want unknown mentioning --active", status, detail)
	}
	if n := httpAttempts.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were made without --active", n)
	}
	if got := dialedAddrs(); len(got) != 0 {
		t.Fatalf("raw connections were opened without --active: %v", got)
	}
}

func TestScanActiveDoesNotConnectWhenNoPolicyIsPublished(t *testing.T) {
	a, out, errb := newTestApp(healthyFake(), nil) // no MX and no _mta-sts record
	if code := a.run([]string{"scan", "--active", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}

	if status, _ := findingOf(t, out.Bytes(), "email.mtasts.fetch"); status != "info" {
		t.Errorf("email.mtasts.fetch = %s, want info", status)
	}
	// The web check legitimately requests https://example.com/ (one request);
	// what must not happen is a request to the MTA-STS host.
	for _, u := range requestedURLs() {
		if strings.Contains(u, "mta-sts") {
			t.Fatalf("the MTA-STS policy was requested (%s) for a domain without an MTA-STS record", u)
		}
		if u != "https://example.com/" {
			t.Fatalf("unexpected HTTP request %s", u)
		}
	}
}

// With --active the TLS check connects, but only to the domain on port 443,
// and only through the dialer the CLI built.
func TestScanActiveDialsOnlyTheDomainOnPort443(t *testing.T) {
	a, _, errb := newTestApp(healthyFake(), nil)

	if code := a.run([]string{"scan", "--active", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}

	got := dialedAddrs()
	if len(got) == 0 {
		t.Fatal("--active must run the TLS check, which connects to port 443")
	}
	for _, addr := range got {
		if addr != "example.com:443" {
			t.Fatalf("an active check dialled %q; only example.com:443 is allowed", addr)
		}
	}
}

func TestScanActiveBuildsTheHTTPClientFromTheScanResolver(t *testing.T) {
	a, _, errb := newTestApp(healthyFake(), nil)
	var gotResolver dnsx.Resolver
	var gotTimeout time.Duration
	a.newHTTP = func(r dnsx.Resolver, d time.Duration) *http.Client {
		gotResolver, gotTimeout = r, d
		return &http.Client{Transport: countingTransport{}}
	}

	if code := a.run([]string{"scan", "--active", "--timeout", "7s", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}

	if gotResolver == nil || gotTimeout != 7*time.Second {
		t.Fatalf("resolver=%v timeout=%v: the HTTP client must resolve names through the scan's resolver and honour --timeout", gotResolver, gotTimeout)
	}
}

// dkimSelectors returns the selectors reported by email.dkim.key findings, in order.
func dkimSelectors(t *testing.T, out []byte) []string {
	t.Helper()
	var got struct {
		Findings []struct {
			ID       string   `json:"id"`
			Status   string   `json:"status"`
			Evidence []string `json:"evidence"`
			Detail   string   `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	var sels []string
	for _, f := range got.Findings {
		if f.ID == "email.dkim.key" && len(f.Evidence) > 0 {
			sels = append(sels, strings.TrimPrefix(f.Evidence[0], "selector="))
		}
	}
	return sels
}

func TestScanDKIMSelectorFlag(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--dkim-selector", "s1", "--dkim-selector", "s2,s3", "example.com"},
		{"scan", "example.com", "--dkim-selector=s1,s2", "--dkim-selector", "s3"},
		{"scan", "--dkim-selector", " S1 , s2 ,,s3", "--dkim-selector", "s1", "example.com"},
	} {
		a, out, errb := newTestApp(healthyFake(), nil)
		if code := a.run(args); code != 0 {
			t.Fatalf("%v: exit code = %d, stderr = %q", args, code, errb.String())
		}
		if got := strings.Join(dkimSelectors(t, out.Bytes()), ","); got != "s1,s2,s3" {
			t.Errorf("%v: selectors = %q, want s1,s2,s3", args, got)
		}
	}
}

func TestScanWithoutDKIMSelectorIsUnknown(t *testing.T) {
	a, out, _ := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	status, detail := findingOf(t, out.Bytes(), "email.dkim.key")
	if status != "unknown" || !strings.Contains(detail, "--dkim-selector") {
		t.Fatalf("email.dkim.key = %s %q, want unknown mentioning --dkim-selector", status, detail)
	}
}

func TestScanRejectsTooManyDKIMSelectors(t *testing.T) {
	a, out, errb := newTestApp(healthyFake(), nil)
	args := []string{"scan", "--dkim-selector", "a,b,c,d,e,f,g,h,i,j,k", "example.com"}

	if code := a.run(args); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "at most 10") {
		t.Errorf("want a usage error and no output, got out=%q err=%q", out.String(), errb.String())
	}
}

func TestScanRejectsAnUnsafeEHLOName(t *testing.T) {
	for _, name := range []string{"a b", "x\r\nMAIL FROM:<a@b>", "bad/name"} {
		a, out, errb := newTestApp(healthyFake(), nil)
		if code := a.run([]string{"scan", "--ehlo-name", name, "example.com"}); code != 2 {
			t.Fatalf("%q: exit code = %d, want 2", name, code)
		}
		if out.Len() != 0 || !strings.Contains(errb.String(), "ehlo-name") {
			t.Errorf("%q: want a usage error naming the flag, got out=%q err=%q", name, out.String(), errb.String())
		}
	}
}

func TestScanAcceptsAValidEHLOName(t *testing.T) {
	a, _, errb := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "--ehlo-name", "scanner.example.org", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
}

func TestScanBuildsTheSafeDialerFromTheScanResolver(t *testing.T) {
	a, _, errb := newTestApp(healthyFake(), nil)
	var gotResolver dnsx.Resolver
	a.newDial = func(r dnsx.Resolver) func(context.Context, string, string) (net.Conn, error) {
		gotResolver = r
		return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no network in tests") }
	}

	if code := a.run([]string{"scan", "--active", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
	if gotResolver == nil {
		t.Fatal("raw connections must be dialled through a dialer built from the scan's resolver")
	}
}

func TestScanWithoutTimeoutFlagLetsEachCheckUseItsOwn(t *testing.T) {
	a, _, errb := newTestApp(healthyFake(), nil)
	var gotTimeout time.Duration
	a.newHTTP = func(_ dnsx.Resolver, d time.Duration) *http.Client {
		gotTimeout = d
		return &http.Client{Transport: countingTransport{}}
	}

	if code := a.run([]string{"scan", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
	if gotTimeout != engine.DefaultCheckTimeout {
		t.Fatalf("HTTP client timeout = %s, want the default %s when --timeout is not given", gotTimeout, engine.DefaultCheckTimeout)
	}
}

func TestScanAcceptsFlagsInAnyPosition(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--active", "--resolver", "9.9.9.9", "example.com"},
		{"scan", "example.com", "--active", "--resolver", "9.9.9.9"},
		{"scan", "--resolver=9.9.9.9", "example.com", "--active"},
	} {
		var addr string
		a, out, errb := newTestApp(healthyFake(), &addr)
		if code := a.run(args); code != 0 {
			t.Fatalf("%v: exit code = %d, stderr = %q", args, code, errb.String())
		}
		if addr != "9.9.9.9" {
			t.Errorf("%v: resolver factory got %q, want 9.9.9.9", args, addr)
		}
		var got scanOutput
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Active || got.Resolver != "9.9.9.9" {
			t.Errorf("%v: header = %+v", args, got)
		}
	}
}

func TestScanRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"url instead of domain", []string{"scan", "https://example.com"}, "not a bare domain"},
		{"ip address", []string{"scan", "192.0.2.1"}, "IP address"},
		{"extra positional", []string{"scan", "a.example.com", "b.example.com"}, "exactly one domain"},
		{"unknown flag", []string{"scan", "--frobnicate", "example.com"}, "frobnicate"},
		{"unknown format", []string{"scan", "--format", "xml", "example.com"}, "format"},
		{"unknown language", []string{"scan", "--format", "md", "--lang", "fr", "example.com"}, "language"},
		{"unknown language in upper case", []string{"scan", "--format", "md", "--lang", "FR", "example.com"}, "language"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errb := newTestApp(healthyFake(), nil)
			if code := a.run(tt.args); code != 2 {
				t.Fatalf("exit code = %d, want 2 (usage error)", code)
			}
			if out.Len() != 0 {
				t.Errorf("stdout must stay empty on usage errors, got %q", out.String())
			}
			if !strings.Contains(errb.String(), tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", errb.String(), tt.wantErr)
			}
		})
	}
}

func TestScanNonexistentDomain(t *testing.T) {
	f := dnsxtest.New()
	f.SetRcode("nope.example.com", dns.TypeA, dns.RcodeNameError)
	a, out, errb := newTestApp(f, nil)

	if code := a.run([]string{"scan", "nope.example.com"}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "does not exist") {
		t.Errorf("want an NXDOMAIN message on stderr and nothing on stdout, got out=%q err=%q", out.String(), errb.String())
	}
}

func TestScanResolverUnreachable(t *testing.T) {
	f := dnsxtest.New()
	f.SetError("example.com", dns.TypeA, errTest("connection refused"))
	a, out, errb := newTestApp(f, nil)

	if code := a.run([]string{"scan", "example.com"}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "resolver") {
		t.Errorf("want a resolver error on stderr, got out=%q err=%q", out.String(), errb.String())
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

// With --active and an MX record, the only extra connection allowed is port 25
// of the MX host itself.
func TestScanActiveDialsTheMXHostOnPort25AndNothingElse(t *testing.T) {
	f := healthyFake()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	a, _, errb := newTestApp(f, nil)

	if code := a.run([]string{"scan", "--active", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
	allowed := map[string]bool{"example.com:443": true, "mail.example.com:25": true}
	var saw25 bool
	for _, addr := range dialedAddrs() {
		if !allowed[addr] {
			t.Fatalf("an active check dialled %q; allowed: %v", addr, allowed)
		}
		saw25 = saw25 || addr == "mail.example.com:25"
	}
	if !saw25 {
		t.Fatal("the STARTTLS check should have tried the MX host on port 25")
	}
}

func TestScanRoutingFlag(t *testing.T) {
	f := healthyFake()
	f.Add(dnsxtest.A("example.com", "193.0.0.1"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "network-info"):
			_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["3333"],"prefix":"193.0.0.0/21"}}`))
		case strings.Contains(r.URL.Path, "rpki-validation"):
			_, _ = w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok","data":{"located_resources":[{"locations":[{"country":"NL"}]}]}}`))
		}
	}))
	defer srv.Close()

	t.Run("default asks RIPEstat", func(t *testing.T) {
		a, out, errb := newTestApp(f, nil)
		built := 0
		a.newRIPE = func(dnsx.Resolver, time.Duration) *ripestat.Client {
			built++
			return &ripestat.Client{HTTP: srv.Client(), BaseURL: srv.URL}
		}
		if code := a.run([]string{"scan", "example.com"}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		var got scanOutput
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if built != 1 {
			t.Errorf("RIPEstat client built %d times, want 1", built)
		}
		if st := statusOf(got, "routing.rpki.roa"); st != "pass" {
			t.Errorf("routing.rpki.roa = %q, want pass", st)
		}
	})

	t.Run("--no-routing sends nothing", func(t *testing.T) {
		a, out, errb := newTestApp(f, nil)
		a.newRIPE = func(dnsx.Resolver, time.Duration) *ripestat.Client {
			t.Error("--no-routing must not even build the RIPEstat client")
			return nil
		}
		if code := a.run([]string{"scan", "example.com", "--no-routing"}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		var got scanOutput
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"routing.origin", "routing.rpki.roa", "routing.geo"} {
			if st := statusOf(got, id); st != "unknown" {
				t.Errorf("%s = %q, want unknown", id, st)
			}
		}
	})
}

func TestScanMarkdownReport(t *testing.T) {
	a, out, errb := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "example.com", "--format", "md"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{"# Relatório de evidência técnica externa", "`example.com`", "## Resumo por área", "Modo: passivo"} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q:\n%s", want, got)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(got), "{") {
		t.Error("--format md must not print JSON")
	}
}

func TestScanJSONIsStillTheDefault(t *testing.T) {
	a, out, errb := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "example.com"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got scanOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("default output is not JSON: %v", err)
	}
}

func TestScanWithoutNetworkDoesNotStartWhenLanguageIsInvalid(t *testing.T) {
	// A bad --lang must be rejected before any DNS query is made.
	f := healthyFake()
	a, _, _ := newTestApp(f, nil)
	if code := a.run([]string{"scan", "example.com", "--format", "md", "--lang", "fr"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if q := f.Queries(); len(q) != 0 {
		t.Errorf("queries were made before the usage error: %v", q)
	}
}

func TestScanEnglishMarkdownReport(t *testing.T) {
	for _, lang := range []string{"en", "EN"} {
		a, out, errb := newTestApp(healthyFake(), nil)
		if code := a.run([]string{"scan", "example.com", "--format", "md", "--lang", lang}); code != 0 {
			t.Fatalf("--lang %s: exit %d: %s", lang, code, errb.String())
		}
		got := out.String()
		for _, want := range []string{"# External technical evidence report", "## Summary by area", "Mode: passive"} {
			if !strings.Contains(got, want) {
				t.Errorf("--lang %s: report lacks %q:\n%s", lang, want, got)
			}
		}
		if strings.Contains(got, "Relatório") {
			t.Errorf("--lang %s: Portuguese title in the English report", lang)
		}
	}
}

func TestScanPortugueseIsTheDefaultLanguage(t *testing.T) {
	a, out, _ := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "example.com", "--format", "md"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "# Relatório de evidência técnica externa") {
		t.Error("the default report language must stay Portuguese")
	}
}

func TestScanProfileFlagsAreValidatedBeforeAnyNetworkWork(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--entity", "private", "example.pt"},
		{"scan", "--reg2690", "maybe", "example.pt"},
	} {
		a, _, stderr := newTestApp(healthyFake(), nil)
		if code := a.run(args); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if !strings.Contains(stderr.String(), "--entity") && !strings.Contains(stderr.String(), "--reg2690") {
			t.Errorf("%v: the error must name the flag, got %q", args, stderr.String())
		}
	}
}

func TestScanProfileFiltersTheMarkdownLegalReferences(t *testing.T) {
	run := func(args ...string) string {
		a, stdout, _ := newTestApp(healthyFake(), nil)
		if code := a.run(append([]string{"scan", "--format", "md", "--no-routing"}, args...)); code != 0 {
			t.Fatalf("exit %d", code)
		}
		return stdout.String()
	}
	plain := run("example.pt")
	if !strings.Contains(plain, "Sem perfil de entidade") {
		t.Error("a scan without profile must say so in the notes")
	}
	pub := run("--entity", "public", "example.pt")
	if strings.Contains(pub, "anexo III, nível") {
		t.Error("--entity public must hide annex III")
	}
	if !strings.Contains(pub, "entidade pública relevante") {
		t.Error("the profile must be stated in the notes")
	}
}

func TestScanJSONEchoesTheProfileOnlyWhenGiven(t *testing.T) {
	a, stdout, _ := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "--no-routing", "example.pt"}); code != 0 {
		t.Fatal(code)
	}
	if strings.Contains(stdout.String(), `"profile"`) {
		t.Error("no profile given: the JSON must not carry one")
	}
	a, stdout, _ = newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "--no-routing", "--entity", "eei", "--reg2690", "no", "example.pt"}); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(stdout.String(), `"entity": "eei"`) || !strings.Contains(stdout.String(), `"reg2690": "no"`) {
		t.Errorf("the profile must be echoed in the JSON, got:\n%s", stdout.String())
	}
}
