package checks_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
)

// fakeRIPE answers RIPEstat data calls from tables and records every request.
type fakeRIPE struct {
	mu       sync.Mutex
	networks map[string]string // ip -> network-info "data"
	rpki     map[string]string // "AS<n>|<prefix>" -> rpki state
	geo      map[string]string // ip -> country
	fail     map[string]bool   // data call name -> answer HTTP 500
	requests []string
}

func newFakeRIPE() *fakeRIPE {
	return &fakeRIPE{networks: map[string]string{}, rpki: map[string]string{}, geo: map[string]string{}, fail: map[string]bool{}}
}

func (f *fakeRIPE) client(t *testing.T) *ripestat.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.URL.RequestURI())
		call := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/data/"), "/data.json")
		if f.fail[call] {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		q := r.URL.Query()
		switch call {
		case "network-info":
			data, ok := f.networks[q.Get("resource")]
			if !ok {
				data = `{"asns":[],"prefix":""}`
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","data":%s}`, data)
		case "rpki-validation":
			st, ok := f.rpki[q.Get("resource")+"|"+q.Get("prefix")]
			if !ok {
				st = "unknown"
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","data":{"status":%q,"validating_roas":[]}}`, st)
		case "maxmind-geo-lite":
			cc := f.geo[q.Get("resource")]
			loc := "[]"
			if cc != "" {
				loc = fmt.Sprintf(`[{"country":%q}]`, cc)
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","data":{"located_resources":[{"locations":%s}]}}`, loc)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &ripestat.Client{HTTP: srv.Client(), BaseURL: srv.URL}
}

func (f *fakeRIPE) count(call string) int {
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, "/data/"+call+"/") {
			n++
		}
	}
	return n
}

func (f *fakeRIPE) announce(ip, prefix string, asns ...string) {
	quoted := make([]string, len(asns))
	for i, a := range asns {
		quoted[i] = `"` + a + `"`
	}
	f.networks[ip] = fmt.Sprintf(`{"asns":[%s],"prefix":%q}`, strings.Join(quoted, ","), prefix)
}

func runRouting(t *testing.T, dns *dnsxtest.Fake, rc *ripestat.Client) []finding.Finding {
	t.Helper()
	return checks.Routing{}.Run(context.Background(), engine.Target{Domain: "example.pt"}, engine.Deps{DNS: dns, RIPE: rc})
}

func TestRoutingMetadata(t *testing.T) {
	r := checks.Routing{}
	if r.Area() != finding.AreaRouting || r.Tier() != finding.TierPassive {
		t.Fatalf("area/tier = %s/%s, want routing/passive", r.Area(), r.Tier())
	}
	if r.Timeout() <= engine.DefaultCheckTimeout {
		t.Errorf("Timeout() = %s: the check makes many sequential calls and needs more than the default", r.Timeout())
	}
}

func TestRoutingAllValid(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	d.Add(dnsxtest.AAAA("example.pt", "2001:67c:2e8::1"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.announce("2001:67c:2e8::1", "2001:67c:2e8::/48", "3333")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.rpki["AS3333|2001:67c:2e8::/48"] = "valid"
	r.geo["193.0.0.1"] = "NL"
	r.geo["2001:67c:2e8::1"] = "NL"

	fs := runRouting(t, d, r.client(t))
	wantStatuses(t, fs, map[string]finding.Status{
		"routing.origin":   finding.StatusInfo,
		"routing.rpki.roa": finding.StatusPass,
		"routing.geo":      finding.StatusInfo,
	})
	origin := get(t, fs, "routing.origin")
	if !containsEvidence(origin.Evidence, "193.0.0.1", "AS3333", "193.0.0.0/21") {
		t.Errorf("origin evidence lacks address, ASN and prefix: %v", origin.Evidence)
	}
	if !containsEvidence(get(t, fs, "routing.geo").Evidence, "193.0.0.1", "NL") {
		t.Errorf("geo evidence = %v", get(t, fs, "routing.geo").Evidence)
	}
}

func containsEvidence(ev []string, parts ...string) bool {
	for _, line := range ev {
		ok := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestRoutingInvalidROAIsAHighFailureForTheProvider(t *testing.T) {
	for _, state := range []string{"invalid_asn", "invalid_length"} {
		d := dnsxtest.New()
		d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
		r := newFakeRIPE()
		r.announce("193.0.0.1", "193.0.0.0/21", "3333")
		r.rpki["AS3333|193.0.0.0/21"] = state

		f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa")
		if f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh || f.Fixer != finding.FixerProvider {
			t.Errorf("%s: got %s/%s/%s, want fail/high/provider", state, f.Status, f.Severity, f.Fixer)
		}
		if !containsEvidence(f.Evidence, "AS3333", "193.0.0.0/21", state) {
			t.Errorf("%s: evidence = %v", state, f.Evidence)
		}
	}
}

func TestRoutingNoROAIsAnInformativeWarning(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333") // no rpki entry: RIPEstat answers "unknown"

	f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa")
	if f.Status != finding.StatusWarn || f.Severity != finding.SeverityLow || f.Fixer != finding.FixerProvider {
		t.Errorf("got %s/%s/%s, want warn/low/provider", f.Status, f.Severity, f.Fixer)
	}
}

func TestRoutingWorstResultWins(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	d.Add(dnsxtest.A("example.pt", "198.51.100.0")) // not public, must be ignored
	d.Add(dnsxtest.A("example.pt", "8.8.8.8"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.announce("8.8.8.8", "8.8.8.0/24", "15169")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.rpki["AS15169|8.8.8.0/24"] = "invalid_asn"

	if f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa"); f.Status != finding.StatusFail {
		t.Fatalf("status = %s, want fail (one invalid among valid ones)", f.Status)
	}
}

func TestRoutingMultiOriginPrefixChecksEveryOrigin(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333", "64496")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.rpki["AS64496|193.0.0.0/21"] = "invalid_asn"

	f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa")
	if f.Status != finding.StatusFail {
		t.Fatalf("status = %s, want fail: the second origin is invalid", f.Status)
	}
	if got := r.count("rpki-validation"); got != 2 {
		t.Errorf("rpki calls = %d, want 2 (one per origin)", got)
	}
}

func TestRoutingSamePrefixIsValidatedOnce(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	d.Add(dnsxtest.A("example.pt", "193.0.0.2"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.announce("193.0.0.2", "193.0.0.0/21", "3333")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"

	runRouting(t, d, r.client(t))
	if got := r.count("rpki-validation"); got != 1 {
		t.Errorf("rpki calls = %d, want 1 for two addresses in one prefix", got)
	}
}

func TestRoutingNeverSendsNonPublicAddressesToRIPE(t *testing.T) {
	d := dnsxtest.New()
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "192.168.1.5", "169.254.169.254", "100.64.0.1"} {
		d.Add(dnsxtest.A("example.pt", ip))
	}
	d.Add(dnsxtest.AAAA("example.pt", "fd00::1"))
	r := newFakeRIPE()

	fs := runRouting(t, d, r.client(t))
	if len(r.requests) != 0 {
		t.Fatalf("non-public addresses reached a third party: %v", r.requests)
	}
	wantStatuses(t, fs, map[string]finding.Status{
		"routing.origin": finding.StatusUnknown, "routing.rpki.roa": finding.StatusUnknown, "routing.geo": finding.StatusUnknown,
	})
}

func TestRoutingNoAddressesIsUnknown(t *testing.T) {
	r := newFakeRIPE()
	fs := runRouting(t, dnsxtest.New(), r.client(t))
	for _, id := range []string{"routing.origin", "routing.rpki.roa", "routing.geo"} {
		if f := get(t, fs, id); f.Status != finding.StatusUnknown || f.Detail == "" {
			t.Errorf("%s = %s (%q), want unknown with a reason", id, f.Status, f.Detail)
		}
	}
}

func TestRoutingWithoutRIPEClientIsUnknown(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	fs := runRouting(t, d, nil)
	for _, id := range []string{"routing.origin", "routing.rpki.roa", "routing.geo"} {
		if f := get(t, fs, id); f.Status != finding.StatusUnknown {
			t.Errorf("%s = %s, want unknown", id, f.Status)
		}
	}
}

func TestRoutingRIPEFailureNeverProducesAPass(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.fail["rpki-validation"] = true

	f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa")
	if f.Status != finding.StatusUnknown {
		t.Fatalf("status = %s, want unknown when the RPKI call fails", f.Status)
	}
}

func TestRoutingPartialFailureDoesNotHideTheGoodNewsAsPass(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	d.Add(dnsxtest.A("example.pt", "8.8.8.8")) // the second address has no network-info answer
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.networks["8.8.8.8"] = `{"asns":["15169"],"prefix":"not-a-prefix"}` // malformed: that lookup fails

	f := get(t, runRouting(t, d, r.client(t)), "routing.rpki.roa")
	if f.Status == finding.StatusPass {
		t.Fatalf("an incomplete check must not pass: %+v", f)
	}
}

func TestRoutingUnannouncedAddress(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "5.5.5.5"))
	r := newFakeRIPE() // network-info answers an empty announcement

	fs := runRouting(t, d, r.client(t))
	origin := get(t, fs, "routing.origin")
	if origin.Status != finding.StatusInfo || !containsEvidence(origin.Evidence, "5.5.5.5", "not announced") {
		t.Errorf("origin = %s %v", origin.Status, origin.Evidence)
	}
	if f := get(t, fs, "routing.rpki.roa"); f.Status != finding.StatusUnknown {
		t.Errorf("rpki = %s, want unknown: there is no announcement to validate", f.Status)
	}
}

func TestRoutingIncludesMailHostsAndCapsAddresses(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	d.Add(dnsxtest.MX("example.pt", 10, "mail.example.pt"))
	d.Add(dnsxtest.A("mail.example.pt", "8.8.4.4"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.announce("8.8.4.4", "8.8.4.0/24", "15169")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"
	r.rpki["AS15169|8.8.4.0/24"] = "valid"

	fs := runRouting(t, d, r.client(t))
	if !containsEvidence(get(t, fs, "routing.origin").Evidence, "8.8.4.4", "AS15169") {
		t.Errorf("the MX host's address is missing: %v", get(t, fs, "routing.origin").Evidence)
	}

	// Cap: 30 addresses on the domain, at most checks.MaxRoutingAddresses reach RIPE.
	d2 := dnsxtest.New()
	for i := 1; i <= 30; i++ {
		d2.Add(dnsxtest.A("example.pt", fmt.Sprintf("193.0.%d.1", i)))
	}
	r2 := newFakeRIPE()
	f2 := runRouting(t, d2, r2.client(t))
	if got := r2.count("network-info"); got != checks.MaxRoutingAddresses {
		t.Errorf("network-info calls = %d, want %d", got, checks.MaxRoutingAddresses)
	}
	if !strings.Contains(get(t, f2, "routing.origin").Detail, "limited") {
		t.Errorf("the truncation must be disclosed, detail = %q", get(t, f2, "routing.origin").Detail)
	}
}

func TestRoutingGeoIsInformativeAndAcceptsMissingLocation(t *testing.T) {
	d := dnsxtest.New()
	d.Add(dnsxtest.A("example.pt", "193.0.0.1"))
	r := newFakeRIPE()
	r.announce("193.0.0.1", "193.0.0.0/21", "3333")
	r.rpki["AS3333|193.0.0.0/21"] = "valid"

	f := get(t, runRouting(t, d, r.client(t)), "routing.geo")
	if f.Status != finding.StatusInfo || !containsEvidence(f.Evidence, "193.0.0.1", "no location") {
		t.Errorf("geo = %s %v", f.Status, f.Evidence)
	}
}
