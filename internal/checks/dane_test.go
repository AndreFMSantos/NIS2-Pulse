package checks_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec/dnssectest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	daneTLSA   = "email.dane.tlsa"
	daneParams = "email.dane.params"
	sha256Hex  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func sha512Hex() string { return sha256Hex + sha256Hex }

func tlsaName(host string) string { return "_25._tcp." + host + "." }

// daneWorld is a signed hierarchy pt. > example.pt. serving the given MX hosts.
func daneWorld(t *testing.T, opts dnssectest.Options, hosts ...string) *dnssectest.World {
	t.Helper()
	w := dnssectest.New(t, opts, "pt.", "example.pt.")
	for i, h := range hosts {
		w.Fake.Add(dnsxtest.MX("example.pt", uint16(10*(i+1)), h))
	}
	return w
}

func runDANE(t *testing.T, w *dnssectest.World) []finding.Finding {
	t.Helper()
	c := checks.DANE{Anchors: w.Anchors}
	if c.Tier() != finding.TierPassive {
		t.Fatal("DANE only reads DNS, so it is passive")
	}
	return c.Run(context.Background(), engine.Target{Domain: "example.pt"},
		engine.Deps{DNS: w.Fake, Now: func() time.Time { return w.Now }})
}

func TestDANEStatus(t *testing.T) {
	good := func(host string) dns.RR { return dnsxtest.TLSA(tlsaName(host), 3, 1, 1, sha256Hex) }
	tests := []struct {
		name   string
		opts   dnssectest.Options
		hosts  []string
		setup  func(w *dnssectest.World)
		status finding.Status
		sev    finding.Severity
	}{
		{"no TLSA anywhere: DANE is optional", dnssectest.Options{}, []string{"mail.example.pt"},
			func(*dnssectest.World) {}, finding.StatusInfo, ""},
		{"authenticated TLSA on the only MX", dnssectest.Options{}, []string{"mail.example.pt"},
			func(w *dnssectest.World) { w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail.example.pt")) },
			finding.StatusPass, finding.SeverityMedium},
		{"TLSA on one of two MX hosts", dnssectest.Options{}, []string{"mail.example.pt", "mail2.example.pt"},
			func(w *dnssectest.World) { w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail.example.pt")) },
			finding.StatusWarn, finding.SeverityMedium},
		{"TLSA on both MX hosts", dnssectest.Options{}, []string{"mail.example.pt", "mail2.example.pt"},
			func(w *dnssectest.World) {
				w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail.example.pt"))
				w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail2.example.pt"))
			}, finding.StatusPass, finding.SeverityMedium},
		{"TLSA in an unsigned zone is ignored by senders", dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}},
			[]string{"mail.example.pt"},
			func(w *dnssectest.World) {
				w.Fake.AddFor(tlsaName("mail.example.pt"), dns.TypeTLSA, good("mail.example.pt"))
			},
			finding.StatusWarn, finding.SeverityMedium},
		{"bad signature on the TLSA set: senders defer delivery", dnssectest.Options{}, []string{"mail.example.pt"},
			func(w *dnssectest.World) {
				w.SignRRset(t, "example.pt.", dnssectest.RRsetExpired, good("mail.example.pt"))
			},
			finding.StatusFail, finding.SeverityHigh},
		{"unsigned TLSA set in a signed zone", dnssectest.Options{}, []string{"mail.example.pt"},
			func(w *dnssectest.World) {
				w.SignRRset(t, "example.pt.", dnssectest.RRsetUnsigned, good("mail.example.pt"))
			},
			finding.StatusFail, finding.SeverityHigh},
		{"broken chain with TLSA published", dnssectest.Options{WrongDS: map[string]bool{"example.pt.": true}},
			[]string{"mail.example.pt"},
			func(w *dnssectest.World) { w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail.example.pt")) },
			finding.StatusFail, finding.SeverityHigh},
		{"a bogus host outweighs a good one", dnssectest.Options{}, []string{"mail.example.pt", "mail2.example.pt"},
			func(w *dnssectest.World) {
				w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, good("mail.example.pt"))
				w.SignRRset(t, "example.pt.", dnssectest.RRsetExpired, good("mail2.example.pt"))
			}, finding.StatusFail, finding.SeverityHigh},
		{"query failure is unknown", dnssectest.Options{}, []string{"mail.example.pt"},
			func(w *dnssectest.World) {
				w.Fake.SetRcode(tlsaName("mail.example.pt"), dns.TypeTLSA, dns.RcodeServerFailure)
			},
			finding.StatusUnknown, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := daneWorld(t, tc.opts, tc.hosts...)
			tc.setup(w)
			f := byID(runDANE(t, w), daneTLSA)
			if f == nil {
				t.Fatalf("no %s finding", daneTLSA)
			}
			if f.Status != tc.status || f.Severity != tc.sev {
				t.Fatalf("got %s/%s, want %s/%s (detail %q, evidence %v)", f.Status, f.Severity, tc.status, tc.sev, f.Detail, f.Evidence)
			}
		})
	}
}

func TestDANEWithoutMailIsInfoAndMakesNoTLSAQuery(t *testing.T) {
	w := daneWorld(t, dnssectest.Options{}) // no MX
	fs := runDANE(t, w)
	if f := byID(fs, daneTLSA); f == nil || f.Status != finding.StatusInfo {
		t.Fatalf("got %+v", fs)
	}
	for _, q := range w.Fake.Queries() {
		if strings.Contains(q, "TLSA") {
			t.Fatalf("a domain without mail must not be asked for TLSA: %q", q)
		}
	}
}

func TestDANENullMXIsInfo(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	w.Fake.Add(dnsxtest.MX("example.pt", 0, "."))
	if f := byID(runDANE(t, w), daneTLSA); f == nil || f.Status != finding.StatusInfo {
		t.Fatalf("got %+v", f)
	}
}

func TestDANEMXLookupFailureIsUnknown(t *testing.T) {
	w := daneWorld(t, dnssectest.Options{}, "mail.example.pt")
	w.Fake.SetRcode("example.pt", dns.TypeMX, dns.RcodeServerFailure)
	if f := byID(runDANE(t, w), daneTLSA); f == nil || f.Status != finding.StatusUnknown {
		t.Fatalf("got %+v", f)
	}
}

func TestDANEEvidenceNamesEachHost(t *testing.T) {
	w := daneWorld(t, dnssectest.Options{}, "mail.example.pt", "mail2.example.pt")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), 3, 1, 1, sha256Hex))
	f := byID(runDANE(t, w), daneTLSA)
	joined := strings.Join(f.Evidence, "\n")
	if !strings.Contains(joined, "mail.example.pt") || !strings.Contains(joined, "mail2.example.pt") || !strings.Contains(joined, "3 1 1") {
		t.Fatalf("evidence %q", joined)
	}
}

func TestDANEParams(t *testing.T) {
	rec := func(u, s, m uint8, hex string) dns.RR {
		return dnsxtest.TLSA(tlsaName("mail.example.pt"), u, s, m, hex)
	}
	tests := []struct {
		name   string
		rrs    []dns.RR
		status finding.Status
		sev    finding.Severity
	}{
		{"3 1 1", []dns.RR{rec(3, 1, 1, sha256Hex)}, finding.StatusPass, finding.SeverityLow},
		{"2 1 1", []dns.RR{rec(2, 1, 1, sha256Hex)}, finding.StatusPass, finding.SeverityLow},
		{"3 0 2 with sha-512", []dns.RR{rec(3, 0, 2, sha512Hex())}, finding.StatusPass, finding.SeverityLow},
		{"3 1 0 full key", []dns.RR{rec(3, 1, 0, "3059301306072a8648ce3d0201")}, finding.StatusPass, finding.SeverityLow},
		{"rollover with two good records", []dns.RR{rec(3, 1, 1, sha256Hex), rec(3, 1, 1, strings.Repeat("ab", 32))}, finding.StatusPass, finding.SeverityLow},
		{"PKIX usage next to a good record", []dns.RR{rec(1, 1, 1, sha256Hex), rec(3, 1, 1, sha256Hex)}, finding.StatusWarn, finding.SeverityLow},
		{"only PKIX usages: unusable", []dns.RR{rec(0, 1, 1, sha256Hex), rec(1, 1, 1, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"unknown usage 4", []dns.RR{rec(4, 1, 1, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"unknown usage 9", []dns.RR{rec(9, 1, 1, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"unknown selector 2", []dns.RR{rec(3, 2, 1, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"unknown selector 5", []dns.RR{rec(3, 5, 1, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"unknown matching type", []dns.RR{rec(3, 1, 7, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"sha-256 digest of the wrong length", []dns.RR{rec(3, 1, 1, "abcd")}, finding.StatusFail, finding.SeverityMedium},
		{"sha-512 digest of the wrong length", []dns.RR{rec(3, 1, 2, sha256Hex)}, finding.StatusFail, finding.SeverityMedium},
		{"empty data", []dns.RR{rec(3, 1, 0, "")}, finding.StatusFail, finding.SeverityMedium},
		{"one bad record among good ones", []dns.RR{rec(3, 1, 1, sha256Hex), rec(3, 1, 1, "abcd")}, finding.StatusWarn, finding.SeverityLow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := daneWorld(t, dnssectest.Options{}, "mail.example.pt")
			w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tc.rrs...)
			f := byID(runDANE(t, w), daneParams)
			if f == nil {
				t.Fatalf("no %s finding", daneParams)
			}
			if f.Status != tc.status || f.Severity != tc.sev {
				t.Fatalf("got %s/%s, want %s/%s (detail %q)", f.Status, f.Severity, tc.status, tc.sev, f.Detail)
			}
		})
	}
}

func TestDANEParamsOnlyJudgedWhenAuthenticated(t *testing.T) {
	// Parameters of records that senders ignore are not worth a verdict.
	w := daneWorld(t, dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}}, "mail.example.pt")
	w.Fake.AddFor(tlsaName("mail.example.pt"), dns.TypeTLSA, dnsxtest.TLSA(tlsaName("mail.example.pt"), 9, 9, 9, "zz"))
	if f := byID(runDANE(t, w), daneParams); f != nil {
		t.Fatalf("unexpected %+v", f)
	}
}

func TestDANEIsRegistered(t *testing.T) {
	for _, c := range checks.Default(checks.Options{}) {
		if _, ok := c.(checks.DANE); ok {
			return
		}
	}
	t.Fatal("DANE is not in checks.Default")
}

func TestDANEParamsExplainPKIXUsages(t *testing.T) {
	for _, usage := range []uint8{0, 1} {
		w := daneWorld(t, dnssectest.Options{}, "mail.example.pt")
		w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, dnsxtest.TLSA(tlsaName("mail.example.pt"), usage, 1, 1, sha256Hex))
		f := byID(runDANE(t, w), daneParams)
		if !strings.Contains(strings.Join(f.Evidence, " "), "PKIX") {
			t.Fatalf("usage %d: evidence %v should explain that PKIX usages are not for SMTP", usage, f.Evidence)
		}
	}
}

func TestDANEExaminesAtMostTenHostsAndListsEachOnce(t *testing.T) {
	var hosts []string
	for i := 0; i < 12; i++ {
		hosts = append(hosts, fmt.Sprintf("mx%02d.example.pt", i))
	}
	hosts = append(hosts, "mx00.example.pt") // a duplicate MX host
	w := daneWorld(t, dnssectest.Options{}, hosts...)
	f := byID(runDANE(t, w), daneTLSA)
	tlsaQueries := 0
	for _, q := range w.Fake.Queries() {
		if strings.Contains(q, "/TLSA") {
			tlsaQueries++
		}
	}
	if tlsaQueries != 10 {
		t.Fatalf("%d TLSA queries, want 10 (cap, and no duplicate host)", tlsaQueries)
	}
	last := f.Evidence[len(f.Evidence)-1]
	if !strings.Contains(last, "first 10") {
		t.Fatalf("the cap must be reported: %q", last)
	}
	if got := strings.Count(strings.Join(f.Evidence, "\n"), "mx00.example.pt:"); got != 1 {
		t.Fatalf("mx00 listed %d times", got)
	}
}

func TestDANEEvidenceCountsIdenticalRecordsInsteadOfRepeatingThem(t *testing.T) {
	w := daneWorld(t, dnssectest.Options{}, "mail.example.pt")
	var rrs []dns.RR
	for i := 0; i < 3; i++ {
		rrs = append(rrs, dnsxtest.TLSA(tlsaName("mail.example.pt"), 3, 1, 1, strings.Repeat(fmt.Sprintf("%02x", i+1), 32)))
	}
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, rrs...)
	fs := runDANE(t, w)
	for _, id := range []string{daneTLSA, daneParams} {
		f := byID(fs, id)
		if joined := strings.Join(f.Evidence, "\n"); !strings.Contains(joined, "3 1 1 x3") || strings.Count(joined, "3 1 1") != 1 {
			t.Fatalf("%s evidence %q", id, joined)
		}
	}
}
