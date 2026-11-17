package checks_test

import (
	"errors"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	caaPresent = "dns.caa.present"
	caaIssue   = "dns.caa.issue"
	caaIodef   = "dns.caa.iodef"
)

func TestCAA(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		setup  func(f *dnsxtest.Fake)
		want   map[string]finding.Status
	}{
		{
			name:   "no CAA anywhere",
			domain: "example.com",
			setup:  func(f *dnsxtest.Fake) {},
			want:   map[string]finding.Status{caaPresent: finding.StatusWarn},
		},
		{
			name:   "issue restricts issuance",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusPass, caaIssue: finding.StatusPass, caaIodef: finding.StatusInfo},
		},
		{
			name:   "iodef gives CAs a contact",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))
				f.Add(dnsxtest.CAA("example.com", 0, "iodef", "mailto:security@example.com"))
			},
			want: map[string]finding.Status{caaIodef: finding.StatusPass},
		},
		{
			name:   "property tags are case-insensitive",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "ISSUE", "letsencrypt.org"))
			},
			want: map[string]finding.Status{caaIssue: finding.StatusPass},
		},
		{
			name:   "issue with an empty value forbids all issuance",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "issue", ";"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusPass, caaIssue: finding.StatusInfo},
		},
		{
			name:   "only iodef restricts nothing",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "iodef", "mailto:security@example.com"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusPass, caaIssue: finding.StatusWarn},
		},
		{
			name:   "only issuewild still leaves normal issuance open",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "issuewild", "letsencrypt.org"))
			},
			want: map[string]finding.Status{caaIssue: finding.StatusWarn},
		},
		{
			name:   "climbs to the parent when the name has none",
			domain: "www.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusPass, caaIssue: finding.StatusPass},
		},
		{
			name:   "closest CAA RRset wins over the parent's",
			domain: "www.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.CAA("www.example.com", 0, "issue", ";"))
				f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))
			},
			want: map[string]finding.Status{caaIssue: finding.StatusInfo},
		},
		{
			name:   "resolver failure",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.SetError("example.com", dns.TypeCAA, errors.New("timeout"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusUnknown, caaIssue: finding.StatusUnknown, caaIodef: finding.StatusUnknown},
		},
		{
			name:   "SERVFAIL",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.SetRcode("example.com", dns.TypeCAA, dns.RcodeServerFailure)
			},
			want: map[string]finding.Status{caaPresent: finding.StatusUnknown},
		},
		{
			name:   "failure while climbing means we cannot say none exists",
			domain: "www.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.SetError("example.com", dns.TypeCAA, errors.New("timeout"))
			},
			want: map[string]finding.Status{caaPresent: finding.StatusUnknown},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			tt.setup(f)
			got := run(t, checks.CAA{}, f, tt.domain)
			wantStatuses(t, got, tt.want)
		})
	}
}

func TestCAAStopsAtTheOrganisationalDomain(t *testing.T) {
	for domain, want := range map[string][]string{
		"a.b.example.com":    {"a.b.example.com./CAA", "b.example.com./CAA", "example.com./CAA"},
		"a.example.co.uk":    {"a.example.co.uk./CAA", "example.co.uk./CAA"},
		"example.com":        {"example.com./CAA"},
		"www.example.com.br": {"www.example.com.br./CAA", "example.com.br./CAA"},
	} {
		f := dnsxtest.New()
		_ = run(t, checks.CAA{}, f, domain)
		got := f.Queries()
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: queries = %v, want %v (never ask for the TLD or a public suffix)", domain, got, want)
		}
	}
}

func TestCAAStopsClimbingOnceFound(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.CAA("b.example.com", 0, "issue", "letsencrypt.org"))
	_ = run(t, checks.CAA{}, f, "a.b.example.com")
	if got := f.Queries(); len(got) != 2 {
		t.Fatalf("expected 2 queries (a.b, b), got %v", got)
	}
}

func TestCAAReportsWhereTheRecordsWereFound(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.CAA("example.com", 0, "issue", "letsencrypt.org"))
	got := run(t, checks.CAA{}, f, "www.example.com")

	present := get(t, got, caaPresent)
	if !strings.Contains(present.Detail, "example.com") || !strings.Contains(present.Detail, "www.example.com") {
		t.Errorf("an inherited RRset must say where it came from, got %q", present.Detail)
	}
	issue := get(t, got, caaIssue)
	if len(issue.Evidence) != 1 || issue.Evidence[0] != `0 issue "letsencrypt.org"` {
		t.Errorf("evidence should be the record in presentation form, got %v", issue.Evidence)
	}
}
