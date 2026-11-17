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
	dmPresent   = "email.dmarc.present"
	dmPolicy    = "email.dmarc.policy"
	dmEnforce   = "email.dmarc.enforcement"
	dmReporting = "email.dmarc.reporting"
)

func TestDMARC(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		setup  func(f *dnsxtest.Fake)
		want   map[string]finding.Status
	}{
		{
			name:   "no record at the domain or the organisational domain",
			domain: "example.com",
			setup:  func(f *dnsxtest.Fake) {},
			want:   map[string]finding.Status{dmPresent: finding.StatusFail},
		},
		{
			name:   "full reject policy with reporting",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass, dmEnforce: finding.StatusPass, dmReporting: finding.StatusPass},
		},
		{
			name:   "monitoring-only policy",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusWarn},
		},
		{
			name:   "quarantine counts as enforcing",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=quarantine; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass},
		},
		{
			name:   "test mode (t=y) is a warning: the policy is not fully applied",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; t=y; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass, dmEnforce: finding.StatusWarn},
		},
		{
			name:   "t=n is the default and passes",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; t=n; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmEnforce: finding.StatusPass},
		},
		{
			name:   "partial pct is a warning",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass, dmEnforce: finding.StatusWarn},
		},
		{
			name:   "invalid pct is a warning",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=abc; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmEnforce: finding.StatusWarn},
		},
		{
			name:   "missing rua",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass, dmReporting: finding.StatusWarn},
		},
		{
			name:   "missing p tag",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusFail},
		},
		{
			name:   "invalid p value",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=banana"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusFail},
		},
		{
			name:   "multiple DMARC records",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=none"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusFail},
		},
		{
			name:   "TXT that is not DMARC is ignored",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "something else"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusFail},
		},
		{
			name:   "record may start with whitespace and mixed case version tag value",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", " v=DMARC1 ; p=Reject ; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass},
		},
		{
			name:   "subdomain inherits the organisational domain record",
			domain: "mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass},
		},
		{
			name:   "sp overrides p for an inheriting subdomain",
			domain: "mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusWarn},
		},
		{
			name:   "sp is ignored at the organisational domain itself",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass},
		},
		{
			name:   "organisational domain uses the public suffix list",
			domain: "a.b.example.co.uk",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.co.uk", "v=DMARC1; p=reject; rua=mailto:d@example.co.uk"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass},
		},
		{
			name:   "tree walk: the closest record without psd is found above an intermediate empty name",
			domain: "a.b.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass},
		},
		{
			name:   "tree walk: psd=n makes the closer domain the organisational domain",
			domain: "a.mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=none; psd=n"))
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusWarn},
		},
		{
			name:   "tree walk: a record at a public suffix domain (psd=y) applies when nothing is below it",
			domain: "a.mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.com", "v=DMARC1; p=reject; psd=y"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusPass, dmPolicy: finding.StatusPass},
		},
		{
			name:   "tree walk: several records at one name are all discarded and the walk goes on",
			domain: "a.mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=none"))
				f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=quarantine"))
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusPass},
		},
		{
			name:   "own record wins over the organisational domain",
			domain: "mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=none"))
				f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
			},
			want: map[string]finding.Status{dmPolicy: finding.StatusWarn},
		},
		{
			name:   "resolver failure",
			domain: "example.com",
			setup: func(f *dnsxtest.Fake) {
				f.SetError("_dmarc.example.com", dns.TypeTXT, errors.New("timeout"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusUnknown, dmPolicy: finding.StatusUnknown, dmEnforce: finding.StatusUnknown, dmReporting: finding.StatusUnknown},
		},
		{
			name:   "resolver failure on the organisational lookup",
			domain: "mail.example.com",
			setup: func(f *dnsxtest.Fake) {
				f.SetError("_dmarc.example.com", dns.TypeTXT, errors.New("timeout"))
			},
			want: map[string]finding.Status{dmPresent: finding.StatusUnknown},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			withMail(f, tt.domain)
			tt.setup(f)
			got := run(t, checks.DMARC{}, f, tt.domain)
			wantStatuses(t, got, tt.want)
		})
	}
}

func TestDMARCDoesNotQueryOrgDomainWhenOwnRecordExists(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=reject"))
	_ = run(t, checks.DMARC{}, f, "mail.example.com")
	if q := f.Queries(); len(q) != 1 {
		t.Fatalf("expected a single query, got %v", q)
	}
}

func TestDMARCNotesInheritance(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"))
	got := run(t, checks.DMARC{}, f, "mail.example.com")
	present := get(t, got, dmPresent)
	if present.Detail == "" {
		t.Error("an inherited record must be flagged in Detail so the report can say so")
	}
	if len(present.Evidence) != 1 || present.Evidence[0] != "v=DMARC1; p=reject; rua=mailto:d@example.com" {
		t.Errorf("evidence must be the raw record, got %v", present.Evidence)
	}
}

// dmarcQueries lists the _dmarc names asked, without the trailing dot and record type.
func dmarcQueries(f *dnsxtest.Fake) []string {
	var out []string
	for _, q := range f.Queries() {
		if name, ok := strings.CutSuffix(q, "./TXT"); ok && strings.HasPrefix(name, "_dmarc.") {
			out = append(out, name)
		}
	}
	return out
}

func TestDMARCTreeWalkStopsAtPSDTag(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.mail.example.com", "v=DMARC1; p=none; psd=n"))
	_ = run(t, checks.DMARC{}, f, "a.mail.example.com")
	for _, q := range dmarcQueries(f) {
		if q == "_dmarc.example.com" || q == "_dmarc.com" {
			t.Fatalf("the walk went past a psd=n record: %v", dmarcQueries(f))
		}
	}
}

// RFC 9989 section 4.10: an Author Domain with more than eight labels is shortened to seven, so the
// walk never makes more than eight queries and never asks about the long names in between.
func TestDMARCTreeWalkIsBoundedForDeepNames(t *testing.T) {
	deep := "a.b.c.d.e.f.g.h.example.com" // 10 labels
	f := dnsxtest.New()
	_ = run(t, checks.DMARC{}, f, deep)
	q := dmarcQueries(f)
	if len(q) > 8 {
		t.Fatalf("%d queries for a 10-label name, want at most 8: %v", len(q), q)
	}
	for _, name := range q {
		if name == "_dmarc.b.c.d.e.f.g.h.example.com" || name == "_dmarc.c.d.e.f.g.h.example.com" {
			t.Fatalf("queried a name the shortcut must skip: %s", name)
		}
	}
	want := map[string]bool{"_dmarc." + deep: true, "_dmarc.d.e.f.g.h.example.com": true, "_dmarc.example.com": true, "_dmarc.com": true}
	for name := range want {
		found := false
		for _, got := range q {
			found = found || got == name
		}
		if !found {
			t.Errorf("expected a query for %s, got %v", name, q)
		}
	}
}

func TestDMARCTreeWalkIgnoresARecordOnlyAboveTheShortcut(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.b.c.d.e.f.g.h.example.com", "v=DMARC1; p=reject"))
	got := run(t, checks.DMARC{}, f, "a.b.c.d.e.f.g.h.example.com")
	if present := get(t, got, dmPresent); present.Status == finding.StatusPass || len(present.Evidence) != 0 {
		t.Fatalf("a record the shortcut skips must not be found, got %v %v", present.Status, present.Evidence)
	}
}

func TestDMARCEnforcementMentionsTheTag(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; t=y; rua=mailto:d@example.com"))
	e := get(t, run(t, checks.DMARC{}, f, "example.com"), dmEnforce)
	if !strings.Contains(e.Detail, "t=y") {
		t.Errorf("detail must name the tag, got %q", e.Detail)
	}
	f = dnsxtest.New()
	f.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"))
	e = get(t, run(t, checks.DMARC{}, f, "example.com"), dmEnforce)
	if !strings.Contains(e.Detail, "pct") || !strings.Contains(e.Detail, "RFC 9989") {
		t.Errorf("a legacy pct must say that RFC 9989 removed it, got %q", e.Detail)
	}
}
