package checks_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	spfPresent = "email.spf.present"
	spfPolicy  = "email.spf.policy"
	spfLookups = "email.spf.lookups"
)

func TestSPF(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *dnsxtest.Fake)
		want  map[string]finding.Status
	}{
		{
			name:  "no TXT at all",
			setup: func(f *dnsxtest.Fake) {},
			want:  map[string]finding.Status{spfPresent: finding.StatusFail},
		},
		{
			name: "only unrelated TXT",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "google-site-verification=abc"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusFail},
		},
		{
			name: "multiple SPF records is a permerror",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ~all"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusFail},
		},
		{
			name: "hard fail only",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusPass, spfPolicy: finding.StatusPass, spfLookups: finding.StatusPass},
		},
		{
			name: "policy comes from the top record, not from includes",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 include:_spf.example.net -all"))
				f.Add(dnsxtest.TXT("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 ~all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusPass, spfLookups: finding.StatusPass},
		},
		{
			name: "soft fail is a warning",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.1 ~all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusWarn},
		},
		{
			name: "neutral all is not a policy",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.1 ?all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusFail},
		},
		{
			name: "plus all allows everyone",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 +all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusFail},
		},
		{
			name: "bare all means plus all",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusFail},
		},
		{
			name: "no all mechanism",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.1"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusFail},
		},
		{
			name: "redirect supplies the policy",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 redirect=_spf.example.net"))
				f.Add(dnsxtest.TXT("_spf.example.net", "v=spf1 -all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusPass, spfLookups: finding.StatusPass},
		},
		{
			name: "redirect is ignored when all is present",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ~all redirect=_spf.example.net"))
				f.Add(dnsxtest.TXT("_spf.example.net", "v=spf1 -all"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusWarn},
		},
		{
			name: "multi-string TXT is concatenated without spaces",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.1 -a", "ll"))
			},
			want: map[string]finding.Status{spfPolicy: finding.StatusPass},
		},
		{
			name: "version and mechanisms are case-insensitive",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "V=SPF1 IP4:192.0.2.1 -ALL"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusPass, spfPolicy: finding.StatusPass},
		},
		{
			name: "version must be followed by a space",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf10 -all"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusFail},
		},
		{
			name: "ten lookups is within the limit",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", spfWithIncludes(10)))
				addLeafSPF(f, 10)
			},
			want: map[string]finding.Status{spfLookups: finding.StatusPass},
		},
		{
			name: "eleven lookups exceeds the limit",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", spfWithIncludes(11)))
				addLeafSPF(f, 11)
			},
			want: map[string]finding.Status{spfLookups: finding.StatusFail},
		},
		{
			name: "nested includes count toward the same limit",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 include:a.example.net include:b.example.net -all"))
				f.Add(dnsxtest.TXT("a.example.net", "v=spf1 "+strings.Repeat("a ", 6)+"-all"))
				f.Add(dnsxtest.TXT("b.example.net", "v=spf1 "+strings.Repeat("mx ", 4)+"-all"))
			},
			// 2 includes + 6 a + 4 mx = 12
			want: map[string]finding.Status{spfLookups: finding.StatusFail},
		},
		{
			name: "include loop is a permerror, not an infinite loop",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 include:loop.example.net -all"))
				f.Add(dnsxtest.TXT("loop.example.net", "v=spf1 include:loop.example.net -all"))
			},
			want: map[string]finding.Status{spfLookups: finding.StatusFail},
		},
		{
			name: "include of a domain without SPF is a permerror",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 include:nospf.example.net -all"))
			},
			want: map[string]finding.Status{spfLookups: finding.StatusFail, spfPolicy: finding.StatusPass},
		},
		{
			name: "ptr is deprecated",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 ptr -all"))
			},
			want: map[string]finding.Status{spfLookups: finding.StatusWarn},
		},
		{
			name: "resolver failure on the domain",
			setup: func(f *dnsxtest.Fake) {
				f.SetError("example.com", dns.TypeTXT, errors.New("timeout"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusUnknown, spfPolicy: finding.StatusUnknown, spfLookups: finding.StatusUnknown},
		},
		{
			name: "SERVFAIL on the domain",
			setup: func(f *dnsxtest.Fake) {
				f.SetRcode("example.com", dns.TypeTXT, dns.RcodeServerFailure)
			},
			want: map[string]finding.Status{spfPresent: finding.StatusUnknown},
		},
		{
			name: "resolver failure inside an include",
			setup: func(f *dnsxtest.Fake) {
				f.Add(dnsxtest.TXT("example.com", "v=spf1 include:flaky.example.net -all"))
				f.SetError("flaky.example.net", dns.TypeTXT, errors.New("timeout"))
			},
			want: map[string]finding.Status{spfPresent: finding.StatusPass, spfPolicy: finding.StatusPass, spfLookups: finding.StatusUnknown},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			withMail(f, "example.com")
			tt.setup(f)
			got := run(t, checks.SPF{}, f, "example.com")
			wantStatuses(t, got, tt.want)
		})
	}
}

func TestSPFSeverities(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 +all"))
	got := run(t, checks.SPF{}, f, "example.com")
	p := get(t, got, spfPolicy)
	if p.Severity != finding.SeverityCritical || p.Fixer != finding.FixerOrganization {
		t.Errorf("+all must be critical and fixable by the organisation, got %+v", p)
	}
	if len(p.Evidence) != 1 || p.Evidence[0] != "v=spf1 +all" {
		t.Errorf("evidence must carry the raw record, got %v", p.Evidence)
	}
}

func TestSPFStopsQueryingAtTheLimit(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", spfWithIncludes(40)))
	addLeafSPF(f, 40)
	_ = run(t, checks.SPF{}, f, "example.com")
	// 1 TXT query for the domain + at most 10 includes (+1 that tips over the limit).
	var txt int
	for _, q := range f.Queries() {
		if strings.HasSuffix(q, "/TXT") {
			txt++
		}
	}
	if txt > 12 {
		t.Fatalf("SPF evaluation made %d TXT queries; it must stop shortly after exceeding 10 lookups", txt)
	}
}

func spfWithIncludes(n int) string {
	var b strings.Builder
	b.WriteString("v=spf1")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, " include:i%d.example.net", i)
	}
	b.WriteString(" -all")
	return b.String()
}

func addLeafSPF(f *dnsxtest.Fake, n int) {
	for i := 1; i <= n; i++ {
		f.Add(dnsxtest.TXT(fmt.Sprintf("i%d.example.net", i), "v=spf1 ip4:192.0.2.1 -all"))
	}
}
