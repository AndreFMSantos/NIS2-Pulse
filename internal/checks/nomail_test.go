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

const mxProfile = "email.mx.profile"

// A domain that does not receive email still needs protecting against being
// spoofed, but a missing record is a recommendation, not a high-severity
// failure: we cannot tell from outside whether such a domain also sends mail.
func TestMissingRecordsOnDomainsThatDoNotReceiveMail(t *testing.T) {
	scenarios := map[string]func(f *dnsxtest.Fake){
		"no MX at all": func(f *dnsxtest.Fake) {},
		"null MX":      func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 0, ".")) },
	}
	for name, setup := range scenarios {
		t.Run(name, func(t *testing.T) {
			f := dnsxtest.New()
			setup(f)

			spf := get(t, run(t, checks.SPF{}, f, "example.com"), spfPresent)
			if spf.Status != finding.StatusWarn || spf.Severity != finding.SeverityMedium {
				t.Errorf("missing SPF on a non-mail domain should be warn/medium, got %+v", spf)
			}
			if !strings.Contains(spf.Detail, `"v=spf1 -all"`) {
				t.Errorf("the detail must say what to publish, got %q", spf.Detail)
			}

			dm := get(t, run(t, checks.DMARC{}, f, "example.com"), dmPresent)
			if dm.Status != finding.StatusWarn || dm.Severity != finding.SeverityMedium {
				t.Errorf("missing DMARC on a non-mail domain should be warn/medium, got %+v", dm)
			}
			if !strings.Contains(dm.Detail, "p=reject") {
				t.Errorf("the detail must say what to publish, got %q", dm.Detail)
			}
		})
	}
}

func TestMissingRecordsOnDomainsThatReceiveMailStayHighSeverity(t *testing.T) {
	f := dnsxtest.New()
	withMail(f, "example.com")

	spf := get(t, run(t, checks.SPF{}, f, "example.com"), spfPresent)
	dm := get(t, run(t, checks.DMARC{}, f, "example.com"), dmPresent)

	for _, got := range []finding.Finding{spf, dm} {
		if got.Status != finding.StatusFail || got.Severity != finding.SeverityHigh {
			t.Errorf("%s: a domain that receives mail must fail with high severity, got %+v", got.ID, got)
		}
	}
}

// If the MX lookup itself fails we do not know the profile, and must not
// soften the verdict on the strength of missing information.
func TestUnknownMailProfileKeepsTheStrictVerdict(t *testing.T) {
	f := dnsxtest.New()
	f.SetError("example.com", dns.TypeMX, errors.New("timeout"))

	spf := get(t, run(t, checks.SPF{}, f, "example.com"), spfPresent)
	dm := get(t, run(t, checks.DMARC{}, f, "example.com"), dmPresent)

	if spf.Status != finding.StatusFail || dm.Status != finding.StatusFail {
		t.Fatalf("an unknown mail profile must keep fail, got spf=%+v dmarc=%+v", spf, dm)
	}
}

// Receiving no mail never excuses a broken record: only absence is softened.
func TestBrokenRecordsOnNonMailDomainsStillFail(t *testing.T) {
	f := dnsxtest.New() // no MX
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ~all"))
	if spf := get(t, run(t, checks.SPF{}, f, "example.com"), spfPresent); spf.Status != finding.StatusFail {
		t.Errorf("two SPF records are invalid whatever the domain does, got %+v", spf)
	}

	f2 := dnsxtest.New()
	f2.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=reject"))
	f2.Add(dnsxtest.TXT("_dmarc.example.com", "v=DMARC1; p=none"))
	if dm := get(t, run(t, checks.DMARC{}, f2, "example.com"), dmPresent); dm.Status != finding.StatusFail {
		t.Errorf("two DMARC records are invalid whatever the domain does, got %+v", dm)
	}
}

func TestMissingRecordsAreNotLookedUpWhenPresent(t *testing.T) {
	// The MX lookup is only needed to judge an absence; do not spend a query otherwise.
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 -all"))
	_ = run(t, checks.SPF{}, f, "example.com")
	for _, q := range f.Queries() {
		if strings.HasSuffix(q, "/MX") {
			t.Fatalf("unexpected MX query when SPF exists: %v", f.Queries())
		}
	}
}

func TestMXProfile(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *dnsxtest.Fake)
		want  finding.Status
		find  string
	}{
		{"receives mail", func(f *dnsxtest.Fake) { withMail(f, "example.com") }, finding.StatusInfo, "mail.example.com"},
		{"explicit null MX", func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 0, ".")) }, finding.StatusPass, "null MX"},
		{"null MX mixed with real hosts: the hosts win (RFC 7505 requires it to be the only MX)", func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.MX("example.com", 0, "."))
			withMail(f, "example.com")
		}, finding.StatusInfo, "mail.example.com"},
		{"no MX: falls back to the A record", func(f *dnsxtest.Fake) {}, finding.StatusWarn, "null MX"},
		{"lookup fails", func(f *dnsxtest.Fake) { f.SetError("example.com", dns.TypeMX, errors.New("timeout")) }, finding.StatusUnknown, "timeout"},
		{"SERVFAIL", func(f *dnsxtest.Fake) { f.SetRcode("example.com", dns.TypeMX, dns.RcodeServerFailure) }, finding.StatusUnknown, "rcode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			tt.setup(f)

			got := get(t, run(t, checks.MX{}, f, "example.com"), mxProfile)

			if got.Status != tt.want {
				t.Fatalf("status = %s, want %s (%+v)", got.Status, tt.want, got)
			}
			if !strings.Contains(strings.Join(append(got.Evidence, got.Detail), " "), tt.find) {
				t.Errorf("%+v should mention %q", got, tt.find)
			}
		})
	}
}

func TestMXProfileListsHostsInPreferenceFreeSortedForm(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 20, "B.Example.com."))
	f.Add(dnsxtest.MX("example.com", 10, "a.example.com"))

	got := get(t, run(t, checks.MX{}, f, "example.com"), mxProfile)

	if len(got.Evidence) != 2 || got.Evidence[0] != "a.example.com" || got.Evidence[1] != "b.example.com" {
		t.Fatalf("evidence should list normalised host names in a stable order, got %v", got.Evidence)
	}
}
