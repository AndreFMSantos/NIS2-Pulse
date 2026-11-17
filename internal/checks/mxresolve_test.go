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

const mxResolves = "email.mx.resolves"

// find returns the finding with the given ID and whether it was produced.
func find(fs []finding.Finding, id string) (finding.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// The mail host named by the MX has to exist: a sender that cannot resolve it
// bounces or queues the message (RFC 5321 §5.1), and nothing in the MX record
// itself shows the problem.
func TestMXHostWithoutAddressFails(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.SetRcode("mail.example.com", dns.TypeA, dns.RcodeNameError)
	f.SetRcode("mail.example.com", dns.TypeAAAA, dns.RcodeNameError)

	got, ok := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if !ok {
		t.Fatal("a domain with MX records must get an email.mx.resolves finding")
	}
	if got.Status != finding.StatusFail || got.Severity != finding.SeverityHigh {
		t.Errorf("no MX host resolves: want fail/high, got %+v", got)
	}
	if !strings.Contains(strings.Join(got.Evidence, "\n"), "mail.example.com") {
		t.Errorf("the evidence must name the host, got %v", got.Evidence)
	}
}

func TestMXHostWithOnlyAAAAPasses(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.AAAA("mail.example.com", "2001:db8::25"))

	got, _ := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if got.Status != finding.StatusPass {
		t.Errorf("an IPv6-only mail host resolves: want pass, got %+v", got)
	}
}

func TestSomeMXHostsUnresolvableWarns(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.MX("example.com", 20, "backup.example.com"))
	f.Add(dnsxtest.A("mail.example.com", "192.0.2.25"))
	f.SetRcode("backup.example.com", dns.TypeA, dns.RcodeNameError)

	got, _ := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if got.Status != finding.StatusWarn || got.Severity != finding.SeverityMedium {
		t.Errorf("one of two hosts missing: want warn/medium, got %+v", got)
	}
	if !strings.Contains(strings.Join(got.Evidence, "\n"), "backup.example.com") {
		t.Errorf("the evidence must name the broken host, got %v", got.Evidence)
	}
}

// RFC 2181 §10.3 forbids an alias as an MX target. It often works, which is why
// it goes unnoticed, so it is a warning while the host still resolves.
func TestMXPointingToAnAliasWarns(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.AddFor("mail.example.com", dns.TypeA,
		dnsxtest.CNAME("mail.example.com", "smtp.provider.example"),
		dnsxtest.A("smtp.provider.example", "192.0.2.25"))

	got, _ := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if got.Status != finding.StatusWarn {
		t.Fatalf("an alias that resolves: want warn, got %+v", got)
	}
	if !strings.Contains(got.Detail, "alias") {
		t.Errorf("the detail must say why, got %q", got.Detail)
	}
}

func TestMXPointingToADanglingAliasFails(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.AddFor("mail.example.com", dns.TypeA, dnsxtest.CNAME("mail.example.com", "gone.provider.example"))

	got, _ := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if got.Status != finding.StatusFail {
		t.Errorf("an alias without addresses: want fail, got %+v", got)
	}
}

// If every lookup fails for transport reasons we know nothing: never a verdict.
func TestMXResolutionUnknownWhenLookupsFail(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.SetError("mail.example.com", dns.TypeA, errors.New("timeout"))
	f.SetError("mail.example.com", dns.TypeAAAA, errors.New("timeout"))

	got, _ := find(run(t, checks.MX{}, f, "example.com"), mxResolves)
	if got.Status != finding.StatusUnknown {
		t.Errorf("failed lookups: want unknown, got %+v", got)
	}
}

// Without mail hosts there is nothing to resolve, so the finding is absent.
func TestNoMXHostsMeansNoResolutionFinding(t *testing.T) {
	for name, setup := range map[string]func(*dnsxtest.Fake){
		"no MX":   func(*dnsxtest.Fake) {},
		"null MX": func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 0, ".")) },
	} {
		t.Run(name, func(t *testing.T) {
			f := dnsxtest.New()
			setup(f)
			if _, ok := find(run(t, checks.MX{}, f, "example.com"), mxResolves); ok {
				t.Error("email.mx.resolves must not be produced without MX hosts")
			}
		})
	}
}
