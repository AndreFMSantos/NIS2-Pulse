package checks_test

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const subdomainsMX = "email.subdomains.mx"

func TestNormalizeSubdomains(t *testing.T) {
	got, err := checks.NormalizeSubdomains("example.com", []string{
		"mail", " SMTP.example.com. ", "mail", "a.b", "",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mail.example.com", "smtp.example.com", "a.b.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeSubdomainsRejects(t *testing.T) {
	cases := map[string][]string{
		"the domain itself": {"example.com"},
		"not a name":        {"mail server"},
		"a URL":             {"https://mail"},
		"an IP address":     {"192.0.2.1"},
	}
	for name, in := range cases {
		if _, err := checks.NormalizeSubdomains("example.com", in); err == nil {
			t.Errorf("%s (%v) must be rejected", name, in)
		}
	}
	var many []string
	for i := 0; i <= checks.MaxSubdomains; i++ {
		many = append(many, "h"+strings.Repeat("a", i))
	}
	if _, err := checks.NormalizeSubdomains("example.com", many); err == nil {
		t.Errorf("more than %d subdomains must be rejected", checks.MaxSubdomains)
	}
}

// The case that motivated the check: a subdomain declares an MX whose host has no
// address, and a scan of the apex never sees it.
func TestSubdomainWithMXToAMissingHostFails(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("blog.example.com", 10, "mail.blog.example.com"))
	f.SetRcode("mail.blog.example.com", dns.TypeA, dns.RcodeNameError)
	f.SetRcode("mail.blog.example.com", dns.TypeAAAA, dns.RcodeNameError)

	got := run(t, checks.MailSubdomains{Names: []string{"blog"}}, f, "example.com")[0]
	if got.ID != subdomainsMX || got.Status != finding.StatusFail || got.Severity != finding.SeverityHigh {
		t.Fatalf("want fail/high, got %+v", got)
	}
	if !strings.Contains(strings.Join(got.Evidence, "\n"), "blog.example.com") {
		t.Errorf("the evidence must name the subdomain, got %v", got.Evidence)
	}
}

func TestSubdomainWithWorkingMXPasses(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("blog.example.com", 10, "mail.blog.example.com"))
	f.Add(dnsxtest.A("mail.blog.example.com", "192.0.2.25"))

	got := run(t, checks.MailSubdomains{Names: []string{"blog.example.com"}}, f, "example.com")[0]
	if got.Status != finding.StatusPass {
		t.Errorf("want pass, got %+v", got)
	}
}

// The worst subdomain decides, and the evidence lists all of them.
func TestWorstSubdomainDecides(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.MX("good.example.com", 10, "mx.good.example.com"))
	f.Add(dnsxtest.A("mx.good.example.com", "192.0.2.25"))
	f.Add(dnsxtest.MX("bad.example.com", 10, "mx.bad.example.com"))
	f.SetRcode("mx.bad.example.com", dns.TypeA, dns.RcodeNameError)
	f.SetRcode("mx.bad.example.com", dns.TypeAAAA, dns.RcodeNameError)

	got := run(t, checks.MailSubdomains{Names: []string{"good", "bad"}}, f, "example.com")[0]
	if got.Status != finding.StatusFail {
		t.Errorf("want fail, got %+v", got)
	}
	joined := strings.Join(got.Evidence, "\n")
	if !strings.Contains(joined, "good.example.com") || !strings.Contains(joined, "bad.example.com") {
		t.Errorf("both subdomains must appear in the evidence, got %v", got.Evidence)
	}
}

func TestSubdomainsWithoutMXAreInformation(t *testing.T) {
	f := dnsxtest.New()
	got := run(t, checks.MailSubdomains{Names: []string{"www", "blog"}}, f, "example.com")[0]
	if got.Status != finding.StatusInfo {
		t.Errorf("subdomains that declare no MX: want info, got %+v", got)
	}
}

func TestInvalidSubdomainListIsUnknown(t *testing.T) {
	got := run(t, checks.MailSubdomains{Names: []string{"example.com"}}, dnsxtest.New(), "example.com")[0]
	if got.Status != finding.StatusUnknown {
		t.Errorf("an invalid list must give unknown, got %+v", got)
	}
}

// The check is opt-in: without subdomains it must not be part of the run (an empty
// check would report unknown).
func TestSubdomainsCheckIsRegisteredOnlyWhenRequested(t *testing.T) {
	has := func(o checks.Options) bool {
		for _, c := range checks.Default(o) {
			if c.ID() == "email.subdomains" {
				return true
			}
		}
		return false
	}
	if has(checks.Options{}) {
		t.Error("email.subdomains must not run without --subdomain")
	}
	if !has(checks.Options{Subdomains: []string{"blog"}}) {
		t.Error("email.subdomains must run when subdomains are given")
	}
}
