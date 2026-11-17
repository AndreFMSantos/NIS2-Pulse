package checks_test

import (
	"strings"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const spfIP4 = "email.spf.ip4"

// An ip4 term that is not an address of the domain itself is not wrong (mail may
// leave through another server), but it is exactly what a typo looks like, so
// it is reported as information for the owner to confirm.
func TestSPFIP4NotMatchingTheDomainsHostsIsInformation(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.248 -all"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.A("mail.example.com", "192.0.2.247"))

	got, ok := find(run(t, checks.SPF{}, f, "example.com"), spfIP4)
	if !ok {
		t.Fatal("an ip4 that matches no own address must produce email.spf.ip4")
	}
	if got.Status != finding.StatusInfo {
		t.Errorf("want info, got %+v", got)
	}
	if !strings.Contains(strings.Join(got.Evidence, "\n"), "192.0.2.248") {
		t.Errorf("the evidence must name the ip4, got %v", got.Evidence)
	}
}

func TestSPFIP4MatchingTheMailHostIsSilent(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.A("mail.example.com", "192.0.2.247"))

	if _, ok := find(run(t, checks.SPF{}, f, "example.com"), spfIP4); ok {
		t.Error("a range that contains the mail host must not produce a finding")
	}
}

func TestSPFIP4MatchingTheApexAddressIsSilent(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.10 -all"))
	f.Add(dnsxtest.A("example.com", "192.0.2.10"))

	if _, ok := find(run(t, checks.SPF{}, f, "example.com"), spfIP4); ok {
		t.Error("an ip4 equal to the apex A record must not produce a finding")
	}
}

// Without any address of its own to compare with there is nothing to say.
func TestSPFIP4WithoutOwnAddressesIsSilent(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.248 -all"))

	if _, ok := find(run(t, checks.SPF{}, f, "example.com"), spfIP4); ok {
		t.Error("with no A and no MX hosts the comparison is meaningless")
	}
}

// An include or redirect may authorise the real sender: the comparison would
// only produce noise, so it is skipped.
func TestSPFIP4IsSkippedWhenTheRecordDelegates(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("example.com", "v=spf1 ip4:192.0.2.248 include:_spf.example.net -all"))
	f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
	f.Add(dnsxtest.A("mail.example.com", "192.0.2.247"))

	if _, ok := find(run(t, checks.SPF{}, f, "example.com"), spfIP4); ok {
		t.Error("a record with include must not produce email.spf.ip4")
	}
}
