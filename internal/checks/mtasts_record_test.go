package checks_test

import (
	"errors"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const mtRecord = "email.mtasts.record"

func TestMTASTSRecord(t *testing.T) {
	withMX := func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 10, "mail.example.com")) }

	tests := []struct {
		name  string
		setup func(f *dnsxtest.Fake)
		want  finding.Status
	}{
		{"domain does not receive mail: not applicable", func(f *dnsxtest.Fake) {}, finding.StatusInfo},
		{"null MX: not applicable", func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 0, ".")) }, finding.StatusInfo},
		{"null MX mixed with real MX hosts still receives mail", func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.MX("example.com", 0, "."))
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=abc123"))
		}, finding.StatusPass},
		{"receives mail, no record", func(f *dnsxtest.Fake) { withMX(f) }, finding.StatusWarn},
		{"valid record", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=20261106T000000"))
		}, finding.StatusPass},
		{"trailing semicolon and spaces are tolerated", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1 ;  id=abc123 ;"))
		}, finding.StatusPass},
		{"version is case-insensitive", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=stsv1; id=abc123"))
		}, finding.StatusPass},
		{"TXT that is not MTA-STS is ignored", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "something else"))
		}, finding.StatusWarn},
		{"missing id", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1"))
		}, finding.StatusFail},
		{"id with illegal characters", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=not valid!"))
		}, finding.StatusFail},
		{"id longer than 32 characters", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=012345678901234567890123456789012"))
		}, finding.StatusFail},
		{"two records: senders treat it as no policy", func(f *dnsxtest.Fake) {
			withMX(f)
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=a"))
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=b"))
		}, finding.StatusFail},
		{"MX lookup fails", func(f *dnsxtest.Fake) {
			f.SetError("example.com", dns.TypeMX, errors.New("timeout"))
		}, finding.StatusUnknown},
		{"TXT lookup fails", func(f *dnsxtest.Fake) {
			withMX(f)
			f.SetError("_mta-sts.example.com", dns.TypeTXT, errors.New("timeout"))
		}, finding.StatusUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			tt.setup(f)
			got := run(t, checks.MTASTSRecord{}, f, "example.com")
			wantStatuses(t, got, map[string]finding.Status{mtRecord: tt.want})
		})
	}
}

func TestMTASTSRecordIsPassive(t *testing.T) {
	if (checks.MTASTSRecord{}).Tier() != finding.TierPassive {
		t.Fatal("reading a TXT record is a plain DNS lookup and must stay passive")
	}
}
