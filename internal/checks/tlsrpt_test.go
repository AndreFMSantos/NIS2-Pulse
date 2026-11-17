package checks_test

import (
	"errors"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const tlsrptRecord = "email.tlsrpt.record"

func TestTLSRPT(t *testing.T) {
	withMX := func(f *dnsxtest.Fake) { withMail(f, "example.com") }
	withSTS := func(f *dnsxtest.Fake) {
		withMX(f)
		f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
	}
	rpt := func(f *dnsxtest.Fake, txt string) { f.Add(dnsxtest.TXT("_smtp._tls.example.com", txt)) }

	tests := []struct {
		name  string
		setup func(f *dnsxtest.Fake)
		want  finding.Status
	}{
		{"domain does not receive mail", func(f *dnsxtest.Fake) {}, finding.StatusInfo},
		{"null MX", func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 0, ".")) }, finding.StatusInfo},
		{"no mail but a leftover MTA-STS record: still nothing to report", func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
		}, finding.StatusInfo},
		{"mail but no MTA-STS and no TLS-RPT: nothing to report on", withMX, finding.StatusInfo},
		{"MTA-STS without TLS-RPT: you would not learn when it blocks mail", withSTS, finding.StatusWarn},
		{"valid mailto record", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1; rua=mailto:tlsrpt@example.com")
		}, finding.StatusPass},
		{"valid https record", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1;rua=https://reports.example.com/tlsrpt")
		}, finding.StatusPass},
		{"several destinations", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1; rua=mailto:a@example.com,https://reports.example.com/x")
		}, finding.StatusPass},
		{"version is case-insensitive and spaces are tolerated", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "V=tlsrptv1 ;  rua=mailto:a@example.com ;")
		}, finding.StatusPass},
		{"record without MTA-STS is still valid", func(f *dnsxtest.Fake) {
			withMX(f)
			rpt(f, "v=TLSRPTv1; rua=mailto:a@example.com")
		}, finding.StatusPass},
		{"missing rua", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1")
		}, finding.StatusFail},
		{"rua with an unsupported scheme", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1; rua=ftp://reports.example.com/x")
		}, finding.StatusFail},
		{"rua destination is empty", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1; rua=")
		}, finding.StatusFail},
		{"two records", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "v=TLSRPTv1; rua=mailto:a@example.com")
			rpt(f, "v=TLSRPTv1; rua=mailto:b@example.com")
		}, finding.StatusWarn},
		{"TXT that is not TLS-RPT is ignored", func(f *dnsxtest.Fake) {
			withSTS(f)
			rpt(f, "something else")
		}, finding.StatusWarn},
		{"MX lookup fails", func(f *dnsxtest.Fake) { f.SetError("example.com", dns.TypeMX, errors.New("timeout")) }, finding.StatusUnknown},
		{"TXT lookup fails", func(f *dnsxtest.Fake) {
			withSTS(f)
			f.SetError("_smtp._tls.example.com", dns.TypeTXT, errors.New("timeout"))
		}, finding.StatusUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			tt.setup(f)
			got := run(t, checks.TLSRPT{}, f, "example.com")
			wantStatuses(t, got, map[string]finding.Status{tlsrptRecord: tt.want})
		})
	}
}
