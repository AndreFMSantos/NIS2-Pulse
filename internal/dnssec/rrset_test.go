package dnssec_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnssec/dnssectest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

const (
	tlsaOwner = "_25._tcp.mail.example.pt."
	tlsaHex   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func validateTLSA(t *testing.T, w *dnssectest.World) dnssec.RRsetResult {
	t.Helper()
	v := &dnssec.Validator{Resolver: w.Fake, Anchors: w.Anchors, Now: func() time.Time { return w.Now }}
	return v.ValidateRRset(context.Background(), "mail.example.pt", tlsaOwner, dns.TypeTLSA)
}

func tlsa() dns.RR { return dnsxtest.TLSA(tlsaOwner, 3, 1, 1, tlsaHex) }

func TestRRsetSecure(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsa())

	r := validateTLSA(t, w)

	if r.Status != dnssec.StatusSecure || len(r.Records) != 1 {
		t.Fatalf("status %s code %s detail %q records %d", r.Status, r.Code, r.Detail, len(r.Records))
	}
	if _, ok := r.Records[0].(*dns.TLSA); !ok {
		t.Fatalf("record is %T", r.Records[0])
	}
}

func TestRRsetBrokenSignatures(t *testing.T) {
	tests := []struct {
		name   string
		defect dnssectest.RRsetDefect
		code   dnssec.Code
	}{
		{"unsigned in a signed zone", dnssectest.RRsetUnsigned, dnssec.CodeSigMissing},
		{"expired signature", dnssectest.RRsetExpired, dnssec.CodeSigExpired},
		{"signature over other data", dnssectest.RRsetTampered, dnssec.CodeSigInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
			w.SignRRset(t, "example.pt.", tc.defect, tlsa())

			r := validateTLSA(t, w)

			if r.Status != dnssec.StatusBogus || r.Code != tc.code {
				t.Fatalf("status %s code %s detail %q, want bogus/%s", r.Status, r.Code, r.Detail, tc.code)
			}
			if len(r.Records) != 1 {
				t.Fatalf("the records must still be returned for diagnosis, got %d", len(r.Records))
			}
		})
	}
}

func TestRRsetInUnsignedZoneIsInsecureButReturned(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")
	w.Fake.AddFor(tlsaOwner, dns.TypeTLSA, tlsa())

	r := validateTLSA(t, w)

	if r.Status != dnssec.StatusInsecure || len(r.Records) != 1 {
		t.Fatalf("status %s records %d: records of an unsigned zone are not authenticated", r.Status, len(r.Records))
	}
}

func TestRRsetAbsentReportsTheChainStatusAndNoRecords(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	r := validateTLSA(t, w)
	if len(r.Records) != 0 || r.Status != dnssec.StatusSecure {
		t.Fatalf("status %s records %d", r.Status, len(r.Records))
	}
}

func TestRRsetBrokenChainWinsOverTheRecords(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{WrongDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsa())

	r := validateTLSA(t, w)

	if r.Status != dnssec.StatusBogus || r.Code != dnssec.CodeDSMismatch || len(r.Records) != 1 {
		t.Fatalf("status %s code %s records %d", r.Status, r.Code, len(r.Records))
	}
}

func TestRRsetQueryFailureIsIndeterminate(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	w.Fake.SetError(tlsaOwner, dns.TypeTLSA, errors.New("boom"))

	r := validateTLSA(t, w)

	if r.Status != dnssec.StatusIndeterminate || r.Code != dnssec.CodeQueryFailed {
		t.Fatalf("status %s code %s", r.Status, r.Code)
	}
}

func TestRRsetOnlyUsesCheckingDisabledQueries(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsa())
	validateTLSA(t, w)
	for _, q := range w.Fake.Queries() {
		if !strings.HasSuffix(q, "+CD") {
			t.Fatalf("query %q was not sent with the CD bit", q)
		}
	}
}

// The chain is walked for the host, not for the underscore name: asking for DS
// records at _25._tcp... would be pointless (they are never zone cuts) and
// slower, once per MX host.
func TestRRsetDoesNotWalkUnderscoreLabels(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	w.SignRRset(t, "example.pt.", dnssectest.RRsetOK, tlsa())
	validateTLSA(t, w)
	for _, q := range w.Fake.Queries() {
		if strings.Contains(q, "_tcp.") && !strings.HasPrefix(q, tlsaOwner+"/TLSA") {
			t.Fatalf("unexpected query %q: only the TLSA query itself may name the underscore labels", q)
		}
	}
}
