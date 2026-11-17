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
)

func validate(t *testing.T, w *dnssectest.World, domain string) dnssec.Result {
	t.Helper()
	v := &dnssec.Validator{
		Resolver: w.Fake,
		Anchors:  w.Anchors,
		Now:      func() time.Time { return w.Now },
	}
	return v.Validate(context.Background(), domain)
}

func zoneNames(r dnssec.Result) []string {
	var out []string
	for _, z := range r.Zones {
		out = append(out, z.Name)
	}
	return out
}

func TestSecureChain(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")

	r := validate(t, w, "example.pt")

	if r.Status != dnssec.StatusSecure {
		t.Fatalf("status = %s code=%s detail=%q err=%v", r.Status, r.Code, r.Detail, r.Err)
	}
	if got := strings.Join(zoneNames(r), " "); got != ". pt. example.pt." {
		t.Errorf("validated zones = %q", got)
	}
	last := r.Zones[len(r.Zones)-1]
	if len(last.Keys) != 2 {
		t.Fatalf("final zone should list both keys, got %+v", last.Keys)
	}
	var sep int
	for _, k := range last.Keys {
		if k.SEP {
			sep++
		}
		if k.Algorithm != dns.ED25519 {
			t.Errorf("unexpected algorithm %d", k.Algorithm)
		}
	}
	if sep != 1 {
		t.Errorf("want exactly one SEP key, got %d", sep)
	}
	if want := w.Now.Add(14 * 24 * time.Hour); !last.Expires.Equal(want) {
		t.Errorf("Expires = %s, want %s", last.Expires, want)
	}
	if len(r.DSDigestTypes) != 1 || r.DSDigestTypes[0] != dns.SHA256 {
		t.Errorf("DSDigestTypes = %v, want [SHA256]", r.DSDigestTypes)
	}
}

func TestOnlyCheckingDisabledQueriesAreSent(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	_ = validate(t, w, "example.pt")

	q := w.Fake.Queries()
	if len(q) == 0 {
		t.Fatal("no queries made")
	}
	for _, s := range q {
		if !strings.HasSuffix(s, "+CD") {
			t.Errorf("query %q was not sent with the CD bit; a validating resolver would hide broken chains behind SERVFAIL", s)
		}
	}
}

func TestSubdomainThatIsNotAZoneCutIsSecure(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")

	r := validate(t, w, "www.example.pt")

	if r.Status != dnssec.StatusSecure {
		t.Fatalf("status = %s code=%s detail=%q", r.Status, r.Code, r.Detail)
	}
	if got := strings.Join(zoneNames(r), " "); got != ". pt. example.pt." {
		t.Errorf("www is not a cut: validated zones = %q", got)
	}
}

func TestInsecureDelegation(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"example.pt.": true}}, "pt.", "example.pt.")

	r := validate(t, w, "example.pt")

	if r.Status != dnssec.StatusInsecure || r.Code != dnssec.CodeDSMissing || r.Zone != "example.pt." {
		t.Fatalf("want insecure ds_missing at example.pt., got status=%s code=%s zone=%s", r.Status, r.Code, r.Zone)
	}
	if got := strings.Join(zoneNames(r), " "); got != ". pt." {
		t.Errorf("zones validated before the gap = %q, want \". pt.\"", got)
	}
}

func TestInsecureTLD(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{NoDS: map[string]bool{"xx.": true}}, "xx.", "example.xx.")

	r := validate(t, w, "example.xx")

	if r.Status != dnssec.StatusInsecure || r.Zone != "xx." {
		t.Fatalf("want insecure at xx., got status=%s zone=%s", r.Status, r.Zone)
	}
}

func TestBogusCases(t *testing.T) {
	tests := []struct {
		name     string
		opts     dnssectest.Options
		wantCode dnssec.Code
		wantZone string
		wantIn   string // substring expected in Detail
	}{
		{"DS matches no DNSKEY", dnssectest.Options{WrongDS: map[string]bool{"example.pt.": true}},
			dnssec.CodeDSMismatch, "example.pt.", "DS"},
		{"zone publishes no DNSKEY", dnssectest.Options{NoDNSKEY: map[string]bool{"example.pt.": true}},
			dnssec.CodeDNSKEYMissing, "example.pt.", "DNSKEY"},
		{"DNSKEY RRset unsigned", dnssectest.Options{NoKeySig: map[string]bool{"example.pt.": true}},
			dnssec.CodeSigMissing, "example.pt.", "RRSIG"},
		{"DNSKEY signature expired", dnssectest.Options{ExpiredKeySig: map[string]bool{"example.pt.": true}},
			dnssec.CodeSigExpired, "example.pt.", "expired"},
		{"DNSKEY signature not yet valid", dnssectest.Options{FutureKeySig: map[string]bool{"example.pt.": true}},
			dnssec.CodeSigNotYetValid, "example.pt.", "not yet valid"},
		{"DNSKEY signature does not verify", dnssectest.Options{TamperedKeySig: map[string]bool{"example.pt.": true}},
			dnssec.CodeSigInvalid, "example.pt.", "signature"},
		{"parent's DS signature expired", dnssectest.Options{ExpiredDSSig: map[string]bool{"example.pt.": true}},
			dnssec.CodeSigExpired, "example.pt.", "DS"},
		{"TLD DNSKEY signature expired", dnssectest.Options{ExpiredKeySig: map[string]bool{"pt.": true}},
			dnssec.CodeSigExpired, "pt.", "expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := dnssectest.New(t, tt.opts, "pt.", "example.pt.")

			r := validate(t, w, "example.pt")

			if r.Status != dnssec.StatusBogus {
				t.Fatalf("status = %s (code=%s detail=%q), want bogus", r.Status, r.Code, r.Detail)
			}
			if r.Code != tt.wantCode || r.Zone != tt.wantZone {
				t.Errorf("code/zone = %s/%s, want %s/%s", r.Code, r.Zone, tt.wantCode, tt.wantZone)
			}
			if !strings.Contains(r.Detail, tt.wantIn) {
				t.Errorf("detail %q should mention %q", r.Detail, tt.wantIn)
			}
		})
	}
}

// Failures at the root can never be the audited domain's fault: they mean a
// stale binary (KSK rollover) or a resolver that strips DNSSEC records.
func TestRootProblemsAreIndeterminateNotBogus(t *testing.T) {
	tests := []struct {
		name     string
		opts     dnssectest.Options
		wantCode dnssec.Code
	}{
		{"anchors do not match the root keys", dnssectest.Options{BadAnchor: true}, dnssec.CodeAnchorMismatch},
		{"resolver returns no root DNSKEY", dnssectest.Options{NoDNSKEY: map[string]bool{".": true}}, dnssec.CodeDNSKEYMissing},
		{"resolver returns no root RRSIG", dnssectest.Options{NoKeySig: map[string]bool{".": true}}, dnssec.CodeSigMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := dnssectest.New(t, tt.opts, "pt.", "example.pt.")

			r := validate(t, w, "example.pt")

			if r.Status != dnssec.StatusIndeterminate || r.Code != tt.wantCode || r.Zone != "." {
				t.Fatalf("want indeterminate %s at the root, got status=%s code=%s zone=%s", tt.wantCode, r.Status, r.Code, r.Zone)
			}
		})
	}
}

func TestUnsupportedAlgorithmIsIndeterminate(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{OpaqueAlgZone: "example.pt."}, "pt.", "example.pt.")

	r := validate(t, w, "example.pt")

	if r.Status != dnssec.StatusIndeterminate || r.Code != dnssec.CodeUnsupportedAlgorithm {
		t.Fatalf("status=%s code=%s detail=%q, want indeterminate unsupported_algorithm", r.Status, r.Code, r.Detail)
	}
}

func TestResolverFailuresAreIndeterminate(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
		boom := errors.New("connection reset")
		w.Fake.SetError("example.pt.", dns.TypeDNSKEY, boom)

		r := validate(t, w, "example.pt")

		if r.Status != dnssec.StatusIndeterminate || r.Code != dnssec.CodeQueryFailed || !errors.Is(r.Err, boom) {
			t.Fatalf("status=%s code=%s err=%v", r.Status, r.Code, r.Err)
		}
	})
	t.Run("SERVFAIL", func(t *testing.T) {
		w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
		w.Fake.SetRcode("pt.", dns.TypeDS, dns.RcodeServerFailure)

		r := validate(t, w, "example.pt")

		if r.Status != dnssec.StatusIndeterminate || r.Code != dnssec.CodeQueryFailed {
			t.Fatalf("status=%s code=%s", r.Status, r.Code)
		}
	})
}

func TestAnyMatchingAnchorIsEnough(t *testing.T) {
	w := dnssectest.New(t, dnssectest.Options{}, "pt.", "example.pt.")
	stale := *w.Anchors[0]
	stale.KeyTag, stale.Digest = 1111, strings.Repeat("ab", 32)
	w.Anchors = []*dns.DS{&stale, w.Anchors[0]}

	if r := validate(t, w, "example.pt"); r.Status != dnssec.StatusSecure {
		t.Fatalf("status=%s code=%s: a stale anchor next to a good one must not matter", r.Status, r.Code)
	}
}

func TestRootAnchorsAreWellFormed(t *testing.T) {
	anchors := dnssec.RootAnchors()
	tags := map[uint16]bool{}
	for _, a := range anchors {
		tags[a.KeyTag] = true
		if a.Algorithm != dns.RSASHA256 || a.DigestType != dns.SHA256 || len(a.Digest) != 64 {
			t.Errorf("malformed anchor %+v", a)
		}
		if a.Hdr.Name != "." {
			t.Errorf("anchor owner = %q, want the root", a.Hdr.Name)
		}
	}
	// IANA root-anchors.xml (checked 2026-11-06): KSK-2017 and KSK-2024.
	if !tags[20326] || !tags[38696] || len(anchors) != 2 {
		t.Errorf("anchors = %v, want exactly key tags 20326 and 38696", tags)
	}
}
