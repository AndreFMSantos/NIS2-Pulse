package checks_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	dkKey      = "email.dkim.key"
	dkStrength = "email.dkim.strength"
)

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// fakeRSAKey returns the base64 SubjectPublicKeyInfo of an RSA "key" whose
// modulus has exactly bits bits. It is structurally valid but not a usable key
// pair, which is all the checks look at. Building it by hand also lets the
// tests cover keys below 1024 bits, which crypto/rsa refuses to generate.
func fakeRSAKey(t *testing.T, bits int) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	pkcs1, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{n, 65537})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
		asn1.BitString{Bytes: pkcs1, BitLength: 8 * len(pkcs1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func realRSAKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func ed25519Key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// dkimFor returns the finding with the given ID about one selector.
func dkimFor(t *testing.T, fs []finding.Finding, id, selector string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id && len(f.Evidence) > 0 && f.Evidence[0] == "selector="+selector {
			return f
		}
	}
	t.Fatalf("finding %s for selector %q not found in %+v", id, selector, fs)
	return finding.Finding{}
}

func addKey(f *dnsxtest.Fake, selector string, txt ...string) {
	f.Add(dnsxtest.TXT(selector+"._domainkey.example.com", txt...))
}

func runDKIM(t *testing.T, f *dnsxtest.Fake, selectors ...string) []finding.Finding {
	t.Helper()
	return run(t, checks.DKIM{Selectors: selectors}, f, "example.com")
}

func TestDKIMKeyAndStrength(t *testing.T) {
	rsa2048, rsa1024, rsa768, rsa512 := fakeRSAKey(t, 2048), fakeRSAKey(t, 1024), fakeRSAKey(t, 768), fakeRSAKey(t, 512)
	ed := ed25519Key(t)

	tests := []struct {
		name         string
		txt          []string
		key          finding.Status
		strength     finding.Status // "" = no strength finding expected
		keySeverity  finding.Severity
		strengthText string
	}{
		{"rsa 2048", []string{"v=DKIM1; k=rsa; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
		{"v tag is optional", []string{"k=rsa; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
		{"k defaults to rsa", []string{"v=DKIM1; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
		{"rsa 1024 is tolerated but weak", []string{"v=DKIM1; p=" + rsa1024}, finding.StatusPass, finding.StatusWarn, "", "2048"},
		{"rsa 768 is breakable", []string{"v=DKIM1; p=" + rsa768}, finding.StatusPass, finding.StatusFail, "", "768"},
		{"rsa 512 is breakable", []string{"v=DKIM1; p=" + rsa512}, finding.StatusPass, finding.StatusFail, "", "512"},
		{"ed25519", []string{"v=DKIM1; k=ed25519; p=" + ed}, finding.StatusPass, finding.StatusPass, "", ""},
		{"ed25519 key of the wrong length", []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString([]byte("too short"))}, finding.StatusPass, finding.StatusFail, "", "32"},
		{"testing mode", []string{"v=DKIM1; t=y; p=" + rsa2048}, finding.StatusWarn, finding.StatusPass, "", ""},
		{"strict flag alone is fine", []string{"v=DKIM1; t=s; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
		{"revoked key (empty p)", []string{"v=DKIM1; p="}, finding.StatusFail, "", "", ""},
		{"missing p", []string{"v=DKIM1; k=rsa"}, finding.StatusFail, "", "", ""},
		{"p is not base64", []string{"v=DKIM1; p=%%%not base64%%%"}, finding.StatusFail, "", "", ""},
		{"p is not a public key", []string{"v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("hello world"))}, finding.StatusFail, "", "", ""},
		{"wrong version", []string{"v=DKIM2; p=" + rsa2048}, finding.StatusFail, "", "", ""},
		{"unsupported key type", []string{"v=DKIM1; k=dsa; p=" + rsa2048}, finding.StatusFail, "", "", ""},
		{"only sha1 is allowed", []string{"v=DKIM1; h=sha1; p=" + rsa2048}, finding.StatusFail, finding.StatusPass, "", ""},
		{"sha1 next to sha256 is fine", []string{"v=DKIM1; h=sha1:sha256; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
		{"folded base64 with spaces", []string{"v=DKIM1; p=" + rsa2048[:40] + " " + rsa2048[40:100] + "  " + rsa2048[100:]}, finding.StatusPass, finding.StatusPass, "", ""},
		{"key split in several character-strings", []string{"v=DKIM1; p=" + rsa2048[:200], rsa2048[200:]}, finding.StatusPass, finding.StatusPass, "", ""},
		{"extra tags are ignored", []string{"v=DKIM1; n=notes; s=email; p=" + rsa2048}, finding.StatusPass, finding.StatusPass, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			addKey(f, "s1", tt.txt...)

			got := runDKIM(t, f, "s1")

			if k := dkimFor(t, got, dkKey, "s1"); k.Status != tt.key {
				t.Errorf("key status = %s, want %s (%+v)", k.Status, tt.key, k)
			}
			var strength *finding.Finding
			for i := range got {
				if got[i].ID == dkStrength {
					strength = &got[i]
				}
			}
			switch {
			case tt.strength == "" && strength != nil:
				t.Errorf("no strength finding expected for an unusable key, got %+v", *strength)
			case tt.strength != "" && strength == nil:
				t.Errorf("strength finding missing, want %s", tt.strength)
			case strength != nil && strength.Status != tt.strength:
				t.Errorf("strength = %s, want %s (%+v)", strength.Status, tt.strength, *strength)
			case strength != nil && tt.strengthText != "" && !strings.Contains(strength.Detail, tt.strengthText):
				t.Errorf("strength detail %q should mention %q", strength.Detail, tt.strengthText)
			}
		})
	}
}

// The detail is what the report shows the administrator, so each failure must
// say its own reason, not just fail.
func TestDKIMExplainsWhyAKeyFails(t *testing.T) {
	tests := []struct {
		name, txt, detail string
	}{
		{"revoked", "v=DKIM1; p=", "revoked"},
		{"no p tag", "v=DKIM1; k=rsa", "no p tag"},
		{"bad base64", "v=DKIM1; p=%%%", "base64"},
		{"not a public key", "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("hello world")), "SubjectPublicKeyInfo"},
		{"wrong version", "v=DKIM2; p=abc", "DKIM1"},
		{"unsupported key type", "v=DKIM1; k=dsa; p=abc", "key type"},
		{"sha1 only", "v=DKIM1; h=sha1; p=" + fakeRSAKey(t, 2048), "SHA-1"},
		{"testing mode", "v=DKIM1; t=y; p=" + fakeRSAKey(t, 2048), "t=y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dnsxtest.New()
			addKey(f, "s1", tt.txt)

			k := dkimFor(t, runDKIM(t, f, "s1"), dkKey, "s1")

			if !strings.Contains(k.Detail, tt.detail) {
				t.Fatalf("detail %q should explain the problem (mention %q)", k.Detail, tt.detail)
			}
		})
	}
}

func TestDKIMAcceptsARealRSAKey(t *testing.T) {
	f := dnsxtest.New()
	addKey(f, "s1", "v=DKIM1; k=rsa; p="+realRSAKey(t))

	got := runDKIM(t, f, "s1")

	if dkimFor(t, got, dkKey, "s1").Status != finding.StatusPass || dkimFor(t, got, dkStrength, "s1").Status != finding.StatusPass {
		t.Fatalf("a real 2048-bit key from crypto/rsa must pass, got %+v", got)
	}
}

func TestDKIMWeakKeysAreJudgedNotRejectedAsParseErrors(t *testing.T) {
	// crypto/x509 refuses to parse RSA keys below 1024 bits. A weak key found in
	// the wild must still produce a verdict about its weakness.
	f := dnsxtest.New()
	addKey(f, "old", "v=DKIM1; p="+fakeRSAKey(t, 512))

	got := runDKIM(t, f, "old")

	s := dkimFor(t, got, dkStrength, "old")
	if s.Status != finding.StatusFail || s.Severity != finding.SeverityHigh {
		t.Fatalf("a 512-bit key is a high-severity weakness, got %+v", s)
	}
}

func TestDKIMSelectorProblems(t *testing.T) {
	t.Run("selector not published", func(t *testing.T) {
		k := dkimFor(t, runDKIM(t, dnsxtest.New(), "s1"), dkKey, "s1")
		if k.Status != finding.StatusFail || k.Severity != finding.SeverityHigh || !strings.Contains(k.Detail, "s1._domainkey.example.com") {
			t.Fatalf("a selector the user named but that does not exist is a real finding, got %+v", k)
		}
	})
	t.Run("several TXT records at the selector", func(t *testing.T) {
		f := dnsxtest.New()
		addKey(f, "s1", "v=DKIM1; p="+fakeRSAKey(t, 2048))
		addKey(f, "s1", "v=DKIM1; p="+fakeRSAKey(t, 2048))
		if k := dkimFor(t, runDKIM(t, f, "s1"), dkKey, "s1"); k.Status != finding.StatusFail {
			t.Fatalf("got %+v", k)
		}
	})
	t.Run("resolver error", func(t *testing.T) {
		f := dnsxtest.New()
		f.SetError("s1._domainkey.example.com", dns.TypeTXT, errors.New("timeout"))
		if k := dkimFor(t, runDKIM(t, f, "s1"), dkKey, "s1"); k.Status != finding.StatusUnknown {
			t.Fatalf("got %+v", k)
		}
	})
	t.Run("SERVFAIL", func(t *testing.T) {
		f := dnsxtest.New()
		f.SetRcode("s1._domainkey.example.com", dns.TypeTXT, dns.RcodeServerFailure)
		if k := dkimFor(t, runDKIM(t, f, "s1"), dkKey, "s1"); k.Status != finding.StatusUnknown {
			t.Fatalf("got %+v", k)
		}
	})
}

func TestDKIMWithoutSelectorIsUnknownNeverFail(t *testing.T) {
	f := dnsxtest.New()
	got := runDKIM(t, f)

	if len(got) != 1 || got[0].Status != finding.StatusUnknown || got[0].ID != dkKey {
		t.Fatalf("selectors cannot be discovered from DNS, so no selector must mean unknown, got %+v", got)
	}
	if !strings.Contains(got[0].Detail, "--dkim-selector") {
		t.Errorf("the detail must tell the user how to supply a selector, got %q", got[0].Detail)
	}
	if len(f.Queries()) != 0 {
		t.Errorf("nothing should be queried without a selector, got %v", f.Queries())
	}
}

func TestDKIMSeveralSelectorsAreReportedSeparately(t *testing.T) {
	f := dnsxtest.New()
	addKey(f, "good", "v=DKIM1; p="+fakeRSAKey(t, 2048))
	// "gone" is not published.

	got := runDKIM(t, f, "good", "gone")

	if dkimFor(t, got, dkKey, "good").Status != finding.StatusPass || dkimFor(t, got, dkKey, "gone").Status != finding.StatusFail {
		t.Fatalf("each selector needs its own verdict, got %+v", got)
	}
}

func TestDKIMSelectorsAreValidatedAndDeduplicated(t *testing.T) {
	f := dnsxtest.New()
	addKey(f, "s1", "v=DKIM1; p="+fakeRSAKey(t, 2048))

	got := runDKIM(t, f, "S1", "s1", "bad selector!", "../etc", "a/b", "")

	for _, bad := range []string{"bad selector!", "../etc", "a/b"} {
		var found bool
		for _, fi := range got {
			if fi.ID == dkKey && len(fi.Evidence) > 0 && fi.Evidence[0] == "selector="+bad {
				found = fi.Status == finding.StatusUnknown && strings.Contains(fi.Detail, "invalid selector")
			}
		}
		if !found {
			t.Errorf("selector %q must be reported as an invalid (unknown) selector, got %+v", bad, got)
		}
	}
	for _, q := range f.Queries() {
		name := strings.TrimSuffix(q, "/TXT") // the log format is "name./TYPE"
		if strings.ContainsAny(name, " !/") || strings.Contains(name, "..") {
			t.Errorf("an invalid selector reached the resolver: %q", q)
		}
	}
	var s1 int
	for _, q := range f.Queries() {
		if q == "s1._domainkey.example.com./TXT" {
			s1++
		}
	}
	if s1 != 1 {
		t.Errorf("S1 and s1 are the same selector and must be queried once, got %d queries: %v", s1, f.Queries())
	}
}

func TestDKIMAllowsDottedSelectors(t *testing.T) {
	f := dnsxtest.New()
	addKey(f, "mail.2026", "v=DKIM1; p="+fakeRSAKey(t, 2048))
	if k := dkimFor(t, runDKIM(t, f, "mail.2026"), dkKey, "mail.2026"); k.Status != finding.StatusPass {
		t.Fatalf("RFC 6376 allows sub-domain selectors, got %+v", k)
	}
}
