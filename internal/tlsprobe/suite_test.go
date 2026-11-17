package tlsprobe

import (
	"crypto/tls"
	"sort"
	"strings"
	"testing"
)

func TestCatalogIsSortedAndUnique(t *testing.T) {
	if len(Suites) < 300 {
		t.Fatalf("only %d suites: the generated catalog looks truncated", len(Suites))
	}
	if !sort.SliceIsSorted(Suites, func(i, j int) bool { return Suites[i].ID < Suites[j].ID }) {
		t.Fatal("Suites must be ordered by ID")
	}
	seen := map[uint16]bool{}
	for _, s := range Suites {
		if seen[s.ID] {
			t.Fatalf("duplicate ID 0x%04X", s.ID)
		}
		seen[s.ID] = true
		if s.Rec != 'Y' && s.Rec != 'N' && s.Rec != 'D' {
			t.Errorf("0x%04X %s has Rec %q", s.ID, s.Name, s.Rec)
		}
		if !strings.HasPrefix(s.Name, "TLS_") {
			t.Errorf("0x%04X has an odd name %q", s.ID, s.Name)
		}
	}
}

// Go's standard library is an independent source of (ID, name) pairs: every
// suite it implements must be in the catalog under the same name, which proves
// the generated table against something other than itself.
func TestCatalogAgreesWithTheGoStandardLibrary(t *testing.T) {
	var all []*tls.CipherSuite
	all = append(all, tls.CipherSuites()...)
	all = append(all, tls.InsecureCipherSuites()...)
	for _, g := range all {
		got, ok := SuiteByID(g.ID)
		if !ok {
			t.Errorf("Go knows 0x%04X %s but the catalog does not", g.ID, g.Name)
			continue
		}
		if got.Name != g.Name {
			t.Errorf("0x%04X: catalog says %q, Go says %q", g.ID, got.Name, g.Name)
		}
	}
}

func TestCatalogHasWellKnownEntries(t *testing.T) {
	for id, name := range map[uint16]string{
		0x0000: "TLS_NULL_WITH_NULL_NULL",
		0x0004: "TLS_RSA_WITH_RC4_128_MD5",
		0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	} {
		if s, ok := SuiteByID(id); !ok || s.Name != name {
			t.Errorf("0x%04X = %+v (found=%v), want %s", id, s, ok, name)
		}
	}
	if _, ok := SuiteByID(0xFFFF); ok {
		t.Error("an unknown ID must not be found")
	}
}

func TestVersionName(t *testing.T) {
	for v, want := range map[uint16]string{
		VersionSSL30: "SSLv3", VersionTLS10: "TLS 1.0", VersionTLS11: "TLS 1.1",
		VersionTLS12: "TLS 1.2", VersionTLS13: "TLS 1.3", 0x1234: "unknown",
	} {
		if got := VersionName(v); got != want {
			t.Errorf("VersionName(0x%04X) = %q, want %q", v, got, want)
		}
	}
}

func TestOfferedSuites(t *testing.T) {
	legacy := LegacySuites()
	if len(legacy) < 300 {
		t.Fatalf("only %d legacy suites offered", len(legacy))
	}
	for _, id := range legacy {
		s, _ := SuiteByID(id)
		if IsTLS13(s) {
			t.Errorf("TLS 1.3 suite %s must not be offered to TLS 1.2 and below", s.Name)
		}
		if IsSCSV(s) {
			t.Errorf("signalling value %s is not a cipher suite and is added separately", s.Name)
		}
	}
	modern := TLS13Suites()
	if len(modern) < 3 {
		t.Fatalf("TLS 1.3 suites = %v, want at least the three mandatory ones", modern)
	}
	for _, id := range modern {
		if s, _ := SuiteByID(id); !IsTLS13(s) {
			t.Errorf("%s is not a TLS 1.3 suite", s.Name)
		}
	}
}
