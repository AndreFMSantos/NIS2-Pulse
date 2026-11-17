package tlsprobe

import (
	"strings"
	"testing"
)

func TestAssess(t *testing.T) {
	tests := []struct {
		name   string
		rec    byte
		level  Level
		fs     bool
		aead   bool
		reason string
	}{
		// Critical: no encryption, no authentication, or deliberately weakened.
		{"TLS_NULL_WITH_NULL_NULL", 'N', LevelCritical, false, false, "NULL"},
		{"TLS_RSA_WITH_NULL_SHA", 'D', LevelCritical, false, false, "NULL"},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", 'D', LevelCritical, false, false, "export"},
		{"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 'D', LevelCritical, false, false, "export"},
		{"TLS_DH_anon_WITH_AES_128_CBC_SHA", 'D', LevelCritical, false, false, "anonymous"},
		{"TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 'D', LevelCritical, false, false, "anonymous"},
		{"TLS_KRB5_EXPORT_WITH_RC4_40_MD5", 'D', LevelCritical, false, false, "export"},
		// High: broken ciphers.
		{"TLS_RSA_WITH_RC4_128_SHA", 'D', LevelHigh, false, false, "RC4"},
		{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", 'D', LevelHigh, true, false, "RC4"},
		{"TLS_RSA_WITH_DES_CBC_SHA", 'D', LevelHigh, false, false, "DES"},
		{"TLS_DHE_RSA_WITH_DES_CBC_SHA", 'D', LevelHigh, true, false, "DES"},
		// Medium: weak but not trivially broken.
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 'D', LevelMedium, false, false, "3DES"},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 'D', LevelMedium, true, false, "3DES"},
		{"TLS_KRB5_WITH_3DES_EDE_CBC_SHA", 'D', LevelMedium, false, false, "3DES"},
		{"TLS_RSA_WITH_IDEA_CBC_SHA", 'D', LevelMedium, false, false, "IDEA"},
		// Discouraged by IANA only.
		{"TLS_RSA_WITH_AES_128_CBC_SHA", 'D', LevelNote, false, false, "discouraged"},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 'D', LevelNote, true, false, "discouraged"},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", 'D', LevelNote, false, true, "discouraged"},
		// Good.
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 'Y', LevelOK, true, true, ""},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 'Y', LevelOK, true, true, ""},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 'Y', LevelOK, true, true, ""},
		{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 'Y', LevelOK, true, true, ""},
		{"TLS_AES_128_GCM_SHA256", 'Y', LevelOK, true, true, ""},
		{"TLS_AES_256_GCM_SHA384", 'Y', LevelOK, true, true, ""},
		{"TLS_CHACHA20_POLY1305_SHA256", 'Y', LevelOK, true, true, ""},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 'Y', LevelOK, true, true, ""},
		// Key exchange classification.
		{"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 'N', LevelOK, false, true, ""},
		{"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", 'N', LevelOK, false, true, ""},
		{"TLS_PSK_WITH_AES_128_GCM_SHA256", 'N', LevelOK, false, true, ""},
		{"TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 'N', LevelOK, true, true, ""},
		{"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 'N', LevelOK, true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Assess(Suite{Name: tt.name, Rec: tt.rec})
			if got.Level != tt.level {
				t.Errorf("level = %v, want %v (reasons %v)", got.Level, tt.level, got.Reasons)
			}
			if got.ForwardSecret != tt.fs {
				t.Errorf("ForwardSecret = %v, want %v", got.ForwardSecret, tt.fs)
			}
			if got.AEAD != tt.aead {
				t.Errorf("AEAD = %v, want %v", got.AEAD, tt.aead)
			}
			if tt.reason != "" && !strings.Contains(strings.Join(got.Reasons, "; "), tt.reason) {
				t.Errorf("reasons %v should mention %q", got.Reasons, tt.reason)
			}
			if tt.reason == "" && len(got.Reasons) != 0 {
				t.Errorf("a good suite should have no reasons, got %v", got.Reasons)
			}
		})
	}
}

func TestAssessTakesTheWorstLevel(t *testing.T) {
	// Export-grade RC4: both "export" (critical) and "RC4" (high) apply.
	got := Assess(Suite{Name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Rec: 'D'})
	if got.Level != LevelCritical || len(got.Reasons) < 2 {
		t.Fatalf("want critical with both reasons, got %+v", got)
	}
}

func TestAssessWholeCatalogIsConsistent(t *testing.T) {
	var critical, high, medium, fsGood int
	for _, s := range Suites {
		if IsSCSV(s) {
			continue
		}
		a := Assess(s)
		switch a.Level {
		case LevelCritical:
			critical++
		case LevelHigh:
			high++
		case LevelMedium:
			medium++
		}
		// Every suite the IANA registry recommends (Rec Y) must be judged OK.
		if s.Rec == 'Y' && a.Level != LevelOK {
			t.Errorf("%s is recommended by IANA but judged %v: %v", s.Name, a.Level, a.Reasons)
		}
		// Anything with these markers must never be judged better than critical or high.
		if strings.Contains(s.Name, "_NULL_") && a.Level != LevelCritical && !strings.Contains(s.Name, "NULL_WITH_NULL_NULL") {
			t.Errorf("%s has NULL encryption but is judged %v", s.Name, a.Level)
		}
		if strings.Contains(s.Name, "EXPORT") && a.Level != LevelCritical {
			t.Errorf("%s is export-grade but judged %v", s.Name, a.Level)
		}
		if strings.Contains(s.Name, "_RC4_") && a.Level < LevelHigh {
			t.Errorf("%s uses RC4 but is judged %v", s.Name, a.Level)
		}
		if a.ForwardSecret && !strings.Contains(s.Name, "DHE") && !IsTLS13(s) {
			t.Errorf("%s is marked forward secret without an ephemeral key exchange", s.Name)
		}
		if a.ForwardSecret {
			fsGood++
		}
	}
	if critical < 20 || high < 10 || medium < 5 || fsGood < 50 {
		t.Errorf("implausible totals: critical=%d high=%d medium=%d forward-secret=%d", critical, high, medium, fsGood)
	}
}

func TestIsSCSV(t *testing.T) {
	if s, _ := SuiteByID(0x00FF); !IsSCSV(s) {
		t.Error("TLS_EMPTY_RENEGOTIATION_INFO_SCSV is a signalling value")
	}
	if s, _ := SuiteByID(0xC02F); IsSCSV(s) {
		t.Error("a real cipher suite is not a signalling value")
	}
}
