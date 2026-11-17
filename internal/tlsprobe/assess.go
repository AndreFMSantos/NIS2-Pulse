package tlsprobe

import "strings"

// Level ranks how bad it is that a server accepts a cipher suite.
type Level int

// Levels, from harmless to broken.
const (
	LevelOK       Level = iota // nothing to report
	LevelNote                  // only discouraged by the IANA registry
	LevelMedium                // weak, not trivially broken (3DES, IDEA)
	LevelHigh                  // broken cipher (RC4, DES, RC2, MD5)
	LevelCritical              // no encryption, no authentication or export-grade
)

func (l Level) String() string {
	switch l {
	case LevelNote:
		return "note"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	case LevelCritical:
		return "critical"
	}
	return "ok"
}

// Assessment is the judgement of one cipher suite.
type Assessment struct {
	Level   Level
	Reasons []string
	// ForwardSecret is true when the key exchange is ephemeral (DHE, ECDHE or
	// TLS 1.3): a later compromise of the server key cannot decrypt past traffic.
	ForwardSecret bool
	// AEAD is true for authenticated-encryption modes (GCM, CCM, ChaCha20-Poly1305).
	AEAD bool
}

// Assess judges a suite from its IANA name, taking the worst applicable level.
// The names are systematic (TLS_<kx>_<auth>_WITH_<cipher>_<mac>), so the
// judgement is made on whole name tokens: "DES" must not match "3DES".
func Assess(s Suite) Assessment {
	var a Assessment
	raise := func(l Level, reason string) {
		a.Reasons = append(a.Reasons, reason)
		if l > a.Level {
			a.Level = l
		}
	}
	discouraged := func() {
		if s.Rec == 'D' && a.Level == LevelOK {
			raise(LevelNote, "discouraged by the IANA TLS registry")
		}
	}

	if isTLS13Name(s.Name) {
		a.ForwardSecret, a.AEAD = true, true
		discouraged()
		return a
	}

	tokens := strings.Split(s.Name, "_")
	has := func(t string) bool {
		for _, x := range tokens {
			if x == t {
				return true
			}
		}
		return false
	}

	if has("NULL") {
		raise(LevelCritical, "NULL encryption: the traffic is not encrypted")
	}
	if strings.Contains(s.Name, "EXPORT") {
		raise(LevelCritical, "export-grade cipher: deliberately weakened key, breakable in minutes")
	}
	if strings.Contains(s.Name, "_anon_") {
		raise(LevelCritical, "anonymous key exchange: the server is not authenticated")
	}
	if has("RC4") {
		raise(LevelHigh, "RC4 is broken (RFC 7465 prohibits it)")
	}
	if has("DES") || has("DES40") {
		raise(LevelHigh, "single DES has a 56-bit key and can be brute-forced")
	}
	if has("RC2") {
		raise(LevelHigh, "RC2 is obsolete and weak")
	}
	if has("MD5") {
		raise(LevelHigh, "MD5 is broken as a message authentication hash")
	}
	if has("3DES") {
		raise(LevelMedium, "3DES has 64-bit blocks and is vulnerable to Sweet32 (CVE-2016-2183)")
	}
	if has("IDEA") {
		raise(LevelMedium, "IDEA is obsolete")
	}

	a.ForwardSecret = strings.Contains(s.Name, "DHE")
	a.AEAD = has("GCM") || has("CCM") || has("POLY1305")
	discouraged()
	return a
}

func isTLS13Name(name string) bool {
	return strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") ||
		strings.HasPrefix(name, "TLS_AEGIS_")
}
