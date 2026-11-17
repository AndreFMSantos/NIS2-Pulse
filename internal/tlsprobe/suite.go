// Package tlsprobe enumerates the TLS protocol versions and cipher suites a
// server accepts, using its own ClientHello.
//
// crypto/tls cannot do this: it never offers SSLv3, export, NULL or anonymous
// suites and refuses to negotiate what it considers broken, which is exactly
// what an auditor must detect. The probe sends a hand-built ClientHello, reads
// only the server's first answer (ServerHello or alert) and closes: it never
// completes a handshake, sends no application data and needs no certificate
// validation, because it makes no trust decision.
package tlsprobe

import "strings"

// Suite is one entry of the IANA TLS cipher suite registry.
type Suite struct {
	ID   uint16
	Name string
	// Rec is the IANA "Recommended" column: 'Y' recommended, 'N' not
	// recommended (not necessarily flawed), 'D' discouraged.
	Rec byte
}

var byID = func() map[uint16]Suite {
	m := make(map[uint16]Suite, len(Suites))
	for _, s := range Suites {
		m[s.ID] = s
	}
	return m
}()

// SuiteByID returns the registry entry for id.
func SuiteByID(id uint16) (Suite, bool) {
	s, ok := byID[id]
	return s, ok
}

// Protocol versions as they appear on the wire.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// VersionName returns the usual name of a protocol version.
func VersionName(v uint16) string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

// IsSCSV reports whether s is a signalling cipher suite value (for example
// TLS_EMPTY_RENEGOTIATION_INFO_SCSV): it signals something to the server and
// is never selected as a cipher.
func IsSCSV(s Suite) bool { return strings.Contains(s.Name, "SCSV") }

// IsTLS13 reports whether s is a TLS 1.3 suite. These are only valid in TLS
// 1.3 and are never offered to older versions.
func IsTLS13(s Suite) bool {
	return s.ID>>8 == 0x13 || strings.HasPrefix(s.Name, "TLS_AES_") ||
		strings.HasPrefix(s.Name, "TLS_CHACHA20_") || strings.HasPrefix(s.Name, "TLS_AEGIS_")
}

// SCSVRenegotiation is TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746). Offering
// it instead of the renegotiation_info extension keeps the ClientHello of old
// protocol versions minimal.
const SCSVRenegotiation uint16 = 0x00FF

// LegacySuites returns the IDs of every registry suite that can be offered to
// SSLv3 up to TLS 1.2, ordered by ID: all but TLS 1.3 suites and signalling values.
func LegacySuites() []uint16 {
	var ids []uint16
	for _, s := range Suites {
		if !IsTLS13(s) && !IsSCSV(s) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// TLS13Suites returns the IDs of the registry's TLS 1.3 suites, ordered by ID.
func TLS13Suites() []uint16 {
	var ids []uint16
	for _, s := range Suites {
		if IsTLS13(s) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}
