package tlsprobe

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// goParse feeds raw bytes to the TLS server of Go's standard library and
// returns what Go's own ClientHello parser made of them. It is an independent
// judge of our encoder: a misplaced length byte would show up as a different
// server name, cipher list or version list.
func goParse(t *testing.T, raw []byte) *tls.ClientHelloInfo {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	got := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		srv := tls.Server(c, &tls.Config{
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				cp := *chi
				cp.Conn = nil
				got <- &cp
				return nil, errors.New("captured")
			},
		})
		_ = srv.Handshake()
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	select {
	case chi := <-got:
		return chi
	case <-time.After(3 * time.Second):
		t.Fatal("Go's TLS server did not parse the ClientHello: the encoding is invalid")
		return nil
	}
}

func spec12() Spec {
	return Spec{Version: VersionTLS12, Ciphers: []uint16{0xC02F, 0xC030, 0xCCA8, 0x009C, 0x002F, SCSVRenegotiation}, ServerName: "example.com"}
}

func TestClientHelloIsUnderstoodByGo(t *testing.T) {
	raw, err := BuildClientHello(spec12())
	if err != nil {
		t.Fatal(err)
	}

	chi := goParse(t, raw)

	if chi.ServerName != "example.com" {
		t.Errorf("ServerName = %q", chi.ServerName)
	}
	if !reflect.DeepEqual(chi.CipherSuites, spec12().Ciphers) {
		t.Errorf("CipherSuites = %x, want %x", chi.CipherSuites, spec12().Ciphers)
	}
	// Without a supported_versions extension Go derives the list from the
	// client_version field, so a TLS 1.2 hello must peak at TLS 1.2: if it
	// advertised 1.3, a TLS 1.3 server would answer with 1.3 and the probe
	// could never tell whether TLS 1.2 is supported.
	if len(chi.SupportedVersions) == 0 || chi.SupportedVersions[0] != VersionTLS12 {
		t.Errorf("SupportedVersions = %x, want the highest to be TLS 1.2", chi.SupportedVersions)
	}
	for _, v := range chi.SupportedVersions {
		if v == VersionTLS13 {
			t.Errorf("a TLS 1.2 probe advertises TLS 1.3: %x", chi.SupportedVersions)
		}
	}
	if len(chi.SupportedCurves) < 4 {
		t.Errorf("SupportedCurves = %v, want x25519 and the NIST curves", chi.SupportedCurves)
	}
	if len(chi.SignatureSchemes) < 8 {
		t.Errorf("SignatureSchemes = %v", chi.SignatureSchemes)
	}
	if !bytes.Equal(chi.SupportedPoints, []byte{0}) {
		t.Errorf("SupportedPoints = %v, want [uncompressed]", chi.SupportedPoints)
	}
}

func TestClientHelloTLS13(t *testing.T) {
	s := Spec{Version: VersionTLS13, Ciphers: []uint16{0x1301, 0x1302, 0x1303}, ServerName: "example.com",
		KeyShare: bytes.Repeat([]byte{9}, 32), SessionID: bytes.Repeat([]byte{7}, 32)}
	raw, err := BuildClientHello(s)
	if err != nil {
		t.Fatal(err)
	}

	chi := goParse(t, raw)

	if !reflect.DeepEqual(chi.SupportedVersions, []uint16{VersionTLS13}) {
		t.Errorf("SupportedVersions = %x, want only TLS 1.3", chi.SupportedVersions)
	}
	if !reflect.DeepEqual(chi.CipherSuites, s.Ciphers) {
		t.Errorf("CipherSuites = %x", chi.CipherSuites)
	}
	// The legacy field must say TLS 1.2 and the record layer TLS 1.0 (RFC 8446 §5.1, §4.1.2).
	if v := binary.BigEndian.Uint16(raw[9:11]); v != VersionTLS12 {
		t.Errorf("legacy_version = 0x%04X, want 0x0303", v)
	}
	if v := binary.BigEndian.Uint16(raw[1:3]); v != VersionTLS10 {
		t.Errorf("record version = 0x%04X, want 0x0301", v)
	}
}

func TestClientHelloVersionFields(t *testing.T) {
	for _, tt := range []struct {
		version, record uint16
	}{
		{VersionSSL30, VersionSSL30},
		{VersionTLS10, VersionTLS10},
		{VersionTLS11, VersionTLS10},
		{VersionTLS12, VersionTLS10},
	} {
		s := spec12()
		s.Version = tt.version
		raw, err := BuildClientHello(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(raw[1:3]); got != tt.record {
			t.Errorf("version 0x%04X: record version = 0x%04X, want 0x%04X", tt.version, got, tt.record)
		}
		if got := binary.BigEndian.Uint16(raw[9:11]); got != tt.version {
			t.Errorf("version 0x%04X: client_version = 0x%04X", tt.version, got)
		}
		chi := goParse(t, raw)
		if len(chi.CipherSuites) != len(s.Ciphers) {
			t.Errorf("version 0x%04X: Go saw %d suites, want %d", tt.version, len(chi.CipherSuites), len(s.Ciphers))
		}
	}
}

func TestClientHelloLengthsAreConsistent(t *testing.T) {
	s := spec12()
	s.Ciphers = LegacySuites()
	raw, err := BuildClientHello(s)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != 22 {
		t.Fatalf("record type = %d, want handshake (22)", raw[0])
	}
	if got := int(binary.BigEndian.Uint16(raw[3:5])); got != len(raw)-5 {
		t.Errorf("record length = %d, want %d", got, len(raw)-5)
	}
	if raw[5] != 1 {
		t.Errorf("handshake type = %d, want ClientHello (1)", raw[5])
	}
	if got := int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8]); got != len(raw)-9 {
		t.Errorf("handshake length = %d, want %d", got, len(raw)-9)
	}
	// A hello offering the whole registry must still be understood.
	if chi := goParse(t, raw); len(chi.CipherSuites) != len(s.Ciphers) {
		t.Errorf("Go saw %d of %d suites", len(chi.CipherSuites), len(s.Ciphers))
	}
}

func TestClientHelloSNI(t *testing.T) {
	for name, want := range map[string]string{
		"example.com":     "example.com",
		"a.b.example.com": "a.b.example.com",
		"192.0.2.1":       "", // an IP literal is not a valid SNI (RFC 6066 §3)
		"2001:db8::1":     "",
		"":                "",
	} {
		s := spec12()
		s.ServerName = name
		raw, err := BuildClientHello(s)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if got := goParse(t, raw).ServerName; got != want {
			t.Errorf("ServerName %q: Go saw %q, want %q", name, got, want)
		}
	}
}

func TestClientHelloIsDeterministic(t *testing.T) {
	s := spec12()
	s.Random = [32]byte{1, 2, 3}
	a, _ := BuildClientHello(s)
	b, _ := BuildClientHello(s)
	if !bytes.Equal(a, b) {
		t.Fatal("the same spec must give the same bytes")
	}
	s.Random[0] = 9
	if c, _ := BuildClientHello(s); bytes.Equal(a, c) {
		t.Fatal("the random field must be part of the message")
	}
}

func TestClientHelloRejectsBadSpecs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Spec)
		want string
	}{
		{"no ciphers", func(s *Spec) { s.Ciphers = nil }, "cipher"},
		{"too many ciphers", func(s *Spec) { s.Ciphers = make([]uint16, 33000) }, "cipher"},
		{"unknown version", func(s *Spec) { s.Version = 0x0200 }, "version"},
		{"TLS 1.3 without a key share", func(s *Spec) { s.Version = VersionTLS13 }, "key share"},
		{"TLS 1.3 with a short key share", func(s *Spec) { s.Version = VersionTLS13; s.KeyShare = []byte{1} }, "key share"},
		{"session id too long", func(s *Spec) { s.SessionID = make([]byte, 33) }, "session"},
		{"server name too long", func(s *Spec) { s.ServerName = strings.Repeat("a", 256) }, "server name"},
		{"server name with a space", func(s *Spec) { s.ServerName = "bad name.example" }, "server name"},
		{"server name with a null byte", func(s *Spec) { s.ServerName = "a\x00b.example" }, "server name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := spec12()
			tt.edit(&s)
			_, err := BuildClientHello(s)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}
