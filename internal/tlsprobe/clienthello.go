package tlsprobe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Spec describes the ClientHello to build.
type Spec struct {
	// Version is the protocol version being probed. For TLS 1.3 the legacy
	// version field says TLS 1.2 and a supported_versions extension carries 1.3.
	Version uint16
	// Ciphers are offered in this order.
	Ciphers []uint16
	// ServerName becomes the SNI extension; empty and IP literals send none.
	ServerName string
	Random     [32]byte
	// SessionID is at most 32 bytes (TLS 1.3 middlebox-compatibility mode uses 32).
	SessionID []byte
	// KeyShare is the 32-byte X25519 public key, required for TLS 1.3.
	KeyShare []byte
}

// Extension and group identifiers used by the ClientHello.
const (
	extServerName          = 0
	extSupportedGroups     = 10
	extECPointFormats      = 11
	extSignatureAlgorithms = 13
	extSupportedVersions   = 43
	extPSKKeyExchangeModes = 45
	extKeyShare            = 51

	groupX25519 = 0x001d
)

// groups are offered in every probe: the usual elliptic curves and the
// finite-field groups of RFC 7919, so DHE and ECDHE suites can both be chosen.
var groups = []uint16{groupX25519, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102}

// sigAlgs covers modern and legacy signature schemes so that servers with
// RSA, ECDSA or Ed25519 certificates can all answer.
var sigAlgs = []uint16{
	0x0403, 0x0503, 0x0603, // ecdsa_secp{256,384,521}r1
	0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
	0x0807,                 // ed25519
	0x0809, 0x080a, 0x080b, // rsa_pss_pss_sha{256,384,512}
	0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
	0x0203, 0x0201, // ecdsa_sha1, rsa_pkcs1_sha1 (legacy servers)
}

// BuildClientHello encodes a TLS record holding a ClientHello.
func BuildClientHello(s Spec) ([]byte, error) {
	if s.Version < VersionSSL30 || s.Version > VersionTLS13 {
		return nil, fmt.Errorf("unsupported protocol version 0x%04X", s.Version)
	}
	if len(s.Ciphers) == 0 || len(s.Ciphers) > 32000 {
		return nil, fmt.Errorf("a ClientHello needs between 1 and 32000 cipher suites, got %d", len(s.Ciphers))
	}
	if len(s.SessionID) > 32 {
		return nil, errors.New("the session id is at most 32 bytes")
	}
	if s.Version == VersionTLS13 && len(s.KeyShare) != 32 {
		return nil, errors.New("TLS 1.3 needs a 32-byte X25519 key share")
	}
	sni, err := serverNameExtension(s.ServerName)
	if err != nil {
		return nil, err
	}

	clientVersion := s.Version
	if s.Version == VersionTLS13 {
		clientVersion = VersionTLS12
	}

	var body []byte
	body = binary.BigEndian.AppendUint16(body, clientVersion)
	body = append(body, s.Random[:]...)
	body = append(body, byte(len(s.SessionID)))
	body = append(body, s.SessionID...)
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(s.Ciphers)))
	for _, c := range s.Ciphers {
		body = binary.BigEndian.AppendUint16(body, c)
	}
	body = append(body, 1, 0) // compression methods: null only

	ext := extensions(s, sni)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	if len(hs) > 1<<14 {
		return nil, fmt.Errorf("the ClientHello is %d bytes, more than one TLS record can carry", len(hs))
	}

	recordVersion := VersionTLS10 // what browsers send, whatever they offer
	if s.Version == VersionSSL30 {
		recordVersion = VersionSSL30
	}
	rec := []byte{22}
	rec = binary.BigEndian.AppendUint16(rec, recordVersion)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...), nil
}

// extension encodes one extension: type, length, data.
func extension(typ uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func uint16List(vals []uint16) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(2*len(vals)))
	for _, v := range vals {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

func extensions(s Spec, sni []byte) []byte {
	var out []byte
	if sni != nil {
		out = append(out, sni...)
	}
	out = append(out, extension(extSupportedGroups, uint16List(groups))...)
	out = append(out, extension(extECPointFormats, []byte{1, 0})...) // uncompressed
	out = append(out, extension(extSignatureAlgorithms, uint16List(sigAlgs))...)

	if s.Version == VersionTLS13 {
		out = append(out, extension(extSupportedVersions, []byte{2, 0x03, 0x04})...)

		// key_share: a list of (group, key) entries preceded by its own length.
		share := binary.BigEndian.AppendUint16(nil, groupX25519)
		share = binary.BigEndian.AppendUint16(share, uint16(len(s.KeyShare)))
		share = append(share, s.KeyShare...)
		shares := binary.BigEndian.AppendUint16(nil, uint16(len(share)))
		shares = append(shares, share...)
		out = append(out, extension(extKeyShare, shares)...)

		out = append(out, extension(extPSKKeyExchangeModes, []byte{1, 1})...) // psk_dhe_ke
	}
	return out
}

// serverNameExtension returns the SNI extension, or nil when the name is empty
// or an IP literal (RFC 6066 §3 forbids literal addresses in SNI).
func serverNameExtension(name string) ([]byte, error) {
	if name == "" {
		return nil, nil
	}
	if _, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return nil, nil
	}
	if len(name) > 255 {
		return nil, errors.New("server name is longer than 255 bytes")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '.' && r != '_' {
			return nil, fmt.Errorf("server name %q contains characters that are not valid in a host name", name)
		}
	}
	entry := []byte{0} // name_type host_name
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	list = append(list, entry...)
	return extension(extServerName, list), nil
}
