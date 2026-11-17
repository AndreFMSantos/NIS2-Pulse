package tlsprobe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
)

// Kind classifies a server's first answer to a ClientHello.
type Kind int

// Kinds of answer.
const (
	// KindServerHello: the server accepted the offer and chose a version and cipher.
	KindServerHello Kind = iota + 1
	// KindHelloRetryRequest: a TLS 1.3 server asking for a different key share.
	// It still proves TLS 1.3 support and carries the chosen cipher.
	KindHelloRetryRequest
	// KindAlert: a TLS alert, the normal way to say "no".
	KindAlert
	// KindNotTLS: bytes that are not a TLS answer (an HTTP reply, a banner...).
	KindNotTLS
	// KindClosed: the connection ended (or was reset) without any data.
	KindClosed
)

// Response is what the server said first.
type Response struct {
	Kind    Kind
	Version uint16 // negotiated version (ServerHello, HelloRetryRequest)
	Cipher  uint16 // chosen cipher suite (ServerHello, HelloRetryRequest)

	AlertLevel byte // 1 warning, 2 fatal
	AlertDesc  byte

	Detail string // why the answer is KindNotTLS
}

const (
	recordAlert     = 21
	recordHandshake = 22

	// maxRecord is the largest record a TLS peer may send (RFC 8446 §5.1 allows
	// 2^14 plus expansion). Anything bigger is not TLS.
	maxRecord = 1<<14 + 2048
	// maxHandshake bounds the ServerHello we are willing to reassemble. Real ones
	// are well under 1 KiB; the cap stops a hostile server from making us buffer
	// an arbitrary amount.
	maxHandshake = 1 << 16
)

// helloRetryRandom is SHA-256("HelloRetryRequest"), the fixed random value that
// marks a HelloRetryRequest (RFC 8446 §4.1.3).
var helloRetryRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func notTLS(format string, args ...any) (Response, error) {
	return Response{Kind: KindNotTLS, Detail: fmt.Sprintf(format, args...)}, nil
}

// ReadResponse reads the server's first answer from r. It reads untrusted
// bytes, so every length is checked and the amount buffered is bounded.
//
// A clean close or a reset before any data is KindClosed. Other I/O errors
// (timeouts, a stream cut mid-record) are returned, because they say nothing
// reliable about what the server would have answered.
func ReadResponse(r io.Reader) (Response, error) {
	var hdr [5]byte
	n, err := io.ReadFull(r, hdr[:])
	if err != nil {
		switch {
		case n == 0 && (errors.Is(err, io.EOF) || isReset(err)):
			return Response{Kind: KindClosed}, nil
		case n > 0 && hdr[0] != recordAlert && hdr[0] != recordHandshake && errors.Is(err, io.ErrUnexpectedEOF):
			return notTLS("the first bytes % x do not form a TLS record", hdr[:n])
		}
		return Response{}, err
	}

	typ, major := hdr[0], hdr[1]
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if (typ != recordAlert && typ != recordHandshake) || major != 3 || length == 0 || length > maxRecord {
		return notTLS("the first bytes % x do not form a TLS record header", hdr[:])
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Response{}, fmt.Errorf("truncated TLS record: %w", err)
	}

	if typ == recordAlert {
		if len(payload) < 2 {
			return notTLS("alert record of %d byte(s), too short", len(payload))
		}
		return Response{Kind: KindAlert, AlertLevel: payload[0], AlertDesc: payload[1]}, nil
	}

	// Handshake record: reassemble the first message if it is fragmented.
	msg := payload
	for {
		if len(msg) >= 4 {
			total := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
			if total > maxHandshake {
				return notTLS("handshake message of %d bytes is too large for a ServerHello", total)
			}
			if len(msg) >= total {
				return parseServerHello(msg[:total])
			}
		}
		// Need the next record to continue the message.
		var next [5]byte
		if _, err := io.ReadFull(r, next[:]); err != nil {
			return Response{}, fmt.Errorf("handshake message cut short: %w", err)
		}
		nlen := int(binary.BigEndian.Uint16(next[3:5]))
		if next[0] != recordHandshake || next[1] != 3 || nlen == 0 || nlen > maxRecord {
			return notTLS("a fragmented handshake continues with an invalid record % x", next[:])
		}
		more := make([]byte, nlen)
		if _, err := io.ReadFull(r, more); err != nil {
			return Response{}, fmt.Errorf("truncated TLS record: %w", err)
		}
		if len(msg)+len(more) > maxHandshake+maxRecord {
			return notTLS("the handshake message is too large for a ServerHello")
		}
		msg = append(msg, more...)
	}
}

// parseServerHello decodes a complete handshake message that should be a ServerHello.
func parseServerHello(msg []byte) (Response, error) {
	if msg[0] != 2 {
		return notTLS("the first handshake message has type %d, expected ServerHello (2)", msg[0])
	}
	body := msg[4:]
	// server_version(2) random(32) session_id_len(1)
	if len(body) < 35 {
		return notTLS("ServerHello of %d bytes is too short", len(body))
	}
	version := binary.BigEndian.Uint16(body[0:2])
	var random [32]byte
	copy(random[:], body[2:34])
	sidLen := int(body[34])
	rest := body[35:]
	if len(rest) < sidLen+3 {
		return notTLS("ServerHello is cut short after the session id")
	}
	rest = rest[sidLen:]
	cipher := binary.BigEndian.Uint16(rest[0:2])
	rest = rest[3:] // cipher(2) compression(1)

	if len(rest) >= 2 {
		extLen := int(binary.BigEndian.Uint16(rest[0:2]))
		rest = rest[2:]
		if extLen > len(rest) {
			return notTLS("ServerHello extensions claim %d bytes but only %d follow", extLen, len(rest))
		}
		rest = rest[:extLen]
		for len(rest) > 0 {
			if len(rest) < 4 {
				return notTLS("a ServerHello extension header is cut short")
			}
			typ := binary.BigEndian.Uint16(rest[0:2])
			l := int(binary.BigEndian.Uint16(rest[2:4]))
			if l > len(rest)-4 {
				return notTLS("a ServerHello extension claims %d bytes but only %d follow", l, len(rest)-4)
			}
			if typ == extSupportedVersions && l == 2 {
				version = binary.BigEndian.Uint16(rest[4:6])
			}
			rest = rest[4+l:]
		}
	}

	kind := KindServerHello
	if random == helloRetryRandom {
		kind = KindHelloRetryRequest
	}
	return Response{Kind: kind, Version: version, Cipher: cipher}, nil
}

// isReset reports a connection reset or broken pipe.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
