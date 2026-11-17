package tlsprobe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// record wraps a payload in a TLS record header.
func record(typ byte, version uint16, payload []byte) []byte {
	out := []byte{typ}
	out = binary.BigEndian.AppendUint16(out, version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...)
}

// serverHelloMsg builds a ServerHello handshake message (without the record).
func serverHelloMsg(version uint16, random [32]byte, sessionID []byte, cipher uint16, exts []byte) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, version)
	body = append(body, random[:]...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0) // compression: null
	if exts != nil {
		body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
		body = append(body, exts...)
	}
	return append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func ext(typ uint16, data []byte) []byte { return extension(typ, data) }

func supportedVersionsExt(v uint16) []byte {
	return ext(extSupportedVersions, binary.BigEndian.AppendUint16(nil, v))
}

func read(t *testing.T, stream []byte) Response {
	t.Helper()
	r, err := ReadResponse(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	return r
}

func TestServerHelloTLS12(t *testing.T) {
	msg := serverHelloMsg(VersionTLS12, [32]byte{1}, bytes.Repeat([]byte{5}, 32), 0xC02F, ext(0xff01, []byte{0}))
	got := read(t, record(22, VersionTLS12, msg))

	if got.Kind != KindServerHello || got.Version != VersionTLS12 || got.Cipher != 0xC02F {
		t.Fatalf("got %+v", got)
	}
}

func TestServerHelloOldVersionsAndNoExtensions(t *testing.T) {
	for _, v := range []uint16{VersionSSL30, VersionTLS10, VersionTLS11} {
		msg := serverHelloMsg(v, [32]byte{}, nil, 0x002F, nil)
		got := read(t, record(22, v, msg))
		if got.Kind != KindServerHello || got.Version != v || got.Cipher != 0x002F {
			t.Errorf("version 0x%04X: got %+v", v, got)
		}
	}
}

func TestServerHelloTLS13ReadsTheVersionFromTheExtension(t *testing.T) {
	// legacy_version says TLS 1.2; the real version is in supported_versions,
	// which is not the first extension.
	exts := append(ext(extKeyShare, []byte{0, 0x1d, 0, 32}), supportedVersionsExt(VersionTLS13)...)
	msg := serverHelloMsg(VersionTLS12, [32]byte{2}, bytes.Repeat([]byte{5}, 32), 0x1301, exts)

	got := read(t, record(22, VersionTLS12, msg))

	if got.Kind != KindServerHello || got.Version != VersionTLS13 || got.Cipher != 0x1301 {
		t.Fatalf("got %+v", got)
	}
}

func TestHelloRetryRequest(t *testing.T) {
	// RFC 8446 §4.1.3: SHA-256("HelloRetryRequest") in the random field.
	hrr := [32]byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}
	msg := serverHelloMsg(VersionTLS12, hrr, nil, 0x1302, supportedVersionsExt(VersionTLS13))

	got := read(t, record(22, VersionTLS12, msg))

	if got.Kind != KindHelloRetryRequest || got.Version != VersionTLS13 || got.Cipher != 0x1302 {
		t.Fatalf("a HelloRetryRequest still proves TLS 1.3 support and carries the cipher, got %+v", got)
	}
}

func TestAlerts(t *testing.T) {
	for _, tt := range []struct {
		name        string
		level, desc byte
	}{
		{"handshake_failure", 2, 40},
		{"protocol_version", 2, 70},
		{"insufficient_security", 2, 71},
		{"unrecognized_name (warning)", 1, 112},
	} {
		got := read(t, record(21, VersionTLS10, []byte{tt.level, tt.desc}))
		if got.Kind != KindAlert || got.AlertLevel != tt.level || got.AlertDesc != tt.desc {
			t.Errorf("%s: got %+v", tt.name, got)
		}
	}
}

func TestNotTLS(t *testing.T) {
	tests := map[string][]byte{
		"an HTTP reply":                               []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"),
		"an SSH banner":                               []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"an SMTP banner":                              []byte("220 mail.example.com ESMTP\r\n"),
		"a record of an unknown type":                 record(99, VersionTLS12, []byte{1, 2, 3}),
		"a record with the wrong major":               record(22, 0x0401, []byte{1, 2, 3}),
		"an empty record":                             record(22, VersionTLS12, nil),
		"a first handshake that is not a ServerHello": record(22, VersionTLS12, []byte{11, 0, 0, 3, 1, 2, 3}),
		"a truncated ServerHello body":                record(22, VersionTLS12, []byte{2, 0, 0, 10, 3, 3, 1, 2, 3, 4, 5, 6, 7, 8}),
		"an oversized record":                         append([]byte{22, 3, 3, 0xff, 0xff}, bytes.Repeat([]byte{0}, 100)...),
		"extensions longer than the message": record(22, VersionTLS12,
			func() []byte {
				m := serverHelloMsg(VersionTLS12, [32]byte{}, nil, 0xC02F, []byte{0, 43, 0, 2, 3, 4})
				// Rewrite the extensions length to claim far more than is present.
				binary.BigEndian.PutUint16(m[len(m)-8:], 500)
				return m
			}()),
		"an alert too short to read": record(21, VersionTLS12, []byte{2}),
	}
	for name, stream := range tests {
		t.Run(name, func(t *testing.T) {
			got := read(t, stream)
			if got.Kind != KindNotTLS || got.Detail == "" {
				t.Fatalf("got %+v, want KindNotTLS with an explanation", got)
			}
		})
	}
}

func TestClosedWithoutAnswer(t *testing.T) {
	if got := read(t, nil); got.Kind != KindClosed {
		t.Fatalf("got %+v, want KindClosed", got)
	}
}

func TestTruncatedInputs(t *testing.T) {
	// Fewer than five bytes that cannot be TLS: not TLS.
	if got := read(t, []byte("HTT")); got.Kind != KindNotTLS {
		t.Errorf("HTT: got %+v, want KindNotTLS", got)
	}
	// A TLS header promising more bytes than arrive: an error, because we cannot
	// tell a closed connection from a cut one.
	for _, stream := range [][]byte{
		{22, 3, 3},
		append([]byte{22, 3, 3, 0, 50}, bytes.Repeat([]byte{1}, 10)...),
	} {
		if _, err := ReadResponse(bytes.NewReader(stream)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%x: err = %v, want io.ErrUnexpectedEOF", stream, err)
		}
	}
}

func TestServerHelloSplitAcrossRecords(t *testing.T) {
	msg := serverHelloMsg(VersionTLS12, [32]byte{3}, nil, 0xC030, nil)
	stream := append(record(22, VersionTLS12, msg[:20]), record(22, VersionTLS12, msg[20:])...)

	got := read(t, stream)

	if got.Kind != KindServerHello || got.Cipher != 0xC030 {
		t.Fatalf("a ServerHello fragmented over two records must still be read, got %+v", got)
	}
}

func TestFragmentationCannotExhaustMemory(t *testing.T) {
	// A handshake header claiming 16 MB, followed by endless records.
	stream := record(22, VersionTLS12, []byte{2, 0xff, 0xff, 0xff, 1, 2, 3})
	chunk := record(22, VersionTLS12, bytes.Repeat([]byte{7}, 16000))
	for i := 0; i < 20; i++ {
		stream = append(stream, chunk...)
	}

	got := read(t, stream)

	if got.Kind != KindNotTLS || !strings.Contains(got.Detail, "large") {
		t.Fatalf("an absurd handshake length must be refused, got %+v", got)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestReadErrorsAreReturned(t *testing.T) {
	boom := errors.New("i/o timeout")
	if _, err := ReadResponse(errReader{boom}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the read error: a timeout is not the same as a closed connection", err)
	}
}

func FuzzReadResponse(f *testing.F) {
	f.Add(record(22, VersionTLS12, serverHelloMsg(VersionTLS12, [32]byte{}, nil, 0xC02F, nil)))
	f.Add(record(22, VersionTLS12, serverHelloMsg(VersionTLS12, [32]byte{}, bytes.Repeat([]byte{1}, 32), 0x1301, supportedVersionsExt(VersionTLS13))))
	f.Add(record(21, VersionTLS12, []byte{2, 40}))
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte{22, 3, 1, 0, 5, 2, 0, 0, 1, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadResponse(bytes.NewReader(data))
		if err != nil {
			return
		}
		switch got.Kind {
		case KindServerHello, KindHelloRetryRequest:
			if got.Version < VersionSSL30 || got.Version > VersionTLS13 {
				// A server may announce nonsense; the parser must still not panic.
				_ = got
			}
		case KindNotTLS:
			if got.Detail == "" {
				t.Fatal("KindNotTLS needs an explanation")
			}
		}
	})
}

func TestAResetBeforeAnyDataCountsAsClosed(t *testing.T) {
	// Many servers answer an unacceptable ClientHello by resetting the connection.
	got, err := ReadResponse(errReader{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}})
	if err != nil || got.Kind != KindClosed {
		t.Fatalf("got %+v, %v; want KindClosed", got, err)
	}
}

// countingReader counts the bytes the parser pulls from the network.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// The declared length of a handshake message is checked as soon as the header
// is read, so a hostile server cannot make us download megabytes before we
// notice: we must stop after the first record.
func TestAbsurdHandshakeLengthIsRefusedBeforeReadingMore(t *testing.T) {
	stream := record(22, VersionTLS12, []byte{2, 0xff, 0xff, 0xff, 1, 2, 3})
	for i := 0; i < 20; i++ {
		stream = append(stream, record(22, VersionTLS12, bytes.Repeat([]byte{7}, 16000))...)
	}
	cr := &countingReader{r: bytes.NewReader(stream)}

	got, err := ReadResponse(cr)

	if err != nil || got.Kind != KindNotTLS {
		t.Fatalf("got %+v, %v", got, err)
	}
	if cr.n > 64 {
		t.Fatalf("read %d bytes before refusing: the declared length must be rejected from the first record", cr.n)
	}
}
