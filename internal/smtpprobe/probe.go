// Package smtpprobe speaks the first few lines of SMTP, just far enough to
// learn whether a mail server offers STARTTLS and to hand the connection over
// to a TLS handshake (RFC 5321 for SMTP, RFC 3207 for STARTTLS).
//
// It is deliberately tiny and defensive, because it talks to servers it does
// not control:
//
//   - it sends only EHLO, STARTTLS and QUIT: never MAIL, RCPT, DATA, VRFY,
//     EXPN or AUTH, so no mail can be created and no address can be probed;
//   - replies are read one byte at a time, never beyond the final CRLF, so
//     nothing a hostile server appends to its "220 Go ahead" is swallowed: it
//     stays on the connection for the TLS handshake to reject (the STARTTLS
//     command-injection class of bugs);
//   - every line and every reply is size-limited, and the whole exchange is
//     bound by the context and a deadline.
package smtpprobe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxLineBytes  = 1024 // RFC 5321 allows 512 including CRLF; be lenient, not unbounded
	maxReplyLines = 64
	maxReplyBytes = 8192
	maxBannerLen  = 200
	defaultBudget = 20 * time.Second
)

// Negotiation is what the server said before any TLS.
type Negotiation struct {
	// Banner is the first line of the 220 greeting, cut to a safe length.
	Banner string
	// Capabilities are the EHLO keywords, upper-cased, without parameters.
	Capabilities []string
	// StartTLS reports whether the server advertised STARTTLS and accepted the
	// command: when true the connection is ready for a TLS handshake.
	StartTLS bool
}

// ReplyError means the server answered a command with an unexpected code, for
// example 554 at the greeting or 454 to STARTTLS.
type ReplyError struct {
	Stage string // "greeting", "EHLO" or "STARTTLS"
	Code  int
	Text  string
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("the server answered %d to %s: %s", e.Code, e.Stage, e.Text)
}

// ProtocolError means the bytes received were not a valid SMTP reply.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "not a valid SMTP reply: " + e.Msg }

// ValidName reports whether s is acceptable as an EHLO name. It accepts host
// names and address literals only, so a name can never smuggle a second
// command into the EHLO line.
func ValidName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '[', r == ']', r == ':':
		default:
			return false
		}
	}
	return true
}

// Negotiate runs greeting, EHLO and (if offered) STARTTLS on conn. On success
// with StartTLS true, the caller must start the TLS handshake on conn next. If
// the server does not offer STARTTLS, Negotiate says QUIT and the caller should
// close the connection. conn's deadline is cleared on return.
func Negotiate(ctx context.Context, conn net.Conn, ehloName string) (*Negotiation, error) {
	if !ValidName(ehloName) {
		return nil, fmt.Errorf("smtpprobe: %q is not a valid EHLO name", ehloName)
	}
	deadline := time.Now().Add(defaultBudget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	n := &Negotiation{}
	code, lines, err := readReply(conn)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, &ReplyError{Stage: "greeting", Code: code, Text: first(lines)}
	}
	n.Banner = first(lines)
	if len(n.Banner) > maxBannerLen {
		n.Banner = n.Banner[:maxBannerLen]
	}

	if _, err := conn.Write([]byte("EHLO " + ehloName + "\r\n")); err != nil {
		return nil, err
	}
	code, lines, err = readReply(conn)
	if err != nil {
		return nil, err
	}
	if code != 250 {
		return nil, &ReplyError{Stage: "EHLO", Code: code, Text: first(lines)}
	}
	for _, l := range lines[1:] { // the first line is the server's name, not a keyword
		if fields := strings.Fields(l); len(fields) > 0 {
			kw := strings.ToUpper(fields[0])
			n.Capabilities = append(n.Capabilities, kw)
			if kw == "STARTTLS" {
				n.StartTLS = true
			}
		}
	}
	if !n.StartTLS {
		_, _ = conn.Write([]byte("QUIT\r\n")) // polite, best effort
		return n, nil
	}

	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		return nil, err
	}
	code, lines, err = readReply(conn)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, &ReplyError{Stage: "STARTTLS", Code: code, Text: first(lines)}
	}
	return n, nil
}

func first(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// readReply reads one (possibly multi-line) reply. It reads byte by byte so it
// never consumes anything after the final CRLF.
func readReply(conn net.Conn) (code int, texts []string, err error) {
	total := 0
	for {
		line, err := readLine(conn)
		if err != nil {
			return 0, nil, err
		}
		total += len(line) + 2
		if total > maxReplyBytes {
			return 0, nil, &ProtocolError{Msg: "the reply is longer than 8 KiB"}
		}
		if len(line) < 3 {
			return 0, nil, &ProtocolError{Msg: "line shorter than a reply code"}
		}
		c, cerr := strconv.Atoi(line[:3])
		if cerr != nil || c < 100 || c > 599 {
			return 0, nil, &ProtocolError{Msg: "the line does not start with a three-digit code"}
		}
		if len(texts) > 0 && c != code {
			return 0, nil, &ProtocolError{Msg: "the lines of one reply carry different codes"}
		}
		code = c
		last := true
		text := ""
		if len(line) > 3 {
			switch line[3] {
			case ' ':
			case '-':
				last = false
			default:
				return 0, nil, &ProtocolError{Msg: "the code is not followed by a space or a hyphen"}
			}
			text = line[4:]
		}
		texts = append(texts, text)
		if last {
			return code, texts, nil
		}
		if len(texts) >= maxReplyLines {
			return 0, nil, &ProtocolError{Msg: "more than 64 lines in one reply"}
		}
	}
}

// readLine reads up to CRLF, one byte at a time, refusing lines over the limit.
func readLine(conn net.Conn) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := conn.Read(one)
		if n == 1 {
			buf = append(buf, one[0])
			if len(buf) >= 2 && buf[len(buf)-2] == '\r' && buf[len(buf)-1] == '\n' {
				return string(buf[:len(buf)-2]), nil
			}
			if len(buf) > maxLineBytes {
				return "", &ProtocolError{Msg: "a line is longer than 1024 bytes"}
			}
		}
		if err != nil {
			return "", err
		}
	}
}
