package smtpprobe_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/smtpprobe"
)

// step is one thing the scripted server does: it first reads a command line
// (unless expect is empty, as for the greeting), then writes reply verbatim.
type step struct {
	expect string // prefix of the command line the client must send, case-insensitive
	reply  string
}

type server struct {
	mu       sync.Mutex
	commands []string
	done     chan struct{}
}

func (s *server) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// serve runs script on a loopback listener and returns the client side of one
// connection. After the script it lets tail run (for example to write extra
// bytes) and then closes, unless hold is set, in which case it waits for the
// client to close.
func serve(t *testing.T, script []step, tail func(net.Conn)) (net.Conn, *server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &server{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for _, st := range script {
			if st.expect != "" {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				s.mu.Lock()
				s.commands = append(s.commands, line)
				s.mu.Unlock()
				if !strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(st.expect)) {
					return
				}
			}
			if _, err := c.Write([]byte(st.reply)); err != nil {
				return
			}
		}
		if tail != nil {
			tail(c)
		}
		// drain whatever the client still sends (QUIT)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				s.mu.Lock()
				s.commands = append(s.commands, strings.TrimRight(line, "\r\n"))
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl, s
}

func negotiate(t *testing.T, conn net.Conn) (*smtpprobe.Negotiation, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return smtpprobe.Negotiate(ctx, conn, "probe.invalid")
}

var happy = []step{
	{"", "220-mx.example.com ESMTP\r\n220 ready\r\n"},
	{"EHLO probe.invalid", "250-mx.example.com\r\n250-SIZE 52428800\r\n250-starttls\r\n250 8BITMIME\r\n"},
	{"STARTTLS", "220 2.0.0 Ready to start TLS\r\n"},
}

func TestNegotiateHappyPath(t *testing.T) {
	conn, srv := serve(t, happy, nil)
	n, err := negotiate(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if !n.StartTLS {
		t.Fatal("STARTTLS should be offered (keywords are case-insensitive)")
	}
	if n.Banner != "mx.example.com ESMTP" {
		t.Fatalf("banner %q: the first line of the greeting", n.Banner)
	}
	if strings.Join(n.Capabilities, ",") != "SIZE,STARTTLS,8BITMIME" {
		t.Fatalf("capabilities %v", n.Capabilities)
	}
	_ = conn.Close()
	<-srv.done
	if got := strings.Join(srv.got(), "|"); got != "EHLO probe.invalid|STARTTLS" {
		t.Fatalf("the client sent %q; nothing but EHLO and STARTTLS is allowed before the handshake", got)
	}
}

func TestNegotiateWithoutSTARTTLSSaysQuit(t *testing.T) {
	conn, srv := serve(t, []step{
		{"", "220 mx ESMTP\r\n"},
		{"EHLO", "250-mx\r\n250 SIZE 100\r\n"},
	}, nil)
	n, err := negotiate(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if n.StartTLS {
		t.Fatal("STARTTLS is not offered")
	}
	_ = conn.Close()
	<-srv.done
	if got := strings.Join(srv.got(), "|"); got != "EHLO probe.invalid|QUIT" {
		t.Fatalf("the client sent %q", got)
	}
}

func TestNegotiateDoesNotMatchSTARTTLSInsideOtherWords(t *testing.T) {
	conn, _ := serve(t, []step{
		{"", "220 mx\r\n"},
		{"EHLO", "250-mx\r\n250 X-NOSTARTTLS-HERE\r\n"},
	}, nil)
	n, err := negotiate(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if n.StartTLS {
		t.Fatal("only the keyword STARTTLS counts")
	}
}

func TestNegotiateReplyErrors(t *testing.T) {
	tests := []struct {
		name   string
		script []step
		stage  string
		code   int
	}{
		{"greeting refused", []step{{"", "554 no service for you\r\n"}}, "greeting", 554},
		{"greeting asks to retry later", []step{{"", "421 too many connections\r\n"}}, "greeting", 421},
		{"EHLO rejected", []step{{"", "220 hi\r\n"}, {"EHLO", "550 bad helo\r\n"}}, "EHLO", 550},
		{"STARTTLS refused", []step{{"", "220 hi\r\n"}, {"EHLO", "250-hi\r\n250 STARTTLS\r\n"}, {"STARTTLS", "454 TLS not available\r\n"}}, "STARTTLS", 454},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := serve(t, tc.script, nil)
			_, err := negotiate(t, conn)
			var re *smtpprobe.ReplyError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want a ReplyError", err)
			}
			if re.Stage != tc.stage || re.Code != tc.code {
				t.Fatalf("stage %q code %d, want %q %d", re.Stage, re.Code, tc.stage, tc.code)
			}
		})
	}
}

func TestNegotiateProtocolErrors(t *testing.T) {
	tests := []struct {
		name  string
		reply string
	}{
		{"not an SMTP reply", "hello there\r\n"},
		{"non-numeric code", "abc ready\r\n"},
		{"mixed codes in one reply", "220-first\r\n250 second\r\n"},
		{"reply too big in many medium lines", strings.Repeat("220-"+strings.Repeat("a", 900)+"\r\n", 20) + "220 end\r\n"},
		{"code not followed by space or hyphen", "220x ready\r\n"},
		{"code below 100", "099 ready\r\n"},
		{"code above 599", "600 ready\r\n"},
		{"line shorter than a code", "22\r\n"},
		{"line too long", "220 " + strings.Repeat("a", 5000) + "\r\n"},
		{"too many lines", strings.Repeat("220-line\r\n", 500) + "220 end\r\n"},
		{"bare LF is not a line ending", "220 ready\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := serve(t, []step{{"", tc.reply}}, func(c net.Conn) { time.Sleep(200 * time.Millisecond) })
			_, err := negotiate(t, conn)
			if err == nil {
				t.Fatal("expected an error")
			}
			var pe *smtpprobe.ProtocolError
			var re *smtpprobe.ReplyError
			// A bare LF never completes a line, so the read ends by timeout or limit; all
			// that matters is that it is an error and not a hang or a success.
			if tc.name != "bare LF is not a line ending" && !errors.As(err, &pe) {
				t.Fatalf("got %T %v, want a ProtocolError (reply error: %v)", err, err, errors.As(err, &re))
			}
		})
	}
}

func TestNegotiateReadsAtMostTheLimitFromAHostileServer(t *testing.T) {
	conn, _ := serve(t, []step{{"", "220 " + strings.Repeat("a", 1<<20)}}, nil)
	start := time.Now()
	_, err := negotiate(t, conn)
	if err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("a never-ending line must be refused early, not read until the deadline")
	}
}

// RFC 3207 §4.2 and the "STARTTLS command injection" class of bugs: whatever
// the server sends right after its 220 belongs to the TLS handshake. The probe
// therefore must not read a single byte beyond the end of the reply.
func TestNegotiateDoesNotReadPastTheReply(t *testing.T) {
	conn, _ := serve(t, []step{
		{"", "220 hi\r\n"},
		{"EHLO", "250-hi\r\n250 STARTTLS\r\n"},
		{"STARTTLS", "220 Go ahead\r\nINJECTED"},
	}, func(c net.Conn) { time.Sleep(300 * time.Millisecond) })
	if _, err := negotiate(t, conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "INJECTED" {
		t.Fatalf("the bytes after the reply must still be on the connection, read %q", buf[:n])
	}
}

func TestNegotiateStopsWhenTheServerIsSilent(t *testing.T) {
	conn, _ := serve(t, []step{{"", ""}}, func(c net.Conn) { time.Sleep(2 * time.Second) })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := smtpprobe.Negotiate(ctx, conn, "probe.invalid")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}

func TestNegotiateServerHangsUpMidReply(t *testing.T) {
	conn, _ := serve(t, []step{{"", "220-half a reply\r\n"}}, nil)
	if _, err := negotiate(t, conn); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNegotiateRefusesAnUnsafeEHLOName(t *testing.T) {
	conn, srv := serve(t, []step{{"", "220 hi\r\n"}}, nil)
	for _, name := range []string{"", "a b", "evil\r\nMAIL FROM:<x@y>", "x\ry"} {
		if _, err := smtpprobe.Negotiate(context.Background(), conn, name); err == nil {
			t.Fatalf("name %q must be refused", name)
		}
	}
	_ = conn.Close()
	<-srv.done
	if len(srv.got()) != 0 {
		t.Fatalf("nothing may be sent for a refused name: %v", srv.got())
	}
}

func TestNegotiateNeverSendsMailCommands(t *testing.T) {
	conn, srv := serve(t, happy, nil)
	if _, err := negotiate(t, conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-srv.done
	for _, c := range srv.got() {
		u := strings.ToUpper(c)
		for _, bad := range []string{"MAIL", "RCPT", "DATA", "VRFY", "EXPN", "AUTH"} {
			if strings.HasPrefix(u, bad) {
				t.Fatalf("forbidden command sent: %q", c)
			}
		}
	}
}

// RFC 5321 §4.2: a reply line is the code, optionally followed by a space and
// text. A bare "220" is a complete, valid reply.
func TestNegotiateAcceptsRepliesWithoutText(t *testing.T) {
	conn, _ := serve(t, []step{
		{"", "220\r\n"},
		{"EHLO", "250\r\n"},
	}, nil)
	n, err := negotiate(t, conn)
	if err != nil || n.StartTLS || n.Banner != "" {
		t.Fatalf("n=%+v err=%v", n, err)
	}
}

func TestNegotiateTruncatesAHugeBanner(t *testing.T) {
	conn, _ := serve(t, []step{
		{"", "220 " + strings.Repeat("b", 900) + "\r\n"},
		{"EHLO", "250 mx\r\n"},
	}, nil)
	n, err := negotiate(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Banner) > 200 {
		t.Fatalf("banner is %d bytes: it ends up in reports, so it is capped", len(n.Banner))
	}
}

func TestNegotiateStopsWhenTheContextIsCancelled(t *testing.T) {
	conn, _ := serve(t, []step{{"", ""}}, func(net.Conn) { time.Sleep(3 * time.Second) })
	ctx, cancel := context.WithCancel(context.Background()) // no deadline: only cancel can interrupt
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := smtpprobe.Negotiate(ctx, conn, "probe.invalid"); err == nil || time.Since(start) > time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}

// The caller hands the connection to a TLS handshake next: Negotiate must not
// leave its own deadline behind, or the handshake would die with it.
func TestNegotiateClearsItsDeadline(t *testing.T) {
	conn, _ := serve(t, happy, func(c net.Conn) { time.Sleep(600 * time.Millisecond); _, _ = c.Write([]byte("X")) })
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := smtpprobe.Negotiate(ctx, conn, "probe.invalid"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(450 * time.Millisecond) // beyond the context's deadline
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); n != 1 || err != nil {
		t.Fatalf("read after Negotiate: n=%d err=%v (the deadline was left on the connection)", n, err)
	}
}
