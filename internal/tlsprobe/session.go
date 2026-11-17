package tlsprobe

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"time"
)

const (
	// DefaultMaxConns is the most connections one Session opens. A typical
	// server needs about 20 (one per accepted suite plus one per version); the
	// cap stops a server that accepts every suite from being hammered.
	DefaultMaxConns = 150
	// DefaultProbeTimeout bounds one probe (connect, send, read the answer).
	DefaultProbeTimeout = 8 * time.Second
)

// ErrBudget is returned when a Session has used its connection budget.
var ErrBudget = errors.New("tls probe: connection budget exhausted")

// ProbeError says in which phase a probe failed: "connect" or "io".
type ProbeError struct {
	Phase string
	Err   error
}

func (e *ProbeError) Error() string { return "tls probe " + e.Phase + ": " + e.Err.Error() }

// Unwrap lets errors.Is and errors.As see the underlying network error.
func (e *ProbeError) Unwrap() error { return e.Err }

// Session sends probes to one target, counts connections and spaces them out.
// It is not safe for concurrent use: probes are deliberately sequential.
type Session struct {
	// Dial opens a connection ready for a ClientHello. For plain TLS it is a TCP
	// dial; for STARTTLS it also performs the SMTP greeting and STARTTLS command.
	Dial func(ctx context.Context) (net.Conn, error)
	// ServerName is sent as SNI.
	ServerName string
	// MaxConns is the connection budget; zero means DefaultMaxConns.
	MaxConns int
	// Delay is the pause between consecutive probes.
	Delay time.Duration
	// Timeout bounds one probe; zero means DefaultProbeTimeout.
	Timeout time.Duration
	// Sleep pauses for d or until ctx ends; nil means a real sleep.
	Sleep func(ctx context.Context, d time.Duration) error

	conns int
}

// Conns returns how many connections the session has opened (attempted).
func (s *Session) Conns() int { return s.conns }

func (s *Session) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Probe sends one ClientHello built from spec and returns the server's first
// answer. The session fills in the SNI, the random value and, for TLS 1.3, a
// real X25519 key share, so servers get a well-formed hello.
func (s *Session) Probe(ctx context.Context, spec Spec) (Response, error) {
	max := s.MaxConns
	if max <= 0 {
		max = DefaultMaxConns
	}
	if s.conns >= max {
		return Response{}, ErrBudget
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if s.conns > 0 && s.Delay > 0 {
		if err := s.sleep(ctx, s.Delay); err != nil {
			return Response{}, err
		}
	}
	s.conns++

	spec.ServerName = s.ServerName
	if _, err := rand.Read(spec.Random[:]); err != nil {
		return Response{}, err
	}
	if spec.Version == VersionTLS13 {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return Response{}, err
		}
		spec.KeyShare = key.PublicKey().Bytes()
		spec.SessionID = make([]byte, 32)
		if _, err := rand.Read(spec.SessionID); err != nil {
			return Response{}, err
		}
	}
	hello, err := BuildClientHello(spec)
	if err != nil {
		return Response{}, err
	}

	conn, err := s.Dial(ctx)
	if err != nil {
		return Response{}, &ProbeError{Phase: "connect", Err: err}
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // a cancelled scan must not wait for a slow server
	defer stop()

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(hello); err != nil {
		if isReset(err) {
			return Response{Kind: KindClosed}, nil // the server hung up on our hello
		}
		return Response{}, &ProbeError{Phase: "io", Err: err}
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		return Response{}, &ProbeError{Phase: "io", Err: err}
	}
	return resp, nil
}
