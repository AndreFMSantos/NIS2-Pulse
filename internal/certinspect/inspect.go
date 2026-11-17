// Package certinspect reads the certificate chain a TLS server presents and
// judges it.
//
// Reading a broken certificate (expired, self-signed, for another name) needs
// a connection that does not refuse it, so this package completes the TLS
// handshake with certificate verification switched off. That is a deliberate,
// narrow exception to the project rule "never skip verification", and it is
// made safe by four conditions, each enforced by a test:
//
//   - it lives only in this file: a test fails if any other production file
//     mentions the option that disables verification;
//   - the connection is used only to read the chain: the inspector sends no
//     application data, only the handshake and the closing alert (plus the
//     caller's Farewell, which exists for SMTP's QUIT and is empty for HTTPS);
//   - verification is not skipped, it is done here, with x509.Verify, and its
//     outcome is always part of the Result: a certificate that does not verify
//     can never vanish silently;
//   - nothing learned from an unverified connection is trusted.
package certinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// TrustKind classifies whether the presented chain is trusted.
type TrustKind string

// Trust kinds.
const (
	// TrustOK: the chain verifies against the trust store.
	TrustOK TrustKind = "ok"
	// TrustSelfSigned: the server presents a self-signed certificate.
	TrustSelfSigned TrustKind = "self-signed"
	// TrustUntrustedRoot: the chain ends in a root that is not in the trust store.
	TrustUntrustedRoot TrustKind = "untrusted-root"
	// TrustUnknownIssuer: the issuer of the last certificate sent is not in the
	// trust store: either the server omits an intermediate or the CA is not trusted.
	TrustUnknownIssuer TrustKind = "unknown-issuer"
	// TrustOther: the chain fails to verify for another reason (see Detail).
	TrustOther TrustKind = "other"
)

// Trust is the verdict on the chain, independent of time and of the host name.
type Trust struct {
	Kind   TrustKind
	Detail string
}

// TimeProblem names a certificate of the chain that is outside its validity.
type TimeProblem struct {
	Subject   string
	Expired   bool // false means "not yet valid"
	NotBefore time.Time
	NotAfter  time.Time
}

// Result is everything learned from one handshake.
type Result struct {
	// ServerName is the name the leaf was checked against.
	ServerName string
	// Chain is the chain as the server presented it, leaf first.
	Chain []*x509.Certificate
	// TLSVersion and CipherSuite are what the handshake negotiated.
	TLSVersion  uint16
	CipherSuite uint16
	// Trust says whether the chain leads to a trusted root, ignoring time.
	Trust Trust
	// Time is the first certificate (leaf first) outside its validity, or nil.
	// Time problems are judged on their own so they neither hide nor duplicate
	// a trust problem: Go's verifier stops at an expired certificate without
	// saying whether the rest of the chain would have been trusted.
	Time *TimeProblem
	// Hostname is nil when the leaf is valid for ServerName.
	Hostname error
	// VerifiedChains are the chains x509.Verify built, when Trust is TrustOK.
	VerifiedChains [][]*x509.Certificate
}

// HandshakeError reports that a connection was made but the TLS handshake
// could not be completed (the port does not speak TLS, no common version or
// suite, a reset...). It is different from a failure to connect at all.
type HandshakeError struct{ Err error }

func (e *HandshakeError) Error() string { return "TLS handshake failed: " + e.Err.Error() }

// Unwrap lets errors.Is and errors.As see the underlying error.
func (e *HandshakeError) Unwrap() error { return e.Err }

// Options configure Inspect.
type Options struct {
	// Dial opens the connection (through the safe dialer in production).
	Dial func(ctx context.Context) (net.Conn, error)
	// ServerName is sent as SNI and checked against the leaf.
	ServerName string
	// Roots is the trust store; nil means the system roots.
	Roots *x509.CertPool
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Timeout bounds the whole inspection; zero means 10 seconds.
	Timeout time.Duration
	// Farewell is written once, inside the tunnel, right after the handshake and
	// before the closing alert. Protocols that upgrade to TLS (SMTP STARTTLS) use
	// it to say goodbye properly ("QUIT\r\n") instead of hanging up mid-session.
	// Nil, as for HTTPS, means that nothing at all is sent.
	Farewell []byte
}

// Inspect completes one TLS handshake and judges the chain presented. It
// returns an error only when no handshake could be completed.
func Inspect(ctx context.Context, o Options) (*Result, error) {
	if o.Dial == nil {
		return nil, errors.New("certinspect: no dialer")
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	conn, err := o.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		ServerName: o.ServerName,
		MinVersion: tls.VersionTLS10, // an old server must still be inspectable
		// INTENTIONAL: InsecureSkipVerify is set so that the handshake completes
		// even for a certificate that would not verify. We verify below ourselves
		// and always report the outcome; see the package documentation.
		InsecureSkipVerify: true,
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, &HandshakeError{Err: err}
	}
	cs := tc.ConnectionState()
	if len(o.Farewell) > 0 {
		_, _ = tc.Write(o.Farewell) // best effort: the certificate has been read already
	}
	_ = tc.Close() // sends the closing alert

	chain := cs.PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("certinspect: the server presented no certificate")
	}
	res := &Result{ServerName: o.ServerName, Chain: chain, TLSVersion: cs.Version, CipherSuite: cs.CipherSuite}

	current := now()
	res.Time = timeProblem(chain, current)
	at := current
	if res.Time != nil {
		at = verificationTime(chain)
	}
	res.Trust, res.VerifiedChains = verifyTrust(chain, o.Roots, at)
	res.Hostname = chain[0].VerifyHostname(o.ServerName)
	return res, nil
}

func subject(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// timeProblem returns the first certificate of the chain outside its validity.
func timeProblem(chain []*x509.Certificate, now time.Time) *TimeProblem {
	for _, c := range chain {
		switch {
		case now.Before(c.NotBefore):
			return &TimeProblem{Subject: subject(c), Expired: false, NotBefore: c.NotBefore, NotAfter: c.NotAfter}
		case now.After(c.NotAfter):
			return &TimeProblem{Subject: subject(c), Expired: true, NotBefore: c.NotBefore, NotAfter: c.NotAfter}
		}
	}
	return nil
}

// verificationTime picks a moment at which every presented certificate was
// valid, so that trust can be judged separately from time. If the certificates
// never overlapped, the leaf's own start is used.
func verificationTime(chain []*x509.Certificate) time.Time {
	latestStart, earliestEnd := chain[0].NotBefore, chain[0].NotAfter
	for _, c := range chain[1:] {
		if c.NotBefore.After(latestStart) {
			latestStart = c.NotBefore
		}
		if c.NotAfter.Before(earliestEnd) {
			earliestEnd = c.NotAfter
		}
	}
	if latestStart.Before(earliestEnd) {
		return latestStart.Add(time.Second)
	}
	return chain[0].NotBefore.Add(time.Second)
}

func verifyTrust(chain []*x509.Certificate, roots *x509.CertPool, at time.Time) (Trust, [][]*x509.Certificate) {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	verified, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err == nil {
		return Trust{Kind: TrustOK}, verified
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return classifyUnknownAuthority(chain), nil
	}
	return Trust{Kind: TrustOther, Detail: err.Error()}, nil
}

func classifyUnknownAuthority(chain []*x509.Certificate) Trust {
	leaf, top := chain[0], chain[len(chain)-1]
	switch {
	case len(chain) == 1 && selfSigned(leaf):
		return Trust{Kind: TrustSelfSigned, Detail: "the server presents a self-signed certificate: nobody vouches for it"}
	case selfSigned(top):
		return Trust{Kind: TrustUntrustedRoot,
			Detail: fmt.Sprintf("the chain ends in the root %q, which is not in the trust store", subject(top))}
	case len(chain) == 1:
		return Trust{Kind: TrustUnknownIssuer,
			Detail: fmt.Sprintf("the server sends only its own certificate and its issuer %q is not trusted: if the CA is a public one, the server is missing the intermediate certificate in its chain", top.Issuer.CommonName)}
	}
	return Trust{Kind: TrustUnknownIssuer,
		Detail: fmt.Sprintf("the issuer %q of the last certificate sent (%q) is not in the trust store: the server may be missing an intermediate certificate, or the CA is not trusted", top.Issuer.CommonName, subject(top))}
}

// selfSigned reports whether c names itself as issuer and carries a valid
// signature by its own key. CheckSignatureFrom is not used because it demands
// that the signer be a CA, which a self-signed leaf is not.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
