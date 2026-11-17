// Package safehttp builds the only HTTP client that active checks may use.
//
// Connections go through safenet, which resolves host names itself and refuses
// non-public addresses (see its documentation for the SSRF rationale). On top
// of that this client:
//
//   - never follows redirects (a redirect can lead anywhere);
//   - verifies certificates (TLS 1.2 or later) and never skips verification;
//   - ignores proxy environment variables, opens no persistent connections
//     and bounds the size of response headers.
package safehttp

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/safenet"
)

// ErrNonPublicAddress is returned when a host resolves to an address that is
// not on the public Internet. The client never connects in that case.
var ErrNonPublicAddress = safenet.ErrNonPublicAddress

// Options configure New.
type Options struct {
	// Resolver resolves host names (A and AAAA). Required.
	Resolver dnsx.Resolver
	// Timeout bounds one whole request, including connecting and reading.
	Timeout time.Duration

	// Unexported: tests need to reach a loopback server with a private CA.
	allowNonPublic bool
	rootCAs        *x509.CertPool
}

// New returns a client following the rules in the package documentation.
func New(o Options) *http.Client {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	dialer := &safenet.Dialer{Resolver: o.Resolver, AllowNonPublic: o.allowNonPublic}
	tr := &http.Transport{
		Proxy:                  nil, // never route through a proxy named in the environment
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.rootCAs},
		TLSHandshakeTimeout:    5 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
