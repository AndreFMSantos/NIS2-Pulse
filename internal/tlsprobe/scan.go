package tlsprobe

import (
	"context"
	"errors"
)

// VersionResult is what a server accepts for one protocol version.
type VersionResult struct {
	Version   uint16
	Supported bool
	// Ciphers are the suites the server accepted, in the order it chose them
	// (its preference, when it enforces one).
	Ciphers []uint16
}

// Report is the outcome of a Scan.
type Report struct {
	// Versions has one entry per protocol version, SSLv3 first, TLS 1.3 last.
	Versions []VersionResult
	// Conns is the number of connections used.
	Conns int
	// Incomplete means the result may miss something: the connection budget ran
	// out, a probe timed out or was cut, the context ended, or the server
	// answered inconsistently.
	Incomplete bool
	// NotTLS explains why, if the port answered with something that is not TLS.
	NotTLS string
}

// Supported returns the accepted protocol versions, oldest first.
func (r *Report) Supported() []uint16 {
	var out []uint16
	for _, v := range r.Versions {
		if v.Supported {
			out = append(out, v.Version)
		}
	}
	return out
}

// Scan discovers which protocol versions and cipher suites a server accepts.
//
// For each version it offers every suite, notes the one the server picks,
// removes it from the offer and asks again until the server refuses: that
// costs one connection per accepted suite plus one per version, instead of one
// per suite in the registry. The first probe that cannot even connect returns
// an error; later failures only mark the report incomplete.
func Scan(ctx context.Context, s *Session) (*Report, error) {
	rep := &Report{}
	byVersion := map[uint16]*VersionResult{}

	finish := func() *Report {
		for _, v := range []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13} {
			vr := byVersion[v]
			if vr == nil {
				vr = &VersionResult{Version: v}
			}
			rep.Versions = append(rep.Versions, *vr)
		}
		rep.Conns = s.Conns()
		return rep
	}
	anySupported := func() bool {
		for _, vr := range byVersion {
			if vr.Supported {
				return true
			}
		}
		return false
	}

	// TLS 1.2 first: it is accepted almost everywhere, so a port that does not
	// speak TLS is recognised after a single connection.
versions:
	for _, v := range []uint16{VersionTLS12, VersionTLS13, VersionTLS11, VersionTLS10, VersionSSL30} {
		vr := &VersionResult{Version: v}
		byVersion[v] = vr
		offered := offeredFor(v)

		for len(offered) > 0 {
			resp, err := s.Probe(ctx, Spec{Version: v, Ciphers: withSCSV(v, offered)})
			if err != nil {
				switch {
				case errors.Is(err, ErrBudget):
					rep.Incomplete = true
					return finish(), nil
				case ctx.Err() != nil:
					rep.Incomplete = true
					return finish(), ctx.Err()
				case s.Conns() == 1:
					return nil, err // the very first probe failed: nothing was learned
				}
				rep.Incomplete = true
				var pe *ProbeError
				if errors.As(err, &pe) && pe.Phase == "connect" {
					return finish(), nil // the server stopped accepting connections: do not hammer it
				}
				continue versions // a timeout or a cut stream: give up on this version only
			}

			switch resp.Kind {
			case KindServerHello, KindHelloRetryRequest:
				if resp.Version != v {
					continue versions // the server answered with another version: v itself is refused
				}
				if !contains(offered, resp.Cipher) {
					rep.Incomplete = true // chose something we did not offer: do not trust the loop
					continue versions
				}
				vr.Supported = true
				vr.Ciphers = append(vr.Ciphers, resp.Cipher)
				offered = remove(offered, resp.Cipher)
			case KindNotTLS:
				if !anySupported() {
					rep.NotTLS = resp.Detail
					return finish(), nil
				}
				continue versions
			default: // alert or closed: the server has nothing more to accept at this version
				continue versions
			}
		}
	}
	return finish(), nil
}

// offeredFor returns the suites to offer for version v.
func offeredFor(v uint16) []uint16 {
	if v == VersionTLS13 {
		return TLS13Suites()
	}
	return LegacySuites()
}

// withSCSV adds the renegotiation signalling value that SSLv3 to TLS 1.2
// hellos carry in place of the renegotiation_info extension.
func withSCSV(v uint16, suites []uint16) []uint16 {
	out := append([]uint16(nil), suites...)
	if v != VersionTLS13 {
		out = append(out, SCSVRenegotiation)
	}
	return out
}

func contains(list []uint16, x uint16) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func remove(list []uint16, x uint16) []uint16 {
	out := make([]uint16, 0, len(list))
	for _, v := range list {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
