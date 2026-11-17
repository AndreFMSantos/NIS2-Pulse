// Package engine runs checks concurrently and enforces the safety model:
// a check of tier Active is never executed unless Options.Active is true.
package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
)

// DefaultCheckTimeout bounds a single check when Options.CheckTimeout is zero.
const DefaultCheckTimeout = 10 * time.Second

// Target is the domain being assessed, already normalised (lowercase ASCII,
// no trailing dot).
type Target struct {
	Domain string
}

// Deps are the injected collaborators of a check. Tests replace them with
// fakes so no check needs the network.
type Deps struct {
	DNS  dnsx.Resolver
	HTTP *http.Client
	// Dial opens raw TCP connections for active checks that speak their own
	// protocol (for example TLS probing). In production it comes from safenet
	// and refuses non-public addresses; checks must never dial by any other means.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RIPE queries RIPEstat for routing data. It is nil when the user passed
	// --no-routing; the routing check then reports unknown and sends nothing.
	RIPE *ripestat.Client
	Now  func() time.Time
}

// Check is one externally observable property to verify.
type Check interface {
	ID() string
	Area() finding.Area
	Tier() finding.Tier
	Run(ctx context.Context, t Target, d Deps) []finding.Finding
}

// Timeouter is implemented by checks that need more than DefaultCheckTimeout,
// for example a check that makes many connections in series.
type Timeouter interface {
	Timeout() time.Duration
}

// Options configure a run.
type Options struct {
	// Active permits checks of tier Active (the --active flag).
	Active bool
	// CheckTimeout bounds every check when positive (the user's --timeout wins
	// over everything). Zero means each check gets DefaultCheckTimeout, or the
	// longer time it asks for through Timeouter.
	CheckTimeout time.Duration
}

// timeoutFor returns the time limit of one check.
func timeoutFor(c Check, o Options) time.Duration {
	if o.CheckTimeout > 0 {
		return o.CheckTimeout
	}
	d := DefaultCheckTimeout
	if tc, ok := c.(Timeouter); ok && tc.Timeout() > d {
		d = tc.Timeout()
	}
	return d
}

// Run executes all checks concurrently and returns their findings in check
// order, so reports are deterministic. A failing, panicking, slow or empty
// check yields an unknown finding and never aborts the run.
func Run(ctx context.Context, t Target, checks []Check, d Deps, o Options) []finding.Finding {
	results := make([][]finding.Finding, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		if c.Tier() == finding.TierActive && !o.Active {
			results[i] = []finding.Finding{
				finding.Unknown(c.ID(), c.Area(), c.Tier(), "skipped: requires --active"),
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = runOne(ctx, c, t, d, timeoutFor(c, o))
		}()
	}
	wg.Wait()

	var out []finding.Finding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func runOne(ctx context.Context, c Check, t Target, d Deps, timeout time.Duration) []finding.Finding {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	unknown := func(detail string) []finding.Finding {
		return []finding.Finding{finding.Unknown(c.ID(), c.Area(), c.Tier(), detail)}
	}

	done := make(chan []finding.Finding, 1) // buffered: a late check must not block forever
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- unknown(fmt.Sprintf("check panicked: %v", r))
			}
		}()
		done <- c.Run(cctx, t, d)
	}()

	select {
	case r := <-done:
		if len(r) == 0 {
			return unknown("check returned no result")
		}
		return r
	case <-cctx.Done():
		if cctx.Err() == context.DeadlineExceeded {
			return unknown(fmt.Sprintf("check timed out after %s", timeout))
		}
		return unknown("check cancelled")
	}
}
