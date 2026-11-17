// Package ripestat is a small client for the RIPEstat Data API
// (https://stat.ripe.net/docs/data_api), used by the routing check.
//
// RIPEstat is a third party: every call tells it one public IP address, one
// ASN or one prefix of the audited domain. The client therefore only accepts
// well-formed IP addresses, ASNs and prefixes (nothing from a DNS answer is
// pasted into a URL unchecked), never follows redirects and bounds the size of
// what it reads. The HTTP client is injected: in production it comes from
// safehttp, in tests it points at a local fake.
package ripestat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public RIPEstat endpoint.
const DefaultBaseURL = "https://stat.ripe.net"

// MaxResponseBytes bounds how much of a response is read.
const MaxResponseBytes = 1 << 20

// Client talks to RIPEstat.
type Client struct {
	// HTTP performs the requests. Redirects are never followed, whatever its policy.
	HTTP *http.Client
	// BaseURL defaults to DefaultBaseURL.
	BaseURL string
}

// Network is the announcement that covers an address (data call network-info).
type Network struct {
	// ASNs are the origin ASNs announcing Prefix, without the "AS" prefix.
	// More than one means a multi-origin prefix. Empty means "not announced".
	ASNs   []string
	Prefix string
}

// State is the RPKI origin validation state of a (prefix, origin) pair,
// as defined by RFC 6811 (plus the reason RIPEstat gives for "invalid").
type State string

// RPKI states.
const (
	StateValid         State = "valid"
	StateInvalidASN    State = "invalid_asn"
	StateInvalidLength State = "invalid_length"
	// StateUnknown means no ROA covers the prefix ("not found" in RFC 6811).
	StateUnknown State = "unknown"
)

// ROA is a Route Origin Authorization that covers the validated prefix.
type ROA struct {
	Origin    string
	Prefix    string
	MaxLength int
	Validity  State
}

// Validation is the answer of the rpki-validation data call.
type Validation struct {
	State State
	ROAs  []ROA
}

// NetworkInfo returns the prefix and origin ASNs announcing ip.
func (c *Client) NetworkInfo(ctx context.Context, ip string) (Network, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return Network{}, fmt.Errorf("ripestat: %q is not an IP address", ip)
	}
	var data struct {
		ASNs   []json.Number `json:"asns"`
		Prefix string        `json:"prefix"`
	}
	if err := c.get(ctx, "network-info", url.Values{"resource": {ip}}, &data); err != nil {
		return Network{}, err
	}
	n := Network{Prefix: data.Prefix}
	for _, a := range data.ASNs {
		n.ASNs = append(n.ASNs, a.String())
	}
	if n.Prefix != "" {
		if _, err := netip.ParsePrefix(n.Prefix); err != nil {
			return Network{}, fmt.Errorf("ripestat: network-info returned a malformed prefix %q", n.Prefix)
		}
	}
	return n, nil
}

// RPKI validates the announcement of prefix by asn against the RPKI.
func (c *Client) RPKI(ctx context.Context, asn, prefix string) (Validation, error) {
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	if n, err := strconv.ParseUint(asn, 10, 32); err != nil || n == 0 {
		return Validation{}, fmt.Errorf("ripestat: %q is not an ASN", asn)
	}
	if _, err := netip.ParsePrefix(prefix); err != nil {
		return Validation{}, fmt.Errorf("ripestat: %q is not a prefix", prefix)
	}
	var data struct {
		Status string `json:"status"`
		ROAs   []struct {
			Origin    json.Number `json:"origin"`
			Prefix    string      `json:"prefix"`
			Validity  string      `json:"validity"`
			MaxLength int         `json:"max_length"`
		} `json:"validating_roas"`
	}
	q := url.Values{"resource": {"AS" + asn}, "prefix": {prefix}}
	if err := c.get(ctx, "rpki-validation", q, &data); err != nil {
		return Validation{}, err
	}
	state := State(data.Status)
	switch state {
	case StateValid, StateInvalidASN, StateInvalidLength, StateUnknown:
	default:
		return Validation{}, fmt.Errorf("ripestat: unexpected RPKI state %q", data.Status)
	}
	v := Validation{State: state}
	for _, r := range data.ROAs {
		v.ROAs = append(v.ROAs, ROA{Origin: r.Origin.String(), Prefix: r.Prefix, MaxLength: r.MaxLength, Validity: State(r.Validity)})
	}
	return v, nil
}

// Geo returns the countries (ISO 3166-1 alpha-2) a MaxMind GeoLite database
// associates with ip. The result is approximate and says nothing about where
// data is stored; an empty slice means the database has no location.
func (c *Client) Geo(ctx context.Context, ip string) ([]string, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return nil, fmt.Errorf("ripestat: %q is not an IP address", ip)
	}
	var data struct {
		Located []struct {
			Locations []struct {
				Country string `json:"country"`
			} `json:"locations"`
		} `json:"located_resources"`
	}
	if err := c.get(ctx, "maxmind-geo-lite", url.Values{"resource": {ip}}, &data); err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range data.Located {
		for _, l := range r.Locations {
			if isCountryCode(l.Country) && !seen[l.Country] {
				seen[l.Country] = true
				out = append(out, l.Country)
			}
		}
	}
	return out, nil
}

// isCountryCode accepts two upper-case ASCII letters. MaxMind answers "?" for
// anycast addresses, and nothing else from a third party is copied into a report.
func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// retryDelay is the pause before the single retry of a transient failure.
const retryDelay = 300 * time.Millisecond

// get performs one data call and decodes its "data" member into out. A
// transient failure (network error or HTTP 5xx) is retried exactly once.
func (c *Client) get(ctx context.Context, call string, q url.Values, out any) error {
	body, transient, err := c.fetch(ctx, call, q)
	if err != nil && transient && ctx.Err() == nil {
		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			return err
		}
		body, _, err = c.fetch(ctx, call, q)
	}
	if err != nil {
		return err
	}
	return decode(call, body, out)
}

// fetch performs one HTTP request and returns the body. transient says
// whether trying again could help.
func (c *Client) fetch(ctx context.Context, call string, q url.Values) (body []byte, transient bool, err error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u := base + "/data/" + call + "/data.json?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "nis2-pulse")
	// Work on a copy so that redirects are refused whatever the caller passed.
	hc := *c.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("ripestat %s: %w", call, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= 500, fmt.Errorf("ripestat %s: HTTP %d", call, resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("ripestat %s: %w", call, err)
	}
	if len(body) > MaxResponseBytes {
		return nil, false, fmt.Errorf("ripestat %s: response larger than %d bytes", call, MaxResponseBytes)
	}
	return body, false, nil
}

// decode checks the RIPEstat envelope and decodes its "data" member into out.
func decode(call string, body []byte, out any) error {
	var env struct {
		Status   string          `json:"status"`
		Messages [][]string      `json:"messages"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("ripestat %s: invalid JSON: %w", call, err)
	}
	if env.Status != "ok" {
		return fmt.Errorf("ripestat %s: %w", call, errors.New(apiMessage(env.Messages, env.Status)))
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("ripestat %s: unexpected data: %w", call, err)
	}
	return nil
}

func apiMessage(msgs [][]string, status string) string {
	for _, m := range msgs {
		if len(m) == 2 && m[0] == "error" {
			return m[1]
		}
	}
	return "status " + strconv.Quote(status)
}
