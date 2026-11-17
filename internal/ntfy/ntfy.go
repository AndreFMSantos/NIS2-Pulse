// Package ntfy sends push notifications through an ntfy server (https://ntfy.sh).
//
// The URL of the topic is a secret: anybody who knows it can read and publish,
// and it may carry credentials. It therefore comes from the environment or a
// file (never from an argument, which is visible in the process list), and this
// package never puts it in an error, a log line or a printed value; only the host
// is shown.
//
// The destination is chosen by the operator, not derived from audited data, so
// it may be a private address (a server on the LAN or on a VPN) and the
// public-address rule that protects the scanner does not apply. Redirects are
// still refused and every request has a time limit.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Limits of the ntfy API.
const (
	maxTitle = 250
	maxBody  = 4096
	maxTags  = 10
)

var (
	topicOK   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	segmentOK = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// Message is a notification.
type Message struct {
	Title    string
	Body     string
	Priority int // 1 (min) to 5 (max); out-of-range values are clamped
	Tags     []string
}

// Client publishes to one topic.
type Client struct {
	base     string // scheme://host[:port]/optional/prefix/ (no credentials)
	topic    string
	user     string
	password string
	hasAuth  bool
	host     string
	http     *http.Client
}

// New parses the URL of a topic, for example https://ntfy.sh/my-alerts or
// http://:tk_token@192.168.1.10:8080/my-alerts. Error messages never repeat the
// input.
func New(raw string) (*Client, error) {
	bad := func(why string) (*Client, error) { return nil, errors.New("ntfy: the topic URL is not valid: " + why) }
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return bad("it cannot be parsed")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return bad("the scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return bad("no host")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return bad("it must not have a query or a fragment")
	}
	path := u.EscapedPath()
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return bad("the path is not plain")
	}
	idx := strings.LastIndex(path, "/")
	topic := path[idx+1:]
	if idx < 0 || !topicOK.MatchString(topic) {
		return bad("it must end with a topic of letters, digits, _ or - (up to 64)")
	}
	c := &Client{topic: topic, host: u.Host}
	prefix := path[:idx+1]
	for _, seg := range strings.Split(strings.Trim(prefix, "/"), "/") {
		if seg != "" && !segmentOK.MatchString(seg) {
			return bad("the path is not plain")
		}
	}
	c.base = u.Scheme + "://" + u.Host + prefix
	if u.User != nil {
		c.hasAuth = true
		c.user = u.User.Username()
		c.password, _ = u.User.Password()
	}
	c.http = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// String shows the host only.
func (c *Client) String() string { return "ntfy(" + c.host + ")" }

// GoString shows the host only, so that %#v cannot leak the topic either.
func (c *Client) GoString() string { return c.String() }

// Send publishes m. A non-200 answer or a network error is returned without the
// URL, the credentials or the body of the reply.
func (c *Client) Send(ctx context.Context, m Message) error {
	if strings.TrimSpace(m.Title) == "" && strings.TrimSpace(m.Body) == "" {
		return errors.New("ntfy: refusing to send an empty notification")
	}
	prio := m.Priority
	if prio < 1 {
		prio = 1
	}
	if prio > 5 {
		prio = 5
	}
	tags := m.Tags
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	clean := make([]string, 0, len(tags))
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" {
			clean = append(clean, t)
		}
	}
	payload, err := json.Marshal(map[string]any{
		"topic":    c.topic,
		"title":    cut(m.Title, maxTitle),
		"message":  cut(m.Body, maxBody),
		"priority": prio,
		"tags":     clean,
	})
	if err != nil {
		return errors.New("ntfy: cannot encode the notification")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, bytes.NewReader(payload))
	if err != nil {
		return errors.New("ntfy: cannot build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nis2-pulse")
	if c.hasAuth {
		req.SetBasicAuth(c.user, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the URL; keep only the cause.
		var ue *url.Error
		reason := "request failed"
		if errors.As(err, &ue) && ue.Err != nil {
			reason = ue.Err.Error()
		}
		if ctx.Err() != nil {
			reason = ctx.Err().Error()
		}
		return fmt.Errorf("ntfy: sending to %s failed: %s", c.host, scrub(reason, c))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ntfy: %s answered HTTP %d", c.host, resp.StatusCode)
	}
	return nil
}

// scrub removes the secrets from a lower-level error text, just in case.
func scrub(s string, c *Client) string {
	for _, secret := range []string{c.topic, c.password} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "***")
		}
	}
	return s
}

// cut returns s limited to max bytes, never splitting a UTF-8 sequence.
func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && s[end]&0xC0 == 0x80 {
		end--
	}
	return s[:end]
}
