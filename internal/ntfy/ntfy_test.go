package ntfy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/ntfy"
)

type captured struct {
	method, path, ctype, auth string
	body                      map[string]any
	raw                       string
}

func server(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got.method, got.path, got.ctype, got.auth, got.raw = r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), string(raw)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `{"error":"secret-topic-name-in-the-reply"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestSendPublishesJSONToTheServerRoot(t *testing.T) {
	srv, got := server(t, 200)
	c, err := ntfy.New(srv.URL + "/my-alerts")
	if err != nil {
		t.Fatal(err)
	}
	err = c.Send(context.Background(), ntfy.Message{Title: "nis2-pulse: exemplo.pt: 1 a piorar", Body: "Registo DMARC (email.dmarc.present): falha, alta", Priority: 4, Tags: []string{"warning"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" || got.path != "/" || !strings.HasPrefix(got.ctype, "application/json") {
		t.Errorf("request = %+v", got)
	}
	if got.body["topic"] != "my-alerts" || got.body["title"] != "nis2-pulse: exemplo.pt: 1 a piorar" || got.body["priority"] != float64(4) {
		t.Errorf("payload = %v", got.body)
	}
	if !strings.Contains(got.raw, "falha, alta") {
		t.Errorf("UTF-8 text must go through intact: %s", got.raw)
	}
	if got.auth != "" {
		t.Errorf("no credentials were configured, but Authorization = %q", got.auth)
	}
}

func TestSendKeepsASubPathOfTheServer(t *testing.T) {
	srv, got := server(t, 200)
	c, err := ntfy.New(srv.URL + "/notify/prefix/topic_1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), ntfy.Message{Title: "t", Body: "b", Priority: 3}); err != nil {
		t.Fatal(err)
	}
	if got.path != "/notify/prefix/" || got.body["topic"] != "topic_1" {
		t.Errorf("path = %q topic = %v", got.path, got.body["topic"])
	}
}

func TestCredentialsInTheURLBecomeBasicAuthAndTokensWork(t *testing.T) {
	srv, got := server(t, 200)
	hostPort := strings.TrimPrefix(srv.URL, "http://")
	for name, tc := range map[string]struct{ url, want string }{
		"user and password": {"http://andre:s3cret@" + hostPort + "/t", "Basic YW5kcmU6czNjcmV0"}, // andre:s3cret
		"token only":        {"http://:tk_abc123@" + hostPort + "/t", "Basic OnRrX2FiYzEyMw=="},   // :tk_abc123
	} {
		c, err := ntfy.New(tc.url)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Send(context.Background(), ntfy.Message{Title: "t", Body: "b", Priority: 3}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.auth != tc.want {
			t.Errorf("%s: Authorization = %q, want %q", name, got.auth, tc.want)
		}
	}
}

func TestNewRejectsWhatIsNotATopicURL(t *testing.T) {
	for _, bad := range []string{
		"", "ntfy.sh/topic", "ftp://ntfy.sh/topic", "file:///etc/passwd", "javascript:alert(1)", "http:///topic", "https://ntfy.sh", "https://ntfy.sh/",
		"https://ntfy.sh/topic?auth=x", "https://ntfy.sh/topic#frag", "https://ntfy.sh/to pic", "https://ntfy.sh/topic/../x", "https://ntfy.sh/" + strings.Repeat("a", 65),
	} {
		if _, err := ntfy.New(bad); err == nil {
			t.Errorf("New(%q) must be refused", bad)
		}
	}
}

// The topic and the credentials are the secret: they must not appear in any error
// or printed representation.
func TestTheSecretNeverLeaks(t *testing.T) {
	const topic, pass = "very-secret-topic-9f3", "hunter2-password"
	check := func(what, s string) {
		for _, secret := range []string{topic, pass} {
			if strings.Contains(s, secret) {
				t.Errorf("%s leaks %q: %s", what, secret, s)
			}
		}
	}
	// Bad URLs: the message may not echo the input.
	for _, bad := range []string{"ftp://u:" + pass + "@h/" + topic, "https://u:" + pass + "@h/" + topic + "?x=1", "https://u:" + pass + "@h/" + topic + "/../x"} {
		_, err := ntfy.New(bad)
		if err == nil {
			t.Fatalf("New(%q) should fail", bad)
		}
		check("New error", err.Error())
	}
	// Unreachable server.
	c, err := ntfy.New("http://u:" + pass + "@127.0.0.1:1/" + topic)
	if err != nil {
		t.Fatal(err)
	}
	check("String()", c.String())
	check("%v", fmt.Sprintf("%v", c))
	check("%+v", fmt.Sprintf("%+v", c))
	check("%#v", fmt.Sprintf("%#v", c))
	check("Sprint", fmt.Sprint(c))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Send(ctx, ntfy.Message{Title: "t", Body: "b", Priority: 3}); err == nil {
		t.Fatal("sending to a closed port must fail")
	} else {
		check("transport error", err.Error())
	}
	// Server errors: the reply body (which here repeats the topic) is not echoed either.
	srv, _ := server(t, 403)
	c2, _ := ntfy.New("http://u:" + pass + "@" + strings.TrimPrefix(srv.URL, "http://") + "/" + topic)
	err = c2.Send(context.Background(), ntfy.Message{Title: "t", Body: "b", Priority: 3})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("HTTP 403 must be an error that names the status: %v", err)
	}
	check("HTTP error", err.Error())
	check("reply body", err.Error()+"secret-topic-name-in-the-reply")
	if strings.Contains(err.Error(), "secret-topic-name-in-the-reply") {
		t.Error("the server reply must not be echoed")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	c, _ := ntfy.New(redir.URL + "/t")
	if err := c.Send(context.Background(), ntfy.Message{Title: "t", Body: "b", Priority: 3}); err == nil {
		t.Error("a redirect must be an error")
	}
	if hits != 0 {
		t.Errorf("the redirect target was contacted %d time(s)", hits)
	}
}

func TestSendRespectsTheContextAndAnInternalTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // the server only notices a closed connection after the body was read
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	c, _ := ntfy.New(slow.URL + "/t")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Send(ctx, ntfy.Message{Title: "t", Body: "b", Priority: 3}); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Send took %s: it must give up with the context", time.Since(start))
	}
}

func TestSendClampsAndBoundsTheMessage(t *testing.T) {
	srv, got := server(t, 200)
	c, _ := ntfy.New(srv.URL + "/t")
	long := strings.Repeat("x", 10000)
	if err := c.Send(context.Background(), ntfy.Message{Title: long, Body: long, Priority: 99, Tags: make([]string, 50)}); err != nil {
		t.Fatal(err)
	}
	if p := got.body["priority"]; p != float64(5) {
		t.Errorf("priority = %v, want clamped to 5", p)
	}
	if len(got.body["message"].(string)) > 4096 || len(got.body["title"].(string)) > 250 {
		t.Errorf("message %d bytes, title %d bytes: over ntfy's limits", len(got.body["message"].(string)), len(got.body["title"].(string)))
	}
	if tags, _ := got.body["tags"].([]any); len(tags) > 10 {
		t.Errorf("%d tags sent", len(tags))
	}
	if err := c.Send(context.Background(), ntfy.Message{Title: "t", Body: "b", Priority: -3}); err != nil {
		t.Fatal(err)
	}
	if p := got.body["priority"]; p != float64(1) {
		t.Errorf("priority = %v, want clamped to 1", p)
	}
}

func TestSendRefusesAnEmptyMessage(t *testing.T) {
	srv, got := server(t, 200)
	c, _ := ntfy.New(srv.URL + "/t")
	if err := c.Send(context.Background(), ntfy.Message{}); err == nil {
		t.Error("an empty notification is a bug, not something to send")
	}
	if got.method != "" {
		t.Error("nothing may reach the server")
	}
}
