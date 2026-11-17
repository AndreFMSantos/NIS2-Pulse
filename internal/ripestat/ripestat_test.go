package ripestat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/ripestat"
)

// serve starts a fake RIPEstat answering each data call path with body.
func serve(t *testing.T, routes map[string]string) (*ripestat.Client, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &ripestat.Client{HTTP: srv.Client(), BaseURL: srv.URL}, &seen
}

func TestNetworkInfo(t *testing.T) {
	c, seen := serve(t, map[string]string{
		"/data/network-info/data.json": `{"status":"ok","data":{"asns":["3333","64496"],"prefix":"193.0.0.0/21"}}`,
	})
	got, err := c.NetworkInfo(context.Background(), "193.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "193.0.0.0/21" || len(got.ASNs) != 2 || got.ASNs[0] != "3333" {
		t.Fatalf("got %+v", got)
	}
	if want := "/data/network-info/data.json?resource=193.0.0.1"; (*seen)[0] != want {
		t.Errorf("request = %q, want %q", (*seen)[0], want)
	}
}

func TestNetworkInfoUnannounced(t *testing.T) {
	c, _ := serve(t, map[string]string{
		"/data/network-info/data.json": `{"status":"ok","data":{"asns":[],"prefix":""}}`,
	})
	got, err := c.NetworkInfo(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ASNs) != 0 || got.Prefix != "" {
		t.Fatalf("unannounced address should give an empty answer, got %+v", got)
	}
}

func TestRPKIStatuses(t *testing.T) {
	for _, status := range []string{"valid", "invalid_asn", "invalid_length", "unknown"} {
		c, seen := serve(t, map[string]string{
			"/data/rpki-validation/data.json": `{"status":"ok","data":{"status":"` + status + `","validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21","validity":"` + status + `","max_length":21}]}}`,
		})
		got, err := c.RPKI(context.Background(), "3333", "193.0.0.0/21")
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if string(got.State) != status {
			t.Errorf("state = %q, want %q", got.State, status)
		}
		if status != "unknown" && (len(got.ROAs) != 1 || got.ROAs[0].Origin != "3333" || got.ROAs[0].MaxLength != 21) {
			t.Errorf("%s: roas = %+v", status, got.ROAs)
		}
		if want := "/data/rpki-validation/data.json?prefix=193.0.0.0%2F21&resource=AS3333"; (*seen)[0] != want {
			t.Errorf("request = %q, want %q", (*seen)[0], want)
		}
	}
}

func TestRPKIRejectsUnexpectedState(t *testing.T) {
	c, _ := serve(t, map[string]string{
		"/data/rpki-validation/data.json": `{"status":"ok","data":{"status":"banana","validating_roas":[]}}`,
	})
	if _, err := c.RPKI(context.Background(), "3333", "193.0.0.0/21"); err == nil {
		t.Fatal("an unknown validation state must be an error, not a verdict")
	}
}

func TestGeo(t *testing.T) {
	c, _ := serve(t, map[string]string{
		"/data/maxmind-geo-lite/data.json": `{"status":"ok","data":{"located_resources":[{"resource":"193.0.0.1/32","locations":[{"country":"NL","city":"Amsterdam","resources":["193.0.0.0/20"],"covered_percentage":100.0}]}]}}`,
	})
	got, err := c.Geo(context.Background(), "193.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "NL" {
		t.Fatalf("countries = %v", got)
	}
}

func TestGeoNoLocation(t *testing.T) {
	c, _ := serve(t, map[string]string{
		"/data/maxmind-geo-lite/data.json": `{"status":"ok","data":{"located_resources":[{"resource":"203.0.113.5/32","locations":[]}]}}`,
	})
	got, err := c.Geo(context.Background(), "203.0.113.5")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; want no countries and no error", got, err)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]string{
		"api error status": `{"status":"error","messages":[["error","bad resource"]],"data":{}}`,
		"not json":         `<html>maintenance</html>`,
		"empty":            ``,
	}
	for name, body := range cases {
		c, _ := serve(t, map[string]string{"/data/network-info/data.json": body})
		if _, err := c.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHTTPErrorAndRedirect(t *testing.T) {
	c, _ := serve(t, map[string]string{}) // every path 404s
	if _, err := c.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
		t.Error("HTTP 404 must be an error")
	}

	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["1"],"prefix":"10.0.0.0/8"}}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	// redirect.Client() follows redirects by default; the ripestat client must override that.
	rc := &ripestat.Client{HTTP: redirect.Client(), BaseURL: redirect.URL}
	if _, err := rc.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
		t.Error("a redirect must be an error, not followed")
	}
	if hits != 0 {
		t.Errorf("the redirect target was contacted %d time(s)", hits)
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	big := `{"status":"ok","data":{"asns":["` + strings.Repeat("1", ripestat.MaxResponseBytes) + `"],"prefix":""}}`
	c, _ := serve(t, map[string]string{"/data/network-info/data.json": big})
	if _, err := c.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
		t.Fatal("a response larger than the limit must be rejected")
	}
}

func TestRejectsMalformedInput(t *testing.T) {
	c, seen := serve(t, map[string]string{})
	ctx := context.Background()
	if _, err := c.NetworkInfo(ctx, "not-an-ip"); err == nil {
		t.Error("NetworkInfo must reject a non-IP")
	}
	if _, err := c.Geo(ctx, "193.0.0.1&x=1"); err == nil {
		t.Error("Geo must reject a non-IP")
	}
	if _, err := c.RPKI(ctx, "3333; drop", "193.0.0.0/21"); err == nil {
		t.Error("RPKI must reject a malformed ASN")
	}
	if _, err := c.RPKI(ctx, "3333", "193.0.0.0/99"); err == nil {
		t.Error("RPKI must reject a malformed prefix")
	}
	if len(*seen) != 0 {
		t.Errorf("malformed input must not reach the network, saw %v", *seen)
	}
}

func TestGeoIgnoresCodesThatAreNotCountries(t *testing.T) {
	// MaxMind answers "?" for anycast addresses (seen for Cloudflare's 104.21.0.0/17).
	c, _ := serve(t, map[string]string{
		"/data/maxmind-geo-lite/data.json": `{"status":"ok","data":{"located_resources":[{"locations":[{"country":"?"},{"country":"pt"},{"country":"PT"},{"country":"<b>"},{"country":""}]}]}}`,
	})
	got, err := c.Geo(context.Background(), "104.21.81.250")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "PT" {
		t.Fatalf("countries = %v, want only [PT]", got)
	}
}

// flaky answers the first n requests with HTTP 500 and then with body.
func flaky(t *testing.T, n int, body string) (*ripestat.Client, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls <= n {
			http.Error(w, "busy", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &ripestat.Client{HTTP: srv.Client(), BaseURL: srv.URL}, &calls
}

const okNetwork = `{"status":"ok","data":{"asns":["3333"],"prefix":"193.0.0.0/21"}}`

func TestOneTransientFailureIsRetried(t *testing.T) {
	c, calls := flaky(t, 1, okNetwork)
	got, err := c.NetworkInfo(context.Background(), "193.0.0.1")
	if err != nil || got.Prefix != "193.0.0.0/21" {
		t.Fatalf("got %+v, %v; want success after one retry", got, err)
	}
	if *calls != 2 {
		t.Errorf("calls = %d, want 2", *calls)
	}
}

func TestRetryIsBoundedToOne(t *testing.T) {
	c, calls := flaky(t, 100, okNetwork)
	if _, err := c.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
		t.Fatal("expected an error")
	}
	if *calls != 2 {
		t.Errorf("calls = %d, want exactly 2 (one retry, never a loop)", *calls)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	c, _ := serve(t, map[string]string{}) // 404 for everything
	if _, err := c.NetworkInfo(context.Background(), "193.0.0.1"); err == nil {
		t.Fatal("expected an error")
	}
	// serve() records requests; a 404 must be tried once only.
	c2, seen := serve(t, map[string]string{})
	_, _ = c2.NetworkInfo(context.Background(), "193.0.0.1")
	if len(*seen) != 1 {
		t.Errorf("requests = %d, want 1 for HTTP 404", len(*seen))
	}
}

func TestRetryStopsWhenContextIsDone(t *testing.T) {
	c, calls := flaky(t, 100, okNetwork)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.NetworkInfo(ctx, "193.0.0.1"); err == nil {
		t.Fatal("expected an error")
	}
	if *calls > 1 {
		t.Errorf("calls = %d: a cancelled context must not be retried", *calls)
	}
}
