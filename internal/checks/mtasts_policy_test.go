package checks_test

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

const (
	mtFetch  = "email.mtasts.fetch"
	mtMode   = "email.mtasts.mode"
	mtMX     = "email.mtasts.mx"
	mtMaxAge = "email.mtasts.maxage"
)

func TestMTASTSPolicy(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    map[string]finding.Status
		missing []string // findings that must NOT be produced
	}{
		{
			name: "enforce, covered MX, long max_age",
			body: goodPolicy,
			want: map[string]finding.Status{mtFetch: finding.StatusPass, mtMode: finding.StatusPass, mtMX: finding.StatusPass, mtMaxAge: finding.StatusPass},
		},
		{
			name: "testing mode only reports problems",
			body: "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMode: finding.StatusWarn},
		},
		{
			name: "mode none disables the policy",
			body: "version: STSv1\nmode: none\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMode: finding.StatusWarn},
		},
		{
			name: "MX not covered in enforce mode loses mail",
			body: "version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMX: finding.StatusFail},
		},
		{
			name: "MX not covered in testing mode is only a warning",
			body: "version: STSv1\nmode: testing\nmx: other.example.net\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMX: finding.StatusWarn},
		},
		{
			name: "wildcard matches exactly one label",
			body: "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMX: finding.StatusPass},
		},
		{
			name: "several mx lines are all honoured",
			body: "version: STSv1\nmode: enforce\nmx: backup.example.net\nmx: mail.example.com\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMX: finding.StatusPass},
		},
		{
			name: "host names compare case-insensitively and ignore a trailing dot",
			body: "version: STSv1\nmode: enforce\nmx: MAIL.Example.COM.\nmax_age: 604800\n",
			want: map[string]finding.Status{mtMX: finding.StatusPass},
		},
		{
			name: "short max_age gives almost no downgrade protection",
			body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 3600\n",
			want: map[string]finding.Status{mtMaxAge: finding.StatusWarn},
		},
		{
			name: "CRLF line endings are accepted",
			body: "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n",
			want: map[string]finding.Status{mtFetch: finding.StatusPass, mtMode: finding.StatusPass},
		},
		{
			name: "unknown keys are ignored",
			body: goodPolicy + "x-future: whatever\n",
			want: map[string]finding.Status{mtFetch: finding.StatusPass},
		},
		{
			name:    "wrong version",
			body:    "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
			want:    map[string]finding.Status{mtFetch: finding.StatusFail},
			missing: []string{mtMode, mtMX, mtMaxAge},
		},
		{
			name:    "unknown mode",
			body:    "version: STSv1\nmode: banana\nmx: mail.example.com\nmax_age: 604800\n",
			want:    map[string]finding.Status{mtFetch: finding.StatusFail},
			missing: []string{mtMode},
		},
		{
			name:    "missing max_age",
			body:    "version: STSv1\nmode: enforce\nmx: mail.example.com\n",
			want:    map[string]finding.Status{mtFetch: finding.StatusFail},
			missing: []string{mtMode},
		},
		{
			name:    "max_age is not a number",
			body:    "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: soon\n",
			want:    map[string]finding.Status{mtFetch: finding.StatusFail},
			missing: []string{mtMode},
		},
		{
			name:    "enforce without any mx",
			body:    "version: STSv1\nmode: enforce\nmax_age: 604800\n",
			want:    map[string]finding.Status{mtFetch: finding.StatusFail},
			missing: []string{mtMode},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pki := newPKI(t)
			ps := startPolicy(t, pki.validLeaf(t), pki.pool, policyBody(tt.body))

			got := runPolicy(t, mtastsDNS(), ps.client)

			wantStatuses(t, got, tt.want)
			for _, id := range tt.missing {
				for _, f := range got {
					if f.ID == id {
						t.Errorf("finding %s must not be produced for an unusable policy, got %+v", id, f)
					}
				}
			}
		})
	}
}

func TestMTASTSWildcardDoesNotMatchDeeperNames(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
	f.Add(dnsxtest.MX("example.com", 10, "a.b.example.com"))
	pki := newPKI(t)
	ps := startPolicy(t, pki.validLeaf(t), pki.pool,
		policyBody("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n"))

	got := runPolicy(t, f, ps.client)

	mx := get(t, got, mtMX)
	if mx.Status != finding.StatusFail || len(mx.Evidence) == 0 || !strings.Contains(strings.Join(mx.Evidence, " "), "a.b.example.com") {
		t.Fatalf("*.example.com must not cover a.b.example.com, and the uncovered host must be listed, got %+v", mx)
	}
}

func TestMTASTSWildcardDoesNotMatchTheApex(t *testing.T) {
	f := dnsxtest.New()
	f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
	f.Add(dnsxtest.MX("example.com", 10, "example.com"))
	pki := newPKI(t)
	ps := startPolicy(t, pki.validLeaf(t), pki.pool,
		policyBody("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n"))

	if mx := get(t, runPolicy(t, f, ps.client), mtMX); mx.Status != finding.StatusFail {
		t.Fatalf("*.example.com must not cover example.com itself, got %+v", mx)
	}
}

func TestMTASTSPolicyRequestShape(t *testing.T) {
	pki := newPKI(t)
	ps := startPolicy(t, pki.validLeaf(t), pki.pool, policyBody(goodPolicy))

	_ = runPolicy(t, mtastsDNS(), ps.client)

	host, path, method := ps.request()
	if host != "mta-sts.example.com" || path != "/.well-known/mta-sts.txt" || method != http.MethodGet {
		t.Fatalf("request = %s https://%s%s; want GET https://mta-sts.example.com/.well-known/mta-sts.txt", method, host, path)
	}
	if n := ps.hits.Load(); n != 1 {
		t.Fatalf("exactly one request is allowed per scan, got %d", n)
	}
}

func TestMTASTSPolicyHTTPProblems(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    finding.Status
		detail  string
	}{
		{"404", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, finding.StatusFail, "404"},
		{"500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, finding.StatusFail, "500"},
		{"redirect is never followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example.net/policy", http.StatusMovedPermanently)
		}, finding.StatusFail, "redirect"},
		{"policy larger than 64 KiB", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(goodPolicy + strings.Repeat("x-pad: "+strings.Repeat("a", 100)+"\n", 800)))
		}, finding.StatusFail, "64"},
		{"wrong content type is a warning", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(goodPolicy))
		}, finding.StatusWarn, "text/plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pki := newPKI(t)
			ps := startPolicy(t, pki.validLeaf(t), pki.pool, tt.handler)

			got := runPolicy(t, mtastsDNS(), ps.client)

			fetch := get(t, got, mtFetch)
			if fetch.Status != tt.want || !strings.Contains(strings.ToLower(fetch.Detail), strings.ToLower(tt.detail)) {
				t.Fatalf("fetch = %+v, want status %s with detail containing %q", fetch, tt.want, tt.detail)
			}
			if ps.hits.Load() != 1 {
				t.Errorf("hits = %d, want 1 (a redirect must not be followed)", ps.hits.Load())
			}
		})
	}
}

func TestMTASTSPolicyCertificateProblems(t *testing.T) {
	pki, otherPKI := newPKI(t), newPKI(t)
	soon := time.Now().Add(time.Hour)

	t.Run("certificate from an untrusted authority", func(t *testing.T) {
		ps := startPolicy(t, otherPKI.validLeaf(t), pki.pool, policyBody(goodPolicy))
		fetch := get(t, runPolicy(t, mtastsDNS(), ps.client), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "trusted") {
			t.Fatalf("got %+v", fetch)
		}
	})
	t.Run("certificate for another host name", func(t *testing.T) {
		cert := pki.leaf(t, []string{"www.example.org"}, time.Now().Add(-time.Hour), soon)
		ps := startPolicy(t, cert, pki.pool, policyBody(goodPolicy))
		fetch := get(t, runPolicy(t, mtastsDNS(), ps.client), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "mta-sts.example.com") {
			t.Fatalf("got %+v", fetch)
		}
	})
	t.Run("expired certificate", func(t *testing.T) {
		cert := pki.leaf(t, []string{"mta-sts.example.com"}, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		ps := startPolicy(t, cert, pki.pool, policyBody(goodPolicy))
		fetch := get(t, runPolicy(t, mtastsDNS(), ps.client), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "expired") {
			t.Fatalf("got %+v", fetch)
		}
	})
	t.Run("certificate not yet valid", func(t *testing.T) {
		cert := pki.leaf(t, []string{"mta-sts.example.com"}, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
		ps := startPolicy(t, cert, pki.pool, policyBody(goodPolicy))
		fetch := get(t, runPolicy(t, mtastsDNS(), ps.client), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "not yet valid") {
			t.Fatalf("got %+v", fetch)
		}
	})
}

func TestMTASTSPolicyConnectionProblems(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close() // nothing listens any more
		fetch := get(t, runPolicy(t, mtastsDNS(), clientTo(addr, newPKI(t).pool)), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "refused") {
			t.Fatalf("a published MTA-STS record with nothing on port 443 is a real problem, got %+v", fetch)
		}
	})
	t.Run("timeout is unknown, not a verdict", func(t *testing.T) {
		pki := newPKI(t)
		ps := startPolicy(t, pki.validLeaf(t), pki.pool, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(600 * time.Millisecond)
		})
		ps.client.Timeout = 100 * time.Millisecond

		fetch := get(t, runPolicy(t, mtastsDNS(), ps.client), mtFetch)

		if fetch.Status != finding.StatusUnknown {
			t.Fatalf("a slow network says nothing about the domain, got %+v", fetch)
		}
	})
	t.Run("host that does not resolve", func(t *testing.T) {
		c := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "mta-sts.example.com", IsNotFound: true}
		})}
		fetch := get(t, runPolicy(t, mtastsDNS(), c), mtFetch)
		if fetch.Status != finding.StatusFail || !strings.Contains(fetch.Detail, "does not resolve") {
			t.Fatalf("got %+v", fetch)
		}
	})
	t.Run("non-public address is refused and reported as unknown", func(t *testing.T) {
		c := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errNonPublic()
		})}
		fetch := get(t, runPolicy(t, mtastsDNS(), c), mtFetch)
		if fetch.Status != finding.StatusUnknown || !strings.Contains(fetch.Detail, "non-public") {
			t.Fatalf("the safety stop must be explained and must not accuse the domain, got %+v", fetch)
		}
	})
}

func TestMTASTSPolicyNeverConnectsWithoutAPublishedRecord(t *testing.T) {
	pki := newPKI(t)
	cases := map[string]func(f *dnsxtest.Fake){
		"no TXT record": func(f *dnsxtest.Fake) { f.Add(dnsxtest.MX("example.com", 10, "mail.example.com")) },
		"no MX":         func(f *dnsxtest.Fake) { f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1")) },
		"null MX": func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
			f.Add(dnsxtest.MX("example.com", 0, "."))
		},
		"two records are ambiguous": func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=1"))
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "v=STSv1; id=2"))
		},
		"TXT is not MTA-STS": func(f *dnsxtest.Fake) {
			f.Add(dnsxtest.MX("example.com", 10, "mail.example.com"))
			f.Add(dnsxtest.TXT("_mta-sts.example.com", "unrelated"))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			ps := startPolicy(t, pki.validLeaf(t), pki.pool, policyBody(goodPolicy))
			f := dnsxtest.New()
			setup(f)

			got := runPolicy(t, f, ps.client)

			if n := ps.hits.Load(); n != 0 {
				t.Fatalf("connected to the target %d time(s) although the domain does not claim MTA-STS", n)
			}
			if len(got) != 1 || got[0].Status != finding.StatusInfo {
				t.Fatalf("want a single info finding, got %+v", got)
			}
		})
	}
}

func TestMTASTSPolicyWithoutHTTPClient(t *testing.T) {
	got := runPolicy(t, mtastsDNS(), nil)
	if len(got) != 1 || got[0].Status != finding.StatusUnknown {
		t.Fatalf("want one unknown finding, got %+v", got)
	}
}

func TestMTASTSPolicyDNSFailures(t *testing.T) {
	pki := newPKI(t)
	ps := startPolicy(t, pki.validLeaf(t), pki.pool, policyBody(goodPolicy))
	f := mtastsDNS()
	f.SetError("example.com", dns.TypeMX, net.ErrClosed)

	got := runPolicy(t, f, ps.client)

	if ps.hits.Load() != 0 || len(got) != 1 || got[0].Status != finding.StatusUnknown {
		t.Fatalf("hits=%d got=%+v; without the MX list nothing can be judged", ps.hits.Load(), got)
	}
}
