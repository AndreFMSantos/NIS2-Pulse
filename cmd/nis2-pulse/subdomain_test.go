package main

import (
	"strings"
	"testing"
)

func TestScanSubdomainFlagAddsTheFinding(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--subdomain", "blog", "example.com"},
		{"scan", "example.com", "--subdomain=blog.example.com,www"},
	} {
		a, out, errb := newTestApp(healthyFake(), nil)
		if code := a.run(args); code != 0 {
			t.Fatalf("%v: exit code = %d, stderr = %q", args, code, errb.String())
		}
		if status, _ := findingOf(t, out.Bytes(), "email.subdomains.mx"); status == "" {
			t.Errorf("%v: no email.subdomains.mx finding", args)
		}
	}
}

func TestScanWithoutSubdomainFlagHasNoSubdomainFinding(t *testing.T) {
	a, out, _ := newTestApp(healthyFake(), nil)
	if code := a.run([]string{"scan", "example.com"}); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.Contains(out.String(), "email.subdomains") {
		t.Error("the subdomain check must be opt-in")
	}
}

func TestScanRejectsAnInvalidSubdomain(t *testing.T) {
	for _, sub := range []string{"example.com", "https://x", "192.0.2.1"} {
		a, out, errb := newTestApp(healthyFake(), nil)
		if code := a.run([]string{"scan", "--subdomain", sub, "example.com"}); code != 2 {
			t.Fatalf("%q: exit code = %d, want 2", sub, code)
		}
		if out.Len() != 0 || !strings.Contains(errb.String(), "subdomain") {
			t.Errorf("%q: want a usage error naming the flag, got out=%q err=%q", sub, out.String(), errb.String())
		}
	}
}
