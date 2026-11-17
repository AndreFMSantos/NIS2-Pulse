package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/dnsx/dnsxtest"
)

func TestParseSupplierList(t *testing.T) {
	in := "# fornecedores\n\nExample.COM;Acme Cloud\nexample.net\n  example.org ; Org  \nexample.com;Duplicado\n"
	got, err := parseSupplierList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 distinct suppliers (duplicate dropped), got %v", got)
	}
	want := []supplierEntry{{"example.com", "Acme Cloud"}, {"example.net", ""}, {"example.org", "Org"}}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSupplierListErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":           "# only a comment\n\n",
		"url":             "https://example.com/x\n",
		"ip":              "192.0.2.1\n",
		"bad second line": "example.com\nnot a domain\n",
		"too many (51)":   strings.Repeat("a.example.com\n", 0) + manyDomains(51),
	} {
		if _, err := parseSupplierList(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	_, err := parseSupplierList(strings.NewReader("example.com\nnot a domain\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error must name the line, got %v", err)
	}
	if _, err := parseSupplierList(strings.NewReader(manyDomains(50))); err != nil {
		t.Errorf("exactly 50 suppliers must be accepted: %v", err)
	}
}

func manyDomains(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("s")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + (i/26)%26)))
		b.WriteString(".example.com\n")
	}
	return b.String()
}

func writeList(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fornecedores.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func suppliersFake() *dnsxtest.Fake {
	f := healthyFake()
	f.Add(dnsxtest.TXT("example.net", "v=spf1 +all"))
	f.SetRcode("nope.example.com", dns.TypeA, dns.RcodeNameError)
	return f
}

func TestSuppliersMarkdownCompareAndStayPassive(t *testing.T) {
	list := writeList(t, "example.com;Acme\nexample.net;Beta\nnope.example.com;Gone\n")
	a, out, errb := newTestApp(suppliersFake(), nil)
	if code := a.run([]string{"suppliers", "--no-routing", list}); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"Acme", "Beta", "Gone", "example.com", "example.net", "nope.example.com", "GR.CA-7", "não é uma auditoria"} {
		if !strings.Contains(strings.ToLower(s), strings.ToLower(want)) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "NXDOMAIN") {
		t.Errorf("a supplier that does not exist must be reported with the reason:\n%s", s)
	}
	if len(dialedAddrs()) != 0 || httpAttempts.Load() != 0 {
		t.Errorf("suppliers is passive: no dial and no HTTP; dialed=%v http=%d", dialedAddrs(), httpAttempts.Load())
	}
}

func TestSuppliersJSON(t *testing.T) {
	list := writeList(t, "example.com;Acme\nexample.net\n")
	a, out, _ := newTestApp(suppliersFake(), nil)
	if code := a.run([]string{"suppliers", "--no-routing", "--format", "json", list}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got struct {
		Suppliers []struct {
			Name, Domain, Error string
			Fail, Warn          int
		} `json:"suppliers"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if len(got.Suppliers) != 2 {
		t.Fatalf("want 2 suppliers, got %+v", got.Suppliers)
	}
}

func TestSuppliersIsPassiveOnly(t *testing.T) {
	list := writeList(t, "example.com\n")
	a, _, errb := newTestApp(suppliersFake(), nil)
	if code := a.run([]string{"suppliers", "--active", list}); code != 2 {
		t.Fatalf("--active must not exist for suppliers: exit %d, stderr %q", code, errb.String())
	}
}

func TestSuppliersAllFailingIsAnError(t *testing.T) {
	list := writeList(t, "nope.example.com\n")
	a, _, _ := newTestApp(suppliersFake(), nil)
	if code := a.run([]string{"suppliers", "--no-routing", list}); code != 1 {
		t.Fatalf("exit %d, want 1 when no supplier could be scanned", code)
	}
}

func TestSuppliersUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no file":         {"suppliers"},
		"missing file":    {"suppliers", filepath.Join(t.TempDir(), "nope.txt")},
		"bad lang":        {"suppliers", "--lang", "fr", writeList(t, "example.com\n")},
		"bad format":      {"suppliers", "--format", "xml", writeList(t, "example.com\n")},
		"bad concurrency": {"suppliers", "--concurrency", "99", writeList(t, "example.com\n")},
		"bad list":        {"suppliers", writeList(t, "https://example.com\n")},
	} {
		a, _, _ := newTestApp(suppliersFake(), nil)
		if code := a.run(args); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
