package engine_test

import (
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{"  Example.COM.  ", "example.com", false},
		{"www.example.pt", "www.example.pt", false},
		{"bücher.de", "xn--bcher-kva.de", false},
		{"xn--bcher-kva.de", "xn--bcher-kva.de", false},
		{"", "", true},
		{"   ", "", true},
		{"localhost", "", true},
		{"com", "", true},
		{"192.0.2.1", "", true},
		{"2001:db8::1", "", true},
		{"https://example.com", "", true},
		{"example.com/path", "", true},
		{"user@example.com", "", true},
		{"example.com:443", "", true},
		{"a..example.com", "", true},
		{"-bad.example.com", "", true},
		{"exa mple.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := engine.ParseTarget(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTarget(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got.Domain != tt.want {
				t.Fatalf("ParseTarget(%q) = %q, want %q", tt.in, got.Domain, tt.want)
			}
		})
	}
}

func TestParseTargetRejectsOverlongNames(t *testing.T) {
	label := make([]byte, 64)
	for i := range label {
		label[i] = 'a'
	}
	if _, err := engine.ParseTarget(string(label) + ".com"); err == nil {
		t.Fatal("a label longer than 63 octets must be rejected")
	}
}
