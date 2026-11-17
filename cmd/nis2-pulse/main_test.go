package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{"no args prints usage", nil, 2, "", "Usage:"},
		{"version", []string{"version"}, 0, "nis2-pulse", ""},
		{"scan without domain", []string{"scan"}, 2, "", "missing domain"},
		{"unknown command", []string{"frobnicate"}, 2, "", "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tt.args, &out, &errb)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout %q does not contain %q", out.String(), tt.wantOut)
			}
			if !strings.Contains(errb.String(), tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", errb.String(), tt.wantErr)
			}
		})
	}
}
