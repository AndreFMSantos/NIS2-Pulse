package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/report"
)

func TestWriteJSON(t *testing.T) {
	res := report.Result{
		Tool:      "nis2-pulse",
		Version:   "1.2.3",
		Target:    "example.com",
		ScannedAt: time.Date(2026, 11, 6, 18, 0, 0, 0, time.UTC),
		Resolver:  "1.1.1.1:53",
		Active:    false,
		Findings: []finding.Finding{
			{ID: "email.spf.present", Area: finding.AreaEmail, Tier: finding.TierPassive, Status: finding.StatusPass},
		},
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, res); err != nil {
		t.Fatal(err)
	}

	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	for k, want := range map[string]any{
		"tool": "nis2-pulse", "version": "1.2.3", "target": "example.com",
		"scanned_at": "2026-11-06T18:00:00Z", "resolver": "1.1.1.1:53", "active": false,
	} {
		if back[k] != want {
			t.Errorf("%s = %v, want %v", k, back[k], want)
		}
	}
	if fs, ok := back["findings"].([]any); !ok || len(fs) != 1 {
		t.Errorf("findings = %v, want a list of 1", back["findings"])
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("output should end with a newline")
	}
}

func TestWriteJSONEmptyFindingsIsAnArray(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, report.Result{Tool: "nis2-pulse"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Fatalf("empty findings must serialise as [] not null:\n%s", buf.String())
	}
}
