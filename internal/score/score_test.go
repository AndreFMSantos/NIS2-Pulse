package score_test

import (
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/score"
)

func f(area finding.Area, st finding.Status, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: "x." + string(st) + string(sev), Area: area, Status: st, Severity: sev}
}

func byArea(t *testing.T, as []score.Area, a finding.Area) score.Area {
	t.Helper()
	for _, x := range as {
		if x.Area == a {
			return x
		}
	}
	t.Fatalf("area %s missing in %+v", a, as)
	return score.Area{}
}

func TestAllPassIs100(t *testing.T) {
	as := score.Compute([]finding.Finding{f(finding.AreaEmail, finding.StatusPass, ""), f(finding.AreaEmail, finding.StatusPass, finding.SeverityHigh)})
	a := byArea(t, as, finding.AreaEmail)
	if a.Score == nil || *a.Score != 100 {
		t.Fatalf("score = %v, want 100", a.Score)
	}
	if a.Decided != 2 || a.Total != 2 {
		t.Errorf("decided/total = %d/%d, want 2/2", a.Decided, a.Total)
	}
}

func TestPenalties(t *testing.T) {
	tests := []struct {
		name string
		in   finding.Finding
		want int
	}{
		{"fail critical", f(finding.AreaDNS, finding.StatusFail, finding.SeverityCritical), 60},
		{"fail high", f(finding.AreaDNS, finding.StatusFail, finding.SeverityHigh), 75},
		{"fail medium", f(finding.AreaDNS, finding.StatusFail, finding.SeverityMedium), 88},
		{"fail low", f(finding.AreaDNS, finding.StatusFail, finding.SeverityLow), 95},
		{"fail without severity counts as medium", f(finding.AreaDNS, finding.StatusFail, ""), 88},
		{"warn critical", f(finding.AreaDNS, finding.StatusWarn, finding.SeverityCritical), 80},
		{"warn high", f(finding.AreaDNS, finding.StatusWarn, finding.SeverityHigh), 88},
		{"warn medium", f(finding.AreaDNS, finding.StatusWarn, finding.SeverityMedium), 94},
		{"warn low", f(finding.AreaDNS, finding.StatusWarn, finding.SeverityLow), 98},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := byArea(t, score.Compute([]finding.Finding{tt.in}), finding.AreaDNS)
			if a.Score == nil || *a.Score != tt.want {
				t.Fatalf("score = %v, want %d", a.Score, tt.want)
			}
		})
	}
}

func TestScoreNeverGoesBelowZero(t *testing.T) {
	var in []finding.Finding
	for i := 0; i < 10; i++ {
		in = append(in, f(finding.AreaTransport, finding.StatusFail, finding.SeverityCritical))
	}
	if a := byArea(t, score.Compute(in), finding.AreaTransport); a.Score == nil || *a.Score != 0 {
		t.Fatalf("score = %v, want 0", a.Score)
	}
}

func TestAreaWithoutVerdictHasNoScore(t *testing.T) {
	in := []finding.Finding{
		f(finding.AreaRouting, finding.StatusUnknown, ""),
		f(finding.AreaRouting, finding.StatusInfo, ""),
	}
	a := byArea(t, score.Compute(in), finding.AreaRouting)
	if a.Score != nil {
		t.Fatalf("score = %d: an area where nothing could be verified must not get a number", *a.Score)
	}
	if a.Decided != 0 || a.Unknown != 1 {
		t.Errorf("decided = %d unknown = %d", a.Decided, a.Unknown)
	}
}

func TestInfoAndUnknownDoNotChangeTheScore(t *testing.T) {
	base := []finding.Finding{f(finding.AreaEmail, finding.StatusFail, finding.SeverityHigh)}
	more := append(append([]finding.Finding{}, base...),
		f(finding.AreaEmail, finding.StatusInfo, ""), f(finding.AreaEmail, finding.StatusUnknown, ""))
	a, b := byArea(t, score.Compute(base), finding.AreaEmail), byArea(t, score.Compute(more), finding.AreaEmail)
	if *a.Score != *b.Score {
		t.Errorf("score changed from %d to %d by info/unknown findings", *a.Score, *b.Score)
	}
	if b.Total != 2 || b.Unknown != 1 {
		t.Errorf("coverage: total = %d (info excluded, unknown counted), unknown = %d", b.Total, b.Unknown)
	}
}

func TestOrderAndNoGlobalScore(t *testing.T) {
	in := []finding.Finding{
		f(finding.AreaRouting, finding.StatusPass, ""), f(finding.AreaTransport, finding.StatusPass, ""),
		f(finding.AreaEmail, finding.StatusPass, ""), f(finding.AreaDNS, finding.StatusPass, ""),
	}
	as := score.Compute(in)
	want := []finding.Area{finding.AreaEmail, finding.AreaDNS, finding.AreaTransport, finding.AreaRouting}
	if len(as) != len(want) {
		t.Fatalf("got %d areas, want %d: no global entry is allowed", len(as), len(want))
	}
	for i, w := range want {
		if as[i].Area != w {
			t.Errorf("position %d = %s, want %s", i, as[i].Area, w)
		}
	}
}

// Adding a failure can never raise a score.
func TestMonotonic(t *testing.T) {
	sevs := []finding.Severity{"", finding.SeverityLow, finding.SeverityMedium, finding.SeverityHigh, finding.SeverityCritical}
	var in []finding.Finding
	prev := 100
	for _, st := range []finding.Status{finding.StatusWarn, finding.StatusFail} {
		for _, sev := range sevs {
			in = append(in, f(finding.AreaEmail, st, sev))
			got := *byArea(t, score.Compute(in), finding.AreaEmail).Score
			if got > prev {
				t.Fatalf("score rose from %d to %d after adding %s/%s", prev, got, st, sev)
			}
			if got < 0 || got > 100 {
				t.Fatalf("score %d out of range", got)
			}
			prev = got
		}
	}
}

func TestCountsByStatus(t *testing.T) {
	in := []finding.Finding{
		f(finding.AreaEmail, finding.StatusPass, ""), f(finding.AreaEmail, finding.StatusWarn, finding.SeverityLow),
		f(finding.AreaEmail, finding.StatusFail, finding.SeverityHigh), f(finding.AreaEmail, finding.StatusUnknown, ""),
	}
	a := byArea(t, score.Compute(in), finding.AreaEmail)
	if a.Pass != 1 || a.Warn != 1 || a.Fail != 1 || a.Unknown != 1 || a.Decided != 3 || a.Total != 4 {
		t.Fatalf("counts = %+v", a)
	}
}

func TestPenaltyMatchesTheNoteTable(t *testing.T) {
	cases := []struct {
		st   finding.Status
		sev  finding.Severity
		want int
	}{
		{finding.StatusPass, finding.SeverityHigh, 0}, {finding.StatusInfo, "", 0}, {finding.StatusUnknown, finding.SeverityCritical, 0},
		{finding.StatusFail, finding.SeverityCritical, 40}, {finding.StatusFail, finding.SeverityHigh, 25},
		{finding.StatusFail, finding.SeverityMedium, 12}, {finding.StatusFail, finding.SeverityLow, 5}, {finding.StatusFail, "", 12},
		{finding.StatusWarn, finding.SeverityCritical, 20}, {finding.StatusWarn, finding.SeverityHigh, 12},
		{finding.StatusWarn, finding.SeverityMedium, 6}, {finding.StatusWarn, finding.SeverityLow, 2}, {finding.StatusWarn, "", 6},
	}
	for _, c := range cases {
		if got := score.Penalty(c.st, c.sev); got != c.want {
			t.Errorf("Penalty(%s,%s) = %d, want %d", c.st, c.sev, got, c.want)
		}
	}
}
