// Package score turns findings into a 0-100 note per area.
//
// There is deliberately no global note: weights between areas would be
// arbitrary, and a single number invites the reading "X% compliant", which the
// report must never say. The note is a hygiene indicator for one area, built
// as 100 minus a penalty for each failed or doubtful check, and it is not
// computed at all for an area where no check reached a verdict.
package score

import "github.com/AndreFMSantos/NIS2-Pulse/internal/finding"

// Area is the summary of one area.
type Area struct {
	Area finding.Area
	// Score is 0-100, or nil when no check of the area reached a verdict.
	Score *int
	// Counts by status. Decided = Pass + Warn + Fail. Info findings are not
	// counted anywhere (they carry no verdict); Total = Decided + Unknown.
	Pass, Warn, Fail, Unknown int
	Decided, Total            int
}

// order is the order in which areas are reported.
var order = []finding.Area{finding.AreaEmail, finding.AreaDNS, finding.AreaTransport, finding.AreaRouting}

// Penalty points. A finding without a severity is treated as medium: the
// report does not hide it, and does not let it weigh like a critical one.
var (
	failPenalty = map[finding.Severity]int{
		finding.SeverityCritical: 40, finding.SeverityHigh: 25, finding.SeverityMedium: 12, finding.SeverityLow: 5,
	}
	warnPenalty = map[finding.Severity]int{
		finding.SeverityCritical: 20, finding.SeverityHigh: 12, finding.SeverityMedium: 6, finding.SeverityLow: 2,
	}
)

func penalty(table map[finding.Severity]int, sev finding.Severity) int {
	if p, ok := table[sev]; ok {
		return p
	}
	return table[finding.SeverityMedium]
}

// Penalty returns the points a finding takes off the note of its area: 0 for
// pass, info and unknown. The monitoring uses it as the measure of "how bad".
func Penalty(st finding.Status, sev finding.Severity) int {
	switch st {
	case finding.StatusFail:
		return penalty(failPenalty, sev)
	case finding.StatusWarn:
		return penalty(warnPenalty, sev)
	default:
		return 0
	}
}

// Compute returns one entry per area in the fixed report order, including
// areas that have no findings at all.
func Compute(findings []finding.Finding) []Area {
	acc := map[finding.Area]*Area{}
	lost := map[finding.Area]int{}
	for _, a := range order {
		acc[a] = &Area{Area: a}
	}
	for _, f := range findings {
		a, ok := acc[f.Area]
		if !ok {
			a = &Area{Area: f.Area}
			acc[f.Area] = a
		}
		switch f.Status {
		case finding.StatusPass:
			a.Pass++
		case finding.StatusWarn:
			a.Warn++
			lost[f.Area] += penalty(warnPenalty, f.Severity)
		case finding.StatusFail:
			a.Fail++
			lost[f.Area] += penalty(failPenalty, f.Severity)
		case finding.StatusUnknown:
			a.Unknown++
		}
	}
	out := make([]Area, 0, len(acc))
	emit := func(a *Area) {
		a.Decided = a.Pass + a.Warn + a.Fail
		a.Total = a.Decided + a.Unknown
		if a.Decided > 0 {
			s := 100 - lost[a.Area]
			if s < 0 {
				s = 0
			}
			a.Score = &s
		}
		out = append(out, *a)
	}
	for _, area := range order {
		emit(acc[area])
		delete(acc, area)
	}
	var rest []finding.Area
	for area := range acc {
		rest = append(rest, area)
	}
	sortAreas(rest)
	for _, area := range rest {
		emit(acc[area])
	}
	return out
}

func sortAreas(a []finding.Area) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
