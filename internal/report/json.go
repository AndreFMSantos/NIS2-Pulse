// Package report renders scan results.
package report

import (
	"encoding/json"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/catalog"
	"io"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
)

// Result is the machine-readable output of one scan.
type Result struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Target    string            `json:"target"`
	ScannedAt time.Time         `json:"scanned_at"`
	Resolver  string            `json:"resolver"`
	Active    bool              `json:"active"`
	Findings  []finding.Finding `json:"findings"`
	// Profile is what the user declared about the entity (see catalog.Profile); nil when nothing was.
	Profile *catalog.Profile `json:"profile,omitempty"`
}

// WriteJSON writes r as indented JSON followed by a newline. A nil Findings
// slice is written as [] so consumers never see null.
func WriteJSON(w io.Writer, r Result) error {
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
