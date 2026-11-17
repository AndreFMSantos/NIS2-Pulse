package checks_test

import (
	"testing"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/checks"
)

func TestDefaultChecksHaveUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range checks.Default(checks.Options{}) {
		if c.ID() == "" {
			t.Fatalf("check %T has an empty ID", c)
		}
		if seen[c.ID()] {
			t.Fatalf("duplicate check ID %q", c.ID())
		}
		seen[c.ID()] = true
	}
	if len(seen) == 0 {
		t.Fatal("no default checks registered")
	}
}

func TestDefaultPassesTheEHLONameToTheSTARTTLSCheck(t *testing.T) {
	for _, c := range checks.Default(checks.Options{EHLOName: "scanner.example.org"}) {
		if st, ok := c.(checks.StartTLS); ok {
			if st.EHLOName != "scanner.example.org" {
				t.Fatalf("EHLOName = %q", st.EHLOName)
			}
			return
		}
	}
	t.Fatal("StartTLS is not registered")
}
