package catalog

import (
	"fmt"
	"strings"
)

// Scope says which kind of entity a legal source applies to. An empty scope applies to every entity.
type Scope string

// Scopes of the sources of Entry.Legal.
const (
	// ScopeEEI: Regulation (CNCS) 756/2026 annex III, the minimum measures of essential and important entities.
	ScopeEEI Scope = "eei"
	// ScopePublic: Regulation (CNCS) 756/2026 annex IV, the controls of public relevant entities. It is not
	// for the essential and important entities of annex III.
	ScopePublic Scope = "public"
	// ScopeReg2690: Implementing Regulation (EU) 2024/2690, which applies directly only to the "entidades
	// pertinentes" of its article 1 (DNS, cloud, data centres, CDNs, managed services, trust services...).
	ScopeReg2690 Scope = "reg2690"
)

// Profile is what the user says about the entity, to choose which legal references to print. The tool cannot
// know it (scope depends on registration with the CNCS and on the risk matrix): it is a declaration, never a
// finding. The zero Profile prints every reference.
type Profile struct {
	// Entity is "eei" (essential or important entity, annex III) or "public" (public relevant entity, annex IV).
	Entity string `json:"entity,omitempty"`
	// Reg2690 is "yes" or "no": whether Implementing Regulation 2024/2690 covers the entity directly.
	Reg2690 string `json:"reg2690,omitempty"`
}

// ParseProfile validates the values of --entity and --reg2690 (case-insensitive, empty means not given).
func ParseProfile(entity, reg2690 string) (Profile, error) {
	p := Profile{Entity: strings.ToLower(strings.TrimSpace(entity)), Reg2690: strings.ToLower(strings.TrimSpace(reg2690))}
	switch p.Entity {
	case "", "eei", "public":
	default:
		return Profile{}, fmt.Errorf("invalid --entity %q (supported: eei, public)", entity)
	}
	switch p.Reg2690 {
	case "", "yes", "no":
	default:
		return Profile{}, fmt.Errorf("invalid --reg2690 %q (supported: yes, no)", reg2690)
	}
	return p, nil
}

// IsZero reports whether nothing was declared.
func (p Profile) IsZero() bool { return p == Profile{} }

// Applies reports whether a source is printed for this profile.
func (p Profile) Applies(s Source) bool {
	switch s.Scope {
	case ScopeEEI:
		return p.Entity != "public"
	case ScopePublic:
		return p.Entity != "eei"
	case ScopeReg2690:
		return p.Reg2690 != "no"
	}
	return true
}

// ForProfile returns e with only the legal sources that apply to p. The shared tables are not modified.
func (e Entry) ForProfile(p Profile) Entry {
	if p.IsZero() {
		return e
	}
	kept := make([]Source, 0, len(e.Legal))
	for _, s := range e.Legal {
		if p.Applies(s) {
			kept = append(kept, s)
		}
	}
	e.Legal = kept
	return e
}
