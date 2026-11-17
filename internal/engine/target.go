package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// lookupProfile converts internationalised names to their ASCII (punycode)
// form with the validation a DNS lookup needs.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.VerifyDNSLength(true),
)

// ParseTarget validates user input and returns the normalised target
// (lowercase ASCII, no trailing dot). It deliberately rejects IP addresses,
// URLs, ports and single labels: nis2-pulse assesses domain names.
func ParseTarget(input string) (Target, error) {
	s := strings.TrimSuffix(strings.TrimSpace(input), ".")
	if s == "" {
		return Target{}, errors.New("empty domain")
	}
	if strings.ContainsAny(s, "/@: \t") {
		return Target{}, fmt.Errorf("%q is not a bare domain name (no scheme, path, user, port or spaces)", input)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return Target{}, fmt.Errorf("%q is an IP address; provide a domain name", input)
	}
	ascii, err := lookupProfile.ToASCII(s)
	if err != nil {
		return Target{}, fmt.Errorf("invalid domain %q: %w", input, err)
	}
	ascii = strings.ToLower(ascii)
	if !strings.Contains(ascii, ".") {
		return Target{}, fmt.Errorf("%q has a single label; provide a full domain such as example.pt", input)
	}
	return Target{Domain: ascii}, nil
}
