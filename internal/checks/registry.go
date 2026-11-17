package checks

import "github.com/AndreFMSantos/NIS2-Pulse/internal/engine"

// Options configure the checks that need input from the user.
type Options struct {
	// DKIMSelectors are the selectors the DKIM check looks up.
	DKIMSelectors []string
	// EHLOName is the name announced to mail servers by the STARTTLS check;
	// empty means checks.DefaultEHLOName.
	EHLOName string
	// Subdomains are subdomains whose MX records are examined (--subdomain);
	// empty means the check does not run.
	Subdomains []string
}

// Default returns every check in report order. New checks are added here.
func Default(o Options) []engine.Check {
	cs := []engine.Check{
		MX{},
		SPF{},
		DKIM{Selectors: o.DKIMSelectors},
		DMARC{},
		MTASTSRecord{},
		MTASTSPolicy{},
		TLSRPT{},
		DANE{},
		StartTLS{EHLOName: o.EHLOName},
		TLS{},
		Cert{},
		Web{},
		DNSSEC{},
		CAA{},
		Routing{},
	}
	if len(o.Subdomains) > 0 {
		cs = append(cs, MailSubdomains{Names: o.Subdomains})
	}
	return cs
}
