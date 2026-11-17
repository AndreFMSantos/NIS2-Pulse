package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/certinspect"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/engine"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/finding"
	"github.com/AndreFMSantos/NIS2-Pulse/internal/tlsprobe"
)

// Finding IDs produced by the certificate check.
const (
	idCertService   = "transport.cert.service"
	idCertChain     = "transport.cert.chain"
	idCertHostname  = "transport.cert.hostname"
	idCertValidity  = "transport.cert.validity"
	idCertLifetime  = "transport.cert.lifetime"
	idCertKey       = "transport.cert.key"
	idCertSignature = "transport.cert.signature"
	idCertInventory = "transport.cert.inventory"

	day            = 24 * time.Hour
	maxListedNames = 10
)

// Cert inspects the certificate the HTTPS port of the domain presents.
//
// It is ACTIVE: one connection to <domain>:443 through the safe dialer. The
// handshake is completed with Go's verification switched off (the single,
// tested exception to the "never skip verification" rule, confined to package
// certinspect) so that broken certificates can be read; the chain is then
// verified here and the outcome is always reported. No application data is sent.
//
// Only the certificate the server presents to a modern client is inspected: a
// server that serves a second certificate to other clients (for example an RSA
// and an ECDSA one) is not enumerated. Revocation (OCSP, CRL) is not checked.
type Cert struct {
	// Roots is the trust store; nil means the system roots.
	Roots *x509.CertPool
}

// ID implements engine.Check.
func (Cert) ID() string { return "transport.cert" }

// Area implements engine.Check.
func (Cert) Area() finding.Area { return finding.AreaTransport }

// Tier implements engine.Check.
func (Cert) Tier() finding.Tier { return finding.TierActive }

// Run implements engine.Check.
func (c Cert) Run(ctx context.Context, t engine.Target, d engine.Deps) []finding.Finding {
	if d.Dial == nil {
		return []finding.Finding{serviceFinding(idCertService, finding.StatusUnknown, "no dialer available")}
	}
	addr := net.JoinHostPort(t.Domain, "443")
	res, err := certinspect.Inspect(ctx, certinspect.Options{
		Dial:       func(ctx context.Context) (net.Conn, error) { return d.Dial(ctx, "tcp", addr) },
		ServerName: t.Domain,
		Roots:      c.Roots,
		Now:        d.Now,
	})
	if err != nil {
		var he *certinspect.HandshakeError
		if errors.As(err, &he) && !isTimeout(err) {
			return []finding.Finding{serviceFinding(idCertService, finding.StatusUnknown,
				fmt.Sprintf("the TLS handshake with %s could not be completed (%v), so its certificate could not be read", addr, he.Err))}
		}
		return []finding.Finding{connectionProblem(idCertService, err, addr)}
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	return AssessCertificate(res, now)
}

// AssessCertificate turns an inspection into findings. It is exported so that
// keys, signature algorithms and validity periods that no test server could
// reasonably present are tested too.
func AssessCertificate(res *certinspect.Result, now time.Time) []finding.Finding {
	leaf := res.Chain[0]
	out := []finding.Finding{
		certChainFinding(res),
		certHostnameFinding(res),
		certValidityFinding(res, now),
	}
	if res.Trust.Kind == certinspect.TrustOK {
		out = append(out, certLifetimeFinding(leaf))
	}
	return append(out, certKeyFinding(leaf), certSignatureFinding(res.Chain), certInventoryFinding(res, now))
}

func certFinding(id string, status finding.Status, sev finding.Severity, evidence []string, detail string) finding.Finding {
	f := finding.Finding{ID: id, Area: finding.AreaTransport, Tier: finding.TierActive,
		Status: status, Severity: sev, Evidence: evidence, Detail: detail}
	if status == finding.StatusPass || status == finding.StatusWarn || status == finding.StatusFail {
		f.Fixer = finding.FixerOrganization
	}
	return f
}

func subjects(chain []*x509.Certificate) []string {
	out := make([]string, 0, len(chain))
	for _, c := range chain {
		out = append(out, certName(c))
	}
	return out
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func certChainFinding(res *certinspect.Result) finding.Finding {
	ev := []string{strings.Join(subjects(res.Chain), " -> ")}
	if res.Trust.Kind == certinspect.TrustOK {
		return certFinding(idCertChain, finding.StatusPass, finding.SeverityHigh, ev, "")
	}
	return certFinding(idCertChain, finding.StatusFail, finding.SeverityHigh, ev, res.Trust.Detail)
}

func namesOf(c *x509.Certificate) []string {
	names := append([]string(nil), c.DNSNames...)
	return names
}

func capNames(names []string) []string {
	if len(names) <= maxListedNames {
		return names
	}
	return append(append([]string(nil), names[:maxListedNames]...), fmt.Sprintf("... and %d more", len(names)-maxListedNames))
}

func certHostnameFinding(res *certinspect.Result) finding.Finding {
	leaf := res.Chain[0]
	if res.Hostname == nil {
		return certFinding(idCertHostname, finding.StatusPass, finding.SeverityHigh, capNames(namesOf(leaf)), "")
	}
	return certFinding(idCertHostname, finding.StatusFail, finding.SeverityHigh, capNames(namesOf(leaf)),
		fmt.Sprintf("the certificate is not valid for %s; it covers only the names listed", res.ServerName))
}

func certValidityFinding(res *certinspect.Result, now time.Time) finding.Finding {
	leaf := res.Chain[0]
	ev := []string{fmt.Sprintf("valid from %s to %s", leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"))}

	if tp := res.Time; tp != nil {
		if tp.Expired {
			ago := int(now.Sub(tp.NotAfter) / day)
			return certFinding(idCertValidity, finding.StatusFail, finding.SeverityCritical, ev,
				fmt.Sprintf("the certificate of %q expired on %s (%d days ago): browsers and clients refuse it", tp.Subject, tp.NotAfter.UTC().Format("2006-01-02"), ago))
		}
		return certFinding(idCertValidity, finding.StatusFail, finding.SeverityHigh, ev,
			fmt.Sprintf("the certificate of %q is not yet valid (it starts on %s)", tp.Subject, tp.NotBefore.UTC().Format("2006-01-02")))
	}

	remaining := leaf.NotAfter.Sub(now)
	days := int(remaining / day)
	switch {
	case remaining < 14*day:
		return certFinding(idCertValidity, finding.StatusWarn, finding.SeverityHigh, ev,
			fmt.Sprintf("the certificate expires in %d days: renew it now, and check that automatic renewal works", days))
	case remaining < 30*day:
		return certFinding(idCertValidity, finding.StatusWarn, finding.SeverityMedium, ev,
			fmt.Sprintf("the certificate expires in %d days: automatic renewal normally happens well before this", days))
	}
	return certFinding(idCertValidity, finding.StatusPass, finding.SeverityHigh, ev, fmt.Sprintf("valid for another %d days", days))
}

// lifetimeStep is one row of the CA/Browser Forum Baseline Requirements
// section 6.3.2 schedule: certificates issued on or after from may not be valid
// for more than maxDays days.
type lifetimeStep struct {
	from    time.Time
	maxDays int
}

// publicLifetimeSchedule lists the steps in chronological order. Certificates
// issued before the first step are exempt. The dates and limits come from the
// Baseline Requirements text kept in the vault (official-docs, section 6.3.2,
// table "Maximum Validity Period of Subscriber Certificates").
var publicLifetimeSchedule = []lifetimeStep{
	{time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC), 398},
	{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
	{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
}

// maxLifetimeDays returns the longest validity allowed for a certificate
// issued at notBefore, or 0 when no limit applies yet.
func maxLifetimeDays(notBefore time.Time) int {
	limit := 0
	for _, step := range publicLifetimeSchedule {
		if !notBefore.Before(step.from) {
			limit = step.maxDays
		}
	}
	return limit
}

// certLifetimeFinding applies the maximum validity that was in force when the
// certificate was issued, but only when the chain is trusted (it is a rule of
// the public web PKI, meaningless for a private CA).
func certLifetimeFinding(leaf *x509.Certificate) finding.Finding {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	ev := []string{fmt.Sprintf("validity period of %d days", int(life/day))}
	limit := maxLifetimeDays(leaf.NotBefore)
	if limit == 0 || life <= time.Duration(limit)*day {
		return certFinding(idCertLifetime, finding.StatusPass, finding.SeverityLow, ev, "")
	}
	return certFinding(idCertLifetime, finding.StatusWarn, finding.SeverityLow, ev,
		fmt.Sprintf("publicly trusted certificates issued on %s may not be valid for more than %d days (CA/Browser Forum Baseline Requirements 6.3.2): browsers may reject this one",
			leaf.NotBefore.UTC().Format("2006-01-02"), limit))
}

func certKeyFinding(leaf *x509.Certificate) finding.Finding {
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		ev := []string{fmt.Sprintf("RSA %d bits", bits)}
		if bits < 2048 {
			return certFinding(idCertKey, finding.StatusFail, finding.SeverityHigh, ev,
				fmt.Sprintf("an RSA key of %d bits is too small: 2048 bits is the minimum accepted today", bits))
		}
		return certFinding(idCertKey, finding.StatusPass, finding.SeverityHigh, ev, "")
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		ev := []string{fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)}
		if bits < 256 {
			return certFinding(idCertKey, finding.StatusFail, finding.SeverityHigh, ev,
				fmt.Sprintf("an elliptic curve of %d bits is too small: use P-256 or larger", bits))
		}
		return certFinding(idCertKey, finding.StatusPass, finding.SeverityHigh, ev, "")
	case ed25519.PublicKey:
		return certFinding(idCertKey, finding.StatusPass, finding.SeverityHigh, []string{"Ed25519"}, "")
	}
	return finding.Unknown(idCertKey, finding.AreaTransport, finding.TierActive,
		fmt.Sprintf("unsupported public key type %s", leaf.PublicKeyAlgorithm))
}

func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// certSignatureFinding judges the leaf and the intermediates the server sends. A
// self-issued certificate in the chain (a root) is skipped: the signature of a
// trust anchor over itself proves nothing and is not what clients rely on.
func certSignatureFinding(chain []*x509.Certificate) finding.Finding {
	var weak []string
	for i, c := range chain {
		if i > 0 && c.Issuer.String() == c.Subject.String() {
			continue
		}
		if weakSignature(c.SignatureAlgorithm) {
			weak = append(weak, fmt.Sprintf("%s: %s", certName(c), c.SignatureAlgorithm))
		}
	}
	if len(weak) == 0 {
		return certFinding(idCertSignature, finding.StatusPass, finding.SeverityHigh, nil, "")
	}
	return certFinding(idCertSignature, finding.StatusFail, finding.SeverityHigh, weak,
		"SHA-1 and MD5 signatures can be forged: no browser accepts them for a publicly trusted certificate")
}

func certInventoryFinding(res *certinspect.Result, now time.Time) finding.Finding {
	leaf := res.Chain[0]
	fp := sha256.Sum256(leaf.Raw)
	key := "unknown key"
	if k := certKeyFinding(leaf); len(k.Evidence) > 0 {
		key = k.Evidence[0]
		if strings.HasPrefix(key, "RSA") {
			key += "s" // "RSA 2048 bits"
			key = strings.Replace(key, "bitss", "bits", 1)
		}
	}
	ev := []string{
		"subject: " + certName(leaf),
		"names: " + strings.Join(capNames(namesOf(leaf)), ", "),
		"issuer: " + leaf.Issuer.CommonName,
		fmt.Sprintf("valid: %s to %s (%d days left)", leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"), int(leaf.NotAfter.Sub(now)/day)),
		"key: " + key,
		"signature: " + leaf.SignatureAlgorithm.String(),
		"chain sent: " + strings.Join(subjects(res.Chain), " -> "),
		"sha256: " + hex.EncodeToString(fp[:]),
		fmt.Sprintf("negotiated: %s %s", tlsprobe.VersionName(res.TLSVersion), tls.CipherSuiteName(res.CipherSuite)),
	}
	return finding.Finding{ID: idCertInventory, Area: finding.AreaTransport, Tier: finding.TierActive, Status: finding.StatusInfo, Evidence: ev}
}
