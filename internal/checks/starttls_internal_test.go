package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/AndreFMSantos/NIS2-Pulse/internal/certinspect"
)

// A SHA-1 signed certificate cannot be produced by Go's own x509 package any
// more, so the weak-signature branch is tested on a hand-built certificate.
func TestCertProblemsReportsASHA1Signature(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(90 * 24 * time.Hour),
		PublicKey:          &ecdsa.PublicKey{Curve: elliptic.P256()},
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	leaf.Subject.CommonName = "mail.example.pt"
	res := &certinspect.Result{Chain: []*x509.Certificate{leaf}, Trust: certinspect.Trust{Kind: certinspect.TrustOK}}

	got := strings.Join(certProblems(res, "mail.example.pt", now), " | ")
	if !strings.Contains(got, "weak signature") || !strings.Contains(got, "SHA1") {
		t.Fatalf("problems %q", got)
	}

	leaf.SignatureAlgorithm = x509.SHA256WithRSA
	if p := certProblems(res, "mail.example.pt", now); len(p) != 0 {
		t.Fatalf("a SHA-256 certificate has no problems: %v", p)
	}
}
