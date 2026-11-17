package dnssec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func seededKey(i uint64) (*dns.DNSKEY, ed25519.PrivateKey) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], i)
	seed := sha256.Sum256(append([]byte("nis2-pulse-collision-"), b[:]...))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return &dns.DNSKEY{
		Hdr:    dns.Header{Name: "example.pt.", Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))},
	}, priv
}

// collidingKeys finds two different keys with the same key tag (a 16-bit
// checksum: a pair turns up after a few hundred keys). The search is
// deterministic, so the test always uses the same pair.
func collidingKeys(t *testing.T) (a, b *dns.DNSKEY, privB ed25519.PrivateKey) {
	t.Helper()
	seen := map[uint16]uint64{}
	for i := uint64(0); i < 5000; i++ {
		k, _ := seededKey(i)
		tag := k.KeyTag()
		if j, ok := seen[tag]; ok && tag != 0 {
			a, _ = seededKey(j)
			b, privB = seededKey(i)
			return a, b, privB
		}
		seen[tag] = i
	}
	t.Fatal("no key tag collision among 5000 keys: the premise is wrong")
	return nil, nil, nil
}

// Two keys of one zone may share a key tag (RFC 4034 appendix B: the tag is only
// a hint). The validator must try every candidate, not stop at the first.
func TestVerifyAnyTriesEveryKeyWithTheSameTag(t *testing.T) {
	a, b, privB := collidingKeys(t)
	if a.KeyTag() != b.KeyTag() || a.PublicKey == b.PublicKey {
		t.Fatalf("not a collision: %d vs %d", a.KeyTag(), b.KeyTag())
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	rr := &dns.TXT{Hdr: dns.Header{Name: "example.pt.", Class: dns.ClassINET, TTL: 300}, TXT: rdata.TXT{Txt: []string{"hello"}}}
	sig := dns.NewRRSIG("example.pt.", b.Algorithm, b.KeyTag(), uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(time.Hour).Unix()))
	if err := sig.Sign(privB, []dns.RR{rr}, &dns.SignOption{}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	for name, keys := range map[string][]*dns.DNSKEY{
		"wrong key listed first": {a, b},
		"right key listed first": {b, a},
		"right key alone":        {b},
	} {
		if code, _ := verifyAny([]dns.RR{rr}, []*dns.RRSIG{sig}, keys, "example.pt.", now); code != "" {
			t.Errorf("%s: code = %q, want success", name, code)
		}
	}
	if code, _ := verifyAny([]dns.RR{rr}, []*dns.RRSIG{sig}, []*dns.DNSKEY{a}, "example.pt.", now); code != CodeSigInvalid {
		t.Errorf("only the colliding wrong key: code = %q, want %q", code, CodeSigInvalid)
	}
}

// Key 80349 of the same seed family has the signer's key tag (34154) once its Protocol is
// set to 2, or once its Zone Key bit is cleared (both change the checksum by 256, found
// by brute force), so the validator considers it a candidate for the signature.
const unusableCounter = 80349

func unusableKeys(t *testing.T) (signer *dns.DNSKEY, priv ed25519.PrivateKey, badProtocol, noZoneBit *dns.DNSKEY) {
	t.Helper()
	signer, priv = seededKey(0)
	badProtocol, _ = seededKey(unusableCounter)
	badProtocol.Protocol = 2
	noZoneBit, _ = seededKey(unusableCounter)
	noZoneBit.Flags = 0
	for name, k := range map[string]*dns.DNSKEY{"protocol 2": badProtocol, "no zone bit": noZoneBit} {
		if k.KeyTag() != signer.KeyTag() || k.PublicKey == signer.PublicKey {
			t.Fatalf("premise broken for the %s key: tag %d vs %d", name, k.KeyTag(), signer.KeyTag())
		}
	}
	return signer, priv, badProtocol, noZoneBit
}

// RFC 4034 sections 2.1.1 and 2.1.2: a DNSKEY without the Zone Key bit, or with Protocol
// other than 3, MUST NOT be used to verify an RRSIG. Such a key is not a failed
// signature: it is no key at all, and the zone must not be accused of a bad signature.
func TestKeysThatMustNotVerifyAreNotCandidates(t *testing.T) {
	signer, priv, badProtocol, noZoneBit := unusableKeys(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	rr := &dns.TXT{Hdr: dns.Header{Name: "example.pt.", Class: dns.ClassINET, TTL: 300}, TXT: rdata.TXT{Txt: []string{"hello"}}}
	sig := dns.NewRRSIG("example.pt.", signer.Algorithm, signer.KeyTag(), uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(time.Hour).Unix()))
	if err := sig.Sign(priv, []dns.RR{rr}, &dns.SignOption{}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*dns.DNSKEY{"protocol 2": badProtocol, "no zone bit": noZoneBit} {
		code, _ := verifyAny([]dns.RR{rr}, []*dns.RRSIG{sig}, []*dns.DNSKEY{bad}, "example.pt.", now)
		if code != CodeSigMissing {
			t.Errorf("%s alone: code = %q, want %q (no usable key, not an invalid signature)", name, code, CodeSigMissing)
		}
		if code, _ := verifyAny([]dns.RR{rr}, []*dns.RRSIG{sig}, []*dns.DNSKEY{bad, signer}, "example.pt.", now); code != "" {
			t.Errorf("%s next to the real key: code = %q, want success", name, code)
		}
	}
}
