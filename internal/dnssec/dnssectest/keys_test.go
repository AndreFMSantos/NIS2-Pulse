package dnssectest

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// tagZeroSeed is the seed of an Ed25519 key that, published as a ZSK (flags 256)
// under the name "pt.", has key tag 0. Found by brute force (counter 105497 of
// sha256("nis2-pulse-tag0-" || counter)); the test below re-checks the premise.
//
// Why it matters: the key tag is a 16-bit checksum of the DNSKEY, so about one
// random key in 65536 has tag 0, and dns.RRSIG.Sign refuses tag 0 with
// "dns: bad key". A full test run builds ~730 keys, so ~1.1% of the runs failed
// at random (seen once: TestStartTLSDANEMatch, "sign pt.: dns: bad key").
const tagZeroSeed = "32de484b3d3ac5b1a5900d4b2d63d5bc49ced67222aaa28ccf0a0bdec645562e"

func tagZeroKey(t *testing.T) (*dns.DNSKEY, ed25519.PrivateKey) {
	t.Helper()
	seed, err := hex.DecodeString(tagZeroSeed)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	k := &dns.DNSKEY{
		Hdr:    dns.Header{Name: "pt.", Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))},
	}
	return k, priv
}

// The premise: Sign rejects a key with tag 0. If the library ever stops doing
// that, the retry in newKey is no longer needed and this test says so.
func TestSignRejectsKeyTagZero(t *testing.T) {
	k, priv := tagZeroKey(t)
	if k.KeyTag() != 0 {
		t.Fatalf("test key has tag %d, want 0: the DNSKEY encoding changed", k.KeyTag())
	}
	rr := &dns.TXT{Hdr: dns.Header{Name: "pt.", Class: dns.ClassINET, TTL: 300}, TXT: rdata.TXT{Txt: []string{"x"}}}
	s := dns.NewRRSIG("pt.", k.Algorithm, k.KeyTag(), uint32(time.Now().Unix()), uint32(time.Now().Add(time.Hour).Unix()))
	if err := s.Sign(priv, []dns.RR{rr}, &dns.SignOption{}); err == nil {
		t.Skip("dns.RRSIG.Sign accepts key tag 0 now: newKey's retry can be removed")
	}
}

func TestNewKeyNeverReturnsKeyTagZero(t *testing.T) {
	zk, zpriv := tagZeroKey(t)
	orig := generateKey
	t.Cleanup(func() { generateKey = orig })
	calls := 0
	generateKey = func(k *dns.DNSKEY) (crypto.PrivateKey, error) {
		calls++
		if calls == 1 { // the first draw is the unlucky one
			k.PublicKey = zk.PublicKey
			return zpriv, nil
		}
		return orig(k)
	}
	k, signer := newKey(t, "pt.", 256, false)
	if k.KeyTag() == 0 {
		t.Fatal("newKey returned a key with tag 0: signing with it fails with 'dns: bad key'")
	}
	if calls < 2 {
		t.Errorf("generator called %d time(s): the tag-0 key was not redrawn", calls)
	}
	if signer == nil {
		t.Fatal("no signer")
	}
}

func TestNewKeyGivesUpIfItCannotAvoidTagZero(t *testing.T) {
	zk, zpriv := tagZeroKey(t)
	orig := generateKey
	t.Cleanup(func() { generateKey = orig })
	generateKey = func(k *dns.DNSKEY) (crypto.PrivateKey, error) {
		k.PublicKey = zk.PublicKey
		return zpriv, nil
	}
	ft := &fakeT{T: t}
	func() {
		defer func() { _ = recover() }()
		newKey(ft, "pt.", 256, false)
	}()
	if !ft.failed {
		t.Error("an endless run of tag-0 keys must fail the test instead of looping forever")
	}
}
