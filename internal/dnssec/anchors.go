package dnssec

import "codeberg.org/miekg/dns"

// rootAnchor is a DS-form trust anchor for the DNS root zone.
type rootAnchor struct {
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     string
}

// rootAnchors are the root zone KSKs currently published by IANA at
// https://data.iana.org/root-anchors/root-anchors.xml (checked 2026-11-06):
// KSK-2017 (tag 20326, valid from 2017-02-02) and KSK-2024 (tag 38696, valid
// from 2024-07-18). KSK-2010 (tag 19036) expired in 2019 and is omitted.
//
// These are compiled into the binary, so a future root KSK rollover requires a
// new release. A mismatch is reported as "indeterminate" and never as a
// problem of the audited domain.
var rootAnchors = []rootAnchor{
	{20326, dns.RSASHA256, dns.SHA256, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
	{38696, dns.RSASHA256, dns.SHA256, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
}

// RootAnchors returns the built-in trust anchors as DS records owned by ".".
func RootAnchors() []*dns.DS {
	out := make([]*dns.DS, 0, len(rootAnchors))
	for _, a := range rootAnchors {
		ds := &dns.DS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 86400}}
		ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest = a.keyTag, a.algorithm, a.digestType, a.digest
		out = append(out, ds)
	}
	return out
}
