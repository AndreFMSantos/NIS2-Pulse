package catalog

// en is the English catalog. It mirrors pt.go entry by entry (same IDs, examples,
// verification commands, sources and legal framing); tests compare the two. Texts
// describe technical evidence and never say that a domain "complies" with anything.
var en = map[string]Entry{
	// ---- Email: profile, SPF, DKIM, DMARC ----
	"email.mx.profile": {
		Title:   "Mail profile (MX records)",
		Why:     "MX records say who receives the domain's email. A domain with no MX receives mail badly but can still be used to send or spoof email, so how SPF and DMARC are judged depends on this profile.",
		Fix:     "If the domain does not receive email, declare a null MX (RFC 7505). If it does, check that the MX records point to the right servers.",
		Example: "{{domain}}. IN MX 0 .",
		Verify:  "dig +short MX {{domain}}",
	},
	"email.mx.resolves": {
		Title:   "The mail servers named by the MX records exist",
		Why:     "An MX record only names a host. If that name has no address (A or AAAA), or is an alias (CNAME), senders cannot deliver: the message is queued or bounced. The problem shows neither in the MX record nor in a scan of the domain, only when someone tries to send.",
		Fix:     "Create the A record (and AAAA, if you use IPv6) of the mail host named in the MX, or change the MX to a name that exists. The MX must not point to a CNAME: point it to the name that holds the address.",
		Example: "mail.{{domain}}. IN A 192.0.2.25\n{{domain}}. IN MX 10 mail.{{domain}}.",
		Verify:  "dig +short MX {{domain}}\ndig +short A mail.{{domain}}",
	},
	"email.subdomains.mx": {
		Title:   "Named subdomains: the mail servers of their MX records exist",
		Why:     "The mail of a subdomain (for example blog.example.pt) has its own MX records, which a scan of the main domain does not see. If the named server does not exist, senders cannot deliver to that subdomain and the problem only shows when someone tries.",
		Fix:     "For every subdomain that receives email, create the A (and AAAA) record of the mail server named in the MX, or correct the MX. If the subdomain does not receive email, declare a null MX.",
		Example: "blog.{{domain}}. IN MX 10 mail.blog.{{domain}}.\nmail.blog.{{domain}}. IN A 192.0.2.25",
		Verify:  "dig +short MX blog.{{domain}}\ndig +short A mail.blog.{{domain}}",
	},
	"email.spf.ip4": {
		Title:   "SPF ip4/ip6 addresses match the domain",
		Why:     "An SPF address that belongs to none of the domain own servers may be right (mail leaves through another server), but it is also what a mistake looks like: the web server address instead of the mail server, or an old IP. If it is wrong, legitimate mail fails SPF.",
		Fix:     "Confirm the real sending address in the headers of a message sent from the domain (the Received field) and correct the SPF to use it.",
		Example: "{{domain}}. IN TXT \"v=spf1 ip4:192.0.2.25 -all\"",
		Verify:  "dig +short TXT {{domain}}",
	},
	"email.spf.present": {
		Title:   "SPF record exists and is unique",
		Why:     "SPF (RFC 7208) says which servers may send email on behalf of the domain. Without it, or with more than one record, receivers cannot decide and the domain is easier to spoof.",
		Fix:     "Publish exactly one SPF TXT record and list the authorised senders in it. If the domain does not send email, publish an SPF that forbids every sender.",
		Example: "; domain that sends email\n{{domain}}. IN TXT \"v=spf1 include:_spf.your-provider.example -all\"\n; domain that does not send email\n{{domain}}. IN TXT \"v=spf1 -all\"",
		Verify:  "dig +short TXT {{domain}}",
	},
	"email.spf.policy": {
		Title:  "Final SPF policy (-all, ~all, ?all)",
		Why:    "The last mechanism decides what happens to senders that are not listed. -all rejects, ~all accepts but marks, ?all and +all protect nothing.",
		Fix:    "End the SPF with -all once every legitimate sender is listed. Move from ~all to -all only after the DMARC reports show that nothing legitimate fails.",
		Verify: "dig +short TXT {{domain}} | grep spf1",
	},
	"email.spf.lookups": {
		Title:  "SPF limit of 10 DNS lookups",
		Why:    "SPF may make at most 10 DNS lookups (include, a, mx, ptr, exists, redirect). Above that the receiver returns a permanent error and SPF stops working. include loops and the ptr mechanism make it worse.",
		Fix:    "Reduce the includes (drop providers you no longer use), replace mechanisms with ip4/ip6 ranges when they are stable, and avoid ptr.",
		Verify: "dig +short TXT {{domain}}\n# Count include, a, mx, exists and redirect, recursively: the total may not exceed 10",
	},
	"email.dkim.key": {
		Title:   "DKIM key published and usable",
		Why:     "DKIM (RFC 6376) signs messages to prove where they come from. A missing or duplicated record, one without a public key (empty p=, revoked key) or one in test mode (t=y) does not protect.",
		Fix:     "Publish the key at the selector your email provider gives you, with the exact selector and public key it supplies.",
		Example: "<selector>._domainkey.{{domain}}. IN TXT \"v=DKIM1; k=rsa; p=<public key>\"",
		Verify:  "# The selector is in the s= field of the DKIM-Signature header of a message the domain sent\ndig +short TXT <selector>._domainkey.{{domain}}",
	},
	"email.dkim.strength": {
		Title:  "DKIM key size",
		Why:    "RSA keys below 1024 bits can be broken; 1024 to 2047 bits are discouraged. The current recommendation is 2048 bits or more.",
		Fix:    "Generate a 2048-bit RSA key at the email provider, publish it under a new selector, switch sending to that selector and only then remove the old one.",
		Verify: "dig +short TXT <selector>._domainkey.{{domain}}\n# Copy p= (base64) to a file and read the key size with: openssl pkey -pubin -text -noout",
	},
	"email.dmarc.present": {
		Title:   "DMARC record exists",
		Why:     "DMARC (RFC 9989) ties SPF and DKIM to the visible From address and tells receivers what to do when they fail. Without it there is no policy against spoofing of the domain.",
		Fix:     "Start with a monitoring policy with reports, fix the legitimate senders that fail, then move to quarantine and then reject. If the domain does not send email, publish the reject policy right away.",
		Example: "; starting point\n_dmarc.{{domain}}. IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@{{domain}}\"\n; domain that does not send email\n_dmarc.{{domain}}. IN TXT \"v=DMARC1; p=reject\"",
		Verify:  "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.policy": {
		Title:  "Active DMARC policy (quarantine or reject)",
		Why:    "With p=none DMARC only observes: spoofed messages are still delivered. Only quarantine and reject protect.",
		Fix:    "Read the aggregate reports, fix the legitimate senders that fail, and move to p=quarantine and then p=reject.",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.enforcement": {
		Title:  "The DMARC policy is applied in full",
		Why:    "With t=y (test mode) or with pct below 100, part of the spoofed messages escapes the policy. They are meant for a gradual rollout, not as a final state. RFC 9989 removed the pct tag and introduced t.",
		Fix:    "Remove t=y (the default is t=n) and the pct tag when the rollout is over.",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.reporting": {
		Title:  "DMARC reports requested (rua)",
		Why:    "Without rua= you do not receive the aggregate reports that show who sends email on behalf of the domain, and without them it is hard to move to quarantine or reject safely.",
		Fix:    "Add rua=mailto:dmarc@{{domain}} to the DMARC record (or use a service that aggregates and reads the reports).",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},

	// ---- Email: MTA-STS, TLS-RPT, DANE, STARTTLS ----
	"email.mtasts.record": {
		Title:   "MTA-STS record",
		Why:     "MTA-STS (RFC 8461) makes servers that send to the domain use TLS with a valid certificate. Without it, an attacker on the network can force delivery in clear text (a downgrade attack).",
		Fix:     "Publish the record and serve the policy over HTTPS. The id must change whenever the policy changes (for example, the date).",
		Example: "_mta-sts.{{domain}}. IN TXT \"v=STSv1; id=20261109T000000\"\n; file https://mta-sts.{{domain}}/.well-known/mta-sts.txt\nversion: STSv1\nmode: testing\nmx: <mx-host>\nmax_age: 86400",
		Verify:  "dig +short TXT _mta-sts.{{domain}}",
	},
	"email.mtasts.fetch": {
		Title:  "The MTA-STS policy can be downloaded",
		Why:    "The record only counts if the policy exists over HTTPS, with a valid certificate, no redirects, as plain text and under 64 KiB.",
		Fix:    "Serve the file at https://mta-sts.{{domain}}/.well-known/mta-sts.txt with Content-Type text/plain, a valid certificate for mta-sts.{{domain}} and no redirect.",
		Verify: "curl -sS -i https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.mode": {
		Title:  "MTA-STS policy mode",
		Why:    "In testing or none mode the policy does not prevent delivery without TLS. Only enforce protects.",
		Fix:    "After confirming in the TLS-RPT reports that there are no legitimate failures, change mode: testing to mode: enforce and increase the record id.",
		Verify: "curl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.mx": {
		Title:  "The MTA-STS policy covers the real MX hosts",
		Why:    "In enforce mode, an MX that the policy does not list stops receiving email: senders refuse to deliver. It is a frequent mistake when changing email provider.",
		Fix:    "Make the mx: lines of the policy match the current MX records in the DNS (patterns such as *.provider.example are allowed) and increase the record id.",
		Verify: "dig +short MX {{domain}}\ncurl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.maxage": {
		Title:  "MTA-STS policy lifetime (max_age)",
		Why:    "max_age says how long senders cache the policy. RFC 8461 expects values of weeks or more; with short values the policy expires quickly and protection against attacks at refresh time drops. The tool warns below 1 day (a threshold of the tool, not of the RFC).",
		Fix:    "Use a max_age of weeks in production (for example 604800, one week, or 2592000, 30 days), after testing in testing mode with a low value.",
		Verify: "curl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.tlsrpt.record": {
		Title:   "TLS reports (TLS-RPT)",
		Why:     "TLS-RPT (RFC 8460) makes other servers send you reports of TLS failures. It is how you see MTA-STS and DANE problems before moving to enforce.",
		Fix:     "Publish the record with an address that somebody reads.",
		Example: "_smtp._tls.{{domain}}. IN TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@{{domain}}\"",
		Verify:  "dig +short TXT _smtp._tls.{{domain}}",
	},
	"email.dane.tlsa": {
		Title:   "DANE/TLSA records of the MX hosts",
		Why:     "DANE (RFC 7672) pins the certificate of each mail server in the DNS, protected by DNSSEC. It is optional but gives strong protection. A TLSA record in an unsigned zone is ignored by senders, and a TLSA record with an invalid signature makes mail get held back.",
		Fix:     "Sign the zone with DNSSEC and publish one TLSA record per MX host. Before replacing the certificate, publish the new TLSA next to the old one and wait for the TTL.",
		Example: "_25._tcp.<mx-host>. IN TLSA 3 1 1 <SHA-256 hash of the public key>",
		Verify:  "dig +dnssec +short TLSA _25._tcp.<mx-host>",
	},
	"email.dane.params": {
		Title:  "TLSA record parameters",
		Why:    "The usage, selector and matching type must be defined values and the data length must fit, otherwise the record is unusable.",
		Fix:    "Use the usual values: 3 1 1 (DANE-EE, public key, SHA-256) or 2 1 1 (DANE-TA).",
		Verify: "dig +short TLSA _25._tcp.<mx-host>",
	},
	"email.dane.match": {
		Title:  "The server certificate matches the TLSA record",
		Why:    "If the presented certificate matches no TLSA record, senders that validate DANE refuse to deliver the mail. It is the typical cause of held mail after renewing a certificate with a new key.",
		Fix:    "Publish the TLSA of the current certificate (or renew the certificate reusing the key). Do it before replacing the certificate.",
		Verify: "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host>\ndig +short TLSA _25._tcp.<mx-host>\n# Compare the presented certificate with the TLSA record",
	},
	"email.starttls.service": {
		Title:  "STARTTLS test on the MX hosts",
		Why:    "Summarises what could be tested. Many providers and networks block outbound port 25; in that case the result is unknown, not a failure.",
		Fix:    "If the result is unknown, repeat from a network that allows outbound port 25, or check manually.",
		Verify: "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host>",
	},
	"email.starttls.offered": {
		Title:  "The MX hosts offer STARTTLS",
		Why:    "Without STARTTLS, received mail travels in clear text between servers and can be read or altered on the network.",
		Fix:    "Enable TLS on the mail server (or at the provider) and check that EHLO announces STARTTLS.",
		Verify: "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host>",
	},
	"email.starttls.tls": {
		Title:  "TLS version on the MX hosts",
		Why:    "Versions below TLS 1.2 have known weaknesses (RFC 8996). If the handshake fails, the protection cannot be confirmed.",
		Fix:    "Configure the mail server for TLS 1.2 and 1.3 and disable the older versions.",
		Verify: "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host> -tls1_2",
	},
	"email.starttls.cert": {
		Title:  "Certificate of the MX hosts",
		Why:    "An untrusted certificate, one with the wrong name, an expired one or one with a weak key or signature takes value away from the encryption. Between servers many senders do not validate the certificate, so the impact depends on MTA-STS and DANE.",
		Fix:    "Install a valid certificate issued by a public CA for the MX name, with an RSA key of 2048 bits or more (or ECDSA), and renew it before it expires.",
		Verify: "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host> </dev/null | openssl x509 -noout -subject -issuer -dates",
	},

	// ---- DNS: DNSSEC and CAA ----
	"dns.dnssec.chain": {
		Title:  "DNSSEC chain of trust",
		Why:    "DNSSEC signs DNS answers so that they cannot be forged. A broken chain (for example a DS that does not match the zone's keys) makes validating resolvers stop resolving the domain.",
		Fix:    "If the zone is signed, publish at the registrar the DS given by the DNS provider and keep it updated at every change of provider or keys. If you do not want DNSSEC, remove the DS. Before touching the DS, confirm with an independent validating resolver (delv or dig +dnssec); an isolated validation failure may come from the resolver and not from the zone.",
		Verify: "dig +dnssec DS {{domain}}\ndelv {{domain}} @1.1.1.1",
	},
	"dns.dnssec.algorithm": {
		Title:  "DNSSEC signing algorithm",
		Why:    "SHA-1 based algorithms (5 and 7) are discouraged (RFC 9904), as is a DS with only a SHA-1 digest.",
		Fix:    "Switch to ECDSA P-256 (13) or Ed25519 (15) at the DNS provider and use a SHA-256 digest in the DS.",
		Verify: "dig +short DNSKEY {{domain}}\ndig +short DS {{domain}}",
	},
	"dns.dnssec.expiry": {
		Title:  "Validity of the DNSSEC signatures",
		Why:    "Signatures have an end date. If less than 48 hours remain, the re-signing process may have stopped and the zone will stop validating.",
		Fix:    "Ask the DNS provider to check the automatic re-signing. If you sign the zone yourself, check the schedule.",
		Verify: "dig +dnssec SOA {{domain}}\n# See the end date in the RRSIG",
	},
	"dns.caa.present": {
		Title:   "CAA records",
		Why:     "CAA (RFC 8659) says which certificate authorities may issue certificates for the domain. Without CAA, any public CA may.",
		Fix:     "Publish a CAA record with the CA you use and, if you want, a contact for incidents.",
		Example: "{{domain}}. IN CAA 0 issue \"letsencrypt.org\"\n{{domain}}. IN CAA 0 iodef \"mailto:security@{{domain}}\"",
		Verify:  "dig +short CAA {{domain}}",
	},
	"dns.caa.issue": {
		Title:  "CAA restricts who may issue",
		Why:    "A CAA with only iodef or issuewild restricts little. issue \";\" forbids all issuance, which is right for a domain without certificates.",
		Fix:    "Add one issue line for each authorised CA.",
		Verify: "dig +short CAA {{domain}}",
	},
	"dns.caa.iodef": {
		Title:   "Contact for issuance incidents (iodef)",
		Why:     "With iodef, a CA that refuses a request because of the CAA record can warn you of an unauthorised issuance attempt.",
		Fix:     "Add a contact where CAs can report certificate requests that violate the policy.",
		Example: "{{domain}}. IN CAA 0 iodef \"mailto:security@{{domain}}\"",
		Verify:  "dig +short CAA {{domain}}",
	},

	// ---- Transport: TLS ----
	"transport.tls.legacy": {
		Title:   "Old TLS versions enabled",
		Why:     "SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses and were retired by RFC 8996. Accepting them allows downgrade attacks.",
		Fix:     "Disable them on the web server or the load balancer.",
		Example: "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
		Verify:  "# Must fail. Recent openssl versions may need -cipher 'DEFAULT:@SECLEVEL=0'\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_1",
	},
	"transport.tls.modern": {
		Title:   "TLS 1.2 and 1.3 available",
		Why:     "TLS 1.3 is simpler and safer; a well configured TLS 1.2 is still acceptable. With neither there is no modern connection possible.",
		Fix:     "Enable TLS 1.3 and keep 1.2 for older clients.",
		Example: "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
		Verify:  "openssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_3",
	},
	"transport.tls.weakciphers": {
		Title:   "Broken cipher suites",
		Why:     "NULL, EXPORT, anonymous, RC4, DES or 3DES suites offer no real protection. The severity follows the worst suite accepted.",
		Fix:     "Restrict the suite list to the recommended ones (AEAD with ECDHE).",
		Example: "# nginx\nssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;\nssl_prefer_server_ciphers off;",
		Verify:  "# Must fail\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -cipher 'aNULL:eNULL:EXPORT:RC4:DES'",
	},
	"transport.tls.discouraged": {
		Title:  "Suites discouraged by IANA",
		Why:    "IANA marks some suites as discouraged (D) even though they are not broken. They reduce the safety margin.",
		Fix:    "Remove them from the server's suite list, keeping the recommended ones (Recommended = Y in the IANA registry).",
		Verify: "# The connection must not complete\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -cipher <suite>",
	},
	"transport.tls.forwardsecrecy": {
		Title:  "Forward secrecy",
		Why:    "With forward secrecy (ECDHE/DHE), stealing the server key later does not allow decrypting old traffic. Suites without it do not guarantee that.",
		Fix:    "Prefer ECDHE suites and remove those with static RSA key exchange.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null 2>/dev/null | grep -E 'Cipher|Server Temp Key'",
	},
	"transport.tls.inventory": {
		Title:  "Inventory of accepted suites",
		Why:    "Lists, per TLS version, everything the server accepts. It is the evidence on which the other TLS findings rest.",
		Fix:    "Not a failure. Use the list to review the server configuration.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_2 -cipher <suite>\n# Confirms one specific suite",
	},
	"transport.tls.service": {
		Title:  "TLS service on port 443",
		Why:    "Without a TLS service on port 443 (or if the port does not speak TLS), the transport tests do not apply to this domain.",
		Fix:    "If there should be HTTPS, check the server, the firewall and the DNS. If the domain has no website, ignore it.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null",
	},

	// ---- Transport: certificate ----
	"transport.cert.service": {
		Title:  "The certificate could be read",
		Why:    "Without a connection or a complete handshake the certificate cannot be assessed, so the remaining certificate findings are unknown.",
		Fix:    "Check that the server answers on {{domain}}:443 and that the firewall lets it through.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null",
	},
	"transport.cert.chain": {
		Title:  "Trusted certificate chain",
		Why:    "A self-signed certificate, one from an untrusted root or one without the intermediates makes browsers and clients show errors or refuse the connection.",
		Fix:    "Use a certificate from a public CA and configure the server to send the full chain (certificate plus intermediates).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} -showcerts </dev/null",
	},
	"transport.cert.hostname": {
		Title:  "The certificate is valid for this name",
		Why:    "If the domain name is not in the certificate, clients refuse the connection or show a warning.",
		Fix:    "Issue a certificate that includes {{domain}} in the Subject Alternative Name extension (or a suitable wildcard certificate).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -ext subjectAltName",
	},
	"transport.cert.validity": {
		Title:  "Certificate validity period",
		Why:    "An expired (or not yet valid) certificate makes the service unreachable for clients that validate. Expiry in less than 30 days deserves attention.",
		Fix:    "Renew the certificate and automate the renewal (for example ACME/Let's Encrypt renewing 30 days before the end).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -dates",
	},
	"transport.cert.lifetime": {
		Title:  "Total certificate lifetime (limit by issue date)",
		Why:    "The public PKI rules (CA/Browser Forum) limit the total validity of a certificate according to its issue date: 398 days until 2026-03-14, 200 days from 2026-03-15 to 2027-03-14, 100 days from 2027-03-15 to 2029-03-14 and 47 days after that. Longer lifetimes point to a CA outside the rules and slow down key rotation. Browsers may reject such certificates.",
		Fix:    "Use short-lived certificates with automatic renewal (for example ACME), so that the next reduction of the limit does not catch you by surprise.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -dates\n# The difference between notBefore and notAfter is the total lifetime",
	},
	"transport.cert.key": {
		Title:  "Certificate key strength",
		Why:    "RSA below 2048 bits and elliptic curves below 256 bits are not considered safe.",
		Fix:    "Generate a new RSA key of 2048 bits (or 3072) or an ECDSA P-256 key and request a new certificate.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -text | grep 'Public-Key'",
	},
	"transport.cert.signature": {
		Title:  "Certificate signature algorithm",
		Why:    "Signatures with SHA-1 or MD5 allow certificates to be forged.",
		Fix:    "Ask the CA for a certificate signed with SHA-256 or higher and also replace old intermediates.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -text | grep 'Signature Algorithm'",
	},
	"transport.cert.inventory": {
		Title:  "Certificate inventory",
		Why:    "Summarises the observed certificate: name, issuer, dates, key, algorithm, chain sent, SHA-256 fingerprint and negotiated suite. It is the evidence behind the other certificate findings.",
		Fix:    "Not a failure. Compare it with what you expected to have installed.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256",
	},

	// ---- Transport: HTTP headers ----
	"transport.http.service": {
		Title:  "HTTPS response of the site",
		Why:    "Records the response code used to assess the headers. A 5xx error prevents a reliable assessment.",
		Fix:    "If it is a 5xx error, fix the origin server or the link with the CDN and repeat the test.",
		Verify: "curl -sSI https://{{domain}}",
	},
	"transport.hsts.header": {
		Title:   "HSTS (Strict-Transport-Security)",
		Why:     "HSTS (RFC 6797) makes the browser always use HTTPS, which prevents downgrade and interception attacks on the first unencrypted connection.",
		Fix:     "Send the header on every HTTPS response. Start with a low value and raise it.",
		Example: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		Verify:  "curl -sSI https://{{domain}} | grep -i strict-transport-security",
	},
	"transport.csp.header": {
		Title:   "Content-Security-Policy",
		Why:     "CSP limits where the site may load scripts and other resources from, which reduces the impact of XSS flaws. Report-only mode, 'unsafe-inline', 'unsafe-eval' or * in scripts take value away from it.",
		Fix:     "Define a restrictive policy and test it first in report-only mode (Content-Security-Policy-Report-Only).",
		Example: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
		Verify:  "curl -sSI https://{{domain}} | grep -i content-security-policy",
	},

	// ---- Routing ----
	"routing.origin": {
		Title:  "BGP origin of the addresses",
		Why:    "Shows which autonomous system (AS) and which prefix announce each address of the domain and of the mail servers. It is the basis for validating RPKI.",
		Fix:    "Not a failure. An address that is not announced in BGP is not reachable on the public Internet.",
		Verify: "# Reverse the octets of the IPv4 address (1.2.3.4 becomes 4.3.2.1)\ndig +short TXT <reversed-octets>.origin.asn.cymru.com",
	},
	"routing.rpki.roa": {
		Title:  "RPKI validation of the origin",
		Why:    "RPKI (RFC 6811) ties a prefix to the AS authorised to announce it. An invalid announcement is dropped by networks that validate, and the lack of a ROA leaves the prefix exposed to route hijacks.",
		Fix:    "The fix depends on whoever holds the prefix, normally the network or hosting provider: ask it to create or correct the ROA (right origin AS and maxLength). It cannot be fixed in the domain's DNS.",
		Verify: "curl -sS 'https://stat.ripe.net/data/rpki-validation/data.json?resource=AS<n>&prefix=<prefix>'",
	},
	"routing.geo": {
		Title:  "Approximate location of the addresses",
		Why:    "Gives the country that a geolocation database associates with each address. It is approximate: CDN anycast addresses have no location and a location does not prove where data is stored.",
		Fix:    "Not a failure. To know where data is processed, consult the contract and the provider's documentation.",
		Verify: "curl -sS 'https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=<address>'",
	},
}

// checkNamesEN names each check for the generated "check not completed" entries.
var checkNamesEN = map[string]string{
	"email.mx":            "MX records",
	"email.subdomains":    "named subdomains (MX)",
	"email.spf":           "SPF",
	"email.dkim":          "DKIM",
	"email.dmarc":         "DMARC",
	"email.mtasts.policy": "MTA-STS policy",
	"email.tlsrpt":        "TLS-RPT",
	"email.dane":          "DANE/TLSA",
	"email.starttls":      "STARTTLS on the MX hosts",
	"transport.tls":       "TLS versions and suites",
	"transport.cert":      "X.509 certificate",
	"transport.web":       "HTTP security headers",
	"dns.dnssec":          "DNSSEC",
	"dns.caa":             "CAA",
	"routing":             "routing (RIPEstat)",
}

func init() {
	for id, name := range checkNamesEN {
		if _, ok := en[id]; ok {
			continue
		}
		en[id] = Entry{
			Title:  "Check not completed: " + name,
			Why:    "This identifier appears when the whole check produced no result: it was skipped (active checks need --active and routing is switched off by --no-routing), timed out or had an internal error. It is not a failure of the domain.",
			Fix:    "If it was skipped, repeat with --active (only on your own domains or with written authorisation) or without --no-routing. If it timed out, repeat or raise --timeout.",
			Verify: "# Read the detail field of the finding: it says why the check was not completed",
		}
	}
}
