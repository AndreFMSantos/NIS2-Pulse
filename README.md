# nis2-pulse

External network-surface and cryptographic-hygiene checker for domains in scope of the EU
NIS2 Directive (2022/2555) and Portugal's Decreto-Lei 125/2025. Single static Go binary.

> **Not an audit and not a certification.** nis2-pulse collects externally observable
> technical evidence (DNS, email authentication, transport security). It cannot measure
> processes, supply-chain management, training or internal controls, so it never reports
> a "compliance percentage". Findings are *evidence related to* technical measures.

**Status:** active development (email, DNS, transport and routing checks, PT/EN Markdown reports, and `watch` monitoring with ntfy alerts implemented).

| Check | Findings | Tier |
|---|---|---|
| Mail profile (RFC 5321 §5.1, RFC 7505, RFC 2181 §10.3) | `email.mx.profile` / `.resolves` (every MX host has an address and is not an alias) | passive |
| SPF (RFC 7208) | `email.spf.present` / `.policy` / `.lookups` / `.ip4` (info: ip4/ip6 terms that match no address of the domain or its MX hosts) | passive |
| Mail of named subdomains (RFC 2181 §10.3) | `email.subdomains.mx` (needs `--subdomain`; the MX hosts of each subdomain must resolve) | passive |
| DKIM (RFC 6376) | `email.dkim.key` / `.strength` (needs `--dkim-selector`) | passive |
| DMARC (RFC 9989) | `email.dmarc.present` / `.policy` / `.enforcement` / `.reporting` | passive |
| DNSSEC chain (RFC 4033-4035) | `dns.dnssec.chain` / `.algorithm` / `.expiry` | passive |
| CAA (RFC 8659) | `dns.caa.present` / `.issue` / `.iodef` | passive |
| MTA-STS record (RFC 8461) | `email.mtasts.record` | passive |
| TLS-RPT (RFC 8460) | `email.tlsrpt.record` | passive |
| TLS versions and cipher suites (RFC 8996, 7568, 8446) | `transport.tls.legacy` / `.modern` / `.weakciphers` / `.discouraged` / `.forwardsecrecy` / `.inventory` / `.service` | **active** (`--active`) |
| MTA-STS policy (RFC 8461) | `email.mtasts.fetch` / `.mode` / `.mx` / `.maxage` | **active** (`--active`) |
| Certificate of `<domain>:443` (RFC 5280, 9525) | `transport.cert.service` / `.chain` / `.hostname` / `.validity` / `.lifetime` / `.key` / `.signature` / `.inventory` | **active** (`--active`) |
| HSTS and CSP headers (RFC 6797) | `transport.hsts.header` / `transport.csp.header` / `transport.http.service` | **active** (`--active`) |
| DANE TLSA records of the MX hosts (RFC 7672, 6698) | `email.dane.tlsa` / `.params` | passive |
| STARTTLS on the MX hosts (RFC 3207) and DANE match | `email.starttls.service` / `.offered` / `.tls` / `.cert`, `email.dane.match` | **active** (`--active`) |
| Routing of the domain's and MX hosts' addresses: origin AS, RPKI origin validation (RFC 6811), approximate geolocation | `routing.origin` / `routing.rpki.roa` / `routing.geo` | passive, queries RIPEstat (see below) |


DKIM selectors cannot be listed from DNS, so you supply them (repeat the flag or use commas, at
most 10); without one the DKIM result is `unknown`, never a failure. Find a selector in the `s=`
tag of the `DKIM-Signature` header of a message the domain sent.

### Report (`--format md`)

The Markdown report (Portuguese by default, English with `--lang en`) has a summary table with **one note from 0 to 100
per area** (email, DNS, transport, routing) and **no global note**, then, for every failure or warning, why it
matters, how to fix it, commands to verify it by hand, the **standards behind it with verbatim quotes** and, for
findings about cryptography, the legal provision the evidence relates to.

- The note starts at 100 and loses points per failed or doubtful check (fail: critical 40, high 25, medium 12,
  low 5; warn: critical 20, high 12, medium 6, low 2; a finding without severity counts as medium). An area where no
  check reached a verdict shows `n/d`, not a number. It is a hygiene indicator, **not a compliance percentage**.
- Citations are exact phrases. `make check-sources` fetches the RFC texts and fails if a quote or a section number
  is not there. Legal quotes (quotations of Portuguese law stay in Portuguese in the English report; Decreto-Lei 125/2025 art. 27.º n.º 1 al. g); NIS2 art. 21.º n.º 2 al. h); Regulamento de
  Execução (UE) 2024/2690 ponto 9.2 al. a)) were checked by hand against the official texts. The report says that these
  articles frame the evidence and do not mean that an entity complies or fails to comply.
- Legal framing is attached only where an official provision names the subject, read in the official text:
  cryptography (Decreto-Lei 125/2025 art. 27.º n.º 1 al. g); NIS2 art. 21.º n.º 2 al. h); Regulamento de Execução
  (UE) 2024/2690 ponto 9.2 a)), email standards (2024/2690 ponto 6.7.2 k)), DNS and routing security (6.7.2 l)),
  plus the non-binding ENISA guidance that lists SPF, DKIM, DMARC, STARTTLS, DANE, DNSSEC and BGP. Regulation
  2024/2690 applies directly only to the "entidades pertinentes" of its article 1 (DNS, TLD, cloud, CDN, managed
  services, trust services...); the report says so. CAA, geolocation, CSP and the mail profile have no provision that
  names them, and get none. The Decreto-Lei has no provision on email standards or DNS. The CNCS Regulation 756/2026
  does not name DNS, DNSSEC or RPKI, and its annex III (private essential and important entities) names no email authentication or HSTS either, but that annex III (mandatory minimum measures,
  art. 30) has control PR.SD-2 on protecting data in transit (Basic level: cryptographic mechanisms, with "technical
  evidence" as the verification criterion; High level: all external interfaces), so TLS, certificate, HSTS, STARTTLS,
  MTA-STS and DANE findings cite it; PR.SP-1 (disable unnecessary protocols) is cited, as an interpretation, by the
  legacy-TLS finding. Annex IV (public relevant entities only, groups B and A) has control T.PEW, which does name email
  authentication, secure protocols and certificates, and, for group A, the security headers of web pages: the SPF, DKIM,
  DMARC, TLS, certificate and (group A) HSTS/CSP findings cite it with the page and say it is for public entities only.
  For annex III the level that applies to an entity comes from its risk matrix, which an external scan cannot know,
  and every reference says so. The report prints the date the legal sources were last checked and warns after 180 days.
- Everything that came from the network (TXT records, headers) is untrusted: it is cleaned, truncated and placed
  in a code span or block that it cannot close, so a hostile domain cannot inject headings, links or HTML.

### Entity profile (`--entity`, `--reg2690`)

Some legal references only apply to certain entities: annex IV (control T.PEW) of CNCS Regulation 756/2026 is for **public relevant entities**, annex III (for example PR.SD-2) for **essential and important entities**, and Implementing Regulation (EU) 2024/2690 only for the entities its article 1 lists. By default the report prints every reference, each with its own caveat. `--entity eei|public` and `--reg2690 yes|no` filter them. The profile is a **declaration**: the tool cannot know it (it depends on the registration with the CNCS and on the risk matrix) and does not check it. The report states the profile used in its notes, and the JSON output echoes it (`profile`) only when given. The findings and scores never change with the profile.

### Supplier report (`suppliers`)

`nis2-pulse suppliers suppliers.txt` scans every domain of a list (one per line, `domain` or `domain;name`, `#` for comments, at most 50) and prints **one comparative report**: a table with the note of each area per supplier, the suppliers that need attention first, the findings to fix per supplier, and the suppliers that could not be scanned. `--format json`, `--lang en`, `--no-routing` and `--concurrency 1..8` (default 3) are available.

It is **passive only** (DNS and RIPEstat): there is no `--active`, because the checks that connect to a server need the owner's permission. So the Transport area is always "n/a". There is **no global score**, and the report says what it cannot know (which service the supplier provides, other domains it uses, the contract). It is an input to the supplier assessment that CNCS Regulation 756/2026 asks for (annex III, GR.CA-7, High level), not the assessment.

### Monitoring (`watch`) and ntfy alerts

`nis2-pulse watch <domain>` repeats the scan and tells you when something gets **worse**, through a push
notification on an [ntfy](https://ntfy.sh) topic (your own server on the LAN or a VPN works; no hosted service of ours).

```bash
nis2-pulse watch --test-notify --ntfy-url-file ~/.config/nis2-pulse/ntfy-url example.pt   # check the topic works
nis2-pulse watch --ntfy-url-file ~/.config/nis2-pulse/ntfy-url example.pt                # one scan, for cron / a timer
nis2-pulse watch --interval 24h example.pt                                               # loop, stops cleanly on SIGINT/SIGTERM
```

`contrib/systemd/` has a user timer (`nis2-pulse-watch@example.pt.timer`, daily, no root); the unit files were checked
with `systemd-analyze verify` but not run under systemd.

- **What is news.** Only a change for the worse compared with the last scan (a finding whose penalty in the area note
  grew, or a new failing finding). An unchanged failure is not repeated; a fix is not notified unless `--notify-resolved`.
  The first scan, and the first one after switching between passive and `--active`, is a silent baseline. Checks that
  only exist because the tool was upgraded join the baseline instead of alerting. A check that stops producing a verdict
  is reported only after 3 scans in a row, once. Three scans in a row that cannot run (resolver down, domain gone) give
  one alert; the old state is kept.
- **Delivery before memory.** The state is saved only after the notification was delivered; if ntfy is down, the same
  change is notified at the next run.
- **The topic URL is a secret.** It comes from `NIS2_PULSE_NTFY_URL` or `--ntfy-url-file` (a URL as an argument is
  refused: it would show in the process list), is never printed or logged (errors show the host only), and a URL file that
  other users can read gets a warning. Credentials in the URL (`https://user:pass@host/topic`, or `https://:tk_token@host/topic`)
  are sent as basic authentication.
- **What the notification contains.** Identifiers, catalog titles and fixed words, never DNS or HTTP text from the audited
  domain. Redirects from the ntfy server are not followed. The destination is chosen by the operator, so it may be a private
  address; the public-address rule of the scanner does not apply to it.
- **State.** One JSON file per domain in `$XDG_STATE_HOME/nis2-pulse` (default `~/.local/state/nis2-pulse`), mode 0600 in a
  0700 directory, written atomically. A damaged, foreign or newer file stops the command (exit 1) and is never overwritten.
- **Politeness.** `--interval` is at least 1h, and at least 6h with `--active` (which connects directly to the target's servers; recommended only with owner consent).

### Routing check and RIPEstat

The routing check never connects to the audited servers. It resolves the A/AAAA records of the domain
and of its MX hosts (at most 10 hosts and 12 public addresses) and asks **RIPEstat**
(`stat.ripe.net`, run by the RIPE NCC) which prefix and origin AS announce each address, whether the
RPKI authorises that origin, and which country a MaxMind GeoLite database associates with it.
RIPEstat is a third party: it learns the public addresses, ASNs and prefixes of the domain, nothing
else. Addresses that are not public are never sent, and `--no-routing` turns the check off, in which
case nothing is sent and the three findings are `unknown`.

- `routing.rpki.roa` is `fail` (high) when a covering ROA exists but does not authorise the origin
  (`invalid_asn`, or `invalid_length` when the announcement is more specific than the ROA allows),
  `warn` (low) when no ROA covers the prefix, `pass` when every origin is valid. The ROA is created
  by whoever holds the prefix, usually the network or hosting provider, so the finding says
  `fixer: provider`. If any lookup fails the result is `unknown`, never `pass`.
- `routing.origin` and `routing.geo` are informative. Geolocation is approximate (anycast addresses
  have no location) and says nothing about where data is stored.
- The client is `internal/ripestat`: it accepts only well-formed IPs, ASNs and prefixes, never follows
  redirects, limits the response size and retries a transient failure once.

### Active checks and their safeguards

Five checks are active: the MTA-STS policy fetch, the TLS probe (versions and cipher suites), the certificate inspection, the HTTP security headers and STARTTLS on the MX hosts.
The TLS probe sends a hand-built ClientHello (`internal/tlsprobe`), because Go's `crypto/tls` never
offers SSLv3, export, NULL or anonymous suites and so can never detect them. It reads only the
server's first answer (ServerHello or alert) and closes: it never completes a handshake, sends no
application data and makes no trust decision. It asks per protocol version with every suite of
the IANA registry on offer, removes the suite the server picks and asks again, so a normal server
takes about 20 sequential connections (budget: 150, 20 ms pause between probes). A scan that cannot
finish never reports a pass.

By default, `nis2-pulse` runs in **passive mode**: it only queries public DNS and public registries
such as RIPEstat, opening zero connections to the target's servers. Active checks open direct
TLS, HTTP, and SMTP connections to servers named by the audited domain's DNS (leaving entries in
their logs), so they only run when `--active` is passed. The flag enforces no technical ownership
check; because it contacts the target's infrastructure directly, using `--active` is recommended
only for domains you own or when the owner agrees. Even then:

- an MTA-STS check connects only when the domain publishes the matching record (exactly one
  `_mta-sts` TXT record and at least one MX), and makes a single request; the TLS probe, the
  certificate inspection and the header check connect only to `<domain>:443` (the header check makes
  one GET and never reads the body);
- the STARTTLS check connects only to the MX hosts the domain publishes (at most ten, one connection
  each, one after the other; none for a domain without MX or with a null MX). It sends EHLO,
  STARTTLS, the TLS handshake and QUIT, and **never** MAIL, RCPT, DATA, VRFY, EXPN or AUTH, so no
  mail is created and no address is probed. Replies are read byte by byte so nothing a hostile
  server appends after "220 Go ahead" is swallowed. Many ISPs and clouds block outbound port 25:
  that gives `unknown`, never a verdict. The announced EHLO name is `nis2-pulse.invalid`; change it
  with `--ehlo-name`. MX hosts may belong to a mail provider: the connection is the same as any
  sending mail server makes, but state it in your authorisation;
- the certificate inspection is the only place where Go's certificate verification is switched off
  (`internal/certinspect`), so that expired or self-signed certificates can be read; the chain is
  then verified in our own code and the outcome is always reported. A test fails if any other file
  mentions the option;
- every connection (HTTP and raw TCP) resolves names through the scan's resolver and **refuses to
  connect if any address is not public** (loopback, private, link-local such as the 169.254.169.254 cloud
  metadata address, CGNAT, documentation ranges), so a hostile DNS cannot aim the tool at
  internal services;
- it never follows redirects, never skips certificate verification (a bad certificate is itself
  a finding), requires TLS 1.2+, ignores proxy variables and bounds response size and time.

```bash
nis2-pulse scan example.com            # JSON on stdout
nis2-pulse scan example.com --resolver 9.9.9.9
nis2-pulse scan example.com --dkim-selector selector1,selector2

# the mail setup of subdomains cannot be listed from DNS, so name them (relative or full, at most 20; nothing is guessed)
nis2-pulse scan example.com --subdomain blog,mail.blog
nis2-pulse scan example.com --active                 # also TLS, certificate, headers, MTA-STS, STARTTLS (connects directly to target; own domains only)
nis2-pulse scan example.com --active --ehlo-name scanner.example.org
nis2-pulse scan example.com --no-routing            # do not query RIPEstat
nis2-pulse scan example.com --format md              # human report in Portuguese (JSON is the default)
nis2-pulse scan example.com --format md --lang en    # the same report in English
nis2-pulse scan example.com --format md --entity public --reg2690 no   # show only the legal references that apply to the declared entity
```

Notes on DNSSEC: queries use the CD bit and the chain is validated here, so a broken chain
is reported at the exact link instead of as SERVFAIL. A missing DS is reported as an
unsigned delegation without NSEC/NSEC3 proof. The IANA root trust anchors are compiled in;
after a root KSK rollover a new release is needed (until then the result is `unknown`).

## Scope and safety model

| Tier | What it does | How it is enabled |
|---|---|---|
| Passive | Public data only: DNS and public registries such as RIPEstat (`--no-routing` skips it) | default |
| Active | Direct connections to the target's own servers (TLS, HTTP, SMTP) | `--active` |

Never: port scanning, vulnerability probing or exploitation. Passive mode touches only public DNS
and registries; `--active` connects directly to the target's servers and is recommended only for
domains you own or when the owner consents.

## Build

```bash
make test lint build
./bin/nis2-pulse version
```

## Dependencies

Minimal and justified. DNS wire format and DNSSEC signature verification use
`codeberg.org/miekg/dns` (v2); the DNSSEC chain walk is implemented in this project.

## License

AGPL-3.0, see [LICENSE](LICENSE).
