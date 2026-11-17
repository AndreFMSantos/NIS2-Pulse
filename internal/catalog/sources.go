package catalog

import "time"

// Source is a citation that backs a catalog entry. Quote is a verbatim phrase
// from the source, so a reader (and a test) can confirm the claim is not an
// invention. RFC quotes are checked by TestRFCQuotesExist (NIS2_CHECK_SOURCES=1);
// the others were checked by hand against the copies in the vault library
// (00-System/references/official-docs) on 2026-11-11 and have Manual set.
type Source struct {
	// Ref is the human reference, for example "RFC 7208 §4.6.4".
	Ref string
	// RefEN is the English wording of Ref for the sources whose Ref is not
	// language-neutral (laws, guidance); empty means Ref is used.
	RefEN string
	// URL points to the source (for RFCs, the section).
	URL string
	// Quote is a verbatim phrase from the source, in the source's language.
	Quote string
	// Manual means the quote was not checked by an automated test.
	Manual bool
	// Scope limits the entities the source applies to (see Profile); empty means all.
	Scope Scope
}

// SourcesCheckedAt is the day the legal and guidance quotes were last checked against the
// official documents (vault script verify-catalog-sources.mjs, and `make check-sources` for the
// RFCs). Update it every time that check is repeated: reports print it and warn when it is old.
var SourcesCheckedAt = time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)

// Label returns the reference as shown in a report in lang.
func (s Source) Label(lang Lang) string {
	if lang == EN && s.RefEN != "" {
		return s.RefEN
	}
	return s.Ref
}

// sources maps a finding ID to the technical standards that define the check.
// Generated from the RFC texts with the section computed from the text, never
// typed from memory; keep the quotes verbatim.
var sources = map[string][]Source{
	"dns.caa.iodef": {
		{Ref: "RFC 8659 §4.4", URL: "https://www.rfc-editor.org/rfc/rfc8659#section-4.4", Quote: "The iodef Property specifies a means of reporting certificate issue requests"},
	},
	"dns.caa.issue": {
		{Ref: "RFC 8659 §3", URL: "https://www.rfc-editor.org/rfc/rfc8659#section-3", Quote: "CAA does not restrict issuance"},
		{Ref: "RFC 8659 §4.2", URL: "https://www.rfc-editor.org/rfc/rfc8659#section-4.2", Quote: "nocerts.example.com CAA 0 issue \";\""},
	},
	"dns.caa.present": {
		{Ref: "RFC 8659", URL: "https://www.rfc-editor.org/rfc/rfc8659", Quote: "allows a DNS domain name holder to specify one or more Certification Authorities (CAs) authorized to issue certificates for that domain name"},
	},
	"dns.dnssec.algorithm": {
		{Ref: "RFC 9904 §1.2", URL: "https://www.rfc-editor.org/rfc/rfc9904#section-1.2", Quote: "it is recommended that algorithms that have been downgraded to NOT RECOMMENDED or lower not be used by authoritative nameservers and DNSSEC signers to create new DNSKEYs"},
	},
	"dns.dnssec.chain": {
		{Ref: "RFC 4035 §4.3", URL: "https://www.rfc-editor.org/rfc/rfc4035#section-4.3", Quote: "establish a chain of trust"},
	},
	"dns.dnssec.expiry": {
		{Ref: "RFC 4034 §3.1.5", URL: "https://www.rfc-editor.org/rfc/rfc4034#section-3.1.5", Quote: "MUST NOT be used for authentication after the expiration date"},
	},
	"email.dane.match": {
		{Ref: "RFC 7672 §3.1.1", URL: "https://www.rfc-editor.org/rfc/rfc7672#section-3.1.1", Quote: "Authentication via certificate usage DANE-EE(3) TLSA records involves simply checking that the server's leaf certificate matches the TLSA record"},
	},
	"email.dane.params": {
		{Ref: "RFC 7672 §3.1", URL: "https://www.rfc-editor.org/rfc/rfc7672#section-3.1", Quote: "we RECOMMEND the use of \"DANE-EE(3) SPKI(1) SHA2-256(1)\""},
	},
	"email.dane.tlsa": {
		{Ref: "RFC 7672 §2.2", URL: "https://www.rfc-editor.org/rfc/rfc7672#section-2.2", Quote: "DNSSEC-validated TLSA records MUST NOT be published for servers that do not support TLS"},
	},
	"email.dkim.key": {
		{Ref: "RFC 6376 §3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc6376#section-3.6.1", Quote: "An empty value means that this public key has been revoked"},
	},
	"email.dkim.strength": {
		{Ref: "RFC 8301 §3.2", URL: "https://www.rfc-editor.org/rfc/rfc8301#section-3.2", Quote: "Signers SHOULD use RSA keys of at least 2048 bits"},
		{Ref: "RFC 8301 §3.2", URL: "https://www.rfc-editor.org/rfc/rfc8301#section-3.2", Quote: "MUST NOT consider signatures using RSA keys of less than 1024 bits as valid signatures"},
	},
	"email.dmarc.enforcement": {
		{Ref: "RFC 9989 §4.7", URL: "https://www.rfc-editor.org/rfc/rfc9989#section-4.7", Quote: "A request that the actor performing the DMARC validation check not apply the policy"},
		{Ref: "RFC 9989 §A.6", URL: "https://www.rfc-editor.org/rfc/rfc9989#appendix-A.6", Quote: "Operational experience showed that the \"pct\" tag was usually not accurately applied"},
	},
	"email.dmarc.policy": {
		{Ref: "RFC 9989 §4.7", URL: "https://www.rfc-editor.org/rfc/rfc9989#section-4.7", Quote: "none: The Domain Owner offers no expression of preference"},
		{Ref: "RFC 9989 §4.7", URL: "https://www.rfc-editor.org/rfc/rfc9989#section-4.7", Quote: "quarantine: The Domain Owner considers such mail to be suspicious"},
	},
	"email.dmarc.present": {
		{Ref: "RFC 9989 §4.10.1", URL: "https://www.rfc-editor.org/rfc/rfc9989#section-4.10.1", Quote: "The DMARC Policy Record to be applied to an email message will be the record found at any of the following locations"},
	},
	"email.dmarc.reporting": {
		{Ref: "RFC 9989 §4.7", URL: "https://www.rfc-editor.org/rfc/rfc9989#section-4.7", Quote: "rua: Addresses to which aggregate feedback reports are to be sent"},
	},
	"email.mtasts.fetch": {
		{Ref: "RFC 8461 §3.3", URL: "https://www.rfc-editor.org/rfc/rfc8461#section-3.3", Quote: "HTTP 3xx redirects MUST NOT be followed"},
	},
	"email.mtasts.maxage": {
		{Ref: "RFC 8461 §3.2", URL: "https://www.rfc-editor.org/rfc/rfc8461#section-3.2", Quote: "it is expected that this value typically be in the range of weeks or greater"},
	},
	"email.mtasts.mode": {
		{Ref: "RFC 8461 §5", URL: "https://www.rfc-editor.org/rfc/rfc8461#section-5", Quote: "In this mode, Sending MTAs MUST NOT deliver the message to hosts that fail MX matching or certificate validation or that do not support STARTTLS"},
	},
	"email.mtasts.mx": {
		{Ref: "RFC 8461 §5", URL: "https://www.rfc-editor.org/rfc/rfc8461#section-5", Quote: "In this mode, Sending MTAs MUST NOT deliver the message to hosts that fail MX matching or certificate validation or that do not support STARTTLS"},
	},
	"email.mtasts.record": {
		{Ref: "RFC 8461", URL: "https://www.rfc-editor.org/rfc/rfc8461", Quote: "is a mechanism enabling mail service providers (SPs) to declare their ability to receive Transport Layer Security (TLS) secure SMTP connections"},
	},
	"email.mx.profile": {
		{Ref: "RFC 7505", URL: "https://www.rfc-editor.org/rfc/rfc7505", Quote: "formalizes the existing mechanism by which a domain announces that it accepts no mail"},
		{Ref: "RFC 5321 §5.1", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-5.1", Quote: "treated as if it was associated with an implicit MX RR, with a preference of 0"},
	},
	"email.mx.resolves": {
		{Ref: "RFC 2181 §10.3", URL: "https://www.rfc-editor.org/rfc/rfc2181#section-10.3", Quote: "This domain name must have as its value one or more address records."},
		{Ref: "RFC 5321 §5.1", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-5.1", Quote: "specifically including a value that will return a CNAME record when queried, lies outside the scope of this Standard"},
	},
	"email.subdomains.mx": {
		{Ref: "RFC 2181 §10.3", URL: "https://www.rfc-editor.org/rfc/rfc2181#section-10.3", Quote: "This domain name must have as its value one or more address records."},
		{Ref: "RFC 5321 §5.1", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-5.1", Quote: "specifically including a value that will return a CNAME record when queried, lies outside the scope of this Standard"},
	},
	"email.spf.ip4": {
		{Ref: "RFC 7208 §5.6", URL: "https://www.rfc-editor.org/rfc/rfc7208#section-5.6", Quote: "These mechanisms test whether <ip> is contained within a given IP network."},
	},
	"email.spf.lookups": {
		{Ref: "RFC 7208 §4.6.4", URL: "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4", Quote: "SPF implementations MUST limit the total number of those terms to 10 during SPF evaluation"},
		{Ref: "RFC 7208 §5.5", URL: "https://www.rfc-editor.org/rfc/rfc7208#section-5.5", Quote: "This mechanism SHOULD NOT be published"},
	},
	"email.spf.policy": {
		{Ref: "RFC 7208 §5.1", URL: "https://www.rfc-editor.org/rfc/rfc7208#section-5.1", Quote: "The \"all\" mechanism is a test that always matches"},
	},
	"email.spf.present": {
		{Ref: "RFC 7208 §3.2", URL: "https://www.rfc-editor.org/rfc/rfc7208#section-3.2", Quote: "A domain name MUST NOT have multiple records that would cause an authorization check to select more than one record"},
	},
	"email.starttls.cert": {
		{Ref: "RFC 8461 §4.2", URL: "https://www.rfc-editor.org/rfc/rfc8461#section-4.2", Quote: "The certificate presented by the receiving MTA MUST not be expired and MUST chain to a root CA that is trusted by the Sending MTA"},
	},
	"email.starttls.offered": {
		{Ref: "RFC 3207", URL: "https://www.rfc-editor.org/rfc/rfc3207", Quote: "allows an SMTP server and client to use TLS (Transport Layer Security) to provide private, authenticated communication over the Internet"},
	},
	"email.starttls.service": {
		{Ref: "RFC 3207", URL: "https://www.rfc-editor.org/rfc/rfc3207", Quote: "allows an SMTP server and client to use TLS (Transport Layer Security) to provide private, authenticated communication over the Internet"},
	},
	"email.starttls.tls": {
		{Ref: "RFC 8996 §5", URL: "https://www.rfc-editor.org/rfc/rfc8996#section-5", Quote: "TLS 1.1 MUST NOT be used"},
		{Ref: "RFC 8996 §4", URL: "https://www.rfc-editor.org/rfc/rfc8996#section-4", Quote: "TLS 1.0 MUST NOT be used"},
	},
	"email.tlsrpt.record": {
		{Ref: "RFC 8460 §3", URL: "https://www.rfc-editor.org/rfc/rfc8460#section-3", Quote: "records that do not begin with \"v=TLSRPTv1;\" are discarded"},
	},
	"routing.rpki.roa": {
		{Ref: "RFC 6811 §2", URL: "https://www.rfc-editor.org/rfc/rfc6811#section-2", Quote: "Valid: At least one VRP Matches the Route Prefix"},
		{Ref: "RFC 6811 §2", URL: "https://www.rfc-editor.org/rfc/rfc6811#section-2", Quote: "Invalid: At least one VRP Covers the Route Prefix, but no VRP Matches it"},
		{Ref: "RFC 6811 §2", URL: "https://www.rfc-editor.org/rfc/rfc6811#section-2", Quote: "NotFound: No VRP Covers the Route Prefix"},
	},
	"transport.cert.chain": {
		{Ref: "RFC 5280", URL: "https://www.rfc-editor.org/rfc/rfc5280", Quote: "An algorithm for X.509 certification path validation is described"},
	},
	"transport.cert.hostname": {
		{Ref: "RFC 9525 §1.5", URL: "https://www.rfc-editor.org/rfc/rfc9525#section-1.5", Quote: "DNS-ID: A subjectAltName entry of type dNSName"},
	},
	"transport.cert.validity": {
		{Ref: "RFC 5280 §4.1.2.5", URL: "https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5", Quote: "Both notBefore and notAfter may be encoded as UTCTime or GeneralizedTime"},
	},
	"transport.hsts.header": {
		{Ref: "RFC 6797 §6.1.1", URL: "https://www.rfc-editor.org/rfc/rfc6797#section-6.1.1", Quote: "The REQUIRED \"max-age\" directive specifies the number of seconds"},
	},
	"transport.tls.forwardsecrecy": {
		{Ref: "RFC 10015 §1", URL: "https://www.rfc-editor.org/rfc/rfc10015#section-1", Quote: "RSA key exchange offers no forward secrecy, by construction"},
	},
	"transport.tls.legacy": {
		{Ref: "RFC 8996 §4", URL: "https://www.rfc-editor.org/rfc/rfc8996#section-4", Quote: "TLS 1.0 MUST NOT be used"},
		{Ref: "RFC 8996 §5", URL: "https://www.rfc-editor.org/rfc/rfc8996#section-5", Quote: "TLS 1.1 MUST NOT be used"},
		{Ref: "RFC 7568 §3", URL: "https://www.rfc-editor.org/rfc/rfc7568#section-3", Quote: "SSLv3 MUST NOT be used"},
	},
	"transport.tls.modern": {
		{Ref: "RFC 9325 §3.1.1", URL: "https://www.rfc-editor.org/rfc/rfc9325#section-3.1.1", Quote: "Implementations MUST support TLS 1.2"},
		{Ref: "RFC 9325 §3.1.1", URL: "https://www.rfc-editor.org/rfc/rfc9325#section-3.1.1", Quote: "Implementations SHOULD support TLS 1.3"},
	},
	"transport.tls.weakciphers": {
		{Ref: "RFC 7465 §2", URL: "https://www.rfc-editor.org/rfc/rfc7465#section-2", Quote: "TLS servers MUST NOT select an RC4 cipher suite"},
		{Ref: "RFC 9325 §4.1", URL: "https://www.rfc-editor.org/rfc/rfc9325#section-4.1", Quote: "MUST NOT negotiate the cipher suites with NULL encryption"},
	},
}

// Manual sources: not RFCs, checked by hand against the vault library copies.
var (
	srcIANASuites = Source{Ref: "IANA, TLS Cipher Suites (coluna Recommended)", RefEN: "IANA, TLS Cipher Suites (Recommended column)", URL: "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml", Manual: true}
	srcMozillaKey = Source{Ref: "Mozilla Server Side TLS 6.0, perfil intermediate, campo rsa_key_size = 2048", RefEN: "Mozilla Server Side TLS 6.0, intermediate profile, field rsa_key_size = 2048", URL: "https://ssl-config.mozilla.org/guidelines/latest.json", Manual: true}
	srcMozillaSig = Source{Ref: "Mozilla Server Side TLS 6.0, perfil intermediate, campo certificate_signatures (sha256WithRSAEncryption, ecdsa-with-SHA256 ou superior)", RefEN: "Mozilla Server Side TLS 6.0, intermediate profile, field certificate_signatures (sha256WithRSAEncryption, ecdsa-with-SHA256 or higher)", URL: "https://ssl-config.mozilla.org/guidelines/latest.json", Manual: true}
	srcCABFLife   = Source{
		Ref: "CA/Browser Forum, Baseline Requirements, 6.3.2", RefEN: "CA/Browser Forum, Baseline Requirements, 6.3.2",
		URL:    "https://cabforum.org/working-groups/server/baseline-requirements/requirements/",
		Quote:  "Subscriber Certificates issued on or after 2026-03-15 and before 2027-03-15 SHOULD NOT have a Validity Period greater than 199 days and MUST NOT have a Validity Period greater than 200 days",
		Manual: true,
	}
	srcCSP = Source{
		Ref: "W3C, Content Security Policy Level 3, introdução", RefEN: "W3C, Content Security Policy Level 3, introduction",
		URL:    "https://www.w3.org/TR/CSP3/",
		Quote:  "mitigate the risk of script injection",
		Manual: true,
	}
	srcRIPEstat = Source{Ref: "RIPE NCC, RIPEstat Data API (network-info, maxmind-geo-lite)", RefEN: "RIPE NCC, RIPEstat Data API (network-info, maxmind-geo-lite)", URL: "https://stat.ripe.net/docs/02.data-api/", Manual: true}
	srcCymru    = Source{Ref: "Team Cymru, IP to ASN mapping (consulta por DNS: origin.asn.cymru.com)", RefEN: "Team Cymru, IP to ASN mapping (DNS query: origin.asn.cymru.com)", URL: "https://www.team-cymru.com/ip-asn-mapping", Manual: true}
	srcRIPERPKI = Source{Ref: "RIPE NCC, RIPEstat Data API, rpki-validation", RefEN: "RIPE NCC, RIPEstat Data API, rpki-validation", URL: "https://stat.ripe.net/docs/02.data-api/rpki-validation.html", Manual: true}
)

// Legal framing. These say which provision a finding supplies technical
// evidence for; none of them says the domain complies with it. NOTE the letter
// changes between the Directive (h) and the Portuguese Decree-Law (g).
var (
	legalDL = Source{
		Ref: "Decreto-Lei n.º 125/2025, art. 27.º, n.º 1, al. g)", RefEN: "Decree-Law no. 125/2025, art. 27(1)(g)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/decreto-lei/125-2025-962603401",
		Quote:  "Políticas e procedimentos relativos à utilização de criptografia e, se for caso disso, de cifragem",
		Manual: true,
	}
	legalNIS2 = Source{
		Ref: "Diretiva (UE) 2022/2555 (NIS2), art. 21.º, n.º 2, al. h)", RefEN: "Directive (EU) 2022/2555 (NIS2), art. 21(2)(h)",
		URL:    "https://eur-lex.europa.eu/eli/dir/2022/2555/oj/por",
		Quote:  "Políticas e procedimentos relativos à utilização de criptografia e, se for caso disso, de cifragem",
		Manual: true,
	}
	legalReg2690 = Source{
		Ref: "Regulamento de Execução (UE) 2024/2690, anexo, ponto 9.2, al. a) (só para as entidades por ele abrangidas)", RefEN: "Implementing Regulation (EU) 2024/2690, annex, point 9.2(a) (only for the entities it covers)",
		URL:    "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/por",
		Quote:  "o tipo, a força e a qualidade das medidas criptográficas necessárias para proteger os ativos das referidas entidades, incluindo os dados inativos e os dados em trânsito",
		Manual: true,
		Scope:  ScopeReg2690,
	}
)

func init() {
	sources["transport.tls.discouraged"] = []Source{srcIANASuites}
	sources["transport.tls.inventory"] = []Source{srcIANASuites}
	sources["transport.cert.key"] = []Source{srcMozillaKey}
	sources["transport.cert.signature"] = []Source{srcMozillaSig}
	sources["transport.cert.lifetime"] = []Source{srcCABFLife}
	sources["transport.csp.header"] = []Source{srcCSP}
	sources["routing.origin"] = []Source{srcCymru, srcRIPEstat}
	sources["routing.geo"] = []Source{srcRIPEstat}
	sources["routing.rpki.roa"] = append(sources["routing.rpki.roa"], srcRIPERPKI)
}

// Regulamento de Execução (UE) 2024/2690, anexo, ponto 6.7.2. It applies directly to the
// "entidades pertinentes" of its article 1 (DNS service providers, TLD registries, cloud,
// data centres, CDNs, managed services, online platforms, trust services), not to every
// entity: the Ref says so and the report repeats it.
var (
	legalReg2690Mail = Source{
		Ref: "Regulamento de Execução (UE) 2024/2690, anexo, ponto 6.7.2, al. k) (só para as entidades por ele abrangidas)", RefEN: "Implementing Regulation (EU) 2024/2690, annex, point 6.7.2(k) (only for the entities it covers)",
		URL:    "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/por",
		Quote:  "Adotam um plano de execução para a implantação de normas modernas, internacionalmente acordadas e interoperáveis em matéria de comunicações por correio eletrónico",
		Manual: true,
		Scope:  ScopeReg2690,
	}
	legalReg2690DNSRouting = Source{
		Ref: "Regulamento de Execução (UE) 2024/2690, anexo, ponto 6.7.2, al. l) (só para as entidades por ele abrangidas)", RefEN: "Implementing Regulation (EU) 2024/2690, annex, point 6.7.2(l) (only for the entities it covers)",
		URL:    "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/por",
		Quote:  "Aplicam as melhores práticas no que se refere à segurança do DNS, à segurança do encaminhamento na Internet e à higiene do encaminhamento do tráfego com origem e destino na rede",
		Manual: true,
		Scope:  ScopeReg2690,
	}
)

const enisaURL = "https://www.enisa.europa.eu/sites/default/files/2025-06/ENISA_Technical_implementation_guidance_on_cybersecurity_risk_management_measures_version_1.0.pdf"

// ENISA guidance for point 6.7.2 (p. 96-97). Indicative and non-binding.
var (
	guideMail = Source{
		Ref: "ENISA, Technical Implementation Guidance v1.0 (junho de 2025), p. 96, orientação indicativa e não vinculativa", RefEN: "ENISA, Technical Implementation Guidance v1.0 (June 2025), p. 96, indicative and non-binding guidance",
		URL:    enisaURL,
		Quote:  "standards such as Start transport layer security (STARTTLS), DNS-based authentication of named entities (DANE)",
		Manual: true,
	}
	guideDNS = Source{
		Ref: "ENISA, Technical Implementation Guidance v1.0 (junho de 2025), p. 96, orientação indicativa e não vinculativa", RefEN: "ENISA, Technical Implementation Guidance v1.0 (June 2025), p. 96, indicative and non-binding guidance",
		URL:    enisaURL,
		Quote:  "Consider DNS security good practices",
		Manual: true,
	}
	guideBGP = Source{
		Ref: "ENISA, Technical Implementation Guidance v1.0 (junho de 2025), p. 97, orientação indicativa e não vinculativa", RefEN: "ENISA, Technical Implementation Guidance v1.0 (June 2025), p. 97, indicative and non-binding guidance",
		URL:    enisaURL,
		Quote:  "Consider Border Gateway Protocol (BGP)",
		Manual: true,
	}
)

var guidance = map[string][]Source{}

// Regulamento (CNCS) n.º 756/2026, anexo III: medidas de cibersegurança mínimas, obrigatórias para as
// entidades essenciais e importantes (art. 30.º do regulamento, art. 26.º n.º 5 do DL 125/2025), por nível
// de conformidade (Básico, Substancial, Elevado: cumulativos). The level that applies comes from the
// entity's risk matrix (annex II), which an external scan cannot know; every Ref says so.
var (
	legalCNCSTransitBasic = Source{
		Ref:    "Regulamento (CNCS) n.º 756/2026, anexo III, nível Básico, controlo PR.SD-2 (p. 71; o nível aplicável depende da matriz de risco da entidade)",
		RefEN:  "CNCS Regulation no. 756/2026, annex III, Basic level, control PR.SD-2 (p. 71; the applicable level depends on the entity's risk matrix)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
		Quote:  "Evidência técnica da implementação de mecanismos criptográficos para os dados em trânsito",
		Manual: true,
		Scope:  ScopeEEI,
	}
	legalCNCSTransitHigh = Source{
		Ref:    "Regulamento (CNCS) n.º 756/2026, anexo III, nível Elevado, controlo PR.SD-2 (p. 82; o nível aplicável depende da matriz de risco da entidade)",
		RefEN:  "CNCS Regulation no. 756/2026, annex III, High level, control PR.SD-2 (p. 82; the applicable level depends on the entity's risk matrix)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
		Quote:  "A entidade deve implementar controlos de segurança que garantam a confidencialidade e integridade da informação em trânsito, consoante a sua classificação, para todos os fluxos de dados e interfaces de comunicação para o exterior",
		Manual: true,
		Scope:  ScopeEEI,
	}
	legalCNCSPEWGroupB = Source{
		Ref:    "Regulamento (CNCS) n.º 756/2026, anexo IV, grupo B, controlo T.PEW (p. 86; só para entidades públicas relevantes, não para as entidades essenciais e importantes do anexo III)",
		RefEN:  "CNCS Regulation no. 756/2026, annex IV, group B, control T.PEW (p. 86; only for public relevant entities, not for the essential and important entities of annex III)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
		Quote:  "Evidência técnica da implementação de mecanismos de segurança para autenticação do correio eletrónico e utilização de protocolos seguros e certificados digitais nas páginas de Internet",
		Manual: true,
		Scope:  ScopePublic,
	}
	legalCNCSPEWGroupA = Source{
		Ref:    "Regulamento (CNCS) n.º 756/2026, anexo IV, grupo A, controlo T.PEW (p. 88; só para entidades públicas relevantes, não para as entidades essenciais e importantes do anexo III; o grupo A cumpre também o grupo B)",
		RefEN:  "CNCS Regulation no. 756/2026, annex IV, group A, control T.PEW (p. 88; only for public relevant entities, not for the essential and important entities of annex III; group A also meets group B)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
		Quote:  "Evidência técnica da implementação de mecanismos de segurança para autenticação e validação do correio eletrónico e utilização de protocolos seguros, certificados digitais e configuração dos cabeçalhos de segurança nas páginas de Internet",
		Manual: true,
		Scope:  ScopePublic,
	}
	legalCNCSProtocols = Source{
		Ref:    "Regulamento (CNCS) n.º 756/2026, anexo III, nível Elevado, controlo PR.SP-1 (p. 83; o nível aplicável depende da matriz de risco da entidade; enquadramento interpretativo)",
		RefEN:  "CNCS Regulation no. 756/2026, annex III, High level, control PR.SP-1 (p. 83; the applicable level depends on the entity's risk matrix; interpretive framing)",
		URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
		Quote:  "desativar todos os protocolos, portos e serviços desnecessários",
		Manual: true,
		Scope:  ScopeEEI,
	}
)

// mapCNCSAnnexIII attaches the controls above to the findings about the cryptographic protection of connections.
func mapCNCSAnnexIII() {
	for _, id := range []string{
		"transport.tls.legacy", "transport.tls.modern", "transport.tls.weakciphers", "transport.tls.discouraged",
		"transport.tls.forwardsecrecy", "transport.cert.chain", "transport.cert.hostname", "transport.cert.validity",
		"transport.cert.lifetime", "transport.cert.key", "transport.cert.signature", "transport.hsts.header",
		"email.starttls.offered", "email.starttls.tls", "email.starttls.cert", "email.mtasts.mode", "email.mtasts.fetch",
		"email.dane.tlsa", "email.dane.match",
	} {
		legal[id] = appendUnique(appendUnique(legal[id], legalCNCSTransitBasic), legalCNCSTransitHigh)
	}
	legal["transport.tls.legacy"] = appendUnique(legal["transport.tls.legacy"], legalCNCSProtocols)
}

// mapCNCSAnnexIV attaches T.PEW (public relevant entities, groups B and A): mail authentication,
// secure protocols and digital certificates, and, for group A only, the security headers of web pages.
func mapCNCSAnnexIV() {
	for _, id := range []string{
		"email.spf.present", "email.spf.policy", "email.spf.lookups", "email.dkim.key", "email.dkim.strength",
		"email.dmarc.present", "email.dmarc.policy", "email.dmarc.enforcement", "email.dmarc.reporting",
		"transport.tls.legacy", "transport.tls.modern", "transport.tls.weakciphers", "transport.tls.discouraged",
		"transport.tls.forwardsecrecy", "transport.cert.chain", "transport.cert.hostname", "transport.cert.validity",
		"transport.cert.lifetime", "transport.cert.key", "transport.cert.signature",
	} {
		legal[id] = appendUnique(appendUnique(legal[id], legalCNCSPEWGroupB), legalCNCSPEWGroupA)
	}
	for _, id := range []string{"transport.hsts.header", "transport.csp.header"} {
		legal[id] = appendUnique(legal[id], legalCNCSPEWGroupA)
	}
}

// mapRegulation2690 attaches point 6.7.2 k) and l) and the ENISA guidance. It runs at
// the end of the init below, after the cryptography mapping, so that nothing it adds is
// overwritten (init order within a package is not something to rely on).
func mapRegulation2690() {
	for _, id := range []string{
		"email.spf.present", "email.spf.policy", "email.spf.lookups", "email.dkim.key", "email.dkim.strength",
		"email.dmarc.present", "email.dmarc.policy", "email.dmarc.enforcement", "email.dmarc.reporting",
		"email.mtasts.record", "email.mtasts.fetch", "email.mtasts.mode", "email.mtasts.mx", "email.mtasts.maxage",
		"email.tlsrpt.record", "email.dane.tlsa", "email.dane.params", "email.dane.match",
		"email.starttls.service", "email.starttls.offered", "email.starttls.tls", "email.starttls.cert",
	} {
		legal[id] = appendUnique(legal[id], legalReg2690Mail)
		guidance[id] = []Source{guideMail}
	}
	for _, id := range []string{"dns.dnssec.chain", "dns.dnssec.algorithm", "dns.dnssec.expiry"} {
		legal[id] = appendUnique(legal[id], legalReg2690DNSRouting)
		guidance[id] = []Source{guideDNS}
	}
	for _, id := range []string{"routing.rpki.roa", "routing.origin"} {
		legal[id] = appendUnique(legal[id], legalReg2690DNSRouting)
		guidance[id] = []Source{guideBGP}
	}
}

func appendUnique(list []Source, s Source) []Source {
	out := append([]Source{}, list...)
	for _, x := range out {
		if x.Ref == s.Ref {
			return out
		}
	}
	return append(out, s)
}

// legalBase is attached to every finding that supplies technical evidence about
// the use of cryptography; legalStrength is added where the finding is about the
// strength of the protocol, suite, key or certificate.
var legalBase = []Source{legalDL, legalNIS2}

var legal = map[string][]Source{}

func init() {
	for _, id := range []string{
		"transport.tls.legacy", "transport.tls.modern", "transport.tls.weakciphers", "transport.tls.discouraged",
		"transport.tls.forwardsecrecy", "transport.cert.chain", "transport.cert.hostname", "transport.cert.validity",
		"transport.cert.lifetime", "transport.cert.key", "transport.cert.signature", "transport.hsts.header",
		"email.starttls.offered", "email.starttls.tls", "email.starttls.cert", "email.mtasts.mode", "email.mtasts.fetch",
		"email.dane.tlsa", "email.dane.match", "email.dkim.key", "email.dkim.strength",
		"dns.dnssec.chain", "dns.dnssec.algorithm", "dns.dnssec.expiry",
	} {
		legal[id] = legalBase
	}
	for _, id := range []string{
		"transport.tls.legacy", "transport.tls.modern", "transport.tls.weakciphers", "transport.tls.discouraged",
		"transport.tls.forwardsecrecy", "transport.cert.key", "transport.cert.signature", "email.starttls.tls",
	} {
		legal[id] = append(append([]Source{}, legalBase...), legalReg2690)
	}
	mapRegulation2690()
	mapCNCSAnnexIII()
	mapCNCSAnnexIV()
}

// SupplierAssessmentSource frames the supplier report: GR.CA-7 asks the entity to assess the
// cybersecurity of its suppliers. A passive scan of a supplier's domain is one input to that
// assessment, not the assessment. It is not attached to any finding.
var SupplierAssessmentSource = Source{
	Ref:    "Regulamento (CNCS) n.º 756/2026, anexo III, nível Elevado, controlo GR.CA-7 (p. 80; o nível aplicável depende da matriz de risco da entidade; enquadramento interpretativo)",
	RefEN:  "CNCS Regulation no. 756/2026, annex III, High level, control GR.CA-7 (p. 80; the applicable level depends on the entity's risk matrix; interpretive framing)",
	URL:    "https://diariodarepublica.pt/dr/detalhe/regulamento/756-2026-1134399056",
	Quote:  "A entidade deve realizar avaliações da cibersegurança dos seus fornecedores em conformidade com o nível de exigência requerido",
	Manual: true,
	Scope:  ScopeEEI,
}
