package catalog

// pt is the Portuguese catalog. Sources: the vault guide (notes/guia-conceitos.md)
// and the RFCs cited there. Texts describe technical evidence and never say that
// a domain "complies" with anything. Keep commands copy-pasteable: they use
// {{domain}}, which Render only fills with a plain host name.
var pt = map[string]Entry{
	// ---- Correio: perfil, SPF, DKIM, DMARC ----
	"email.mx.profile": {
		Title:   "Perfil de correio (registos MX)",
		Why:     "Os registos MX dizem quem recebe o email do domínio. Um domínio sem MX recebe mal, mas pode continuar a ser usado para enviar ou falsificar email, por isso a avaliação de SPF e DMARC depende deste perfil.",
		Fix:     "Se o domínio não recebe email, declare um MX nulo (RFC 7505). Se recebe, confirme que os MX apontam para os servidores certos.",
		Example: "{{domain}}. IN MX 0 .",
		Verify:  "dig +short MX {{domain}}",
	},
	"email.mx.resolves": {
		Title:   "Os servidores de correio dos MX existem",
		Why:     "O registo MX só indica um nome. Se esse nome não tem endereço (A ou AAAA), ou é um alias (CNAME), quem envia email para o domínio não consegue entregar: a mensagem fica em fila ou volta devolvida. O problema não se vê no MX nem numa análise do domínio, só quando alguém tenta enviar.",
		Fix:     "Crie o registo A (e AAAA, se usar IPv6) do servidor de correio indicado no MX, ou corrija o MX para um nome que exista. O MX não deve apontar para um CNAME: aponte para o nome com o endereço.",
		Example: "mail.{{domain}}. IN A 192.0.2.25\n{{domain}}. IN MX 10 mail.{{domain}}.",
		Verify:  "dig +short MX {{domain}}\ndig +short A mail.{{domain}}",
	},
	"email.subdomains.mx": {
		Title:   "Subdomínios indicados: servidores de correio dos MX existem",
		Why:     "O correio de um subdomínio (por exemplo blog.exemplo.pt) tem os seus próprios registos MX, que uma análise do domínio principal não vê. Se o servidor indicado não existe, quem envia para esse subdomínio não consegue entregar e o problema só aparece quando alguém tenta.",
		Fix:     "Para cada subdomínio que receba email, crie o registo A (e AAAA) do servidor de correio do MX, ou corrija o MX. Se o subdomínio não recebe email, declare um MX nulo.",
		Example: "blog.{{domain}}. IN MX 10 mail.blog.{{domain}}.\nmail.blog.{{domain}}. IN A 192.0.2.25",
		Verify:  "dig +short MX blog.{{domain}}\ndig +short A mail.blog.{{domain}}",
	},
	"email.spf.ip4": {
		Title:   "Endereços ip4/ip6 do SPF coincidem com o domínio",
		Why:     "Um endereço do SPF que não é de nenhum servidor do próprio domínio pode estar certo (o correio sai por outro servidor), mas é também o aspeto de um erro: o endereço do servidor web em vez do de correio, ou um IP antigo. Se estiver errado, o correio legítimo falha o SPF.",
		Fix:     "Confirme o endereço real de envio nos cabeçalhos de uma mensagem enviada pelo domínio (campo Received) e acerte o SPF com esse endereço.",
		Example: "{{domain}}. IN TXT \"v=spf1 ip4:192.0.2.25 -all\"",
		Verify:  "dig +short TXT {{domain}}",
	},
	"email.spf.present": {
		Title:   "Registo SPF existe e é único",
		Why:     "O SPF (RFC 7208) diz que servidores podem enviar email em nome do domínio. Sem ele, ou com mais de um registo, os recetores não conseguem decidir e é mais fácil falsificar o domínio.",
		Fix:     "Publique exatamente um registo TXT de SPF e liste nele os remetentes autorizados. Se o domínio não envia email, publique um SPF que proíba todos os remetentes.",
		Example: "; domínio que envia email\n{{domain}}. IN TXT \"v=spf1 include:_spf.o-seu-fornecedor.exemplo -all\"\n; domínio que não envia email\n{{domain}}. IN TXT \"v=spf1 -all\"",
		Verify:  "dig +short TXT {{domain}}",
	},
	"email.spf.policy": {
		Title:  "Política final do SPF (-all, ~all, ?all)",
		Why:    "O mecanismo final decide o que fazer com remetentes não listados. -all rejeita, ~all aceita mas marca, ?all e +all não protegem nada.",
		Fix:    "Termine o SPF com -all depois de listar todos os remetentes legítimos. Passe de ~all para -all só depois de ver, nos relatórios DMARC, que nada legítimo falha.",
		Verify: "dig +short TXT {{domain}} | grep spf1",
	},
	"email.spf.lookups": {
		Title:  "Limite de 10 consultas DNS do SPF",
		Why:    "O SPF só pode fazer 10 consultas DNS (include, a, mx, ptr, exists, redirect). Acima disso o recetor devolve erro permanente e o SPF deixa de funcionar. Ciclos de include e o mecanismo ptr agravam o problema.",
		Fix:    "Reduza os include (retire fornecedores que já não usa), substitua mecanismos por intervalos ip4/ip6 quando forem estáveis e evite ptr.",
		Verify: "dig +short TXT {{domain}}\n# Conte include, a, mx, exists e redirect, de forma recursiva: o total não pode passar de 10",
	},
	"email.dkim.key": {
		Title:   "Chave DKIM publicada e utilizável",
		Why:     "O DKIM (RFC 6376) assina as mensagens para provar a origem. Um registo ausente, duplicado, sem chave pública (p= vazio, chave revogada) ou em modo de teste (t=y) não protege.",
		Fix:     "Publique a chave no seletor que o seu fornecedor de email indica, com o seletor e a chave pública exatos que ele fornece.",
		Example: "<seletor>._domainkey.{{domain}}. IN TXT \"v=DKIM1; k=rsa; p=<chave pública>\"",
		Verify:  "# O seletor está no campo s= do cabeçalho DKIM-Signature de uma mensagem enviada\ndig +short TXT <seletor>._domainkey.{{domain}}",
	},
	"email.dkim.strength": {
		Title:  "Tamanho da chave DKIM",
		Why:    "Chaves RSA abaixo de 1024 bits podem ser quebradas; 1024 a 2047 bits estão desaconselhadas. A recomendação atual é 2048 bits ou mais.",
		Fix:    "Gere uma chave RSA de 2048 bits no fornecedor de email, publique-a num seletor novo, mude o envio para esse seletor e só depois retire o antigo.",
		Verify: "dig +short TXT <seletor>._domainkey.{{domain}}\n# Copie o p= (base64) para um ficheiro e leia o tamanho da chave com: openssl pkey -pubin -text -noout",
	},
	"email.dmarc.present": {
		Title:   "Registo DMARC existe",
		Why:     "O DMARC (RFC 9989) liga SPF e DKIM ao endereço From visível e diz aos recetores o que fazer quando falham. Sem ele não há política contra a falsificação do domínio.",
		Fix:     "Comece por uma política de observação com relatórios, corrija os remetentes legítimos que falham e suba para quarantine e depois reject. Se o domínio não envia email, publique logo a política reject.",
		Example: "; ponto de partida\n_dmarc.{{domain}}. IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@{{domain}}\"\n; domínio que não envia email\n_dmarc.{{domain}}. IN TXT \"v=DMARC1; p=reject\"",
		Verify:  "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.policy": {
		Title:  "Política DMARC ativa (quarantine ou reject)",
		Why:    "Com p=none o DMARC só observa: mensagens falsificadas continuam a ser entregues. Só quarantine e reject protegem.",
		Fix:    "Analise os relatórios agregados, corrija os remetentes legítimos que falham e suba para p=quarantine e depois p=reject.",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.enforcement": {
		Title:  "A política DMARC é aplicada na totalidade",
		Why:    "Com t=y (modo de teste) ou com pct abaixo de 100, parte das mensagens falsificadas escapa à política. Servem para uma subida gradual, não para ficar assim. O RFC 9989 retirou a etiqueta pct e criou a t.",
		Fix:    "Retire t=y (o valor por omissão é t=n) e a etiqueta pct quando a subida terminar.",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},
	"email.dmarc.reporting": {
		Title:  "Relatórios DMARC pedidos (rua)",
		Why:    "Sem rua= não recebe os relatórios agregados que mostram quem envia email em nome do domínio, e sem eles é difícil passar a quarantine ou reject em segurança.",
		Fix:    "Acrescente rua=mailto:dmarc@{{domain}} ao registo DMARC (ou use um serviço que agregue e leia os relatórios).",
		Verify: "dig +short TXT _dmarc.{{domain}}",
	},

	// ---- Correio: MTA-STS, TLS-RPT, DANE, STARTTLS ----
	"email.mtasts.record": {
		Title:   "Registo MTA-STS",
		Why:     "O MTA-STS (RFC 8461) obriga os servidores que enviam para o domínio a usar TLS com um certificado válido. Sem ele, um atacante na rede pode forçar o envio em claro (ataque de downgrade).",
		Fix:     "Publique o registo e sirva a política em HTTPS. O id tem de mudar sempre que a política mudar (por exemplo, a data).",
		Example: "_mta-sts.{{domain}}. IN TXT \"v=STSv1; id=20261109T000000\"\n; ficheiro https://mta-sts.{{domain}}/.well-known/mta-sts.txt\nversion: STSv1\nmode: testing\nmx: <servidor-mx>\nmax_age: 86400",
		Verify:  "dig +short TXT _mta-sts.{{domain}}",
	},
	"email.mtasts.fetch": {
		Title:  "A política MTA-STS pode ser descarregada",
		Why:    "O registo só vale se a política existir em HTTPS, com certificado válido, sem redirecionamentos, em texto simples e com menos de 64 KiB.",
		Fix:    "Sirva o ficheiro em https://mta-sts.{{domain}}/.well-known/mta-sts.txt com Content-Type text/plain, certificado válido para mta-sts.{{domain}} e sem redirecionar.",
		Verify: "curl -sS -i https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.mode": {
		Title:  "Modo da política MTA-STS",
		Why:    "Em testing ou none a política não impede o envio sem TLS. Só enforce protege.",
		Fix:    "Depois de confirmar nos relatórios TLS-RPT que não há falhas legítimas, mude mode: testing para mode: enforce e aumente o id do registo.",
		Verify: "curl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.mx": {
		Title:  "A política MTA-STS cobre os servidores MX reais",
		Why:    "Em modo enforce, um MX que a política não liste deixa de receber email: quem envia recusa entregar. É um erro frequente ao mudar de fornecedor de email.",
		Fix:    "Faça coincidir as linhas mx: da política com os MX atuais do DNS (admitem-se padrões como *.fornecedor.exemplo) e aumente o id do registo.",
		Verify: "dig +short MX {{domain}}\ncurl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.mtasts.maxage": {
		Title:  "Validade (max_age) da política MTA-STS",
		Why:    "O max_age diz durante quanto tempo os remetentes guardam a política. O RFC 8461 espera valores de semanas ou mais; com valores curtos a política expira depressa e a proteção contra ataques na altura da renovação diminui. A app avisa abaixo de 1 dia (limiar da app, não do RFC).",
		Fix:    "Use um max_age de semanas em produção (por exemplo 604800, uma semana, ou 2592000, 30 dias), depois de ter testado em modo testing com um valor baixo.",
		Verify: "curl -sS https://mta-sts.{{domain}}/.well-known/mta-sts.txt",
	},
	"email.tlsrpt.record": {
		Title:   "Relatórios TLS (TLS-RPT)",
		Why:     "O TLS-RPT (RFC 8460) faz os outros servidores enviarem relatórios de falhas de TLS. É a forma de ver problemas de MTA-STS e DANE antes de passar a enforce.",
		Fix:     "Publique o registo com um endereço que alguém leia.",
		Example: "_smtp._tls.{{domain}}. IN TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@{{domain}}\"",
		Verify:  "dig +short TXT _smtp._tls.{{domain}}",
	},
	"email.dane.tlsa": {
		Title:   "Registos DANE/TLSA dos servidores MX",
		Why:     "O DANE (RFC 7672) fixa no DNS o certificado de cada servidor de correio, protegido por DNSSEC. É opcional, mas dá proteção forte. Um TLSA numa zona sem DNSSEC é ignorado pelos remetentes e um TLSA com assinatura inválida faz o correio ficar retido.",
		Fix:     "Assine a zona com DNSSEC e publique um registo TLSA por cada servidor MX. Antes de trocar o certificado, publique o novo TLSA ao lado do antigo e espere o TTL.",
		Example: "_25._tcp.<servidor-mx>. IN TLSA 3 1 1 <hash SHA-256 da chave pública>",
		Verify:  "dig +dnssec +short TLSA _25._tcp.<servidor-mx>",
	},
	"email.dane.params": {
		Title:  "Parâmetros dos registos TLSA",
		Why:    "O uso, o seletor e o tipo de correspondência têm de ser valores definidos e o tamanho dos dados tem de bater certo, senão o registo é inutilizável.",
		Fix:    "Use os valores habituais: 3 1 1 (DANE-EE, chave pública, SHA-256) ou 2 1 1 (DANE-TA).",
		Verify: "dig +short TLSA _25._tcp.<servidor-mx>",
	},
	"email.dane.match": {
		Title:  "O certificado do servidor corresponde ao TLSA",
		Why:    "Se o certificado apresentado não corresponde a nenhum TLSA, quem valida DANE recusa entregar o correio. É a causa típica de correio retido após renovar um certificado com chave nova.",
		Fix:    "Publique o TLSA do certificado atual (ou renove o certificado reutilizando a chave). Faça-o antes de trocar o certificado.",
		Verify: "openssl s_client -starttls smtp -connect <servidor-mx>:25 -servername <servidor-mx>\ndig +short TLSA _25._tcp.<servidor-mx>\n# Compare o certificado apresentado com o registo TLSA",
	},
	"email.starttls.service": {
		Title:  "Teste de STARTTLS nos servidores MX",
		Why:    "Resume o que foi possível testar. Muitos fornecedores e redes bloqueiam a porta 25 de saída; nesse caso o resultado é desconhecido, não uma falha.",
		Fix:    "Se o resultado for desconhecido, repita a partir de uma rede que permita a porta 25 de saída, ou confirme manualmente.",
		Verify: "openssl s_client -starttls smtp -connect <servidor-mx>:25 -servername <servidor-mx>",
	},
	"email.starttls.offered": {
		Title:  "Os servidores MX oferecem STARTTLS",
		Why:    "Sem STARTTLS o correio recebido viaja em claro entre servidores e pode ser lido ou alterado na rede.",
		Fix:    "Ative TLS no servidor de correio (ou no fornecedor) e confirme que o EHLO anuncia STARTTLS.",
		Verify: "openssl s_client -starttls smtp -connect <servidor-mx>:25 -servername <servidor-mx>",
	},
	"email.starttls.tls": {
		Title:  "Versão de TLS nos servidores MX",
		Why:    "Versões abaixo de TLS 1.2 têm fraquezas conhecidas (RFC 8996). Se o handshake falha, não é possível confirmar a proteção.",
		Fix:    "Configure o servidor de correio para TLS 1.2 e 1.3 e desative as versões anteriores.",
		Verify: "openssl s_client -starttls smtp -connect <servidor-mx>:25 -servername <servidor-mx> -tls1_2",
	},
	"email.starttls.cert": {
		Title:  "Certificado dos servidores MX",
		Why:    "Um certificado não confiável, com nome errado, expirado ou com chave ou assinatura fracas tira valor à cifragem. Entre servidores muitos remetentes não validam o certificado, por isso o impacto depende do MTA-STS e do DANE.",
		Fix:    "Instale um certificado válido emitido por uma CA pública para o nome do MX, com chave RSA de 2048 bits ou mais (ou ECDSA) e renove-o antes de expirar.",
		Verify: "openssl s_client -starttls smtp -connect <servidor-mx>:25 -servername <servidor-mx> </dev/null | openssl x509 -noout -subject -issuer -dates",
	},

	// ---- DNS: DNSSEC e CAA ----
	"dns.dnssec.chain": {
		Title:  "Cadeia de confiança DNSSEC",
		Why:    "O DNSSEC assina as respostas DNS para que não possam ser falsificadas. Uma cadeia partida (por exemplo um DS que não corresponde às chaves da zona) faz os resolvedores que validam deixar de resolver o domínio.",
		Fix:    "Se a zona está assinada, publique no registador o DS indicado pelo fornecedor de DNS e mantenha-o atualizado em cada mudança de fornecedor ou de chaves. Se não quer DNSSEC, remova o DS. Antes de mexer no DS, confirme com um resolvedor validador independente (delv ou dig +dnssec); uma falha pontual de validação pode vir do resolvedor e não da zona.",
		Verify: "dig +dnssec DS {{domain}}\ndelv {{domain}} @1.1.1.1",
	},
	"dns.dnssec.algorithm": {
		Title:  "Algoritmo de assinatura do DNSSEC",
		Why:    "Algoritmos baseados em SHA-1 (5 e 7) estão desaconselhados (RFC 9904), tal como um DS apenas com digest SHA-1.",
		Fix:    "Mude para ECDSA P-256 (13) ou Ed25519 (15) no fornecedor de DNS e use digest SHA-256 no DS.",
		Verify: "dig +short DNSKEY {{domain}}\ndig +short DS {{domain}}",
	},
	"dns.dnssec.expiry": {
		Title:  "Validade das assinaturas DNSSEC",
		Why:    "As assinaturas têm data de fim. Se faltarem menos de 48 horas, o processo de re-assinatura pode ter parado e a zona vai deixar de validar.",
		Fix:    "Peça ao fornecedor de DNS para verificar a re-assinatura automática. Se assina a zona você mesmo, confirme o agendamento.",
		Verify: "dig +dnssec SOA {{domain}}\n# Veja a data de fim no RRSIG",
	},
	"dns.caa.present": {
		Title:   "Registos CAA",
		Why:     "O CAA (RFC 8659) diz que autoridades de certificação podem emitir certificados para o domínio. Sem CAA, qualquer CA pública pode.",
		Fix:     "Publique um registo CAA com a CA que usa e, se quiser, um contacto para incidentes.",
		Example: "{{domain}}. IN CAA 0 issue \"letsencrypt.org\"\n{{domain}}. IN CAA 0 iodef \"mailto:seguranca@{{domain}}\"",
		Verify:  "dig +short CAA {{domain}}",
	},
	"dns.caa.issue": {
		Title:  "O CAA restringe quem pode emitir",
		Why:    "Um CAA só com iodef ou issuewild restringe pouco. issue \";\" proíbe toda a emissão, o que é correto para um domínio sem certificados.",
		Fix:    "Acrescente uma linha issue por cada CA autorizada.",
		Verify: "dig +short CAA {{domain}}",
	},
	"dns.caa.iodef": {
		Title:   "Contacto para incidentes de emissão (iodef)",
		Why:     "Com iodef, uma CA que recusa um pedido por causa do CAA pode avisá-lo de uma tentativa de emissão não autorizada.",
		Fix:     "Acrescente um contacto para onde as CA possam comunicar pedidos de emissão que violem a política.",
		Example: "{{domain}}. IN CAA 0 iodef \"mailto:seguranca@{{domain}}\"",
		Verify:  "dig +short CAA {{domain}}",
	},

	// ---- Transporte: TLS ----
	"transport.tls.legacy": {
		Title:   "Versões antigas de TLS ativas",
		Why:     "SSLv3, TLS 1.0 e TLS 1.1 têm fraquezas conhecidas e foram retiradas pelo RFC 8996. Aceitá-las permite ataques de downgrade.",
		Fix:     "Desative-as no servidor web ou no balanceador.",
		Example: "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
		Verify:  "# Deve falhar. Versões recentes do openssl podem exigir -cipher 'DEFAULT:@SECLEVEL=0'\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_1",
	},
	"transport.tls.modern": {
		Title:   "TLS 1.2 e 1.3 disponíveis",
		Why:     "TLS 1.3 é mais simples e mais seguro; TLS 1.2 bem configurado continua aceitável. Sem nenhum deles não há ligação moderna possível.",
		Fix:     "Ative TLS 1.3 e mantenha o 1.2 para clientes mais antigos.",
		Example: "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
		Verify:  "openssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_3",
	},
	"transport.tls.weakciphers": {
		Title:   "Suites de cifras partidas",
		Why:     "Suites NULL, EXPORT, anónimas, RC4, DES ou 3DES não oferecem proteção real. A gravidade segue a pior suite aceite.",
		Fix:     "Restrinja a lista de suites às recomendadas (AEAD com ECDHE).",
		Example: "# nginx\nssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;\nssl_prefer_server_ciphers off;",
		Verify:  "# Deve falhar\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -cipher 'aNULL:eNULL:EXPORT:RC4:DES'",
	},
	"transport.tls.discouraged": {
		Title:  "Suites desencorajadas pela IANA",
		Why:    "A IANA marca algumas suites como desencorajadas (D) mesmo sem estarem partidas. Reduzem a margem de segurança.",
		Fix:    "Retire-as da lista de suites do servidor, mantendo as recomendadas (coluna Recommended = Y no registo IANA).",
		Verify: "# A ligação não deve completar\nopenssl s_client -connect {{domain}}:443 -servername {{domain}} -cipher <suite>",
	},
	"transport.tls.forwardsecrecy": {
		Title:  "Sigilo futuro (forward secrecy)",
		Why:    "Com sigilo futuro (ECDHE/DHE), roubar a chave do servidor mais tarde não permite decifrar tráfego antigo. Suites sem ele não o garantem.",
		Fix:    "Priorize suites ECDHE e retire as de troca de chaves RSA estática.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null 2>/dev/null | grep -E 'Cipher|Server Temp Key'",
	},
	"transport.tls.inventory": {
		Title:  "Inventário das suites aceites",
		Why:    "Lista, por versão de TLS, tudo o que o servidor aceita. É a evidência em que os outros achados de TLS assentam.",
		Fix:    "Não é uma falha. Use a lista para rever a configuração do servidor.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} -tls1_2 -cipher <suite>\n# Confirma uma suite concreta",
	},
	"transport.tls.service": {
		Title:  "Serviço TLS na porta 443",
		Why:    "Sem serviço TLS na porta 443 (ou se a porta não fala TLS), os testes de transporte deste domínio não se aplicam.",
		Fix:    "Se devia haver HTTPS, verifique o servidor, a firewall e o DNS. Se o domínio não tem site, ignore.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null",
	},

	// ---- Transporte: certificado ----
	"transport.cert.service": {
		Title:  "Foi possível ler o certificado",
		Why:    "Sem ligação ou sem handshake completo não se pode avaliar o certificado, por isso os restantes achados do certificado ficam desconhecidos.",
		Fix:    "Confirme que o servidor responde em {{domain}}:443 e que a firewall deixa passar.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null",
	},
	"transport.cert.chain": {
		Title:  "Cadeia de certificados confiável",
		Why:    "Um certificado autoassinado, de uma raiz não confiável ou sem as intermédias faz os browsers e clientes mostrarem erros ou recusarem a ligação.",
		Fix:    "Use um certificado de uma CA pública e configure o servidor para enviar a cadeia completa (certificado mais intermédias).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} -showcerts </dev/null",
	},
	"transport.cert.hostname": {
		Title:  "O certificado vale para este nome",
		Why:    "Se o nome do domínio não consta do certificado, os clientes recusam a ligação ou mostram um aviso.",
		Fix:    "Emita um certificado que inclua {{domain}} na extensão Subject Alternative Name (ou um certificado wildcard adequado).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -ext subjectAltName",
	},
	"transport.cert.validity": {
		Title:  "Prazo de validade do certificado",
		Why:    "Um certificado expirado (ou ainda não válido) deixa o serviço inacessível para clientes que validam. Expirações a menos de 30 dias merecem atenção.",
		Fix:    "Renove o certificado e automatize a renovação (por exemplo ACME/Let's Encrypt com renovação a 30 dias do fim).",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -dates",
	},
	"transport.cert.lifetime": {
		Title:  "Validade total do certificado (limite por data de emissão)",
		Why:    "As regras da PKI pública (CA/Browser Forum) limitam a validade total de um certificado conforme a data de emissão: 398 dias até 2026-03-14, 200 dias entre 2026-03-15 e 2027-03-14, 100 dias entre 2027-03-15 e 2029-03-14 e 47 dias depois. Validades maiores indicam uma CA fora das regras e atrasam a rotação de chaves. Os browsers podem recusar esses certificados.",
		Fix:    "Use certificados de curta duração com renovação automática (por exemplo ACME), para que a próxima redução do limite não o apanhe de surpresa.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -dates\n# A diferença entre notBefore e notAfter é a validade total",
	},
	"transport.cert.key": {
		Title:  "Força da chave do certificado",
		Why:    "RSA abaixo de 2048 bits e curvas elípticas abaixo de 256 bits não são consideradas seguras.",
		Fix:    "Gere uma chave nova RSA de 2048 bits (ou 3072) ou ECDSA P-256 e peça um certificado novo.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -text | grep 'Public-Key'",
	},
	"transport.cert.signature": {
		Title:  "Algoritmo de assinatura do certificado",
		Why:    "Assinaturas com SHA-1 ou MD5 permitem falsificar certificados.",
		Fix:    "Peça à CA um certificado assinado com SHA-256 ou superior e substitua também intermédias antigas.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -text | grep 'Signature Algorithm'",
	},
	"transport.cert.inventory": {
		Title:  "Inventário do certificado",
		Why:    "Resume o certificado observado: nome, emissor, datas, chave, algoritmo, cadeia enviada, impressão SHA-256 e suite negociada. É a evidência dos outros achados do certificado.",
		Fix:    "Não é uma falha. Compare com o que esperava instalar.",
		Verify: "openssl s_client -connect {{domain}}:443 -servername {{domain}} </dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256",
	},

	// ---- Transporte: cabeçalhos HTTP ----
	"transport.http.service": {
		Title:  "Resposta HTTPS do site",
		Why:    "Regista o código de resposta usado para avaliar os cabeçalhos. Um erro 5xx impede uma avaliação fiável.",
		Fix:    "Se for um erro 5xx, corrija o servidor de origem ou a ligação com o CDN e repita o teste.",
		Verify: "curl -sSI https://{{domain}}",
	},
	"transport.hsts.header": {
		Title:   "HSTS (Strict-Transport-Security)",
		Why:     "O HSTS (RFC 6797) obriga o browser a usar sempre HTTPS, o que impede ataques de downgrade e de interceção na primeira ligação sem cifra.",
		Fix:     "Envie o cabeçalho em todas as respostas HTTPS. Comece com um valor baixo e suba.",
		Example: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		Verify:  "curl -sSI https://{{domain}} | grep -i strict-transport-security",
	},
	"transport.csp.header": {
		Title:   "Content-Security-Policy",
		Why:     "A CSP limita de onde o site pode carregar scripts e outros recursos, o que reduz o impacto de falhas XSS. Modo só de relatório, 'unsafe-inline', 'unsafe-eval' ou * nos scripts tiram-lhe valor.",
		Fix:     "Defina uma política restritiva e teste-a primeiro em modo só de relatório (Content-Security-Policy-Report-Only).",
		Example: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
		Verify:  "curl -sSI https://{{domain}} | grep -i content-security-policy",
	},

	// ---- Encaminhamento ----
	"routing.origin": {
		Title:  "Origem BGP dos endereços",
		Why:    "Mostra que sistema autónomo (AS) e que prefixo anunciam cada endereço do domínio e dos servidores de correio. É a base para validar o RPKI.",
		Fix:    "Não é uma falha. Um endereço não anunciado em BGP não é alcançável na Internet pública.",
		Verify: "# Inverta os octetos do IPv4 (1.2.3.4 passa a 4.3.2.1)\ndig +short TXT <octetos-invertidos>.origin.asn.cymru.com",
	},
	"routing.rpki.roa": {
		Title:  "Validação RPKI da origem",
		Why:    "O RPKI (RFC 6811) liga um prefixo ao AS autorizado a anunciá-lo. Um anúncio inválido é descartado por redes que validam, e a falta de ROA deixa o prefixo exposto a desvios de rota (route hijack).",
		Fix:    "A correção depende de quem detém o prefixo, normalmente o fornecedor de rede ou de alojamento: peça-lhe para criar ou corrigir o ROA (AS de origem e maxLength certos). Não se corrige no DNS do domínio.",
		Verify: "curl -sS 'https://stat.ripe.net/data/rpki-validation/data.json?resource=AS<n>&prefix=<prefixo>'",
	},
	"routing.geo": {
		Title:  "Localização aproximada dos endereços",
		Why:    "Dá o país que uma base de geolocalização associa a cada endereço. É aproximada: endereços anycast de CDN não têm localização e a localização não prova onde os dados são guardados.",
		Fix:    "Não é uma falha. Para saber onde os dados são tratados, consulte o contrato e a documentação do fornecedor.",
		Verify: "curl -sS 'https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=<endereço>'",
	},
}

// checkNames maps the ID of a check to its name. The engine reports a check
// that was skipped, timed out or panicked under the check's own ID, so each
// one needs an entry. IDs that are also real findings keep their own entry.
var checkNames = map[string]string{
	"email.mx":            "registos MX",
	"email.subdomains":    "subdomínios indicados (MX)",
	"email.spf":           "SPF",
	"email.dkim":          "DKIM",
	"email.dmarc":         "DMARC",
	"email.mtasts.policy": "política MTA-STS",
	"email.tlsrpt":        "TLS-RPT",
	"email.dane":          "DANE/TLSA",
	"email.starttls":      "STARTTLS nos servidores MX",
	"transport.tls":       "versões e suites de TLS",
	"transport.cert":      "certificado X.509",
	"transport.web":       "cabeçalhos HTTP de segurança",
	"dns.dnssec":          "DNSSEC",
	"dns.caa":             "CAA",
	"routing":             "encaminhamento (RIPEstat)",
}

func init() {
	for id, name := range checkNames {
		if _, ok := pt[id]; ok {
			continue
		}
		pt[id] = Entry{
			Title:  "Verificação não concluída: " + name,
			Why:    "Este identificador aparece quando a verificação inteira não deu resultado: foi saltada (as verificações ativas exigem --active e o encaminhamento é desligado por --no-routing), excedeu o tempo ou teve um erro interno. Não é uma falha do domínio.",
			Fix:    "Se foi saltada, repita com --active (só em domínios seus ou com autorização escrita) ou sem --no-routing. Se excedeu o tempo, repita ou aumente --timeout.",
			Verify: "# Leia o campo detail do achado: diz porque a verificação não foi concluída",
		}
	}
}
