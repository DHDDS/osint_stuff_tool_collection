# Novo batch — Serviços que faltavam na coleção

[← Voltar ao índice](00-INDICE.md)

---

Baseado no `OSINTlinks.md` (coleção Cyber Detective / cipher387). Estes serviços **não constavam** na coleção original e são bons complementos, organizados por área.

## Infraestrutura / IP / BGP

| Link | Description |
| --- | --- |
| [bgp.tools](https://bgp.tools) | Interface mais amigável que o bgp.he.net para explorar ASNs, prefixos, peers e relações de rota. Mostra quem anuncia o que e com quem peeriza |
| [Team Cymru IP-to-ASN](https://www.team-cymru.com/team-cymru-asn-ip-services) | Consulta via whois (`whois -h whois.cymru.com 1.2.3.4`) que responde ASN/rede/país de qualquer IP. Ferramenta de referência para atribuição de rede |
| [IPinfo](https://ipinfo.io) | GeoIP, ASN, tipo de rede, hosting/VPN/proxy detection. Tem API e plano free generoso |
| [IPinfo Lite](https://lite.ipinfo.io) | Versão gratuita e simplificada do IPinfo para consultas rápidas no navegador |
| [Scamalytics](https://scamalytics.com) | Score de fraude por IP: detecta proxy, VPN, TOR, datacenter e histórico de spam |
| [Spur](https://spur.us) | Especializada em detectar anonimizadores: VPN, proxies residenciais, bots e evidências de anonimato |
| [MaxMind GeoIP demo](https://www.maxmind.com/en/geoip-demo) | Geolocalização de IP pela empresa de referência do mercado. Demo gratuita no navegador |
| [Robtex](https://www.robtex.com) | DNS + WHOIS + rota BGP + histórico unificados para qualquer host/IP/domínio |
| [RapidDNS](https://rapiddns.io) | Subdomains, same-IP, história de DNS e subdomain takeover. Interface simples e rápida |
| [DNSDumpster](https://dnsdumpster.com) | Gera mapa visual de DNS de um domínio: subdomains, MX, TXT, servidores e hostnames |
| [ARIN whois](https://whois.arin.net) | Registro oficial de quem é dono de um IP/ASN na América do Norte |
| [Registro.br whois](https://registro.br/tecnologia/ferramentas/whois/) | Registro oficial de domínios .br e blocos IP do Brasil (NIC.br) |
| [RIPE NCC whois](https://apps.db.ripe.net/db-web-ui/query) | Registro oficial para Europa/Oriente Médio/Ásia Central |
| [APNIC whois](https://wq.apnic.net/) | Registro oficial para Ásia-Pacífico |

## Identidade / vazamentos

| Link | Description |
| --- | --- |
| [Epieos](https://epieos.com) | Descobre contas Google/Microsoft/Proton associadas a um e-mail ou telefone, mostrando serviços onde a conta está registrada |
| [EmailRep](https://emailrep.io) | Reputação de endereços de e-mail:大庆 idade, breachs, spam, presença em redes sociais. API free |
| [Snusbase](https://snusbase.com) | Buscador de leaks indexados (vazamentos públicos). Pago, mas com preview que ajuda a confirmar existência |
| [LeakCheck](https://leakcheck.io) | Verifica se e-mail/usuário/senha aparece em leaks conhecidos. Versão gratuita limitada |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Ferramenta CLI para recon de números de telefone: operadora, país, tipo, busca em APIs abertas |
| [HIBP API v3](https://haveibeenpwned.com/API/v3) | A API oficial do HaveIBeenPwned para automatizar checagem de vazamentos de contas e senhas |

## Imagens / satélite

| Link | Description |
| --- | --- |
| [Zoom Earth](https://zoom.earth) | Imagens de satélite quase em tempo real, com camadas de vento, nuvens, chuva e temperatura. Ótimo para datar fenômenos meteorológicos |
| [SunCalc](https://www.suncalc.org) | Posição do sol e sombras para qualquer lugar/data/hora. Técnica clássica para datar ou validar fotos |
| [Mapillary](https://www.mapillary.com) | Street View colaborativo, cobre áreas onde o Google Street View não vai. Zona rural, trilhas, países emergentes |
| [Wikimaps / WMapa](https://wiki.openstreetmap.org/wiki/Tileservers) | Lista de tiles de mapas abertos, incluindo alguns raros por região |

## Transporte / rastreamento

| Link | Description |
| --- | --- |
| [MarineTraffic](https://www.marinetraffic.com) | Rastreamento AIS de navios mundial, com histórico de rotas. Cobertura maior que o VesselFinder |
| [ADS-B.fi globe](https://globe.adsb.fi) | Feed comunitário de aeronaves, menos filtrado que os agregadores comerciais |
| [ADSBlol](https://globe.adsb.lol) | Outro feed comunitário ADS-B, cooperativo, com aeronaves militares às vezes filtradas nos feeds comerciais |

## Verificação / jornalismo investigativo

| Link | Description |
| --- | --- |
| [Bellingcat Toolkit](https://bellingcat.gitbook.io/toolkit) | Metacatálogo mantido pelo Bellingcat: as melhores ferramentas por categoria, sempre atualizadas. Padrão-ouro do jornalismo OSINT |
| [OSINT Combine](https://www.osintcombine.com/tools) | Coleção de ferramentas de busca combinada por plataforma, email, imagem, geolocalização |
| [InVID / WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) | Extensão de navegador para verificação de vídeo: thumbnails reversos, metadados, detecção de manipulação |
| [Forensically](https://29a.ch/photo-forensics/) | Editor de análise forense de imagens no navegador: clone detection, ELA, noise analysis, metadados |
| [FotoForensics](https://fotoforensics.com) | Análise ELA (Error Level Analysis) para detectar edições em fotos. Clássico da verificação |

## Automação / frameworks

| Link | Description |
| --- | --- |
| [OSINT Framework (novo)](https://osintframework.com) | Árvore gigante de ferramentas OSINT por categoria. O site atual mudou; vale conferir o link novo |
| [Pentest-Tools](https://pentest-tools.com) | Bateria de scanners web gratuitos: subdomain finder, port scanner, CMS detector, XSS, SQLi |
| [Tor Metrics](https://metrics.torproject.org) | Estatísticas da rede Tor: número de relays, pontes, tráfego, usuários por país |
| [OnionScan](https://github.com/s-rah/onionscan) | Ferramenta para investigar sites .onion: detecta fingerprints, vazamentos de config e correlação de serviços |

---

Fonte: seleção manual de serviços ausentes em `OSINTlinks.md` (cipher387). Gerada em 2026-11-16.
