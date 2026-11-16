# Contra-Inteligência Cibernética — Comandos de Iniciante a Avançado

[← Voltar ao índice](00-INDICE.md)

> **Aviso legal:** todas as técnicas deste guia são **defensivas e de investigação autorizada** — proteja seus sistemas, detecte vigilância e investigue com autorização. Executar qualquer varredura, interceptação ou análise contra sistemas de terceiros sem permissão é crime (Lei nº 12.737/2012 no Brasil; Computer Fraud and Abuse Act nos EUA; normas equivalentes em outros países).

O objetivo aqui: **saber o que sai da sua rede, o que roda na sua máquina, o que já vazou sobre você e detectar quando alguém tenta acompanhar você.**

---

## Sumário

- [Nível 0 — Conhecer sua superfície](#nível-0--conhecer-sua-superfície)
- [Nível 1 — Anonimato e navegação básica](#nível-1--anonimato-e-navegação-básica)
- [Nível 2 — Comunicações seguras e criptografia](#nível-2--comunicações-seguras-e-criptografia)
- [Nível 3 — Hardening inicial do sistema](#nível-3--hardening-inicial-do-sistema)
- [Nível 4 — Higiene de metadados](#nível-4--higiene-de-metadados)
- [Nível 5 — Monitoramento de rede](#nível-5--monitoramento-de-rede)
- [Nível 6 — Caça a comprometimentos (Threat Hunting)](#nível-6--caça-a-comprometimentos-threat-hunting)
- [Nível 7 — Persistência: onde espiões se escondem](#nível-7--persistência-onde-espiões-se-escondem)
- [Nível 8 — Honeypots e canários (detecção proativa)](#nível-8--honeypots-e-canários-detecção-proativa)
- [Nível 9 — Forense e aquisição de evidência](#nível-9--forense-e-aquisição-de-evidência)
- [Nível 10 — Anti-forense defensiva e destruição segura](#nível-10--anti-forense-defensiva-e-destruição-segura)
- [Nível 11 — Mobile: Android e iOS](#nível-11--mobile-android-e-ios)
- [Nível 12 — Windows rápido](#nível-12--windows-rápido)
- [Nível 13 — Infra, VMs e compartimentalização](#nível-13--infra-vms-e-compartimentalização)
- [Nível 14 — Monitorar sua própria exposição](#nível-14--monitorar-sua-própria-exposição)
- [Rotinas: diária, semanal, mensal](#rotinas)
- [Regra de ouro](#regra-de-ouro)

---

## Nível 0 — Conhecer sua superfície

**Ver que IP você apresenta à internet:**

```bash
curl -4 https://ifconfig.me; echo        # só o IP
curl -s https://ipinfo.io                 # IP + ASN + cidade + org (contexto!)
curl -s https://am.i.mullvad.net/ip       # IP + país (detecta se a VPN escapou o tráfego)```

**Ver quem é o dono de um IP (nível trem):**

```bash
whois -h whois.cymru.com " -v 23.4.71.127"     # Team Cymru: ASN, nome, país
{ echo begin; echo 23.4.71.127; echo end; } | nc whois.cymru.com 43   # em lote
```

**Em qual DNS você cai de verdade (DNS leak manual):**

```bash
dig +short TXT whoami.ds.akahelp.net      # o IP do resolver que te atendeu
```

**O que já vazou sobre você:**

```bash
# senha em vazamentos (k-anonymity, sem cadastrar nada):
h=$(printf '%s' 'MinhaSenha#123' | sha1sum | cut -d' ' -f1)
curl -s "https://api.pwnedpasswords.com/range/${h:0:5}" | grep -xi "${h:5}" && echo "COMPROMETIDA" || echo "limpo"

# email (exige API key do HIBP):curl -s -H "hibp-api-key: $HIBP_KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/voce@dom.com"

# sem HIBP: holehe (diz onde o email está REGISTRADO):
holehe voce@dom.com

# nome de usuário espalhado em quantas plataformas:
sherlock seu_nick --timeout 10
maigret seu_nick --html relatorio     # gera report navegável
```

**Ver se o seu domínio está sendo imitado (typosquatting):**

```bash
dnstwist --registered seudominio.com
```

**Quais certificados novos apareceram para seu domínio (CA transparency):**

```bash
curl -s "https://crt.sh/?q=%25.exemplo.com&output=json" | \
  jq -r '.[] | "\(.id)\t\(.common_name)\t\(.name_value)"' | sort -u | tail -20
```

---

## Nível 1 — Anonimato e navegação básica

**Tor puro e verificação de circuito:**

```bash
sudo systemctl enable --now tor
# testar se o circuito está mesmo no Tor:
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# resposta: {"IsTor":true,"IP":"..."} confirma saída TOR, não sua

# qualquer programa desejando sair pelo tor via proxychains:
proxychains4 -q nmap -sT -Pn 10.0.0.5      # apenas em alvos autorizados
```

**VPN com kill switch (não vazar tráfego se a VPN cair):**

```bash
sudo wg-quick up wg0 && sudo wg show       # wireguard
sudo ufw default deny incoming
sudo ufw default allow outgoing
# kill switch bruto: permitir saída APENAS pela interface da VPN
sudo ufw deny out on eth0 to any
sudo ufw allow out on wg0 to any
```

**Verificação de rede Wi-Fi (evil twin / rogue AP):**

```bash
nmcli -f SSID,BSSID,CHAN,RATE dev wifi list    # compare o BSSID com o de sempre
iw dev wlan0 link                               # BSSID da conexão atual
```

Se o nome da rede é o mesmo mas o BSSID mudou a fabricante (OUI), **desconfie: pode ser um access point falso capturando tráfego.**

**Tails / Whonix:** use Tails quando anonimato for crítico (amnésia por padrão) e Whonix quando quiser VM de workstation com tor forçado por gateway dedicado.

---

## Nível 2 — Comunicações seguras e criptografia

**PGP/GPG — o básico que você precisa dominar:**

```bash
gpg --full-gen-key                                  # chave ed25519/cv25519
gpg --armor --export voce@email.com > chave.pub     # distribua a pública
gpg -ea -r destinatario@x.com arquivo.txt           # cifrar
gpg -d arquivo.txt.asc                              # decifrar
gpg --clear-sign mensagem.txt                       # assinar sem cifrar
gpg --verify mensagem.txt.asc                        # verificar assinatura
gpg --import chave_do_outro.pub && gpg --fingerprint CHAVE  # conferir em canal separado!
```

**Regra de contra-inteligência:** verifique *fingerprints por um canal diferente daquele onde vai comunicar*. Assinatura verificada no mesmo canal que adversário controla não vale nada.

**age — criptografia moderna quando PGP é exagero:**

```bash
age-keygen -o key.txt                                # gera identidade
age -recipients "$(cat key.txt.pub)" -o doc.age doc.pdf
age -d -i key.txt -o doc.pdf doc.age
```

**Senhas fortes no terminal:**

```bash
openssl rand -base64 24          # aleatório forte
pwgen -sy 24 1                   # alternativo
```

**Verificar ISOs e binários (anti supply-chain):**

```bash
sha256sum -c SHA256SUMS
gpg --verify tails-amd64-6.11.iso.sig tails-amd64-6.11.iso   # baixa a chave de OUTRA fonte
```

---

## Nível 3 — Hardening inicial do sistema

```bash
# atualizações automáticas de segurança
sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades

# firewall mínimo
sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable

# brute force de SSH
sudo apt install fail2ban && sudo systemctl enable --now fail2ban

# o que está ESCUTANDO agora (dica para serviços suspeitos):
ss -tulnp
lsof -i -nP                       # processos com sockets abertos

# serviços rodando:
systemctl list-units --type=service --state=running

# desligar o que não usa:
sudo systemctl disable --now nome-do-servico

# lockdown de sshd (chave, sem senha, sem root):
sudo sshd -O "print" 2>/dev/null || grep -E '^(PasswordAuth|PermitRoot|PubkeyAuth)' /etc/ssh/sshd_config
ssh-keygen -t ed25519 -a 100
# depois edite: PasswordAuthentication no / PermitRootLogin no / PubkeyAuthentication yes
```

**Integridade dos binários (baseline + alerta):**

```bash
sudo apt install aide
sudo aide --init && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check                 # toda mudança não autorizada aparece aqui
```

---

## Nível 4 — Higiene de metadados

**Ler metadados de qualquer coisa:**

```bash
exiftool foto.jpg
exiftool -a -u -g1 arquivo.pdf       # mostra TUDO, incluindo tags escondidas
exiftool video.mp4 | grep -iE 'gps|device|author'
```

**Remover metadados antes de publicar/enviar:**

```bash
exiftool -all= -overwrite_original foto.jpg       # zera tudo
mogrify -strip foto.jpg                            # alternativa ImageMagick
exiftool -all= -overwrite_original documento.pdf
exiftool -gps:all= -overwrite_original *.jpg       # só GPS, mantém o resto
```

**Antes de enviar QUALQUER doc/imagem externamente:** rode `exiftool -a -u -g1` e verifique. GPS em foto, nomes de usuário em PDF (`Author`), histórico de revisão em `.docx` — vazamentos clássicos que desmontam identidades.

---

## Nível 5 — Monitoramento de rede

**Captura cirúrgica:**

```bash
sudo tcpdump -i any -nn -w cap.pcap host 10.0.0.5 and not port 22
sudo tcpdump -i any -nn 'tcp[tcpflags] & (tcp-syn) != 0 and dst port 443'   # handshakes TLS
```

**Análise rápida de conversas (quem fala com quem):**

```bash
tshark -r cap.pcap -q -z conv,tcp | head -25
tshark -r cap.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u   # domínios consultados
```

**Detectar exfiltração via DNS (pacote grande demais é suspeito):**

```bash
tshark -r cap.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name    # TXT queries (canal clássico de C2)
```

**Pingar pacote → descobrir o que acionou o tráfego:**

```bash
ss -tnp state established                 # IP destino + PID do processo
sudo strace -f -p $(pidof nome-do-proc) -e trace=network -s 4096   # syscalls de rede em tempo real
```

**Nas dos IPs suspeitos por organismo (Team Cymru em lote):**

```bash
ss -tnp state established | awk '{print $5}' | cut -d: -f1 | sort -u > ips.txt
{ echo begin; grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' ips.txt; echo end; } | nc whois.cymru.com 43
```

**Reputação dos IPs que aparecem:**

```bash
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq .
```

**Rastreio contínuo de volume (anomalia de upload = vazamento):**

```bash
vnstat -l -i eth0          # relatório em tempo real
iftop -i eth0 -nP          # pares IP↔IP ao vivo
nethogs eth0               # por PROCESSO ( saber quem fez o upload)
```

**Alarme de ARP spoofing (MITM local):**

```bash
sudo arpwatch -i eth0                    # loga anomalias de MAC/IP
ip neigh                                 # tabela ARP manual a qualquer momento
```

**Filtragem de saída (egress) com nftables — só deixa falar o que você permitiu:**

```bash
sudo nft add table inet egress
sudo nft add chain inet egress out '{ type filter hook output priority 0; policy drop; }'
sudo nft add rule inet egress out ip daddr 1.1.1.1 udp dport 53 accept
sudo nft add rule inet egress out ip daddr 8.8.8.8 tcp dport 443 accept
sudo nft list table inet egress          # qualquer processo tentando sair para outro lugar MORRE
```

Este é o controle **mais eficaz contra malware** em máquina de alto Valor: ransomware/beacon sem C2 autorizado não consegue encontrar o dono.

**Suricata IDS:**

```bash
sudo apt install suricata
sudo suricata -i eth0 -c /etc/suricata/suricata.yaml
tail -f /var/log/suricata/fast.log        # alertas em tempo real
```

---

## Nível 6 — Caça a comprometimentos (Threat Hunting)

**Tudo que mudou nas últimas 24h (menos logs/temp):**

```bash
find / -xdev -mtime -1 -type f 2>/dev/null | grep -Ev '^/(proc|sys|run|dev|var/log|var/cache)' | head -50
```

**Binários SUID e writáveis — parâmetros clássicos de escalação:**

```bash
find / -xdev -perm -4000 -type f -exec ls -la {} \; 2>/dev/null     # compare com um baseline seu
find / -xdev -type f -perm -o+w ! -type l 2>/dev/null | head -30
```

**Auditd — o esqueleto de detecção que vale ouro:**

```bash
sudo auditctl -w /etc/passwd   -p wa  -k identidade
sudo auditctl -w /etc/shadow   -p wa  -k credenciais
sudo auditctl -w /etc/sudoers  -p wa  -k sudo
sudo auditctl -w /etc/ssh      -p wa  -k ssh
sudo auditctl -w /root         -p rxwa -k root_acessos
sudo ausearch -k identidade -i | tail       # visualizar o uso
```

**osquery — SQL contra o estado da máquina:**

```bash
osqueryi "select pid, name, path from processes where path like '%/tmp/%';"
osqueryi "select name, path, schedule from scheduled_jobs;"          # timers systemd/cron visíveis
osqueryi "select * from users where uid=0;"                          # todo uid 0 é suspeito além do root
```

**Módulos de kernel carregados (rootkits residem aqui):**

```bash
lsmod | awk 'NR>1 {print $1}' | sort > atual.txt     # compare com baseline
sudo modinfo $(lsmod | awk 'NR>1 {print $1}') | grep -E '^(filename|signer)'   # unsigned = sinal vermelho
cat /proc/sys/kernel/modules_disabled                # 1 = travou carga de módulos (pós-diagnóstico)
```

**YARA — palpar binário com assinaturas:**

```bash
yara -r regras/hunting.yar /home/usuario
strings -el suspeito.bin | grep -iE 'https?://|powershell|cmd.exe|github' | sort -u   # triage instantânea
binwalk suspeito.bin                                                               # trojans em firmware/imagens
```

**Scanners pontuais:**

```bash
sudo rkhunter --check --sk
sudo chkrootkit
```

---

## Nível 7 — Persistência: onde espiões se escondem

Checklist de todos os lugares onde algo se reinicia **só**:

```bash
# systemd
systemctl list-unit-files --state=enabled
systemctl list-timers --all

# cron
crontab -l
sudo crontab -l
cat /etc/crontab /etc/cron.*/* 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# shell hooks
tail -50 ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null
cat /etc/profile.d/*.sh 2>/dev/null
cat /etc/rc.local /etc/init.d/rc.local 2>/dev/null

# pré-carga (mais insidioso)
cat /etc/ld.so.preload 2>/dev/null     # vazio é o padrão. Se tiver lib, investigue

# autostart de desktop
ls -la ~/.config/autostart/ 2>/dev/null
ls -la /etc/xdg/autostart/ 2>/dev/null

# contas e sudo
awk -F: '$3==0' /etc/passwd           # usuários com UID 0
grep -r "" /etc/sudoers.d/ 2>/dev/null
last -na 30 ; sudo lastb | head        # logins bem-sucedidos e FALHOS recentes

# chaveiro ssh do agressor
cat ~/.ssh/authorized_keys 2>/dev/null  # chave desconhecida aqui = acesso remoto garantido
```

**Análise de logins SSH suspeitos:**

```bash
sudo journalctl -u ssh --since "today" | grep 'Failed password' | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
sudo grep 'session opened' /var/log/auth.log | grep -v 'user root' | tail   # quem logou e quando
```

**Força de cada serviço (sandboxing systemd — caso sutil de hidden service):**

```bash
systemd-analyze security | grep -E 'UNSAFE|OVERALL' | sort -k5 -h | head -20
```

---

## Nível 8 — Honeypots e canários (detecção proativa)

**Honeyfile com auditd — quem LER o arquivo falso virou alarme:**

```bash
echo " arquivo isca - NÃO ABRIR" > /root/projetos-2026-final.txt
sudo auditctl -w /root/projetos-2026-final.txt -p rwa -k isca
sudo ausearch -k isca -i        # alguém que leu/copiou aparece aqui
```

**Canarytokens (canarytokens.org) — tokens que disparam alerta quando usados:**

- token de **DNS**: um domínio único, dispara quando alguém resolve (ex.: em um `/etc/resolv.conf` adulterado)
- token de **web bug** em documento: dispara quando o PDF é aberto em outra rede
- token de **credencial falsa**: se alguém usar a senha fake, você recebe o IP, país, browser

**Honeypot SSH (cowrie) — ver todo o arsenal de quem te ataca:**

```bash
sudo apt install -y python3-virtualenv
cd /opt && virtualenv cowrie-env && source cowrie-env/bin/activate
pip install -r requirements.txt   # clonar git clone https://github.com/cowrie/cowrie
# configure porta fake 2222 redirecionada; loga comandos, chaves tentadas e IPs
```

**IP sinkhole (nftables tarpit) para scrapers:**

```bash
sudo nft add rule inet filter input ip saddr $IP_MALDITO tcp dport 22 drop
# alternativa: tproxy para uma porta que NUNCA entrega mas segura conexão (desperdiça o tempo do atacante)
```

---

## Nível 9 — Forense e aquisição de evidência

**Ordem de volatilidade:** RAM → swap → disco → logs remotos. RAM morre quando você desliga.

```bash
# AQUISIÇÃO DE DISCO (com hash ANTES, DURANTE e DEPOIS):
sudo sha256sum /dev/sda > hash.origem.txt
sudo dd if=/dev/sda of=/mnt/evid/sda.img bs=4M conv=noerror,sync status=progress
sudo sha256sum /mnt/evid/sda.img > hash.imagem.txt
# os tres arquivos + horário + hd externo ) = cadeia de custódia mínima

# AQUISIÇÃO DE MEMÓRIA (LiME / avml):
sudo insmod lime-$(uname -r).ko "path=/mnt/evid/mem.lime format=lime"
# ou, avml (Go, single binary):
sudo ./avml /mnt/evid/mem.lime

# ANÁLISE com Volatility 3:
python3 vol.py -f mem.lime linux.pstree       # árvore de processos
python3 vol.py -f mem.lime linux.bash         # comandos digitados por shell
python3 vol.py -f mem.lime linux.tty-check=!  # não sintaxe exata — checar docs do plugin
```

**Verificação de integridade de logs (/logs manipulados são falso-alibi):**

```bash
sudo journalctl --verify                    # erro aqui = log desconfiado
stat /var/log/auth.log                      # Compare mtime com o que deveria
# defesa: logs remotos. NO servidor alvo, rsyslog envia em tempo real:
# action(type="omfwd" target="10.0.0.99" port="514" protocol="tcp")
```

---

## Nível 10 — Anti-forense defensiva e destruição segura

> Anti-forense **da sua própria máquina** = apagar de verdade o que você decidiu apagar. Não é ocultar evidência de crime.

```bash
# apagar arquivo, sem backup:
shred -zvu -n 3 arquivo.jpg        # 3 loops + sobrescreve com zero + remove
wipe -rf diretório/                 # alternativa padrão em Debian

# apagar disco inteiro:
sudo dd if=/dev/urandom of=/dev/sdb bs=4M status=progress

# apagar chave de v LM LUKS (dados CRIPTOGRAFADOS ficam irrecuperáveis):
sudo cryptsetup luksErase /dev/sdb1

# swap e memória residual:
sudo swapoff -a && sudo mkswap /dev/disk/by-id/SEU_SWAP && sudo swapon -a

# metadados de sistema de arquivos:
sudo rm -rf /var/tmp /tmp/*           # (dentro da sua rotina, não como mágica)
```

**A verdade absoluta:** sem criptografia de disco (LUKS, APFS, BitLocker), ninguém pode garantir destruição. **Criptografe desde o início** e "apagar" vira "esquecer a chave".

```bash
sudo cryptsetup luksFormat /dev/sdb1 && sudo cryptsetup luksOpen /dev/sdb1 secreto
```

---

## Nível 11 — Mobile: Android e iOS

**Android via adb (depuração USB, dispositivo próprio):**

```bash
adb list devices
adb shell pm list packages -3 | sort                       # apps de terceiros
adb shell dumpsys package pacote.suspeito | grep -E 'perm|INSTALL'    # o app pede o que?
adb shell settings get secure adb_enabled
adb logcat | grep -iE 'accessibility|device_admin'          # malware usa esses serviços
```

**MVT (Mobile Verification Toolkit, da Amnesty International) — checa por spyware conhecido (Pegasus, RCS etc.):**

```bash
pip install mvt
mvt-ios check-backup --output analise backups-do-iphone/    # iOS: analisa backup
mvt-android download-apks --output apks/                     # Android: extrai APKs do device
```

**Sinais manuais de stalkerware no Android:**

```bash
adb shell pm list packages | grep -Ei 'spy|track|monitor|parental|guard'    
adb shell dumpsys device_policy | grep -A5 'Device Owner'     # admin escondido?
Ab Settings → Segurança → Administradores do dispositivo      # verificação manual essencial
```

**iOS:** backup pelo Finder/livre, depois `mvt-ios check-backup` contra os IOCs da Citizen Lab ([verificação em grande escala aqui](https://github.com/mvt-project/mvt)).

---

## Nível 12 — Windows rápido (PowerShell, alvo próprio)

```powershell
# conexões estabelecidas e o PROCESSO de origem:
Get-NetTCPConnection -State Established |
  Select-Object RemoteAddress, RemotePort, OwningProcess, |
  ForEach-Object { [pscustomobject]@{ IP=$_.RemoteAddress; Port=$_.RemotePort;
      Processo=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }

# persistência clássica:
Get-ScheduledTask | Where-Object State -ne Disabled                       # tarefas agendadas
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'    # autorun
wmic startup get caption,command 2>$null

# eventos de logon falho (força bruta):
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 |
  Format-Table TimeCreated, @{L='IP';E={$_.Properties[19].Value}} -AutoSize

# Sysmon + autoruns (arma padrão da comunidade):
.\Sysmon64.exe -i -accepteula sysmonconfig-export.xml     # telemetria definitiva
autorunsc.exe -accepteula -a * -c > autoruns.csv          # tudo que inicia com o Windows
```

---

## Nível 13 — Infra, VMs e compartimentalização

**Snapshots de VM (estado limpo para cada identidade):**

```bash
virsh list --all
virsh snapshot-create-as --domain work-vm --name "clean-$(date +%F)"
virsh snapshot-revert work-vm clean-2026-11-16     # rollback em segundos
```

**Compartimentalização real (a lógica de CI - Contra-Inteligência):**

| Papel | Onde | Regra |
|---|---|---|
| Identidade pública | cliente normal, celular real | nada de Linux forense |
| Identidade de pesquisa | VM no host, navegador isolado | nunca logue na pessoal |
| Operação sensível | Tails/Whonix via Tor, de rede estrangeira | zero correlação com as outras |

**Regra de aço: nunca cruzar identidades.** Cookies, contas de e-mail de recuperação, número de telefone — são exatamente o que VAZEA a correlação.

**Verificar isolamento de navegador da VM:**

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## Nível 14 — Monitorar sua própria exposição

**Monitor de novos certificados (executar via cron semanal):**

```bash
#!/bin/bash
DOM="seudominio.com"
curl -s "https://crt.sh/?q=%25.${DOM}&output=json" | \
  jq -r '.[] | .common_name' | sort -u > /tmp/now.txt
diff /tmp/now.txt /path/baseline.txt | grep '^>' >> /var/log/certs_novos.log
```

**Monitor de vazamentos (mistura HIBP + tor + cron):** use a API do HIBP com key free para checar no primeiro dia de cada mês.

**RSS das fontes que importam:**

```bash
# Vazamentos, breaches e pesquisas de segurança em um único feed:
curl -s "https://haveibeenpwned.com/api/v3/latestbreach" | jq .
```

---

## Rotinas

**Diário (5 min):**

```bash
ss -tulnp | diff - baseline_ports.txt          # serviços novos?
sudo journalctl --since "today" -p err         # erros do sistema
sudo ausearch -k isca -i | tail -5             # honeypot tocado?
```

**Semanal (30 min):** `sudo aide --check` · `sudo rkhunter --check` · `diff` de `lsmod` · revisão de `dnstwist` no seu domínio · revisão de `crt.sh`.

**Mensal:** HIBP nos e-mails suas · rotação de senhas críticas · snapshot limpo das VMs · atualização de IOCs no YARA/MVT · revisão dos canarytokens ativos.

---

## Regra de ouro

> **Contra-inteligência não é ferramenta, é processo:** você *assume que está sendo observado*, minimiza o que sai de você (OPSEC), *instrumenta* o seu próprio perímetro para detectar anomalia, e *responde rápido* quando algo dispara.
>
> O atacante só precisa acertar uma vez. Você precisa defender o tempo inteiro — e a única forma de sustentar isso é com **rotina e automação**, não com pânico reativo.
