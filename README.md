# Quasar Scan

![Quasar Scan](assets/logo.png)

Ferramenta de **descoberta e diagnóstico de rede** para técnicos de provedor de internet em atendimento ao cliente.

Um único executável para Windows, sem instalação: ele sobe uma interface no navegador, varre a rede do cliente,
mede a qualidade da conexão, analisa o Wi-Fi, monitora quedas e gera um relatório do atendimento com o
**antes e depois**. Tudo roda localmente; a rede local é analisada mesmo sem internet.

---

## Sumário

- [Destaques](#destaques)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como usar](#como-usar)
- [Classificações](#classificações)
- [Regras de diagnóstico](#regras-de-diagnóstico)
- [Arquivos e relatórios](#arquivos-e-relatórios)
- [Privacidade e segurança](#privacidade-e-segurança)
- [Solução de problemas](#solução-de-problemas)
- [Desenvolvimento](#desenvolvimento)
- [Arquitetura](#arquitetura)
- [Limitações conhecidas](#limitações-conhecidas)

---

## Destaques

- **Um arquivo só (~12 MB)**: interface, ícone e base de 40 mil fabricantes (IEEE OUI) embutidos. Não precisa de
  Go, .NET, Python nem internet.
- **APIs nativas do Windows**: ping, traceroute, ARP, rotas, Wi-Fi e DHCP sem chamar `ping.exe`/CMD por baixo
  (funciona em Windows de qualquer idioma).
- **Linguagem de atendimento**: cada resultado vem classificado (Excelente / Razoável / Ruim / Péssimo) e cada
  alerta explica o que significa e o que verificar.
- **Ensina os comandos**: as ferramentas mostram o comando equivalente do CMD (`ping -n 10 8.8.8.8`,
  `tracert -d`, `nslookup -type=MX`…), atualizado conforme o técnico preenche o formulário.
- **Relatório com antes e depois** para anexar à ordem de serviço ou entregar ao cliente.

## Requisitos

| | |
|---|---|
| Sistema | Windows 10 ou 11, **64 bits** |
| Navegador | Qualquer navegador moderno (Edge já vem no Windows) |
| Permissão | Pede administrador ao abrir (necessário para renovar IP; o resto funciona sem) |
| Internet | Opcional. Sem ela, os testes externos avisam e a análise local continua |

Não funciona em Windows 7/8 nem em Windows de 32 bits.

## Instalação

1. Descompacte o pacote (`QuasarScan-vX.zip`) em uma pasta fixa, por exemplo `C:\QuasarScan`.
   > Dica: antes de descompactar, clique com o botão direito no `.zip` → **Propriedades** → marque
   > **Desbloquear**. Isso evita o aviso do SmartScreen.
2. Dê dois cliques em **`Criar atalho na Area de Trabalho.bat`** (só na primeira vez).
3. Abra pelo ícone **Quasar Scan** da Área de Trabalho e aceite o pedido de administrador.

O pacote contém apenas `QuasarScan.exe`, o `.bat` do atalho e o `LEIA-ME.txt`.

**Abrir de novo** com o programa já aberto apenas reabre a interface (não cria outra cópia).
**Fechar a aba** do navegador não encerra o programa: use o botão **Encerrar** no canto superior direito.

Opções de linha de comando: `QuasarScan.exe -porta 8765 -sem-navegador`

## Como usar

Fluxo sugerido em um atendimento:

1. **Relatório** → preencha cliente, código, plano e o problema relatado.
2. **Saúde da conexão** → escolha *Cabeado* ou *Wi-Fi* e rode o teste completo (este é o “antes”).
3. Investigue com **Análise geral**, **Wi-Fi**, **Diagnóstico de rede** ou deixe o **Monitoramento** rodando.
4. Depois de resolver, rode o teste completo de novo (o “depois”).
5. **Relatório** → descreva a solução e clique em **Gerar relatório** (imprimir ou salvar em PDF).

### Análise geral

Varredura da rede local (até uma /20; redes maiores varrem a /24 do computador).

- **Descoberta**: ICMP + ARP em paralelo; encontra até aparelhos que bloqueiam ping.
- **Identificação**: fabricante pelo MAC, nome por DNS reverso, NetBIOS, **mDNS/Bonjour** e **UPnP**
  (nome amigável, modelo, serviços como impressora, Chromecast, AirPlay, Spotify Connect).
- **Portas comuns**: HTTP/HTTPS, SSH, Telnet, RDP, SMB, Winbox/API MikroTik, TR-069, RTSP, DVR, impressão etc.
- **Servidores DHCP**: envia um *DHCP Discover* de teste e lista todos que respondem — detecta **DHCP duplicado**.
- **Configuração**: IP, máscara, gateway, DNS, DHCP (servidor e concessão), IPv6, internet e IP público.
- Exporta a lista de dispositivos em **CSV** (abre direto no Excel) ou **JSON**.

### Saúde da conexão

Teste completo em cerca de 15 segundos:

- Latência, jitter e perda até o **roteador**, o **DNS configurado**, **Cloudflare**, **Google** e um site
  (IPv4 e IPv6), com 25 amostras por destino.
- **Qualidade para chamadas de vídeo** (Zoom/Teams/Meet).
- **Traceroute** até 8.8.8.8 com detecção de **CGNAT**, **duplo NAT** e do salto onde a latência sobe.
- **DNS**: velocidade do configurado x Cloudflare, Google e Quad9, e verificação de **sequestro de DNS**.
- **MTU do caminho**, **IPv6** (habilitado, sem prefixo, sem internet ou desabilitado),
  **velocidade negociada da placa x plano** e sinal do Wi-Fi.
- Seletor **Cabeado / Wi-Fi**: no Wi-Fi as faixas de latência dobram.

**Teste de velocidade** (na mesma aba): download, upload e **latência sob carga (bufferbloat)**, usando a
Cloudflare ou um servidor **LibreSpeed do provedor** (informe a URL do backend, ex.:
`http://speedtest.provedor.com.br/backend`). Consome dados: num plano de 500 Mega, cerca de 1 GB.

### Wi-Fi

Sinal (dBm e %), banda, canal, padrão (Wi-Fi 4/5/6/7), velocidade do link e segurança da conexão atual, mais as
redes vizinhas com gráfico de ocupação dos canais e **sugestão do melhor canal**. Avisa sobre sinal fraco, rede
2.4 GHz com 5 GHz disponível, canal congestionado, canal 2.4 GHz fora de 1/6/11, segurança fraca e link abaixo do plano.

### Monitoramento

Pinga roteador, Cloudflare e Google a cada segundo por 5 minutos a 12 horas (ou até parar). Registra cada **queda**
e **pico**, dizendo onde foi: **rede local** (o roteador também parou) ou **internet/provedor** (só a internet
parou). Continua com o navegador fechado e impede o computador de entrar em suspensão.

### Diagnóstico de rede

Os comandos do CMD com formulário, explicação e resultado classificado:

| Ferramenta | Equivalente |
|---|---|
| Ping (IPv4/IPv6, contínuo) | `ping -n 10` / `ping -t` / `ping -6` |
| Traceroute (IPv4/IPv6) | `tracert -d -h 30` |
| Consulta DNS (A, AAAA, MX, TXT, NS, CNAME, PTR) + comparação + sequestro | `nslookup -type=MX` |
| Configuração IP | `ipconfig /all` |
| Limpar cache DNS e renovar IP | `ipconfig /flushdns`, `/release`, `/renew` |
| Tabela ARP | `arp -a` |
| Tabela de rotas | `route print -4` |
| Testar porta | `Test-NetConnection -Port` |
| Teste de MTU | `ping -f -l` |

### Relatório

Os testes feitos durante o atendimento ficam ligados a ele. O relatório (página para imprimir/salvar em PDF)
traz dados do cliente, problema relatado, diagnóstico, **antes e depois** (primeiro x último teste, com
“melhorou/piorou”), conexão, Wi-Fi, velocidade, monitoramento, lista de dispositivos, solução aplicada e
campos de assinatura. **Salvar cópia** grava o HTML na pasta do cliente.

## Classificações

As faixas ficam em [`internal/diag/metrics.go`](internal/diag/metrics.go) — altere lá para ajustar.

| Métrica | Excelente | Razoável | Ruim | Péssimo |
|---|---|---|---|---|
| Latência (internet) | ≤ 15 ms | ≤ 25 ms | ≤ 50 ms | > 50 ms |
| Latência (rede local) | ≤ 3 ms | ≤ 10 ms | ≤ 30 ms | > 30 ms |
| Latência internet **no Wi-Fi** | ≤ 30 ms | ≤ 50 ms | ≤ 100 ms | > 100 ms |
| Latência rede local **no Wi-Fi** | ≤ 6 ms | ≤ 20 ms | ≤ 60 ms | > 60 ms |
| Jitter | ≤ 5 ms | ≤ 15 ms | ≤ 30 ms | > 30 ms |
| Perda de pacotes | 0 % | ≤ 1 % | ≤ 5 % | > 5 % |
| Resposta DNS | ≤ 20 ms | ≤ 50 ms | ≤ 100 ms | > 100 ms |
| Latência sob carga (aumento) | ≤ 20 ms | ≤ 60 ms | ≤ 150 ms | > 150 ms |
| Sinal do Wi-Fi | ≥ −55 dBm | ≥ −67 dBm | ≥ −75 dBm | < −75 dBm |
| Velocidade x plano | ≥ 90 % | ≥ 70 % | ≥ 50 % | < 50 % |

A classificação geral de um destino é a **pior** entre latência, jitter e perda. A qualidade para chamadas usa o
melhor destino da internet (um servidor que despriorize ping não condena a conexão inteira).

## Regras de diagnóstico

Alguns critérios usados nos alertas:

- **MTU**: 1401–1500 é normal (1492 = PPPoE). Aviso de 1300 a 1400; crítico abaixo de 1300. Se o limite vier da
  própria placa do computador, o alerta diz isso.
- **CGNAT**: até 2 saltos na faixa `100.64.0.0/10` é normal (informativo); **3 ou mais** gera alerta de NAT em cascata.
- **Duplo NAT**: endereço privado logo depois do roteador (ex.: ONU em modo roteador + roteador do cliente).
- **Rede local x provedor**: se o jitter até o roteador é quase o mesmo da internet, a oscilação nasce na rede
  local; se o roteador está bem e a internet não, o problema está depois do roteador.
- **Placa a 100 Mbps** com plano maior: aponta cabo sem os 4 pares, mal crimpado ou porta não gigabit.
- **Teste de velocidade limitado pela placa**: não culpa o provedor quando o resultado bate no limite da placa.
- **DHCP duplicado**: mais de um servidor respondendo ao *Discover* (ofertas das placas virtuais do próprio PC,
  como Hyper-V/WSL, são descartadas).
- **Sequestro de DNS**: um domínio inexistente que recebe IP indica redirecionamento; se até o 1.1.1.1 responde,
  há interceptação no caminho.

## Arquivos e relatórios

Tudo é salvo em `relatorios\` ao lado do executável. Com o atendimento preenchido, em uma pasta por cliente:

```
relatorios\
  12345-maria-silva\
    varredura-2026-10-21_14-02-11.json
    saude-2026-10-21_14-05-40.json
    velocidade-2026-10-21_14-07-02.json
    wifi-2026-10-21_14-09-15.json
    monitoramento-2026-10-21_14-10-00.json
    relatorio-2026-10-21_15-30-12.html
```

## Privacidade e segurança

- A interface escuta **somente em `127.0.0.1`** e recusa requisições de outros sites abertos no navegador
  (verificação de `Host`, `Origin` e `Sec-Fetch-Site`).
- Nada é enviado a servidores próprios. Os únicos acessos externos são os testes de internet:
  ping/conexão a 1.1.1.1 e 8.8.8.8, `https://1.1.1.1/cdn-cgi/trace` (IP público), consultas DNS de teste e o
  teste de velocidade (Cloudflare ou o servidor do provedor informado).
- O teste de DHCP só envia *Discover* com um MAC fictício: nenhum IP é reservado ou alterado.
- O navegador é aberto como usuário comum, mesmo com o programa elevado.

## Solução de problemas

| Situação | O que fazer |
|---|---|
| “O Windows protegeu o computador” | **Mais informações** → **Executar assim mesmo** (o executável não tem assinatura digital). Ou desbloqueie o `.zip` antes de extrair. |
| Antivírus apagou o `.exe` | Falso positivo (programa novo que faz varredura de rede). Restaure em Segurança do Windows → Proteção contra vírus e ameaças → Histórico de proteção. |
| Wi-Fi não lista redes vizinhas | Windows 11: ative **Configurações → Privacidade e segurança → Localização**, inclusive para aplicativos da área de trabalho. Ou o rádio Wi-Fi está desligado. |
| “Renovar IP” desabilitado | O programa não está como administrador: feche e abra pelo atalho aceitando o pedido. |
| Poucos nomes de dispositivos | Muitos aparelhos não anunciam nome; celulares com MAC aleatório não mostram fabricante. |
| Interface não abre | Outra instância pode estar aberta: clique no ícone de novo. Se a porta 8765 estiver reservada pelo Windows (Hyper-V/WSL), o programa usa outra automaticamente. |

## Desenvolvimento

Requer **Go 1.26+** (Windows).

```bash
# executável final (sem console, pede administrador via rsrc_windows_amd64.syso)
go build -trimpath -ldflags "-H=windowsgui" -o QuasarScan.exe .

# pacote de distribuição
go build -trimpath -ldflags "-H=windowsgui" -o dist/QuasarScan/QuasarScan.exe .

# testes
go vet ./...
go test ./...
```

**Testar pelo terminal**: o `.syso` faz o executável exigir administrador, o que um terminal comum não consegue
aceitar. Para testes automatizados, compile uma cópia sem ele (mova o `rsrc_windows_amd64.syso` temporariamente
para fora da pasta) e rode com `-sem-navegador -porta 8764`.

**Ícone e manifesto** (refazer o `.syso`). O ícone é recortado do emblema do logo (`assets/logo.png`):

```bash
go run ./tools/genicon
go run github.com/tc-hib/go-winres@v0.3.3 simply --icon assets/icon.png --manifest gui --admin \
  --product-name "Quasar Scan" --file-description "Quasar Scan - diagnostico de rede local" --arch amd64
```

**Base de fabricantes** (atualizar a lista do IEEE, embutida no executável):

```bash
go run ./tools/genoui
```

**Cuidados com antivírus**: o Windows Defender já deu falso positivo heurístico uma vez. Evite que o executável
chame PowerShell, `rundll32` ou CMD, e passe o `.exe` pelo Defender após mudanças grandes:

```powershell
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File .\QuasarScan.exe -DisableRemediation
```

## Arquitetura

```
main.go                 inicia o servidor local, instância única, abre o navegador
internal/
  netinfo/              configuração das placas (GetAdaptersAddresses/GetAdaptersInfo)
  winapi/               APIs nativas: ICMP v4/v6 (TTL e DF), ARP, rotas, cache DNS,
                        renovar IP, Wi-Fi (wlanapi), manter acordado
  scan/                 varredura: ICMP+ARP, DNS reverso, NetBIOS, mDNS, SSDP/UPnP,
                        DHCP, portas, classificação de dispositivos e análise
  diag/                 ping, traceroute, DNS, porta, MTU, sequestro de DNS, Wi-Fi,
                        velocidade, teste de saúde e escalas de classificação
  monitor/              monitoramento contínuo (quedas e picos)
  oui/                  fabricante pelo MAC (base IEEE embutida)
  web/                  servidor HTTP, API, atendimento/relatório e interface (static/)
tools/
  genoui/               gera a base de fabricantes
  genicon/              gera o ícone a partir do logo
```

A interface é HTML/CSS/JS puro em `internal/web/static`, sem bibliotecas externas, embutida no executável.
Operações longas (ping, traceroute, teste de saúde, velocidade) usam *Server-Sent Events* para mostrar o
progresso em tempo real.

### API local

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/info` | administrador? nome do computador |
| GET | `/api/interfaces` | placas de rede |
| POST / GET | `/api/scan` / `/api/status` | inicia e acompanha a varredura |
| GET | `/api/export.csv`, `/api/export.json` | exporta a última varredura |
| GET | `/api/health` | teste completo (SSE) — `?plano=&meio=cabo\|wifi` |
| GET | `/api/speed` | teste de velocidade (SSE) — `?server=&segundos=` |
| GET | `/api/wifi` | análise do Wi-Fi — `?scan=1` |
| POST / GET | `/api/monitor/start`, `/api/monitor/stop`, `/api/monitor` | monitoramento |
| GET | `/api/tools/ping`, `/api/tools/trace` | ping e traceroute (SSE) |
| GET | `/api/tools/dns`, `/api/tools/dnsbench`, `/api/tools/hijack` | consultas DNS |
| GET | `/api/tools/arp`, `/api/tools/routes`, `/api/tools/port`, `/api/tools/mtu` | demais ferramentas |
| POST | `/api/tools/flushdns`, `/api/tools/renew` | limpar cache DNS, renovar IP |
| GET / POST | `/api/atendimento` | dados do atendimento (`?novo=1` inicia outro) |
| GET / POST | `/api/relatorio/dados`, `/api/relatorio/salvar` | relatório |
| GET | `/api/scales` | faixas de classificação |
| POST | `/api/shutdown` | encerra o programa |

## Limitações conhecidas

- Somente Windows 10/11 de 64 bits.
- Varredura limitada a 4.096 endereços (/20) por vez.
- A lista de redes Wi-Fi vizinhas depende da Localização do Windows 11.
- Testar portas do **IP público** de dentro da própria rede não reflete a visão externa (NAT loopback), por isso
  não é feito.
- O executável não tem assinatura digital: SmartScreen e, eventualmente, antivírus podem alertar.
