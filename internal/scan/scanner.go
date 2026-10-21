// Package scan descobre os dispositivos da rede local (Fase 2) e analisa a configuração.
package scan

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"quasarscan/internal/netinfo"
	"quasarscan/internal/oui"
	"quasarscan/internal/winapi"
)

// MaxHosts limita o tamanho da varredura (equivale a uma /20).
const MaxHosts = 4096

type Host struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	RandomMAC  bool     `json:"randomMac"`
	Hostname   string   `json:"hostname,omitempty"`
	NetBIOS    string   `json:"netbios,omitempty"`
	Workgroup  string   `json:"workgroup,omitempty"`
	RTTms      float64  `json:"rttMs"` // -1 = não respondeu ao ping
	TTL        uint8    `json:"ttl,omitempty"`
	OSGuess    string   `json:"osGuess,omitempty"`
	DeviceType string   `json:"deviceType"`
	FoundBy    []string `json:"foundBy"`
	OpenPorts  []Port   `json:"openPorts"`
	IsGateway  bool     `json:"isGateway"`
	IsSelf     bool     `json:"isSelf"`
	// Identificação por mDNS/Bonjour e UPnP.
	MDNSName     string    `json:"mdnsName,omitempty"`
	FriendlyName string    `json:"friendlyName,omitempty"`
	Model        string    `json:"model,omitempty"`
	Services     []string  `json:"services,omitempty"`
	UPnP         *UPnPInfo `json:"upnp,omitempty"`
}

type Finding struct {
	Level  string `json:"level"` // info, aviso, critico
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type Options struct {
	InterfaceIndex uint32 `json:"interfaceIndex"` // 0 = interface principal
	CIDR           string `json:"cidr"`           // opcional: força uma faixa
	ScanPorts      bool   `json:"scanPorts"`
	CheckInternet  bool   `json:"checkInternet"`
}

type Result struct {
	StartedAt  time.Time           `json:"startedAt"`
	FinishedAt time.Time           `json:"finishedAt"`
	DurationS  float64             `json:"durationS"`
	Computer   string              `json:"computer"`
	Interface  *netinfo.Interface  `json:"interface"`
	Interfaces []netinfo.Interface `json:"interfaces"`
	Target     string              `json:"target"`
	Hosts      []Host              `json:"hosts"`
	Internet   *InternetStatus     `json:"internet,omitempty"`
	DHCP       []DHCPOffer         `json:"dhcpServers"`
	DHCPError  string              `json:"dhcpError,omitempty"`
	Findings   []Finding           `json:"findings"`
}

// Progress é o estado de uma varredura em andamento, consultado pela interface web.
type Progress struct {
	Running bool    `json:"running"`
	Phase   string  `json:"phase"`
	Done    int64   `json:"done"`
	Total   int64   `json:"total"`
	Found   int64   `json:"found"`
	Error   string  `json:"error,omitempty"`
	Result  *Result `json:"result,omitempty"`
}

// Scanner garante que só uma varredura rode por vez.
type Scanner struct {
	mu    sync.Mutex
	state Progress
	done  atomic.Int64
	found atomic.Int64
}

func (s *Scanner) Status() Progress {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.state
	p.Done, p.Found = s.done.Load(), s.found.Load()
	return p
}

func (s *Scanner) setPhase(phase string, total int64) {
	s.mu.Lock()
	s.state.Phase, s.state.Total = phase, total
	s.mu.Unlock()
	s.done.Store(0)
}

// Start inicia a varredura em segundo plano.
func (s *Scanner) Start(opt Options) error {
	s.mu.Lock()
	if s.state.Running {
		s.mu.Unlock()
		return fmt.Errorf("já existe uma varredura em andamento")
	}
	s.state = Progress{Running: true, Phase: "Lendo configuração local"}
	s.mu.Unlock()
	s.found.Store(0)

	go func() {
		res, err := s.run(opt)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.Running = false
		s.state.Phase = "Concluído"
		s.state.Result = res
		if err != nil {
			s.state.Error = err.Error()
		}
	}()
	return nil
}

func (s *Scanner) run(opt Options) (*Result, error) {
	res := &Result{StartedAt: time.Now(), Findings: []Finding{}, Hosts: []Host{}}
	res.Computer, _ = os.Hostname()

	ifaces, err := netinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	res.Interfaces = ifaces
	iface := pickInterface(ifaces, opt.InterfaceIndex)
	if iface == nil {
		return res, fmt.Errorf("nenhuma interface ativa com IPv4 foi encontrada — o cabo/Wi-Fi está conectado?")
	}
	res.Interface = iface

	// Internet roda em paralelo com a varredura local.
	var netWG sync.WaitGroup
	if opt.CheckInternet {
		netWG.Add(1)
		go func() { defer netWG.Done(); st := CheckInternet(); res.Internet = &st }()
	}

	selfIP, prefix, err := targetPrefix(iface, opt.CIDR, &res.Findings)
	if err != nil {
		return res, err
	}
	res.Target = prefix.String()

	// Detecção de servidores DHCP em paralelo com a descoberta.
	netWG.Add(1)
	go func() {
		defer netWG.Done()
		var exclude []netip.Prefix
		for _, it := range ifaces {
			if it.Index == iface.Index {
				continue
			}
			for _, a := range it.IPv4 {
				if p, err := netip.ParsePrefix(a.Network); err == nil {
					exclude = append(exclude, p)
				}
			}
		}
		offers, err := DetectDHCP(prefix, exclude, 3*time.Second)
		res.DHCP = offers
		if err != nil {
			res.DHCPError = err.Error()
		}
	}()

	hosts := s.discover(prefix)
	s.identify(selfIP, hosts)
	gateways := map[string]bool{}
	for _, g := range iface.Gateways {
		gateways[g] = true
	}

	// Garante que a própria máquina apareça na lista.
	if selfIP.IsValid() && prefix.Contains(selfIP) {
		if _, ok := hosts[selfIP]; !ok {
			hosts[selfIP] = &Host{IP: selfIP.String(), RTTms: 0, FoundBy: []string{"local"}, OpenPorts: []Port{}}
		}
		hosts[selfIP].IsSelf = true
		hosts[selfIP].MAC = iface.MAC
		hosts[selfIP].Hostname = res.Computer
	}

	s.enrich(hosts, opt.ScanPorts, gateways)

	for _, h := range hosts {
		res.Hosts = append(res.Hosts, *h)
	}
	slices.SortFunc(res.Hosts, func(a, b Host) int {
		return netip.MustParseAddr(a.IP).Compare(netip.MustParseAddr(b.IP))
	})

	netWG.Wait()
	analyze(res)
	res.FinishedAt = time.Now()
	res.DurationS = res.FinishedAt.Sub(res.StartedAt).Seconds()
	return res, nil
}

// discover faz Ping (ICMP) e ARP em todos os IPs da faixa ao mesmo tempo.
func (s *Scanner) discover(prefix netip.Prefix) map[netip.Addr]*Host {
	ips := hostsIn(prefix)
	s.setPhase("Descobrindo dispositivos (ICMP + ARP)", int64(len(ips)))

	var mu sync.Mutex
	found := map[netip.Addr]*Host{}
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for w := 0; w < 256; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				var (
					pr      winapi.EchoReply
					pingErr error
					mac     net.HardwareAddr
					arpErr  error
					inner   sync.WaitGroup
				)
				inner.Add(2)
				go func() {
					defer inner.Done()
					pr, pingErr = winapi.Ping(ip, 800*time.Millisecond)
					if pingErr != nil { // segunda tentativa: Wi-Fi em economia de energia costuma perder o primeiro
						pr, pingErr = winapi.Ping(ip, 800*time.Millisecond)
					}
				}()
				go func() { defer inner.Done(); mac, arpErr = winapi.ARP(ip) }()
				inner.Wait()
				s.done.Add(1)

				if pingErr != nil && arpErr != nil {
					continue
				}
				h := &Host{IP: ip.String(), RTTms: -1, FoundBy: []string{}, OpenPorts: []Port{}}
				if pingErr == nil {
					h.RTTms = float64(pr.RTT.Microseconds()) / 1000
					h.TTL = pr.TTL
					h.OSGuess = guessOS(pr.TTL)
					h.FoundBy = append(h.FoundBy, "ICMP")
				}
				if arpErr == nil {
					h.MAC = mac.String()
					h.FoundBy = append(h.FoundBy, "ARP")
				}
				s.found.Add(1)
				mu.Lock()
				found[ip] = h
				mu.Unlock()
			}
		}()
	}
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	return found
}

// identify pergunta por mDNS/Bonjour e UPnP quem é cada dispositivo.
func (s *Scanner) identify(self netip.Addr, hosts map[netip.Addr]*Host) {
	if !self.IsValid() {
		return
	}
	s.setPhase("Identificando dispositivos (mDNS/Bonjour e UPnP)", 1)
	var addrs []netip.Addr
	for ip := range hosts {
		addrs = append(addrs, ip)
	}
	var mdns map[netip.Addr]*MDNSInfo
	var upnp map[netip.Addr]*UPnPInfo
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); mdns = MDNS(self, addrs, 3*time.Second) }()
	go func() { defer wg.Done(); upnp = SSDP(self, addrs, 3*time.Second) }()
	wg.Wait()
	for ip, h := range hosts {
		if m, ok := mdns[ip]; ok {
			h.MDNSName, h.FriendlyName, h.Model, h.Services = m.Hostname, m.Name, m.Model, m.Services
			if strings.HasPrefix(m.Name, "Spotify Desktop") { // nome genérico do app, não do aparelho
				h.FriendlyName = ""
			}
		}
		if u, ok := upnp[ip]; ok {
			h.UPnP = u
			if h.FriendlyName == "" {
				h.FriendlyName = u.FriendlyName
			}
			if h.Model == "" && u.Model != "" {
				h.Model = strings.TrimSpace(u.Manufacturer + " " + u.Model)
			}
		}
	}
	s.done.Add(1)
}

// enrich completa cada host: fabricante, nomes, portas e tipo de dispositivo.
func (s *Scanner) enrich(hosts map[netip.Addr]*Host, scanPorts bool, gateways map[string]bool) {
	phase := "Identificando dispositivos (nomes e fabricantes)"
	if scanPorts {
		phase = "Identificando dispositivos (nomes, fabricantes e portas)"
	}
	s.setPhase(phase, int64(len(hosts)))

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for ip, h := range hosts {
		wg.Add(1)
		go func(ip netip.Addr, h *Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem; s.done.Add(1) }()

			h.IsGateway = gateways[h.IP]
			if h.OpenPorts == nil {
				h.OpenPorts = []Port{}
			}
			if mac, err := net.ParseMAC(h.MAC); err == nil {
				h.Vendor = oui.Lookup(mac)
				h.RandomMAC = oui.IsRandomized(mac)
			}

			var inner sync.WaitGroup
			inner.Add(2)
			go func() {
				defer inner.Done()
				if h.Hostname == "" {
					h.Hostname = ReverseDNS(ip, 2*time.Second)
				}
			}()
			go func() {
				defer inner.Done()
				if nb, ok := NetBIOS(ip, 1200*time.Millisecond); ok {
					h.NetBIOS, h.Workgroup = nb.Name, nb.Workgroup
				}
			}()
			if scanPorts && !h.IsSelf {
				h.OpenPorts = ScanPorts(ip, CommonPorts, 1200*time.Millisecond)
			}
			inner.Wait()
			h.DeviceType = classify(h)
		}(ip, h)
	}
	wg.Wait()
}

func pickInterface(ifaces []netinfo.Interface, index uint32) *netinfo.Interface {
	for i := range ifaces {
		if index != 0 && ifaces[i].Index == index {
			return &ifaces[i]
		}
	}
	for i := range ifaces {
		if ifaces[i].IsPrimary {
			return &ifaces[i]
		}
	}
	for i := range ifaces { // sem gateway: ainda dá para varrer a rede local
		if ifaces[i].Status == "up" && len(ifaces[i].IPv4) > 0 && !ifaces[i].Virtual {
			return &ifaces[i]
		}
	}
	return nil
}

// targetPrefix decide qual faixa varrer, limitando redes muito grandes.
func targetPrefix(iface *netinfo.Interface, cidr string, findings *[]Finding) (netip.Addr, netip.Prefix, error) {
	var self netip.Addr
	for _, a := range iface.IPv4 {
		ip, err := netip.ParseAddr(a.Address)
		if err == nil && !ip.IsLinkLocalUnicast() {
			self = ip
			break
		}
	}
	if cidr != "" {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil || !p.Addr().Is4() {
			return self, netip.Prefix{}, fmt.Errorf("faixa inválida %q (use o formato 192.168.0.0/24)", cidr)
		}
		p = p.Masked()
		if p.Bits() < 20 {
			return self, netip.Prefix{}, fmt.Errorf("faixa %s é grande demais (máximo /20 = %d IPs)", p, MaxHosts)
		}
		return self, p, nil
	}
	if !self.IsValid() {
		return self, netip.Prefix{}, fmt.Errorf("a interface %q não tem IPv4 válido (só APIPA 169.254.x.x?) — o DHCP pode ter falhado", iface.Name)
	}
	bits := 24
	for _, a := range iface.IPv4 {
		if a.Address == self.String() {
			bits = a.PrefixLen
		}
	}
	p, _ := self.Prefix(bits)
	if bits < 20 {
		p, _ = self.Prefix(24)
		*findings = append(*findings, Finding{"aviso", "Rede muito grande",
			fmt.Sprintf("A máscara é /%d; para não demorar, foi varrida apenas a /24 do seu IP (%s). Use o campo de faixa para outra parte da rede.", bits, p)})
	}
	return self, p, nil
}

func hostsIn(p netip.Prefix) []netip.Addr {
	var ips []netip.Addr
	first := p.Addr()
	if p.Bits() >= 31 {
		for ip := first; p.Contains(ip); ip = ip.Next() {
			ips = append(ips, ip)
		}
		return ips
	}
	for ip := first.Next(); p.Contains(ip.Next()); ip = ip.Next() { // pula rede e broadcast
		ips = append(ips, ip)
	}
	return ips
}

func guessOS(ttl uint8) string {
	switch {
	case ttl == 0:
		return ""
	case ttl <= 64:
		return "Linux/Android/iOS/macOS"
	case ttl <= 128:
		return "Windows"
	default:
		return "Equipamento de rede"
	}
}

func hasPort(h *Host, ports ...int) bool {
	for _, op := range h.OpenPorts {
		if slices.Contains(ports, op.Port) {
			return true
		}
	}
	return false
}

// classify sugere o tipo do dispositivo combinando portas, fabricante e TTL.
func classify(h *Host) string {
	v := strings.ToLower(h.Vendor)
	vendorHas := func(ks ...string) bool {
		for _, k := range ks {
			if strings.Contains(v, k) {
				return true
			}
		}
		return false
	}
	svc := strings.Join(h.Services, "|")
	upnpType := ""
	if h.UPnP != nil {
		upnpType = h.UPnP.DeviceType
	}
	switch {
	case h.IsSelf:
		return "Este computador"
	case h.IsGateway:
		return "Roteador / Gateway"
	case h.UPnP != nil && h.UPnP.IGD:
		return "Roteador (segundo roteador na rede)"
	case strings.Contains(svc, "Impressora") || strings.Contains(svc, "Scanner"):
		return "Impressora"
	case strings.Contains(svc, "Google Cast") || strings.Contains(svc, "Android TV") || strings.Contains(svc, "Fire TV") || upnpType == "MediaRenderer":
		return "Smart TV / Chromecast"
	case strings.Contains(svc, "Apple TV") || strings.Contains(svc, "AirPlay"):
		return "Apple TV / AirPlay"
	case strings.Contains(svc, "Dispositivo Apple"):
		return "Apple (iPhone/iPad/Mac)"
	case strings.Contains(svc, "HomeKit") || strings.Contains(svc, "Matter"):
		return "IoT / Casa inteligente"
	case strings.Contains(svc, "Computador") || strings.Contains(svc, "Compartilhamento") ||
		(strings.Contains(svc, "Spotify") && strings.HasPrefix(strings.ToUpper(h.MDNSName), "DESKTOP-")):
		return "Computador"
	case hasPort(h, 8291, 8728) || vendorHas("routerboard", "mikrotik"):
		return "MikroTik"
	case hasPort(h, 9100, 631):
		return "Impressora"
	case hasPort(h, 37777, 554) || vendorHas("hikvision", "dahua", "hangzhou", "uniview"):
		return "Câmera / DVR"
	case hasPort(h, 62078) || vendorHas("apple"):
		return "Apple (iPhone/iPad/Mac)"
	case hasPort(h, 8008, 8009):
		return "Smart TV / Chromecast"
	case hasPort(h, 7547) || vendorHas("fiberhome", "zte", "huawei", "nokia", "parks", "datacom", "furukawa", "sagemcom", "askey", "mitrastar"):
		return "ONU / Roteador do provedor"
	case vendorHas("tp-link", "tenda", "mercusys", "d-link", "ubiquiti", "multilaser", "intelbras", "netgear", "cisco", "aruba", "ruckus", "cambium"):
		return "Roteador / Access Point"
	case hasPort(h, 3389, 445, 135, 5357) || h.NetBIOS != "":
		return "Computador Windows"
	case vendorHas("espressif", "tuya", "shenzhen", "amazon", "google", "xiaomi", "sonoff"):
		return "IoT / Casa inteligente"
	case h.RandomMAC:
		return "Celular / Notebook (MAC aleatório)"
	case vendorHas("samsung", "motorola", "lg electronics", "oppo", "vivo", "realme", "oneplus"):
		return "Celular / Smart TV"
	case h.TTL > 128:
		return "Equipamento de rede"
	}
	return "Desconhecido"
}

// analyze aplica verificações automáticas sobre a configuração e os dispositivos.
func analyze(res *Result) {
	f := &res.Findings
	add := func(level, title, detail string) { *f = append(*f, Finding{level, title, detail}) }
	it := res.Interface

	if len(it.Gateways) == 0 {
		add("critico", "Sem gateway padrão", "A interface não tem gateway configurado: não há saída para outras redes/internet.")
	}
	for _, g := range it.Gateways {
		ip, err := netip.ParseAddr(g)
		if err != nil || !ip.Is4() {
			continue
		}
		var gwHost *Host
		for i := range res.Hosts {
			if res.Hosts[i].IP == g {
				gwHost = &res.Hosts[i]
			}
		}
		if gwHost == nil {
			add("critico", "Gateway não responde", fmt.Sprintf("O gateway %s não respondeu a ping nem a ARP. Verifique cabo, Wi-Fi ou o roteador.", g))
		} else if rtt, lost := medianPing(ip, 5); lost == 5 {
			add("aviso", "Gateway não responde a ping", fmt.Sprintf("O gateway %s responde ARP mas bloqueia ICMP; não foi possível medir a latência.", g))
		} else if rtt > 20 {
			add("aviso", "Latência alta até o gateway", fmt.Sprintf("Mediana de %.1f ms até o gateway %s (o normal na LAN cabeada é < 5 ms). Pode indicar Wi-Fi fraco, interferência ou roteador sobrecarregado.", rtt, g))
		} else if lost > 0 {
			add("aviso", "Perda de pacotes até o gateway", fmt.Sprintf("%d de 5 pings ao gateway %s se perderam.", lost, g))
		}
	}
	if len(it.DNSServers) == 0 {
		add("critico", "Sem servidor DNS", "Nenhum DNS configurado: sites não vão abrir pelo nome.")
	}
	if !it.DHCP.Enabled {
		add("info", "IP fixo (manual)", "Esta interface está com IP configurado manualmente, sem DHCP.")
	} else if gw4 := firstV4(it.Gateways); it.DHCP.Server != "" && gw4 != "" && it.DHCP.Server != gw4 {
		add("info", "DHCP fora do gateway", fmt.Sprintf("O servidor DHCP (%s) não é o gateway (%s). Normal em redes com servidor dedicado; em residências pode indicar um segundo roteador distribuindo IP.", it.DHCP.Server, gw4))
	}
	for _, a := range it.IPv4 {
		if strings.HasPrefix(a.Address, "169.254.") {
			add("critico", "IP APIPA (169.254.x.x)", "O Windows não recebeu IP do DHCP e se autoatribuiu um endereço. Verifique o servidor DHCP / roteador.")
		}
	}
	if len(it.IPv6) > 0 {
		global := false
		for _, a := range it.IPv6 {
			if a.Scope == "global" {
				global = true
			}
		}
		if !global {
			add("info", "IPv6 só link-local", "A interface não recebeu IPv6 global. Se o provedor entrega IPv6, verifique a configuração do roteador (PD/RA).")
		}
	}

	switch {
	case len(res.DHCP) > 1:
		var list []string
		for _, o := range res.DHCP {
			list = append(list, fmt.Sprintf("%s (oferece %s, gateway %s)", o.Server, o.OfferedIP, o.Router))
		}
		add("critico", "Mais de um servidor DHCP na rede", "Responderam: "+strings.Join(list, "; ")+". Normalmente é um roteador do cliente ligado pela porta LAN em vez da WAN, ou uma ONU/roteador com DHCP ativo em modo bridge. Os dispositivos pegam IP de um ou de outro aleatoriamente, causando quedas.")
	case len(res.DHCP) == 1:
		o := res.DHCP[0]
		if gw4 := firstV4(it.Gateways); gw4 != "" && o.Router != "" && o.Router != gw4 {
			add("aviso", "DHCP entrega outro gateway", fmt.Sprintf("O servidor DHCP %s entrega o gateway %s, mas esta máquina está usando %s.", o.Server, o.Router, gw4))
		}
	case res.DHCPError == "" && it.DHCP.Enabled:
		add("info", "Nenhum servidor DHCP respondeu ao teste", "O teste de DHCP não recebeu ofertas (o servidor pode filtrar MACs desconhecidos). Não indica problema por si só.")
	}
	for _, h := range res.Hosts {
		if h.UPnP != nil && h.UPnP.IGD {
			if h.IsGateway {
				add("info", "UPnP ativo no roteador", "O roteador permite que aplicativos abram portas automaticamente (UPnP). Facilita jogos e câmeras, mas um dispositivo infectado também pode se expor. Desative se não for necessário.")
			} else {
				add("aviso", "Outro roteador na rede", fmt.Sprintf("%s (%s) se anuncia como roteador (UPnP IGD). Pode ser um roteador do cliente em cascata ou mal configurado.", h.IP, h.FriendlyName))
			}
		}
	}

	// Duplicidade: o mesmo MAC respondendo por vários IPs (pode ser repetidor, ponte ou ARP spoofing).
	byMAC := map[string][]string{}
	for _, h := range res.Hosts {
		if h.MAC != "" {
			byMAC[h.MAC] = append(byMAC[h.MAC], h.IP)
		}
	}
	for mac, ips := range byMAC {
		if len(ips) > 1 {
			add("aviso", "MAC respondendo por vários IPs", fmt.Sprintf("O MAC %s aparece em %s. Comum em repetidores/extensores Wi-Fi; se não houver um, pode indicar ARP spoofing.", mac, strings.Join(ips, ", ")))
		}
	}

	risky := map[int]string{23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB"}
	for _, h := range res.Hosts {
		for _, p := range h.OpenPorts {
			if name, ok := risky[p.Port]; ok {
				add("aviso", fmt.Sprintf("%s aberto em %s", name, h.IP),
					fmt.Sprintf("O dispositivo %s (%s) tem a porta %d (%s) aberta na rede local.", h.IP, h.DeviceType, p.Port, name))
			}
		}
	}

	if res.Internet != nil {
		lvl := "info"
		if !res.Internet.Online || !res.Internet.DNSWorks {
			lvl = "critico"
		}
		add(lvl, "Internet", res.Internet.Message)
	}

	rand := 0
	for _, h := range res.Hosts {
		if h.RandomMAC {
			rand++
		}
	}
	if rand > 0 {
		add("info", "Dispositivos com MAC aleatório", fmt.Sprintf("%d dispositivo(s) usam MAC aleatório (privacidade do Android/iOS/Windows). O fabricante não pode ser identificado por eles.", rand))
	}
}

func firstV4(addrs []string) string {
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
			return a
		}
	}
	return ""
}

// medianPing mede a latência com várias amostras para não alarmar por um pico isolado.
func medianPing(ip netip.Addr, n int) (ms float64, lost int) {
	var rtts []float64
	for i := 0; i < n; i++ {
		if r, err := winapi.Ping(ip, time.Second); err == nil {
			rtts = append(rtts, float64(r.RTT.Microseconds())/1000)
		} else {
			lost++
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(rtts) == 0 {
		return 0, lost
	}
	slices.Sort(rtts)
	return rtts[len(rtts)/2], lost
}
