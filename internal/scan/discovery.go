package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// multicastConn abre um socket UDP no IP local e força o multicast a sair pela
// placa desse IP (o Windows costuma mandar pela placa virtual do Hyper-V/WSL).
func multicastConn(local netip.Addr) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		return nil, err
	}
	if ifi := interfaceFor(local); ifi != nil {
		pc := ipv4.NewPacketConn(conn)
		pc.SetMulticastInterface(ifi)
		pc.SetMulticastTTL(255)
	}
	return conn, nil
}

// sendAll envia ao grupo multicast (duas vezes: Wi-Fi perde multicast) e em unicast a cada host.
func sendAll(conn *net.UDPConn, msg []byte, hosts []netip.Addr, port int, group *net.UDPAddr, wait time.Duration) {
	conn.WriteToUDP(msg, group)
	for _, h := range hosts {
		conn.WriteToUDP(msg, net.UDPAddrFromAddrPort(netip.AddrPortFrom(h, uint16(port))))
	}
	time.AfterFunc(wait/2, func() { conn.WriteToUDP(msg, group) })
}

func interfaceFor(local netip.Addr) *net.Interface {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == local {
					return &ifaces[i]
				}
			}
		}
	}
	return nil
}

// MDNSInfo é o que um dispositivo anunciou via mDNS/Bonjour.
type MDNSInfo struct {
	Hostname string   // nome.local
	Name     string   // nome amigável (ex.: "TV da Sala")
	Model    string   // modelo informado no TXT (md=, model=, am=)
	Services []string // serviços em português
}

// serviceNames traduz os tipos de serviço mais comuns.
var serviceNames = map[string]string{
	"_googlecast._tcp":       "Google Cast (Chromecast/TV)",
	"_airplay._tcp":          "AirPlay",
	"_raop._tcp":             "AirPlay (áudio)",
	"_ipp._tcp":              "Impressora (IPP)",
	"_ipps._tcp":             "Impressora (IPPS)",
	"_printer._tcp":          "Impressora (LPD)",
	"_pdl-datastream._tcp":   "Impressora (RAW)",
	"_scanner._tcp":          "Scanner",
	"_uscan._tcp":            "Scanner",
	"_hap._tcp":              "Apple HomeKit",
	"_spotify-connect._tcp":  "Spotify Connect",
	"_companion-link._tcp":   "Dispositivo Apple",
	"_sleep-proxy._udp":      "Apple TV/HomePod",
	"_workstation._tcp":      "Computador",
	"_smb._tcp":              "Compartilhamento de arquivos",
	"_afpovertcp._tcp":       "Compartilhamento Apple",
	"_http._tcp":             "Página web",
	"_androidtvremote2._tcp": "Android TV",
	"_amzn-wplay._tcp":       "Fire TV / Alexa",
	"_matter._tcp":           "Casa inteligente (Matter)",
	"_ssh._tcp":              "SSH",
	"_rfb._tcp":              "Acesso remoto (VNC)",
}

// MDNS consulta os serviços anunciados na rede (a partir do IP local "local").
// Pergunta no grupo multicast e também direto a cada host já descoberto: o firewall
// do Windows (perfil Público) costuma barrar respostas ao multicast, mas aceita a
// resposta de quem recebeu a pergunta. Não ocupa a porta 5353, que é do Windows.
func MDNS(local netip.Addr, hosts []netip.Addr, wait time.Duration) map[netip.Addr]*MDNSInfo {
	out := map[netip.Addr]*MDNSInfo{}
	conn, err := multicastConn(local)
	if err != nil {
		return out
	}
	defer conn.Close()

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.StartQuestions()
	types := append([]string{"_services._dns-sd._udp"}, mapKeys(serviceNames)...)
	for _, t := range types {
		name, _ := dnsmessage.NewName(t + ".local.")
		b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET | 0x8000})
	}
	msg, err := b.Finish()
	if err != nil {
		return out
	}
	sendAll(conn, msg, hosts, 5353, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}, wait)

	// Registros soltos para cruzar no final: instância -> host, host -> IP, instância -> TXT.
	instHost := map[string]string{}
	hostIP := map[string]netip.Addr{}
	instTXT := map[string][]string{}
	instSvc := map[string]string{}
	srcOf := map[string]netip.Addr{}

	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 9000)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		src := from.Addr().Unmap()
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil {
			continue
		}
		for _, rr := range append(m.Answers, m.Additionals...) {
			name := strings.TrimSuffix(rr.Header.Name.String(), ".")
			switch r := rr.Body.(type) {
			case *dnsmessage.AResource:
				hostIP[name] = netip.AddrFrom4(r.A)
			case *dnsmessage.PTRResource:
				if svc := strings.TrimSuffix(name, ".local"); svc != "_services._dns-sd._udp" {
					inst := strings.TrimSuffix(r.PTR.String(), ".")
					instSvc[inst] = svc
					srcOf[inst] = src
				}
			case *dnsmessage.SRVResource:
				instHost[name] = strings.TrimSuffix(r.Target.String(), ".")
			case *dnsmessage.TXTResource:
				instTXT[name] = r.TXT
			}
		}
	}

	get := func(ip netip.Addr) *MDNSInfo {
		if i, ok := out[ip]; ok {
			return i
		}
		i := &MDNSInfo{}
		out[ip] = i
		return i
	}
	for host, ip := range hostIP {
		get(ip).Hostname = strings.TrimSuffix(strings.TrimSuffix(host, "."), ".local")
	}
	for inst, svc := range instSvc {
		ip, ok := hostIP[instHost[inst]]
		if !ok {
			ip, ok = srcOf[inst]
		}
		if !ok {
			continue
		}
		info := get(ip)
		if label := serviceNames[svc]; label != "" && !slices.Contains(info.Services, label) {
			info.Services = append(info.Services, label)
		}
		friendly := strings.SplitN(inst, "._", 2)[0]
		for _, kv := range instTXT[inst] {
			k, v, _ := strings.Cut(kv, "=")
			switch strings.ToLower(k) {
			case "fn":
				friendly = v
			case "md", "model", "am", "ty", "usb_mdl":
				if info.Model == "" {
					info.Model = v
				}
			}
		}
		if info.Name == "" && friendly != "" && !looksLikeID(friendly) {
			info.Name = unescape(friendly)
		}
	}
	return out
}

// looksLikeID descarta nomes que são só identificadores (ex.: "Chromecast-3f2a9c...").
func looksLikeID(s string) bool {
	hex := 0
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-' {
			hex++
		}
	}
	return len(s) >= 24 && hex*10 >= len(s)*9
}

func unescape(s string) string { return strings.ReplaceAll(s, `\032`, " ") }

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// UPnPInfo descreve um dispositivo encontrado via SSDP/UPnP.
type UPnPInfo struct {
	FriendlyName string `json:"friendlyName,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	DeviceType   string `json:"deviceType,omitempty"`
	Server       string `json:"server,omitempty"`
	IGD          bool   `json:"igd"` // roteador com UPnP de abertura de portas ativo
}

// SSDP procura dispositivos UPnP (TVs, roteadores, NAS, consoles) e lê a descrição de cada um.
// Como no mDNS, pergunta no multicast e direto a cada host conhecido.
func SSDP(local netip.Addr, hosts []netip.Addr, wait time.Duration) map[netip.Addr]*UPnPInfo {
	out := map[netip.Addr]*UPnPInfo{}
	conn, err := multicastConn(local)
	if err != nil {
		return out
	}
	defer conn.Close()
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
	sendAll(conn, []byte(req), hosts, 1900, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}, wait)

	locations := map[netip.Addr]map[string]bool{}
	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		ip := from.Addr().Unmap()
		info, ok := out[ip]
		if !ok {
			info = &UPnPInfo{}
			out[ip] = info
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "LOCATION":
				if locations[ip] == nil {
					locations[ip] = map[string]bool{}
				}
				locations[ip][v] = true
			case "SERVER":
				info.Server = v
			case "ST", "NT":
				if strings.Contains(v, "InternetGatewayDevice") || strings.Contains(v, "WANIPConnection") || strings.Contains(v, "WANPPPConnection") {
					info.IGD = true
				}
			}
		}
	}

	// Lê a descrição XML de cada dispositivo (só da própria rede local).
	client := &http.Client{Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for ip, locs := range locations {
		for loc := range locs {
			wg.Add(1)
			go func(ip netip.Addr, loc string) {
				defer wg.Done()
				d, err := fetchDescription(client, ip, loc)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				info := out[ip]
				if info.FriendlyName == "" || strings.Contains(d.Device.DeviceType, "InternetGatewayDevice") {
					info.FriendlyName = strings.TrimSpace(d.Device.FriendlyName)
					info.Manufacturer = strings.TrimSpace(d.Device.Manufacturer)
					info.Model = strings.TrimSpace(strings.TrimSpace(d.Device.ModelName + " " + d.Device.ModelNumber))
					info.DeviceType = shortDeviceType(d.Device.DeviceType)
				}
				if strings.Contains(d.Device.DeviceType, "InternetGatewayDevice") {
					info.IGD = true
				}
			}(ip, loc)
		}
	}
	wg.Wait()
	return out
}

type upnpDescription struct {
	Device struct {
		DeviceType   string `xml:"deviceType"`
		FriendlyName string `xml:"friendlyName"`
		Manufacturer string `xml:"manufacturer"`
		ModelName    string `xml:"modelName"`
		ModelNumber  string `xml:"modelNumber"`
	} `xml:"device"`
}

func fetchDescription(client *http.Client, ip netip.Addr, loc string) (*upnpDescription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
	if err != nil {
		return nil, err
	}
	// Só segue a URL se ela apontar para o próprio dispositivo que respondeu.
	if h, _, _ := net.SplitHostPort(req.URL.Host); h != ip.String() {
		return nil, fmt.Errorf("LOCATION aponta para outro host")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d upnpDescription
	if err := xml.NewDecoder(http.MaxBytesReader(nil, resp.Body, 512<<10)).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// shortDeviceType: "urn:schemas-upnp-org:device:MediaRenderer:1" -> "MediaRenderer".
func shortDeviceType(t string) string {
	parts := strings.Split(t, ":")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return t
}
