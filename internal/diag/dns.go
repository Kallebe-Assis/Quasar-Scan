package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"quasarscan/internal/netinfo"
)

// DNSServer é uma opção de servidor DNS para consulta/comparação.
type DNSServer struct {
	Label string `json:"label"`
	IP    string `json:"ip"`
	Local bool   `json:"local"` // configurado nesta máquina
}

// PublicDNS são os servidores públicos usados como referência.
var PublicDNS = []DNSServer{
	{Label: "Cloudflare", IP: "1.1.1.1"},
	{Label: "Google", IP: "8.8.8.8"},
	{Label: "Quad9", IP: "9.9.9.9"},
}

// SystemDNS lista os DNS IPv4 configurados na interface principal.
func SystemDNS() []DNSServer {
	ifaces, _ := netinfo.Interfaces()
	var out []DNSServer
	seen := map[string]bool{}
	for _, it := range ifaces {
		if !it.IsPrimary {
			continue
		}
		for _, d := range it.DNSServers {
			ip, err := netip.ParseAddr(d)
			if err != nil || !ip.Is4() || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, DNSServer{Label: "Configurado (" + it.Name + ")", IP: d, Local: true})
		}
	}
	return out
}

// resolverFor consulta diretamente o servidor informado, como o nslookup faz
// (sem passar pelo cache DNS do Windows).
func resolverFor(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// DNSResult é a resposta de uma consulta (equivale ao nslookup).
type DNSResult struct {
	Server  string   `json:"server"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Answers []string `json:"answers"`
	TimeMs  float64  `json:"timeMs"`
	Level   Level    `json:"level"`
	Error   string   `json:"error,omitempty"`
}

// DNSTypes são os tipos de registro suportados na consulta.
var DNSTypes = []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR"}

// Lookup consulta um registro DNS num servidor específico.
func Lookup(ctx context.Context, server, name, qtype string) DNSResult {
	res := DNSResult{Server: server, Name: name, Type: strings.ToUpper(qtype), Answers: []string{}}
	r := resolverFor(server)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fqdn := strings.TrimSuffix(name, ".") + "."

	start := time.Now()
	var err error
	switch res.Type {
	case "A", "AAAA":
		network := "ip4"
		if res.Type == "AAAA" {
			network = "ip6"
		}
		var ips []netip.Addr
		ips, err = r.LookupNetIP(ctx, network, fqdn)
		for _, ip := range ips {
			res.Answers = append(res.Answers, ip.Unmap().String())
		}
	case "MX":
		var mx []*net.MX
		mx, err = r.LookupMX(ctx, fqdn)
		for _, m := range mx {
			res.Answers = append(res.Answers, fmt.Sprintf("%s (prioridade %d)", strings.TrimSuffix(m.Host, "."), m.Pref))
		}
	case "TXT":
		res.Answers, err = r.LookupTXT(ctx, fqdn)
	case "NS":
		var ns []*net.NS
		ns, err = r.LookupNS(ctx, fqdn)
		for _, n := range ns {
			res.Answers = append(res.Answers, strings.TrimSuffix(n.Host, "."))
		}
	case "CNAME":
		var c string
		c, err = r.LookupCNAME(ctx, fqdn)
		if c != "" {
			res.Answers = append(res.Answers, strings.TrimSuffix(c, "."))
		}
	case "PTR":
		var names []string
		names, err = r.LookupAddr(ctx, strings.TrimSuffix(name, "."))
		for _, n := range names {
			res.Answers = append(res.Answers, strings.TrimSuffix(n, "."))
		}
	default:
		err = fmt.Errorf("tipo de registro não suportado")
	}
	res.TimeMs = round1(float64(time.Since(start).Microseconds()) / 1000)
	res.Level = DNSTime.Rate(res.TimeMs)
	if err != nil {
		res.Error = dnsError(err)
		res.Level = Pessimo
	}
	return res
}

func dnsError(err error) string {
	var de *net.DNSError
	errors.As(err, &de)
	switch {
	case de != nil && de.IsNotFound:
		return "Nome não existe (NXDOMAIN) ou sem registro deste tipo"
	case de != nil && de.IsTimeout:
		return "Servidor DNS não respondeu (tempo esgotado)"
	}
	return err.Error()
}

// BenchDomains são consultados para comparar a velocidade dos servidores DNS.
var BenchDomains = []string{"google.com", "youtube.com", "facebook.com", "instagram.com",
	"whatsapp.net", "netflix.com", "microsoft.com", "globo.com"}

// DNSBench é o resultado da comparação de um servidor.
type DNSBench struct {
	DNSServer
	MedianMs float64 `json:"medianMs"`
	Failures int     `json:"failures"`
	Level    Level   `json:"level"`
}

// BenchmarkDNS mede a mediana de resposta de cada servidor sobre BenchDomains.
func BenchmarkDNS(ctx context.Context, servers []DNSServer) []DNSBench {
	out := make([]DNSBench, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s DNSServer) {
			defer wg.Done()
			var times []float64
			fails := 0
			for _, d := range BenchDomains {
				r := Lookup(ctx, s.IP, d, "A")
				if r.Error != "" {
					fails++
					continue
				}
				times = append(times, r.TimeMs)
			}
			b := DNSBench{DNSServer: s, Failures: fails, MedianMs: -1, Level: Pessimo}
			if len(times) > 0 {
				slices.Sort(times)
				b.MedianMs = times[len(times)/2]
				b.Level = DNSTime.Rate(b.MedianMs)
			}
			out[i] = b
		}(i, s)
	}
	wg.Wait()
	return out
}
