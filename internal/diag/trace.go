package diag

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"quasarscan/internal/scan"
	"quasarscan/internal/winapi"
)

// Hop é um salto do traceroute. RTTs com -1 são sondas sem resposta ("*").
type Hop struct {
	TTL     int       `json:"ttl"`
	IP      string    `json:"ip,omitempty"`
	Name    string    `json:"name,omitempty"`
	RTTs    []float64 `json:"rtts"`
	BestMs  float64   `json:"bestMs"` // -1 se nenhuma sonda respondeu
	Kind    string    `json:"kind"`   // privado, cgnat, publico
	Reached bool      `json:"reached"`
}

var (
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	privatePrefix = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
)

func addrKind(ip netip.Addr) string {
	if ip.Is6() {
		if ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			return "privado"
		}
		return "publico"
	}
	if cgnatPrefix.Contains(ip) {
		return "cgnat"
	}
	for _, p := range privatePrefix {
		if p.Contains(ip) {
			return "privado"
		}
	}
	return "publico"
}

// Traceroute sonda todos os TTLs em paralelo (bem mais rápido que o tracert,
// que vai um por um) e entrega os saltos em ordem por onHop, até o destino.
func Traceroute(ctx context.Context, target netip.Addr, maxHops int, resolveNames bool, onHop func(Hop)) []Hop {
	const probes = 3
	hops := make([]*Hop, maxHops+1)
	ready := make([]chan struct{}, maxHops+1)
	for i := range ready {
		ready[i] = make(chan struct{})
	}

	var wg sync.WaitGroup
	for ttl := 1; ttl <= maxHops; ttl++ {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			defer close(ready[ttl])
			h := &Hop{TTL: ttl, BestMs: -1, RTTs: []float64{}}
			for p := 0; p < probes && ctx.Err() == nil; p++ {
				r, err := winapi.Echo(target, winapi.EchoOptions{TTL: uint8(ttl), Timeout: 1500 * time.Millisecond})
				if err != nil || !r.From.IsValid() || r.From.IsUnspecified() {
					h.RTTs = append(h.RTTs, -1)
					continue
				}
				ms := float64(r.RTT.Microseconds()) / 1000
				h.RTTs = append(h.RTTs, ms)
				if h.BestMs < 0 || ms < h.BestMs {
					h.BestMs = ms
				}
				h.IP = r.From.String()
				h.Reached = r.Status == winapi.StatusSuccess && r.From == target
			}
			if h.IP != "" {
				ip := netip.MustParseAddr(h.IP)
				h.Kind = addrKind(ip)
				if resolveNames {
					h.Name = scan.ReverseDNS(ip, 1500*time.Millisecond)
				}
			}
			hops[ttl] = h
		}(ttl)
	}

	var result []Hop
	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ready[ttl]:
		case <-ctx.Done():
			return result
		}
		h := *hops[ttl]
		result = append(result, h)
		if onHop != nil {
			onHop(h)
		}
		if h.Reached {
			break
		}
	}
	go wg.Wait() // sondas de TTL acima do destino terminam sozinhas
	return result
}

// TraceFinding é uma conclusão tirada do traceroute.
type TraceFinding struct {
	Level  string `json:"level"` // info, aviso, critico
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// AnalyzeTrace procura duplo NAT, CGNAT e o ponto onde a latência sobe.
func AnalyzeTrace(hops []Hop, gateway string) []TraceFinding {
	var out []TraceFinding
	add := func(l, t, d string) { out = append(out, TraceFinding{l, t, d}) }
	if len(hops) == 0 {
		return out
	}

	responsive := slices.DeleteFunc(slices.Clone(hops), func(h Hop) bool { return h.IP == "" })
	if len(responsive) == 0 {
		add("critico", "Nenhum salto respondeu", "Nem o roteador respondeu ao traceroute. Verifique a conexão local.")
		return out
	}
	if gateway != "" && hops[0].IP != "" && hops[0].IP != gateway {
		add("aviso", "Primeiro salto não é o gateway", fmt.Sprintf("O primeiro salto foi %s, mas o gateway configurado é %s. Pode haver outro roteador/proxy no caminho.", hops[0].IP, gateway))
	}

	// Endereço privado logo após o gateway = outro roteador fazendo NAT (duplo NAT).
	if len(hops) > 1 && hops[1].Kind == "privado" {
		add("aviso", "Provável duplo NAT",
			fmt.Sprintf("Depois do roteador há outro endereço privado (%s). Normalmente é a ONU/modem em modo roteador com outro roteador atrás — isso causa duplo NAT (problemas em jogos, câmeras, VPN e redirecionamento de portas). Se não for intencional, coloque a ONU em bridge ou o roteador em modo AP.", hops[1].IP))
	}
	// Até 2 saltos CGNAT é o normal de um provedor com CGNAT; 3 ou mais indica NAT em cascata.
	var cgnat []string
	for _, h := range hops {
		if h.Kind == "cgnat" {
			cgnat = append(cgnat, fmt.Sprintf("%d (%s)", h.TTL, h.IP))
		}
	}
	switch {
	case len(cgnat) >= 3:
		add("aviso", fmt.Sprintf("%d saltos em CGNAT", len(cgnat)),
			fmt.Sprintf("A rota passa por %d saltos na faixa 100.64.0.0/10: %s. Pode indicar NAT em cascata no provedor, o que soma latência e dificulta jogos, VPN e acesso remoto. Não é possível abrir portas sem IP público ou IPv6.", len(cgnat), strings.Join(cgnat, ", ")))
	case len(cgnat) > 0:
		add("info", "Conexão em CGNAT",
			fmt.Sprintf("Saltos na faixa 100.64.0.0/10: %s. Normal em provedor com CGNAT; só impede abrir portas (câmeras, servidores, acesso remoto) sem IP público ou IPv6.", strings.Join(cgnat, ", ")))
	}

	// Ponto em que a latência dá um salto e se mantém nos saltos seguintes.
	prev := -1.0
	for i, h := range hops {
		if h.BestMs < 0 {
			continue
		}
		if prev >= 0 && h.BestMs-prev >= 30 && staysHigh(hops[i+1:], h.BestMs-15) {
			add("aviso", fmt.Sprintf("Latência sobe no salto %d", h.TTL),
				fmt.Sprintf("De %.0f ms para %.0f ms em %s — a partir deste ponto a rota fica mais lenta.", prev, h.BestMs, h.IP))
			break
		}
		prev = h.BestMs
	}
	if hops[0].BestMs > 10 {
		add("aviso", "Demora já no primeiro salto", fmt.Sprintf("O roteador local levou %.0f ms para responder. Problema dentro da casa/empresa: Wi-Fi fraco, interferência ou roteador sobrecarregado.", hops[0].BestMs))
	}
	if !hops[len(hops)-1].Reached {
		add("info", "Destino não alcançado", "O destino não respondeu dentro do limite de saltos. Pode ser firewall no destino; saltos com * isolados são normais (muitos roteadores não respondem ao traceroute).")
	}
	return out
}

func staysHigh(rest []Hop, min float64) bool {
	for _, h := range rest {
		if h.BestMs >= 0 {
			return h.BestMs >= min
		}
	}
	return true
}
