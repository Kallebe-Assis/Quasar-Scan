package diag

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"quasarscan/internal/netinfo"
	"quasarscan/internal/winapi"
)

// PingReply é uma linha do ping, como no CMD.
type PingReply struct {
	Seq    int     `json:"seq"`
	OK     bool    `json:"ok"`
	From   string  `json:"from,omitempty"`
	RTTms  float64 `json:"rttMs"`
	TTL    uint8   `json:"ttl,omitempty"`
	Bytes  int     `json:"bytes"`
	Status string  `json:"status"`
}

// PingStats é o resumo acumulado do ping, já classificado.
type PingStats struct {
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
	LossPct   float64 `json:"lossPct"`
	MinMs     float64 `json:"minMs"`
	AvgMs     float64 `json:"avgMs"`
	MaxMs     float64 `json:"maxMs"`
	MedianMs  float64 `json:"medianMs"`
	JitterMs  float64 `json:"jitterMs"`
	Scale     string  `json:"scale"` // latencia ou latencia-lan
	Latency   Level   `json:"latency"`
	JitterLvl Level   `json:"jitterLevel"`
	LossLvl   Level   `json:"lossLevel"`
	Overall   Level   `json:"overall"`
}

// NewStats calcula o resumo a partir dos tempos (ms) das respostas recebidas.
// O jitter é a média da diferença absoluta entre pings consecutivos.
// Com wifi=true a latência é avaliada pelas faixas do Wi-Fi (o dobro das do cabo).
func NewStats(rtts []float64, sent int, lan, wifi bool) PingStats {
	latScale := latencyScale(lan, wifi)
	st := PingStats{Sent: sent, Received: len(rtts), Scale: latScale.ID}
	if sent > 0 {
		st.LossPct = math.Round(float64(sent-len(rtts))/float64(sent)*1000) / 10
	}
	st.LossLvl = Loss.Rate(st.LossPct)
	if len(rtts) == 0 {
		st.Latency, st.JitterLvl, st.Overall = Pessimo, Pessimo, Pessimo
		return st
	}
	sorted := slices.Clone(rtts)
	slices.Sort(sorted)
	st.MinMs, st.MaxMs = sorted[0], sorted[len(sorted)-1]
	st.MedianMs = sorted[len(sorted)/2]
	sum := 0.0
	for _, v := range rtts {
		sum += v
	}
	st.AvgMs = round1(sum / float64(len(rtts)))
	if len(rtts) > 1 {
		d := 0.0
		for i := 1; i < len(rtts); i++ {
			d += math.Abs(rtts[i] - rtts[i-1])
		}
		st.JitterMs = round1(d / float64(len(rtts)-1))
	}
	st.Latency = latScale.Rate(st.AvgMs)
	st.JitterLvl = Jitter.Rate(st.JitterMs)
	st.Overall = Worst(st.Latency, st.JitterLvl, st.LossLvl)
	return st
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Resolve aceita IP ou nome e devolve o endereço a usar. Para nomes, family "6"
// pede IPv6; qualquer outro valor usa IPv4.
func Resolve(ctx context.Context, host, family string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ip.Unmap(), nil
	}
	network, label := "ip4", "IPv4"
	if family == "6" {
		network, label = "ip6", "IPv6"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("não foi possível encontrar um endereço %s para %q (verifique o nome ou o DNS)", label, host)
	}
	return ips[0].Unmap(), nil
}

// IsLocal indica se o IP está numa das redes diretamente conectadas, para
// usar a escala de latência de rede local.
func IsLocal(ip netip.Addr) bool {
	ifaces, err := netinfo.Interfaces()
	if err != nil {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return true
	}
	for _, it := range ifaces {
		for _, a := range append(slices.Clone(it.IPv4), it.IPv6...) {
			if p, err := netip.ParsePrefix(a.Network); err == nil && p.Bits() > 0 && p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// PingOptions são os parâmetros do ping (count 0 = contínuo, como "ping -t").
type PingOptions struct {
	Count    int
	Size     int
	Interval time.Duration
	Timeout  time.Duration
	WiFi     bool // classifica a latência com as faixas do Wi-Fi
}

// Ping executa o ping e chama onReply a cada resposta, com o resumo atualizado.
func Ping(ctx context.Context, ip netip.Addr, opt PingOptions, onReply func(PingReply, PingStats)) PingStats {
	lan := IsLocal(ip)
	var rtts []float64
	var st PingStats
	for seq := 1; opt.Count == 0 || seq <= opt.Count; seq++ {
		start := time.Now()
		r, err := winapi.Echo(ip, winapi.EchoOptions{Size: opt.Size, Timeout: opt.Timeout})
		rep := PingReply{Seq: seq, Bytes: opt.Size}
		if err == nil && r.Status == winapi.StatusSuccess {
			rep.OK, rep.From, rep.TTL = true, r.From.String(), r.TTL
			rep.RTTms = float64(r.RTT.Microseconds()) / 1000
			rep.Status = "Resposta"
			rtts = append(rtts, rep.RTTms)
		} else {
			rep.Status = winapi.StatusText(r.Status)
			if r.From.IsValid() && !r.From.IsUnspecified() {
				rep.From = r.From.String()
			}
		}
		st = NewStats(rtts, seq, lan, opt.WiFi)
		onReply(rep, st)

		if opt.Count != 0 && seq == opt.Count {
			break
		}
		select {
		case <-ctx.Done():
			return st
		case <-time.After(opt.Interval - time.Since(start)):
		}
	}
	return st
}
