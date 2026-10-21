package diag

import (
	"fmt"
	"math"
	"slices"

	"quasarscan/internal/winapi"
)

// ChannelUse resume quantas redes ocupam (ou interferem em) um canal.
type ChannelUse struct {
	Channel   int     `json:"channel"`
	BandGHz   float64 `json:"bandGHz"`
	Networks  int     `json:"networks"`  // redes no próprio canal
	Interfere float64 `json:"interfere"` // peso de interferência (inclui canais sobrepostos em 2.4)
	Strongest int     `json:"strongest"` // RSSI da rede mais forte no canal
}

// SSIDGroup agrupa os pontos de acesso de uma mesma rede.
type SSIDGroup struct {
	SSID      string               `json:"ssid"`
	Bands     []float64            `json:"bands"`
	BestRSSI  int                  `json:"bestRssi"`
	APs       []winapi.WifiNetwork `json:"aps"`
	Connected bool                 `json:"connected"`
}

// WifiReport é a análise completa de uma placa Wi-Fi.
type WifiReport struct {
	Interface   string                 `json:"interface"`
	Connection  *winapi.WifiConnection `json:"connection,omitempty"`
	SignalLevel Level                  `json:"signalLevel,omitempty"`
	Networks    []SSIDGroup            `json:"networks"`
	Channels    []ChannelUse           `json:"channels"`
	Best24      int                    `json:"best24,omitempty"`
	Best5       int                    `json:"best5,omitempty"`
	ScanError   string                 `json:"scanError,omitempty"`
	Findings    []TraceFinding         `json:"findings"`
}

// AnalyzeWifi transforma a varredura em diagnóstico (sinal, canal, banda, segurança).
func AnalyzeWifi(ifaces []winapi.WifiInterface, planMbps int) []WifiReport {
	var out []WifiReport
	for _, wi := range ifaces {
		rep := WifiReport{Interface: wi.Name, Connection: wi.Connection, ScanError: wi.ScanError,
			Networks: groupSSIDs(wi.Networks), Channels: channelUse(wi.Networks), Findings: []TraceFinding{}}
		rep.Best24 = bestChannel(rep.Channels, 2.4, []int{1, 6, 11})
		rep.Best5 = bestChannel(rep.Channels, 5, []int{36, 40, 44, 48, 149, 153, 157, 161})
		wifiFindings(&rep, wi.Networks, planMbps)
		out = append(out, rep)
	}
	return out
}

func groupSSIDs(nets []winapi.WifiNetwork) []SSIDGroup {
	bySSID := map[string]*SSIDGroup{}
	var order []string
	for _, n := range nets {
		name := n.SSID
		if name == "" {
			name = "(rede oculta)"
		}
		g, ok := bySSID[name]
		if !ok {
			g = &SSIDGroup{SSID: name, BestRSSI: -200}
			bySSID[name] = g
			order = append(order, name)
		}
		g.APs = append(g.APs, n)
		g.BestRSSI = max(g.BestRSSI, n.RSSI)
		if !slices.Contains(g.Bands, n.BandGHz) && n.BandGHz > 0 {
			g.Bands = append(g.Bands, n.BandGHz)
		}
		g.Connected = g.Connected || n.Connected
	}
	out := make([]SSIDGroup, 0, len(order))
	for _, k := range order {
		g := bySSID[k]
		slices.Sort(g.Bands)
		slices.SortFunc(g.APs, func(a, b winapi.WifiNetwork) int { return b.RSSI - a.RSSI })
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b SSIDGroup) int {
		if a.Connected != b.Connected {
			if a.Connected {
				return -1
			}
			return 1
		}
		return b.BestRSSI - a.BestRSSI
	})
	return out
}

// channelUse conta redes por canal. Em 2.4 GHz canais a menos de 5 de distância
// se sobrepõem; redes mais fortes pesam mais na interferência.
func channelUse(nets []winapi.WifiNetwork) []ChannelUse {
	byCh := map[int]*ChannelUse{}
	add := func(ch int, band float64) *ChannelUse {
		if c, ok := byCh[ch]; ok {
			return c
		}
		c := &ChannelUse{Channel: ch, BandGHz: band, Strongest: -200}
		byCh[ch] = c
		return c
	}
	for _, ch := range []int{1, 6, 11} {
		add(ch, 2.4)
	}
	for _, n := range nets {
		if n.Channel == 0 || n.RSSI < -85 {
			continue
		}
		c := add(n.Channel, n.BandGHz)
		c.Networks++
		c.Strongest = max(c.Strongest, n.RSSI)
	}
	for _, c := range byCh {
		for _, n := range nets {
			if n.Channel == 0 || n.BandGHz != c.BandGHz || n.RSSI < -85 {
				continue
			}
			overlap := n.Channel == c.Channel || (c.BandGHz == 2.4 && abs(n.Channel-c.Channel) < 5)
			if overlap {
				c.Interfere += math.Pow(10, float64(n.RSSI+90)/20) // -50 dBm pesa 100, -70 pesa 10
			}
		}
		c.Interfere = math.Round(c.Interfere*10) / 10
	}
	out := make([]ChannelUse, 0, len(byCh))
	for _, c := range byCh {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b ChannelUse) int {
		if a.BandGHz != b.BandGHz {
			return int(a.BandGHz*10 - b.BandGHz*10)
		}
		return a.Channel - b.Channel
	})
	return out
}

func bestChannel(chs []ChannelUse, band float64, candidates []int) int {
	best, bestScore := 0, math.MaxFloat64
	for _, cand := range candidates {
		score := 0.0
		for _, c := range chs {
			if c.BandGHz == band && c.Channel == cand {
				score = c.Interfere
			}
		}
		if score < bestScore {
			best, bestScore = cand, score
		}
	}
	return best
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func wifiFindings(rep *WifiReport, nets []winapi.WifiNetwork, planMbps int) {
	add := func(l, t, d string) { rep.Findings = append(rep.Findings, TraceFinding{l, t, d}) }
	c := rep.Connection
	if c == nil {
		if rep.ScanError == "" {
			add("info", "Wi-Fi não conectado", "Esta placa Wi-Fi não está conectada a nenhuma rede.")
		}
		return
	}
	rep.SignalLevel = WifiSignal.Rate(float64(c.RSSI))
	switch rep.SignalLevel {
	case Ruim:
		add("aviso", "Sinal fraco", fmt.Sprintf("Sinal de %d dBm: a velocidade cai e podem ocorrer quedas. Aproxime-se do roteador ou instale um repetidor/mesh.", c.RSSI))
	case Pessimo:
		add("critico", "Sinal muito fraco", fmt.Sprintf("Sinal de %d dBm: conexão instável e lenta. O equipamento está longe demais do roteador ou há paredes/obstáculos demais.", c.RSSI))
	}

	switch c.SecurityLevel {
	case "aberta":
		add("critico", "Rede sem senha", "A rede Wi-Fi está aberta: qualquer um pode se conectar e ver o tráfego não criptografado. Configure WPA2 ou WPA3.")
	case "fraca":
		add("aviso", "Segurança fraca", fmt.Sprintf("A rede usa %s / %s, que é obsoleto e quebrável. Use WPA2-Personal (AES) ou WPA3.", c.Security, c.Cipher))
	}

	// Comparação exata: "802.11a" também aparece dentro de "Wi-Fi 5 (802.11ac)".
	if slices.Contains([]string{"802.11a", "802.11b", "802.11g", "DSSS", "FHSS"}, c.PhyType) {
		add("aviso", "Padrão Wi-Fi antigo", fmt.Sprintf("Conectado em %s: limita a velocidade a ~20-25 Mbps reais. Verifique se o roteador ou a placa suporta Wi-Fi 4/5/6.", c.PhyType))
	}

	if planMbps > 0 {
		link := math.Max(c.RxMbps, c.TxMbps)
		if link > 0 && link < float64(planMbps) {
			add("aviso", "Link Wi-Fi abaixo do plano", fmt.Sprintf("A velocidade negociada com o roteador é %.0f Mbps e o plano é %d Mega. Na prática o Wi-Fi entrega ~50-60%% do link, então o plano não chega neste ponto. Melhore o sinal, use 5 GHz ou cabo.", link, planMbps))
		}
	}

	// Mesma rede em 5 GHz disponível, mas conectado em 2.4 GHz.
	if c.BandGHz == 2.4 {
		best5 := -200
		for _, n := range nets {
			if n.SSID == c.SSID && n.BandGHz == 5 {
				best5 = max(best5, n.RSSI)
			}
		}
		if best5 >= -72 {
			add("aviso", "Conectado em 2.4 GHz com 5 GHz disponível", fmt.Sprintf("A mesma rede tem 5 GHz com sinal de %d dBm aqui. 5 GHz é bem mais rápido e sofre menos interferência; se o roteador usa o mesmo nome nas duas bandas, separe os nomes ou ative o band steering.", best5))
		} else if len(nets) > 0 {
			has5 := false
			for _, n := range nets {
				if n.SSID == c.SSID && n.BandGHz == 5 {
					has5 = true
				}
			}
			if !has5 {
				add("info", "Rede só em 2.4 GHz", "Não foi vista a mesma rede em 5 GHz. Se o roteador for dual band, ative a rede 5 GHz para quem está perto dele.")
			}
		}
	}

	if c.BandGHz == 2.4 && c.Channel > 0 && !slices.Contains([]int{1, 6, 11}, c.Channel) {
		add("aviso", "Canal 2.4 GHz fora do padrão", fmt.Sprintf("O roteador está no canal %d. Em 2.4 GHz só 1, 6 e 11 não se sobrepõem; canais intermediários pegam interferência de dois lados.", c.Channel))
	}

	// Congestionamento no canal atual.
	others := 0
	for _, n := range nets {
		if n.SSID == c.SSID || n.RSSI < -80 || n.BandGHz != c.BandGHz {
			continue
		}
		if n.Channel == c.Channel || (c.BandGHz == 2.4 && abs(n.Channel-c.Channel) < 5) {
			others++
		}
	}
	best := rep.Best24
	if c.BandGHz == 5 {
		best = rep.Best5
	}
	if others >= 3 {
		msg := fmt.Sprintf("%d redes vizinhas disputam o canal %d. Isso causa lentidão e oscilação.", others, c.Channel)
		if best != 0 && best != c.Channel {
			msg += fmt.Sprintf(" Sugestão: mudar o roteador para o canal %d, o menos ocupado aqui.", best)
		}
		add("aviso", "Canal congestionado", msg)
	} else if others > 0 && best != 0 && best != c.Channel {
		add("info", "Canal com vizinhos", fmt.Sprintf("%d rede(s) vizinha(s) no canal %d. O canal %d está mais livre.", others, c.Channel, best))
	}

	total24 := 0
	for _, n := range nets {
		if n.BandGHz == 2.4 && n.RSSI >= -80 {
			total24++
		}
	}
	if total24 >= 15 {
		add("info", "Ambiente 2.4 GHz lotado", fmt.Sprintf("%d redes 2.4 GHz com sinal relevante neste local. Prefira 5 GHz sempre que possível.", total24))
	}
}
