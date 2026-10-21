package diag

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"quasarscan/internal/netinfo"
	"quasarscan/internal/scan"
	"quasarscan/internal/winapi"
)

// LatencyTarget é um destino do teste de latência múltiplo.
type LatencyTarget struct {
	Label string    `json:"label"`
	Role  string    `json:"role"` // gateway, dns, internet, site
	Host  string    `json:"host"`
	IP    string    `json:"ip"`
	Stats PingStats `json:"stats"`
	RTTs  []float64 `json:"rtts"` // -1 = perdido, para o gráfico
	Error string    `json:"error,omitempty"`
}

// CallQuality é o veredito para chamadas de vídeo/voz.
type CallQuality struct {
	Level     Level   `json:"level"`
	Verdict   string  `json:"verdict"`
	LatencyMs float64 `json:"latencyMs"`
	JitterMs  float64 `json:"jitterMs"`
	LossPct   float64 `json:"lossPct"`
	Basis     string  `json:"basis"`
}

type HealthReport struct {
	StartedAt time.Time           `json:"startedAt"`
	DurationS float64             `json:"durationS"`
	Interface string              `json:"interface"`
	IfType    string              `json:"ifType"`
	Gateway   string              `json:"gateway"`
	Internet  scan.InternetStatus `json:"internet"`
	Latency   []LatencyTarget     `json:"latency"`
	Trace     []Hop               `json:"trace"`
	TraceTo   string              `json:"traceTo"`
	DNS       []DNSBench          `json:"dns"`
	Hijack    *HijackCheck        `json:"hijack,omitempty"`
	MTU       *MTUResult          `json:"mtu,omitempty"`
	LinkMbps  uint64              `json:"linkMbps"`
	PlanMbps  int                 `json:"planMbps,omitempty"`
	Medium    string              `json:"medium"` // cabo ou wifi: define as faixas de latência
	Mode      string              `json:"mode"`   // rapido ou completo
	Samples   int                 `json:"samples"`
	Speed     *SpeedResult        `json:"speed,omitempty"` // só no modo completo
	IPv6      IPv6Status          `json:"ipv6"`
	Wifi      *WifiReport         `json:"wifi,omitempty"`
	Call      *CallQuality        `json:"call,omitempty"`
	Summary   TraceFinding        `json:"summary"`
	Findings  []TraceFinding      `json:"findings"`
}

// HealthMode define a duração do teste. O rápido dá um retrato em ~15 s; o completo
// mede a latência por 1 minuto (médias e jitter mais confiáveis) e inclui o teste de
// velocidade, rodando sozinho no final para não distorcer as outras medições.
type HealthMode struct {
	ID        string
	Samples   int
	Interval  time.Duration
	Speed     bool
	EstimateS int // duração aproximada, para a barra de progresso
}

var (
	ModeRapido   = HealthMode{ID: "rapido", Samples: 25, Interval: 200 * time.Millisecond, EstimateS: 15}
	ModeCompleto = HealthMode{ID: "completo", Samples: 120, Interval: 500 * time.Millisecond, Speed: true, EstimateS: 95}
)

// HealthModeFor devolve o modo pelo nome (padrão: rápido).
func HealthModeFor(id string) HealthMode {
	if id == ModeCompleto.ID {
		return ModeCompleto
	}
	return ModeRapido
}

// Steps são as etapas do teste, para a barra de progresso.
func (m HealthMode) Steps() []string {
	steps := []string{"internet", "latencia", "traceroute", "dns", "mtu"}
	if m.Speed {
		steps = append(steps, "velocidade")
	}
	return steps
}

// HealthOptions traz dados do atendimento que melhoram o diagnóstico.
// Medium "cabo" ou "wifi"; vazio detecta pela placa em uso.
type HealthOptions struct {
	PlanMbps    int
	Medium      string
	Mode        HealthMode
	SpeedServer string              // vazio = Cloudflare
	OnSpeed     func(SpeedProgress) // progresso do teste de velocidade (modo completo)
}

// IPv6Status resume se o IPv6 está habilitado e funcionando nesta conexão.
type IPv6Status struct {
	State    string   `json:"state"` // ativo, sem-internet, so-link-local, desabilitado
	Text     string   `json:"text"`
	Global   []string `json:"global"`
	Internet bool     `json:"internet"`
}

func ipv6Status(it *netinfo.Interface, internet bool) IPv6Status {
	st := IPv6Status{Global: []string{}, Internet: internet}
	if it == nil {
		st.State, st.Text = "desabilitado", "Sem interface ativa."
		return st
	}
	for _, a := range it.IPv6 {
		if a.Scope == "global" {
			st.Global = append(st.Global, a.Address)
		}
	}
	switch {
	case len(it.IPv6) == 0:
		st.State, st.Text = "desabilitado", "IPv6 desabilitado nesta placa de rede."
	case len(st.Global) == 0:
		st.State, st.Text = "so-link-local", "Placa com IPv6 ligado, mas sem endereço global: o roteador não está entregando prefixo IPv6."
	case !internet:
		st.State, st.Text = "sem-internet", "Há endereço IPv6 global, mas a internet por IPv6 não responde."
	default:
		st.State, st.Text = "ativo", "IPv6 habilitado e funcionando."
	}
	return st
}

// RunHealth executa o teste completo de saúde da conexão (Fase 3).
func RunHealth(ctx context.Context, opt HealthOptions, onStep func(step string)) HealthReport {
	if opt.Mode.Samples == 0 {
		opt.Mode = ModeRapido
	}
	rep := HealthReport{StartedAt: time.Now(), Findings: []TraceFinding{}, Latency: []LatencyTarget{}, Trace: []Hop{}, DNS: []DNSBench{},
		PlanMbps: opt.PlanMbps, Medium: opt.Medium, Mode: opt.Mode.ID, Samples: opt.Mode.Samples}
	ifaces, _ := netinfo.Interfaces()
	var primary *netinfo.Interface
	for i := range ifaces {
		if ifaces[i].IsPrimary {
			primary = &ifaces[i]
		}
	}
	hasV6 := false
	if rep.Medium != "cabo" && rep.Medium != "wifi" {
		rep.Medium = "cabo"
		if primary != nil && primary.Type == "Wi-Fi" {
			rep.Medium = "wifi"
		}
	}
	if primary != nil {
		rep.Interface, rep.IfType, rep.LinkMbps = primary.Name, primary.Type, primary.SpeedMbps
		for _, a := range primary.IPv6 {
			hasV6 = hasV6 || a.Scope == "global"
		}
		if primary.Type == "Wi-Fi" {
			if w, err := winapi.WifiScan(false); err == nil {
				for _, r := range AnalyzeWifi(w, opt.PlanMbps) {
					if r.Connection != nil {
						rep.Wifi = &r
						break
					}
				}
			}
		}
		for _, g := range primary.Gateways {
			if ip, err := netip.ParseAddr(g); err == nil && ip.Is4() {
				rep.Gateway = g
				break
			}
		}
	}

	targets := []LatencyTarget{}
	if rep.Gateway != "" {
		targets = append(targets, LatencyTarget{Label: "Roteador (gateway)", Role: "gateway", Host: rep.Gateway})
	}
	for _, d := range SystemDNS() {
		if d.IP != rep.Gateway {
			targets = append(targets, LatencyTarget{Label: "DNS configurado", Role: "dns", Host: d.IP})
		}
	}
	targets = append(targets,
		LatencyTarget{Label: "Cloudflare", Role: "internet", Host: "1.1.1.1"},
		LatencyTarget{Label: "Google DNS", Role: "internet", Host: "8.8.8.8"},
		LatencyTarget{Label: "Site (google.com.br)", Role: "site", Host: "www.google.com.br"},
	)
	if hasV6 {
		targets = append(targets,
			LatencyTarget{Label: "Cloudflare (IPv6)", Role: "internet6", Host: "2606:4700:4700::1111"},
			LatencyTarget{Label: "Google (IPv6)", Role: "internet6", Host: "2001:4860:4860::8888"},
		)
	}

	// Etapa 1: latência sozinha. O traceroute dispara várias sondas de uma vez e os
	// roteadores limitam a geração de ICMP, o que distorceria a latência e o jitter.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		rep.Internet = scan.CheckInternet()
		onStep("internet")
	}()
	go func() {
		defer wg.Done()
		var lw sync.WaitGroup
		for i := range targets {
			lw.Add(1)
			go func(t *LatencyTarget) {
				defer lw.Done()
				measureTarget(ctx, t, rep.Medium == "wifi", opt.Mode)
			}(&targets[i])
		}
		lw.Wait()
		rep.Latency = targets
		onStep("latencia")
	}()
	wg.Wait()

	// Etapa 2: traceroute, DNS (velocidade e sequestro) e MTU.
	wg.Add(3)
	go func() {
		defer wg.Done()
		rep.TraceTo = "8.8.8.8"
		rep.Trace = Traceroute(ctx, netip.MustParseAddr(rep.TraceTo), 20, false, nil)
		onStep("traceroute")
	}()
	go func() {
		defer wg.Done()
		rep.DNS = BenchmarkDNS(ctx, append(SystemDNS(), PublicDNS...))
		if rep.Internet.Online {
			h := CheckHijack(ctx)
			rep.Hijack = &h
		}
		onStep("dns")
	}()
	go func() {
		defer wg.Done()
		m := TestMTU(ctx, netip.MustParseAddr("8.8.8.8"))
		if m.Error == "" {
			rep.MTU = &m
		}
		onStep("mtu")
	}()
	wg.Wait()

	// Etapa 3 (completo): velocidade por último e sozinha, porque satura o link.
	if opt.Mode.Speed && rep.Internet.Online && ctx.Err() == nil {
		onSpeed := opt.OnSpeed
		if onSpeed == nil {
			onSpeed = func(SpeedProgress) {}
		}
		sp := RunSpeed(ctx, SpeedOptions{Server: opt.SpeedServer, PlanMbps: opt.PlanMbps}, onSpeed)
		rep.Speed = &sp
	}
	if opt.Mode.Speed {
		onStep("velocidade")
	}

	rep.IPv6 = ipv6Status(primary, rep.Internet.IPv6)
	rep.Call = callQuality(rep.Latency)
	diagnose(&rep)
	rep.DurationS = time.Since(rep.StartedAt).Seconds()
	return rep
}

func measureTarget(ctx context.Context, t *LatencyTarget, wifi bool, mode HealthMode) {
	t.RTTs = []float64{}
	ip, err := Resolve(ctx, t.Host, "")
	if err != nil {
		t.Error = err.Error()
		t.Stats = NewStats(nil, 0, false, wifi)
		return
	}
	t.IP = ip.String()
	opt := PingOptions{Count: mode.Samples, Size: 32, Interval: mode.Interval, Timeout: time.Second, WiFi: wifi}
	t.Stats = Ping(ctx, ip, opt, func(r PingReply, _ PingStats) {
		if r.OK {
			t.RTTs = append(t.RTTs, r.RTTms)
		} else {
			t.RTTs = append(t.RTTs, -1)
		}
	})
}

// callQuality usa o melhor destino da internet: um servidor que despriorize ICMP
// não deve condenar a conexão inteira.
func callQuality(targets []LatencyTarget) *CallQuality {
	var best *LatencyTarget
	rank := map[Level]int{Excelente: 0, Razoavel: 1, Ruim: 2, Pessimo: 3}
	for i := range targets {
		t := &targets[i]
		if t.Role != "internet" || t.Stats.Received == 0 {
			continue
		}
		if best == nil || rank[t.Stats.Overall] < rank[best.Stats.Overall] ||
			(t.Stats.Overall == best.Stats.Overall && t.Stats.AvgMs < best.Stats.AvgMs) {
			best = t
		}
	}
	if best == nil {
		return nil
	}
	s := best.Stats
	cq := &CallQuality{Level: s.Overall, LatencyMs: s.AvgMs, JitterMs: s.JitterMs, LossPct: s.LossPct,
		Basis: fmt.Sprintf("%s (%s), %d amostras", best.Label, best.IP, s.Sent)}
	cq.Verdict = map[Level]string{
		Excelente: "Excelente para chamadas de vídeo, reuniões (Zoom/Teams/Meet) e jogos online.",
		Razoavel:  "Boa para chamadas e reuniões; jogos competitivos podem sentir pequenas oscilações.",
		Ruim:      "Chamadas podem picotar, atrasar a voz ou congelar o vídeo.",
		Pessimo:   "Imprópria para chamadas: espere cortes, travamentos e quedas.",
	}[s.Overall]
	return cq
}

// diagnose cruza os resultados e escreve as conclusões em linguagem de atendimento.
func diagnose(rep *HealthReport) {
	add := func(l, t, d string) { rep.Findings = append(rep.Findings, TraceFinding{l, t, d}) }
	var gw *LatencyTarget
	var internet []LatencyTarget
	for i, t := range rep.Latency {
		switch t.Role {
		case "gateway":
			gw = &rep.Latency[i]
		case "internet", "site":
			internet = append(internet, t)
		}
	}

	gwBad := gw != nil && (gw.Stats.Received == 0 || gw.Stats.Overall == Ruim || gw.Stats.Overall == Pessimo)
	switch {
	case rep.Gateway == "":
		add("critico", "Sem gateway configurado", "A placa de rede não tem gateway: sem saída para a internet. Verifique o DHCP/IP.")
	case gw != nil && gw.Stats.Received == 0:
		add("critico", "Roteador não responde", fmt.Sprintf("O gateway %s não respondeu a nenhum ping. Verifique cabo/Wi-Fi e se o roteador está ligado.", rep.Gateway))
	case gwBad:
		hint := "Verifique o cabo, a porta do roteador e se o roteador está sobrecarregado."
		if rep.IfType == "Wi-Fi" {
			hint = "Conexão por Wi-Fi: aproxime-se do roteador, prefira 5 GHz, troque o canal ou verifique interferência."
		}
		add("critico", "Problema na rede local", fmt.Sprintf("Até o roteador: média %.1f ms, jitter %.1f ms, perda %.0f%%. %s",
			gw.Stats.AvgMs, gw.Stats.JitterMs, gw.Stats.LossPct, hint))
	}

	switch {
	case !rep.Internet.Online && gw != nil && gw.Stats.Received > 0:
		add("critico", "Roteador OK, mas sem internet", "A rede local funciona, mas nada sai para a internet. Verifique a WAN do roteador (PPPoE/DHCP), a ONU (luz LOS/PON) e se há bloqueio no provedor.")
	case !rep.Internet.Online:
		add("critico", "Sem internet", rep.Internet.Message)
	case !gwBad:
		worst := Excelente
		netJitter := 0.0
		for _, t := range internet {
			if t.Stats.Received > 0 {
				worst = Worst(worst, t.Stats.Overall)
				netJitter = max(netJitter, t.Stats.JitterMs)
			}
		}
		// Se a oscilação até o roteador é quase a mesma da internet, ela nasce na rede local.
		localJitter := gw != nil && gw.Stats.JitterMs > Jitter.Excelente && gw.Stats.JitterMs >= netJitter*0.6
		if (worst == Ruim || worst == Pessimo) && localJitter {
			add("aviso", "Oscilação nasce na rede local", fmt.Sprintf("O jitter até o roteador (%.1f ms) é quase o mesmo da internet (%.1f ms): os picos acontecem entre este computador e o roteador, não no provedor. Verifique cabo/Wi-Fi, a placa de rede e a carga do roteador.", gw.Stats.JitterMs, netJitter))
		} else if worst == Ruim || worst == Pessimo {
			add("aviso", "Rede local OK, lentidão depois do roteador", "O roteador responde bem, mas os destinos na internet estão lentos ou instáveis. O problema está no link/rota do provedor — veja o traceroute para localizar o ponto.")
		}
	}

	analyzeDNS(rep, add)
	analyzeExtras(rep, add)
	rep.Findings = append(rep.Findings, AnalyzeTrace(rep.Trace, rep.Gateway)...)

	order := map[string]int{"critico": 0, "aviso": 1, "info": 2}
	slices.SortStableFunc(rep.Findings, func(a, b TraceFinding) int { return order[a.Level] - order[b.Level] })
	rep.Summary = TraceFinding{"ok", "Conexão saudável", "Rede local, internet e DNS dentro do esperado."}
	if len(rep.Findings) > 0 && rep.Findings[0].Level != "info" {
		rep.Summary = rep.Findings[0]
	}
}

func analyzeDNS(rep *HealthReport, add func(l, t, d string)) {
	if !rep.Internet.Online {
		return
	}
	var best *DNSBench
	var system []DNSBench
	for i, b := range rep.DNS {
		if b.Local {
			system = append(system, b)
			continue
		}
		if b.MedianMs >= 0 && (best == nil || b.MedianMs < best.MedianMs) {
			best = &rep.DNS[i]
		}
	}
	if len(system) == 0 || best == nil {
		return
	}
	for _, s := range system {
		switch {
		case s.MedianMs < 0:
			add("critico", "DNS configurado não responde", fmt.Sprintf("O DNS %s não respondeu às consultas, mas o %s (%s) funciona. Sites não abrem pelo nome: troque o DNS no roteador/DHCP.", s.IP, best.Label, best.IP))
		case s.Failures > 0:
			add("aviso", "DNS configurado com falhas", fmt.Sprintf("O DNS %s falhou em %d de %d consultas.", s.IP, s.Failures, len(BenchDomains)))
		case s.MedianMs > best.MedianMs*2 && s.MedianMs-best.MedianMs > 30:
			add("aviso", "DNS configurado está lento", fmt.Sprintf("O DNS %s responde em %.0f ms; o %s (%s) responde em %.0f ms. Trocar o DNS pode deixar a navegação mais rápida.", s.IP, s.MedianMs, best.Label, best.IP, best.MedianMs))
		}
	}
}

// analyzeExtras cobre IPv6, velocidade da placa, Wi-Fi, MTU e sequestro de DNS.
func analyzeExtras(rep *HealthReport, add func(l, t, d string)) {
	var v6ok, v6total int
	v4ok := false
	for _, t := range rep.Latency {
		switch t.Role {
		case "internet6":
			v6total++
			if t.Stats.Received > 0 {
				v6ok++
			}
		case "internet":
			v4ok = v4ok || t.Stats.Received > 0
		}
	}
	switch {
	case v6total > 0 && v6ok == 0 && v4ok:
		add("aviso", "IPv6 configurado, mas sem resposta", "O computador tem IPv6 global, mas os servidores IPv6 não respondem. Sites podem demorar a abrir (tentam IPv6 antes). Verifique o IPv6 na WAN do roteador.")
	case rep.IPv6.State == "so-link-local":
		add("info", "IPv6 não entregue pelo roteador", rep.IPv6.Text+" Se o provedor oferece IPv6, ative-o na WAN e na LAN do roteador (DHCPv6-PD/SLAAC).")
	case rep.IPv6.State == "desabilitado":
		add("info", "IPv6 desabilitado na placa", "O protocolo IPv6 está desligado nas propriedades da placa de rede deste computador.")
	}

	if rep.IfType == "Ethernet" && rep.LinkMbps > 0 {
		switch {
		case rep.LinkMbps <= 10:
			add("critico", "Placa de rede a 10 Mbps", "O cabo/porta negociou apenas 10 Mbps. Quase sempre é cabo danificado, conector mal crimpado ou porta com defeito.")
		case rep.LinkMbps <= 100 && (rep.PlanMbps == 0 || rep.PlanMbps > 100):
			msg := "A placa negociou 100 Mbps (Fast Ethernet)."
			if rep.PlanMbps > 100 {
				msg = fmt.Sprintf("A placa negociou 100 Mbps, mas o plano é de %d Mega: este computador não passa de ~94 Mbps.", rep.PlanMbps)
			}
			add("aviso", "Cabo/porta a 100 Mbps", msg+" Gigabit precisa dos 4 pares do cabo (Cat5e ou superior) e de portas gigabit no roteador/switch e na placa. Cabo com par rompido ou mal crimpado cai para 100 Mbps.")
		}
	}

	if rep.Wifi != nil {
		for _, f := range rep.Wifi.Findings {
			add(f.Level, "Wi-Fi: "+f.Title, f.Detail)
		}
	}
	if rep.MTU != nil && rep.MTU.Level != "ok" {
		add(map[string]string{"info": "info", "aviso": "aviso", "critico": "critico"}[rep.MTU.Level], fmt.Sprintf("MTU do caminho: %d", rep.MTU.PathMTU), rep.MTU.Verdict)
	}
	if rep.Speed != nil {
		if rep.Speed.Error != "" {
			add("aviso", "Teste de velocidade não concluído", rep.Speed.Error)
		}
		for _, f := range rep.Speed.Findings {
			add(f.Level, f.Title, f.Detail)
		}
	}
	if rep.Hijack != nil && rep.Hijack.Level != "ok" {
		add(rep.Hijack.Level, "DNS responde domínios inexistentes", rep.Hijack.Verdict)
	}
}
