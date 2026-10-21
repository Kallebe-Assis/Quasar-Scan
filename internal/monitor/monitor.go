// Package monitor faz o monitoramento contínuo da conexão: pinga roteador e internet
// a cada segundo por um período longo e registra quedas e picos, para pegar
// problemas intermitentes ("a internet cai à noite").
package monitor

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"quasarscan/internal/diag"
	"quasarscan/internal/netinfo"
	"quasarscan/internal/winapi"
)

const (
	interval     = time.Second
	outageAfter  = 3   // perdas seguidas para considerar queda
	spikeFloorMs = 100 // pico = acima disso e de 4x a mediana
)

// Target é um destino monitorado, com o resumo acumulado.
type Target struct {
	Label     string     `json:"label"`
	Role      string     `json:"role"` // gateway, internet
	IP        string     `json:"ip"`
	Sent      int        `json:"sent"`
	Received  int        `json:"received"`
	LossPct   float64    `json:"lossPct"`
	AvgMs     float64    `json:"avgMs"`
	MaxMs     float64    `json:"maxMs"`
	JitterMs  float64    `json:"jitterMs"`
	UptimePct float64    `json:"uptimePct"` // % de segundos sem estar em queda
	Level     diag.Level `json:"level"`

	sum, jitterSum float64
	jitterN        int
	last           float64
	lossRun        int
	downSecs       int
	recent         []float64
	addr           netip.Addr
}

// Minute agrega um minuto de amostras de cada destino (para o gráfico).
type Minute struct {
	At    time.Time `json:"at"`
	AvgMs []float64 `json:"avgMs"` // por destino, -1 se tudo perdido
	MaxMs []float64 `json:"maxMs"`
	Lost  []int     `json:"lost"`
	Sent  []int     `json:"sent"`
}

// Event é uma queda ou pico registrado.
type Event struct {
	Kind    string    `json:"kind"`  // queda, pico
	Scope   string    `json:"scope"` // rede-local, internet, destino
	Target  string    `json:"target"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end,omitempty"`
	Seconds int       `json:"seconds"`
	PeakMs  float64   `json:"peakMs,omitempty"`
	Detail  string    `json:"detail"`
	open    bool
}

// Status é o estado do monitoramento enviado para a interface.
type Status struct {
	Running   bool      `json:"running"`
	StartedAt time.Time `json:"startedAt"`
	EndsAt    time.Time `json:"endsAt,omitempty"` // zero = até parar
	StoppedAt time.Time `json:"stoppedAt,omitempty"`
	Elapsed   int       `json:"elapsed"`
	Targets   []Target  `json:"targets"`
	Minutes   []Minute  `json:"minutes"`
	Events    []Event   `json:"events"`
	Summary   string    `json:"summary"`
	Level     string    `json:"level"` // ok, aviso, critico
}

type Monitor struct {
	mu     sync.Mutex
	st     Status
	cancel context.CancelFunc
	cur    *Minute
	OnDone func(Status) // chamado ao terminar, para salvar o resultado
}

// Start inicia o monitoramento por "dur" (0 = até parar).
func (m *Monitor) Start(dur time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Running {
		return fmt.Errorf("o monitoramento já está em andamento")
	}
	targets := buildTargets()
	if len(targets) == 0 {
		return fmt.Errorf("nenhuma interface com gateway IPv4 ativa")
	}
	now := time.Now()
	m.st = Status{Running: true, StartedAt: now, Targets: targets, Minutes: []Minute{}, Events: []Event{}}
	if dur > 0 {
		m.st.EndsAt = now.Add(dur)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if dur > 0 {
		ctx, cancel = context.WithDeadline(context.Background(), m.st.EndsAt)
	}
	m.cancel = cancel
	m.cur = nil
	go m.loop(ctx)
	return nil
}

// Stop encerra o monitoramento em andamento.
func (m *Monitor) Stop() {
	m.mu.Lock()
	c := m.cancel
	m.mu.Unlock()
	if c != nil {
		c()
	}
}

// Snapshot devolve uma cópia do estado atual.
func (m *Monitor) Snapshot() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.st
	s.Targets = slices.Clone(m.st.Targets)
	s.Minutes = slices.Clone(m.st.Minutes)
	if m.cur != nil {
		s.Minutes = append(s.Minutes, *m.cur)
	}
	s.Events = slices.Clone(m.st.Events)
	if s.Running {
		s.Elapsed = int(time.Since(s.StartedAt).Seconds())
	}
	summarize(&s)
	return s
}

func buildTargets() []Target {
	var out []Target
	list, _ := netinfo.Interfaces()
	for _, it := range list {
		if !it.IsPrimary {
			continue
		}
		for _, g := range it.Gateways {
			if ip, err := netip.ParseAddr(g); err == nil && ip.Is4() {
				out = append(out, Target{Label: "Roteador (gateway)", Role: "gateway", IP: g, addr: ip})
				break
			}
		}
	}
	for _, t := range []struct{ label, ip string }{{"Cloudflare", "1.1.1.1"}, {"Google DNS", "8.8.8.8"}} {
		out = append(out, Target{Label: t.label, Role: "internet", IP: t.ip, addr: netip.MustParseAddr(t.ip)})
	}
	return out
}

func (m *Monitor) loop(ctx context.Context) {
	// Impede a suspensão enquanto monitora (vale para esta thread, por isso o Lock).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	winapi.KeepAwake(true)
	defer winapi.KeepAwake(false)

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		m.round(time.Now())
		select {
		case <-ctx.Done():
			m.finish()
			return
		case <-tick.C:
		}
	}
}

// round pinga todos os destinos em paralelo e atualiza estatísticas e eventos.
func (m *Monitor) round(now time.Time) {
	m.mu.Lock()
	n := len(m.st.Targets)
	addrs := make([]netip.Addr, n)
	for i := range m.st.Targets {
		addrs[i] = m.st.Targets[i].addr
	}
	m.mu.Unlock()

	rtts := make([]float64, n)
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func(i int, a netip.Addr) {
			defer wg.Done()
			rtts[i] = -1
			if r, err := winapi.Ping(a, 900*time.Millisecond); err == nil {
				rtts[i] = float64(r.RTT.Microseconds()) / 1000
			}
		}(i, a)
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	minute := now.Truncate(time.Minute)
	if m.cur == nil || !m.cur.At.Equal(minute) {
		if m.cur != nil {
			m.st.Minutes = append(m.st.Minutes, *m.cur)
		}
		m.cur = &Minute{At: minute, AvgMs: make([]float64, n), MaxMs: make([]float64, n), Lost: make([]int, n), Sent: make([]int, n)}
	}
	for i := range m.st.Targets {
		t := &m.st.Targets[i]
		v := rtts[i]
		t.Sent++
		m.cur.Sent[i]++
		if v < 0 {
			t.lossRun++
			m.cur.Lost[i]++
		} else {
			okBefore := m.cur.Sent[i] - m.cur.Lost[i] - 1
			m.cur.AvgMs[i] = (m.cur.AvgMs[i]*float64(okBefore) + v) / float64(okBefore+1)
			m.cur.MaxMs[i] = math.Max(m.cur.MaxMs[i], v)
			t.Received++
			t.sum += v
			if t.Received > 1 {
				t.jitterSum += math.Abs(v - t.last)
				t.jitterN++
			}
			t.last = v
			t.MaxMs = math.Max(t.MaxMs, v)
			m.checkSpike(t, v, now)
			t.recent = append(t.recent, v)
			if len(t.recent) > 120 {
				t.recent = t.recent[1:]
			}
			t.lossRun = 0
		}
		if t.lossRun >= outageAfter {
			t.downSecs++
		}
		t.LossPct = math.Round(float64(t.Sent-t.Received)/float64(t.Sent)*1000) / 10
		if t.Received > 0 {
			t.AvgMs = math.Round(t.sum/float64(t.Received)*10) / 10
		}
		if t.jitterN > 0 {
			t.JitterMs = math.Round(t.jitterSum/float64(t.jitterN)*10) / 10
		}
		t.UptimePct = math.Round(float64(t.Sent-t.downSecs)/float64(t.Sent)*10000) / 100
		lat := diag.LatencyInternet
		if t.Role == "gateway" {
			lat = diag.LatencyLAN
		}
		t.Level = diag.Worst(lat.Rate(t.AvgMs), diag.Jitter.Rate(t.JitterMs), diag.Loss.Rate(t.LossPct))
	}
	m.updateIncidents(now)
	for i := range m.st.Events {
		if e := &m.st.Events[i]; e.open {
			e.Seconds = int(now.Sub(e.Start).Seconds()) + 1
		}
	}
}

func (m *Monitor) checkSpike(t *Target, v float64, now time.Time) {
	if len(t.recent) < 20 {
		return
	}
	med := median(t.recent)
	if v < spikeFloorMs || v < med*4 {
		return
	}
	// Junta picos próximos (até 10 s) num evento só.
	for i := len(m.st.Events) - 1; i >= 0; i-- {
		e := &m.st.Events[i]
		if e.Kind == "pico" && e.Target == t.IP && now.Sub(e.End) <= 10*time.Second {
			e.End, e.PeakMs = now, math.Max(e.PeakMs, v)
			e.Seconds = int(e.End.Sub(e.Start).Seconds()) + 1
			e.Detail = fmt.Sprintf("Latência chegou a %.0f ms (normal: ~%.0f ms).", e.PeakMs, med)
			return
		}
	}
	m.st.Events = append(m.st.Events, Event{Kind: "pico", Scope: "destino", Target: t.IP, Start: now, End: now, Seconds: 1,
		PeakMs: v, Detail: fmt.Sprintf("Latência chegou a %.0f ms (normal: ~%.0f ms).", v, med)})
}

// updateIncidents mantém um evento por situação de queda. Se o roteador caiu, é a
// rede local; se só a internet caiu (todos os destinos externos), é o link/provedor;
// senão, cada destino que caiu sozinho vira um evento próprio.
func (m *Monitor) updateIncidents(now time.Time) {
	type incident struct{ scope, target, detail string }
	var gw *Target
	var netDown, netTotal int
	var single []incident
	for i := range m.st.Targets {
		t := &m.st.Targets[i]
		isDown := t.lossRun >= outageAfter
		if t.Role == "gateway" {
			gw = t
			continue
		}
		netTotal++
		if isDown {
			netDown++
			single = append(single, incident{"destino", t.IP, "Apenas este destino parou de responder; os demais seguiam normais."})
		}
	}
	var active []incident
	switch {
	case gw != nil && gw.lossRun >= outageAfter:
		active = []incident{{"rede-local", gw.IP, "O roteador parou de responder: queda na rede local (Wi-Fi, cabo, roteador desligando/reiniciando)."}}
	case netTotal > 0 && netDown == netTotal:
		active = []incident{{"internet", "internet", "O roteador respondia, mas a internet inteira parou: queda no link/provedor (ONU, PPPoE, fibra)."}}
	default:
		active = single
	}

	key := func(scope, target string) string { return scope + "|" + target }
	isActive := map[string]incident{}
	for _, in := range active {
		isActive[key(in.scope, in.target)] = in
	}
	for i := range m.st.Events {
		e := &m.st.Events[i]
		if !e.open {
			continue
		}
		if _, ok := isActive[key(e.Scope, e.Target)]; ok {
			delete(isActive, key(e.Scope, e.Target)) // continua aberto
			continue
		}
		e.open, e.End = false, now
		e.Seconds = int(now.Sub(e.Start).Seconds())
	}
	for _, in := range active {
		if _, ok := isActive[key(in.scope, in.target)]; ok {
			m.st.Events = append(m.st.Events, Event{Kind: "queda", Scope: in.scope, Target: in.target, Detail: in.detail,
				Start: now.Add(-time.Duration(outageAfter-1) * interval), open: true})
		}
	}
}

func (m *Monitor) finish() {
	m.mu.Lock()
	now := time.Now()
	for i := range m.st.Events {
		if e := &m.st.Events[i]; e.open {
			e.open, e.End = false, now
		}
	}
	if m.cur != nil {
		m.st.Minutes = append(m.st.Minutes, *m.cur)
		m.cur = nil
	}
	m.st.Running = false
	m.st.StoppedAt = now
	m.st.Elapsed = int(now.Sub(m.st.StartedAt).Seconds())
	cb := m.OnDone
	m.mu.Unlock()
	if cb != nil {
		cb(m.Snapshot())
	}
}

func summarize(s *Status) {
	var localOut, netOut, spikes int
	for _, e := range s.Events {
		switch {
		case e.Kind == "pico":
			spikes++
		case e.Scope == "rede-local":
			localOut++
		case e.Scope == "internet":
			netOut++
		}
	}
	switch {
	case localOut > 0 && netOut > 0:
		s.Level, s.Summary = "critico", fmt.Sprintf("%d queda(s) na rede local e %d no link/provedor.", localOut, netOut)
	case localOut > 0:
		s.Level, s.Summary = "critico", fmt.Sprintf("%d queda(s), todas na rede local (o roteador parou de responder). O problema está dentro do cliente: Wi-Fi, cabo ou roteador.", localOut)
	case netOut > 0:
		s.Level, s.Summary = "critico", fmt.Sprintf("%d queda(s) da internet com o roteador respondendo normalmente: problema no link/provedor.", netOut)
	case spikes > 0:
		s.Level, s.Summary = "aviso", fmt.Sprintf("Sem quedas, mas com %d pico(s) de latência.", spikes)
	case s.Elapsed > 0 || !s.StartedAt.IsZero():
		s.Level, s.Summary = "ok", "Nenhuma queda ou pico registrado até agora."
	}
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s[len(s)/2]
}
