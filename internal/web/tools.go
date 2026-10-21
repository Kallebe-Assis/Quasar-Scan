package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"quasarscan/internal/diag"
	"quasarscan/internal/netinfo"
	"quasarscan/internal/oui"
	"quasarscan/internal/winapi"
)

func (s *Server) registerTools(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/scales", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, diag.Scales) })
	mux.HandleFunc("GET /api/tools/ping", s.toolPing)
	mux.HandleFunc("GET /api/tools/trace", s.toolTrace)
	mux.HandleFunc("GET /api/tools/dnsservers", s.toolDNSServers)
	mux.HandleFunc("GET /api/tools/dns", s.toolDNS)
	mux.HandleFunc("GET /api/tools/dnsbench", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, diag.BenchmarkDNS(r.Context(), append(diag.SystemDNS(), diag.PublicDNS...)))
	})
	mux.HandleFunc("POST /api/tools/flushdns", s.toolFlushDNS)
	mux.HandleFunc("GET /api/tools/arp", s.toolARP)
	mux.HandleFunc("GET /api/tools/routes", s.toolRoutes)
	mux.HandleFunc("GET /api/tools/port", s.toolPort)
	mux.HandleFunc("GET /api/health", s.health)
}

// eventStream envia eventos SSE; é seguro chamar send de várias goroutines.
type eventStream struct {
	mu sync.Mutex
	w  http.ResponseWriter
	f  http.Flusher
}

func newStream(w http.ResponseWriter) *eventStream {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	f, _ := w.(http.Flusher)
	return &eventStream{w: w, f: f}
}

func (e *eventStream) send(event string, v any) {
	data, _ := json.Marshal(v)
	e.mu.Lock()
	defer e.mu.Unlock()
	fmt.Fprintf(e.w, "event: %s\ndata: %s\n\n", event, data)
	if e.f != nil {
		e.f.Flush()
	}
}

func (e *eventStream) fail(msg string) { e.send("erro", map[string]string{"message": msg}) }

func queryInt(r *http.Request, key string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return def
	}
	return clamp(v, min, max)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func queryHost(r *http.Request) (string, error) {
	h := strings.TrimSpace(r.URL.Query().Get("host"))
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\") {
		return "", fmt.Errorf("informe um IP ou nome válido (ex.: 8.8.8.8 ou google.com)")
	}
	return h, nil
}

func (s *Server) toolPing(w http.ResponseWriter, r *http.Request) {
	ev := newStream(w)
	host, err := queryHost(r)
	if err != nil {
		ev.fail(err.Error())
		return
	}
	ip, err := diag.Resolve(r.Context(), host, r.URL.Query().Get("ip"))
	if err != nil {
		ev.fail(err.Error())
		return
	}
	opt := diag.PingOptions{
		Count:    queryInt(r, "count", 10, 0, 10000), // 0 = contínuo (-t), até o usuário parar
		Size:     queryInt(r, "size", 32, 1, 65500),
		Interval: time.Second,
		Timeout:  time.Duration(queryInt(r, "timeout", 1000, 100, 10000)) * time.Millisecond,
	}
	ev.send("inicio", map[string]any{"host": host, "ip": ip.String(), "local": diag.IsLocal(ip), "size": opt.Size})
	st := diag.Ping(r.Context(), ip, opt, func(rep diag.PingReply, st diag.PingStats) {
		ev.send("resposta", map[string]any{"reply": rep, "stats": st})
	})
	ev.send("fim", st)
}

func (s *Server) toolTrace(w http.ResponseWriter, r *http.Request) {
	ev := newStream(w)
	host, err := queryHost(r)
	if err != nil {
		ev.fail(err.Error())
		return
	}
	ip, err := diag.Resolve(r.Context(), host, r.URL.Query().Get("ip"))
	if err != nil {
		ev.fail(err.Error())
		return
	}
	names := r.URL.Query().Get("names") != "0"
	ev.send("inicio", map[string]any{"host": host, "ip": ip.String()})
	hops := diag.Traceroute(r.Context(), ip, queryInt(r, "maxHops", 30, 1, 64), names, func(h diag.Hop) {
		ev.send("salto", h)
	})
	ev.send("fim", map[string]any{"findings": diag.AnalyzeTrace(hops, primaryGateway())})
}

func (s *Server) toolDNSServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"system": diag.SystemDNS(), "public": diag.PublicDNS, "types": diag.DNSTypes})
}

func (s *Server) toolDNS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := strings.TrimSpace(q.Get("name"))
	server := strings.TrimSpace(q.Get("server"))
	if name == "" || len(name) > 253 {
		http.Error(w, "informe o nome a consultar", http.StatusBadRequest)
		return
	}
	if server == "" {
		sys := diag.SystemDNS()
		if len(sys) == 0 {
			http.Error(w, "nenhum DNS configurado nesta máquina", http.StatusBadRequest)
			return
		}
		server = sys[0].IP
	}
	if ip, err := netip.ParseAddr(server); err != nil || !ip.Is4() {
		http.Error(w, "servidor DNS deve ser um IPv4 (ex.: 1.1.1.1)", http.StatusBadRequest)
		return
	}
	qtype := q.Get("type")
	if qtype == "" {
		qtype = "A"
	}
	writeJSON(w, diag.Lookup(r.Context(), server, name, qtype))
}

func (s *Server) toolFlushDNS(w http.ResponseWriter, r *http.Request) {
	if err := winapi.FlushDNSCache(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"message": "Cache DNS do Windows limpo com sucesso."})
}

func ifaceNames() map[uint32]string {
	names := map[uint32]string{}
	if list, err := netinfo.Interfaces(); err == nil {
		for _, it := range list {
			names[it.Index] = it.Name
		}
	}
	return names
}

func primaryGateway() string {
	list, _ := netinfo.Interfaces()
	for _, it := range list {
		if !it.IsPrimary {
			continue
		}
		for _, g := range it.Gateways {
			if ip, err := netip.ParseAddr(g); err == nil && ip.Is4() {
				return g
			}
		}
	}
	return ""
}

func (s *Server) toolARP(w http.ResponseWriter, r *http.Request) {
	entries, err := winapi.ARPTable()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := ifaceNames()
	type row struct {
		winapi.ARPEntry
		Interface string `json:"interface"`
		Vendor    string `json:"vendor,omitempty"`
		Kind      string `json:"kind"` // unicast, multicast, broadcast
	}
	out := []row{}
	for _, e := range entries {
		rw := row{ARPEntry: e, Interface: names[e.IfIndex], Kind: "unicast"}
		ip := netip.MustParseAddr(e.IP)
		switch {
		case ip.IsMulticast():
			rw.Kind = "multicast"
		case strings.HasSuffix(e.IP, ".255") || e.MAC == "ff:ff:ff:ff:ff:ff":
			rw.Kind = "broadcast"
		}
		if mac, err := net.ParseMAC(e.MAC); err == nil && rw.Kind == "unicast" {
			rw.Vendor = oui.Lookup(mac)
		}
		if e.MAC == "" || e.MAC == "00:00:00:00:00:00" {
			continue // entradas incompletas
		}
		out = append(out, rw)
	}
	writeJSON(w, out)
}

func (s *Server) toolRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := winapi.Routes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := ifaceNames()
	type row struct {
		winapi.Route
		Interface string `json:"interface"`
	}
	out := []row{}
	for _, rt := range routes {
		out = append(out, row{rt, names[rt.IfIndex]})
	}
	writeJSON(w, out)
}

func (s *Server) toolPort(w http.ResponseWriter, r *http.Request) {
	host, err := queryHost(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	port := queryInt(r, "port", 0, 0, 65535)
	if port == 0 {
		http.Error(w, "informe uma porta entre 1 e 65535", http.StatusBadRequest)
		return
	}
	writeJSON(w, diag.TestPort(r.Context(), host, r.URL.Query().Get("ip"), port))
}

// health executa o teste completo da Fase 3 e envia o progresso por SSE.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ev := newStream(w)
	q := r.URL.Query()
	mode := diag.HealthModeFor(q.Get("modo"))
	plan := queryInt(r, "plano", 0, 0, 100000)
	if plan == 0 {
		plan = s.planMbps()
	}
	ev.send("inicio", map[string]any{"steps": mode.Steps(), "mode": mode.ID, "estimateS": mode.EstimateS})

	// Avisa o tempo decorrido a cada segundo, para a barra de progresso.
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				ev.send("tempo", int(time.Since(start).Seconds()))
			}
		}
	}()

	rep := diag.RunHealth(r.Context(), diag.HealthOptions{
		PlanMbps:    plan,
		Medium:      q.Get("meio"),
		Mode:        mode,
		SpeedServer: q.Get("server"),
		OnSpeed:     func(p diag.SpeedProgress) { ev.send("velocidade", p) },
	}, func(step string) { ev.send("etapa", step) })
	close(done)
	if r.Context().Err() != nil {
		return
	}
	s.hist.mu.Lock()
	s.hist.health = append(s.hist.health, rep)
	if rep.Speed != nil && rep.Speed.Error == "" {
		s.hist.speed = append(s.hist.speed, *rep.Speed) // entra no antes/depois do relatório
	}
	s.hist.mu.Unlock()
	s.saveJSON("saude", rep.StartedAt, rep)
	ev.send("fim", rep)
}
