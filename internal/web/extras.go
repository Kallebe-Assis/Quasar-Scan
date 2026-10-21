package web

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"quasarscan/internal/diag"
	"quasarscan/internal/monitor"
	"quasarscan/internal/winapi"
)

func (s *Server) registerExtras(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/info", s.info)
	mux.HandleFunc("GET /api/atendimento", s.getAtendimento)
	mux.HandleFunc("POST /api/atendimento", s.setAtendimento)
	mux.HandleFunc("GET /api/relatorio/dados", s.reportData)
	mux.HandleFunc("POST /api/relatorio/salvar", s.saveReport)
	mux.HandleFunc("GET /api/wifi", s.wifi)
	mux.HandleFunc("GET /api/speed", s.speed)
	mux.HandleFunc("POST /api/monitor/start", s.monitorStart)
	mux.HandleFunc("POST /api/monitor/stop", func(w http.ResponseWriter, r *http.Request) { s.mon.Stop(); s.monitorStatus(w, r) })
	mux.HandleFunc("GET /api/monitor", s.monitorStatus)
	mux.HandleFunc("GET /api/tools/mtu", s.toolMTU)
	mux.HandleFunc("GET /api/tools/hijack", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, diag.CheckHijack(r.Context())) })
	mux.HandleFunc("POST /api/tools/renew", s.toolRenew)

	s.mon.OnDone = func(st monitor.Status) {
		s.hist.mu.Lock()
		s.hist.monitor = &st
		s.hist.mu.Unlock()
		s.saveJSON("monitoramento", st.StartedAt, st)
	}
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, map[string]any{"admin": winapi.IsAdmin(), "computer": host})
}

func (s *Server) wifi(w http.ResponseWriter, r *http.Request) {
	ifaces, err := winapi.WifiScan(r.URL.Query().Get("scan") != "0")
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	reps := diag.AnalyzeWifi(ifaces, s.planMbps())
	if len(reps) == 0 {
		http.Error(w, "nenhuma placa Wi-Fi encontrada neste computador", http.StatusNotFound)
		return
	}
	for _, rep := range reps {
		if rep.Connection != nil {
			s.hist.mu.Lock()
			s.hist.wifi = append(s.hist.wifi, rep)
			s.hist.mu.Unlock()
			s.saveJSON("wifi", time.Now(), rep)
			break
		}
	}
	writeJSON(w, reps)
}

func (s *Server) speed(w http.ResponseWriter, r *http.Request) {
	ev := newStream(w)
	plan := queryInt(r, "plano", 0, 0, 100000)
	if plan == 0 {
		plan = s.planMbps()
	}
	opt := diag.SpeedOptions{Server: r.URL.Query().Get("server"), PlanMbps: plan,
		Duration: time.Duration(queryInt(r, "segundos", 10, 5, 30)) * time.Second}
	ev.send("inicio", map[string]any{"planMbps": plan})
	res := diag.RunSpeed(r.Context(), opt, func(p diag.SpeedProgress) { ev.send("progresso", p) })
	if r.Context().Err() != nil {
		return // cancelado pelo usuário
	}
	if res.Error == "" {
		s.hist.mu.Lock()
		s.hist.speed = append(s.hist.speed, res)
		s.hist.mu.Unlock()
		s.saveJSON("velocidade", time.Now(), res)
	}
	ev.send("fim", res)
}

func (s *Server) monitorStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Minutes int `json:"minutes"` // 0 = até parar
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := s.mon.Start(time.Duration(clamp(body.Minutes, 0, 7*24*60)) * time.Minute); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.monitorStatus(w, r)
}

func (s *Server) monitorStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.Snapshot())
}

func (s *Server) toolMTU(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "8.8.8.8"
	}
	ip, err := diag.Resolve(r.Context(), host, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, diag.TestMTU(r.Context(), ip))
}

func (s *Server) toolRenew(w http.ResponseWriter, r *http.Request) {
	if !winapi.IsAdmin() {
		http.Error(w, "renovar o IP exige que o Quasar Scan esteja rodando como administrador", http.StatusForbidden)
		return
	}
	var body struct {
		IfIndex uint32 `json:"ifIndex"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := winapi.RenewIP(body.IfIndex); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"message": "IP liberado e renovado com sucesso."})
}
