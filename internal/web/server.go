// Package web serve a interface no navegador e a API local usada por ela.
package web

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"quasarscan/internal/monitor"
	"quasarscan/internal/netinfo"
	"quasarscan/internal/scan"
)

//go:embed static
var static embed.FS

type Server struct {
	scanner    scan.Scanner
	reportsDir string
	onShutdown func()
	hist       history
	mon        monitor.Monitor

	mu        sync.Mutex
	lastSaved string
}

// New cria o servidor; onShutdown é chamado quando o usuário clica em "Encerrar".
func New(reportsDir string, onShutdown func()) *Server {
	return &Server{reportsDir: reportsDir, onShutdown: onShutdown}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /api/interfaces", s.interfaces)
	mux.HandleFunc("POST /api/scan", s.startScan)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/export.json", s.exportJSON)
	mux.HandleFunc("GET /api/export.csv", s.exportCSV)
	mux.HandleFunc("POST /api/shutdown", s.shutdown)
	s.registerTools(mux)
	s.registerExtras(mux)
	return localOnly(mux)
}

// localOnly bloqueia requisições vindas de outros sites (DNS rebinding/CSRF):
// a API só aceita o próprio endereço local como Host.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "acesso negado", http.StatusForbidden)
			return
		}
		// Bloqueia páginas de outros sites abertas no navegador acionando a API.
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" || !sameOrigin(r.Header.Get("Origin"), r.Host) {
			http.Error(w, "acesso negado", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	return origin == "" || origin == "http://"+host
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	list, err := netinfo.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (s *Server) shutdown(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	s.onShutdown()
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var opt scan.Options
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		http.Error(w, "parâmetros inválidos", http.StatusBadRequest)
		return
	}
	if err := s.scanner.Start(opt); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.mu.Lock()
	s.lastSaved = ""
	s.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st := s.scanner.Status()
	s.mu.Lock()
	if !st.Running && st.Result != nil && s.lastSaved == "" {
		s.hist.mu.Lock()
		s.hist.scans = append(s.hist.scans, st.Result)
		s.hist.mu.Unlock()
		s.lastSaved = s.saveJSON("varredura", st.Result.StartedAt, st.Result)
	}
	saved := s.lastSaved
	s.mu.Unlock()
	writeJSON(w, struct {
		scan.Progress
		SavedTo string `json:"savedTo,omitempty"`
	}{st, saved})
}

func (s *Server) result(w http.ResponseWriter) *scan.Result {
	st := s.scanner.Status()
	if st.Result == nil {
		http.Error(w, "nenhuma varredura concluída", http.StatusNotFound)
	}
	return st.Result
}

func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request) {
	res := s.result(w)
	if res == nil {
		return
	}
	w.Header().Set("Content-Disposition", attachment(res, "json"))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	res := s.result(w)
	if res == nil {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", attachment(res, "csv"))
	w.Write([]byte("\xef\xbb\xbf")) // BOM para o Excel reconhecer acentos
	cw := csv.NewWriter(w)
	cw.Comma = ';' // padrão do Excel em português
	cw.Write([]string{"IP", "MAC", "Fabricante", "MAC aleatório", "Nome", "Hostname", "NetBIOS", "Modelo", "Serviços", "Tipo", "Sistema (TTL)", "Ping (ms)", "Portas abertas", "Gateway"})
	for _, h := range res.Hosts {
		var ports []string
		for _, p := range h.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Service))
		}
		ping := "sem resposta"
		if h.RTTms >= 0 {
			ping = strings.ReplaceAll(fmt.Sprintf("%.1f", h.RTTms), ".", ",")
		}
		cw.Write([]string{h.IP, h.MAC, h.Vendor, yesNo(h.RandomMAC), h.FriendlyName, h.Hostname, h.NetBIOS, h.Model,
			strings.Join(h.Services, ", "), h.DeviceType, h.OSGuess, ping, strings.Join(ports, ", "), yesNo(h.IsGateway)})
	}
	cw.Flush()
}

func attachment(res *scan.Result, ext string) string {
	return fmt.Sprintf(`attachment; filename="varredura-%s.%s"`, res.StartedAt.Format("2006-01-02_15-04-05"), ext)
}

func yesNo(b bool) string {
	if b {
		return "sim"
	}
	return "não"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
