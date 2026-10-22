package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"quasarscan/internal/diag"
	"quasarscan/internal/monitor"
	"quasarscan/internal/pc"
	"quasarscan/internal/scan"
)

// Atendimento identifica a visita técnica: os testes feitos durante ela são
// guardados juntos, salvos na pasta do cliente e comparados no relatório (antes/depois).
type Atendimento struct {
	Cliente    string    `json:"cliente"`
	Codigo     string    `json:"codigo"`
	Tecnico    string    `json:"tecnico"`
	Endereco   string    `json:"endereco"`
	PlanoMbps  int       `json:"planoMbps"`
	Meio       string    `json:"meio"` // cabo ou wifi (faixas de latência do teste completo)
	Problema   string    `json:"problema"`
	Solucao    string    `json:"solucao"`
	IniciadoEm time.Time `json:"iniciadoEm"`
}

// history guarda os resultados da sessão atual (desde o início do atendimento).
type history struct {
	mu      sync.Mutex
	atend   Atendimento
	scans   []*scan.Result
	health  []diag.HealthReport
	speed   []diag.SpeedResult
	wifi    []diag.WifiReport
	monitor *monitor.Status
	pc      *pc.Report
}

func (h *history) reset(a Atendimento) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a.IniciadoEm = time.Now()
	h.atend = a
	h.scans, h.health, h.speed, h.wifi, h.monitor, h.pc = nil, nil, nil, nil, nil, nil
}

// firstLast devolve o primeiro e o último itens (para o antes/depois).
func firstLast[T any](list []T) (first, last *T) {
	if len(list) == 0 {
		return nil, nil
	}
	return &list[0], &list[len(list)-1]
}

// clientDir é a pasta onde os arquivos do atendimento são salvos.
func (s *Server) clientDir() string {
	s.hist.mu.Lock()
	name := s.hist.atend.Cliente
	code := s.hist.atend.Codigo
	s.hist.mu.Unlock()
	folder := slug(strings.TrimSpace(code + " " + name))
	if folder == "" {
		return s.reportsDir
	}
	return filepath.Join(s.reportsDir, folder)
}

// slug gera um nome de pasta seguro: "João da Silva / 123" -> "joao-da-silva-123".
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		switch {
		case unicode.Is(unicode.Mn, r): // acentos
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteRune('-')
			dash = true
		}
	}
	out := strings.TrimSuffix(b.String(), "-")
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

// saveJSON grava um resultado em relatorios/<cliente>/<tipo>-<data>.json.
func (s *Server) saveJSON(kind string, at time.Time, v any) string {
	dir := s.clientDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.json", kind, at.Format("2006-01-02_15-04-05")))
	data, _ := json.MarshalIndent(v, "", "  ")
	if os.WriteFile(path, data, 0o644) != nil {
		return ""
	}
	return path
}

func (s *Server) getAtendimento(w http.ResponseWriter, r *http.Request) {
	dir := s.clientDir() // antes do Lock: clientDir também trava o histórico
	s.hist.mu.Lock()
	defer s.hist.mu.Unlock()
	writeJSON(w, map[string]any{
		"atendimento": s.hist.atend,
		"contagem": map[string]int{"varreduras": len(s.hist.scans), "saude": len(s.hist.health),
			"velocidade": len(s.hist.speed), "wifi": len(s.hist.wifi)},
		"pasta": dir,
	})
}

// setAtendimento atualiza os dados; com ?novo=1 inicia um novo atendimento (zera o histórico).
func (s *Server) setAtendimento(w http.ResponseWriter, r *http.Request) {
	var a Atendimento
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&a); err != nil {
		http.Error(w, "dados inválidos", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("novo") == "1" {
		s.hist.reset(a)
	} else {
		s.hist.mu.Lock()
		a.IniciadoEm = s.hist.atend.IniciadoEm
		if a.IniciadoEm.IsZero() {
			a.IniciadoEm = time.Now()
		}
		s.hist.atend = a
		s.hist.mu.Unlock()
	}
	s.getAtendimento(w, r)
}

func (s *Server) planMbps() int {
	s.hist.mu.Lock()
	defer s.hist.mu.Unlock()
	return s.hist.atend.PlanoMbps
}

// reportData junta tudo o que o relatório precisa, com o antes/depois de cada teste.
func (s *Server) reportData(w http.ResponseWriter, r *http.Request) {
	s.hist.mu.Lock()
	defer s.hist.mu.Unlock()
	h := &s.hist
	host, _ := os.Hostname()
	scanFirst, scanLast := firstLast(h.scans)
	healthFirst, healthLast := firstLast(h.health)
	speedFirst, speedLast := firstLast(h.speed)
	_, wifiLast := firstLast(h.wifi)
	mon := h.monitor
	if snap := s.mon.Snapshot(); snap.Running && snap.StartedAt.After(h.atend.IniciadoEm) {
		mon = &snap // monitoramento ainda rodando: entra o resultado parcial
	}
	writeJSON(w, map[string]any{
		"atendimento": h.atend,
		"computador":  host,
		"geradoEm":    time.Now(),
		"scanFirst":   deref(scanFirst), "scanLast": deref(scanLast), "scans": len(h.scans),
		"healthFirst": healthFirst, "healthLast": healthLast, "healths": len(h.health),
		"speedFirst": speedFirst, "speedLast": speedLast, "speeds": len(h.speed),
		"wifi":    wifiLast,
		"monitor": mon,
		"pc":      pcSummary(h.pc),
		"scales":  diag.Scales,
	})
}

func deref(p **scan.Result) *scan.Result {
	if p == nil {
		return nil
	}
	return *p
}

// saveReport grava o HTML do relatório (montado pela interface) na pasta do cliente.
func (s *Server) saveReport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	var body struct {
		HTML string `json:"html"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !strings.HasPrefix(body.HTML, "<!doctype html>") {
		http.Error(w, "relatório inválido", http.StatusBadRequest)
		return
	}
	dir := s.clientDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	path := filepath.Join(dir, "relatorio-"+time.Now().Format("2006-01-02_15-04-05")+".html")
	if err := os.WriteFile(path, []byte(body.HTML), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"path": path})
}

// pcSummary leva para o relatório só o essencial da inspeção do computador
// (a lista completa de processos e serviços não cabe num relatório para o cliente).
func pcSummary(r *pc.Report) map[string]any {
	if r == nil {
		return nil
	}
	var important []pc.Finding
	for _, f := range r.Findings {
		if f.Level != "info" {
			important = append(important, f)
		}
	}
	return map[string]any{
		"startedAt": r.StartedAt, "score": r.Score, "grade": r.Grade, "summary": r.Summary,
		"system": r.System, "checklist": r.Checklist, "findings": important, "threats": r.Security.Threats,
	}
}
