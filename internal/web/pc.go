package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"quasarscan/internal/pc"
	"quasarscan/internal/winapi"
)

func (s *Server) registerPC(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/pc/inspecao", s.pcInspect)
	mux.HandleFunc("GET /api/pc/acoes", s.pcActions)
	mux.HandleFunc("GET /api/pc/acao", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.pcRunner.Status()) })
	mux.HandleFunc("POST /api/pc/acao", s.pcStartAction)
	mux.HandleFunc("POST /api/pc/acao/cancelar", func(w http.ResponseWriter, r *http.Request) {
		s.pcRunner.Cancel()
		writeJSON(w, s.pcRunner.Status())
	})
	mux.HandleFunc("POST /api/pc/abrir", s.pcReveal)
	mux.HandleFunc("POST /api/pc/seguranca", func(w http.ResponseWriter, r *http.Request) {
		if err := pc.OpenSecurityCenter(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// pcInspect executa a inspeção do computador e envia o progresso por SSE.
func (s *Server) pcInspect(w http.ResponseWriter, r *http.Request) {
	ev := newStream(w)
	ev.send("inicio", map[string]any{"steps": pc.Steps})
	rep := pc.Inspect(func(step string) { ev.send("etapa", step) },
		func(done, total int) {
			if done%10 == 0 || done == total {
				ev.send("progresso", map[string]int{"done": done, "total": total})
			}
		})
	if r.Context().Err() != nil {
		return
	}
	s.hist.mu.Lock()
	s.hist.pc = &rep
	s.hist.mu.Unlock()
	s.saveJSON("computador", rep.StartedAt, rep)
	ev.send("fim", rep)
}

func (s *Server) pcActions(w http.ResponseWriter, r *http.Request) {
	home, _ := os.UserHomeDir()
	writeJSON(w, map[string]any{
		"actions":   pc.Actions,
		"job":       s.pcRunner.Status(),
		"admin":     winapi.IsAdmin(),
		"downloads": filepath.Join(home, "Downloads"),
	})
}

func (s *Server) pcStartAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     string `json:"id"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, "parâmetros inválidos", http.StatusBadRequest)
		return
	}
	if err := s.pcRunner.Start(body.ID, body.Target, winapi.IsAdmin()); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, s.pcRunner.Status())
}

func (s *Server) pcReveal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil || !filepath.IsAbs(body.Path) {
		http.Error(w, "caminho inválido", http.StatusBadRequest)
		return
	}
	if err := pc.RevealFile(body.Path); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
