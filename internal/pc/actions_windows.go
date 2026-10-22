package pc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

// Action é uma ferramenta oficial do Windows que a aba pode executar.
type Action struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Command string `json:"command"` // equivalente para rodar no CMD (como administrador)
	Admin   bool   `json:"admin"`
	Changes bool   `json:"changes"` // altera o sistema (pede confirmação na interface)
	Minutes string `json:"minutes"` // duração típica
}

var Actions = []Action{
	{"defender-rapida", "Verificação rápida do Defender", `MpCmdRun -Scan -ScanType 1`, false, false, "2 a 10 min"},
	{"defender-completa", "Verificação completa do Defender", `MpCmdRun -Scan -ScanType 2`, false, false, "30 min a horas"},
	{"defender-pasta", "Verificar uma pasta com o Defender", `MpCmdRun -Scan -ScanType 3 -File <pasta>`, false, false, "depende da pasta"},
	{"defender-atualizar", "Atualizar definições de vírus", `MpCmdRun -SignatureUpdate`, false, false, "1 a 3 min"},
	{"sfc-verificar", "Verificar arquivos do Windows (SFC)", `sfc /verifyonly`, true, false, "5 a 15 min"},
	{"sfc-reparar", "Reparar arquivos do Windows (SFC)", `sfc /scannow`, true, true, "10 a 20 min"},
	{"dism-verificar", "Verificar imagem do Windows (DISM)", `DISM /Online /Cleanup-Image /ScanHealth`, true, false, "5 a 20 min"},
	{"dism-reparar", "Reparar imagem do Windows (DISM)", `DISM /Online /Cleanup-Image /RestoreHealth`, true, true, "10 a 30 min (usa internet)"},
}

// Job é a execução de uma ação.
type Job struct {
	Action   Action    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Running  bool      `json:"running"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Lines    []string  `json:"lines"`
	Progress string    `json:"progress,omitempty"`
	ExitCode int       `json:"exitCode"`
	Level    string    `json:"level,omitempty"` // ok, aviso, critico
	Result   string    `json:"result,omitempty"`
}

// Runner garante uma ação por vez (o Defender e o SFC não rodam em paralelo).
type Runner struct {
	mu  sync.Mutex
	job *Job
	cmd *exec.Cmd
}

// Status devolve uma cópia da ação atual ou da última.
func (r *Runner) Status() *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.job == nil {
		return nil
	}
	j := *r.job
	j.Lines = append(make([]string, 0, len(r.job.Lines)), r.job.Lines...) // nunca nil: vira [] no JSON
	return &j
}

// Cancel interrompe a ação em andamento.
func (r *Runner) Cancel() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		r.cmd.Process.Kill()
	}
}

// Start inicia uma ação. target é a pasta, para "defender-pasta".
func (r *Runner) Start(id, target string, admin bool) error {
	var act *Action
	for i := range Actions {
		if Actions[i].ID == id {
			act = &Actions[i]
		}
	}
	if act == nil {
		return fmt.Errorf("ação desconhecida")
	}
	if act.Admin && !admin {
		return fmt.Errorf("esta verificação exige que o Quasar Scan esteja rodando como administrador")
	}
	exe, args, err := commandFor(id, target)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.job != nil && r.job.Running {
		return fmt.Errorf("já há uma verificação em andamento: %s", r.job.Action.Title)
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("não foi possível iniciar: %v", err)
	}
	r.cmd = cmd
	r.job = &Job{Action: *act, Target: target, Running: true, Started: time.Now(), Lines: []string{}}
	job := r.job

	go r.read(job, pr)
	go func() {
		err := cmd.Wait()
		pw.Close()
		time.Sleep(200 * time.Millisecond) // deixa a leitura terminar
		r.mu.Lock()
		defer r.mu.Unlock()
		job.Running = false
		job.Finished = time.Now()
		job.ExitCode = cmd.ProcessState.ExitCode()
		if err != nil && job.ExitCode == -1 {
			job.Level, job.Result = "aviso", "Interrompido."
		} else {
			job.Level, job.Result = interpret(id, job.ExitCode, job.Lines)
		}
		r.cmd = nil
	}()
	return nil
}

// read separa a saída em linhas (o SFC e o DISM usam \r para atualizar o percentual).
func (r *Runner) read(job *Job, rd io.Reader) {
	br := bufio.NewReader(rd)
	var raw bytes.Buffer
	var utf16 *bool
	flush := func(final bool) {
		data := raw.Bytes()
		if utf16 == nil && len(data) >= 4 {
			b := bytes.Count(data[:min(len(data), 200)], []byte{0}) > len(data[:min(len(data), 200)])/4
			utf16 = &b
		}
		text := decodeConsole(data, utf16 != nil && *utf16)
		raw.Reset()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, part := range strings.FieldsFunc(text, func(c rune) bool { return c == '\r' || c == '\n' }) {
			line := strings.TrimSpace(strings.ReplaceAll(part, "\x00", ""))
			if line == "" {
				continue
			}
			if strings.Contains(line, "%") && len(line) < 80 && !final {
				job.Progress = line
				continue
			}
			job.Lines = append(job.Lines, line)
			if len(job.Lines) > 300 {
				job.Lines = job.Lines[len(job.Lines)-300:]
			}
		}
	}
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		raw.Write(buf[:n])
		// Processa até o último separador de linha completo.
		if i := bytes.LastIndexAny(raw.Bytes(), "\r\n"); i >= 0 && (utf16 == nil || !*utf16 || i%2 == 1) {
			rest := append([]byte(nil), raw.Bytes()[i+1:]...)
			raw.Truncate(i + 1)
			flush(false)
			raw.Write(rest)
		}
		if err != nil {
			flush(true)
			return
		}
	}
}

// decodeConsole converte a saída: o SFC escreve em UTF-16; os demais, na página de código
// do console (850 no Windows em português).
func decodeConsole(b []byte, utf16 bool) string {
	if utf16 {
		if out, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(b); err == nil {
			return string(out)
		}
	}
	if utf8.Valid(b) {
		return string(b)
	}
	out, _ := charmap.CodePage850.NewDecoder().Bytes(b)
	return string(out)
}

func commandFor(id, target string) (string, []string, error) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	switch id {
	case "defender-rapida":
		return mpCmdRun(), []string{"-Scan", "-ScanType", "1"}, nil
	case "defender-completa":
		return mpCmdRun(), []string{"-Scan", "-ScanType", "2"}, nil
	case "defender-pasta":
		st, err := os.Stat(target)
		if err != nil || !st.IsDir() {
			return "", nil, fmt.Errorf("pasta não encontrada: %s", target)
		}
		return mpCmdRun(), []string{"-Scan", "-ScanType", "3", "-File", target}, nil
	case "defender-atualizar":
		return mpCmdRun(), []string{"-SignatureUpdate"}, nil
	case "sfc-verificar":
		return filepath.Join(sys, "sfc.exe"), []string{"/verifyonly"}, nil
	case "sfc-reparar":
		return filepath.Join(sys, "sfc.exe"), []string{"/scannow"}, nil
	case "dism-verificar":
		return filepath.Join(sys, "Dism.exe"), []string{"/Online", "/Cleanup-Image", "/ScanHealth"}, nil
	case "dism-reparar":
		return filepath.Join(sys, "Dism.exe"), []string{"/Online", "/Cleanup-Image", "/RestoreHealth"}, nil
	}
	return "", nil, fmt.Errorf("ação desconhecida")
}

// mpCmdRun usa a versão mais nova da plataforma do Defender (atualizada pelo Windows Update).
func mpCmdRun() string {
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows Defender\Platform\*\MpCmdRun.exe`))
	sort.Strings(matches)
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return filepath.Join(os.Getenv("ProgramFiles"), `Windows Defender\MpCmdRun.exe`)
}

// interpret traduz o resultado de cada ferramenta.
func interpret(id string, code int, lines []string) (string, string) {
	all := strings.ToLower(strings.Join(lines, " "))
	has := func(ks ...string) bool {
		for _, k := range ks {
			if strings.Contains(all, k) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.HasPrefix(id, "defender-") && id != "defender-atualizar":
		switch code {
		case 0:
			return "ok", "Nenhuma ameaça encontrada."
		case 2:
			return "critico", "O Defender encontrou ameaças. Veja a lista de ameaças e confirme se foram removidas em Segurança do Windows."
		}
		return "aviso", fmt.Sprintf("A verificação terminou com erro (código %d). Confira a saída abaixo.", code)
	case id == "defender-atualizar":
		if code == 0 {
			return "ok", "Definições de vírus atualizadas."
		}
		return "aviso", fmt.Sprintf("Não foi possível atualizar (código %d). O computador está com internet?", code)
	case strings.HasPrefix(id, "sfc"):
		switch {
		case has("não encontrou nenhuma violação", "did not find any integrity violations"):
			return "ok", "Nenhum arquivo do Windows corrompido."
		case has("reparou", "successfully repaired"):
			return "ok", "Arquivos corrompidos foram encontrados e reparados. Reinicie o computador."
		case has("não conseguiu corrigir", "unable to fix", "não foi possível reparar"):
			return "critico", "Há arquivos corrompidos que o SFC não conseguiu reparar. Rode o reparo do DISM e depois o SFC novamente."
		case has("encontrou violações", "found integrity violations", "violações de integridade"):
			return "aviso", "Há arquivos do Windows corrompidos. Use “Reparar arquivos do Windows (SFC)”."
		case has("administrador", "administrator"):
			return "aviso", "Exige administrador."
		}
		return "aviso", "Verificação concluída; leia a saída abaixo."
	case strings.HasPrefix(id, "dism"):
		switch {
		case code != 0:
			return "aviso", fmt.Sprintf("O DISM terminou com erro (código %d).", code)
		case has("reparável", "repairable"):
			return "aviso", "A imagem do Windows está danificada, mas pode ser reparada: use “Reparar imagem do Windows (DISM)”."
		case has("restauração", "restore operation completed", "concluída com êxito", "completed successfully"):
			return "ok", "Concluído com êxito."
		}
		return "ok", "Nenhum dano encontrado na imagem do Windows."
	}
	return "ok", "Concluído."
}

// OpenSecurityCenter abre o aplicativo Segurança do Windows.
func OpenSecurityCenter() error { return shellOpen("windowsdefender:", "") }

// RevealFile abre o Explorer com o arquivo selecionado.
func RevealFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("arquivo não encontrado")
	}
	return shellOpen("explorer.exe", `/select,"`+path+`"`)
}

func shellOpen(file, args string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	f, _ := windows.UTF16PtrFromString(file)
	var a *uint16
	if args != "" {
		a, _ = windows.UTF16PtrFromString(args)
	}
	return windows.ShellExecute(0, verb, f, a, nil, windows.SW_SHOWNORMAL)
}
