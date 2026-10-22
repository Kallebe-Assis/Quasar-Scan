package pc

import (
	"bytes"
	"encoding/xml"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// StartupItem é algo que o Windows executa sozinho (ao ligar, ao entrar ou agendado).
type StartupItem struct {
	Kind      string    `json:"kind"` // registro, pasta, tarefa, winlogon
	Location  string    `json:"location"`
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	Path      string    `json:"path"`
	Enabled   bool      `json:"enabled"`
	Hidden    bool      `json:"hidden,omitempty"`
	Author    string    `json:"author,omitempty"`
	Signature Signature `json:"signature"`
	Flags     []Flag    `json:"flags"`
}

var runKeys = []struct {
	root  registry.Key
	label string
	path  string
}{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
}

// CollectStartup lista os programas de inicialização automática.
func CollectStartup() []StartupItem {
	items := []StartupItem{}

	for _, rk := range runKeys {
		k, err := registry.OpenKey(rk.root, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			cmd, _, err := k.GetStringValue(n)
			if err != nil || cmd == "" {
				continue
			}
			items = append(items, StartupItem{Kind: "registro", Location: rk.label + `\` + rk.path, Name: n, Command: cmd,
				Enabled: startupApproved(rk.root, rk.path, n)})
		}
		k.Close()
	}

	// Winlogon: malware costuma trocar o Shell (explorer.exe) ou acrescentar algo ao Userinit.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE); err == nil {
		for _, n := range []string{"Shell", "Userinit"} {
			if v, _, err := k.GetStringValue(n); err == nil {
				items = append(items, StartupItem{Kind: "winlogon", Location: `HKLM\...\Winlogon`, Name: n, Command: v, Enabled: true})
			}
		}
		k.Close()
	}

	for _, dir := range []struct{ path, loc string }{
		{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), "Inicializar (usuário)"},
		{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`), "Inicializar (todos)"},
	} {
		entries, _ := os.ReadDir(dir.path)
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(dir.path, e.Name())
			cmd := full
			if strings.EqualFold(filepath.Ext(full), ".lnk") {
				if t := shortcutTarget(full); t != "" {
					cmd = t
				}
			}
			items = append(items, StartupItem{Kind: "pasta", Location: dir.loc, Name: e.Name(), Command: cmd, Enabled: true})
		}
	}

	items = append(items, collectTasks()...)

	for i := range items {
		items[i].Flags = []Flag{}
		items[i].Path = ExePath(items[i].Command)
	}
	return items
}

// startupApproved lê se o item foi desativado pelo Gerenciador de Tarefas.
func startupApproved(root registry.Key, runPath, name string) bool {
	sub := "Run"
	if strings.Contains(runPath, "WOW6432Node") {
		sub = "Run32"
	}
	k, err := registry.OpenKey(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue(name)
	if err != nil || len(v) == 0 {
		return true
	}
	return v[0]&1 == 0 // 0x02/0x06 = ativo; 0x03/0x07 = desativado
}

// shortcutTarget lê o destino de um atalho .lnk pelo componente do próprio Windows.
func shortcutTarget(lnk string) string {
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oe, ok := err.(*ole.OleError); !ok || oe.Code() != 1 { // 1 = S_FALSE, já inicializado
			return ""
		}
	}
	defer ole.CoUninitialize()
	unk, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return ""
	}
	defer unk.Release()
	sh, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return ""
	}
	defer sh.Release()
	v, err := oleutil.CallMethod(sh, "CreateShortcut", lnk)
	if err != nil {
		return ""
	}
	sc := v.ToIDispatch()
	defer sc.Release()
	target, _ := oleutil.GetProperty(sc, "TargetPath")
	args, _ := oleutil.GetProperty(sc, "Arguments")
	t := strings.TrimSpace(target.ToString())
	if a := strings.TrimSpace(args.ToString()); a != "" && t != "" {
		return `"` + t + `" ` + a
	}
	return t
}

// Tarefas agendadas: lê os XML em %SystemRoot%\System32\Tasks (exige administrador).
// As tarefas da própria Microsoft (pasta \Microsoft\) ficam de fora para não poluir a lista.
type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Settings struct {
		Enabled string `xml:"Enabled"`
		Hidden  string `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func collectTasks() []StartupItem {
	var out []StartupItem
	root := filepath.Join(os.Getenv("SystemRoot"), `System32\Tasks`)
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if strings.EqualFold(rel, "Microsoft") {
				return filepath.SkipDir
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var t taskXML
		if decodeTaskXML(raw, &t) != nil {
			return nil
		}
		for _, ex := range t.Actions.Exec {
			cmd := strings.TrimSpace(ex.Command)
			if cmd == "" {
				continue
			}
			if !strings.HasPrefix(cmd, `"`) && strings.Contains(cmd, " ") {
				cmd = `"` + cmd + `"`
			}
			if ex.Arguments != "" {
				cmd += " " + ex.Arguments
			}
			out = append(out, StartupItem{Kind: "tarefa", Location: "Tarefas agendadas", Name: `\` + rel, Command: cmd,
				Enabled: !strings.EqualFold(t.Settings.Enabled, "false"), Hidden: strings.EqualFold(t.Settings.Hidden, "true"),
				Author: t.RegistrationInfo.Author})
		}
		return nil
	})
	return out
}

// Os XML de tarefas são gravados em UTF-16 com BOM.
func decodeTaskXML(raw []byte, t *taskXML) error {
	var data []byte = raw
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		dec, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder(), raw)
		if err != nil {
			return err
		}
		data = dec
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil } // já convertido para UTF-8
	return d.Decode(t)
}

// ExePath extrai o executável de uma linha de comando ("C:\x\y.exe" -a, %SystemRoot%\..., rundll32 x.dll).
func ExePath(cmd string) string {
	cmd = strings.TrimRight(strings.TrimSpace(expandEnv(cmd)), ",") // Userinit termina com vírgula
	if cmd == "" {
		return ""
	}
	var cand string
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			cand = cmd[1 : end+1]
		}
	} else {
		// Sem aspas: tenta prefixos cada vez maiores ("C:\Program Files\App\app.exe -x").
		parts := strings.Fields(cmd)
		for i := len(parts); i >= 1; i-- {
			p := strings.Join(parts[:i], " ")
			if fileExists(p) {
				return p
			}
			if fileExists(p + ".exe") {
				return p + ".exe"
			}
		}
		cand = parts[0]
	}
	cand = strings.Trim(cand, `" `)
	if cand == "" {
		return ""
	}
	if filepath.IsAbs(cand) {
		return cand
	}
	// Nome sem caminho: procura onde o Windows procuraria.
	for _, dir := range []string{filepath.Join(os.Getenv("SystemRoot"), "System32"), os.Getenv("SystemRoot")} {
		for _, name := range []string{cand, cand + ".exe"} {
			if p := filepath.Join(dir, name); fileExists(p) {
				return p
			}
		}
	}
	return cand
}

func expandEnv(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return s
	}
	buf := make([]uint16, 2048)
	n, err := windows.ExpandEnvironmentStrings(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return s
	}
	return windows.UTF16ToString(buf[:n])
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
