package pc

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Flag é um alerta sobre um item (processo, serviço, inicialização).
type Flag struct {
	Level string `json:"level"` // critico, aviso, info
	Text  string `json:"text"`
}

// Finding é um ponto do relatório da inspeção.
type Finding struct {
	Level    string `json:"level"` // critico, aviso, info
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Path     string `json:"path,omitempty"`
}

// Check é um item da conferência de proteção do computador.
type Check struct {
	Item   string `json:"item"`
	Status string `json:"status"` // ok, info, aviso, critico
	Value  string `json:"value"`
	Detail string `json:"detail,omitempty"`
}

var (
	systemRoot = strings.ToLower(os.Getenv("SystemRoot"))
	// Nomes de processos do Windows que malware costuma imitar.
	systemNames = map[string]bool{"svchost.exe": true, "lsass.exe": true, "csrss.exe": true, "winlogon.exe": true,
		"services.exe": true, "smss.exe": true, "wininit.exe": true, "spoolsv.exe": true, "explorer.exe": true,
		"taskhostw.exe": true, "dllhost.exe": true, "conhost.exe": true, "rundll32.exe": true, "lsm.exe": true,
		"sihost.exe": true, "ctfmon.exe": true, "runtimebroker.exe": true, "dwm.exe": true, "searchindexer.exe": true}
	// Comandos típicos de malware ("viver da terra": usar ferramentas do próprio Windows).
	lolbins = []struct {
		re  *regexp.Regexp
		why string
	}{
		{regexp.MustCompile(`(?i)powershell(\.exe)?["']?\s.*(-e(nc|ncodedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|-w(indowstyle)?\s+h(idden)?)`), "PowerShell com comando oculto/codificado ou baixando da internet"},
		{regexp.MustCompile(`(?i)mshta(\.exe)?["']?\s+(https?:|javascript:|vbscript:)`), "mshta executando script da internet"},
		{regexp.MustCompile(`(?i)regsvr32(\.exe)?["']?\s.*/i:\s*https?:|scrobj\.dll`), "regsvr32 carregando script remoto"},
		{regexp.MustCompile(`(?i)rundll32(\.exe)?["']?\s+(javascript:|.*url\.dll.*https?:|.*\\(temp|appdata)\\)`), "rundll32 executando script ou DLL de pasta temporária"},
		{regexp.MustCompile(`(?i)certutil(\.exe)?["']?\s.*-urlcache`), "certutil baixando arquivo da internet"},
		{regexp.MustCompile(`(?i)bitsadmin(\.exe)?["']?\s.*/transfer`), "bitsadmin baixando arquivo"},
		{regexp.MustCompile(`(?i)(wscript|cscript)(\.exe)?["']?\s.*\\(appdata|temp|users\\public|programdata)\\.*\.(vbs|vbe|js|jse|wsf)`), "script VBS/JS rodando de pasta de usuário"},
		{regexp.MustCompile(`(?i)cmd(\.exe)?["']?\s+/c\s+.*(https?:|\\appdata\\.*\.(bat|cmd|vbs|ps1))`), "cmd executando script de pasta de usuário ou da internet"},
	}
	// Domínios que nunca deveriam estar no arquivo hosts (redirecionamento = golpe).
	sensitiveHosts = regexp.MustCompile(`(?i)(google|gmail|youtube|facebook|instagram|whatsapp|microsoft|windowsupdate|live\.com|outlook|office|apple|icloud|bb\.com\.br|itau|bradesco|caixa|santander|nubank|bancointer|inter\.co|sicoob|sicredi|mercadopago|paypal|gov\.br|avast|kaspersky|eset|norton|mcafee|malwarebytes)`)
	benignHosts    = regexp.MustCompile(`(?i)(docker\.internal|kubernetes|localhost|\.local$|\.lan$|\.home$|wpad)`)
)

// zone classifica de onde o executável roda.
func zone(path string) string {
	p := strings.ToLower(path)
	switch {
	case p == "":
		return ""
	case strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`):
		return "temp"
	case strings.Contains(p, `\$recycle.bin\`) || strings.Contains(p, `\downloads\`) || strings.Contains(p, `\users\public\`):
		return "suspeita"
	case strings.Contains(p, `\appdata\`):
		return "usuario"
	case strings.HasPrefix(p, systemRoot+`\`):
		return "windows"
	case strings.Contains(p, `\program files`):
		return "programas"
	case strings.Contains(p, `\programdata\`):
		return "programdata"
	}
	return "outro"
}

var zoneNames = map[string]string{"temp": "pasta temporária", "suspeita": "pasta de downloads/lixeira/pública",
	"usuario": "pasta do usuário (AppData)", "programdata": "ProgramData", "outro": "fora das pastas de programas"}

func lolbin(cmd string) string {
	for _, l := range lolbins {
		if l.re.MatchString(cmd) {
			return l.why
		}
	}
	return ""
}

// signatureFlags aplica as regras de assinatura e local do executável.
func signatureFlags(path string, sig Signature, what string) []Flag {
	var f []Flag
	z := zone(path)
	switch sig.Status {
	case "invalido":
		f = append(f, Flag{"critico", "Assinatura digital inválida ou adulterada: o arquivo foi modificado depois de assinado."})
	case "sem-assinatura":
		switch z {
		case "temp", "suspeita":
			f = append(f, Flag{"critico", fmt.Sprintf("%s sem assinatura digital rodando de %s.", what, zoneNames[z])})
		case "usuario", "programdata", "outro":
			f = append(f, Flag{"aviso", fmt.Sprintf("%s sem assinatura digital em %s.", what, zoneNames[z])})
		case "windows":
			f = append(f, Flag{"aviso", what + " sem assinatura dentro da pasta do Windows. Os arquivos do próprio Windows são assinados; drivers antigos de terceiros (impressoras, por exemplo) às vezes não, mas é também onde malware se esconde. Confira de que programa é."})
		default:
			f = append(f, Flag{"info", what + " sem assinatura digital."})
		}
	}
	return f
}

func analyzeStartup(items []StartupItem, self string) {
	for i := range items {
		it := &items[i]
		if strings.EqualFold(it.Path, self) {
			continue
		}
		if it.Kind == "winlogon" {
			v := strings.ToLower(strings.TrimRight(strings.TrimSpace(it.Command), ","))
			ok := (it.Name == "Shell" && v == "explorer.exe") ||
				(it.Name == "Userinit" && (v == systemRoot+`\system32\userinit.exe` || v == `c:\windows\system32\userinit.exe`))
			if !ok {
				it.Flags = append(it.Flags, Flag{"critico", fmt.Sprintf("Winlogon %s alterado (o padrão é %s). Técnica clássica de malware para rodar a cada login.",
					it.Name, map[string]string{"Shell": "explorer.exe", "Userinit": `C:\Windows\system32\userinit.exe,`}[it.Name])})
			}
			continue
		}
		if why := lolbin(it.Command); why != "" {
			it.Flags = append(it.Flags, Flag{"critico", "Comando suspeito: " + why + "."})
		}
		if it.Signature.Status == "inexistente" {
			it.Flags = append(it.Flags, Flag{"info", "O arquivo não existe mais: resto de programa desinstalado (pode ser removido)."})
			continue
		}
		it.Flags = append(it.Flags, signatureFlags(it.Path, it.Signature, "Programa de inicialização")...)
		if it.Kind == "tarefa" && it.Hidden && !it.Signature.Signed() {
			it.Flags = append(it.Flags, Flag{"aviso", "Tarefa agendada oculta executando programa sem assinatura."})
		}
	}
}

func analyzeProcesses(procs []Process, selfPID int) {
	for i := range procs {
		p := &procs[i]
		if int(p.PID) == selfPID || p.Path == "" {
			continue
		}
		name := strings.ToLower(p.Name)
		dir := strings.ToLower(filepath.Dir(p.Path))
		if systemNames[name] {
			expected := dir == systemRoot+`\system32` || dir == systemRoot+`\syswow64` || (name == "explorer.exe" && dir == systemRoot)
			if !expected {
				p.Flags = append(p.Flags, Flag{"critico", fmt.Sprintf("%s é um nome de processo do Windows, mas está rodando de %s. Disfarce típico de malware.", p.Name, filepath.Dir(p.Path))})
			}
		}
		p.Flags = append(p.Flags, signatureFlags(p.Path, p.Signature, "Processo")...)
		if !p.Signature.Signed() && p.Signature.Status != "inexistente" && len(p.Remote) > 0 {
			p.Flags = append(p.Flags, Flag{"aviso", fmt.Sprintf("Processo sem assinatura conectado à internet (%s).", strings.Join(first(p.Remote, 3), ", "))})
		}
	}
}

func analyzeServices(svcs []Service, self string) {
	for i := range svcs {
		s := &svcs[i]
		if strings.EqualFold(s.Path, self) {
			continue
		}
		if why := lolbin(s.Command); why != "" {
			s.Flags = append(s.Flags, Flag{"critico", "Comando suspeito no serviço: " + why + "."})
		}
		if s.Signature.Status == "inexistente" {
			if s.StartType != "Desativado" && !strings.Contains(strings.ToLower(s.Command), `\system32\svchost.exe`) {
				s.Flags = append(s.Flags, Flag{"info", "O executável do serviço não existe: resto de programa desinstalado."})
			}
			continue
		}
		what := "Serviço"
		if s.DLL {
			what = "DLL do serviço"
		}
		s.Flags = append(s.Flags, signatureFlags(s.Path, s.Signature, what)...)
		// Caminho com espaço e sem aspas: o Windows pode executar "C:\Program.exe" no lugar.
		cmd := strings.TrimSpace(s.Command)
		if !strings.HasPrefix(cmd, `"`) && zone(s.Path) != "windows" {
			if exe := strings.Index(strings.ToLower(cmd), ".exe"); exe > 0 && strings.Contains(cmd[:exe], " ") {
				s.Flags = append(s.Flags, Flag{"info", "Caminho do serviço com espaços e sem aspas (brecha conhecida de segurança)."})
			}
		}
	}
}

func first(list []string, n int) []string {
	if len(list) > n {
		return list[:n]
	}
	return list
}
