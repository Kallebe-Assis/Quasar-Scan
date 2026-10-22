package pc

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Report é o resultado completo da inspeção do computador.
type Report struct {
	StartedAt time.Time     `json:"startedAt"`
	DurationS float64       `json:"durationS"`
	System    SystemInfo    `json:"system"`
	Security  Security      `json:"security"`
	Startup   []StartupItem `json:"startup"`
	Processes []Process     `json:"processes"`
	Services  []Service     `json:"services"`
	Checklist []Check       `json:"checklist"`
	Findings  []Finding     `json:"findings"`
	Score     int           `json:"score"`
	Grade     string        `json:"grade"` // excelente, razoavel, ruim, pessimo
	Summary   string        `json:"summary"`
}

// Steps são as etapas da inspeção, para a barra de progresso.
var Steps = []string{"sistema", "protecao", "inicializacao", "processos", "servicos", "assinaturas", "analise"}

// Inspect executa a inspeção. onStep avisa cada etapa concluída; onProgress, o
// avanço da verificação de assinaturas (a etapa mais demorada).
func Inspect(onStep func(string), onProgress func(done, total int)) Report {
	r := Report{StartedAt: time.Now()}
	self, _ := os.Executable()
	selfPID := os.Getpid()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.System = CollectSystem(); onStep("sistema") }()
	go func() { defer wg.Done(); r.Security = CollectSecurity(); onStep("protecao") }()
	r.Startup = CollectStartup()
	onStep("inicializacao")
	r.Processes = CollectProcesses()
	onStep("processos")
	r.Services = CollectServices()
	onStep("servicos")
	wg.Wait()

	// Assinaturas: cada arquivo só é verificado uma vez, com 8 em paralelo.
	paths := map[string]bool{}
	for _, it := range r.Startup {
		paths[it.Path] = true
	}
	for _, p := range r.Processes {
		paths[p.Path] = true
	}
	for _, s := range r.Services {
		paths[s.Path] = true
	}
	delete(paths, "")
	list := make([]string, 0, len(paths))
	for p := range paths {
		list = append(list, p)
	}
	var done atomic.Int32
	jobs := make(chan string)
	var sw sync.WaitGroup
	for w := 0; w < 8; w++ {
		sw.Add(1)
		go func() {
			defer sw.Done()
			for p := range jobs {
				VerifyFile(p)
				onProgress(int(done.Add(1)), len(list))
			}
		}()
	}
	for _, p := range list {
		jobs <- p
	}
	close(jobs)
	sw.Wait()
	for i := range r.Startup {
		r.Startup[i].Signature = VerifyFile(r.Startup[i].Path)
	}
	for i := range r.Processes {
		if r.Processes[i].Path != "" {
			r.Processes[i].Signature = VerifyFile(r.Processes[i].Path)
		}
	}
	for i := range r.Services {
		r.Services[i].Signature = VerifyFile(r.Services[i].Path)
	}
	onStep("assinaturas")

	analyzeStartup(r.Startup, self)
	analyzeProcesses(r.Processes, selfPID)
	analyzeServices(r.Services, self)
	r.Checklist = checklist(r.System, r.Security)
	r.Findings = findings(&r)
	score(&r)
	onStep("analise")
	r.DurationS = time.Since(r.StartedAt).Seconds()
	return r
}

// checklist é a conferência de proteção do computador.
func checklist(si SystemInfo, sec Security) []Check {
	var c []Check
	add := func(item, status, value, detail string) { c = append(c, Check{item, status, value, detail}) }

	var active []string
	for _, a := range sec.Antivirus {
		if a.Enabled {
			active = append(active, a.Name)
		}
	}
	switch {
	case len(active) > 0:
		add("Antivírus", "ok", strings.Join(active, ", "), "")
	case len(sec.Antivirus) > 0:
		add("Antivírus", "critico", "Desligado", "Há antivírus instalado, mas nenhum está ativo.")
	default:
		add("Antivírus", "critico", "Nenhum", "Nenhum antivírus registrado na Central de Segurança do Windows.")
	}

	d := sec.Defender
	if d.Available {
		passive := strings.Contains(strings.ToLower(d.Mode), "passive") || strings.Contains(strings.ToLower(d.Mode), "passivo")
		switch {
		case passive:
			add("Microsoft Defender", "info", "Modo passivo", "Outro antivírus está protegendo o computador; o Defender fica em segundo plano.")
		case !d.RealTime:
			add("Proteção em tempo real", "critico", "Desligada", "O Defender não está verificando os arquivos ao serem abertos. Religue em Segurança do Windows.")
		default:
			add("Proteção em tempo real", "ok", "Ligada", "")
		}
		if !passive {
			switch {
			case d.SignatureAgeDays < 0:
				add("Definições de vírus", "aviso", "Desconhecida", "")
			case d.SignatureAgeDays <= 3:
				add("Definições de vírus", "ok", fmt.Sprintf("Atualizadas (%s)", d.SignatureUpdated), "")
			case d.SignatureAgeDays <= 7:
				add("Definições de vírus", "aviso", fmt.Sprintf("%d dias", d.SignatureAgeDays), "Atualize as definições do Defender.")
			default:
				add("Definições de vírus", "critico", fmt.Sprintf("%d dias", d.SignatureAgeDays), "Definições muito antigas: o antivírus não reconhece ameaças recentes.")
			}
			switch {
			case d.QuickScanAgeDays < 0:
				add("Última verificação", "aviso", "Nunca", "Faça uma verificação rápida.")
			case d.QuickScanAgeDays <= 14:
				add("Última verificação", "ok", fmt.Sprintf("Há %d dia(s)", d.QuickScanAgeDays), "")
			default:
				add("Última verificação", "aviso", fmt.Sprintf("Há %d dias", d.QuickScanAgeDays), "Faça uma verificação rápida.")
			}
			if !d.TamperProtected {
				add("Proteção contra violações", "aviso", "Desligada", "Programas maliciosos podem desligar o Defender. Ative em Segurança do Windows.")
			}
		}
	}

	active = active[:0]
	for _, t := range sec.Threats {
		if t.Active || !t.Cleaned {
			active = append(active, t.Name)
		}
	}
	if len(active) > 0 {
		add("Ameaças ativas", "critico", fmt.Sprintf("%d", len(active)), "O Defender encontrou ameaças que ainda não foram removidas: "+strings.Join(active, ", "))
	} else if len(sec.Threats) > 0 {
		add("Ameaças ativas", "ok", "Nenhuma", fmt.Sprintf("%d ameaça(s) no histórico, todas removidas.", len(sec.Threats)))
	}

	off := []string{}
	for _, f := range si.Firewall {
		if !f.Enabled {
			off = append(off, f.Profile)
		}
	}
	switch {
	case len(off) == 0:
		add("Firewall do Windows", "ok", "Ligado", "")
	case contains(off, "Pública"):
		add("Firewall do Windows", "critico", "Desligado: "+strings.Join(off, ", "), "Sem firewall na rede pública o computador fica exposto em redes de terceiros.")
	default:
		add("Firewall do Windows", "aviso", "Desligado: "+strings.Join(off, ", "), "")
	}

	if si.UAC {
		add("Controle de Conta (UAC)", "ok", "Ligado", "")
	} else {
		add("Controle de Conta (UAC)", "critico", "Desligado", "Qualquer programa roda como administrador sem perguntar.")
	}

	switch {
	case sec.UpdateAgeDays < 0:
		add("Atualizações do Windows", "info", "Desconhecida", "")
	case sec.UpdateAgeDays <= 45:
		add("Atualizações do Windows", "ok", "Última há "+plural(sec.UpdateAgeDays, "dia"), "")
	case sec.UpdateAgeDays <= 90:
		add("Atualizações do Windows", "aviso", "Última há "+plural(sec.UpdateAgeDays, "dia"), "Verifique o Windows Update.")
	default:
		add("Atualizações do Windows", "critico", "Última há "+plural(sec.UpdateAgeDays, "dia"), "Windows sem atualizações de segurança há mais de 3 meses.")
	}
	if si.RebootPending {
		add("Reinicialização pendente", "aviso", "Sim", "Há atualizações esperando o computador reiniciar para concluir.")
	}

	for _, dk := range si.Disks {
		switch {
		case dk.FreePct < 5:
			add("Espaço em disco "+dk.Drive, "critico", fmt.Sprintf("%.1f GB livres (%d%%)", dk.FreeGB, dk.FreePct), "Quase sem espaço: o Windows fica lento e não consegue se atualizar.")
		case dk.FreePct < 10:
			add("Espaço em disco "+dk.Drive, "aviso", fmt.Sprintf("%.1f GB livres (%d%%)", dk.FreeGB, dk.FreePct), "Pouco espaço livre.")
		default:
			add("Espaço em disco "+dk.Drive, "ok", fmt.Sprintf("%.0f GB livres (%d%%)", dk.FreeGB, dk.FreePct), "")
		}
	}
	if si.RAMUsedPct >= 90 {
		add("Memória RAM", "aviso", fmt.Sprintf("%d%% em uso de %.0f GB", si.RAMUsedPct, si.RAMTotalGB), "Memória quase cheia: lentidão. Veja os processos abertos.")
	} else {
		add("Memória RAM", "ok", fmt.Sprintf("%d%% em uso de %.0f GB", si.RAMUsedPct, si.RAMTotalGB), "")
	}
	if si.UptimeHours > 14*24 {
		add("Tempo ligado", "info", plural(int(si.UptimeHours/24), "dia"), "Reiniciar de vez em quando aplica atualizações e libera memória.")
	}
	if si.SecureBoot != nil && !*si.SecureBoot {
		add("Secure Boot", "info", "Desligado", "Protege contra malware que se instala antes do Windows. Ativável na BIOS/UEFI.")
	}
	if si.Proxy.Enabled || si.Proxy.AutoURL != "" {
		v := si.Proxy.Server
		if v == "" {
			v = si.Proxy.AutoURL
		}
		add("Proxy do navegador", "aviso", v, "Todo o tráfego web passa por esse proxy. Se o cliente não configurou, pode ser adware/malware interceptando a navegação.")
	}
	return c
}

// findings junta os alertas de todos os itens numa lista única, do mais grave ao menos.
func findings(r *Report) []Finding {
	out := []Finding{}
	for _, it := range r.Startup {
		for _, f := range it.Flags {
			out = append(out, Finding{f.Level, "Inicialização", it.Name, f.Text, it.Path})
		}
	}
	for _, p := range r.Processes {
		for _, f := range p.Flags {
			out = append(out, Finding{f.Level, "Processo", fmt.Sprintf("%s (PID %d)", p.Name, p.PID), f.Text, p.Path})
		}
	}
	for _, s := range r.Services {
		for _, f := range s.Flags {
			out = append(out, Finding{f.Level, "Serviço", s.DisplayName, f.Text, s.Path})
		}
	}
	for _, h := range r.System.Hosts {
		host := strings.Fields(h)[1:]
		name := strings.Join(host, " ")
		switch {
		case sensitiveHosts.MatchString(name):
			out = append(out, Finding{"critico", "Arquivo hosts", name, "O arquivo hosts redireciona " + name + " para " + strings.Fields(h)[0] + ". Golpe comum para roubar senhas ou bloquear antivírus.", ""})
		case benignHosts.MatchString(name):
		default:
			out = append(out, Finding{"info", "Arquivo hosts", name, "Entrada personalizada no arquivo hosts: " + h, ""})
		}
	}
	for _, t := range r.Security.Threats {
		if t.Active || !t.Cleaned {
			out = append(out, Finding{"critico", "Ameaça do Defender", t.Name, "Ameaça detectada e não removida. Arquivos: " + strings.Join(t.Resources, "; "), first(t.Resources, 1)[0]})
		}
	}
	rank := map[string]int{"critico": 0, "aviso": 1, "info": 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Level] < rank[out[j].Level] })
	return out
}

// score dá a nota de 0 a 100: começa em 100 e desconta por problema.
func score(r *Report) {
	s := 100
	var crit, warn int
	for _, f := range r.Findings {
		switch f.Level {
		case "critico":
			crit++
		case "aviso":
			warn++
		}
	}
	for _, c := range r.Checklist {
		switch c.Status {
		case "critico":
			crit++
		case "aviso":
			warn++
		}
	}
	s -= min(crit*20, 70) + min(warn*5, 30)
	r.Score = max(s, 0)
	switch {
	case r.Score >= 85:
		r.Grade = "excelente"
	case r.Score >= 70:
		r.Grade = "razoavel"
	case r.Score >= 50:
		r.Grade = "ruim"
	default:
		r.Grade = "pessimo"
	}
	switch {
	case crit > 0:
		graves := "1 problema grave"
		if crit > 1 {
			graves = fmt.Sprintf("%d problemas graves", crit)
		}
		r.Summary = fmt.Sprintf("%s e %s para revisar.", graves, plural(warn, "aviso"))
	case warn > 0:
		r.Summary = fmt.Sprintf("Nenhum problema grave; %s para revisar.", plural(warn, "aviso"))
	default:
		r.Summary = "Nenhum problema encontrado: proteção ativa e nada suspeito em execução."
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
