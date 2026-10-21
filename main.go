// Quasar Scan — ferramenta local de descoberta e diagnóstico de rede.
// Abre um servidor web apenas em 127.0.0.1 e a interface no navegador padrão.
// Compilado sem console (-H windowsgui) e pedindo administrador (manifesto no .syso):
// erros aparecem em caixa de mensagem.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"quasarscan/internal/web"
)

const appName = "Quasar Scan"

func main() {
	port := flag.Int("porta", 8765, "porta local da interface web")
	noBrowser := flag.Bool("sem-navegador", false, "não abrir o navegador automaticamente")
	flag.Parse()

	exe, _ := os.Executable()
	// Já está aberto? Então só mostra a interface de novo.
	if existing := runningInstance(*port); existing != "" {
		openBrowser(existing)
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		// Porta ocupada ou reservada pelo Windows (Hyper-V/WSL reservam faixas): usa uma livre.
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			fail("Não foi possível iniciar o servidor local:\n" + err.Error())
		}
	}
	saveInstancePort(ln.Addr().(*net.TCPAddr).Port)
	url := fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{}
	app := web.New(filepath.Join(filepath.Dir(exe), "relatorios"), func() {
		go func() {
			time.Sleep(300 * time.Millisecond) // deixa a resposta chegar ao navegador
			srv.Shutdown(context.Background())
		}()
	})
	srv.Handler = app.Handler()

	if !*noBrowser {
		openBrowser(url)
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fail(err.Error())
	}
}

// instanceFile guarda a porta em uso, para o segundo clique no ícone achar a
// instância aberta mesmo quando ela não conseguiu usar a porta padrão.
func instanceFile() string {
	dir, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "QuasarScan", "porta.txt")
}

func saveInstancePort(port int) {
	if f := instanceFile(); f != "" {
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, []byte(strconv.Itoa(port)), 0o644)
	}
}

// runningInstance devolve a URL de uma instância já aberta, ou "".
func runningInstance(defaultPort int) string {
	ports := []int{defaultPort}
	if f := instanceFile(); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && p != defaultPort {
				ports = append([]int{p}, ports...)
			}
		}
	}
	for _, p := range ports {
		url := fmt.Sprintf("http://127.0.0.1:%d/", p)
		if isRunning(url) {
			return url
		}
	}
	return ""
}

func isRunning(url string) bool {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url + "api/info")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Confirma que é o Quasar Scan, e não outro programa na mesma porta.
	var info struct {
		Computer *string `json:"computer"`
	}
	return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&info) == nil && info.Computer != nil
}

// openBrowser abre a URL no navegador padrão. Como o programa roda como
// administrador, a abertura é delegada ao Explorer (que roda como usuário comum),
// para o navegador não herdar a elevação.
func openBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString("explorer.exe")
	args, _ := windows.UTF16PtrFromString(url)
	if windows.ShellExecute(0, verb, file, args, nil, windows.SW_SHOWNORMAL) != nil {
		target, _ := windows.UTF16PtrFromString(url)
		windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
	}
}

func fail(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(appName)
	windows.MessageBox(0, t, c, windows.MB_OK|windows.MB_ICONERROR)
	os.Exit(1)
}
