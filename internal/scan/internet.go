package scan

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// InternetStatus resume o acesso à internet. Todos os testes são opcionais:
// sem internet, a varredura local continua e o usuário é avisado.
type InternetStatus struct {
	Online     bool   `json:"online"`
	IPv4       bool   `json:"ipv4"`
	IPv6       bool   `json:"ipv6"`
	DNSWorks   bool   `json:"dnsWorks"`
	PublicIPv4 string `json:"publicIPv4,omitempty"`
	PublicIPv6 string `json:"publicIPv6,omitempty"`
	Message    string `json:"message"`
}

// CheckInternet testa conectividade IPv4/IPv6, resolução DNS e descobre o IP público.
func CheckInternet() InternetStatus {
	var st InternetStatus
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); st.IPv4 = dialAny("tcp4", "1.1.1.1:443", "8.8.8.8:443") }()
	go func() {
		defer wg.Done()
		st.IPv6 = dialAny("tcp6", "[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443")
	}()
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := net.DefaultResolver.LookupHost(ctx, "www.google.com")
		st.DNSWorks = err == nil
	}()
	go func() {
		defer wg.Done()
		st.PublicIPv4 = publicIP("tcp4", "https://1.1.1.1/cdn-cgi/trace")
	}()
	wg.Wait()
	if st.IPv6 {
		st.PublicIPv6 = publicIP("tcp6", "https://[2606:4700:4700::1111]/cdn-cgi/trace")
	}

	st.Online = st.IPv4 || st.IPv6
	switch {
	case !st.Online:
		st.Message = "Sem acesso à internet. Testes externos (IP público, portas WAN) foram ignorados; a varredura local foi feita normalmente."
	case !st.DNSWorks:
		st.Message = "Há conexão com a internet, mas a resolução DNS falhou: verifique os servidores DNS configurados."
	case !st.IPv6:
		st.Message = "Internet OK via IPv4. Sem conectividade IPv6."
	default:
		st.Message = "Internet OK (IPv4 e IPv6)."
	}
	return st
}

func dialAny(network string, addrs ...string) bool {
	for _, a := range addrs {
		c, err := net.DialTimeout(network, a, 3*time.Second)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// publicIP usa o endpoint /cdn-cgi/trace da Cloudflare, que devolve "ip=<seu IP>".
func publicIP(network, url string) string {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			return v
		}
	}
	return ""
}
