package scan

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Port é uma porta TCP encontrada aberta.
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// CommonPorts são as portas verificadas por padrão nos hosts da LAN. A escolha
// privilegia o que ajuda a identificar o equipamento e o que é risco de segurança.
var CommonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	53:    "DNS",
	80:    "HTTP",
	135:   "MS-RPC",
	139:   "NetBIOS",
	443:   "HTTPS",
	445:   "SMB (compartilhamento)",
	554:   "RTSP (câmera)",
	631:   "IPP (impressora)",
	1883:  "MQTT (IoT)",
	3389:  "RDP (área de trabalho remota)",
	5000:  "UPnP / NAS",
	5357:  "WSD (Windows)",
	7547:  "TR-069 (gerência do provedor)",
	8000:  "HTTP alternativo / DVR",
	8008:  "Chromecast / Smart TV",
	8009:  "Chromecast / Smart TV",
	8080:  "HTTP alternativo",
	8291:  "Winbox (MikroTik)",
	8443:  "HTTPS alternativo",
	8728:  "API MikroTik",
	9100:  "Impressão RAW",
	37777: "DVR Intelbras/Dahua",
	62078: "iPhone/iPad (sync)",
}

// ScanPorts faz TCP connect nas portas informadas e devolve as abertas.
func ScanPorts(ip netip.Addr, ports map[int]string, timeout time.Duration) []Port {
	var (
		mu   sync.Mutex
		open = []Port{}
		wg   sync.WaitGroup
	)
	for p, svc := range ports {
		wg.Add(1)
		go func(p int, svc string) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)), timeout)
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, Port{Port: p, Service: svc})
			mu.Unlock()
		}(p, svc)
	}
	wg.Wait()
	slices.SortFunc(open, func(a, b Port) int { return a.Port - b.Port })
	return open
}
