package scan

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ReverseDNS tenta obter o nome do host pelo DNS (PTR). Muitos roteadores
// registram o hostname que o cliente informou no DHCP.
func ReverseDNS(ip netip.Addr, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// NetBIOSInfo é o resultado de uma consulta NBSTAT (UDP 137).
type NetBIOSInfo struct {
	Name      string
	Workgroup string
}

// NetBIOS consulta o nome NetBIOS do host (Windows, Samba, NAS, várias impressoras).
// Funciona sem DNS e sem internet.
func NetBIOS(ip netip.Addr, timeout time.Duration) (NetBIOSInfo, bool) {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip.String(), "137"), timeout)
	if err != nil {
		return NetBIOSInfo{}, false
	}
	defer conn.Close()

	id := uint16(rand.IntN(0xffff))
	req := []byte{
		byte(id >> 8), byte(id), // transaction id
		0x00, 0x00, // flags
		0x00, 0x01, // 1 pergunta
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, // tamanho do nome codificado
	}
	// Nome "*" com 15 bytes nulos, codificado em "first-level encoding".
	req = append(req, 'C', 'K')
	for i := 0; i < 15; i++ {
		req = append(req, 'A', 'A')
	}
	req = append(req, 0x00, 0x00, 0x21, 0x00, 0x01) // fim do nome, tipo NBSTAT, classe IN

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return NetBIOSInfo{}, false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return NetBIOSInfo{}, false
	}
	buf = buf[:n]

	// cabeçalho(12) + nome(34) + tipo(2) + classe(2) + ttl(4) + rdlength(2) = 56
	count := int(buf[56])
	var info NetBIOSInfo
	for i := 0; i < count; i++ {
		off := 57 + i*18
		if off+18 > len(buf) {
			break
		}
		name := strings.TrimRight(string(buf[off:off+15]), " \x00")
		suffix := buf[off+15]
		group := buf[off+16]&0x80 != 0
		if suffix != 0x00 {
			continue
		}
		if !group && info.Name == "" {
			info.Name = name
		} else if group && info.Workgroup == "" {
			info.Workgroup = name
		}
	}
	return info, info.Name != ""
}
