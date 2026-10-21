package scan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// DHCPOffer é a resposta (OFFER) de um servidor DHCP ao nosso DISCOVER de teste.
type DHCPOffer struct {
	Server    string   `json:"server"`    // identificador do servidor (opção 54)
	From      string   `json:"from"`      // IP de origem do pacote
	OfferedIP string   `json:"offeredIp"` // IP que ele daria
	Mask      string   `json:"mask,omitempty"`
	Router    string   `json:"router,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	LeaseSecs uint32   `json:"leaseSecs,omitempty"`
}

// DetectDHCP envia um DHCP DISCOVER com um MAC fictício e coleta todas as ofertas.
// Mais de um servidor respondendo = DHCP duplicado (ex.: roteador do cliente ligado
// pela porta LAN). Só envia DISCOVER: nenhum IP é de fato reservado ou alterado.
// Exige administrador (a porta 68 é privilegiada no Windows).
//
// exclude são as redes das outras placas desta máquina (Hyper-V, WSL, VPN): ofertas
// vindas delas são do próprio computador, não da rede do cliente.
func DetectDHCP(prefix netip.Prefix, exclude []netip.Prefix, wait time.Duration) ([]DHCPOffer, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			serr = windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
			if serr == nil {
				serr = windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
			}
		})
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
	if err != nil {
		return nil, fmt.Errorf("não foi possível usar a porta 68 do DHCP: %v", err)
	}
	defer pc.Close()

	var mac [6]byte
	rand.Read(mac[:])
	mac[0] = (mac[0] | 0x02) &^ 0x01 // MAC localmente administrado e unicast
	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	pkt := make([]byte, 240, 300)
	pkt[0], pkt[1], pkt[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, MAC de 6 bytes
	binary.BigEndian.PutUint32(pkt[4:], xid)
	binary.BigEndian.PutUint16(pkt[10:], 0x8000) // pede resposta em broadcast
	copy(pkt[28:], mac[:])
	copy(pkt[236:], []byte{99, 130, 83, 99}) // magic cookie
	pkt = append(pkt, 53, 1, 1)              // DHCPDISCOVER
	pkt = append(pkt, 61, 7, 1)              // client identifier
	pkt = append(pkt, mac[:]...)
	pkt = append(pkt, 12, 11)
	pkt = append(pkt, []byte("quasar-scan")...)   // hostname (11 bytes)
	pkt = append(pkt, 55, 6, 1, 3, 6, 15, 51, 54) // parâmetros pedidos
	pkt = append(pkt, 255)
	for len(pkt) < 300 {
		pkt = append(pkt, 0)
	}

	// Broadcast dirigido à sub-rede (sai pela interface certa) e broadcast geral.
	targets := []string{"255.255.255.255:67"}
	if prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() < 31 {
		b := prefix.Masked().Addr().As4()
		hostBits := 32 - prefix.Bits()
		v := binary.BigEndian.Uint32(b[:]) | (1<<hostBits - 1)
		binary.BigEndian.PutUint32(b[:], v)
		targets = append([]string{netip.AddrFrom4(b).String() + ":67"}, targets...)
	}
	for _, t := range targets {
		addr, _ := net.ResolveUDPAddr("udp4", t)
		pc.WriteTo(pkt, addr)
	}

	seen := map[string]bool{}
	var offers []DHCPOffer
	pc.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		o, ok := parseOffer(buf[:n], xid)
		if !ok {
			continue
		}
		o.From = from.(*net.UDPAddr).IP.String()
		if fromLocalVirtual(o.From, exclude) {
			continue
		}
		if o.Server == "" {
			o.Server = o.From
		}
		if seen[o.Server] {
			continue
		}
		seen[o.Server] = true
		offers = append(offers, o)
	}
	return offers, nil
}

func parseOffer(b []byte, xid uint32) (DHCPOffer, bool) {
	var o DHCPOffer
	if len(b) < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:]) != xid {
		return o, false
	}
	o.OfferedIP = net.IP(b[16:20]).String()
	isOffer := false
	for i := 240; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		v := b[i+2 : i+2+l]
		switch code {
		case 53:
			isOffer = l == 1 && v[0] == 2
		case 54:
			if l == 4 {
				o.Server = net.IP(v).String()
			}
		case 1:
			if l == 4 {
				o.Mask = net.IP(v).String()
			}
		case 3:
			if l >= 4 {
				o.Router = net.IP(v[:4]).String()
			}
		case 6:
			for j := 0; j+4 <= l; j += 4 {
				o.DNS = append(o.DNS, net.IP(v[j:j+4]).String())
			}
		case 51:
			if l == 4 {
				o.LeaseSecs = binary.BigEndian.Uint32(v)
			}
		}
		i += 2 + l
	}
	return o, isOffer
}

func fromLocalVirtual(ip string, exclude []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range exclude {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
