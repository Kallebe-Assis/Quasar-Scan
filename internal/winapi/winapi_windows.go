// Package winapi expõe as APIs nativas do Windows (iphlpapi/dnsapi/wlanapi) usadas
// pelas ferramentas: ICMP (ping/traceroute/MTU), ARP, rotas, cache DNS, DHCP e Wi-Fi.
// Só a renovação de IP exige administrador.
package winapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile        = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle       = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho          = iphlpapi.NewProc("IcmpSendEcho")
	procSendARP               = iphlpapi.NewProc("SendARP")
	procGetIpNetTable         = iphlpapi.NewProc("GetIpNetTable")
	procGetIpForwardTable     = iphlpapi.NewProc("GetIpForwardTable")
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

// Códigos de status do ICMP (ipexport.h).
const (
	StatusSuccess         = 0
	StatusNetUnreachable  = 11002
	StatusHostUnreachable = 11003
	StatusPacketTooBig    = 11009
	StatusTimedOut        = 11010
	StatusTTLExpired      = 11013
)

type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// EchoOptions configura um ICMP Echo. TTL 0 usa o padrão do sistema.
// DontFragment liga o bit DF (só IPv4), usado no teste de MTU.
type EchoOptions struct {
	TTL          uint8
	Size         int
	Timeout      time.Duration
	DontFragment bool
}

const ipFlagDF = 0x02

// options monta a IP_OPTION_INFORMATION; nil usa os padrões do Windows.
func (o EchoOptions) options() *ipOptionInformation {
	if o.TTL == 0 && !o.DontFragment {
		return nil
	}
	opt := &ipOptionInformation{Ttl: o.TTL}
	if opt.Ttl == 0 {
		opt.Ttl = 128
	}
	if o.DontFragment {
		opt.Flags = ipFlagDF
	}
	return opt
}

// EchoReply é a resposta de um ICMP Echo. From é quem respondeu: o destino, ou o
// roteador intermediário quando Status == StatusTTLExpired (base do traceroute).
type EchoReply struct {
	From   netip.Addr
	RTT    time.Duration
	TTL    uint8
	Status uint32
}

// Echo envia um ICMP Echo Request (IcmpSendEcho para IPv4, Icmp6SendEcho2 para IPv6).
func Echo(ip netip.Addr, opt EchoOptions) (EchoReply, error) {
	ip = ip.Unmap()
	if ip.Is6() {
		return echo6(ip, opt)
	}
	if opt.Size <= 0 {
		opt.Size = 32 // mesmo padrão do ping do Windows
	}
	if opt.Timeout <= 0 {
		opt.Timeout = time.Second
	}
	h, _, err := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return EchoReply{}, err
	}
	defer procIcmpCloseHandle.Call(h)

	payload := make([]byte, opt.Size)
	for i := range payload {
		payload[i] = byte('a' + i%23)
	}
	var opts uintptr
	if o := opt.options(); o != nil {
		opts = uintptr(unsafe.Pointer(o))
	}
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+opt.Size+64)
	n, _, callErr := procIcmpSendEcho.Call(
		h,
		uintptr(addrToUint32(ip)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		opts,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(opt.Timeout.Milliseconds()),
	)
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	// Em "TTL expirado" algumas versões do Windows devolvem 0 mas preenchem o buffer.
	if n == 0 && r.Address == 0 {
		if errno, ok := callErr.(windows.Errno); ok && errno != 0 {
			return EchoReply{Status: uint32(errno)}, fmt.Errorf("%s", StatusText(uint32(errno)))
		}
		return EchoReply{Status: StatusTimedOut}, fmt.Errorf("%s", StatusText(StatusTimedOut))
	}
	var from [4]byte
	binary.LittleEndian.PutUint32(from[:], r.Address)
	rtt := time.Duration(r.RoundTripTime) * time.Millisecond
	if rtt == 0 {
		rtt = 500 * time.Microsecond // a API arredonda para ms; "<1ms"
	}
	res := EchoReply{From: netip.AddrFrom4(from), RTT: rtt, TTL: r.Options.Ttl, Status: r.Status}
	if r.Status != StatusSuccess && r.Status != StatusTTLExpired {
		return res, fmt.Errorf("%s", StatusText(r.Status))
	}
	return res, nil
}

// Ping é um Echo simples, usado pela varredura da rede.
func Ping(ip netip.Addr, timeout time.Duration) (EchoReply, error) {
	r, err := Echo(ip, EchoOptions{Timeout: timeout})
	if err == nil && r.Status != StatusSuccess {
		err = fmt.Errorf("%s", StatusText(r.Status))
	}
	return r, err
}

// StatusText traduz o status ICMP para a mensagem que o técnico vê no ping do Windows.
func StatusText(s uint32) string {
	switch s {
	case StatusSuccess:
		return "Resposta"
	case StatusNetUnreachable:
		return "Rede de destino inacessível"
	case StatusHostUnreachable:
		return "Host de destino inacessível"
	case StatusTimedOut:
		return "Esgotado o tempo limite do pedido"
	case StatusTTLExpired:
		return "TTL expirado no trânsito"
	case StatusPacketTooBig:
		return "O pacote precisa ser fragmentado, mas o DF está ativo"
	case 11050:
		return "Falha geral"
	}
	return fmt.Sprintf("Erro ICMP %d", s)
}

// ARP resolve o MAC de um IP da rede local via SendARP.
func ARP(ip netip.Addr) (net.HardwareAddr, error) {
	var mac [8]byte
	size := uint32(len(mac))
	ret, _, _ := procSendARP.Call(
		uintptr(addrToUint32(ip)),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}
	if size < 6 {
		return nil, fmt.Errorf("MAC inválido")
	}
	return net.HardwareAddr(mac[:6]), nil
}

// ARPEntry é uma linha da tabela ARP (equivale ao "arp -a").
type ARPEntry struct {
	IfIndex uint32 `json:"ifIndex"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Type    string `json:"type"`
}

type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

// ARPTable lê a tabela ARP do Windows.
func ARPTable() ([]ARPEntry, error) {
	buf, err := fetchTable(procGetIpNetTable)
	if err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := unsafe.Slice((*mibIPNetRow)(unsafe.Pointer(&buf[4])), count)
	types := map[uint32]string{1: "outro", 2: "inválido", 3: "dinâmico", 4: "estático"}
	list := make([]ARPEntry, 0, count)
	for _, r := range rows {
		e := ARPEntry{IfIndex: r.Index, IP: uint32ToAddr(r.Addr).String(), Type: types[r.Type]}
		if r.PhysAddrLen >= 6 {
			e.MAC = net.HardwareAddr(r.PhysAddr[:6]).String()
		}
		list = append(list, e)
	}
	return list, nil
}

// Route é uma linha da tabela de rotas IPv4 (equivale ao "route print").
type Route struct {
	Destination string `json:"destination"`
	PrefixLen   int    `json:"prefixLen"`
	Mask        string `json:"mask"`
	NextHop     string `json:"nextHop"`
	IfIndex     uint32 `json:"ifIndex"`
	Metric      uint32 `json:"metric"`
	Protocol    string `json:"protocol"`
}

type mibIPForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAS uint32
	Metric1, Metric2, Metric3, Metric4, Metric5                       uint32
}

// Routes lê a tabela de rotas IPv4.
func Routes() ([]Route, error) {
	buf, err := fetchTable(procGetIpForwardTable)
	if err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := unsafe.Slice((*mibIPForwardRow)(unsafe.Pointer(&buf[4])), count)
	protos := map[uint32]string{2: "local", 3: "configurada", 4: "ICMP", 8: "RIP", 13: "OSPF", 14: "BGP"}
	list := make([]Route, 0, count)
	for _, r := range rows {
		maskIP := uint32ToAddr(r.Mask)
		ones, _ := net.IPMask(maskIP.AsSlice()).Size()
		p := protos[r.Proto]
		if p == "" {
			p = "automática"
		}
		list = append(list, Route{
			Destination: uint32ToAddr(r.Dest).String(),
			PrefixLen:   ones,
			Mask:        maskIP.String(),
			NextHop:     uint32ToAddr(r.NextHop).String(),
			IfIndex:     r.IfIndex,
			Metric:      r.Metric1,
			Protocol:    p,
		})
	}
	return list, nil
}

// FlushDNSCache limpa o cache do cliente DNS (equivale ao "ipconfig /flushdns").
func FlushDNSCache() error {
	ok, _, err := procDnsFlushResolverCache.Call()
	if ok == 0 {
		return fmt.Errorf("DnsFlushResolverCache: %v", err)
	}
	return nil
}

// fetchTable chama as APIs GetIp*Table(buffer, &tamanho, ordenar) até o buffer bastar.
func fetchTable(proc *windows.LazyProc) ([]byte, error) {
	size := uint32(16 * 1024)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
		switch windows.Errno(ret) {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue
		default:
			return nil, windows.Errno(ret)
		}
	}
	return nil, fmt.Errorf("tabela grande demais")
}

// in_addr em ordem de rede, lido como uint32 little-endian.
func addrToUint32(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.LittleEndian.Uint32(b[:])
}

func uint32ToAddr(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
