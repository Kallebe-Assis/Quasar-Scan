// Package netinfo coleta a configuração de rede da própria máquina (Fase 1):
// interfaces, MAC, IPv4/IPv6, máscara, gateway, DNS e DHCP.
package netinfo

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	gaaFlagIncludePrefix   = 0x0010
	gaaFlagIncludeGateways = 0x0080

	adapterDHCPEnabled = 0x0004

	ifTypeEthernet = 6
	ifTypeWifi     = 71
	ifTypeLoopback = 24
	ifTypeTunnel   = 131
	ifTypePPP      = 23
	ifTypeVirtual  = 53
)

type IPAddr struct {
	Address   string `json:"address"`
	PrefixLen int    `json:"prefixLen"`
	Mask      string `json:"mask,omitempty"`   // só IPv4
	Network   string `json:"network"`          // ex: 192.168.1.0/24
	Scope     string `json:"scope,omitempty"`  // IPv6: global, link-local, ULA
	Origin    string `json:"origin,omitempty"` // dhcp, manual, slaac...
}

type DHCPInfo struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	ServerV6      string `json:"serverV6,omitempty"`
	LeaseObtained string `json:"leaseObtained,omitempty"`
	LeaseExpires  string `json:"leaseExpires,omitempty"`
}

type Interface struct {
	Index       uint32   `json:"index"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	MAC         string   `json:"mac,omitempty"`
	MTU         uint32   `json:"mtu"`
	SpeedMbps   uint64   `json:"speedMbps"`
	Virtual     bool     `json:"virtual"`
	IPv4        []IPAddr `json:"ipv4"`
	IPv6        []IPAddr `json:"ipv6"`
	Gateways    []string `json:"gateways"`
	DNSServers  []string `json:"dnsServers"`
	DNSSuffix   string   `json:"dnsSuffix,omitempty"`
	DHCP        DHCPInfo `json:"dhcp"`
	Metric      uint32   `json:"metric"`
	IsPrimary   bool     `json:"isPrimary"` // interface usada para sair para a internet
}

// Interfaces lista todas as placas de rede (físicas e virtuais).
func Interfaces() ([]Interface, error) {
	addrs, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	leases := dhcpLeases()

	var list []Interface
	for aa := addrs; aa != nil; aa = aa.Next {
		if aa.IfType == ifTypeLoopback {
			continue
		}
		it := Interface{
			Index:       aa.IfIndex,
			Name:        windows.UTF16PtrToString(aa.FriendlyName),
			Description: windows.UTF16PtrToString(aa.Description),
			Type:        ifTypeName(aa.IfType),
			Status:      operStatus(aa.OperStatus),
			MTU:         aa.Mtu,
			SpeedMbps:   aa.TransmitLinkSpeed / 1_000_000,
			DNSSuffix:   windows.UTF16PtrToString(aa.DnsSuffix),
			Metric:      aa.Ipv4Metric,
			Gateways:    []string{},
			DNSServers:  []string{},
			IPv4:        []IPAddr{},
			IPv6:        []IPAddr{},
		}
		if aa.PhysicalAddressLength > 0 {
			it.MAC = net.HardwareAddr(aa.PhysicalAddress[:aa.PhysicalAddressLength]).String()
		}
		it.Virtual = isVirtual(it.Description, aa.IfType)

		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := sockaddrToAddr(ua.Address)
			if !ip.IsValid() {
				continue
			}
			a := IPAddr{
				Address:   ip.String(),
				PrefixLen: int(ua.OnLinkPrefixLength),
				Origin:    prefixOrigin(ua.PrefixOrigin, ua.SuffixOrigin),
			}
			if p, err := ip.Prefix(a.PrefixLen); err == nil {
				a.Network = p.String()
			}
			if ip.Is4() {
				a.Mask = net.IP(net.CIDRMask(a.PrefixLen, 32)).String()
				it.IPv4 = append(it.IPv4, a)
			} else {
				a.Scope = v6Scope(ip)
				it.IPv6 = append(it.IPv6, a)
			}
		}
		for gw := aa.FirstGatewayAddress; gw != nil; gw = gw.Next {
			if ip := sockaddrToAddr(gw.Address); ip.IsValid() {
				it.Gateways = append(it.Gateways, ip.String())
			}
		}
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			if ip := sockaddrToAddr(dns.Address); ip.IsValid() && !isSiteLocalDNSPlaceholder(ip) {
				it.DNSServers = append(it.DNSServers, ip.String())
			}
		}

		it.DHCP.Enabled = aa.Flags&adapterDHCPEnabled != 0
		if ip := sockaddrToAddr(aa.Dhcpv4Server); ip.IsValid() && !ip.IsUnspecified() {
			it.DHCP.Server = ip.String()
		}
		if ip := sockaddrToAddr(aa.Dhcpv6Server); ip.IsValid() && !ip.IsUnspecified() {
			it.DHCP.ServerV6 = ip.String()
		}
		if l, ok := leases[aa.IfIndex]; ok && it.DHCP.Enabled {
			it.DHCP.LeaseObtained = l[0]
			it.DHCP.LeaseExpires = l[1]
		}
		list = append(list, it)
	}

	markPrimary(list)
	return list, nil
}

// markPrimary marca como principal a interface ativa com gateway IPv4 e menor métrica.
func markPrimary(list []Interface) {
	best := -1
	for i, it := range list {
		if it.Status != "up" || len(it.IPv4) == 0 || !hasV4(it.Gateways) {
			continue
		}
		if best == -1 || it.Metric < list[best].Metric {
			best = i
		}
	}
	if best >= 0 {
		list[best].IsPrimary = true
	}
}

func hasV4(addrs []string) bool {
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
			return true
		}
	}
	return false
}

func adapterAddresses() (*windows.IpAdapterAddresses, error) {
	size := uint32(16 * 1024)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			gaaFlagIncludePrefix|gaaFlagIncludeGateways, 0, aa, &size)
		if err == nil {
			return aa, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer insuficiente")
}

// dhcpLeases usa a API antiga GetAdaptersInfo, a única que expõe as datas da concessão DHCP.
func dhcpLeases() map[uint32][2]string {
	res := map[uint32][2]string{}
	size := uint32(16 * 1024)
	var buf []byte
	for i := 0; i < 5; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersInfo((*windows.IpAdapterInfo)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return res
		}
	}
	for ai := (*windows.IpAdapterInfo)(unsafe.Pointer(&buf[0])); ai != nil; ai = ai.Next {
		if ai.DhcpEnabled == 0 || ai.LeaseObtained == 0 {
			continue
		}
		res[ai.Index] = [2]string{
			time.Unix(ai.LeaseObtained, 0).Format(time.RFC3339),
			time.Unix(ai.LeaseExpires, 0).Format(time.RFC3339),
		}
	}
	return res
}

func sockaddrToAddr(sa windows.SocketAddress) netip.Addr {
	if sa.Sockaddr == nil {
		return netip.Addr{}
	}
	switch sa.Sockaddr.Addr.Family {
	case windows.AF_INET:
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom4(p.Addr)
	case windows.AF_INET6:
		p := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom16(p.Addr)
	}
	return netip.Addr{}
}

// O Windows lista fec0:0:0:ffff::1/2/3 como DNS padrão quando não há DNS IPv6 configurado.
func isSiteLocalDNSPlaceholder(ip netip.Addr) bool {
	b := ip.As16()
	return ip.Is6() && b[0] == 0xfe && b[1] == 0xc0
}

func v6Scope(ip netip.Addr) string {
	switch {
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.As16()[0]&0xfe == 0xfc:
		return "ULA (privado)"
	case ip.IsGlobalUnicast():
		return "global"
	}
	return "outro"
}

func prefixOrigin(prefix, suffix int32) string {
	switch {
	case prefix == 3 || suffix == 3: // IpPrefixOriginDhcp / IpSuffixOriginDhcp
		return "dhcp"
	case prefix == 1: // Manual
		return "manual"
	case prefix == 4 && suffix == 6: // RouterAdvertisement + Random
		return "slaac (temporário)"
	case prefix == 4:
		return "slaac"
	case prefix == 2: // WellKnown
		return "automático"
	}
	return ""
}

func ifTypeName(t uint32) string {
	switch t {
	case ifTypeEthernet:
		return "Ethernet"
	case ifTypeWifi:
		return "Wi-Fi"
	case ifTypeTunnel:
		return "Túnel"
	case ifTypePPP:
		return "PPP"
	case ifTypeVirtual:
		return "Virtual"
	}
	return fmt.Sprintf("Outro (%d)", t)
}

func operStatus(s uint32) string {
	switch s {
	case 1:
		return "up"
	case 2:
		return "down"
	case 7:
		return "lowerlayerdown"
	}
	return "unknown"
}

func isVirtual(desc string, t uint32) bool {
	if t == ifTypeTunnel || t == ifTypeVirtual {
		return true
	}
	for _, k := range []string{"Virtual", "Hyper-V", "VMware", "VirtualBox", "TAP", "WireGuard",
		"Bluetooth", "Loopback", "Wintun", "Npcap", "WAN Miniport", "Teredo", "ISATAP", "Docker", "WSL"} {
		if containsFold(desc, k) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
