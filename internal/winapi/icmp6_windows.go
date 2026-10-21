package winapi

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procIcmp6CreateFile = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmp6SendEcho2  = iphlpapi.NewProc("Icmp6SendEcho2")
)

// ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX é empacotado (26 bytes: porta 2, flowinfo 4,
// endereço 16, scope 4); Status e RoundTripTime vêm depois, alinhados em 4.
const (
	icmp6AddrOff   = 6
	icmp6StatusOff = 28
	icmp6RTTOff    = 32
)

// echo6 envia um ICMPv6 Echo Request. O TTL vira o "hop limit" (traceroute IPv6).
func echo6(ip netip.Addr, opt EchoOptions) (EchoReply, error) {
	if opt.Size <= 0 {
		opt.Size = 32
	}
	if opt.Timeout <= 0 {
		opt.Timeout = time.Second
	}
	h, _, err := procIcmp6CreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return EchoReply{}, err
	}
	defer procIcmpCloseHandle.Call(h)

	src := windows.RawSockaddrInet6{Family: windows.AF_INET6}
	dst := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: ip.As16()}
	if z, err := strconv.Atoi(ip.Zone()); err == nil {
		dst.Scope_id = uint32(z)
	}
	payload := make([]byte, opt.Size)
	for i := range payload {
		payload[i] = byte('a' + i%23)
	}
	var opts uintptr
	if opt.TTL > 0 {
		opts = uintptr(unsafe.Pointer(&ipOptionInformation{Ttl: opt.TTL}))
	}
	reply := make([]byte, 64+opt.Size+64)
	n, _, callErr := procIcmp6SendEcho2.Call(
		h, 0, 0, 0,
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&dst)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		opts,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(opt.Timeout.Milliseconds()),
	)
	var addr [16]byte
	copy(addr[:], reply[icmp6AddrOff:icmp6AddrOff+16])
	from := netip.AddrFrom16(addr)
	status := binary.LittleEndian.Uint32(reply[icmp6StatusOff:])
	if n == 0 && from.IsUnspecified() {
		if errno, ok := callErr.(windows.Errno); ok && errno != 0 {
			return EchoReply{Status: uint32(errno)}, fmt.Errorf("%s", StatusText(uint32(errno)))
		}
		return EchoReply{Status: StatusTimedOut}, fmt.Errorf("%s", StatusText(StatusTimedOut))
	}
	rtt := time.Duration(binary.LittleEndian.Uint32(reply[icmp6RTTOff:])) * time.Millisecond
	if rtt == 0 {
		rtt = 500 * time.Microsecond
	}
	res := EchoReply{From: from, RTT: rtt, Status: status}
	if status != StatusSuccess && status != StatusTTLExpired {
		return res, fmt.Errorf("%s", StatusText(status))
	}
	return res, nil
}
