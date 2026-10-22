package pc

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process é um processo em execução, com o executável e as conexões de rede.
type Process struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Signature Signature `json:"signature"`
	Listening []string  `json:"listening"` // portas abertas esperando conexão
	Remote    []string  `json:"remote"`    // conexões estabelecidas com IPs públicos
	Flags     []Flag    `json:"flags"`
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// CollectProcesses lista os processos em execução e associa as conexões TCP de cada um.
func CollectProcesses() []Process {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return []Process{}
	}
	defer windows.CloseHandle(snap)

	byPID := map[uint32]*Process{}
	var list []*Process
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := &Process{PID: e.ProcessID, PPID: e.ParentProcessID, Name: windows.UTF16ToString(e.ExeFile[:]),
			Listening: []string{}, Remote: []string{}, Flags: []Flag{}}
		if p.PID != 0 && p.PID != 4 {
			p.Path = processPath(p.PID)
		}
		byPID[p.PID] = p
		list = append(list, p)
	}

	for _, c := range tcpConnections() {
		p, ok := byPID[c.pid]
		if !ok {
			continue
		}
		switch {
		case c.state == 2: // LISTEN
			port := fmt.Sprint(c.local.Port())
			if !contains(p.Listening, port) {
				p.Listening = append(p.Listening, port)
			}
		case c.state == 5 && isPublic(c.remote.Addr()): // ESTABLISHED com a internet
			r := c.remote.String()
			if !contains(p.Remote, r) && len(p.Remote) < 20 {
				p.Remote = append(p.Remote, r)
			}
		}
	}

	out := make([]Process, 0, len(list))
	for _, p := range list {
		sort.Slice(p.Listening, func(i, j int) bool {
			return len(p.Listening[i]) < len(p.Listening[j]) || p.Listening[i] < p.Listening[j]
		})
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

type tcpConn struct {
	local, remote netip.AddrPort
	state         uint32
	pid           uint32
}

// tcpConnections lê as tabelas TCP (IPv4 e IPv6) com o PID dono de cada conexão.
func tcpConnections() []tcpConn {
	var out []tcpConn
	for _, af := range []uint32{windows.AF_INET, windows.AF_INET6} {
		size := uint32(64 * 1024)
		var buf []byte
		for i := 0; i < 4; i++ {
			buf = make([]byte, size)
			// TCP_TABLE_OWNER_PID_ALL = 5
			r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), 5, 0)
			if r == 0 {
				break
			}
			if windows.Errno(r) != windows.ERROR_INSUFFICIENT_BUFFER {
				buf = nil
				break
			}
		}
		if len(buf) < 4 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(buf))
		if af == windows.AF_INET {
			// MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 x uint32)
			for i := 0; i < n; i++ {
				o := 4 + i*24
				if o+24 > len(buf) {
					break
				}
				row := buf[o : o+24]
				var la, ra [4]byte
				copy(la[:], row[4:8])
				copy(ra[:], row[12:16])
				out = append(out, tcpConn{
					state:  binary.LittleEndian.Uint32(row[0:]),
					local:  netip.AddrPortFrom(netip.AddrFrom4(la), port(row[8:12])),
					remote: netip.AddrPortFrom(netip.AddrFrom4(ra), port(row[16:20])),
					pid:    binary.LittleEndian.Uint32(row[20:]),
				})
			}
		} else {
			// MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid (56 bytes)
			for i := 0; i < n; i++ {
				o := 4 + i*56
				if o+56 > len(buf) {
					break
				}
				row := buf[o : o+56]
				var la, ra [16]byte
				copy(la[:], row[0:16])
				copy(ra[:], row[24:40])
				out = append(out, tcpConn{
					local:  netip.AddrPortFrom(netip.AddrFrom16(la).Unmap(), port(row[20:24])),
					remote: netip.AddrPortFrom(netip.AddrFrom16(ra).Unmap(), port(row[44:48])),
					state:  binary.LittleEndian.Uint32(row[48:]),
					pid:    binary.LittleEndian.Uint32(row[52:]),
				})
			}
		}
	}
	return out
}

// As portas vêm em ordem de rede nos 2 primeiros bytes do DWORD.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func isPublic(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip) && !ip.IsLoopback()
}
