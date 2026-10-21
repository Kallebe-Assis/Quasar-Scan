package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetInterfaceInfo = iphlpapi.NewProc("GetInterfaceInfo")
	procIpReleaseAddress = iphlpapi.NewProc("IpReleaseAddress")
	procIpRenewAddress   = iphlpapi.NewProc("IpRenewAddress")
)

// IsAdmin indica se o processo está rodando elevado (como administrador).
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

type ipAdapterIndexMap struct {
	Index uint32
	Name  [128]uint16
}

// RenewIP libera e renova o IP DHCP de uma interface (ipconfig /release + /renew).
// Exige administrador.
func RenewIP(ifIndex uint32) error {
	size := uint32(4096)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		ret, _, _ := procGetInterfaceInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		if ret == 0 {
			break
		}
		if windows.Errno(ret) != windows.ERROR_INSUFFICIENT_BUFFER {
			return fmt.Errorf("GetInterfaceInfo: %v", windows.Errno(ret))
		}
	}
	count := *(*int32)(unsafe.Pointer(&buf[0]))
	maps := unsafe.Slice((*ipAdapterIndexMap)(unsafe.Pointer(&buf[4])), count)
	for i := range maps {
		if maps[i].Index != ifIndex {
			continue
		}
		// A falha do release é ignorada: a interface pode já estar sem IP.
		procIpReleaseAddress.Call(uintptr(unsafe.Pointer(&maps[i])))
		if ret, _, _ := procIpRenewAddress.Call(uintptr(unsafe.Pointer(&maps[i]))); ret != 0 {
			return fmt.Errorf("o servidor DHCP não respondeu à renovação (%v)", windows.Errno(ret))
		}
		return nil
	}
	return fmt.Errorf("interface %d não usa DHCP ou não foi encontrada", ifIndex)
}

var procSetThreadExecutionState = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadExecutionState")

// KeepAwake impede (on=true) ou volta a permitir a suspensão do computador.
// Vale para a thread atual: quem chama deve usar runtime.LockOSThread.
func KeepAwake(on bool) {
	const esContinuous, esSystemRequired = 0x80000000, 0x00000001
	flags := uintptr(esContinuous)
	if on {
		flags |= esSystemRequired
	}
	procSetThreadExecutionState.Call(flags)
}
