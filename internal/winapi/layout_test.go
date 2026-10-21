package winapi

import (
	"testing"
	"unsafe"
)

// Os tamanhos precisam bater com wlanapi.h, senão os campos são lidos deslocados.
func TestWlanLayout(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"WLAN_INTERFACE_INFO", unsafe.Sizeof(wlanInterfaceInfo{}), 532},
		{"WLAN_CONNECTION_ATTRIBUTES", unsafe.Sizeof(wlanConnectionAttributes{}), 604},
		{"WLAN_BSS_ENTRY", unsafe.Sizeof(wlanBssEntry{}), 360},
		{"BSS.CenterFreqKHz offset", unsafe.Offsetof(wlanBssEntry{}.CenterFreqKHz), 92},
		{"BSS.RSSI offset", unsafe.Offsetof(wlanBssEntry{}.RSSI), 56},
		{"CONN.SignalQuality offset", unsafe.Offsetof(wlanConnectionAttributes{}.SignalQuality), 576},
		{"CONN.AuthAlgorithm offset", unsafe.Offsetof(wlanConnectionAttributes{}.AuthAlgorithm), 596},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, esperado %d", c.name, c.got, c.want)
		}
	}
}
