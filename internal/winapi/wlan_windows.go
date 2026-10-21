package winapi

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wlanapi                   = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle        = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle       = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces    = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface    = wlanapi.NewProc("WlanQueryInterface")
	procWlanScan              = wlanapi.NewProc("WlanScan")
	procWlanGetNetworkBssList = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanFreeMemory        = wlanapi.NewProc("WlanFreeMemory")
)

// Opcodes de WlanQueryInterface (wlanapi.h).
const (
	opCurrentConnection = 7
	opChannelNumber     = 8
	opRSSI              = 0x10000102
)

type dot11SSID struct {
	Length uint32
	SSID   [32]byte
}

type wlanInterfaceInfo struct {
	GUID        windows.GUID
	Description [256]uint16
	State       uint32
}

type wlanConnectionAttributes struct {
	State       uint32
	Mode        uint32
	ProfileName [256]uint16
	// WLAN_ASSOCIATION_ATTRIBUTES
	SSID          dot11SSID
	BssType       uint32
	BSSID         [6]byte
	PhyType       uint32
	PhyIndex      uint32
	SignalQuality uint32
	RxRate        uint32 // kbps
	TxRate        uint32 // kbps
	// WLAN_SECURITY_ATTRIBUTES
	SecurityEnabled int32
	OneXEnabled     int32
	AuthAlgorithm   uint32
	CipherAlgorithm uint32
}

type wlanBssEntry struct {
	SSID          dot11SSID
	PhyID         uint32
	BSSID         [6]byte
	BssType       uint32
	PhyType       uint32
	RSSI          int32
	LinkQuality   uint32
	InRegDomain   uint8
	BeaconPeriod  uint16
	Timestamp     uint64
	HostTimestamp uint64
	Capability    uint16
	CenterFreqKHz uint32
	RateSetLength uint32
	RateSet       [126]uint16
	IeOffset      uint32
	IeSize        uint32
}

// WifiConnection descreve a conexão Wi-Fi atual de uma interface.
type WifiConnection struct {
	Interface     string  `json:"interface"`
	State         string  `json:"state"`
	SSID          string  `json:"ssid"`
	BSSID         string  `json:"bssid"`
	SignalPct     int     `json:"signalPct"`
	RSSI          int     `json:"rssi"`
	Channel       int     `json:"channel"`
	BandGHz       float64 `json:"bandGHz"`
	PhyType       string  `json:"phy"`
	RxMbps        float64 `json:"rxMbps"`
	TxMbps        float64 `json:"txMbps"`
	Security      string  `json:"security"`
	Cipher        string  `json:"cipher"`
	SecurityLevel string  `json:"securityLevel"` // ok, fraca, aberta
}

// WifiNetwork é um ponto de acesso visto na varredura (uma BSSID).
type WifiNetwork struct {
	SSID      string  `json:"ssid"`
	BSSID     string  `json:"bssid"`
	RSSI      int     `json:"rssi"`
	Quality   int     `json:"quality"`
	Channel   int     `json:"channel"`
	BandGHz   float64 `json:"bandGHz"`
	PhyType   string  `json:"phy"`
	Connected bool    `json:"connected"`
}

// WifiInterface junta conexão atual e redes vizinhas de uma placa Wi-Fi.
type WifiInterface struct {
	Name       string          `json:"name"`
	GUID       string          `json:"guid"`
	Connection *WifiConnection `json:"connection,omitempty"`
	Networks   []WifiNetwork   `json:"networks"`
	ScanError  string          `json:"scanError,omitempty"`
}

var phyNames = map[uint32]string{1: "FHSS", 2: "DSSS", 4: "802.11a", 5: "802.11b", 6: "802.11g",
	7: "Wi-Fi 4 (802.11n)", 8: "Wi-Fi 5 (802.11ac)", 9: "802.11ad", 10: "Wi-Fi 6 (802.11ax)", 11: "Wi-Fi 7 (802.11be)"}

var authNames = map[uint32]string{1: "Aberta", 2: "WEP compartilhada", 3: "WPA-Enterprise", 4: "WPA-Personal",
	5: "WPA (nenhum)", 6: "WPA2-Enterprise", 7: "WPA2-Personal", 8: "WPA3-Enterprise 192", 9: "WPA3-Personal (SAE)",
	10: "OWE (Enhanced Open)", 11: "WPA3-Enterprise"}

var cipherNames = map[uint32]string{0: "nenhuma", 1: "WEP-40", 2: "TKIP", 4: "AES (CCMP)", 5: "WEP-104",
	6: "AES-256 (BIP)", 8: "GCMP", 9: "GCMP-256", 0x100: "WPA (grupo)", 0x101: "WEP"}

// WifiScan lê a conexão atual e, se scan=true, varre as redes vizinhas (~4 s).
func WifiScan(scan bool) ([]WifiInterface, error) {
	var negotiated uint32
	var h windows.Handle
	if ret, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h))); ret != 0 {
		if windows.Errno(ret) == windows.ERROR_SERVICE_NOT_ACTIVE {
			return nil, fmt.Errorf("serviço de Wi-Fi (WLAN AutoConfig) desativado ou sem placa Wi-Fi")
		}
		return nil, fmt.Errorf("WlanOpenHandle: %v", windows.Errno(ret))
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)

	var list unsafe.Pointer
	if ret, _, _ := procWlanEnumInterfaces.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&list))); ret != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces: %v", windows.Errno(ret))
	}
	defer procWlanFreeMemory.Call(uintptr(list))
	count := *(*uint32)(list)
	infos := unsafe.Slice((*wlanInterfaceInfo)(unsafe.Add(list, 8)), count)

	if scan {
		for i := range infos {
			procWlanScan.Call(uintptr(h), uintptr(unsafe.Pointer(&infos[i].GUID)), 0, 0, 0)
		}
		time.Sleep(4 * time.Second) // o Windows conclui a varredura em até ~4 s
	}

	var out []WifiInterface
	for i := range infos {
		info := &infos[i]
		wi := WifiInterface{Name: windows.UTF16ToString(info.Description[:]), GUID: info.GUID.String(), Networks: []WifiNetwork{}}
		wi.Connection = queryConnection(h, info)
		if scan {
			nets, err := bssList(h, &info.GUID)
			if err != nil {
				wi.ScanError = err.Error()
				if wi.Connection == nil {
					wi.ScanError = "Wi-Fi desligado (rádio inativo). Ligue o Wi-Fi do computador para analisar as redes. Detalhe: " + err.Error()
				}
			}
			for j := range nets {
				if wi.Connection != nil && nets[j].BSSID == wi.Connection.BSSID {
					nets[j].Connected = true
				}
			}
			wi.Networks = nets
		}
		out = append(out, wi)
	}
	return out, nil
}

func queryConnection(h windows.Handle, info *wlanInterfaceInfo) *WifiConnection {
	var size uint32
	var data unsafe.Pointer
	if ret, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(&info.GUID)), opCurrentConnection, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0); ret != 0 {
		return nil // desconectada
	}
	defer procWlanFreeMemory.Call(uintptr(data))
	a := (*wlanConnectionAttributes)(data)
	if a.State != 1 { // wlan_interface_state_connected
		return nil
	}
	c := &WifiConnection{
		Interface: windows.UTF16ToString(info.Description[:]),
		State:     "conectado",
		SSID:      string(a.SSID.SSID[:min(a.SSID.Length, 32)]),
		BSSID:     net.HardwareAddr(a.BSSID[:]).String(),
		SignalPct: int(a.SignalQuality),
		PhyType:   phyNames[a.PhyType],
		RxMbps:    float64(a.RxRate) / 1000,
		TxMbps:    float64(a.TxRate) / 1000,
		Security:  authNames[a.AuthAlgorithm],
		Cipher:    cipherNames[a.CipherAlgorithm],
	}
	switch {
	case a.SecurityEnabled == 0 || a.AuthAlgorithm == 1:
		c.SecurityLevel = "aberta"
	case a.AuthAlgorithm == 2 || a.AuthAlgorithm == 4 || a.AuthAlgorithm == 3 || a.CipherAlgorithm == 1 || a.CipherAlgorithm == 2 || a.CipherAlgorithm == 5:
		c.SecurityLevel = "fraca"
	default:
		c.SecurityLevel = "ok"
	}
	if v, ok := queryUint32(h, info, opChannelNumber); ok {
		c.Channel = int(v)
		c.BandGHz = bandForChannel(c.Channel)
	}
	if v, ok := queryUint32(h, info, opRSSI); ok {
		c.RSSI = int(int32(v))
	} else {
		c.RSSI = c.SignalPct/2 - 100 // aproximação usada pelo próprio Windows
	}
	return c
}

func queryUint32(h windows.Handle, info *wlanInterfaceInfo, op uint32) (uint32, bool) {
	var size uint32
	var data unsafe.Pointer
	if ret, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(&info.GUID)), uintptr(op), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0); ret != 0 {
		return 0, false
	}
	defer procWlanFreeMemory.Call(uintptr(data))
	return *(*uint32)(data), true
}

func bssList(h windows.Handle, guid *windows.GUID) ([]WifiNetwork, error) {
	var list unsafe.Pointer
	ret, _, _ := procWlanGetNetworkBssList.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), 0, 3 /* dot11_BSS_type_any */, 0, 0, uintptr(unsafe.Pointer(&list)))
	if ret != 0 {
		if windows.Errno(ret) == windows.ERROR_ACCESS_DENIED {
			return nil, fmt.Errorf("o Windows bloqueou a lista de redes vizinhas. Ative a Localização em Configurações > Privacidade e segurança > Localização (incluindo \"Permitir que aplicativos da área de trabalho acessem sua localização\")")
		}
		return nil, fmt.Errorf("WlanGetNetworkBssList: %v", windows.Errno(ret))
	}
	defer procWlanFreeMemory.Call(uintptr(list))
	count := *(*uint32)(unsafe.Add(list, 4))
	entries := unsafe.Slice((*wlanBssEntry)(unsafe.Add(list, 8)), count)
	nets := make([]WifiNetwork, 0, count)
	for _, e := range entries {
		ch, band := channelFromFreq(e.CenterFreqKHz)
		nets = append(nets, WifiNetwork{
			SSID:    string(e.SSID.SSID[:min(e.SSID.Length, 32)]),
			BSSID:   net.HardwareAddr(e.BSSID[:]).String(),
			RSSI:    int(e.RSSI),
			Quality: int(e.LinkQuality),
			Channel: ch,
			BandGHz: band,
			PhyType: phyNames[e.PhyType],
		})
	}
	return nets, nil
}

func channelFromFreq(khz uint32) (int, float64) {
	mhz := int(khz / 1000)
	switch {
	case mhz == 2484:
		return 14, 2.4
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5, 2.4
	case mhz >= 5150 && mhz <= 5925:
		return (mhz - 5000) / 5, 5
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5, 6
	}
	return 0, 0
}

func bandForChannel(ch int) float64 {
	switch {
	case ch >= 1 && ch <= 14:
		return 2.4
	case ch >= 32 && ch <= 177:
		return 5
	}
	return 0
}
