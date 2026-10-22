package pc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SystemInfo descreve o computador e a configuração básica de segurança.
type SystemInfo struct {
	Computer      string     `json:"computer"`
	User          string     `json:"user"`
	OS            string     `json:"os"`
	Build         string     `json:"build"`
	InstallDate   string     `json:"installDate,omitempty"`
	UptimeHours   float64    `json:"uptimeHours"`
	RAMTotalGB    float64    `json:"ramTotalGB"`
	RAMUsedPct    int        `json:"ramUsedPct"`
	Disks         []Disk     `json:"disks"`
	UAC           bool       `json:"uac"`
	SecureBoot    *bool      `json:"secureBoot,omitempty"`
	Firewall      []Firewall `json:"firewall"`
	Proxy         Proxy      `json:"proxy"`
	Hosts         []string   `json:"hosts"` // entradas do arquivo hosts fora o padrão
	RebootPending bool       `json:"rebootPending"`
}

type Disk struct {
	Drive   string  `json:"drive"`
	TotalGB float64 `json:"totalGB"`
	FreeGB  float64 `json:"freeGB"`
	FreePct int     `json:"freePct"`
}

type Firewall struct {
	Profile string `json:"profile"`
	Enabled bool   `json:"enabled"`
}

type Proxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	AutoURL string `json:"autoUrl,omitempty"` // script PAC
}

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// CollectSystem lê informações do sistema pelo registro e por APIs do Windows.
func CollectSystem() SystemInfo {
	si := SystemInfo{Disks: []Disk{}, Firewall: []Firewall{}, Hosts: []string{}}
	si.Computer, _ = os.Hostname()
	si.User = os.Getenv("USERNAME")
	si.UptimeHours = float64(windows.DurationSinceBoot().Hours())
	si.UptimeHours = float64(int(si.UptimeHours*10)) / 10

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProductName")
		disp, _, _ := k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuild")
		ubr, _, _ := k.GetIntegerValue("UBR")
		if b, _ := strconv.Atoi(build); b >= 22000 {
			name = strings.Replace(name, "Windows 10", "Windows 11", 1) // o registro do Win11 ainda diz "Windows 10"
		}
		si.OS = strings.TrimSpace(name + " " + disp)
		si.Build = fmt.Sprintf("%s.%d", build, ubr)
		if inst, _, err := k.GetIntegerValue("InstallDate"); err == nil && inst > 0 {
			si.InstallDate = time.Unix(int64(inst), 0).Format("02/01/2006")
		}
		k.Close()
	}

	ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		si.RAMTotalGB = round1(float64(ms.TotalPhys) / (1 << 30))
		si.RAMUsedPct = int(ms.MemoryLoad)
	}

	drives, _ := windows.GetLogicalDrives()
	for i := 0; i < 26; i++ {
		if drives&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(rp) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(rp, &free, &total, &totalFree) == nil && total > 0 {
			si.Disks = append(si.Disks, Disk{Drive: root[:2], TotalGB: round1(float64(total) / (1 << 30)),
				FreeGB: round1(float64(totalFree) / (1 << 30)), FreePct: int(totalFree * 100 / total)})
		}
	}

	si.UAC = regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", 1) != 0
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("UEFISecureBootEnabled"); err == nil {
			b := v != 0
			si.SecureBoot = &b
		}
		k.Close()
	}
	for _, p := range []struct{ key, name string }{{"DomainProfile", "Domínio"}, {"StandardProfile", "Privada"}, {"PublicProfile", "Pública"}} {
		base := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + p.key
		on := regDWORD(registry.LOCAL_MACHINE, base, "EnableFirewall", 1) != 0
		// Política de grupo tem prioridade sobre a configuração local.
		if pol := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\WindowsFirewall\`+p.key, "EnableFirewall", 2); pol != 2 {
			on = pol != 0
		}
		si.Firewall = append(si.Firewall, Firewall{Profile: p.name, Enabled: on})
	}

	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE); err == nil {
		en, _, _ := k.GetIntegerValue("ProxyEnable")
		si.Proxy.Enabled = en != 0
		si.Proxy.Server, _, _ = k.GetStringValue("ProxyServer")
		si.Proxy.AutoURL, _, _ = k.GetStringValue("AutoConfigURL")
		k.Close()
	}
	si.Hosts = readHosts()
	si.RebootPending = keyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) ||
		keyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`)
	return si
}

// readHosts devolve as linhas ativas do arquivo hosts que não são o padrão (localhost).
func readHosts() []string {
	out := []string{}
	f, err := os.Open(filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if len(fields) == 2 && strings.EqualFold(fields[1], "localhost") {
			continue
		}
		out = append(out, strings.Join(fields, " "))
	}
	return out
}

func regDWORD(root registry.Key, path, name string, def uint64) uint64 {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return def
	}
	return v
}

func keyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
