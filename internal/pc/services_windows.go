package pc

import (
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Service é um serviço do Windows (programa que roda em segundo plano).
type Service struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	Description string    `json:"description,omitempty"`
	Command     string    `json:"command"`
	Path        string    `json:"path"` // executável, ou a DLL quando hospedado no svchost
	DLL         bool      `json:"dll,omitempty"`
	StartType   string    `json:"startType"`
	Running     bool      `json:"running"`
	Signature   Signature `json:"signature"`
	Flags       []Flag    `json:"flags"`
}

var startTypes = map[uint32]string{mgr.StartAutomatic: "Automático", mgr.StartManual: "Manual", mgr.StartDisabled: "Desativado", 0: "Boot", 1: "Sistema"}

// CollectServices lista os serviços Win32 e o executável (ou DLL) de cada um.
func CollectServices() []Service {
	// Só leitura: mgr.Connect pediria acesso total (exige administrador).
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return []Service{}
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return []Service{}
	}
	out := make([]Service, 0, len(names))
	for _, n := range names {
		np, _ := windows.UTF16PtrFromString(n)
		sh, err := windows.OpenService(h, np, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		s := &mgr.Service{Name: n, Handle: sh}
		cfg, err := s.Config()
		if err != nil {
			s.Close()
			continue
		}
		// Só serviços de aplicação (não drivers de kernel).
		if cfg.ServiceType&(windows.SERVICE_WIN32_OWN_PROCESS|windows.SERVICE_WIN32_SHARE_PROCESS) == 0 {
			s.Close()
			continue
		}
		sv := Service{Name: n, DisplayName: cfg.DisplayName, Description: cfg.Description, Command: cfg.BinaryPathName,
			StartType: startTypes[cfg.StartType], Flags: []Flag{}}
		if cfg.DelayedAutoStart && cfg.StartType == mgr.StartAutomatic {
			sv.StartType = "Automático (atrasado)"
		}
		if st, err := s.Query(); err == nil {
			sv.Running = st.State == svc.Running
		}
		s.Close()

		sv.Path = ExePath(cfg.BinaryPathName)
		// Serviços dentro do svchost: o código de verdade está na ServiceDll.
		if strings.EqualFold(baseName(sv.Path), "svchost.exe") {
			if dll := serviceDLL(n); dll != "" {
				sv.Path, sv.DLL = dll, true
			}
		}
		out = append(out, sv)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName) })
	return out
}

func serviceDLL(name string) string {
	for _, sub := range []string{`\Parameters`, ``} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name+sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue("ServiceDll")
		k.Close()
		if err == nil && v != "" {
			return expandEnv(v)
		}
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
