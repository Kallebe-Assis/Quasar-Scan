package pc

import (
	"sort"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// Antivirus é um antivírus registrado na Central de Segurança do Windows.
type Antivirus struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"upToDate"`
	Path     string `json:"path,omitempty"`
}

// Defender resume o estado do Microsoft Defender.
type Defender struct {
	Available        bool   `json:"available"`
	Enabled          bool   `json:"enabled"`
	RealTime         bool   `json:"realTime"`
	TamperProtected  bool   `json:"tamperProtected"`
	Mode             string `json:"mode,omitempty"` // Normal, Passive (outro antivírus ativo), EDR Block...
	SignatureVersion string `json:"signatureVersion,omitempty"`
	SignatureAgeDays int    `json:"signatureAgeDays"`
	SignatureUpdated string `json:"signatureUpdated,omitempty"`
	QuickScanAgeDays int    `json:"quickScanAgeDays"` // -1 = nunca
	FullScanAgeDays  int    `json:"fullScanAgeDays"`
	Error            string `json:"error,omitempty"`
}

// Threat é uma ameaça encontrada pelo Defender (histórico).
type Threat struct {
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	Active    bool     `json:"active"`
	Executed  bool     `json:"executed"`
	Detected  string   `json:"detected"`
	Resources []string `json:"resources"`
	Cleaned   bool     `json:"cleaned"`
}

// Update é uma atualização instalada (hotfix).
type Update struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	InstalledOn string `json:"installedOn"`
}

type Security struct {
	Antivirus     []Antivirus `json:"antivirus"`
	Defender      Defender    `json:"defender"`
	Threats       []Threat    `json:"threats"`
	LastUpdate    *Update     `json:"lastUpdate,omitempty"`
	UpdateAgeDays int         `json:"updateAgeDays"` // -1 = desconhecido
	Updates       []Update    `json:"updates"`
}

type wmiAV struct {
	DisplayName            string
	ProductState           uint32
	PathToSignedProductExe string
}

type wmiMpStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	IsTamperProtected             bool
	AMRunningMode                 string
	AntivirusSignatureVersion     string
	AntivirusSignatureAge         uint32
	AntivirusSignatureLastUpdated time.Time
	QuickScanAge                  uint32
	FullScanAge                   uint32
}

type wmiMpThreat struct {
	ThreatID         int64
	ThreatName       string
	SeverityID       uint8
	IsActive         bool
	DidThreatExecute bool
}

type wmiMpDetection struct {
	ThreatID                       int64
	InitialDetectionTime           time.Time
	Resources                      []string
	ActionSuccess                  bool
	CurrentThreatExecutionStatusID uint8
}

type wmiQFE struct {
	HotFixID    string
	Description string
	InstalledOn string
}

var severities = map[uint8]string{0: "Desconhecida", 1: "Baixa", 2: "Moderada", 4: "Alta", 5: "Grave"}

// CollectSecurity consulta a Central de Segurança, o Defender e as atualizações via WMI.
func CollectSecurity() Security {
	sec := Security{Antivirus: []Antivirus{}, Threats: []Threat{}, Updates: []Update{}, UpdateAgeDays: -1}

	var avs []wmiAV
	if wmi.QueryNamespace("SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct", &avs, `root\SecurityCenter2`) == nil {
		for _, a := range avs {
			// productState: bits 12-15 = ligado (0x1000); bits 4-7 = definições desatualizadas (0x10).
			sec.Antivirus = append(sec.Antivirus, Antivirus{Name: a.DisplayName, Enabled: a.ProductState&0x1000 != 0,
				UpToDate: a.ProductState&0x10 == 0, Path: a.PathToSignedProductExe})
		}
	}

	var st []wmiMpStatus
	if err := wmi.QueryNamespace("SELECT * FROM MSFT_MpComputerStatus", &st, `root\Microsoft\Windows\Defender`); err != nil || len(st) == 0 {
		sec.Defender.Error = "Não foi possível ler o status do Microsoft Defender (desinstalado ou substituído por outro antivírus)."
	} else {
		s := st[0]
		sec.Defender = Defender{Available: true, Enabled: s.AMServiceEnabled && s.AntivirusEnabled, RealTime: s.RealTimeProtectionEnabled,
			TamperProtected: s.IsTamperProtected, Mode: s.AMRunningMode, SignatureVersion: s.AntivirusSignatureVersion,
			SignatureAgeDays: ageDays(s.AntivirusSignatureAge), QuickScanAgeDays: ageDays(s.QuickScanAge), FullScanAgeDays: ageDays(s.FullScanAge)}
		if !s.AntivirusSignatureLastUpdated.IsZero() {
			sec.Defender.SignatureUpdated = s.AntivirusSignatureLastUpdated.Local().Format("02/01/2006 15:04")
		}
	}

	var threats []wmiMpThreat
	var dets []wmiMpDetection
	wmi.QueryNamespace("SELECT ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute FROM MSFT_MpThreat", &threats, `root\Microsoft\Windows\Defender`)
	wmi.QueryNamespace("SELECT ThreatID, InitialDetectionTime, Resources, ActionSuccess, CurrentThreatExecutionStatusID FROM MSFT_MpThreatDetection", &dets, `root\Microsoft\Windows\Defender`)
	for _, t := range threats {
		th := Threat{Name: t.ThreatName, Severity: severities[t.SeverityID], Active: t.IsActive, Executed: t.DidThreatExecute, Resources: []string{}}
		var last time.Time
		for _, d := range dets {
			if d.ThreatID != t.ThreatID {
				continue
			}
			for _, r := range d.Resources {
				r = strings.TrimPrefix(strings.TrimPrefix(r, "file:_"), "process:_")
				if r != "" && !contains(th.Resources, r) {
					th.Resources = append(th.Resources, r)
				}
			}
			if d.InitialDetectionTime.After(last) {
				last = d.InitialDetectionTime
				th.Cleaned = d.ActionSuccess
			}
		}
		if !last.IsZero() {
			th.Detected = last.Local().Format("02/01/2006 15:04")
		}
		sec.Threats = append(sec.Threats, th)
	}

	var qfe []wmiQFE
	if wmi.Query("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering", &qfe) == nil {
		var newest time.Time
		for _, q := range qfe {
			u := Update{ID: q.HotFixID, Description: q.Description, InstalledOn: q.InstalledOn}
			if t, ok := parseQFEDate(q.InstalledOn); ok {
				u.InstalledOn = t.Format("02/01/2006")
				if t.After(newest) {
					newest = t
					sec.LastUpdate = &u
				}
			}
			sec.Updates = append(sec.Updates, u)
		}
		if !newest.IsZero() {
			sec.UpdateAgeDays = int(time.Since(newest).Hours() / 24)
		}
		sort.Slice(sec.Updates, func(i, j int) bool { return sec.Updates[i].ID > sec.Updates[j].ID })
	}
	return sec
}

// O Defender usa 65535 (ou mais) para "nunca".
func ageDays(v uint32) int {
	if v >= 65535 {
		return -1
	}
	return int(v)
}

// InstalledOn vem como "M/D/YYYY" (formato americano) ou, em alguns sistemas, hexadecimal.
func parseQFEDate(s string) (time.Time, bool) {
	for _, layout := range []string{"1/2/2006", "01/02/2006", "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
