// Package pc inspeciona o próprio computador (não a rede): proteção do sistema,
// ameaças do Windows Defender, programas de inicialização, processos, serviços e
// sinais comuns de malware. Só lê — nada é apagado ou alterado automaticamente.
package pc

import (
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Signature é o resultado da verificação de assinatura digital de um executável.
type Signature struct {
	Status    string `json:"status"` // assinado, sem-assinatura, invalido, inexistente, erro
	Publisher string `json:"publisher,omitempty"`
	Catalog   bool   `json:"catalog,omitempty"` // assinado via catálogo do Windows
}

// Signed indica assinatura válida (embutida ou por catálogo).
func (s Signature) Signed() bool { return s.Status == "assinado" }

var (
	wintrust                                 = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData        = wintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
)

const (
	trustNoSignature   = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustSubjectForm   = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
	trustProviderUnkn  = 0x800B0001 // TRUST_E_PROVIDER_UNKNOWN
	fileNotFound       = 0x80070002
	cryptFileError     = 0x80092003 // CRYPT_E_FILE_ERROR
	catalogSubjectsMsg = "Microsoft Windows (catálogo)"
)

var (
	sigCache   = map[string]Signature{}
	sigCacheMu sync.Mutex
)

// VerifyFile confere a assinatura digital de um arquivo. Primeiro a embutida; se não
// houver, procura o arquivo nos catálogos do Windows (como os arquivos do sistema).
// Não consulta a internet (sem checagem de revogação online), então é rápido.
func VerifyFile(path string) Signature {
	if path == "" {
		return Signature{Status: "inexistente"}
	}
	key := strings.ToLower(path)
	sigCacheMu.Lock()
	if s, ok := sigCache[key]; ok {
		sigCacheMu.Unlock()
		return s
	}
	sigCacheMu.Unlock()

	var s Signature
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		s = Signature{Status: "inexistente"}
	} else {
		s = verifyEmbedded(path)
	}
	switch {
	case s.Status != "sem-assinatura":
	case strings.Contains(key, `\program files\windowsapps\`):
		// Apps da Microsoft Store: a assinatura é do pacote (MSIX), não do arquivo, e a
		// pasta WindowsApps é protegida — só o instalador da Store grava nela.
		s = Signature{Status: "assinado", Publisher: "Aplicativo da Microsoft Store (pacote assinado)"}
	case inCatalog(path):
		s = Signature{Status: "assinado", Publisher: catalogSubjectsMsg, Catalog: true}
	}
	sigCacheMu.Lock()
	sigCache[key] = s
	sigCacheMu.Unlock()
	return s
}

func verifyEmbedded(path string) Signature {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Signature{Status: "erro"}
	}
	file := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	var s Signature
	switch {
	case verr == nil:
		s = Signature{Status: "assinado", Publisher: signerName(data.StateData)}
	default:
		code := uint32(0)
		if e, ok := verr.(windows.Errno); ok {
			code = uint32(e)
		}
		switch code {
		case trustNoSignature, trustSubjectForm, trustProviderUnkn:
			s = Signature{Status: "sem-assinatura"}
		case fileNotFound, cryptFileError, uint32(windows.ERROR_FILE_NOT_FOUND), uint32(windows.ERROR_PATH_NOT_FOUND):
			s = Signature{Status: "erro"} // arquivo sumiu ou está bloqueado durante a leitura
		default:
			// Assinatura presente mas inválida (adulterada, expirada, raiz não confiável).
			s = Signature{Status: "invalido", Publisher: signerName(data.StateData)}
		}
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return s
}

// signerName lê o nome do certificado de quem assinou (ex.: "Google LLC").
// CRYPT_PROVIDER_SGNR: pasCertChain fica no offset 16; CRYPT_PROVIDER_CERT: pCert no offset 8.
func signerName(state windows.Handle) string {
	if state == 0 {
		return ""
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	// sgnr aponta para memória do wintrust (não do Go), válida até o WTD_STATEACTION_CLOSE.
	sp := *(*unsafe.Pointer)(unsafe.Pointer(&sgnr))
	if *(*uint32)(unsafe.Add(sp, 12)) == 0 {
		return ""
	}
	chain := *(*unsafe.Pointer)(unsafe.Add(sp, 16))
	if chain == nil {
		return ""
	}
	cert := *(**windows.CertContext)(unsafe.Add(chain, 8))
	if cert == nil {
		return ""
	}
	buf := make([]uint16, 256)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// inCatalog procura o hash do arquivo nos catálogos de assinatura do Windows.
func inCatalog(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	for _, alg := range []string{"SHA256", ""} {
		var admin uintptr
		var algPtr *uint16
		if alg != "" {
			algPtr, _ = windows.UTF16PtrFromString(alg)
		}
		if r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algPtr)), 0, 0); r == 0 {
			continue
		}
		found := false
		var size uint32 = 64
		hash := make([]byte, size)
		windows.SetFilePointer(h, 0, nil, windows.FILE_BEGIN)
		if r, _, _ := procCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); r != 0 {
			info, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
			if info != 0 {
				found = true
				procCryptCATAdminReleaseCatalogContext.Call(admin, info, 0)
			}
		}
		procCryptCATAdminReleaseContext.Call(admin, 0)
		if found {
			return true
		}
	}
	return false
}
