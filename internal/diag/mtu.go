package diag

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"quasarscan/internal/netinfo"
	"quasarscan/internal/winapi"
)

// MTUResult é o resultado do teste de MTU do caminho até um destino.
type MTUResult struct {
	Target     string `json:"target"`
	PathMTU    int    `json:"pathMtu"`    // maior pacote IP que passa sem fragmentar
	MaxPayload int    `json:"maxPayload"` // valor para usar no "ping -f -l"
	LocalMTU   uint32 `json:"localMtu"`   // MTU configurado na placa de rede
	Level      string `json:"level"`      // ok, info, aviso, critico
	Verdict    string `json:"verdict"`
	Probes     int    `json:"probes"`
	Error      string `json:"error,omitempty"`
}

// ipICMPHeader é o cabeçalho IPv4 (20) + ICMP (8): MTU = payload + 28.
const ipICMPHeader = 28

// TestMTU descobre o MTU do caminho com pings de bit DF ("ping -f -l"), por busca binária.
func TestMTU(ctx context.Context, target netip.Addr) MTUResult {
	res := MTUResult{Target: target.String(), LocalMTU: primaryMTU()}
	if !target.Is4() {
		res.Error = "o teste de MTU usa IPv4"
		return res
	}
	passes := func(size int) bool {
		res.Probes++
		for try := 0; try < 2 && ctx.Err() == nil; try++ { // 2 tentativas: perda comum não é "grande demais"
			r, err := winapi.Echo(target, winapi.EchoOptions{Size: size, DontFragment: true, Timeout: 900 * time.Millisecond})
			if err == nil && r.Status == winapi.StatusSuccess {
				return true
			}
			if r.Status == winapi.StatusPacketTooBig {
				return false
			}
		}
		return false
	}

	if !passes(64) {
		res.Error = fmt.Sprintf("o destino %s não respondeu ao ping; não dá para medir o MTU", target)
		return res
	}
	lo, hi := 64, 1472 // lo sempre passa; procura o maior que passa
	if passes(hi) {
		lo = hi
	} else {
		for hi-lo > 1 {
			mid := (lo + hi) / 2
			if passes(mid) {
				lo = mid
			} else {
				hi = mid
			}
		}
	}
	res.MaxPayload = lo
	res.PathMTU = lo + ipICMPHeader

	// Só é problema a partir de 1400 para baixo; entre 1401 e 1499 é normal (PPPoE, túneis leves).
	switch {
	case res.PathMTU >= 1500:
		res.Level, res.Verdict = "ok", "MTU 1500: padrão Ethernet, sem restrição no caminho."
	case res.PathMTU == 1492:
		res.Level, res.Verdict = "ok", "MTU 1492: normal em conexões PPPoE (8 bytes do PPPoE)."
	case res.PathMTU > 1400:
		res.Level, res.Verdict = "ok", fmt.Sprintf("MTU %d: um pouco abaixo de 1500, dentro do normal.", res.PathMTU)
	case res.PathMTU >= 1300:
		res.Level, res.Verdict = "aviso", fmt.Sprintf("MTU %d: baixo. Pode causar sites que não carregam, VPN instável ou falhas em apps se o roteador não ajustar o MSS. Verifique MTU/MSS da WAN e túneis no caminho.", res.PathMTU)
	default:
		res.Level, res.Verdict = "critico", fmt.Sprintf("MTU %d: muito baixo. Espere lentidão e falhas de navegação; revise a configuração de MTU da WAN/túnel.", res.PathMTU)
	}
	if res.LocalMTU > 0 && res.LocalMTU < 1500 && int(res.LocalMTU) == res.PathMTU {
		res.Verdict += fmt.Sprintf(" Atenção: o limite vem da própria placa deste computador (MTU %d configurado), não da rede.", res.LocalMTU)
	}
	return res
}

func primaryMTU() uint32 {
	if it := primaryInterface(); it != nil {
		return it.MTU
	}
	return 0
}

// primaryInterface devolve a interface usada para sair para a internet.
func primaryInterface() *netinfo.Interface {
	list, _ := netinfo.Interfaces()
	for i := range list {
		if list[i].IsPrimary {
			return &list[i]
		}
	}
	return nil
}
