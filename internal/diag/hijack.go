package diag

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// HijackCheck testa se servidores DNS inventam respostas para domínios que não existem.
type HijackCheck struct {
	Domain  string        `json:"domain"`
	Results []HijackEntry `json:"results"`
	Level   string        `json:"level"` // ok, aviso, critico
	Verdict string        `json:"verdict"`
}

type HijackEntry struct {
	DNSServer
	Hijacked bool     `json:"hijacked"`
	Answers  []string `json:"answers"`
	Error    string   `json:"error,omitempty"`
}

// CheckHijack consulta um domínio aleatório (que não existe) no DNS configurado e
// no 1.1.1.1. O certo é "não existe" (NXDOMAIN); um IP na resposta indica redirecionamento.
func CheckHijack(ctx context.Context) HijackCheck {
	b := make([]byte, 8)
	rand.Read(b)
	res := HijackCheck{Domain: "dn-" + hex.EncodeToString(b) + ".com", Results: []HijackEntry{}, Level: "ok"}
	servers := append(SystemDNS(), PublicDNS[0])
	for _, s := range servers {
		r := Lookup(ctx, s.IP, res.Domain, "A")
		e := HijackEntry{DNSServer: s, Answers: r.Answers}
		switch {
		case len(r.Answers) > 0:
			e.Hijacked = true
		case r.Error != "" && !strings.Contains(r.Error, "NXDOMAIN"):
			e.Error = r.Error
		}
		res.Results = append(res.Results, e)
	}

	var sys, pub []HijackEntry
	for _, e := range res.Results {
		if e.Local {
			sys = append(sys, e)
		} else {
			pub = append(pub, e)
		}
	}
	switch {
	case len(pub) > 0 && pub[0].Hijacked:
		res.Level = "critico"
		res.Verdict = fmt.Sprintf("Até a consulta direta ao 1.1.1.1 devolveu %s para um domínio inexistente: as consultas DNS estão sendo interceptadas no caminho (roteador ou rede). Verifique se o roteador não está comprometido.", strings.Join(pub[0].Answers, ", "))
	case anyHijacked(sys):
		res.Level = "aviso"
		res.Verdict = "O DNS configurado responde com um IP para domínios que não existem (redireciona para página de busca/propaganda ou foi adulterado). Pode quebrar apps e é sinal de DNS do roteador alterado — confira o DNS configurado no roteador."
	default:
		res.Verdict = "Nenhum sinal de sequestro: domínios inexistentes são recusados corretamente."
	}
	return res
}

func anyHijacked(list []HijackEntry) bool {
	for _, e := range list {
		if e.Hijacked {
			return true
		}
	}
	return false
}
