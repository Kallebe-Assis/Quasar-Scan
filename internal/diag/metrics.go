// Package diag reúne as ferramentas de diagnóstico (ping, traceroute, DNS, portas)
// e o teste de saúde da conexão (Fase 3), com classificação dos resultados.
package diag

// Level é a classificação de uma métrica, do melhor para o pior.
type Level string

const (
	Excelente Level = "excelente"
	Razoavel  Level = "razoavel"
	Ruim      Level = "ruim"
	Pessimo   Level = "pessimo"
)

// Scale define até quanto (inclusive) cada nível vale. Acima de Ruim é Péssimo.
// Com Higher=true a lógica se inverte (maior é melhor): "a partir de" cada limite.
type Scale struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Unit      string  `json:"unit"`
	Excelente float64 `json:"excelente"`
	Razoavel  float64 `json:"razoavel"`
	Ruim      float64 `json:"ruim"`
	Hint      string  `json:"hint"`
	Higher    bool    `json:"higher,omitempty"`
}

// Escalas usadas em toda a ferramenta. Ajuste os limites aqui.
var (
	LatencyInternet = Scale{"latencia", "Latência (internet)", "ms", 15, 25, 50,
		"Tempo de ida e volta até um servidor na internet.", false}
	LatencyLAN = Scale{"latencia-lan", "Latência (rede local)", "ms", 3, 10, 30,
		"Até o roteador/gateway. Cabo fica em ~1 ms; Wi-Fi bom fica abaixo de 10 ms.", false}
	Jitter = Scale{"jitter", "Jitter (variação)", "ms", 5, 15, 30,
		"Variação entre um ping e outro. Afeta chamadas, jogos e vídeo ao vivo.", false}
	Loss = Scale{"perda", "Perda de pacotes", "%", 0, 1, 5,
		"Pacotes que não voltaram. Qualquer perda constante é sinal de problema.", false}
	DNSTime = Scale{"dns", "Resposta DNS", "ms", 20, 50, 100,
		"Tempo para traduzir um nome (ex.: google.com) em IP.", false}
	Bufferbloat = Scale{"bufferbloat", "Latência sob carga (aumento)", "ms", 20, 60, 150,
		"Quanto a latência sobe enquanto a internet está sendo usada no máximo. Alto = chamadas e jogos travam quando alguém baixa algo.", false}
	WifiSignal = Scale{"sinal", "Sinal do Wi-Fi", "dBm", -55, -67, -75,
		"Intensidade do sinal recebido. Quanto mais perto de zero, melhor.", true}
	PlanPct = Scale{"plano", "Velocidade em relação ao plano", "%", 90, 70, 50,
		"Quanto do plano contratado foi entregue no teste.", true}
)

// No Wi-Fi a latência é naturalmente maior: as faixas de latência dobram.
var (
	LatencyInternetWifi = LatencyInternet.wifi()
	LatencyLANWifi      = LatencyLAN.wifi()
)

func (s Scale) wifi() Scale {
	s.ID += "-wifi"
	s.Name += " no Wi-Fi"
	s.Excelente, s.Razoavel, s.Ruim = s.Excelente*2, s.Razoavel*2, s.Ruim*2
	s.Hint += " No Wi-Fi as faixas são o dobro das do cabo."
	return s
}

// latencyScale escolhe a escala de latência pelo destino (rede local ou internet) e pelo meio.
func latencyScale(lan, wifi bool) Scale {
	switch {
	case lan && wifi:
		return LatencyLANWifi
	case lan:
		return LatencyLAN
	case wifi:
		return LatencyInternetWifi
	}
	return LatencyInternet
}

// Scales é a lista enviada para a interface montar as legendas.
var Scales = []Scale{LatencyInternet, LatencyLAN, LatencyInternetWifi, LatencyLANWifi, Jitter, Loss, DNSTime, Bufferbloat, WifiSignal, PlanPct}

// Rate classifica um valor numa escala.
func (s Scale) Rate(v float64) Level {
	if s.Higher {
		switch {
		case v >= s.Excelente:
			return Excelente
		case v >= s.Razoavel:
			return Razoavel
		case v >= s.Ruim:
			return Ruim
		}
		return Pessimo
	}
	switch {
	case v <= s.Excelente:
		return Excelente
	case v <= s.Razoavel:
		return Razoavel
	case v <= s.Ruim:
		return Ruim
	}
	return Pessimo
}

// Worst devolve o pior nível entre os informados.
func Worst(levels ...Level) Level {
	rank := map[Level]int{Excelente: 0, Razoavel: 1, Ruim: 2, Pessimo: 3}
	w := Excelente
	for _, l := range levels {
		if rank[l] > rank[w] {
			w = l
		}
	}
	return w
}
