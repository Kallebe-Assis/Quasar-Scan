package diag

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

// PortResult é o resultado de um teste de porta TCP (equivale ao "telnet host porta"
// ou "Test-NetConnection -Port").
type PortResult struct {
	Host   string  `json:"host"`
	IP     string  `json:"ip"`
	Port   int     `json:"port"`
	State  string  `json:"state"` // aberta, fechada, filtrada
	TimeMs float64 `json:"timeMs"`
	Detail string  `json:"detail"`
}

// TestPort tenta abrir uma conexão TCP e interpreta o tipo de falha.
func TestPort(ctx context.Context, host, family string, port int) PortResult {
	res := PortResult{Host: host, Port: port}
	ip, err := Resolve(ctx, host, family)
	if err != nil {
		res.State, res.Detail = "erro", err.Error()
		return res
	}
	res.IP = ip.String()

	start := time.Now()
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	res.TimeMs = round1(float64(time.Since(start).Microseconds()) / 1000)
	switch {
	case err == nil:
		c.Close()
		res.State, res.Detail = "aberta", "A conexão foi aceita: há um serviço escutando nesta porta."
	case errors.Is(err, syscall.Errno(10061)): // WSAECONNREFUSED
		res.State, res.Detail = "fechada", "O equipamento respondeu recusando: ele está acessível, mas nada escuta nesta porta."
	default:
		res.State, res.Detail = "filtrada", "Sem resposta: um firewall está bloqueando, ou o equipamento está desligado/inacessível."
	}
	return res
}
