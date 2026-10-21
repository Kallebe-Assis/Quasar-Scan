package diag

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"quasarscan/internal/winapi"
)

// SpeedOptions escolhe o servidor do teste de velocidade.
// Server "" usa a Cloudflare; uma URL usa um servidor LibreSpeed (ex.: do próprio provedor).
type SpeedOptions struct {
	Server   string
	PlanMbps int
	Duration time.Duration // por fase (download e upload)
}

// SpeedProgress é enviado durante o teste para a interface atualizar o velocímetro.
type SpeedProgress struct {
	Phase   string  `json:"phase"` // latencia, download, upload
	Mbps    float64 `json:"mbps"`
	PingMs  float64 `json:"pingMs"`
	Elapsed float64 `json:"elapsed"`
}

type SpeedResult struct {
	Server       string         `json:"server"`
	DownloadMbps float64        `json:"downloadMbps"`
	UploadMbps   float64        `json:"uploadMbps"`
	IdleMs       float64        `json:"idleMs"`
	DownLoadedMs float64        `json:"downLoadedMs"` // latência durante o download
	UpLoadedMs   float64        `json:"upLoadedMs"`
	BloatDownMs  float64        `json:"bloatDownMs"` // aumento em relação à latência ociosa
	BloatUpMs    float64        `json:"bloatUpMs"`
	BloatLevel   Level          `json:"bloatLevel"`
	DataMB       float64        `json:"dataMB"`
	PlanMbps     int            `json:"planMbps,omitempty"`
	DownPct      float64        `json:"downPct,omitempty"`
	UpPct        float64        `json:"upPct,omitempty"`
	DownLevel    Level          `json:"downLevel,omitempty"`
	LinkMbps     uint64         `json:"linkMbps,omitempty"`
	Findings     []TraceFinding `json:"findings"`
	Error        string         `json:"error,omitempty"`
}

type speedBackend struct {
	label    string
	host     string
	download func() string
	upload   func() string
}

func backendFor(server string) (speedBackend, error) {
	if strings.TrimSpace(server) == "" {
		return speedBackend{
			label:    "Cloudflare (speed.cloudflare.com)",
			host:     "speed.cloudflare.com",
			download: func() string { return "https://speed.cloudflare.com/__down?bytes=25000000" },
			upload:   func() string { return "https://speed.cloudflare.com/__up" },
		}, nil
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(server), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return speedBackend{}, fmt.Errorf("URL do servidor inválida (ex.: http://speedtest.provedor.com.br/backend)")
	}
	base := u.String()
	return speedBackend{
		label:    "LibreSpeed (" + u.Host + ")",
		host:     u.Hostname(),
		download: func() string { return base + "/garbage.php?ckSize=50" },
		upload:   func() string { return base + "/empty.php" },
	}, nil
}

// zeroReader gera dados para o upload e conta o que foi efetivamente enviado.
type zeroReader struct {
	left    int64
	counter *atomic.Int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > z.left {
		n = z.left
	}
	clear(p[:n])
	z.left -= n
	z.counter.Add(n)
	return int(n), nil
}

// RunSpeed mede latência ociosa, download e upload, com a latência durante a carga.
func RunSpeed(ctx context.Context, opt SpeedOptions, onProgress func(SpeedProgress)) SpeedResult {
	res := SpeedResult{PlanMbps: opt.PlanMbps, Findings: []TraceFinding{}}
	if opt.Duration == 0 {
		opt.Duration = 10 * time.Second
	}
	be, err := backendFor(opt.Server)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Server = be.label
	res.LinkMbps = primarySpeed()

	pingIP, err := Resolve(ctx, be.host, "")
	if err != nil {
		res.Error = "sem acesso ao servidor de teste: " + err.Error()
		return res
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 16,
		DisableCompression:  true,
	}}

	// Latência ociosa: 10 pings.
	var idle []float64
	for i := 0; i < 10 && ctx.Err() == nil; i++ {
		if r, err := winapi.Echo(pingIP, winapi.EchoOptions{Timeout: time.Second}); err == nil {
			idle = append(idle, float64(r.RTT.Microseconds())/1000)
		}
		onProgress(SpeedProgress{Phase: "latencia", PingMs: median(idle)})
		time.Sleep(100 * time.Millisecond)
	}
	res.IdleMs = round1(median(idle))
	// Sem resposta ao ping (alguns servidores bloqueiam ICMP): mede pela Cloudflare.
	if len(idle) == 0 {
		pingIP = netip.MustParseAddr("1.1.1.1")
	}

	var total atomic.Int64
	down, downPing := runPhase(ctx, "download", opt.Duration, pingIP, onProgress, func(ctx context.Context, counter *atomic.Int64) {
		req, _ := http.NewRequestWithContext(ctx, "GET", be.download(), nil)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 64*1024)
		for {
			n, err := resp.Body.Read(buf)
			counter.Add(int64(n))
			if err != nil {
				return
			}
		}
	}, &total)
	up, upPing := runPhase(ctx, "upload", opt.Duration, pingIP, onProgress, func(ctx context.Context, counter *atomic.Int64) {
		req, _ := http.NewRequestWithContext(ctx, "POST", be.upload(), &zeroReader{left: 10 << 20, counter: counter})
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = 10 << 20
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}, &total)

	res.DownloadMbps, res.UploadMbps = round1(down), round1(up)
	res.DownLoadedMs, res.UpLoadedMs = round1(median(downPing)), round1(median(upPing))
	res.BloatDownMs = round1(math.Max(0, res.DownLoadedMs-res.IdleMs))
	res.BloatUpMs = round1(math.Max(0, res.UpLoadedMs-res.IdleMs))
	res.BloatLevel = Bufferbloat.Rate(math.Max(res.BloatDownMs, res.BloatUpMs))
	res.DataMB = round1(float64(total.Load()) / 1e6)
	if res.DownloadMbps == 0 {
		res.Error = "o download não transferiu dados: servidor inacessível ou bloqueado"
	}
	speedFindings(&res)
	return res
}

// runPhase roda workers em paralelo por "dur", amostrando a vazão e a latência.
// Os 2 primeiros segundos (subida da conexão TCP) não entram na média.
func runPhase(ctx context.Context, phase string, dur time.Duration, pingIP netip.Addr,
	onProgress func(SpeedProgress), worker func(context.Context, *atomic.Int64), total *atomic.Int64) (float64, []float64) {
	const workers = 6
	const warmup = 2 * time.Second
	pctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	var counter atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pctx.Err() == nil {
				worker(pctx, &counter)
			}
		}()
	}

	var pings []float64
	var pmu sync.Mutex
	wg.Add(1)
	go func() { // latência sob carga
		defer wg.Done()
		for pctx.Err() == nil {
			if r, err := winapi.Echo(pingIP, winapi.EchoOptions{Timeout: 2 * time.Second}); err == nil && pctx.Err() == nil {
				pmu.Lock()
				pings = append(pings, float64(r.RTT.Microseconds())/1000)
				pmu.Unlock()
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	start := time.Now()
	var warmBytes int64
	var warmAt time.Time
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	lastBytes, lastT := int64(0), start
	for pctx.Err() == nil {
		select {
		case <-pctx.Done():
		case now := <-tick.C:
			b := counter.Load()
			inst := float64(b-lastBytes) * 8 / now.Sub(lastT).Seconds() / 1e6
			lastBytes, lastT = b, now
			if warmAt.IsZero() && now.Sub(start) >= warmup {
				warmBytes, warmAt = b, now
			}
			pmu.Lock()
			p := median(pings)
			pmu.Unlock()
			onProgress(SpeedProgress{Phase: phase, Mbps: round1(inst), PingMs: p, Elapsed: now.Sub(start).Seconds()})
		}
	}
	end := time.Now()
	final := counter.Load()
	cancel()
	wg.Wait()
	total.Add(final)

	if warmAt.IsZero() || end.Sub(warmAt) < 500*time.Millisecond {
		return float64(final) * 8 / end.Sub(start).Seconds() / 1e6, pings
	}
	return float64(final-warmBytes) * 8 / end.Sub(warmAt).Seconds() / 1e6, pings
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	return s[len(s)/2]
}

func speedFindings(res *SpeedResult) {
	add := func(l, t, d string) { res.Findings = append(res.Findings, TraceFinding{l, t, d}) }
	if res.Error != "" {
		return
	}
	if res.PlanMbps > 0 {
		res.DownPct = round1(res.DownloadMbps / float64(res.PlanMbps) * 100)
		res.DownLevel = PlanPct.Rate(res.DownPct)
		nicLimited := res.LinkMbps > 0 && res.LinkMbps < uint64(res.PlanMbps)
		if nicLimited {
			add("aviso", "A placa de rede limita o teste", fmt.Sprintf("Este computador está conectado a %d Mbps, abaixo do plano de %d Mega: o teste nunca vai passar disso. Teste num equipamento com porta gigabit/cabo bom ou Wi-Fi 5/6 perto do roteador.", res.LinkMbps, res.PlanMbps))
		}
		switch {
		case res.DownLevel == Excelente || res.DownLevel == Razoavel:
		case nicLimited && res.DownloadMbps >= float64(res.LinkMbps)*0.85:
			res.DownLevel = "" // não dá para avaliar o plano: o limite é a placa
			add("info", "Velocidade no limite da placa", fmt.Sprintf("Download de %.0f Mbps: praticamente o máximo da conexão de %d Mbps deste computador. A internet pode estar entregando mais — o limite é local.", res.DownloadMbps, res.LinkMbps))
		default:
			add("aviso", "Velocidade abaixo do plano", fmt.Sprintf("Download de %.0f Mbps = %.0f%% do plano de %d Mega.", res.DownloadMbps, res.DownPct, res.PlanMbps))
		}
	}
	switch res.BloatLevel {
	case Ruim, Pessimo:
		add("aviso", "Bufferbloat: latência dispara com a internet em uso",
			fmt.Sprintf("A latência sobe %.0f ms no download e %.0f ms no upload. Chamadas e jogos travam quando alguém baixa ou envia algo. Ative SQM/QoS (fq_codel/CAKE) no roteador, se disponível.", res.BloatDownMs, res.BloatUpMs))
	}
}

func primarySpeed() uint64 {
	if it := primaryInterface(); it != nil {
		return it.SpeedMbps
	}
	return 0
}
