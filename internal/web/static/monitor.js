// Aba "Monitoramento": acompanha o monitoramento contínuo que roda no servidor.
let monTimer = null;
const COLORS = ["var(--accent)", "var(--l1)", "var(--l3)"];
const fmtDur = (s) => s >= 3600 ? `${Math.floor(s / 3600)}h${String(Math.floor(s % 3600 / 60)).padStart(2, "0")}` : s >= 60 ? `${Math.floor(s / 60)} min ${s % 60}s` : `${s}s`;
const fmtTime = (t) => new Date(t).toLocaleTimeString("pt-BR");

async function monitorAction(path, body) {
  showError("");
  try {
    renderMonitor(await getJSON(path, body ? { method: "POST", body: JSON.stringify(body) } : { method: "POST" }));
  } catch (e) { showError(e.message); }
  pollMonitor();
}

$("m-go").onclick = () => {
  if ($("m-go").dataset.running === "1") {
    if (confirm("Parar o monitoramento agora?")) monitorAction("api/monitor/stop");
    return;
  }
  monitorAction("api/monitor/start", { minutes: +$("m-dur").value });
};

async function pollMonitor() {
  clearTimeout(monTimer);
  try {
    const st = await getJSON("api/monitor");
    renderMonitor(st);
    if (st.running) monTimer = setTimeout(pollMonitor, 2000);
  } catch {}
}

// timeline desenha, por minuto, a latência média de cada destino e marca perdas em vermelho.
function timeline(st) {
  const mins = st.minutes;
  if (!mins.length) return "";
  const W = 800, H = 160, n = st.targets.length;
  const vals = mins.flatMap(m => m.maxMs).filter(v => v > 0);
  const top = Math.max(60, ...mins.flatMap(m => m.avgMs)) * 1.15;
  const x = (i) => mins.length === 1 ? W / 2 : (i / (mins.length - 1)) * (W - 20) + 10;
  const y = (v) => H - 18 - (v / top) * (H - 30);
  let svg = "";
  mins.forEach((m, i) => {
    const lost = m.lost.reduce((a, b) => a + b, 0);
    if (lost) svg += `<rect x="${x(i) - 3}" y="4" width="6" height="${H - 22}" fill="var(--l4)" opacity="${Math.min(0.85, 0.2 + lost / (m.sent.reduce((a, b) => a + b, 0) || 1))}"><title>${fmtTime(m.at)}: ${lost} pacote(s) perdido(s)</title></rect>`;
  });
  for (let t = 0; t < n; t++) {
    const pts = mins.map((m, i) => m.avgMs[t] > 0 ? `${x(i)},${y(m.avgMs[t])}` : null).filter(Boolean);
    if (pts.length > 1) svg += `<polyline points="${pts.join(" ")}" fill="none" stroke="${COLORS[t % 3]}" stroke-width="2"/>`;
    else if (pts.length === 1) { const [px, py] = pts[0].split(","); svg += `<circle cx="${px}" cy="${py}" r="3" fill="${COLORS[t % 3]}"/>`; }
  }
  svg += `<text x="10" y="${H - 4}" font-size="11" fill="var(--muted)">${fmtTime(mins[0].at)}</text>
    <text x="${W - 10}" y="${H - 4}" font-size="11" fill="var(--muted)" text-anchor="end">${fmtTime(mins[mins.length - 1].at)}</text>
    <text x="${W - 10}" y="14" font-size="11" fill="var(--muted)" text-anchor="end">${Math.round(top)} ms</text>`;
  const leg = st.targets.map((t, i) => `<span style="color:${COLORS[i % 3]}">● ${esc(t.label)}</span>`).join(" &nbsp; ") + ' &nbsp; <span class="c-pessimo">▮ perdas</span>';
  return `<div class="card timeline"><h3>Latência média por minuto</h3><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${svg}</svg><div class="sub">${leg}</div></div>`;
}

function renderMonitor(st) {
  const btn = $("m-go");
  btn.dataset.running = st.running ? "1" : "";
  btn.textContent = st.running ? "Parar monitoramento" : "Iniciar monitoramento";
  btn.className = st.running ? "stop" : "";
  $("m-dur").disabled = st.running;
  if (!st.startedAt || st.startedAt.startsWith("0001")) return;

  const remaining = st.endsAt && !st.endsAt.startsWith("0001") ? Math.max(0, Math.round((new Date(st.endsAt) - Date.now()) / 1000)) : null;
  let html = `<div class="progress" style="display:block;margin-top:14px"><b>${st.running ? "Monitorando" : "Monitoramento encerrado"}</b>
    <span class="sub"> · início ${fmtDate(st.startedAt)} · decorrido ${fmtDur(st.elapsed)}${st.running && remaining != null ? ` · faltam ${fmtDur(remaining)}` : st.running ? " · até parar" : ""}</span>
    ${st.running && remaining != null ? `<div class="bar"><div style="width:${(st.elapsed / (st.elapsed + remaining)) * 100}%"></div></div>` : ""}</div>`;
  html += `<div class="finding big ${st.level || "ok"}" style="margin-top:14px"><b>${{ ok: "Sem problemas até agora", aviso: "Atenção", critico: "Quedas registradas" }[st.level] || "Resumo"}</b>${esc(st.summary)}</div>`;
  html += `<div class="metrics" style="margin-top:14px">` + st.targets.map(t => `<div class="metric">
    <div class="label">${esc(t.label)} <span class="mono">${esc(t.ip)}</span></div>
    <div class="value">${t.uptimePct.toFixed(2)} <small>% no ar</small></div>
    <div class="sub">média ${t.avgMs.toFixed(0)} ms · máx ${t.maxMs.toFixed(0)} ms · jitter ${t.jitterMs.toFixed(1)} ms · perda ${t.lossPct}%</div>${lvl(t.level)}</div>`).join("") + `</div>`;
  html += `<div style="margin-top:14px">${timeline(st)}</div>`;
  html += `<h2>Eventos (${st.events.length})</h2>`;
  html += st.events.length ? `<div class="tablewrap"><table><thead><tr><th>Tipo</th><th>Onde</th><th>Início</th><th>Duração</th><th>Detalhe</th></tr></thead><tbody>` +
    [...st.events].reverse().map(e => `<tr><td>${e.kind === "queda" ? '<span class="lvl pessimo">Queda</span>' : '<span class="lvl ruim">Pico</span>'}</td>
      <td>${{ "rede-local": "Rede local / roteador", internet: "Internet / provedor", destino: "Destino " + esc(e.target) }[e.scope]}</td>
      <td class="mono">${fmtTime(e.start)}</td><td class="num">${fmtDur(e.seconds)}</td><td>${esc(e.detail)}</td></tr>`).join("") + `</tbody></table></div>`
    : '<p class="sub">Nenhuma queda ou pico registrado.</p>';
  html += legend("latencia", "latencia-lan", "jitter", "perda");
  $("mcontent").innerHTML = html;
}

pollMonitor();
