// Página do relatório: monta o documento a partir dos testes do atendimento.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtDate = (s) => s && !s.startsWith("0001") ? new Date(s).toLocaleString("pt-BR") : "";
const NAMES = { excelente: "Excelente", razoavel: "Razoável", ruim: "Ruim", pessimo: "Péssimo" };
const lvl = (l) => l ? `<span class="lvl ${l}">${NAMES[l]}</span>` : "";
const kv = (rows) => '<dl class="kv">' + rows.filter(r => r[1] !== undefined && r[1] !== "" && r[1] !== null)
  .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("") + "</dl>";
const findings = (list) => list.map(f => `<div class="finding ${f.level}"><b>${esc(f.title)}</b>${esc(f.detail)}</div>`).join("");
let scales = {}, medium = "cabo";
const rate = (id, v) => {
  const s = scales[id.startsWith("latencia") && medium === "wifi" ? id + "-wifi" : id];
  if (!s || v == null) return "";
  if (s.higher) return v >= s.excelente ? "excelente" : v >= s.razoavel ? "razoavel" : v >= s.ruim ? "ruim" : "pessimo";
  return v <= s.excelente ? "excelente" : v <= s.razoavel ? "razoavel" : v <= s.ruim ? "ruim" : "pessimo";
};

// metrics extrai os números comparáveis de um teste de saúde e de um de velocidade.
function metrics(h, sp) {
  const m = {};
  if (h) {
    const gw = h.latency.find(t => t.role === "gateway");
    if (gw && gw.stats.received) Object.assign(m, { gwLat: gw.stats.avgMs, gwJit: gw.stats.jitterMs, gwLoss: gw.stats.lossPct });
    if (h.call) Object.assign(m, { netLat: h.call.latencyMs, netJit: h.call.jitterMs, netLoss: h.call.lossPct, call: h.call.level });
    const dns = h.dns.find(d => d.local);
    if (dns && dns.medianMs >= 0) m.dns = dns.medianMs;
    if (h.wifi?.connection) m.signal = h.wifi.connection.rssi;
  }
  if (sp) Object.assign(m, { down: sp.downloadMbps, up: sp.uploadMbps, bloat: Math.max(sp.bloatDownMs, sp.bloatUpMs) });
  return m;
}

const ROWS = [
  ["gwLat", "Latência até o roteador", "ms", true, "latencia-lan"], ["gwJit", "Jitter até o roteador", "ms", true, "jitter"],
  ["gwLoss", "Perda até o roteador", "%", true, "perda"], ["netLat", "Latência até a internet", "ms", true, "latencia"],
  ["netJit", "Jitter na internet", "ms", true, "jitter"], ["netLoss", "Perda na internet", "%", true, "perda"],
  ["dns", "Resposta do DNS configurado", "ms", true, "dns"], ["signal", "Sinal do Wi-Fi", "dBm", false, "sinal"],
  ["down", "Download", "Mbps", false, ""], ["up", "Upload", "Mbps", false, ""], ["bloat", "Aumento de latência em uso", "ms", true, "bufferbloat"],
];

function compareTable(before, after) {
  const fmt = (v, u) => v == null ? "—" : `${u === "Mbps" || u === "dBm" ? Math.round(v) : (+v).toFixed(1).replace(".0", "")} ${u}`;
  const rows = ROWS.filter(([k]) => before[k] != null || after[k] != null).map(([k, label, unit, lowerBetter, scale]) => {
    const b = before[k], a = after[k];
    let diff = "";
    if (b != null && a != null && Math.abs(a - b) > (unit === "%" ? 0 : 0.5)) {
      const better = lowerBetter ? a < b : a > b;
      diff = `<span class="${better ? "better" : "worse"}">${better ? "melhorou" : "piorou"}</span>`;
    }
    return `<tr><td>${label}</td><td class="num">${fmt(b, unit)} ${scale ? lvl(rate(scale, b)) : ""}</td>
      <td class="num">${fmt(a, unit)} ${scale ? lvl(rate(scale, a)) : ""}</td><td>${diff}</td></tr>`;
  });
  if (before.call || after.call) rows.push(`<tr><td>Qualidade para chamadas</td><td class="num">${lvl(before.call) || "—"}</td><td class="num">${lvl(after.call) || "—"}</td><td></td></tr>`);
  return `<table><thead><tr><th>Medição</th><th class="num">Antes</th><th class="num">Depois</th><th></th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

function singleTable(m) {
  const fmt = (v, u) => `${u === "Mbps" || u === "dBm" ? Math.round(v) : (+v).toFixed(1).replace(".0", "")} ${u}`;
  const rows = ROWS.filter(([k]) => m[k] != null).map(([k, label, unit, , scale]) =>
    `<tr><td>${label}</td><td class="num">${fmt(m[k], unit)}</td><td>${scale ? lvl(rate(scale, m[k])) : ""}</td></tr>`);
  if (m.call) rows.push(`<tr><td>Qualidade para chamadas</td><td class="num"></td><td>${lvl(m.call)}</td></tr>`);
  return `<table><thead><tr><th>Medição</th><th class="num">Resultado</th><th>Classificação</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

async function render() {
  const d = await (await fetch("api/relatorio/dados")).json();
  (d.scales || []).forEach(s => scales[s.id] = s);
  const a = d.atendimento, scan = d.scanLast, h = d.healthLast, sp = d.speedLast;
  medium = h?.medium || "cabo";
  let html = `<header><div><h1><img src="icon.png" alt="">Relatório de Atendimento Técnico</h1>
      <div class="muted">Quasar Scan · diagnóstico de rede e conexão</div></div>
    <div class="meta">Emitido em ${fmtDate(d.geradoEm)}<br>${a.iniciadoEm ? "Atendimento iniciado em " + fmtDate(a.iniciadoEm) + "<br>" : ""}Computador usado: ${esc(d.computador)}</div></header>`;

  html += `<div class="grid">${kv([["Cliente", esc(a.cliente) || '<span class="muted">não informado</span>'], ["Código / contrato", esc(a.codigo)], ["Endereço", esc(a.endereco)]])}
    ${kv([["Técnico", esc(a.tecnico)], ["Plano contratado", a.planoMbps ? a.planoMbps + " Mega" : ""]])}</div>`;
  if (a.problema) html += `<h2>Problema relatado</h2><div class="box">${esc(a.problema)}</div>`;

  // Diagnóstico principal
  if (h) {
    html += `<h2>Diagnóstico</h2>` + findings([h.summary]) +
      findings(h.findings.filter(f => f.level !== "info" && f.title !== h.summary.title).slice(0, 8));
  }

  // Antes e depois
  // Só compara o que foi medido mais de uma vez; o resto aparece apenas no "depois".
  const before = metrics(d.healths >= 2 ? d.healthFirst : null, d.speeds >= 2 ? d.speedFirst : null), after = metrics(h, sp);
  const hasCompare = d.healths >= 2 || d.speeds >= 2;
  if (Object.keys(after).length) {
    html += hasCompare
      ? `<h2>Antes e depois do atendimento</h2><p class="muted">Antes: primeiro teste (${fmtDate(d.healthFirst?.startedAt)}). Depois: último teste (${fmtDate(h?.startedAt)}).</p>` + compareTable(before, after)
      : `<h2>Medições</h2>` + singleTable(after);
  }

  if (a.solucao) html += `<h2>Solução aplicada</h2><div class="box">${esc(a.solucao)}</div>`;

  // Conexão
  if (scan || h) {
    const it = scan?.interface;
    const cgnat = h?.findings.some(f => f.title.includes("CGNAT"));
    html += `<h2>Conexão</h2><div class="grid">` + kv([
      ["Interface", it ? `${esc(it.name)} (${esc(it.type)})` : esc(h?.interface)],
      ["Velocidade da placa", (it?.speedMbps || h?.linkMbps) ? (it?.speedMbps || h.linkMbps) + " Mbps" : ""],
      ["IP local", it ? it.ipv4.map(x => esc(x.address + "/" + x.prefixLen)).join(", ") : ""],
      ["Gateway", it ? it.gateways.filter(g => g.includes(".")).map(esc).join(", ") : esc(h?.gateway)],
      ["DNS", it ? it.dnsServers.map(esc).join(", ") : ""],
    ]) + kv([
      ["IP público", esc(h?.internet.publicIPv4 || scan?.internet?.publicIPv4)],
      ["IPv6", h ? esc(h.ipv6.text) : (scan?.internet?.ipv6 ? "Sim" : "Não")],
      ["Meio do teste", h ? (h.medium === "wifi" ? "Wi-Fi" : "Cabeado") : ""],
      ["Tipo de teste", h ? (h.mode === "completo" ? `Check-up completo (${h.samples} pings por destino)` : `Teste rápido (${h.samples} pings por destino)`) : ""],
      ["CGNAT", h ? (cgnat ? "Sim" : "Não detectado") : ""],
      ["MTU do caminho", h?.mtu ? h.mtu.pathMtu + " bytes" : ""],
      ["Servidores DHCP", scan ? (scan.dhcpServers.length ? scan.dhcpServers.map(o => esc(o.server)).join(", ") : "nenhum respondeu") : ""],
    ]) + `</div>`;
  }

  // Wi-Fi
  const w = d.wifi;
  if (w?.connection) {
    const c = w.connection;
    html += `<h2>Wi-Fi</h2><div class="grid">` + kv([["Rede", esc(c.ssid)], ["Sinal", `${c.rssi} dBm ${lvl(w.signalLevel)}`], ["Banda / canal", `${c.bandGHz} GHz / canal ${c.channel}`]]) +
      kv([["Padrão", esc(c.phy)], ["Velocidade do link", Math.round(c.rxMbps) + " Mbps"], ["Segurança", esc(c.security)]]) + `</div>` +
      findings(w.findings.filter(f => f.level !== "info"));
  }

  // Velocidade
  if (sp) {
    html += `<h2>Teste de velocidade</h2>` + kv([["Download", `${Math.round(sp.downloadMbps)} Mbps${sp.planMbps ? ` (${Math.round(sp.downloadMbps / sp.planMbps * 100)}% do plano)` : ""}`],
      ["Upload", Math.round(sp.uploadMbps) + " Mbps"], ["Latência", `${Math.round(sp.idleMs)} ms ociosa · ${Math.round(sp.downLoadedMs)} ms no download · ${Math.round(sp.upLoadedMs)} ms no upload`],
      ["Servidor", esc(sp.server)], ["Realizado em", d.speeds > 1 ? `${d.speeds} testes; mostrado o último` : ""]]);
  }

  // Monitoramento
  const m = d.monitor;
  if (m) {
    const dur = Math.round(m.elapsed / 60);
    html += `<h2>Monitoramento contínuo</h2><p>${fmtDate(m.startedAt)} — ${dur} minuto(s)${m.running ? " (ainda em andamento)" : ""}. ${esc(m.summary)}</p><table><thead><tr><th>Destino</th><th class="num">No ar</th><th class="num">Perda</th><th class="num">Média</th><th class="num">Máx.</th></tr></thead><tbody>` +
      m.targets.map(t => `<tr><td>${esc(t.label)} <span class="mono muted">${esc(t.ip)}</span></td><td class="num">${t.uptimePct.toFixed(2)}%</td><td class="num">${t.lossPct}%</td><td class="num">${Math.round(t.avgMs)} ms</td><td class="num">${Math.round(t.maxMs)} ms</td></tr>`).join("") + `</tbody></table>`;
    const quedas = m.events.filter(e => e.kind === "queda");
    if (quedas.length) html += `<p><b>Quedas:</b></p><table><tbody>` + quedas.map(e => `<tr><td>${new Date(e.start).toLocaleString("pt-BR")}</td><td class="num">${e.seconds}s</td><td>${esc(e.detail)}</td></tr>`).join("") + `</tbody></table>`;
  }

  // Inspeção do computador
  const pc = d.pc;
  if (pc) {
    const gradeTxt = { excelente: "Saudável", razoavel: "Pontos de atenção", ruim: "Problemas encontrados", pessimo: "Em risco" }[pc.grade];
    const problems = pc.checklist.filter(c => c.status === "critico" || c.status === "aviso");
    html += `<h2>Inspeção do computador</h2><p><b>Nota ${pc.score}/100 — ${gradeTxt}.</b> ${esc(pc.summary)} <span class="muted">(${esc(pc.system.os)}, ${fmtDate(pc.startedAt)})</span></p>`;
    html += `<table><thead><tr><th>Conferência</th><th>Situação</th></tr></thead><tbody>` +
      pc.checklist.map(c => `<tr><td>${esc(c.item)}</td><td>${{ ok: "✔ ", aviso: "⚠ ", critico: "✖ ", info: "" }[c.status]}${esc(c.value)}${c.detail && c.status !== "ok" ? `<div class="muted">${esc(c.detail)}</div>` : ""}</td></tr>`).join("") + `</tbody></table>`;
    if (pc.findings?.length) {
      html += `<p style="margin-top:10px"><b>Itens suspeitos ou que merecem atenção:</b></p>` + findings(pc.findings.slice(0, 12).map(f => ({ level: f.level, title: `${f.category}: ${f.title}`, detail: f.detail + (f.path ? " — " + f.path : "") })));
    } else if (!problems.length) {
      html += `<p>Nenhum programa, processo ou serviço suspeito encontrado.</p>`;
    }
  }

  // Dispositivos
  if (scan) {
    html += `<h2>Dispositivos na rede (${scan.hosts.length})</h2><table><thead><tr><th>IP</th><th>Nome</th><th>Fabricante / modelo</th><th>Tipo</th></tr></thead><tbody>` +
      scan.hosts.map(x => `<tr><td class="mono">${esc(x.ip)}</td><td>${esc(x.friendlyName || x.hostname || x.netbios || x.mdnsName || "—")}</td>
        <td>${esc(x.model || x.vendor || (x.randomMac ? "MAC aleatório" : "—"))}</td><td>${esc(x.deviceType)}</td></tr>`).join("") + `</tbody></table>`;
  }

  if (!scan && !h && !sp && !w && !m && !pc) html += `<p class="muted" style="margin-top:20px">Nenhum teste foi feito neste atendimento ainda.</p>`;

  html += `<div class="sign"><div>${esc(a.tecnico) || "Técnico"}</div><div>${esc(a.cliente) || "Cliente"}</div></div>
    <footer>Gerado pelo Quasar Scan · ${fmtDate(d.geradoEm)}</footer>`;
  document.getElementById("page").innerHTML = html;
  document.title = `Relatório - ${a.cliente || "atendimento"} - ${new Date().toLocaleDateString("pt-BR")}`;
}

document.getElementById("print").onclick = () => window.print();
document.getElementById("save").onclick = async () => {
  // Salva só o documento, sem botões nem scripts.
  const clone = document.documentElement.cloneNode(true);
  clone.querySelectorAll(".noprint, script").forEach(e => e.remove());
  clone.querySelectorAll('link[rel="icon"]').forEach(e => e.remove());
  clone.querySelectorAll("img").forEach(e => e.remove());
  const html = "<!doctype html>\n" + clone.outerHTML;
  const r = await fetch("api/relatorio/salvar", { method: "POST", body: JSON.stringify({ html }) });
  document.getElementById("saved").textContent = r.ok ? "Salvo em " + (await r.json()).path : "Erro ao salvar";
};
render().catch(e => { document.getElementById("page").innerHTML = `<p>Erro ao montar o relatório: ${esc(e.message)}</p>`; });
