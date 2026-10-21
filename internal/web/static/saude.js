// Aba "Saúde da conexão": teste completo da Fase 3.
const STEP_NAMES = { internet: "Conexão com a internet", latencia: "Latência (25 pings por destino)",
  traceroute: "Traceroute até 8.8.8.8", dns: "DNS (velocidade e sequestro)", mtu: "MTU do caminho" };
const KIND_TAG = { privado: '<span class="tag">privado</span>', cgnat: '<span class="tag risk">CGNAT</span>', publico: '<span class="tag">público</span>' };

// spark é um mini gráfico de barras para caber numa célula da tabela.
function spark(rtts, scaleId) {
  const W = 125, H = 26, vals = rtts.filter(v => v >= 0);
  const top = Math.max(...vals, 5), bw = W / Math.max(rtts.length, 1);
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="display:block">` + rtts.map((v, i) => v < 0
    ? `<rect x="${i * bw}" y="0" width="${Math.max(bw - 1, 1)}" height="${H}" fill="var(--l4)" opacity=".35"/>`
    : `<rect x="${i * bw}" y="${H - Math.max(2, v / top * H)}" width="${Math.max(bw - 1, 1)}" height="${Math.max(2, v / top * H)}" fill="var(--l${["excelente","razoavel","ruim","pessimo"].indexOf(rate(scaleId, v)) + 1})"/>`).join("") + "</svg>";
}

// Meio da conexão: escolhido pelo técnico ou detectado pela placa em uso.
const currentMedium = () => app.atend.meio || (app.primary?.type === "Wi-Fi" ? "wifi" : "cabo");
function renderMedium() {
  document.querySelectorAll("#meio button").forEach(b => b.classList.toggle("on", b.dataset.v === currentMedium()));
}
document.querySelectorAll("#meio button").forEach(b => b.onclick = () => {
  saveAtend({ meio: b.dataset.v }).then(renderMedium).catch(e => showError(e.message));
});
app.ready.then(renderMedium);

function runHealth() {
  showError("");
  $("hgo").disabled = true;
  $("hprogress").style.display = "block";
  const es = new EventSource(`api/health?plano=${app.atend.planoMbps || 0}&meio=${currentMedium()}`);
  es.addEventListener("inicio", (e) => {
    $("hsteps").innerHTML = JSON.parse(e.data).steps.map(s => `<span id="step-${s}">${esc(STEP_NAMES[s] || s)}</span>`).join("");
  });
  es.addEventListener("etapa", (e) => $("step-" + JSON.parse(e.data))?.classList.add("done"));
  es.addEventListener("fim", (e) => {
    es.close();
    $("hgo").disabled = false;
    $("hprogress").style.display = "none";
    renderHealth(JSON.parse(e.data));
  });
  es.onerror = () => {
    es.close();
    $("hgo").disabled = false;
    $("hprogress").style.display = "none";
    showError("O teste foi interrompido (o programa foi fechado?).");
  };
}

function renderHealth(r) {
  const cq = r.call;
  let html = `<div class="finding big ${r.summary.level}" style="margin-top:14px"><b>${esc(r.summary.title)}</b>${esc(r.summary.detail)}</div>`;

  html += `<h2>Qualidade para chamadas de vídeo e voz</h2>`;
  if (cq) {
    html += `<div class="metrics">
      <div class="metric"><div class="label">Veredito</div><div class="value">${lvl(cq.level)}</div><div class="sub">${esc(cq.verdict)}</div></div>
      <div class="metric"><div class="label">Latência média</div><div class="value">${cq.latencyMs.toFixed(0)} <small>ms</small></div>${lvl(rate("latencia", cq.latencyMs))}</div>
      <div class="metric"><div class="label">Jitter</div><div class="value">${cq.jitterMs.toFixed(1)} <small>ms</small></div>${lvl(rate("jitter", cq.jitterMs))}</div>
      <div class="metric"><div class="label">Perda de pacotes</div><div class="value">${cq.lossPct} <small>%</small></div>${lvl(rate("perda", cq.lossPct))}</div>
    </div><div class="sub" style="margin-top:6px">Base: ${esc(cq.basis)}</div>`;
  } else {
    html += `<div class="sub">Sem acesso à internet: não foi possível avaliar.</div>`;
  }

  const others = r.findings.filter(f => f.title !== r.summary.title);
  if (others.length) {
    html += `<h2>Outros pontos</h2><div class="findings">` +
      others.map(f => `<div class="finding ${f.level}"><b>${esc(f.title)}</b>${esc(f.detail)}</div>`).join("") + `</div>`;
  }

  html += `<h2>Latência por destino</h2><div class="tablewrap"><table><thead><tr>
    <th>Destino</th><th>IP</th><th>Média</th><th>Mín / Máx</th><th>Jitter</th><th>Perda</th><th>25 pings</th><th>Resultado</th></tr></thead><tbody>` +
    r.latency.map(t => {
      const s = t.stats;
      if (t.error) return `<tr><td>${esc(t.label)}</td><td class="mono">${esc(t.host)}</td><td colspan="6" class="bad">${esc(t.error)}</td></tr>`;
      return `<tr><td>${esc(t.label)}${s.scale.startsWith("latencia-lan") ? '<div class="sub">escala de rede local</div>' : ""}</td>
        <td class="mono">${esc(t.ip)}</td>
        <td class="num">${s.received ? fmtMs(s.avgMs) : "—"} ${lvl(s.latency)}</td>
        <td class="num">${s.received ? fmtMs(s.minMs) + " / " + fmtMs(s.maxMs) : "—"}</td>
        <td class="num">${s.received ? fmtMs(s.jitterMs) : "—"} ${lvl(s.jitterLevel)}</td>
        <td class="num">${s.lossPct}% ${lvl(s.lossLevel)}</td>
        <td>${spark(t.rtts, s.scale)}</td>
        <td>${lvl(s.overall)}</td></tr>`;
    }).join("") + `</tbody></table></div>`;

  html += `<div class="cards" style="margin-top:22px">`;
  html += `<div class="card" style="grid-column:span 2;min-width:0"><h3>Traceroute até ${esc(r.traceTo)}</h3><div style="overflow-x:auto"><table><thead><tr><th>Salto</th><th>IP</th><th>Tempo</th><th>Tipo</th></tr></thead><tbody>` +
    r.trace.map(h => `<tr><td class="num">${h.ttl}</td><td class="mono">${h.ip ? esc(h.ip) : '<span class="sub">* sem resposta</span>'}${h.ip === r.gateway ? ' <span class="tag gw">gateway</span>' : ""}${h.reached ? ' <span class="tag self">destino</span>' : ""}</td>
      <td class="num">${fmtMs(h.bestMs)}</td><td>${h.ip ? KIND_TAG[h.kind] || "" : ""}</td></tr>`).join("") + `</tbody></table></div></div>`;

  const dns = [...r.dns].sort((a, b) => (a.medianMs < 0) - (b.medianMs < 0) || a.medianMs - b.medianMs);
  html += `<div class="card"><h3>Servidores DNS (mediana de 8 consultas)</h3><table><tbody>` +
    dns.map(d => `<tr${d.local ? ' class="hl"' : ""}><td>${esc(d.local ? "Configurado" : d.label)}<div class="sub mono">${esc(d.ip)}</div></td>
      <td class="num">${d.medianMs < 0 ? '<span class="bad">não respondeu</span>' : fmtMs(d.medianMs)}${d.failures ? `<div class="sub">${d.failures} falha(s)</div>` : ""}</td>
      <td>${lvl(d.level)}</td></tr>`).join("") + `</tbody></table></div>`;

  if (r.mtu) html += `<div class="card"><h3>MTU do caminho</h3>${kv([["MTU", `${r.mtu.pathMtu} bytes`], ["Placa local", r.mtu.localMtu ? r.mtu.localMtu + " bytes" : ""],
    ["Teste no CMD", `<span class="mono">ping -f -l ${r.mtu.maxPayload} ${esc(r.mtu.target)}</span>`]])}<div class="sub" style="margin-top:6px">${esc(r.mtu.verdict)}</div></div>`;
  if (r.hijack) html += `<div class="card"><h3>Sequestro de DNS</h3>${r.hijack.results.map(h => `<div>${esc(h.local ? "Configurado " + h.ip : h.label + " " + h.ip)}: ${h.hijacked ? '<span class="bad">responde ' + esc(h.answers.join(", ")) + "</span>" : '<span class="ok">recusa corretamente</span>'}</div>`).join("")}<div class="sub" style="margin-top:6px">${esc(r.hijack.verdict)}</div></div>`;
  if (r.wifi?.connection) {
    const c = r.wifi.connection;
    html += `<div class="card"><h3>Wi-Fi</h3>${kv([["Rede", esc(c.ssid)], ["Sinal", `${c.rssi} dBm (${c.signalPct}%) ${lvl(r.wifi.signalLevel)}`],
      ["Banda / canal", `${c.bandGHz} GHz / ${c.channel}`], ["Velocidade do link", `${c.rxMbps.toFixed(0)} Mbps`]])}</div>`;
  }
  const v6 = r.ipv6, v6cls = { ativo: "ok", "sem-internet": "bad", "so-link-local": "warn", desabilitado: "warn" }[v6.state];
  html += `<div class="card"><h3>IPv6</h3>${kv([["Status", `<span class="${v6cls}">${{ ativo: "Habilitado", "sem-internet": "Habilitado, sem internet", "so-link-local": "Sem prefixo do roteador", desabilitado: "Desabilitado" }[v6.state]}</span>`],
    ["Internet IPv6", v6.internet ? '<span class="ok">sim</span>' : '<span class="sub">não</span>'],
    ["Endereço global", v6.global.map(esc).join("<br>")], ["IP público v6", esc(r.internet.publicIPv6)]])}<div class="sub" style="margin-top:6px">${esc(v6.text)}</div></div>`;
  const inet = r.internet;
  html += `<div class="card"><h3>Conexão</h3>${kv([["Interface", esc(r.interface) + (r.ifType ? ` <span class="sub">${esc(r.ifType)}</span>` : "")],
    ["Placa negociada", r.linkMbps ? `${r.linkMbps} Mbps` + (r.planMbps && r.linkMbps < r.planMbps ? ' <span class="tag risk">abaixo do plano</span>' : "") : ""],
    ["Plano", r.planMbps ? r.planMbps + " Mega" : '<span class="sub">não informado</span>'],
    ["Meio avaliado", r.medium === "wifi" ? "Wi-Fi (faixas de latência x2)" : "Cabeado"],
    ["Gateway", esc(r.gateway) || '<span class="bad">nenhum</span>'],
    ["Internet", inet.online ? '<span class="ok">online</span>' : '<span class="bad">offline</span>'],
    ["IPv6", inet.ipv6 ? '<span class="ok">sim</span>' : '<span class="sub">não</span>'],
    ["IP público", esc(inet.publicIPv4)], ["IP público v6", esc(inet.publicIPv6)]])}</div></div>`;

  const w = r.medium === "wifi" ? "-wifi" : "";
  html += `<h2>Como ler as classificações</h2>` + legend("latencia" + w, "latencia-lan" + w, "jitter", "perda", "dns", "sinal");
  html += `<div class="footer">Teste de ${fmtDate(r.startedAt)} · ${r.durationS.toFixed(1)} s</div>`;
  $("hcontent").innerHTML = html;
}

$("hgo").onclick = runHealth;
