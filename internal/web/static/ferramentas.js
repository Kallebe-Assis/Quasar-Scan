// Aba "Diagnóstico de rede": os comandos do CMD com interface e classificação.
let stream = null; // EventSource da ferramenta ativa (ping/tracert)

function stopStream() {
  if (stream) { stream.close(); stream = null; }
}

const gwChip = () => app.gateway ? `<button class="chip" data-v="${esc(app.gateway)}">Roteador (${esc(app.gateway)})</button>` : "";
function hostChips(extra = []) {
  return `<div class="chips"><span class="sub">Atalhos:</span>${gwChip()}` +
    [["8.8.8.8", "Google DNS"], ["1.1.1.1", "Cloudflare"], ["www.google.com.br", "google.com.br"], ...extra]
      .map(([v, l]) => `<button class="chip" data-v="${esc(v)}">${esc(l)}</button>`).join("") + `</div>`;
}
// bindChips faz os atalhos preencherem o campo indicado.
function bindChips(root, inputId, after) {
  root.querySelectorAll(".chip[data-v]").forEach(c => c.onclick = () => { $(inputId).value = c.dataset.v; after?.(); });
}
const protoSelect = (id) => `<label class="f">Protocolo<select id="${id}" title="Vale para nomes; IPs digitados são detectados sozinhos"><option value="">IPv4</option><option value="6">IPv6</option></select></label>`;
const v6chips = () => `<button class="chip" data-v="2001:4860:4860::8888">Google IPv6</button><button class="chip" data-v="2606:4700:4700::1111">Cloudflare IPv6</button>`;
const cmdLine = (id) => `<div class="cmd">Equivalente no CMD: <code id="${id}"></code></div>`;

// ---------- Ping ----------
function toolPing(el) {
  el.innerHTML = `<h2>Ping</h2>
    <p class="about">Testa se um equipamento responde e mede o tempo de resposta (latência), a variação (jitter) e a perda de pacotes. Use para checar o roteador, a internet ou qualquer IP.</p>
    <div class="form">
      <label class="f">Destino (IP ou nome)<input type="text" id="p-host" class="mono" value="${esc(app.gateway || "8.8.8.8")}" style="width:220px"></label>
      <label class="f">Quantidade<select id="p-count"><option value="4">4</option><option value="10" selected>10</option><option value="30">30</option><option value="100">100</option><option value="0">Contínuo (até parar)</option></select></label>
      <label class="f">Tamanho (bytes)<input type="number" id="p-size" value="32" min="1" max="65500" style="width:100px"></label>
      ${protoSelect("p-ip")}
      <button id="p-go">Iniciar</button>
      ${hostChips()}${v6chips()}
    </div>
    ${cmdLine("p-cmd")}
    <div class="console" id="p-out"></div>
    <div class="metrics" id="p-metrics"></div>
    <div id="p-chart"></div>
    <div id="p-verdict"></div>
    <div id="p-legend"></div>`;
  const upd = () => {
    const n = +$("p-count").value, size = +$("p-size").value;
    $("p-cmd").textContent = `ping ${$("p-ip").value === "6" ? "-6 " : ""}${n === 0 ? "-t" : "-n " + n}${size !== 32 ? " -l " + size : ""} ${$("p-host").value.trim()}`;
  };
  ["p-host", "p-count", "p-size", "p-ip"].forEach(id => $(id).oninput = upd);
  bindChips(el, "p-host", upd);
  upd();

  $("p-go").onclick = () => {
    if (stream) { finishPing(true); return; }
    const host = $("p-host").value.trim(), out = $("p-out");
    out.innerHTML = ""; $("p-metrics").innerHTML = ""; $("p-chart").innerHTML = ""; $("p-verdict").innerHTML = "";
    const rtts = [];
    let last = null, ip = host, scale = "latencia";
    const line = (html) => { out.insertAdjacentHTML("beforeend", html + "\n"); out.scrollTop = out.scrollHeight; };
    stream = new EventSource(`api/tools/ping?host=${encodeURIComponent(host)}&count=${$("p-count").value}&size=${$("p-size").value}&ip=${$("p-ip").value}`);
    $("p-go").textContent = "Parar"; $("p-go").className = "stop";

    stream.addEventListener("inicio", (e) => {
      const d = JSON.parse(e.data); ip = d.ip; scale = d.local ? "latencia-lan" : "latencia";
      line(`Disparando ${esc(d.host)}${d.host !== d.ip ? " [" + esc(d.ip) + "]" : ""} com ${d.size} bytes de dados:`);
      $("p-legend").innerHTML = legend(scale, "jitter", "perda") + (d.local ? '<div class="sub" style="margin-top:4px">O destino está na rede local, então a latência usa a escala de rede local (mais exigente).</div>' : "");
    });
    stream.addEventListener("resposta", (e) => {
      const { reply: r, stats } = JSON.parse(e.data); last = stats;
      if (r.ok) {
        const t = r.rttMs < 1 ? "<1ms" : "=" + r.rttMs.toFixed(0) + "ms";
        line(`<span class="c-${rate(scale, r.rttMs)}">Resposta de ${esc(r.from)}: bytes=${r.bytes} tempo${t}${r.ttl ? " TTL=" + r.ttl : ""}</span>`);
      } else {
        line(`<span class="e">${r.from ? "Resposta de " + esc(r.from) + ": " : ""}${esc(r.status)}.</span>`);
      }
      rtts.push(r.ok ? r.rttMs : -1);
      $("p-chart").innerHTML = rttChart(rtts.slice(-100), scale);
      renderPingMetrics(stats);
    });
    stream.addEventListener("fim", () => finishPing(false));
    stream.addEventListener("erro", (e) => { line(`<span class="e">${esc(JSON.parse(e.data).message)}</span>`); finishPing(false); });
    stream.onerror = () => finishPing(false);

    window.finishPing = (stopped) => {
      stopStream();
      $("p-go").textContent = "Iniciar"; $("p-go").className = "";
      if (!last) return;
      if (stopped) line("Interrompido pelo usuário.");
      line(`\nEstatísticas do Ping para ${esc(ip)}:\n    Pacotes: Enviados = ${last.sent}, Recebidos = ${last.received}, Perdidos = ${last.sent - last.received} (${last.lossPct}% de perda)` +
        (last.received ? `\nAproximar um número redondo de vezes em milissegundos:\n    Mínimo = ${last.minMs.toFixed(0)}ms, Máximo = ${last.maxMs.toFixed(0)}ms, Média = ${last.avgMs.toFixed(0)}ms` : ""));
      const msg = { excelente: "Conexão excelente com este destino.", razoavel: "Conexão aceitável, com alguma lentidão ou oscilação.",
        ruim: "Conexão ruim: lentidão ou instabilidade perceptível.", pessimo: "Conexão péssima: muito lenta, instável ou sem resposta." }[last.overall];
      const cls = { excelente: "ok", razoavel: "info", ruim: "aviso", pessimo: "critico" }[last.overall];
      $("p-verdict").innerHTML = `<div class="finding ${cls}" style="margin-top:10px"><b>Resultado: ${LEVEL_NAMES[last.overall]}</b>${msg}</div>`;
    };
  };
}

function renderPingMetrics(s) {
  $("p-metrics").innerHTML = `
    <div class="metric"><div class="label">Enviados / Recebidos</div><div class="value">${s.sent} <small>/ ${s.received}</small></div></div>
    <div class="metric"><div class="label">Perda</div><div class="value">${s.lossPct} <small>%</small></div>${lvl(s.lossLevel)}</div>
    <div class="metric"><div class="label">Média</div><div class="value">${s.received ? s.avgMs.toFixed(1) : "—"} <small>ms</small></div>${lvl(s.latency)}</div>
    <div class="metric"><div class="label">Mín / Máx</div><div class="value">${s.received ? s.minMs.toFixed(0) + " <small>/ " + s.maxMs.toFixed(0) + " ms</small>" : "—"}</div></div>
    <div class="metric"><div class="label">Jitter</div><div class="value">${s.jitterMs.toFixed(1)} <small>ms</small></div>${lvl(s.jitterLevel)}</div>
    <div class="metric"><div class="label">Classificação geral</div><div class="value">${lvl(s.overall)}</div></div>`;
}

// ---------- Traceroute ----------
function toolTrace(el) {
  el.innerHTML = `<h2>Traceroute</h2>
    <p class="about">Mostra o caminho (saltos) até o destino. Ajuda a ver onde a conexão fica lenta ou para: dentro da casa, no roteador, no provedor ou depois. Também detecta CGNAT e duplo NAT. Aqui as sondas saem em paralelo, então é bem mais rápido que o tracert.</p>
    <div class="form">
      <label class="f">Destino (IP ou nome)<input type="text" id="t-host" class="mono" value="8.8.8.8" style="width:220px"></label>
      <label class="f">Máx. de saltos<select id="t-max"><option>15</option><option selected>30</option></select></label>
      <label class="chk"><input type="checkbox" id="t-names" checked> Resolver nomes</label>
      ${protoSelect("t-ip")}
      <button id="t-go">Iniciar</button>
      ${hostChips()}${v6chips()}
    </div>
    ${cmdLine("t-cmd")}
    <div id="t-out"></div><div id="t-find"></div>`;
  const upd = () => $("t-cmd").textContent = `tracert${$("t-ip").value === "6" ? " -6" : ""}${$("t-names").checked ? "" : " -d"} -h ${$("t-max").value} ${$("t-host").value.trim()}`;
  ["t-host", "t-max", "t-names", "t-ip"].forEach(id => $(id).oninput = upd);
  bindChips(el, "t-host", upd);
  upd();

  $("t-go").onclick = () => {
    stopStream();
    $("t-find").innerHTML = "";
    $("t-out").innerHTML = `<p class="sub" id="t-status">Rastreando…</p><div class="tablewrap"><table><thead><tr><th>Salto</th><th>Sonda 1</th><th>Sonda 2</th><th>Sonda 3</th><th>IP</th><th>Nome</th><th>Tipo</th></tr></thead><tbody id="t-rows"></tbody></table></div>`;
    $("t-go").disabled = true;
    const done = () => { stopStream(); $("t-go").disabled = false; };
    stream = new EventSource(`api/tools/trace?host=${encodeURIComponent($("t-host").value.trim())}&maxHops=${$("t-max").value}&names=${$("t-names").checked ? 1 : 0}&ip=${$("t-ip").value}`);
    stream.addEventListener("inicio", (e) => { const d = JSON.parse(e.data); $("t-status").textContent = `Rastreando a rota para ${d.host} [${d.ip}] com no máximo ${$("t-max").value} saltos:`; });
    stream.addEventListener("salto", (e) => {
      const h = JSON.parse(e.data);
      const probe = (v) => `<td class="num c-${rate("latencia", v)}">${v < 0 ? "*" : fmtMs(v)}</td>`;
      const probes = [0, 1, 2].map(i => probe(h.rtts[i] ?? -1)).join("");
      $("t-rows").insertAdjacentHTML("beforeend", `<tr><td class="num">${h.ttl}</td>${probes}
        <td class="mono">${h.ip ? esc(h.ip) : '<span class="sub">Esgotado o tempo limite</span>'}${h.ip === app.gateway ? ' <span class="tag gw">gateway</span>' : ""}${h.reached ? ' <span class="tag self">destino</span>' : ""}</td>
        <td>${esc(h.name)}</td><td>${h.ip ? KIND_TAG[h.kind] || "" : ""}</td></tr>`);
    });
    stream.addEventListener("fim", (e) => {
      const f = JSON.parse(e.data).findings;
      $("t-status").textContent += " — rastreamento concluído.";
      $("t-find").innerHTML = (f.length ? `<h2>Análise</h2><div class="findings">` + f.map(x => `<div class="finding ${x.level}"><b>${esc(x.title)}</b>${esc(x.detail)}</div>`).join("") + "</div>" : "") + legend("latencia");
      done();
    });
    stream.addEventListener("erro", (e) => { $("t-out").innerHTML = `<div class="finding critico"><b>Erro</b>${esc(JSON.parse(e.data).message)}</div>`; done(); });
    stream.onerror = done;
  };
}

// ---------- Consulta DNS ----------
async function toolDNS(el) {
  const info = await getJSON("api/tools/dnsservers");
  const opts = info.system.map(s => `<option value="${esc(s.ip)}">${esc(s.label)} — ${esc(s.ip)}</option>`).join("") +
    info.public.map(s => `<option value="${esc(s.ip)}">${esc(s.label)} — ${esc(s.ip)}</option>`).join("") + `<option value="outro">Outro…</option>`;
  el.innerHTML = `<h2>Consulta DNS</h2>
    <p class="about">Pergunta a um servidor DNS qual o IP (ou outro registro) de um nome. Use quando um site não abre pelo nome, para comparar o DNS do provedor com os públicos, ou para verificar registros de e-mail (MX).</p>
    <div class="form">
      <label class="f">Nome<input type="text" id="d-name" class="mono" value="google.com" style="width:220px"></label>
      <label class="f">Tipo<select id="d-type">${info.types.map(t => `<option>${t}</option>`).join("")}</select></label>
      <label class="f">Servidor<select id="d-server">${opts}</select></label>
      <label class="f" id="d-custom-wrap" style="display:none">IP do servidor<input type="text" id="d-custom" class="mono" placeholder="ex.: 200.0.0.1" style="width:140px"></label>
      <button id="d-go">Consultar</button>
    </div>
    ${cmdLine("d-cmd")}
    <div id="d-out" class="result"></div>
    <h2>Comparar servidores DNS</h2>
    <div class="panelbar"><div class="desc"><b>Velocidade de cada servidor</b>Mede a velocidade do DNS configurado e dos públicos (Cloudflare, Google, Quad9) com 8 consultas cada.</div><button id="d-bench" class="ghost">Comparar</button></div>
    <div id="d-bench-out" class="result"></div>
    <h2>Verificar sequestro de DNS</h2>
    <div class="panelbar"><div class="desc"><b>Teste com domínio inexistente</b>Pergunta por um domínio que não existe. O correto é “não existe”; se o DNS devolver um IP, ele está redirecionando (propaganda, roteador adulterado ou interceptação no caminho).</div><button id="d-hj" class="ghost">Verificar</button></div>
    <div id="d-hj-out" class="result"></div>`;
  const server = () => $("d-server").value === "outro" ? $("d-custom").value.trim() : $("d-server").value;
  const upd = () => {
    $("d-custom-wrap").style.display = $("d-server").value === "outro" ? "" : "none";
    const t = $("d-type").value;
    $("d-cmd").textContent = `nslookup ${t !== "A" ? "-type=" + t + " " : ""}${$("d-name").value.trim()} ${server()}`;
  };
  ["d-name", "d-type", "d-server", "d-custom"].forEach(id => $(id).oninput = upd);
  upd();

  $("d-go").onclick = async () => {
    $("d-out").innerHTML = '<p class="sub">Consultando…</p>';
    try {
      const r = await getJSON(`api/tools/dns?name=${encodeURIComponent($("d-name").value.trim())}&type=${$("d-type").value}&server=${encodeURIComponent(server())}`);
      $("d-out").innerHTML = `<div class="card">${kv([["Servidor", esc(r.server)], ["Nome", esc(r.name)], ["Tipo", esc(r.type)],
        ["Tempo", `${fmtMs(r.timeMs)} ${r.error ? "" : lvl(r.level)}`],
        [r.error ? "Erro" : "Respostas", r.error ? `<span class="bad">${esc(r.error)}</span>` : (r.answers.map(esc).join("<br>") || '<span class="sub">nenhuma</span>')]])}</div>` + legend("dns");
    } catch (e) { $("d-out").innerHTML = `<div class="finding critico"><b>Erro</b>${esc(e.message)}</div>`; }
  };
  $("d-hj").onclick = async () => {
    $("d-hj").disabled = true;
    $("d-hj-out").innerHTML = '<p class="sub">Consultando…</p>';
    const h = await getJSON("api/tools/hijack");
    $("d-hj-out").innerHTML = `<div class="finding ${h.level}"><b>${h.level === "ok" ? "Sem sequestro" : "Sequestro detectado"}</b>${esc(h.verdict)}</div>
      <div class="sub" style="margin-top:6px">Domínio testado: <span class="mono">${esc(h.domain)}</span> · ` +
      h.results.map(r => `${esc(r.local ? "configurado " + r.ip : r.label)}: ${r.hijacked ? '<span class="bad">' + esc(r.answers.join(", ")) + "</span>" : r.error ? esc(r.error) : '<span class="ok">não existe</span>'}`).join(" · ") + "</div>";
    $("d-hj").disabled = false;
  };
  $("d-bench").onclick = async () => {
    $("d-bench").disabled = true;
    $("d-bench-out").innerHTML = '<p class="sub">Medindo…</p>';
    const list = (await getJSON("api/tools/dnsbench")).sort((a, b) => (a.medianMs < 0) - (b.medianMs < 0) || a.medianMs - b.medianMs);
    $("d-bench-out").innerHTML = `<div class="tablewrap"><table><thead><tr><th>#</th><th>Servidor</th><th>IP</th><th>Mediana</th><th>Falhas</th><th>Resultado</th></tr></thead><tbody>` +
      list.map((d, i) => `<tr${d.local ? ' class="hl"' : ""}><td class="num">${i + 1}</td><td>${esc(d.label)}</td><td class="mono">${esc(d.ip)}</td>
        <td class="num">${d.medianMs < 0 ? '<span class="bad">não respondeu</span>' : fmtMs(d.medianMs)}</td><td class="num">${d.failures}</td><td>${lvl(d.level)}</td></tr>`).join("") +
      `</tbody></table></div>` + legend("dns");
    $("d-bench").disabled = false;
  };
}

// ---------- Configuração IP ----------
async function toolIPConfig(el) {
  el.innerHTML = `<h2>Configuração IP</h2>
    <p class="about">Mostra a configuração completa de todas as placas de rede: IP, máscara, gateway, DNS, DHCP, IPv6 e MAC.</p>
    <div class="form"><label class="chk"><input type="checkbox" id="i-all"> Mostrar desconectadas e virtuais</label><button id="i-go" class="ghost">Atualizar</button></div>
    <div class="cmd">Equivalente no CMD: <code>ipconfig /all</code></div>
    <div id="i-out" class="cards"></div>`;
  const render = async () => {
    const list = await getJSON("api/interfaces");
    const all = $("i-all").checked;
    $("i-out").innerHTML = list.filter(i => all || (i.status === "up" && !i.virtual)).map(i => `<div class="card"${i.isPrimary ? ' style="border-color:var(--accent)"' : ""}>
      <h3>${esc(i.name)}${i.isPrimary ? ' <span class="tag gw">principal</span>' : ""}${i.virtual ? ' <span class="tag">virtual</span>' : ""}</h3>
      ${kv([["Descrição", esc(i.description)], ["Status", i.status === "up" ? '<span class="ok">conectado</span>' : '<span class="sub">desconectado</span>'],
        ["Tipo", esc(i.type)], ["Endereço físico", esc(i.mac)], ["Velocidade", i.speedMbps ? i.speedMbps + " Mbps" : ""], ["MTU", i.mtu],
        ["DHCP", i.dhcp.enabled ? "Sim" : "Não"],
        ["IPv4", i.ipv4.map(a => esc(a.address)).join("<br>")], ["Máscara", i.ipv4.map(a => esc(a.mask)).join("<br>")],
        ["IPv6", i.ipv6.map(a => `${esc(a.address)}/${a.prefixLen} <span class="sub">${esc(a.scope)}</span>`).join("<br>")],
        ["Gateway", i.gateways.map(esc).join("<br>")], ["Servidor DHCP", esc(i.dhcp.server)],
        ["Concessão obtida", fmtDate(i.dhcp.leaseObtained)], ["Concessão expira", fmtDate(i.dhcp.leaseExpires)],
        ["Servidores DNS", i.dnsServers.map(esc).join("<br>")], ["Sufixo DNS", esc(i.dnsSuffix)], ["Métrica", i.metric]])}</div>`).join("")
      || '<div class="sub">Nenhuma interface conectada.</div>';
  };
  $("i-go").onclick = render; $("i-all").onchange = render;
  render();
}

// ---------- Limpar cache DNS ----------
function toolFlush(el) {
  el.innerHTML = `<h2>Limpar cache DNS</h2>
    <p class="about">Apaga os endereços de sites guardados pelo Windows. Use quando um site mudou de servidor, abre a página errada ou antiga, ou depois de trocar o DNS do roteador.</p>
    <div class="form"><button id="f-go">Limpar cache DNS</button></div>
    <div class="cmd">Equivalente no CMD: <code>ipconfig /flushdns</code></div>
    <div id="f-out" class="result"></div>
    <h2>Renovar IP (DHCP)</h2>
    <p class="about">Libera o IP atual e pede um novo ao servidor DHCP. Use quando a placa ficou com IP 169.254.x.x, depois de trocar o roteador ou mudar a configuração do DHCP. A conexão cai por alguns segundos.</p>
    <div class="form"><label class="f">Interface<select id="f-if"></select></label><button id="f-renew">Renovar IP</button></div>
    <div class="cmd">Equivalente no CMD (como administrador): <code>ipconfig /release</code> <code>ipconfig /renew</code></div>
    <div id="f-renew-out" class="result"></div>`;
  $("f-if").innerHTML = app.interfaces.filter(i => i.status === "up" && i.dhcp.enabled && !i.virtual)
    .map(i => `<option value="${i.index}">${esc(i.name)} — ${esc(i.ipv4[0]?.address || "sem IP")}</option>`).join("") || "<option value=0>Nenhuma interface com DHCP</option>";
  if (!app.info.admin) {
    $("f-renew").disabled = true;
    $("f-renew-out").innerHTML = '<div class="finding aviso"><b>Precisa de administrador</b>Feche o programa e abra pelo atalho, aceitando o pedido de administrador do Windows.</div>';
  }
  $("f-renew").onclick = async () => {
    if (!confirm("A conexão desta interface vai cair por alguns segundos. Continuar?")) return;
    $("f-renew").disabled = true;
    $("f-renew-out").innerHTML = '<p class="sub">Renovando… (pode levar até 1 minuto)</p>';
    try {
      const r = await getJSON("api/tools/renew", { method: "POST", body: JSON.stringify({ ifIndex: +$("f-if").value }) });
      $("f-renew-out").innerHTML = `<div class="finding ok"><b>Pronto</b>${esc(r.message)}</div>`;
    } catch (e) { $("f-renew-out").innerHTML = `<div class="finding critico"><b>Erro</b>${esc(e.message)}</div>`; }
    $("f-renew").disabled = false;
  };
  $("f-go").onclick = async () => {
    try {
      const r = await getJSON("api/tools/flushdns", { method: "POST" });
      $("f-out").innerHTML = `<div class="finding ok"><b>Pronto</b>${esc(r.message)}</div>`;
    } catch (e) { $("f-out").innerHTML = `<div class="finding critico"><b>Erro</b>${esc(e.message)}</div>`; }
  };
}

// ---------- Tabela ARP ----------
async function toolARP(el) {
  el.innerHTML = `<h2>Tabela ARP</h2>
    <p class="about">Lista os dispositivos com quem este computador conversou recentemente na rede local (IP ↔ MAC). Útil para achar o MAC de um equipamento ou detectar IP duplicado.</p>
    <div class="form"><input type="text" id="a-filter" placeholder="filtrar…" style="width:200px"><label class="chk"><input type="checkbox" id="a-all"> Incluir multicast/broadcast</label><button id="a-go" class="ghost">Atualizar</button></div>
    <div class="cmd">Equivalente no CMD: <code>arp -a</code></div>
    <div id="a-out"></div>`;
  let rows = [];
  const render = () => {
    const q = $("a-filter").value.toLowerCase(), all = $("a-all").checked;
    const list = rows.filter(r => (all || r.kind === "unicast") && (!q || JSON.stringify(r).toLowerCase().includes(q)));
    $("a-out").innerHTML = `<div class="tablewrap"><table><thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>Tipo</th><th>Interface</th></tr></thead><tbody>` +
      list.map(r => `<tr${r.ip === app.gateway ? ' class="hl"' : ""}><td class="mono">${esc(r.ip)}${r.ip === app.gateway ? ' <span class="tag gw">gateway</span>' : ""}</td><td class="mono">${esc(r.mac)}</td>
        <td>${esc(r.vendor) || '<span class="sub">—</span>'}</td><td>${esc(r.type)}${r.kind !== "unicast" ? ` <span class="sub">${r.kind}</span>` : ""}</td><td>${esc(r.interface)}</td></tr>`).join("") +
      `</tbody></table></div><div class="sub" style="margin-top:6px">${list.length} entrada(s)</div>`;
  };
  const load = async () => { rows = await getJSON("api/tools/arp"); render(); };
  $("a-filter").oninput = render; $("a-all").onchange = render; $("a-go").onclick = load;
  load();
}

// ---------- Tabela de rotas ----------
async function toolRoutes(el) {
  el.innerHTML = `<h2>Tabela de rotas</h2>
    <p class="about">Mostra para onde o Windows envia o tráfego de cada rede. A rota <span class="mono">0.0.0.0/0</span> é a rota padrão: tudo que não é da rede local sai pelo gateway dela. Mais de uma rota padrão pode indicar VPN ou duas placas conectadas.</p>
    <div class="form"><label class="chk"><input type="checkbox" id="r-all"> Incluir loopback e multicast</label><button id="r-go" class="ghost">Atualizar</button></div>
    <div class="cmd">Equivalente no CMD: <code>route print -4</code></div>
    <div id="r-out"></div>`;
  let rows = [];
  const noise = (r) => r.destination.startsWith("127.") || r.destination.startsWith("224.") || r.destination === "255.255.255.255" || r.prefixLen === 32 && r.destination.endsWith(".255");
  const render = () => {
    const list = rows.filter(r => $("r-all").checked || !noise(r)).sort((a, b) => a.prefixLen - b.prefixLen || a.metric - b.metric);
    const defaults = list.filter(r => r.prefixLen === 0).length;
    $("r-out").innerHTML = (defaults > 1 ? `<div class="finding aviso" style="margin-bottom:10px"><b>${defaults} rotas padrão</b>Há mais de uma saída padrão (VPN ou duas placas conectadas). O Windows usa a de menor métrica.</div>` : "") +
      `<div class="tablewrap"><table><thead><tr><th>Destino</th><th>Máscara</th><th>Gateway</th><th>Interface</th><th>Métrica</th><th>Origem</th></tr></thead><tbody>` +
      list.map(r => `<tr${r.prefixLen === 0 ? ' class="hl"' : ""}><td class="mono">${esc(r.destination)}/${r.prefixLen}${r.prefixLen === 0 ? ' <span class="tag gw">rota padrão</span>' : ""}</td>
        <td class="mono">${esc(r.mask)}</td><td class="mono">${r.nextHop === "0.0.0.0" ? '<span class="sub">na rede (direto)</span>' : esc(r.nextHop)}</td>
        <td>${esc(r.interface)}</td><td class="num">${r.metric}</td><td>${esc(r.protocol)}</td></tr>`).join("") + `</tbody></table></div>`;
  };
  const load = async () => { rows = await getJSON("api/tools/routes"); render(); };
  $("r-all").onchange = render; $("r-go").onclick = load;
  load();
}

// ---------- Teste de MTU ----------
function toolMTU(el) {
  el.innerHTML = `<h2>Teste de MTU</h2>
    <p class="about">Descobre o maior pacote que passa sem ser fragmentado até o destino. MTU errado (comum em PPPoE e túneis) faz alguns sites, aplicativos ou VPNs não carregarem, mesmo com a internet “funcionando”.</p>
    <div class="form">
      <label class="f">Destino<input type="text" id="u-host" class="mono" value="8.8.8.8" style="width:220px"></label>
      <button id="u-go">Testar</button>
      ${hostChips()}
    </div>
    <div class="cmd">Equivalente no CMD (testando tamanhos à mão): <code id="u-cmd">ping -f -l 1472 8.8.8.8</code></div>
    <div id="u-out" class="result"></div>`;
  bindChips(el, "u-host", () => $("u-cmd").textContent = `ping -f -l 1472 ${$("u-host").value}`);
  $("u-go").onclick = async () => {
    $("u-go").disabled = true;
    $("u-out").innerHTML = '<p class="sub">Testando tamanhos de pacote…</p>';
    try {
      const r = await getJSON(`api/tools/mtu?host=${encodeURIComponent($("u-host").value.trim())}`);
      if (r.error) throw new Error(r.error);
      $("u-cmd").textContent = `ping -f -l ${r.maxPayload} ${r.target}`;
      $("u-out").innerHTML = `<div class="metrics"><div class="metric"><div class="label">MTU do caminho</div><div class="value">${r.pathMtu} <small>bytes</small></div></div>
        <div class="metric"><div class="label">Maior ping sem fragmentar</div><div class="value">${r.maxPayload} <small>bytes</small></div></div>
        <div class="metric"><div class="label">MTU da placa local</div><div class="value">${r.localMtu || "—"} <small>bytes</small></div></div>
        <div class="metric"><div class="label">Pacotes de teste</div><div class="value">${r.probes}</div></div></div>
        <div class="finding ${r.level}" style="margin-top:10px"><b>Resultado</b>${esc(r.verdict)}</div>
        <div class="sub" style="margin-top:6px">Referência: 1500 = Ethernet padrão · 1492 = PPPoE · abaixo disso, túnel ou configuração manual.</div>`;
    } catch (e) { $("u-out").innerHTML = `<div class="finding critico"><b>Erro</b>${esc(e.message)}</div>`; }
    $("u-go").disabled = false;
  };
}

// ---------- Testar porta ----------
const PORT_CHIPS = [[80, "HTTP"], [443, "HTTPS"], [22, "SSH"], [23, "Telnet"], [3389, "RDP"], [8291, "Winbox"], [7547, "TR-069"], [554, "RTSP"], [37777, "DVR"], [9100, "Impressora"]];
function toolPort(el) {
  el.innerHTML = `<h2>Testar porta</h2>
    <p class="about">Verifica se uma porta TCP está aberta em um equipamento: acesso ao roteador (HTTP/Winbox), câmeras/DVR, área de trabalho remota, impressoras ou servidores.</p>
    <div class="form">
      <label class="f">Destino (IP ou nome)<input type="text" id="o-host" class="mono" value="${esc(app.gateway)}" style="width:220px"></label>
      <label class="f">Porta<input type="number" id="o-port" class="mono" value="80" min="1" max="65535" style="width:100px"></label>
      ${protoSelect("o-ip")}
      <button id="o-go">Testar</button>
      ${hostChips()}
      <div class="chips"><span class="sub">Portas:</span>${PORT_CHIPS.map(([p, n]) => `<button class="chip" data-p="${p}">${p} ${n}</button>`).join("")}</div>
    </div>
    ${cmdLine("o-cmd")}
    <div id="o-out" class="result"></div>`;
  const upd = () => $("o-cmd").textContent = `Test-NetConnection ${$("o-host").value.trim()} -Port ${$("o-port").value}   (PowerShell)`;
  ["o-host", "o-port"].forEach(id => $(id).oninput = upd);
  bindChips(el, "o-host", upd);
  el.querySelectorAll(".chip[data-p]").forEach(c => c.onclick = () => { $("o-port").value = c.dataset.p; upd(); });
  upd();
  $("o-go").onclick = async () => {
    $("o-go").disabled = true;
    try {
      const r = await getJSON(`api/tools/port?host=${encodeURIComponent($("o-host").value.trim())}&port=${$("o-port").value}&ip=${$("o-ip").value}`);
      const cls = { aberta: "ok", fechada: "aviso", filtrada: "critico", erro: "critico" }[r.state];
      $("o-out").insertAdjacentHTML("afterbegin", `<div class="finding ${cls}" style="margin-bottom:8px"><b>${esc(r.host)}${r.ip && r.ip !== r.host ? " (" + esc(r.ip) + ")" : ""} porta ${r.port}: ${esc(r.state.toUpperCase())}</b>${esc(r.detail)}${r.timeMs ? ` <span class="sub">(${fmtMs(r.timeMs)})</span>` : ""}</div>`);
    } catch (e) { $("o-out").insertAdjacentHTML("afterbegin", `<div class="finding critico"><b>Erro</b>${esc(e.message)}</div>`); }
    $("o-go").disabled = false;
  };
}

const TOOLS = [
  { id: "ping", name: "Ping", cmd: "ping", fn: toolPing },
  { id: "tracert", name: "Traceroute", cmd: "tracert", fn: toolTrace },
  { id: "dns", name: "Consulta DNS", cmd: "nslookup", fn: toolDNS },
  { id: "ipconfig", name: "Configuração IP", cmd: "ipconfig /all", fn: toolIPConfig },
  { id: "flush", name: "Cache DNS e renovar IP", cmd: "ipconfig /flushdns /renew", fn: toolFlush },
  { id: "arp", name: "Tabela ARP", cmd: "arp -a", fn: toolARP },
  { id: "rotas", name: "Tabela de rotas", cmd: "route print", fn: toolRoutes },
  { id: "porta", name: "Testar porta", cmd: "Test-NetConnection", fn: toolPort },
  { id: "mtu", name: "Teste de MTU", cmd: "ping -f -l", fn: toolMTU },
];

function openTool(id) {
  stopStream();
  const t = TOOLS.find(x => x.id === id) || TOOLS[0];
  document.querySelectorAll("#toolmenu button").forEach(b => b.classList.toggle("active", b.dataset.tool === t.id));
  Promise.resolve(t.fn($("toolpanel"))).catch(e => showError(e.message));
}

$("toolmenu").innerHTML = TOOLS.map(t => `<button data-tool="${t.id}">${esc(t.name)}<small>${esc(t.cmd)}</small></button>`).join("");
$("toolmenu").querySelectorAll("button").forEach(b => b.onclick = () => openTool(b.dataset.tool));
app.ready.then(() => openTool("ping"));
