// Aba "Análise geral": varredura da rede local (Fases 1 e 2).
const RISKY = new Set([21, 23, 445, 3389]);
let result = null, sortKey = "ip", sortAsc = true, filter = "";

async function loadInterfaces() {
  await app.ready;
  const sel = $("iface");
  sel.innerHTML = "";
  app.interfaces.filter(i => i.status === "up" && i.ipv4.length)
    .sort((a, b) => (b.isPrimary - a.isPrimary) || (a.virtual - b.virtual))
    .forEach(i => {
      const o = document.createElement("option");
      o.value = i.index;
      o.textContent = `${i.name} — ${i.ipv4[0].address}/${i.ipv4[0].prefixLen}${i.isPrimary ? " (principal)" : ""}${i.virtual ? " [virtual]" : ""}`;
      sel.appendChild(o);
    });
  if (!sel.options.length) sel.innerHTML = "<option value=0>Nenhuma interface ativa</option>";
}

async function startScan() {
  showError("");
  const r = await fetch("api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interfaceIndex: +$("iface").value, cidr: $("cidr").value.trim(),
                           scanPorts: $("ports").checked, checkInternet: $("inet").checked }) });
  if (!r.ok) { showError(await r.text()); return; }
  $("go").disabled = true;
  $("progress").style.display = "block";
  pollScan();
}

async function pollScan() {
  const st = await (await fetch("api/status")).json();
  $("phase").textContent = st.phase;
  $("counts").textContent = st.total ? `${st.done}/${st.total} · ${st.found} dispositivo(s) encontrado(s)` : "";
  $("barfill").style.width = st.total ? (100 * st.done / st.total) + "%" : "5%";
  if (st.running) { setTimeout(pollScan, 400); return; }
  $("go").disabled = false;
  $("progress").style.display = "none";
  if (st.error) showError(st.error);
  if (st.result) { result = st.result; result.savedTo = st.savedTo; renderScan(); }
}

function renderScan() {
  const r = result, it = r.interface;
  const v4 = it.ipv4.map(a => `${esc(a.address)}/${a.prefixLen}`).join("<br>");
  const masks = it.ipv4.map(a => esc(a.mask)).join("<br>");
  const v6 = it.ipv6.map(a => `${esc(a.address)}/${a.prefixLen} <span class="sub">${esc(a.scope)}${a.origin ? ", " + esc(a.origin) : ""}</span>`).join("<br>");
  const inet = r.internet;
  const yes = (b) => b ? '<span class="ok">sim</span>' : '<span class="bad">não</span>';

  let html = `<h2>Configuração da rede</h2><div class="cards">
    <div class="card"><h3>Interface</h3>${kv([["Nome", esc(it.name)], ["Tipo", esc(it.type)], ["Adaptador", esc(it.description)],
      ["MAC", esc(it.mac)], ["Velocidade", it.speedMbps ? it.speedMbps + " Mbps" : ""], ["MTU", it.mtu], ["Computador", esc(r.computer)]])}</div>
    <div class="card"><h3>IPv4</h3>${kv([["IP", v4], ["Máscara", masks], ["Rede", esc(it.ipv4.map(a => a.network).join(", "))],
      ["Gateway", it.gateways.map(esc).join("<br>") || '<span class="bad">nenhum</span>'], ["Varrido", esc(r.target)]])}</div>
    <div class="card"><h3>DNS e DHCP</h3>${kv([["DNS", it.dnsServers.map(esc).join("<br>") || '<span class="bad">nenhum</span>'],
      ["Sufixo", esc(it.dnsSuffix)], ["DHCP", it.dhcp.enabled ? '<span class="ok">ativado</span>' : "desativado (IP fixo)"],
      ["Servidor", esc(it.dhcp.server)], ["Servidor v6", esc(it.dhcp.serverV6)],
      ["Concessão", fmtDate(it.dhcp.leaseObtained)], ["Expira", fmtDate(it.dhcp.leaseExpires)]])}</div>
    <div class="card"><h3>IPv6</h3>${v6 ? kv([["Endereços", v6]]) : '<span class="sub">Sem IPv6 nesta interface</span>'}</div>
    <div class="card"><h3>Internet</h3>${inet ? kv([["Status", inet.online ? '<span class="ok">online</span>' : '<span class="bad">offline</span>'],
      ["IPv4", yes(inet.ipv4)], ["IPv6", yes(inet.ipv6)], ["DNS resolve", yes(inet.dnsWorks)],
      ["IP público", esc(inet.publicIPv4)], ["IP público v6", esc(inet.publicIPv6)]]) : '<span class="sub">Testes de internet desativados</span>'}</div>
    <div class="card"><h3>Servidores DHCP na rede</h3>${r.dhcpError ? `<span class="sub">${esc(r.dhcpError)}</span>`
      : r.dhcpServers.length ? r.dhcpServers.map(o => kv([["Servidor", esc(o.server) + (r.dhcpServers.length > 1 ? ' <span class="tag risk">duplicado</span>' : "")],
          ["Oferece IP", esc(o.offeredIp) + (o.mask ? " / " + esc(o.mask) : "")], ["Gateway", esc(o.router)], ["DNS", (o.dns || []).map(esc).join(", ")],
          ["Concessão", o.leaseSecs ? (o.leaseSecs >= 3600 ? (o.leaseSecs / 3600).toFixed(1).replace(".0", "") + " h" : Math.round(o.leaseSecs / 60) + " min") : ""]])).join("<hr style='border:0;border-top:1px solid var(--border)'>")
      : '<span class="sub">Nenhum servidor respondeu ao teste.</span>'}</div>
  </div>`;

  if (r.findings.length) {
    const order = { critico: 0, aviso: 1, info: 2 };
    html += `<h2>Análise</h2><div class="findings">` + [...r.findings].sort((a, b) => order[a.level] - order[b.level])
      .map(f => `<div class="finding ${f.level}"><b>${esc(f.title)}</b>${esc(f.detail)}</div>`).join("") + `</div>`;
  }

  html += `<div class="toolbar"><h2>Dispositivos (${r.hosts.length})</h2>
    <input type="text" id="filter" placeholder="filtrar…" value="${esc(filter)}" style="width:200px">
    <a href="api/export.csv"><button class="ghost">Exportar CSV</button></a>
    <a href="api/export.json"><button class="ghost">Exportar JSON</button></a></div>
    <div class="tablewrap"><table><thead><tr>
      ${[["ip","IP"],["name","Nome"],["vendor","Fabricante / MAC"],["deviceType","Tipo"],["rttMs","Ping"],["ports","Portas e serviços"]]
        .map(([k, l]) => `<th data-k="${k}" class="${sortKey === k ? "sorted" + (sortAsc ? " asc" : "") : ""}">${l}</th>`).join("")}
    </tr></thead><tbody id="rows"></tbody></table></div>`;

  html += `<details><summary>Todas as interfaces desta máquina (${r.interfaces.length})</summary><div class="cards" style="margin-top:10px">` +
    r.interfaces.map(i => `<div class="card"><h3>${esc(i.name)}${i.virtual ? " · virtual" : ""}</h3>${kv([["Status", esc(i.status)], ["Tipo", esc(i.type)],
      ["MAC", esc(i.mac)], ["IPv4", i.ipv4.map(a => esc(a.address + "/" + a.prefixLen)).join("<br>")],
      ["IPv6", i.ipv6.map(a => esc(a.address)).join("<br>")], ["Gateway", i.gateways.map(esc).join("<br>")]])}</div>`).join("") + `</div></details>`;

  html += `<div class="footer">Varredura de ${fmtDate(r.startedAt)} · ${r.durationS.toFixed(1)} s${r.savedTo ? " · salvo em " + esc(r.savedTo) : ""}</div>`;
  $("content").innerHTML = html;

  document.querySelectorAll("#content th[data-k]").forEach(th => th.onclick = () => {
    sortAsc = sortKey === th.dataset.k ? !sortAsc : true; sortKey = th.dataset.k; renderScan();
  });
  $("filter").oninput = (e) => { filter = e.target.value; renderRows(); };
  renderRows();
}

const ipNum = (ip) => ip.split(".").reduce((n, o) => n * 256 + +o, 0);
const nameOf = (h) => h.friendlyName || h.hostname || h.netbios || h.mdnsName || "";

function renderRows() {
  const q = filter.toLowerCase();
  const val = (h) => ({ ip: ipNum(h.ip), name: nameOf(h).toLowerCase(), vendor: (h.vendor || "").toLowerCase(),
    deviceType: h.deviceType, rttMs: h.rttMs < 0 ? 1e9 : h.rttMs, ports: h.openPorts.length })[sortKey];
  const hosts = result.hosts
    .filter(h => !q || JSON.stringify(h).toLowerCase().includes(q))
    .sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (sortAsc ? 1 : -1); });

  $("rows").innerHTML = hosts.map(h => {
    const tags = (h.isGateway ? '<span class="tag gw">gateway</span>' : "") + (h.isSelf ? '<span class="tag self">esta máquina</span>' : "");
    const main = nameOf(h);
    const names = [main,
      h.hostname && h.hostname !== main ? h.hostname : "",
      h.mdnsName && h.mdnsName !== main && h.mdnsName !== h.hostname ? h.mdnsName + ".local" : "",
      h.netbios && h.netbios !== main && h.netbios !== h.hostname ? "NetBIOS: " + h.netbios : "",
      h.workgroup ? "Grupo: " + h.workgroup : "",
      h.model && h.model !== main ? "Modelo: " + h.model : ""].filter(Boolean);
    const vendor = h.vendor ? esc(h.vendor) : (h.randomMac ? '<span class="sub">MAC aleatório (privacidade)</span>' : (h.mac ? '<span class="sub">desconhecido</span>' : ""));
    const ping = h.rttMs < 0 ? '<span class="sub">bloqueia ping</span>' : (h.rttMs < 1 ? "&lt;1 ms" : h.rttMs.toFixed(0) + " ms");
    const ports = h.openPorts.map(p => `<span class="tag ${RISKY.has(p.port) ? "risk" : ""}" title="${esc(p.service)}">${p.port} ${esc(p.service.split(" ")[0])}</span>`).join("");
    return `<tr>
      <td class="mono">${esc(h.ip)}<br>${tags}</td>
      <td>${names.length ? esc(names[0]) + names.slice(1).map(n => `<div class="sub">${esc(n)}</div>`).join("") : '<span class="sub">—</span>'}</td>
      <td>${vendor}<div class="sub mono">${esc(h.mac)}</div></td>
      <td>${esc(h.deviceType)}${h.osGuess ? `<div class="sub">${esc(h.osGuess)}</div>` : ""}</td>
      <td class="mono">${ping}${h.ttl ? `<div class="sub">TTL ${h.ttl}</div>` : ""}</td>
      <td>${ports || '<span class="sub">—</span>'}${(h.services || []).length ? `<div style="margin-top:3px">${h.services.map(x => `<span class="tag gw">${esc(x)}</span>`).join("")}</div>` : ""}${h.upnp?.igd ? '<span class="tag risk" title="Abre portas automaticamente">UPnP ativo</span>' : ""}</td></tr>`;
  }).join("") || `<tr><td colspan="6" class="sub" style="text-align:center;padding:20px">Nenhum dispositivo corresponde ao filtro</td></tr>`;
}

$("go").onclick = startScan;
loadInterfaces();
// Se a página for recarregada no meio de uma varredura, retoma o acompanhamento.
fetch("api/status").then(r => r.json()).then(st => {
  if (st.running) { $("go").disabled = true; $("progress").style.display = "block"; pollScan(); }
  else if (st.result) { result = st.result; result.savedTo = st.savedTo; renderScan(); }
});
