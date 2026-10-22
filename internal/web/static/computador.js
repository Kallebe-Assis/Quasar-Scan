// Aba "Computador": inspeção do próprio PC e ferramentas oficiais do Windows.
const PC_STEPS = { sistema: "Sistema", protecao: "Proteção e Defender", inicializacao: "Inicialização automática",
  processos: "Processos e conexões", servicos: "Serviços", assinaturas: "Assinaturas digitais", analise: "Análise" };
const CHECK_LABEL = { ok: "OK", aviso: "Atenção", critico: "Problema", info: "Info" };
let pcReport = null, pcJobTimer = null;

function runPC() {
  showError("");
  $("pcgo").disabled = true;
  $("pcprogress").style.display = "block";
  $("pccount").textContent = "";
  const es = new EventSource("api/pc/inspecao");
  es.addEventListener("inicio", (e) => {
    $("pcsteps").innerHTML = JSON.parse(e.data).steps.map(s => `<span id="pcstep-${s}">${esc(PC_STEPS[s] || s)}</span>`).join("");
  });
  es.addEventListener("etapa", (e) => $("pcstep-" + JSON.parse(e.data))?.classList.add("done"));
  es.addEventListener("progresso", (e) => {
    const p = JSON.parse(e.data);
    $("pccount").textContent = `· conferindo assinaturas ${p.done}/${p.total}`;
  });
  es.addEventListener("fim", (e) => {
    es.close();
    $("pcgo").disabled = false;
    $("pcprogress").style.display = "none";
    pcReport = JSON.parse(e.data);
    renderPC();
  });
  es.onerror = () => { es.close(); $("pcgo").disabled = false; $("pcprogress").style.display = "none"; showError("A inspeção foi interrompida."); };
}

const sigLabel = (s) => ({
  assinado: s.publisher ? `<span class="ok">${esc(s.publisher)}</span>` : '<span class="ok">assinado</span>',
  "sem-assinatura": '<span class="warn">sem assinatura</span>',
  invalido: '<span class="bad">assinatura inválida</span>',
  inexistente: '<span class="sub">arquivo não existe</span>',
  erro: '<span class="sub">não verificado</span>',
}[s.status] || "");
const flagTags = (flags) => flags.map(f => `<span class="tag ${f.level === "critico" ? "risk" : ""}" title="${esc(f.text)}">${CHECK_LABEL[f.level] || f.level}</span>`).join("");
const revealBtn = (path) => path ? `<button class="chip mini" data-reveal="${esc(path)}" title="Abrir a pasta no Explorer">Abrir local</button>` : "";

function renderPC() {
  const r = pcReport, si = r.system, sec = r.security;
  const crit = r.findings.filter(f => f.level === "critico"), warn = r.findings.filter(f => f.level === "aviso"), info = r.findings.filter(f => f.level === "info");
  const gradeCls = { excelente: "ok", razoavel: "info", ruim: "aviso", pessimo: "critico" }[r.grade];

  let html = `<div class="finding big ${gradeCls}" style="margin-top:14px"><div class="scorebox">
      <div class="num">${r.score}<small>/100</small></div>
      <div><b>${{ excelente: "Computador saudável", razoavel: "Pontos de atenção", ruim: "Problemas encontrados", pessimo: "Computador em risco" }[r.grade]}</b>${esc(r.summary)}</div></div></div>`;

  html += `<h2>Conferência de proteção</h2><div class="checks">` + r.checklist.map(c =>
    `<div class="check ${c.status}"><b><span class="dot"></span>${esc(c.item)}${c.detail ? infoIcon(esc(c.detail)) : ""}</b><div class="v">${esc(c.value)}</div></div>`).join("") + `</div>`;

  const findingRow = (f) => `<tr><td>${lvl({ critico: "pessimo", aviso: "ruim", info: "razoavel" }[f.level], CHECK_LABEL[f.level])}</td>
    <td class="sub">${esc(f.category)}</td><td><b>${esc(f.title)}</b><div>${esc(f.detail)}</div>${f.path ? `<div class="sub mono">${esc(f.path)}</div>` : ""}</td><td>${revealBtn(f.path)}</td></tr>`;
  html += `<h2>Itens que merecem atenção (${crit.length + warn.length})</h2>`;
  html += crit.length + warn.length
    ? `<div class="tablewrap"><table><tbody>${[...crit, ...warn].map(findingRow).join("")}</tbody></table></div>`
    : `<div class="finding ok"><b>Nada suspeito encontrado</b>Nenhum programa de inicialização, processo ou serviço com sinais de malware.</div>`;
  if (info.length) html += `<details class="block"><summary>Outras observações (${info.length})</summary><div class="tablewrap"><table><tbody>${info.map(findingRow).join("")}</tbody></table></div></details>`;

  if (sec.threats.length) {
    html += `<h2>Histórico de ameaças do Defender (${sec.threats.length})</h2><div class="tablewrap"><table><thead><tr><th>Ameaça</th><th>Gravidade</th><th>Detectada</th><th>Situação</th><th>Arquivos</th></tr></thead><tbody>` +
      sec.threats.map(t => `<tr><td><b>${esc(t.name)}</b></td><td>${esc(t.severity)}</td><td class="mono">${esc(t.detected)}</td>
        <td>${t.active || !t.cleaned ? '<span class="bad">não removida</span>' : '<span class="ok">removida</span>'}</td>
        <td class="sub mono">${t.resources.map(esc).join("<br>")}</td></tr>`).join("") + `</tbody></table></div>`;
  }

  // Listas completas, recolhidas.
  html += `<h2>Detalhes</h2>`;
  html += `<details class="block"><summary>Sistema</summary><div class="cards">
    <div class="card"><h3>Windows</h3>${kv([["Sistema", esc(si.os)], ["Build", esc(si.build)], ["Instalado em", esc(si.installDate)],
      ["Computador", esc(si.computer)], ["Usuário", esc(si.user)], ["Ligado há", si.uptimeHours >= 24 ? (si.uptimeHours / 24).toFixed(1) + " dias" : si.uptimeHours + " h"]])}</div>
    <div class="card"><h3>Hardware</h3>${kv([["Memória", `${si.ramTotalGB} GB (${si.ramUsedPct}% em uso)`],
      ...si.disks.map(d => [`Disco ${d.drive}`, `${d.freeGB} GB livres de ${d.totalGB} GB (${d.freePct}%)`]),
      ["Secure Boot", si.secureBoot == null ? "não suportado" : si.secureBoot ? "ligado" : "desligado"]])}</div>
    <div class="card"><h3>Proteção</h3>${kv([["Defender", sec.defender.available ? `${sec.defender.mode || ""} · definições ${esc(sec.defender.signatureVersion)}` : esc(sec.defender.error)],
      ["Firewall", si.firewall.map(f => `${esc(f.profile)}: ${f.enabled ? "ligado" : '<span class="bad">desligado</span>'}`).join("<br>")],
      ["Última atualização", sec.lastUpdate ? `${esc(sec.lastUpdate.id)} em ${esc(sec.lastUpdate.installedOn)}` : ""],
      ["Proxy", si.proxy.enabled ? esc(si.proxy.server) : si.proxy.autoUrl ? esc(si.proxy.autoUrl) : "não"],
      ["Arquivo hosts", si.hosts.length ? si.hosts.map(esc).join("<br>") : "padrão"]])}</div></div></details>`;

  html += `<details class="block"><summary>Programas de inicialização (${r.startup.length})</summary><div class="tablewrap"><table><thead><tr><th>Nome</th><th>Onde</th><th>Executável</th><th>Assinatura</th><th></th></tr></thead><tbody>` +
    r.startup.map(it => `<tr><td><b>${esc(it.name)}</b>${it.enabled ? "" : ' <span class="tag">desativado</span>'}${it.hidden ? ' <span class="tag risk">oculta</span>' : ""} ${flagTags(it.flags)}</td>
      <td class="sub">${esc(it.location)}</td><td class="mono sub" style="white-space:normal;word-break:break-all">${esc(it.command)}</td><td>${sigLabel(it.signature)}</td><td>${revealBtn(it.signature.status !== "inexistente" ? it.path : "")}</td></tr>`).join("") + `</tbody></table></div></details>`;

  html += `<details class="block"><summary>Processos em execução (${r.processes.length})</summary>
    <div class="controls" style="margin-bottom:8px"><input type="text" id="pcpfilter" placeholder="filtrar…" style="width:200px"><label class="chk"><input type="checkbox" id="pcponly"> Só sem assinatura ou com alerta</label></div>
    <div class="tablewrap"><table><thead><tr><th>Processo</th><th>Executável</th><th>Assinatura</th><th>Rede</th><th></th></tr></thead><tbody id="pcprows"></tbody></table></div></details>`;

  html += `<details class="block"><summary>Serviços (${r.services.length})</summary>
    <div class="controls" style="margin-bottom:8px"><input type="text" id="pcsfilter" placeholder="filtrar…" style="width:200px"><label class="chk"><input type="checkbox" id="pcsms" checked> Ocultar os da Microsoft</label></div>
    <div class="tablewrap"><table><thead><tr><th>Serviço</th><th>Início</th><th>Executável</th><th>Assinatura</th><th></th></tr></thead><tbody id="pcsrows"></tbody></table></div></details>`;

  html += `<div class="footer">Inspeção de ${fmtDate(r.startedAt)} · ${r.durationS.toFixed(1)} s</div>`;
  $("pccontent").innerHTML = html;
  $("pcpfilter").oninput = $("pcponly").onchange = renderPCProcesses;
  $("pcsfilter").oninput = $("pcsms").onchange = renderPCServices;
  renderPCProcesses();
  renderPCServices();
}

function renderPCProcesses() {
  const q = $("pcpfilter").value.toLowerCase(), only = $("pcponly").checked;
  const list = pcReport.processes.filter(p => (!only || p.flags.length || (p.path && p.signature.status !== "assinado")) &&
    (!q || (p.name + p.path + (p.signature.publisher || "")).toLowerCase().includes(q)));
  $("pcprows").innerHTML = list.map(p => `<tr><td><b>${esc(p.name)}</b> <span class="sub">PID ${p.pid}</span> ${flagTags(p.flags)}</td>
    <td class="mono sub" style="white-space:normal;word-break:break-all">${esc(p.path) || '<span class="sub">protegido pelo sistema</span>'}</td>
    <td>${p.path ? sigLabel(p.signature) : ""}</td>
    <td class="sub">${p.listening.length ? "escuta: " + p.listening.slice(0, 6).join(", ") : ""}${p.remote.length ? `<div>${p.remote.length} conexão(ões) com a internet</div>` : ""}</td>
    <td>${revealBtn(p.path)}</td></tr>`).join("") || '<tr><td colspan="5" class="sub">Nenhum processo.</td></tr>';
}

function renderPCServices() {
  const q = $("pcsfilter").value.toLowerCase(), hideMS = $("pcsms").checked;
  const isMS = (s) => /microsoft/i.test(s.signature.publisher || "");
  const list = pcReport.services.filter(s => (!hideMS || !isMS(s) || s.flags.length) &&
    (!q || (s.displayName + s.name + s.path).toLowerCase().includes(q)));
  $("pcsrows").innerHTML = list.map(s => `<tr><td><b>${esc(s.displayName)}</b> <span class="sub">${esc(s.name)}</span>${s.running ? ' <span class="tag self">rodando</span>' : ""} ${flagTags(s.flags)}</td>
    <td class="sub">${esc(s.startType)}</td><td class="mono sub" style="white-space:normal;word-break:break-all">${esc(s.path)}${s.dll ? " (DLL)" : ""}</td>
    <td>${sigLabel(s.signature)}</td><td>${revealBtn(s.signature.status !== "inexistente" ? s.path : "")}</td></tr>`).join("") || '<tr><td colspan="5" class="sub">Nenhum serviço.</td></tr>';
}

// "Abrir local": mostra o arquivo selecionado no Explorer.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-reveal]");
  if (!b) return;
  try { await fetch("api/pc/abrir", { method: "POST", body: JSON.stringify({ path: b.dataset.reveal }) }).then(r => { if (!r.ok) throw new Error("Arquivo não encontrado."); }); }
  catch (err) { showError(err.message); }
});

// ---------- Ferramentas do Windows (Defender, SFC, DISM) ----------
async function loadPCTools() {
  const d = await getJSON("api/pc/acoes");
  const groups = [["Antivírus (Windows Defender)", "defender"], ["Arquivos do Windows", "sfc"], ["Imagem do Windows", "dism"]];
  $("pctools").innerHTML = `<div class="panelbar" style="margin-bottom:10px"><div class="desc"><b>Ferramentas oficiais do Windows</b>Rodam em segundo plano, uma por vez. As de reparo alteram arquivos do sistema e pedem confirmação. SFC e DISM exigem administrador.</div>
      <button class="ghost" id="pcsec">Abrir Segurança do Windows</button></div>` +
    groups.map(([title, prefix]) => `<h3 class="sub" style="margin:14px 0 8px">${title}</h3><div class="actions">` +
      d.actions.filter(a => a.id.startsWith(prefix)).map(a => `<div class="card"><h3>${esc(a.title)}</h3>
        <div class="cmd" style="margin:4px 0">CMD: <code>${esc(a.command)}</code></div>
        <div class="sub">Duração típica: ${esc(a.minutes)}${a.admin && !d.admin ? ' · <span class="warn">exige administrador</span>' : ""}</div>
        ${a.id === "defender-pasta" ? `<input type="text" id="pcfolder" class="mono" value="${esc(d.downloads)}" style="width:100%;margin-top:8px">` : ""}
        <button class="${a.changes ? "stop" : ""}" data-action="${a.id}" data-changes="${a.changes ? 1 : ""}" data-noadmin="${a.admin && !d.admin ? 1 : ""}">${a.changes ? "Reparar" : "Executar"}</button></div>`).join("") + `</div>`).join("") +
    `<div id="pcjob" style="margin-top:14px"></div>`;
  $("pcsec").onclick = () => fetch("api/pc/seguranca", { method: "POST" });
  document.querySelectorAll("#pctools [data-action]").forEach(b => {
    b.disabled = b.dataset.noadmin === "1";
    b.onclick = () => startPCAction(b.dataset.action, !!b.dataset.changes);
  });
  renderPCJob(d.job);
}

async function startPCAction(id, changes) {
  if (changes && !confirm("Esta ação repara arquivos do Windows e pode levar vários minutos. Continuar?")) return;
  showError("");
  try {
    const job = await getJSON("api/pc/acao", { method: "POST", body: JSON.stringify({ id, target: id === "defender-pasta" ? $("pcfolder").value.trim() : "" }) });
    renderPCJob(job);
  } catch (e) { showError(e.message); }
}

function renderPCJob(job) {
  clearTimeout(pcJobTimer);
  if (!job) return;
  // Uma ferramenta por vez; as que exigem administrador ficam travadas sem ele.
  document.querySelectorAll("#pctools [data-action]").forEach(b => b.disabled = job.running || b.dataset.noadmin === "1");
  const elapsed = Math.round(((job.running ? Date.now() : new Date(job.finished)) - new Date(job.started)) / 1000);
  let html = `<div class="card"><h3>${esc(job.action.title)}${job.target ? " · " + esc(job.target) : ""}</h3>`;
  if (job.running) {
    html += `<p><b>Em andamento…</b> <span class="sub">${fmtSecs(elapsed)}${job.progress ? " · " + esc(job.progress) : ""}</span> <button class="ghost mini" id="pccancel">Cancelar</button></p>`;
  } else {
    html += `<div class="finding ${job.level}" style="margin:6px 0"><b>${esc(job.result)}</b><span class="sub">Concluído em ${fmtSecs(elapsed)}</span></div>`;
  }
  html += `<div class="console" style="max-height:220px">${(job.lines || []).slice(-60).map(esc).join("\n")}</div></div>`;
  $("pcjob").innerHTML = html;
  if ($("pccancel")) $("pccancel").onclick = () => fetch("api/pc/acao/cancelar", { method: "POST" });
  if (job.running) {
    pcJobTimer = setTimeout(async () => renderPCJob(await getJSON("api/pc/acao")), 1500);
  }
}

$("pcgo").onclick = runPC;
app.ready.then(() => loadPCTools().catch(e => showError(e.message)));
