// Teste de velocidade (na aba "Saúde da conexão"), com latência sob carga (bufferbloat).
let speedStream = null;
const PHASE_NAMES = { latencia: "Medindo latência", download: "Download", upload: "Upload" };

try { $("sp-url").value = localStorage.getItem("speedUrl") || ""; } catch {}
$("sp-server").onchange = () => { $("sp-url").style.display = $("sp-server").value === "librespeed" ? "" : "none"; };

function stopSpeed() {
  if (speedStream) { speedStream.close(); speedStream = null; }
  $("sp-go").textContent = "Iniciar teste de velocidade"; $("sp-go").className = "";
}

$("sp-go").onclick = () => {
  if (speedStream) { stopSpeed(); $("sp-out").innerHTML = '<p class="sub">Teste cancelado.</p>'; return; }
  showError("");
  let server = "";
  if ($("sp-server").value === "librespeed") {
    server = $("sp-url").value.trim();
    if (!server) { showError("Informe a URL do servidor LibreSpeed do provedor."); return; }
    try { localStorage.setItem("speedUrl", server); } catch {}
  }
  $("sp-out").innerHTML = `<div class="card gauge" style="margin-top:12px"><div class="ph" id="sp-ph">Conectando…</div>
    <div class="big" id="sp-mbps">—</div><div class="sub" id="sp-ping"></div></div>`;
  $("sp-go").textContent = "Cancelar"; $("sp-go").className = "stop";
  const down = [], up = [];
  speedStream = new EventSource(`api/speed?server=${encodeURIComponent(server)}&segundos=${$("sp-dur").value}`);
  speedStream.addEventListener("progresso", (e) => {
    const p = JSON.parse(e.data);
    $("sp-ph").textContent = PHASE_NAMES[p.phase] || p.phase;
    $("sp-mbps").innerHTML = p.phase === "latencia" ? `${p.pingMs.toFixed(0)} <small>ms</small>` : `${p.mbps.toFixed(0)} <small>Mbps</small>`;
    $("sp-ping").textContent = p.phase !== "latencia" && p.pingMs ? `Latência durante o ${PHASE_NAMES[p.phase].toLowerCase()}: ${p.pingMs.toFixed(0)} ms` : "";
    if (p.phase === "download") down.push(p.mbps);
    if (p.phase === "upload") up.push(p.mbps);
  });
  speedStream.addEventListener("fim", (e) => { stopSpeed(); renderSpeed(JSON.parse(e.data)); });
  speedStream.onerror = () => { stopSpeed(); showError("O teste de velocidade foi interrompido."); };
};

function renderSpeed(r) { $("sp-out").innerHTML = speedHTML(r, true); }

// speedHTML monta as métricas do teste de velocidade (withFindings: inclui os alertas).
function speedHTML(r, withFindings) {
  if (r.error) return `<div class="finding critico" style="margin-top:12px"><b>Não foi possível testar a velocidade</b>${esc(r.error)}</div>`;
  const pct = (v) => r.planMbps ? `<div class="sub">${(v / r.planMbps * 100).toFixed(0)}% do plano de ${r.planMbps} Mega</div>` : "";
  let html = `<div class="metrics" style="margin-top:12px">
    <div class="metric"><div class="label">Download</div><div class="value">${r.downloadMbps.toFixed(0)} <small>Mbps</small></div>${r.downLevel ? lvl(r.downLevel) : ""}${pct(r.downloadMbps)}</div>
    <div class="metric"><div class="label">Upload</div><div class="value">${r.uploadMbps.toFixed(0)} <small>Mbps</small></div>${pct(r.uploadMbps)}</div>
    <div class="metric"><div class="label">Latência ociosa</div><div class="value">${r.idleMs.toFixed(0)} <small>ms</small></div>${lvl(rate("latencia", r.idleMs))}</div>
    <div class="metric"><div class="label">Latência no download</div><div class="value">${r.downLoadedMs.toFixed(0)} <small>ms</small></div><div class="sub">+${r.bloatDownMs.toFixed(0)} ms</div></div>
    <div class="metric"><div class="label">Latência no upload</div><div class="value">${r.upLoadedMs.toFixed(0)} <small>ms</small></div><div class="sub">+${r.bloatUpMs.toFixed(0)} ms</div></div>
    <div class="metric"><div class="label">Bufferbloat</div><div class="value">${lvl(r.bloatLevel)}</div><div class="sub">quanto a latência sobe em uso</div></div>
  </div>
  <div class="sub" style="margin-top:6px">Servidor: ${esc(r.server)} · ${r.dataMB.toFixed(0)} MB transferidos${r.linkMbps ? ` · placa de rede a ${r.linkMbps} Mbps` : ""}</div>`;
  if (withFindings && r.findings.length) html += `<div style="margin-top:10px">${findingsHTML(r.findings)}</div>`;
  html += legend("plano", "bufferbloat");
  return html;
}
