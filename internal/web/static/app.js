// Base comum: utilitários, abas, escalas de classificação e encerramento.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtDate = (s) => s ? new Date(s).toLocaleString("pt-BR") : "";
const fmtMs = (v) => v < 0 || v == null ? "—" : (v < 1 ? "&lt;1" : (v < 10 ? v.toFixed(1) : v.toFixed(0))) + " ms";

const app = { scales: {}, interfaces: [], primary: null, gateway: "", info: {}, atend: {} };

function kv(rows) {
  return '<dl class="kv">' + rows.filter(r => r[1] !== undefined && r[1] !== "" && r[1] !== null)
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("") + "</dl>";
}

const LEVEL_NAMES = { excelente: "Excelente", razoavel: "Razoável", ruim: "Ruim", pessimo: "Péssimo" };
const lvl = (level, text) => level ? `<span class="lvl ${level}">${esc(text ?? LEVEL_NAMES[level])}</span>` : "";

function rate(scaleId, v) {
  const s = app.scales[scaleId];
  if (!s || v == null || (!s.higher && v < 0)) return "";
  if (s.higher) return v >= s.excelente ? "excelente" : v >= s.razoavel ? "razoavel" : v >= s.ruim ? "ruim" : "pessimo";
  return v <= s.excelente ? "excelente" : v <= s.razoavel ? "razoavel" : v <= s.ruim ? "ruim" : "pessimo";
}

// legend monta a régua de classificação, ex.: "Latência: ≤15 ms Excelente · ≤25 ms Razoável …"
function legend(...ids) {
  return '<div class="legend">' + ids.map(id => app.scales[id]).filter(Boolean).map(s => s.higher
    ? `<span class="scale" title="${esc(s.hint)}"><b>${esc(s.name)}:</b>
      ${lvl("excelente", `Excelente: ${s.excelente} ${s.unit} ou mais`)}${lvl("razoavel", `Razoável: ${s.razoavel} ${s.unit} ou mais`)}${lvl("ruim", `Ruim: ${s.ruim} ${s.unit} ou mais`)}${lvl("pessimo", `Péssimo: abaixo de ${s.ruim} ${s.unit}`)}</span>`
    : `<span class="scale" title="${esc(s.hint)}"><b>${esc(s.name)}:</b>
      ${lvl("excelente", `Excelente: ${s.excelente === 0 ? "" : "até "}${s.excelente} ${s.unit}`)}${lvl("razoavel", `Razoável: até ${s.razoavel} ${s.unit}`)}${lvl("ruim", `Ruim: até ${s.ruim} ${s.unit}`)}${lvl("pessimo", `Péssimo: acima de ${s.ruim} ${s.unit}`)}</span>`
  ).join("") + "</div>";
}

// rttChart desenha barras dos tempos de ping (perdidos em vermelho) com as linhas da escala.
function rttChart(rtts, scaleId) {
  const s = app.scales[scaleId];
  const W = 600, H = 120, n = Math.max(rtts.length, 10);
  const vals = rtts.filter(v => v >= 0);
  const top = Math.max(...vals, s ? s.ruim * 1.15 : 10, 5);
  const y = (v) => H - 4 - (v / top) * (H - 10);
  const bw = W / n;
  let bars = rtts.map((v, i) => v < 0
    ? `<rect x="${i * bw + 1}" y="2" width="${Math.max(bw - 2, 1)}" height="${H - 6}" fill="var(--l4)" opacity=".25"><title>perdido</title></rect>`
    : `<rect x="${i * bw + 1}" y="${y(v)}" width="${Math.max(bw - 2, 1)}" height="${H - 4 - y(v)}" fill="var(--l${["excelente","razoavel","ruim","pessimo"].indexOf(rate(scaleId, v)) + 1})"><title>${v} ms</title></rect>`).join("");
  let lines = "";
  if (s) for (const [k, c] of [["excelente", "--l1"], ["razoavel", "--l2"], ["ruim", "--l3"]]) {
    if (s[k] <= top) lines += `<line x1="0" x2="${W}" y1="${y(s[k])}" y2="${y(s[k])}" stroke="var(${c})" stroke-dasharray="4 4" opacity=".7"/>
      <text x="${W - 4}" y="${y(s[k]) - 3}" text-anchor="end" font-size="10" fill="var(${c})">${s[k]} ms</text>`;
  }
  return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${lines}${bars}</svg></div>`;
}

function showError(msg) {
  if (!msg) { $("error").style.display = "none"; return; }
  $("error").innerHTML = "<b>Erro</b>" + esc(msg);
  $("error").style.display = "block";
}

async function getJSON(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.json();
}

// infoize troca descrições longas por um ícone "i" com a explicação no balão:
// o título das barras de ação fica visível e o texto vai para o ícone.
function infoIcon(text) {
  return `<span class="info" tabindex="0" role="button" aria-label="Mais informações">i<span class="tip">${text}</span></span>`;
}
function infoize(root = document) {
  root.querySelectorAll(".panelbar .desc:not([data-info])").forEach(d => {
    d.dataset.info = "1";
    const title = d.querySelector("b");
    if (title) title.remove();
    const text = d.innerHTML.trim();
    if (!text) { if (title) d.append(title); return; }
    d.innerHTML = (title ? title.outerHTML : "") + infoIcon(text);
  });
  // Alertas com explicação longa: fica o título, a explicação vai para o ícone.
  root.querySelectorAll(".finding:not([data-info])").forEach(f => {
    f.dataset.info = "1";
    const b = f.querySelector(":scope > b");
    if (!b || f.id === "error") return;
    const rest = f.innerHTML.slice(f.innerHTML.indexOf("</b>") + 4).trim();
    if (rest.replace(/<[^>]+>/g, "").length <= 90) return;
    b.insertAdjacentHTML("beforeend", infoIcon(rest));
    f.innerHTML = b.outerHTML;
  });
  root.querySelectorAll(".tool p.about:not([data-info])").forEach(p => {
    p.dataset.info = "1";
    const h = p.parentElement.querySelector("h2");
    if (h) { h.insertAdjacentHTML("beforeend", infoIcon(p.innerHTML)); p.remove(); }
  });
}
// O balão é "fixed" e se posiciona perto do ícone, sem sair da tela.
function placeTip(e) {
  const icon = e.target.closest?.(".info");
  if (!icon) return;
  const tip = icon.querySelector(".tip"), r = icon.getBoundingClientRect();
  tip.style.display = "block";
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = Math.max(8, Math.min(r.left - 10, innerWidth - w - 8)) + "px";
  tip.style.top = (r.bottom + 8 + h > innerHeight ? Math.max(8, r.top - h - 8) : r.bottom + 8) + "px";
  tip.style.display = "";
}
document.addEventListener("mouseover", placeTip);
document.addEventListener("focusin", placeTip);

// As abas desenham conteúdo dinamicamente; converte o que for aparecendo.
infoize();
new MutationObserver(() => infoize()).observe(document.querySelector("main"), { childList: true, subtree: true });

// Abas
document.querySelectorAll("nav.tabs button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav.tabs button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll("section.tab").forEach(s => s.classList.toggle("active", s.id === "tab-" + b.dataset.tab));
  showError("");
  try { localStorage.setItem("aba", b.dataset.tab); } catch {}
});
try {
  const saved = localStorage.getItem("aba");
  if (saved) document.querySelector(`nav.tabs button[data-tab="${saved}"]`)?.click();
} catch {}

$("quit").onclick = async () => {
  if (!confirm("Encerrar o Quasar Scan?")) return;
  await fetch("api/shutdown", { method: "POST" }).catch(() => {});
  document.body.innerHTML = '<div class="empty" style="padding-top:120px"><b>Quasar Scan encerrado</b>Pode fechar esta aba. Para abrir de novo, use o atalho na Área de Trabalho.</div>';
};

// findingsHTML monta a lista de achados (crítico, aviso, informação).
const findingsHTML = (list) => '<div class="findings">' +
  list.map(f => `<div class="finding ${f.level}"><b>${esc(f.title)}</b>${esc(f.detail)}</div>`).join("") + "</div>";

// Atendimento: dados do cliente, compartilhados por todas as abas.
function renderAtendChip() {
  const a = app.atend, chip = $("atendchip");
  chip.textContent = a.cliente ? `Atendimento: ${a.cliente}${a.codigo ? " (" + a.codigo + ")" : ""}` : "Sem atendimento";
  chip.classList.toggle("on", !!a.cliente);
  document.querySelectorAll("input.plano").forEach(i => { if (document.activeElement !== i) i.value = a.planoMbps || ""; });
}
async function loadAtend() {
  const d = await getJSON("api/atendimento");
  app.atend = d.atendimento; app.atendInfo = d;
  renderAtendChip();
  return d;
}
async function saveAtend(changes, novo = false) {
  const d = await getJSON("api/atendimento" + (novo ? "?novo=1" : ""), { method: "POST",
    body: JSON.stringify({ ...(novo ? {} : app.atend), ...changes }) });
  app.atend = d.atendimento; app.atendInfo = d;
  renderAtendChip();
  return d;
}
// Qualquer campo "Plano (Mega)" atualiza o atendimento.
document.addEventListener("change", (e) => {
  if (e.target.matches("input.plano")) saveAtend({ planoMbps: Math.max(0, +e.target.value || 0) }).catch(err => showError(err.message));
});
$("atendchip").onclick = () => document.querySelector('nav.tabs button[data-tab="relatorio"]').click();

app.ready = (async () => {
  const [scales, ifaces, info] = await Promise.all([getJSON("api/scales"), getJSON("api/interfaces"), getJSON("api/info")]);
  scales.forEach(s => app.scales[s.id] = s);
  app.interfaces = ifaces;
  app.info = info;
  app.primary = ifaces.find(i => i.isPrimary) || null;
  app.gateway = app.primary?.gateways.find(g => g.includes(".")) || "";
  const chip = $("adminchip");
  chip.style.display = "";
  chip.textContent = info.admin ? "Administrador" : "Sem administrador";
  chip.className = "tag " + (info.admin ? "self" : "risk");
  chip.title = info.admin ? "Rodando como administrador: todos os recursos disponíveis." : "Abra pelo atalho e aceite o pedido de administrador para renovar IP.";
  await loadAtend();
})().catch(e => showError("Falha ao carregar: " + e.message));
