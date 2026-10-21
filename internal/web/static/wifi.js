// Aba "Wi-Fi": conexão atual, redes vizinhas e canais.
async function runWifi() {
  showError("");
  $("wgo").disabled = true;
  $("wcontent").innerHTML = '<div class="progress" style="display:block"><b>Procurando redes Wi-Fi…</b> <span class="sub">leva cerca de 5 segundos</span></div>';
  try {
    renderWifi(await getJSON("api/wifi?scan=1"));
  } catch (e) {
    $("wcontent").innerHTML = `<div class="finding aviso"><b>Wi-Fi indisponível</b>${esc(e.message)}</div>`;
  }
  $("wgo").disabled = false;
}

function channelBars(chs, band, cur, best) {
  const list = chs.filter(c => c.bandGHz === band);
  if (!list.length) return "";
  const top = Math.max(...list.map(c => c.interfere), 1);
  return `<div class="card"><h3>Canais ${band} GHz <span class="sub">(altura = interferência; tracejado = canal sugerido)</span></h3><div class="chbars">` +
    list.map(c => `<div class="ch${c.channel === cur ? " cur" : ""}${c.channel === best ? " best" : ""}" title="Canal ${c.channel}: ${c.networks} rede(s)">
      <span>${c.networks || ""}</span><div class="b" style="height:${Math.max(2, c.interfere / top * 90)}%"></div><span>${c.channel}</span></div>`).join("") +
    `</div><div class="sub">Azul: canal atual · número acima da barra: redes no canal${best ? ` · <span class="c-excelente">sugerido: ${best}</span>` : ""}</div></div>`;
}

function renderWifi(reports) {
  let html = "";
  for (const r of reports) {
    const c = r.connection;
    html += `<h2>${esc(r.interface)}</h2>`;
    if (c) {
      const secCls = { ok: "ok", fraca: "warn", aberta: "bad" }[c.securityLevel];
      html += `<div class="metrics">
        <div class="metric"><div class="label">Rede conectada</div><div class="value" style="font-size:18px">${esc(c.ssid || "(oculta)")}</div><div class="sub mono">${esc(c.bssid)}</div></div>
        <div class="metric"><div class="label">Sinal</div><div class="value">${c.rssi} <small>dBm</small></div>${lvl(r.signalLevel)} <span class="sub">${c.signalPct}%</span></div>
        <div class="metric"><div class="label">Banda / canal</div><div class="value">${c.bandGHz} <small>GHz · canal ${c.channel}</small></div></div>
        <div class="metric"><div class="label">Velocidade do link</div><div class="value">${c.rxMbps.toFixed(0)} <small>Mbps</small></div><div class="sub">envio: ${c.txMbps.toFixed(0)} Mbps</div></div>
        <div class="metric"><div class="label">Padrão</div><div class="value" style="font-size:16px">${esc(c.phy || "—")}</div></div>
        <div class="metric"><div class="label">Segurança</div><div class="value ${secCls}" style="font-size:16px">${esc(c.security || "—")}</div><div class="sub">${esc(c.cipher)}</div></div>
      </div>`;
    }
    if (r.findings.length) html += `<h2>Diagnóstico</h2>` + findingsHTML(r.findings);
    if (r.scanError) html += `<div class="finding aviso" style="margin-top:10px"><b>Redes vizinhas</b>${esc(r.scanError)}</div>`;
    if (r.networks.length) {
      html += `<h2>Canais</h2><div class="cards">` + channelBars(r.channels, 2.4, c?.bandGHz === 2.4 ? c.channel : 0, r.best24) +
        channelBars(r.channels, 5, c?.bandGHz === 5 ? c.channel : 0, r.best5) + `</div>`;
      html += `<h2>Redes encontradas (${r.networks.length})</h2><div class="tablewrap"><table><thead><tr><th>Rede</th><th>Sinal</th><th>Bandas</th><th>Canais</th><th>Pontos de acesso</th><th>Padrão</th></tr></thead><tbody>` +
        r.networks.map(n => `<tr${n.connected ? ' class="hl"' : ""}><td>${esc(n.ssid)}${n.connected ? ' <span class="tag self">conectado</span>' : ""}</td>
          <td class="num">${n.bestRssi} dBm ${lvl(rate("sinal", n.bestRssi))}</td>
          <td>${n.bands.map(b => b + " GHz").join(" + ")}</td>
          <td class="mono">${[...new Set(n.aps.map(a => a.channel))].join(", ")}</td>
          <td class="num">${n.aps.length}</td><td class="sub">${esc([...new Set(n.aps.map(a => a.phy).filter(Boolean))].join(", "))}</td></tr>`).join("") +
        `</tbody></table></div>`;
    }
  }
  html += `<h2>Como ler</h2>` + legend("sinal");
  $("wcontent").innerHTML = html || '<div class="empty"><b>Nenhuma placa Wi-Fi</b></div>';
}

$("wgo").onclick = runWifi;
