// Aba "Relatório": dados do atendimento e geração do relatório para o cliente/OS.
const ATEND_FIELDS = [
  ["cliente", "Cliente", "Nome do cliente"], ["codigo", "Código / contrato", "ex.: 12345"],
  ["tecnico", "Técnico", "Seu nome"], ["endereco", "Endereço", "Rua, número, bairro"],
];

async function renderRelatorio() {
  const d = await loadAtend();
  const a = d.atendimento, c = d.contagem;
  const started = a.iniciadoEm && !a.iniciadoEm.startsWith("0001");
  $("rcontent").innerHTML = `
    <div class="panelbar"><div class="desc"><b>Atendimento</b>Os testes feitos a partir de agora ficam ligados a este atendimento, são salvos na pasta do cliente e entram no relatório. Faça um teste no início (antes) e outro depois de resolver: o relatório mostra a comparação.</div>
      <button id="r-new" class="ghost">Novo atendimento</button></div>
    <div class="form" style="margin-top:12px">
      <div class="formgrid">
        ${ATEND_FIELDS.map(([k, l, ph]) => `<label class="f">${l}<input type="text" id="r-${k}" value="${esc(a[k] || "")}" placeholder="${ph}"></label>`).join("")}
        <label class="f">Plano (Mega)<input type="number" id="r-plano" class="plano" min="0" value="${a.planoMbps || ""}" placeholder="ex.: 500"></label>
      </div>
      <label class="f" style="width:100%">Problema relatado pelo cliente<textarea id="r-problema" placeholder="ex.: internet cai à noite, Wi-Fi lento no quarto">${esc(a.problema || "")}</textarea></label>
      <label class="f" style="width:100%">Solução aplicada / observações<textarea id="r-solucao" placeholder="ex.: trocado canal do Wi-Fi de 6 para 11, refeito conector do cabo">${esc(a.solucao || "")}</textarea></label>
      <button id="r-save">Salvar dados</button><span class="sub" id="r-saved"></span>
    </div>
    <h2>Testes deste atendimento</h2>
    <div class="metrics">
      <div class="metric"><div class="label">Varreduras da rede</div><div class="value">${c.varreduras}</div></div>
      <div class="metric"><div class="label">Testes de saúde</div><div class="value">${c.saude}</div>${c.saude >= 2 ? '<div class="sub">tem antes e depois</div>' : ""}</div>
      <div class="metric"><div class="label">Testes de velocidade</div><div class="value">${c.velocidade}</div>${c.velocidade >= 2 ? '<div class="sub">tem antes e depois</div>' : ""}</div>
      <div class="metric"><div class="label">Análises de Wi-Fi</div><div class="value">${c.wifi}</div></div>
    </div>
    <div class="sub" style="margin-top:8px">${started ? "Iniciado em " + fmtDate(a.iniciadoEm) + " · " : ""}Arquivos salvos em <span class="mono">${esc(d.pasta)}</span></div>
    <div class="panelbar" style="margin-top:16px"><div class="desc"><b>Relatório</b>Abre o relatório numa nova aba, pronto para imprimir ou salvar em PDF (Ctrl+P → “Salvar como PDF”).</div>
      <button id="r-report">Gerar relatório</button></div>`;

  const collect = () => {
    const o = {};
    ATEND_FIELDS.forEach(([k]) => o[k] = $("r-" + k).value.trim());
    o.planoMbps = Math.max(0, +$("r-plano").value || 0);
    o.problema = $("r-problema").value.trim();
    o.solucao = $("r-solucao").value.trim();
    return o;
  };
  $("r-save").onclick = async () => {
    try { await saveAtend(collect()); $("r-saved").textContent = " Salvo."; try { localStorage.setItem("tecnico", $("r-tecnico").value.trim()); } catch {} }
    catch (e) { showError(e.message); }
  };
  $("r-new").onclick = async () => {
    if (!confirm("Iniciar um novo atendimento? Os testes atuais continuam salvos na pasta, mas saem do relatório.")) return;
    let tec = "";
    try { tec = localStorage.getItem("tecnico") || ""; } catch {}
    await saveAtend({ tecnico: tec }, true);
    renderRelatorio();
  };
  $("r-report").onclick = async () => {
    await saveAtend(collect());
    window.open("relatorio.html", "_blank");
  };
}

document.querySelector('nav.tabs button[data-tab="relatorio"]').addEventListener("click", () => renderRelatorio().catch(e => showError(e.message)));
app.ready.then(() => { if (document.querySelector("#tab-relatorio.active")) renderRelatorio(); });
