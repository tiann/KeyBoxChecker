import "./styles.css";
import { TRUST_DATA } from "./trust-data.js";
import { analyzeKeybox, decodeKeyboxBytes, resultToText } from "./analyzer.js";

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const resultEl = document.getElementById("result");
const toolbar = document.getElementById("toolbar");
const copyJson = document.getElementById("copy-json");
const copyText = document.getElementById("copy-text");
const clearBtn = document.getElementById("clear");
let lastResult = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

function badge(status) {
  return `<span class="badge ${escapeHtml(status)}">${escapeHtml(status).toUpperCase()}</span>`;
}

function render(result) {
  lastResult = result;
  toolbar.classList.remove("hidden");
  const warning = result.trustData?.fetchedAt ? `<p><small>Offline revocation snapshot: ${escapeHtml(result.trustData.fetchedAt)}; entries=${result.trustData.revocationEntryCount}</small></p>` : "";
  const keyboxes = result.keyboxes.map(kb => `
    <article class="card">
      <h3>Device ID: ${escapeHtml(kb.deviceId)}</h3>
      ${kb.keys.map((key, idx) => `
        <section class="card">
          <h4>${badge(key.status)} Key #${idx + 1}: ${escapeHtml(key.algorithm)}</h4>
          <div class="grid">
            <div class="kv"><span>Private key</span>${key.privateKey.matchesLeafCertificate ? "✅ matches leaf certificate" : "❌ mismatch/invalid"}</div>
            <div class="kv"><span>Certificate chain</span>${key.chain.valid ? "✅ valid signatures" : "❌ invalid signatures or issuer"}</div>
            <div class="kv"><span>Root</span>${key.root.recognized ? "✅" : "❌"} ${escapeHtml(key.root.label)}</div>
            <div class="kv"><span>Revocation</span>${key.revocation.hits.length ? "❌ hit" : "✅ serial not found"}</div>
          </div>
          ${key.warnings.length ? `<ul>${key.warnings.map(w => `<li>⚠️ ${escapeHtml(w)}</li>`).join("")}</ul>` : ""}
          ${key.errors.length ? `<ul>${key.errors.map(e => `<li>❌ ${escapeHtml(e)}</li>`).join("")}</ul>` : ""}
          <h4>Certificates (${key.actualCertificateCount}/${key.declaredCertificateCount})</h4>
          <div class="grid">
            ${key.certificates.map((cert, certIdx) => `
              <div class="kv">
                <span>#${certIdx + 1} ${certIdx === 0 ? "leaf" : certIdx === key.certificates.length - 1 ? "root" : "intermediate"}</span>
                <strong>${escapeHtml(cert.serialHex)}</strong><br />
                ${escapeHtml(cert.subject)}<br />
                <small>${escapeHtml(cert.publicKeyType)} ${escapeHtml(cert.curve || "")} · ${escapeHtml(cert.signatureAlgorithm)}</small><br />
                <small>${escapeHtml(cert.notBefore)} → ${escapeHtml(cert.notAfter)}</small>
              </div>`).join("")}
          </div>
          <h4>Checks</h4>
          <ul>${key.chain.checks.map(c => `<li>${c.status === "pass" ? "✅" : "❌"} ${escapeHtml(c.message)}</li>`).join("")}</ul>
          ${key.revocation.hits.length ? `<h4>Revocation hits</h4><pre>${escapeHtml(JSON.stringify(key.revocation.hits, null, 2))}</pre>` : ""}
        </section>`).join("")}
    </article>`).join("");
  resultEl.innerHTML = `
    <article class="card">
      <h2>${badge(result.overall)} Analysis complete</h2>
      ${warning}
      <p>File contents are processed only in this page's memory. They are not uploaded and no external domains are contacted by default.</p>
      ${result.warnings.length ? `<ul>${result.warnings.map(w => `<li>⚠️ ${escapeHtml(w)}</li>`).join("")}</ul>` : ""}
      ${result.errors.length ? `<ul>${result.errors.map(e => `<li>❌ ${escapeHtml(e)}</li>`).join("")}</ul>` : ""}
    </article>
    ${keyboxes}`;
}

async function handleFile(file) {
  resultEl.innerHTML = `<article class="card"><h2>${badge("info")} Analyzing ${escapeHtml(file.name)}</h2></article>`;
  toolbar.classList.add("hidden");
  try {
    if (file.size > 512 * 1024) throw new Error("File is larger than 512 KiB");
    const bytes = new Uint8Array(await file.arrayBuffer());
    const xml = decodeKeyboxBytes(bytes);
    const result = await analyzeKeybox(xml, TRUST_DATA, new Date());
    render(result);
  } catch (error) {
    lastResult = null;
    resultEl.innerHTML = `<article class="card"><h2>${badge("error")} Error</h2><p>${escapeHtml(error.message || String(error))}</p></article>`;
  }
}

dropZone.addEventListener("click", () => fileInput.click());
dropZone.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") fileInput.click(); });
fileInput.addEventListener("change", () => { const file = fileInput.files?.[0]; if (file) handleFile(file); });
for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.add("dragover"); });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.remove("dragover"); });
}
dropZone.addEventListener("drop", event => { const file = event.dataTransfer?.files?.[0]; if (file) handleFile(file); });
copyJson.addEventListener("click", () => lastResult && navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2)));
copyText.addEventListener("click", () => lastResult && navigator.clipboard.writeText(resultToText(lastResult)));
clearBtn.addEventListener("click", () => { lastResult = null; fileInput.value = ""; toolbar.classList.add("hidden"); resultEl.innerHTML = ""; });

resultEl.innerHTML = `<article class="card"><h2>${badge("info")} Ready</h2><p>Using offline trust data: ${escapeHtml(TRUST_DATA.version)}; revocation entries: ${Object.keys(TRUST_DATA.status.entries).length}.</p></article>`;
