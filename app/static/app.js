// ====== elementos del DOM ======
const uploadForm = document.getElementById("uploadForm");
const uploadMsg = document.getElementById("uploadMsg");
const previewSection = document.getElementById("previewSection");
const previewTable = document.getElementById("previewTable");
const columnsDiv = document.getElementById("columns");
const strategyPanel = document.getElementById("strategyPanel");
const runBtn = document.getElementById("runAnonymize");
const filenameBadge = document.getElementById("filenameBadge");
const piiSuggestions = document.getElementById("piiSuggestions");
const piiDetectedList = document.getElementById("piiDetectedList");

// ====== estado ======
let lastUpload = null;          // { filename, columns, head }
let originalHeadRows = [];      // copia inmutable de las primeras filas del dataset
let currentColumns = [];
let lastSuggestions = {};       // columna -> estrategia (ej. "hash:length=24")

// ========= utilidades de vista =========
function htmlEncode(s) {
  const div = document.createElement("div");
  div.innerText = s == null ? "" : String(s);
  return div.innerHTML;
}

// ========= subida y render base =========
uploadForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = document.getElementById("fileInput").files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  uploadMsg.textContent = "Subiendo...";
  try {
    const res = await fetch("/upload", { method: "POST", body: formData });
    if (!res.ok) throw new Error("Error al subir el archivo.");
    const data = await res.json();
    lastUpload = data; // { filename, columns, head }
    currentColumns = data.columns || [];
    originalHeadRows = (data.head || []).map(r => ({ ...r })); // copia
    uploadMsg.innerHTML = `<span class="badge">OK</span> ${htmlEncode(data.filename)}`;
    renderPreviewSkeleton(data);

    // Llama automáticamente a /api/analyze para sugerencias y auto-aplícalas
    await autoAnalyzeAndSuggest(data.filename, currentColumns);

    // Primera renderización de vista previa (con sugerencias aplicadas)
    await renderPreviewTable();
  } catch (err) {
    console.error(err);
    uploadMsg.textContent = "Error al subir el archivo.";
  }
});

function renderPreviewSkeleton(data) {
  previewSection.classList.remove("hidden");
  filenameBadge.textContent = data.filename ? `Archivo: ${data.filename}` : "";
  columnsDiv.innerHTML = `<strong>Columnas:</strong> ${data.columns.map(c=>htmlEncode(c)).join(", ")}`;

  // Cabecera de tabla (filas se llenan en renderPreviewTable)
  const headers = `<thead><tr>${data.columns.map(c => `<th>${htmlEncode(c)}</th>`).join("")}</tr></thead>`;
  previewTable.innerHTML = headers + `<tbody></tbody>`;

  // Panel de selección de estrategia
  buildStrategyGrid(data.columns);
}

function buildStrategyGrid(columns) {
  strategyPanel.innerHTML = "";
  const grid = document.createElement("div");
  grid.className = "selector-grid";

  columns.forEach(col => {
    const cell = document.createElement("div");
    cell.className = "cell";
    cell.innerHTML = `
      <label>${htmlEncode(col)}</label>
      <select data-col="${htmlEncode(col)}">
        <option value="">(ignorar)</option>
        <option value="mask">mask</option>
        <option value="hash">hash</option>
        <option value="drop">drop</option>
        <option value="pseudonym">pseudonym</option>
        <option value="generalize_date">generalize_date</option>
        <option value="generalize_geo">generalize_geo</option>
        <option value="bucket_numeric">bucket_numeric</option>
        <option value="bucket_age">bucket_age</option>
        <option value="redact_text">redact_text</option>
      </select>
    `;
    grid.appendChild(cell);
  });
  strategyPanel.appendChild(grid);

  // 🔁 Escuchar cambios para previsualizar en tiempo real
  strategyPanel.querySelectorAll("select").forEach(sel => {
    sel.addEventListener("change", () => {
      // al cambiar, invalidar estrategia completa si base no coincide
      const full = sel.getAttribute("data-full-strategy");
      if (full && full.split(":")[0] !== sel.value) {
        sel.removeAttribute("data-full-strategy");
      }
      renderPreviewTable();
    });
  });
}

// ========= sugerencias automáticas (servidor) =========
async function autoAnalyzeAndSuggest(filename, columns) {
  try {
    const res = await fetch(`/api/analyze?filename=${encodeURIComponent(filename)}`, {
      method: "POST"
    });
    if (!res.ok) throw new Error("No se pudo analizar el archivo.");
    const data = await res.json();
    lastSuggestions = data.suggestions || {};

    // Mostrar lista de PII detectada
    const detected = data.detected_pii_columns || [];
    if (detected.length > 0) {
      piiSuggestions.classList.remove("hidden");
      piiDetectedList.innerHTML = detected.map(c => `<span class="badge">${htmlEncode(c)}</span>`).join(" ");
    } else {
      piiSuggestions.classList.add("hidden");
      piiDetectedList.innerHTML = "";
    }

    // Aplicar sugerencias automáticamente a los <select>
    const selects = strategyPanel.querySelectorAll("select");
    selects.forEach(s => {
      const col = s.dataset.col;
      const suggestion = lastSuggestions[col];
      if (!suggestion) return;
      const base = suggestion.split(":")[0];
      const matchingOption = Array.from(s.options).find(o => o.value === base);
      if (matchingOption) s.value = base;
      // Guardamos la estrategia completa para enviar al backend
      s.setAttribute("data-full-strategy", suggestion);
    });
  } catch (err) {
    console.error(err);
  }
}

// ========= PREVISUALIZACIÓN EN TIEMPO REAL =========
// Implementaciones ligeras de las estrategias para vista previa.
// NOTA: Son heurísticas para UI; la anonimización final la hace el backend.

function maskText(str, keepStart = 1, keepEnd = 1, char = "*") {
  const s = (str ?? "").toString();
  if (s.length <= keepStart + keepEnd) return char.repeat(s.length);
  return s.slice(0, keepStart) + char.repeat(s.length - keepStart - keepEnd) + s.slice(-keepEnd);
}
function maskEmail(str) {
  const s = (str ?? "").toString();
  const at = s.indexOf("@");
  if (at === -1) return maskText(s, 1, 1);
  return s[0] + "***" + s.slice(at);
}
function maskPhoneDigits(str, tailKeep = 2) {
  const s = (str ?? "").toString();
  const digits = Array.from(s).filter(c => /\d/.test(c));
  if (digits.length === 0) return s;
  const masked = s.replace(/\d/g, "*");
  const tail = digits.slice(-tailKeep).join("");
  return masked + (tailKeep > 0 ? ` (${tail})` : "");
}
function previewHash(value, length = 16) {
  // Hash no criptográfico (para UI). Backend usa SHA-256 real.
  const s = (value ?? "").toString();
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  const hex = ("00000000" + h.toString(16)).slice(-8);
  return hex.repeat(Math.ceil(length / 8)).slice(0, length);
}
function generalizeDate(str, granularity = "year_month") {
  const s = (str ?? "").toString().trim();
  const d = new Date(s.replace(/(\d{2})\/(\d{2})\/(\d{4})/, "$2/$1/$3")); // soporta dd/mm/yyyy simple
  if (isNaN(d.getTime())) return s;
  if (granularity === "year") return String(d.getFullYear());
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  return `${d.getFullYear()}-${mm}`;
}
function generalizeGeo(str, levels = 2) {
  const s = (str ?? "").toString();
  const noDigits = s.replace(/\d/g, "").trim();
  const parts = noDigits.split(",").map(p => p.trim()).filter(Boolean);
  if (parts.length === 0) return s;
  return parts.slice(-Math.abs(levels)).join(", ");
}
function bucketNumeric(str, size = 10) {
  const x = Number(str);
  if (!isFinite(x) || size <= 0) return String(str ?? "");
  const lo = Math.floor(x / size) * size;
  const hi = lo + size - 1;
  return `${lo}-${hi}`;
}
function bucketAge(str, bins = [0,12,18,30,45,60,75,200]) {
  const age = Number(str);
  if (!isFinite(age)) return String(str ?? "");
  for (let i = 0; i < bins.length - 1; i++) {
    if (bins[i] <= age && age < bins[i+1]) return `${bins[i]}-${bins[i+1]-1}`;
  }
  return String(str ?? "");
}
function redactText(str) {
  const s = (str ?? "").toString();
  // Emails
  let out = s.replace(/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/g, (_, a, b) => a + "***" + b);
  // Teléfonos aproximados
  out = out.replace(/(?:\+?\d[\d\-\s().]{6,}\d)/g, m => m.replace(/\d/g, "*"));
  // DNI y RUC (8 y 11 dígitos)
  out = out.replace(/\b\d{8}\b/g, m => "*".repeat(m.length));
  out = out.replace(/\b\d{11}\b/g, m => "*".repeat(m.length));
  return out;
}

// Parsea estrategia completa "name:k=v,k2=v2" -> {name, params}
function parseStrategy(strat) {
  if (!strat) return { name: "", params: {} };
  const [name, raw] = strat.split(":");
  const params = {};
  if (raw) {
    raw.split(",").forEach(kv => {
      const [k, v] = kv.split("=").map(s => s?.trim());
      if (!k) return;
      const num = Number(v);
      params[k] = isFinite(num) && v !== "" && !Number.isNaN(num) ? num : v;
    });
  }
  return { name: (name || "").trim(), params };
}

// Aplica la estrategia (solo para previsualización)
function applyStrategyValue(v, stratFull) {
  const { name, params } = parseStrategy(stratFull || "");
  const s = v == null ? "" : String(v);

  if (!name) return s;

  switch (name) {
    case "drop":
      return "[REMOVIDO]";
    case "mask": {
      // Heurística: email / teléfono / genérico
      if (s.includes("@")) return maskEmail(s);
      const digitCount = (s.match(/\d/g) || []).length;
      if (digitCount >= 6) return maskPhoneDigits(s, 2);
      const ks = Number(params.keep_start ?? 1);
      const ke = Number(params.keep_end ?? 1);
      const ch = String(params.char ?? "*");
      return maskText(s, ks, ke, ch);
    }
    case "hash": {
      const length = Number(params.length ?? 16);
      return previewHash(s, length);
    }
    case "pseudonym": {
      const prefix = String(params.prefix ?? "ID_");
      return prefix + previewHash(s, 10);
    }
    case "generalize_date": {
      const gran = String(params.granularity ?? "year_month");
      return generalizeDate(s, gran);
    }
    case "generalize_geo": {
      const lv = Number(params.levels ?? 2);
      return generalizeGeo(s, lv);
    }
    case "bucket_numeric": {
      const size = Number(params.size ?? 10);
      return bucketNumeric(s, size);
    }
    case "bucket_age": {
      return bucketAge(s);
    }
    case "redact_text": {
      return redactText(s);
    }
    default:
      return maskText(s);
  }
}

// Construye el plan a partir de los selects
function getCurrentPlan() {
  const plan = {};
  const selects = strategyPanel.querySelectorAll("select");
  selects.forEach(s => {
    const col = s.dataset.col;
    const base = s.value;
    const full = s.getAttribute("data-full-strategy");
    if (!base) return;
    // Si hay una completa y coincide con la base, enviar la completa, si no, la base
    const chosen = full && full.split(":")[0] === base ? full : base;
    plan[col] = chosen;
  });
  return plan;
}

// Renderiza la tabla de previsualización aplicando el plan actual
async function renderPreviewTable() {
  if (!originalHeadRows || originalHeadRows.length === 0) return;
  const plan = getCurrentPlan();
  const tbody = document.createElement("tbody");

  for (const row of originalHeadRows) {
    const tr = document.createElement("tr");
    currentColumns.forEach(col => {
      const td = document.createElement("td");
      const strat = plan[col]; // puede ser undefined -> deja original
      const val = strat ? applyStrategyValue(row[col], strat) : (row[col] ?? "");
      td.innerHTML = htmlEncode(val);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }

  // Reemplaza cuerpo de la tabla manteniendo thead
  const thead = previewTable.querySelector("thead");
  previewTable.innerHTML = "";
  if (thead) previewTable.appendChild(thead);
  previewTable.appendChild(tbody);
}

// ========= envío al backend =========
runBtn?.addEventListener("click", async () => {
  if (!lastUpload) return;
  const plan = getCurrentPlan();
  let selected_columns = Object.keys(plan);

  // 👇 Si no hay ninguna selección, aplica sugerencias automáticas
  if (selected_columns.length === 0 && lastSuggestions) {
    for (const [col, strat] of Object.entries(lastSuggestions)) {
      if (strat) plan[col] = strat; // aplica sugerencia completa
    }
    selected_columns = Object.keys(plan);
    if (selected_columns.length === 0) {
      alert("Selecciona al menos una columna o usa las sugerencias automáticas.");
      return;
    }
  }

  const payload = { selected_columns, strategies: plan, sample_rows: 10 };

  try {
    const res = await fetch(`/anonymize/${encodeURIComponent(lastUpload.filename)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    // 👇 loguea los errores 422 para ver exactamente qué falló
    if (!res.ok) {
      let msg = "Error al anonimizar";
      try { const err = await res.json(); console.error("422 details:", err); msg += `: ${JSON.stringify(err)}`; } catch {}
      throw new Error(msg);
    }

    const data = await res.json();
    window.location.href = data.report_url;
  } catch (err) {
    console.error(err);
    alert("Ocurrió un error al anonimizar. Revisa la consola.");
  }
});
runBtn?.addEventListener("click", async () => {
  if (!lastUpload) return;
  const plan = getCurrentPlan();
  const selected_columns = Object.keys(plan);
  const payload = { selected_columns, strategies: plan, sample_rows: 10 };

  try {
    const res = await fetch(`/anonymize/${encodeURIComponent(lastUpload.filename)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error("Error al anonimizar");
    const data = await res.json(); // { report_url }
    window.location.href = data.report_url;
  } catch (err) {
    console.error(err);
    alert("Ocurrió un error al anonimizar. Revisa la consola.");
  }
});