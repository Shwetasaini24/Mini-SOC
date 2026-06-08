/* ── Mini SOC Dashboard — JavaScript ─────────────────────────────────────── */

"use strict";

// ─── State ────────────────────────────────────────────────────────────────────
let currentPage   = 1;
let refreshTimer  = null;
let hourlyChart   = null;
let statusChart   = null;

// ─── Clock ────────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent =
    now.toUTCString().replace("GMT", "UTC");
}
setInterval(updateClock, 1000);
updateClock();

// ─── Navigation ───────────────────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", e => {
    e.preventDefault();
    const sec = item.dataset.section;

    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));

    item.classList.add("active");
    document.getElementById("section-" + sec).classList.add("active");
    document.getElementById("page-title").textContent = sec.toUpperCase();

    if (sec === "logs")    loadLogs();
    if (sec === "threats") loadThreats();
  });
});

// ─── API helpers ──────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const res  = await fetch(url, opts);
  const data = await res.json();
  return data;
}

// ─── Stats + Charts ───────────────────────────────────────────────────────────
async function refreshStats() {
  try {
    const d = await apiFetch("/api/stats");

    // KPIs
    animateCount("kpi-total",   d.total_logs);
    animateCount("kpi-threats", d.total_threats);
    animateCount("kpi-high",    d.high_severity);
    animateCount("kpi-med",     d.med_severity);

    // Badge
    document.getElementById("threat-badge").textContent = d.total_threats;

    // Sim button state
    if (d.sim_active) {
      document.getElementById("simStart").classList.add("hidden");
      document.getElementById("simStop").classList.remove("hidden");
    } else {
      document.getElementById("simStart").classList.remove("hidden");
      document.getElementById("simStop").classList.add("hidden");
    }

    // Top IPs table
    renderTopIPs(d.top_ips);

    // Recent threats table (on overview)
    renderRecentThreats(d.threats.slice(0, 8));

    // Charts
    renderHourlyChart(d.hourly);
    renderStatusChart(d.status_dist);

  } catch (err) {
    console.error("Stats error:", err);
  }
}

function animateCount(id, target) {
  const el      = document.getElementById(id);
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;

  const step  = Math.ceil(Math.abs(target - current) / 20);
  const dir   = target > current ? 1 : -1;
  let   val   = current;
  const timer = setInterval(() => {
    val += dir * step;
    if ((dir > 0 && val >= target) || (dir < 0 && val <= target)) {
      val = target;
      clearInterval(timer);
    }
    el.textContent = val.toLocaleString();
  }, 30);
}

// ─── Top IPs Table ────────────────────────────────────────────────────────────
function renderTopIPs(ips) {
  const tbody = document.getElementById("topIpsTbody");
  if (!ips || ips.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:1.5rem">No data yet</td></tr>';
    return;
  }

  const maxCount = Math.max(...ips.map(r => r.cnt));
  tbody.innerHTML = ips.map(row => {
    const pct  = Math.round((row.cnt / maxCount) * 100);
    const cls  = pct > 66 ? "high" : pct > 33 ? "med" : "";
    const risk = pct > 66 ? "HIGH" : pct > 33 ? "MED" : "LOW";
    return `
      <tr>
        <td>${escHtml(row.ip_address)}</td>
        <td style="color:var(--accent)">${row.cnt.toLocaleString()}</td>
        <td>
          <div class="risk-bar-wrap">
            <div class="risk-bar"><div class="risk-fill ${cls}" style="width:${pct}%"></div></div>
            <span class="sev-badge sev-${risk === 'MED' ? 'MEDIUM' : risk}">${risk}</span>
          </div>
        </td>
      </tr>`;
  }).join("");
}

// ─── Recent Threats Table (Overview) ─────────────────────────────────────────
function renderRecentThreats(threats) {
  const tbody = document.getElementById("recentThreatsTbody");
  if (!threats || threats.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:1.5rem">No threats</td></tr>';
    return;
  }
  tbody.innerHTML = threats.map(t => `
    <tr>
      <td style="font-size:0.7rem">${escHtml(t.threat_type)}</td>
      <td>${escHtml(t.ip_address)}</td>
      <td><span class="sev-badge sev-${t.severity}">${t.severity}</span></td>
    </tr>`).join("");
}

// ─── Hourly Chart ─────────────────────────────────────────────────────────────
function renderHourlyChart(hourly) {
  const labels = hourly.map(r => r.hour || "00:00");
  const values = hourly.map(r => r.cnt);

  const ctx = document.getElementById("hourlyChart").getContext("2d");

  if (hourlyChart) {
    hourlyChart.data.labels = labels;
    hourlyChart.data.datasets[0].data = values;
    hourlyChart.update("none");
    return;
  }

  hourlyChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Log Entries",
        data: values,
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.08)",
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: "#00d4ff",
        tension: 0.4,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: "#3a6070", font: { family: "'Share Tech Mono'" , size: 10 } },
          grid:  { color: "rgba(13,47,69,0.6)" },
        },
        y: {
          ticks: { color: "#3a6070", font: { family: "'Share Tech Mono'", size: 10 } },
          grid:  { color: "rgba(13,47,69,0.6)" },
          beginAtZero: true,
        }
      },
      animation: { duration: 400 },
    }
  });
}

// ─── Status Code Chart ────────────────────────────────────────────────────────
function renderStatusChart(statusDist) {
  const labels  = statusDist.map(r => String(r.status_code));
  const values  = statusDist.map(r => r.cnt);
  const colors  = labels.map(code => {
    const n = parseInt(code);
    if (n < 300) return "#00ff9d";
    if (n < 400) return "#8be9fd";
    if (n < 500) return "#ffb800";
    return "#ff3b6b";
  });

  const ctx = document.getElementById("statusChart").getContext("2d");

  if (statusChart) {
    statusChart.data.labels             = labels;
    statusChart.data.datasets[0].data   = values;
    statusChart.data.datasets[0].backgroundColor = colors.map(c => c + "99");
    statusChart.data.datasets[0].borderColor     = colors;
    statusChart.update("none");
    return;
  }

  statusChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + "55"),
        borderColor: colors,
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#4a7a8a",
            font: { family: "'Share Tech Mono'", size: 10 },
            boxWidth: 10,
          }
        }
      },
      animation: { duration: 400 },
    }
  });
}

// ─── Threat Alerts Section ────────────────────────────────────────────────────
async function loadThreats() {
  try {
    const d     = await apiFetch("/api/stats");
    const grid  = document.getElementById("alertGrid");
    const icons = { BRUTE_FORCE: "🔓", HTTP_FLOOD: "🌊", PATH_SCAN: "🔍" };

    if (!d.threats || d.threats.length === 0) {
      grid.innerHTML = '<div class="no-data">No threats detected yet.<br>Upload logs or start simulation.</div>';
      return;
    }

    grid.innerHTML = d.threats.map(t => `
      <div class="alert-card ${escHtml(t.severity)}">
        <div class="alert-top">
          <span class="alert-type">${icons[t.threat_type] || "⚠"} ${escHtml(t.threat_type)}</span>
          <span class="alert-ip">${escHtml(t.ip_address)}</span>
        </div>
        <div class="alert-desc">${escHtml(t.description)}</div>
        <div class="alert-meta">
          <span class="sev-badge sev-${t.severity}">${t.severity}</span>
          &nbsp; occurrences: ${t.count}
          &nbsp; · &nbsp; ${t.detected_at}
        </div>
      </div>`).join("");
  } catch (err) {
    console.error("Threats error:", err);
  }
}

// ─── Log Stream Section ───────────────────────────────────────────────────────
async function loadLogs() {
  const severity = document.getElementById("logFilter").value;
  try {
    const d    = await apiFetch(`/api/logs?page=${currentPage}&per_page=50&severity=${severity}`);
    const tbody = document.getElementById("logsTbody");

    document.getElementById("logCount").textContent =
      `${d.total.toLocaleString()} total entries`;

    if (!d.logs || d.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">No log entries found.</td></tr>';
    } else {
      tbody.innerHTML = d.logs.map(log => {
        const sc   = log.status_code;
        const scCls = sc < 300 ? "status-2xx" : sc < 400 ? "status-3xx" : sc < 500 ? "status-4xx" : "status-5xx";
        return `
          <tr>
            <td>${escHtml(log.timestamp || log.created_at || "—")}</td>
            <td>${escHtml(log.ip_address || "—")}</td>
            <td style="color:var(--accent)">${escHtml(log.method || "—")}</td>
            <td style="color:var(--muted)">${escHtml(log.path || "—")}</td>
            <td class="${scCls}">${sc}</td>
            <td><span class="sev-badge sev-${log.severity}">${log.severity}</span></td>
          </tr>`;
      }).join("");
    }

    // Pagination
    const totalPages = Math.ceil(d.total / 50);
    renderPagination(totalPages, d.page);

  } catch (err) {
    console.error("Logs error:", err);
  }
}

function renderPagination(total, current) {
  const el = document.getElementById("pagination");
  if (total <= 1) { el.innerHTML = ""; return; }

  let html = "";
  // Show max 7 page buttons around current
  const start = Math.max(1, current - 3);
  const end   = Math.min(total, current + 3);

  if (start > 1) html += `<button class="page-btn" onclick="goPage(1)">1</button>`;
  if (start > 2) html += `<button class="page-btn" disabled>…</button>`;

  for (let p = start; p <= end; p++) {
    html += `<button class="page-btn ${p === current ? "active" : ""}" onclick="goPage(${p})">${p}</button>`;
  }

  if (end < total - 1) html += `<button class="page-btn" disabled>…</button>`;
  if (end < total)     html += `<button class="page-btn" onclick="goPage(${total})">${total}</button>`;

  el.innerHTML = html;
}

function goPage(p) {
  currentPage = p;
  loadLogs();
}

// ─── Simulation ───────────────────────────────────────────────────────────────
async function startSim() {
  await apiFetch("/api/simulation/start", { method: "POST" });
  document.getElementById("simStart").classList.add("hidden");
  document.getElementById("simStop").classList.remove("hidden");
}

async function stopSim() {
  await apiFetch("/api/simulation/stop", { method: "POST" });
  document.getElementById("simStart").classList.remove("hidden");
  document.getElementById("simStop").classList.add("hidden");
}

// ─── Clear Data ───────────────────────────────────────────────────────────────
async function clearData() {
  if (!confirm("Clear ALL logs and threats?")) return;
  showLoader("CLEARING DATABASE…");
  await apiFetch("/api/clear", { method: "POST" });
  hideLoader();
  refreshStats();
}

// ─── File Upload ──────────────────────────────────────────────────────────────
async function uploadFile(input) {
  const file = input.files[0];
  if (!file) return;

  showLoader(`UPLOADING ${file.name}…`);
  const form = new FormData();
  form.append("file", file);

  try {
    const data = await apiFetch("/api/upload", { method: "POST", body: form });
    hideLoader();
    input.value = "";

    const resultEl = document.getElementById("uploadResult");
    resultEl.classList.remove("hidden", "error", "success");

    if (data.error) {
      resultEl.classList.add("error");
      resultEl.innerHTML = `❌ ERROR: ${escHtml(data.error)}`;
    } else {
      resultEl.classList.add("success");
      resultEl.innerHTML = `
        ✅ UPLOAD COMPLETE<br>
        📄 File: <span style="color:var(--accent)">${escHtml(file.name)}</span><br>
        ✔ Parsed: <span style="color:var(--accent2)">${data.inserted}</span> entries<br>
        ✗ Skipped: <span style="color:var(--muted)">${data.skipped}</span> lines<br>
        ${data.message}`;
      // Refresh stats after upload
      refreshStats();
    }
  } catch (err) {
    hideLoader();
    const resultEl = document.getElementById("uploadResult");
    resultEl.classList.remove("hidden"); resultEl.classList.add("error");
    resultEl.innerHTML = `❌ Upload failed: ${escHtml(String(err))}`;
  }
}

// Drag & drop support
const dropZone = document.getElementById("dropZone");
dropZone.addEventListener("dragover",  e => { e.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) {
    const inp = document.getElementById("fileInput");
    // Assign file via DataTransfer trick
    const dt = new DataTransfer();
    dt.items.add(file);
    inp.files = dt.files;
    uploadFile(inp);
  }
});

// ─── Loader ───────────────────────────────────────────────────────────────────
function showLoader(msg = "PROCESSING…") {
  document.getElementById("loaderText").textContent = msg;
  document.getElementById("loaderOverlay").classList.remove("hidden");
}

function hideLoader() {
  document.getElementById("loaderOverlay").classList.add("hidden");
}

// ─── Utility ─────────────────────────────────────────────────────────────────
function escHtml(str) {
  if (str === null || str === undefined) return "—";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Auto-refresh ─────────────────────────────────────────────────────────────
function startAutoRefresh() {
  refreshStats();
  refreshTimer = setInterval(() => {
    refreshStats();
    // Also refresh log/threat section if active
    const activeSec = document.querySelector(".section.active");
    if (activeSec && activeSec.id === "section-logs")    loadLogs();
    if (activeSec && activeSec.id === "section-threats") loadThreats();
  }, 4000); // Every 4 seconds
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  startAutoRefresh();
});
