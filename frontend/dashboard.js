/* ── VulnStats Dashboard ──────────────────────────────────────────────────── */
"use strict";

const API = "";          // same-origin; change to "http://localhost:8000" for dev
const PAGE_SIZE = 50;

/* ── State ────────────────────────────────────────────────────────────────── */
const state = {
  domain: "",
  months: 24,
  kevOnly: false,
  minCvss: null,
  search: "",
  page: 0,
  charts: {},
};

/* ── Chart.js defaults ───────────────────────────────────────────────────── */
Chart.defaults.color = "#8b949e";
Chart.defaults.borderColor = "#30363d";
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
Chart.defaults.font.size = 11;

/* ── Utils ────────────────────────────────────────────────────────────────── */
const fmt = (v, unit = " days") =>
  v == null ? "–" : `${Number(v).toLocaleString(undefined, { maximumFractionDigits: 1 })}${unit}`;

const fmtDate = (s) => (s ? new Date(s).toLocaleDateString() : "–");

const cvssColor = (v) => {
  if (v == null) return "#8b949e";
  if (v >= 9) return "#f85149";
  if (v >= 7) return "#e3b341";
  if (v >= 4) return "#3fb950";
  return "#79c0ff";
};

const domainClass = (d) => `domain-${d || "other"}`;

async function apiFetch(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

/* ── KPI render ──────────────────────────────────────────────────────────── */
function renderKPIs(data) {
  document.getElementById("totalCves").textContent =
    data.total_cves?.toLocaleString() ?? "–";
  document.getElementById("kevCves").textContent =
    data.kev_cves?.toLocaleString() ?? "–";
  document.getElementById("avgMttr").textContent = fmt(data.avg_mttr_days);
  document.getElementById("medianMttr").textContent =
    `Median: ${fmt(data.median_mttr_days)}`;
  document.getElementById("avgMtte").textContent = fmt(data.avg_mtte_days);
  document.getElementById("avgExposure").textContent = fmt(
    data.avg_exposure_window_days
  );
  document.getElementById("exploitedPct").textContent = fmt(
    data.pct_exploited_before_patch,
    "%"
  );
}

/* ── Trend chart ─────────────────────────────────────────────────────────── */
function renderTrendChart(trends) {
  const labels = trends.map((t) => t.period);
  const mttrs = trends.map((t) => t.avg_mttr);
  const mttes = trends.map((t) => t.avg_mtte);
  const exposures = trends.map((t) => t.avg_exposure);

  // 3-month rolling average smoother
  const smooth = (arr) =>
    arr.map((_, i) => {
      const slice = arr.slice(Math.max(0, i - 2), i + 1).filter((v) => v != null);
      return slice.length ? slice.reduce((a, b) => a + b, 0) / slice.length : null;
    });

  const ctx = document.getElementById("trendChart");
  if (state.charts.trend) state.charts.trend.destroy();
  state.charts.trend = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Avg MTTR (days)",
          data: smooth(mttrs),
          borderColor: "#e3b341",
          backgroundColor: "rgba(227,179,65,.08)",
          fill: true,
          tension: 0.35,
          pointRadius: 2,
        },
        {
          label: "Avg MTTE (days)",
          data: smooth(mttes),
          borderColor: "#f85149",
          backgroundColor: "rgba(248,81,73,.08)",
          fill: true,
          tension: 0.35,
          pointRadius: 2,
        },
        {
          label: "Exposure Window (days)",
          data: smooth(exposures),
          borderColor: "#bc8cff",
          backgroundColor: "rgba(188,140,255,.06)",
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          borderDash: [4, 3],
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "top" },
        tooltip: {
          callbacks: {
            label: (ctx) =>
              ctx.parsed.y == null
                ? " –"
                : ` ${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)} days`,
          },
        },
      },
      scales: {
        y: { title: { display: true, text: "Days" }, beginAtZero: false },
      },
    },
  });
}

/* ── Domain pie ──────────────────────────────────────────────────────────── */
function renderDomainPie(domains) {
  const ctx = document.getElementById("domainPieChart");
  const COLORS = {
    os: "#58a6ff",
    cloud: "#79c0ff",
    saas: "#bc8cff",
    webapp: "#e3b341",
    other: "#484f58",
  };
  if (state.charts.pie) state.charts.pie.destroy();
  state.charts.pie = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: domains.map((d) => d.domain.toUpperCase()),
      datasets: [
        {
          data: domains.map((d) => d.count),
          backgroundColor: domains.map((d) => COLORS[d.domain] ?? "#484f58"),
          borderColor: "#161b22",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      cutout: "65%",
      plugins: { legend: { position: "right" } },
    },
  });
}

/* ── Domain MTTR bar ─────────────────────────────────────────────────────── */
function renderDomainMttr(domains) {
  const ctx = document.getElementById("domainMttrChart");
  if (state.charts.domainBar) state.charts.domainBar.destroy();
  state.charts.domainBar = new Chart(ctx, {
    type: "bar",
    data: {
      labels: domains.map((d) => d.domain.toUpperCase()),
      datasets: [
        {
          label: "Avg MTTR (days)",
          data: domains.map((d) => d.avg_mttr_days),
          backgroundColor: "#58a6ff",
        },
        {
          label: "Avg MTTE (days)",
          data: domains.map((d) => d.avg_mtte_days),
          backgroundColor: "#f85149",
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: { y: { beginAtZero: true } },
    },
  });
}

/* ── EPSS histogram ──────────────────────────────────────────────────────── */
function renderEpssChart(data) {
  const ctx = document.getElementById("epssChart");
  if (state.charts.epss) state.charts.epss.destroy();
  state.charts.epss = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.labels,
      datasets: [
        {
          label: "CVE count",
          data: data.counts,
          backgroundColor: data.counts.map((_, i) => {
            const t = i / 9;
            const r = Math.round(88 + t * 160);
            const g = Math.round(166 - t * 117);
            const b = Math.round(255 - t * 174);
            return `rgb(${r},${g},${b})`;
          }),
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { title: { display: true, text: "EPSS Score Range" } },
        y: { beginAtZero: true, title: { display: true, text: "Count" } },
      },
    },
  });
}

/* ── CVE table ───────────────────────────────────────────────────────────── */
function renderCveTable(cves) {
  const tbody = document.getElementById("cveTableBody");
  if (!cves.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="loading">No results</td></tr>`;
    return;
  }
  tbody.innerHTML = cves
    .map((c) => {
      const cvss = c.cvss_score;
      const epss = c.epss_score;
      return `
      <tr data-cve="${c.cve_id}">
        <td><code style="color:var(--accent)">${c.cve_id}</code></td>
        <td><span class="domain-chip ${domainClass(c.domain)}">${c.domain ?? "?"}</span></td>
        <td>${fmtDate(c.published_date)}</td>
        <td style="color:${cvssColor(cvss)}">${cvss != null ? cvss.toFixed(1) : "–"}</td>
        <td>${epss != null ? (epss * 100).toFixed(2) + "%" : "–"}</td>
        <td>${fmt(c.mttr_days)}</td>
        <td>${fmt(c.mtte_days)}</td>
        <td>${fmt(c.exposure_window_days)}</td>
        <td>${c.in_kev ? '<span class="kev-badge">KEV</span>' : "–"}</td>
      </tr>`;
    })
    .join("");

  // Row click → modal
  tbody.querySelectorAll("tr[data-cve]").forEach((row) => {
    row.addEventListener("click", () => openModal(row.dataset.cve));
  });
}

/* ── CVE modal ───────────────────────────────────────────────────────────── */
async function openModal(cveId) {
  const modal = document.getElementById("cveModal");
  modal.classList.remove("hidden");
  document.getElementById("modalCveId").textContent = cveId;
  document.getElementById("modalDesc").textContent = "Loading…";

  try {
    const d = await apiFetch(`/api/cves/${cveId}`);
    document.getElementById("modalCveId").textContent = d.cve_id;
    document.getElementById("modalDesc").textContent =
      d.description ?? "No description available.";
    document.getElementById("modalPublished").textContent = fmtDate(d.published_date);
    document.getElementById("modalFixed").textContent = fmtDate(d.fixed_date);
    document.getElementById("modalExploited").textContent = fmtDate(d.exploited_date);
    document.getElementById("modalCvss").textContent =
      d.cvss_score != null ? d.cvss_score.toFixed(1) : "–";
    document.getElementById("modalEpss").textContent =
      d.epss_score != null ? (d.epss_score * 100).toFixed(2) + "%" : "–";
    document.getElementById("modalDomain").textContent = d.domain ?? "–";
    document.getElementById("modalMttr").textContent = fmt(d.mttr_days);
    document.getElementById("modalMtte").textContent = fmt(d.mtte_days);
    document.getElementById("modalExposure").textContent = fmt(d.exposure_window_days);
    document.getElementById("modalKev").textContent = d.in_kev ? "YES ⚠" : "No";
  } catch (e) {
    document.getElementById("modalDesc").textContent = "Error loading details.";
  }
}

/* ── Ingest log ──────────────────────────────────────────────────────────── */
function renderIngestLog(rows) {
  const tbody = document.getElementById("ingestTableBody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading">No ingest runs yet</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(
      (r) => `
    <tr>
      <td>${r.source}</td>
      <td style="color:${r.status === "ok" ? "var(--green)" : "var(--red)"}">${r.status}</td>
      <td>${r.records?.toLocaleString() ?? "–"}</td>
      <td style="color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis">${
        r.message ?? "–"
      }</td>
      <td>${r.ran_at ? new Date(r.ran_at).toLocaleString() : "–"}</td>
    </tr>`
    )
    .join("");
}

/* ── Main data load ──────────────────────────────────────────────────────── */
async function loadAll() {
  const domainParam = state.domain ? `?domain=${state.domain}` : "";
  const summaryQ = `/api/summary${domainParam}`;
  const trendsQ = `/api/trends?months=${state.months}${state.domain ? `&domain=${state.domain}` : ""}`;
  const domainsQ = `/api/domains`;
  const epssQ = `/api/epss/distribution`;
  const ingestQ = `/api/ingest/status`;

  // Build CVE query
  const cvep = new URLSearchParams();
  if (state.domain) cvep.set("domain", state.domain);
  if (state.kevOnly) cvep.set("kev_only", "true");
  if (state.minCvss) cvep.set("min_cvss", state.minCvss);
  cvep.set("limit", PAGE_SIZE);
  cvep.set("offset", state.page * PAGE_SIZE);
  const cvesQ = `/api/cves?${cvep}`;

  try {
    const [summary, trends, domains, epss, cves, ingest] = await Promise.all([
      apiFetch(summaryQ),
      apiFetch(trendsQ),
      apiFetch(domainsQ),
      apiFetch(epssQ),
      apiFetch(cvesQ),
      apiFetch(ingestQ),
    ]);

    renderKPIs(summary);
    renderTrendChart(trends);
    renderDomainPie(domains);
    renderDomainMttr(domains);
    renderEpssChart(epss);

    // Filter table by search string client-side
    const filtered = state.search
      ? cves.filter((c) =>
          c.cve_id.toLowerCase().includes(state.search.toLowerCase())
        )
      : cves;
    renderCveTable(filtered);
    document.getElementById("tableCount").textContent = filtered.length;

    renderIngestLog(ingest);

    document.getElementById("lastUpdated").textContent =
      "Updated " + new Date().toLocaleTimeString();
    document.getElementById("prevPage").disabled = state.page === 0;
    document.getElementById("nextPage").disabled = cves.length < PAGE_SIZE;
    document.getElementById("pageInfo").textContent = `Page ${state.page + 1}`;
  } catch (err) {
    console.error("Load failed:", err);
    document.getElementById("lastUpdated").textContent = "⚠ Error loading data";
  }
}

/* ── Wire controls ───────────────────────────────────────────────────────── */
document.getElementById("domainFilter").addEventListener("change", (e) => {
  state.domain = e.target.value;
  state.page = 0;
  loadAll();
});

document.getElementById("trendMonths").addEventListener("change", (e) => {
  state.months = Number(e.target.value);
  loadAll();
});

document.getElementById("refreshBtn").addEventListener("click", loadAll);

document.getElementById("triggerIngestBtn").addEventListener("click", async () => {
  const btn = document.getElementById("triggerIngestBtn");
  btn.disabled = true;
  btn.textContent = "⏳ Ingesting…";
  try {
    await fetch(`${API}/api/ingest/trigger`, { method: "POST" });
    btn.textContent = "✓ Triggered";
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = "⬇ Re-Ingest";
    }, 4000);
  } catch {
    btn.disabled = false;
    btn.textContent = "⬇ Re-Ingest";
  }
});

document.getElementById("kevOnlyFilter").addEventListener("change", (e) => {
  state.kevOnly = e.target.checked;
  state.page = 0;
  loadAll();
});

let cvssTimeout;
document.getElementById("minCvss").addEventListener("input", (e) => {
  clearTimeout(cvssTimeout);
  cvssTimeout = setTimeout(() => {
    state.minCvss = e.target.value ? parseFloat(e.target.value) : null;
    state.page = 0;
    loadAll();
  }, 400);
});

let searchTimeout;
document.getElementById("cveSearch").addEventListener("input", (e) => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    state.search = e.target.value.trim();
    renderCveTable(
      (window.__lastCves || []).filter((c) =>
        c.cve_id.toLowerCase().includes(state.search.toLowerCase())
      )
    );
  }, 200);
});

document.getElementById("prevPage").addEventListener("click", () => {
  if (state.page > 0) { state.page--; loadAll(); }
});
document.getElementById("nextPage").addEventListener("click", () => {
  state.page++;
  loadAll();
});

document.getElementById("modalClose").addEventListener("click", () => {
  document.getElementById("cveModal").classList.add("hidden");
});
document.getElementById("cveModal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget)
    document.getElementById("cveModal").classList.add("hidden");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape")
    document.getElementById("cveModal").classList.add("hidden");
});

/* ── Auto-refresh every 5 minutes ────────────────────────────────────────── */
setInterval(loadAll, 5 * 60 * 1000);

/* ── Boot ─────────────────────────────────────────────────────────────────── */
loadAll();
