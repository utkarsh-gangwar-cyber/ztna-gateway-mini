/* ==========================================================================
   dashboard.js - Charts and live updates for the main dashboard.

   Flow:
     1. Read the initial data embedded in the page (#dashboard-data).
     2. Draw three Chart.js charts and fill the lists/tables.
     3. Every 10 seconds (or on "Refresh now") call /api/dashboard-stats and
        update everything without reloading the page.

   Server text (usernames, reasons...) is inserted with textContent only.
   ========================================================================== */
(function () {
  "use strict";

  const dataElement = document.getElementById("dashboard-data");
  if (!dataElement) return;
  if (!window.Chart) {
    window.showToast("Chart.js could not be loaded. Check your internet connection.", "danger");
    return;
  }

  const REFRESH_MS = 10000;
  const COLORS = {
    granted: "#22c55e", denied: "#ef4444", warning: "#f59e0b",
    placeholder: "#243049", grid: "rgba(148, 163, 184, 0.12)", text: "#9fb0c7",
  };
  const SEVERITY_ICONS = { info: "info", warning: "alert-triangle", critical: "shield-alert" };

  Chart.defaults.color = COLORS.text;
  Chart.defaults.borderColor = COLORS.grid;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

  // ------------------------------------------------------------ DOM helper
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;      // textContent = XSS-safe
    return node;
  }

  // "2026-11-19 08:30:15" -> "11-19 08:30"
  function formatTime(timestamp) {
    return timestamp ? String(timestamp).slice(5, 16) : "";
  }

  // ------------------------------------------------------------ Charts
  const activityChart = new Chart(document.getElementById("activityChart"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "Granted", data: [], borderColor: COLORS.granted, backgroundColor: "rgba(34, 197, 94, 0.15)",
          fill: true, tension: 0.35, pointRadius: 3 },
        { label: "Denied", data: [], borderColor: COLORS.denied, backgroundColor: "rgba(239, 68, 68, 0.15)",
          fill: true, tension: 0.35, pointRadius: 3 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { usePointStyle: true } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } },
    },
  });

  function createDoughnut(canvasId) {
    return new Chart(document.getElementById(canvasId), {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { position: "bottom", labels: { usePointStyle: true } } },
      },
    });
  }
  const outcomeChart = createDoughnut("outcomeChart");
  const trustChart = createDoughnut("trustChart");

  // Show a grey "No data yet" ring when every value is zero.
  function setDoughnut(chart, labels, values, colors) {
    const empty = values.every((value) => value === 0);
    chart.data.labels = empty ? ["No data yet"] : labels;
    chart.data.datasets[0].data = empty ? [1] : values;
    chart.data.datasets[0].backgroundColor = empty ? [COLORS.placeholder] : colors;
    chart.options.plugins.tooltip = { enabled: !empty };
    chart.update();
  }

  // ------------------------------------------------------------ Renderers
  function renderStats(stats) {
    document.querySelectorAll("[data-stat]").forEach((node) => {
      const value = stats[node.dataset.stat];
      if (value !== undefined) node.textContent = value;
    });
    const total = stats.total_requests || 0;
    document.querySelectorAll("[data-rate]").forEach((node) => {
      const count = stats[node.dataset.rate] || 0;
      node.textContent = total ? Math.round((count / total) * 100) + "% of requests" : "";
    });
  }

  function renderCharts(payload) {
    const activity = payload.activity || [];
    activityChart.data.labels = activity.map((day) => day.date.slice(5));
    activityChart.data.datasets[0].data = activity.map((day) => day.granted);
    activityChart.data.datasets[1].data = activity.map((day) => day.denied);
    activityChart.update();

    setDoughnut(outcomeChart, ["Granted", "Denied"],
      [payload.stats.granted, payload.stats.denied], [COLORS.granted, COLORS.denied]);

    const trust = payload.device_trust;
    setDoughnut(trustChart, ["Trusted", "At risk", "Untrusted"],
      [trust.trusted, trust.at_risk, trust.untrusted], [COLORS.granted, COLORS.warning, COLORS.denied]);
    document.querySelectorAll("[data-trust]").forEach((node) => {
      node.textContent = trust[node.dataset.trust];
    });
  }

  function buildEventItem(event) {
    const severity = SEVERITY_ICONS[event.severity] ? event.severity : "info";
    const item = el("div", "event-item sev-" + severity);

    const icon = el("div", "event-icon");
    const iconTag = document.createElement("i");
    iconTag.setAttribute("data-lucide", SEVERITY_ICONS[severity]);
    icon.appendChild(iconTag);

    const body = el("div", "event-body");
    body.appendChild(el("div", "event-title", String(event.event_type || "").replace(/_/g, " ").toLowerCase()));
    body.appendChild(el("div", "event-detail", event.details || ""));
    const meta = [event.username || "system"];
    if (event.resource_name) meta.push(event.resource_name);
    if (event.decision) meta.push(event.decision === "GRANTED" ? "Granted" : "Denied");
    meta.push(formatTime(event.timestamp));
    body.appendChild(el("div", "event-meta", meta.join(" · ")));

    item.append(icon, body);
    return item;
  }

  function renderEvents(events) {
    const list = document.getElementById("eventsList");
    list.replaceChildren();
    if (!events.length) { list.appendChild(el("div", "empty-state", "No security events yet.")); return; }
    events.forEach((event) => list.appendChild(buildEventItem(event)));
  }

  function buildRequestRow(entry) {
    const row = document.createElement("tr");

    const timeCell = el("td", "text-nowrap text-muted", formatTime(entry.timestamp));
    timeCell.title = entry.timestamp + " UTC";
    row.appendChild(timeCell);

    row.appendChild(el("td", "fw-semibold", entry.username));

    const roleCell = document.createElement("td");
    roleCell.appendChild(entry.role ? el("span", "badge-ztna role", entry.role) : el("span", "text-muted", "-"));
    row.appendChild(roleCell);

    row.appendChild(el("td", "", entry.resource_name));

    const granted = entry.decision === "GRANTED";
    const decisionCell = document.createElement("td");
    decisionCell.appendChild(el("span", "badge-ztna " + (granted ? "granted" : "denied"), granted ? "Granted" : "Denied"));
    row.appendChild(decisionCell);

    const reasonCell = el("td", "cell-reason", entry.reason);
    reasonCell.title = entry.reason;
    row.appendChild(reasonCell);
    return row;
  }

  function renderRequests(requests) {
    const body = document.getElementById("requestsBody");
    body.replaceChildren();
    if (!requests.length) {
      const row = document.createElement("tr");
      const cell = el("td", "empty-state", "No access requests yet. Open the Security Lab to generate some.");
      cell.colSpan = 6;
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    requests.forEach((entry) => body.appendChild(buildRequestRow(entry)));
  }

  function renderAll(payload) {
    renderStats(payload.stats);
    renderCharts(payload);
    renderEvents(payload.recent_events || []);
    renderRequests(payload.recent_requests || []);
    document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    window.refreshIcons();         // draw the icons that were just created
  }

  // ------------------------------------------------------------ Live refresh
  const refreshButton = document.getElementById("refreshBtn");

  async function refresh(manual) {
    const fresh = await window.api("/api/dashboard-stats");
    if (!fresh || !fresh.stats) return;          // network error or session ended (api() already warned)
    renderAll(fresh);
    if (manual) window.showToast("Dashboard refreshed.", "success");
  }

  refreshButton.addEventListener("click", async () => {
    refreshButton.disabled = true;
    await refresh(true);
    refreshButton.disabled = false;
  });

  // Draw the initial data immediately, then poll (paused while the tab is hidden).
  renderAll(JSON.parse(dataElement.textContent));
  setInterval(() => { if (!document.hidden) refresh(false); }, REFRESH_MS);
})();