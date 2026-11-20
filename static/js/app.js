/* ==========================================================================
   app.js - Shared UI behaviour used on every page.

   Provides (as window.* functions so page scripts can use them):
     showToast(message, type)      toast notifications (success/danger/warning/info)
     confirmAction({...})          confirmation dialog -> Promise<true|false>
     api(url, method, payload)     fetch helper that adds the CSRF header
     escapeHtml(text)              escape text before putting it into HTML
     refreshIcons()                (re)draw Lucide icons after the DOM changes

   Automatic behaviours:
     - Flask flash messages become toasts
     - <form data-confirm="..."> asks for confirmation before submitting
     - Searchable / filterable tables (data-table-search, data-table-filter)
     - Mobile sidebar toggle, session countdown, show/hide password, demo-account fill

   SECURITY NOTE: text coming from the server or the database (usernames, log
   reasons...) is only ever inserted with textContent, never innerHTML, so a
   malicious value such as "<script>" cannot execute.
   ========================================================================== */
(function () {
  "use strict";

  const docBody = document.body;
  const csrfToken = docBody.dataset.csrf || "";

  // ---------------------------------------------------------------- Icons
  window.refreshIcons = function () {
    if (window.lucide) window.lucide.createIcons();
  };

  // ------------------------------------------------------------ Escaping
  window.escapeHtml = function (value) {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, (ch) => map[ch]);
  };

  // --------------------------------------------------------------- Toasts
  const TOAST_ICONS = { success: "check-circle", danger: "x-circle", warning: "alert-triangle", info: "info" };

  window.showToast = function (message, type) {
    const container = document.getElementById("toastContainer");
    if (!container || !window.bootstrap) return;
    const kind = TOAST_ICONS[type] ? type : "info";

    const toastEl = document.createElement("div");
    toastEl.className = "toast ztna-toast ztna-toast-" + kind;
    toastEl.setAttribute("role", "alert");
    toastEl.innerHTML =
      '<div class="d-flex align-items-start gap-2 p-3">' +
      '<i data-lucide="' + TOAST_ICONS[kind] + '"></i>' +
      '<div class="toast-message flex-grow-1"></div>' +
      '<button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast" aria-label="Close"></button>' +
      "</div>";
    toastEl.querySelector(".toast-message").textContent = message;   // textContent = safe

    container.appendChild(toastEl);
    window.refreshIcons();
    toastEl.addEventListener("hidden.bs.toast", () => toastEl.remove());
    new bootstrap.Toast(toastEl, { delay: kind === "danger" ? 7000 : 4500 }).show();
  };

  function showFlashMessages() {
    const holder = document.getElementById("flash-data");
    if (!holder) return;
    try {
      JSON.parse(holder.textContent).forEach((pair) => window.showToast(pair[1], pair[0]));
    } catch (error) {
      /* ignore malformed flash data */
    }
  }

  // ---------------------------------------------------- Confirmation dialog
  window.confirmAction = function (options) {
    const settings = Object.assign(
      { title: "Please confirm", message: "Are you sure?", confirmText: "Confirm", danger: false },
      options || {}
    );
    return new Promise((resolve) => {
      const modalEl = document.getElementById("confirmModal");
      const okButton = document.getElementById("confirmOk");
      if (!modalEl || !window.bootstrap) { resolve(window.confirm(settings.message)); return; }

      document.getElementById("confirmTitle").textContent = settings.title;
      document.getElementById("confirmMessage").textContent = settings.message;
      okButton.textContent = settings.confirmText;
      okButton.className = "btn " + (settings.danger ? "btn-danger" : "btn-primary");

      const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
      let confirmed = false;
      const onOk = () => { confirmed = true; modal.hide(); };
      const onHidden = () => {
        okButton.removeEventListener("click", onOk);
        modalEl.removeEventListener("hidden.bs.modal", onHidden);
        resolve(confirmed);
      };
      okButton.addEventListener("click", onOk);
      modalEl.addEventListener("hidden.bs.modal", onHidden);
      modal.show();
    });
  };

  // Any form with data-confirm="message" asks first, then submits normally.
  document.addEventListener("submit", async function (event) {
    const form = event.target;
    if (!form.matches || !form.matches("form[data-confirm]")) return;
    event.preventDefault();
    const confirmed = await window.confirmAction({
      title: form.dataset.confirmTitle || "Please confirm",
      message: form.dataset.confirm,
      confirmText: form.dataset.confirmButton || "Confirm",
      danger: form.dataset.confirmDanger === "true",
    });
    if (confirmed) form.submit();     // form.submit() does not re-trigger this handler
  });

  // ------------------------------------------------------------ API helper
  // Sends JSON, adds the CSRF header, and always returns an object with
  // {ok, message, status, ...}. A 401 (session ended) redirects to the login page.
  window.api = async function (url, method, payload) {
    const options = {
      method: method || "GET",
      headers: { "X-CSRF-Token": csrfToken, Accept: "application/json" },
    };
    if (payload !== undefined && payload !== null) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    }

    let response;
    try {
      response = await fetch(url, options);
    } catch (error) {
      window.showToast("Cannot reach the server. Is the app still running?", "danger");
      return { ok: false, message: "Network error", status: 0 };
    }

    let data;
    try { data = await response.json(); }
    catch (error) { data = { ok: false, message: "Unexpected server response." }; }
    data.status = response.status;

    if (response.status === 401) {
      window.showToast(data.message || "Session ended. Please log in again.", "warning");
      setTimeout(() => { window.location.href = docBody.dataset.loginUrl || "/login"; }, 1500);
    }
    return data;
  };

  // ------------------------------------------------- Searchable / filterable tables
  // Markup contract (used by later pages):
  //   <input  data-table-search="tableId">                    free-text search
  //   <select data-table-filter="tableId" data-column="3">    exact-match filter on column 3
  //   <span   data-table-count="tableId">                     shows the visible row count
  //   <tr data-no-results hidden>...</tr>                     "no matches" row inside <tbody>
  // A cell may carry data-value="..." to be matched instead of its visible text.
  function initTableFilters() {
    const tableIds = new Set();
    document.querySelectorAll("[data-table-search], [data-table-filter]").forEach((control) => {
      tableIds.add(control.dataset.tableSearch || control.dataset.tableFilter);
    });

    tableIds.forEach((tableId) => {
      const table = document.getElementById(tableId);
      if (!table) return;
      const searchBox = document.querySelector('[data-table-search="' + tableId + '"]');
      const selects = Array.from(document.querySelectorAll('[data-table-filter="' + tableId + '"]'));
      const counter = document.querySelector('[data-table-count="' + tableId + '"]');

      const applyFilters = () => {
        const needle = searchBox ? searchBox.value.trim().toLowerCase() : "";
        let visible = 0;

        table.querySelectorAll("tbody tr").forEach((row) => {
          if (row.hasAttribute("data-no-results")) return;
          let show = !needle || row.textContent.toLowerCase().includes(needle);

          selects.forEach((select) => {
            const wanted = select.value.trim().toLowerCase();
            if (!wanted) return;
            const cell = row.children[Number(select.dataset.column)];
            const cellValue = cell ? (cell.dataset.value !== undefined ? cell.dataset.value : cell.textContent) : "";
            if (cellValue.trim().toLowerCase() !== wanted) show = false;
          });

          row.hidden = !show;
          if (show) visible += 1;
        });

        if (counter) counter.textContent = visible;
        const noResults = table.querySelector("tr[data-no-results]");
        if (noResults) noResults.hidden = visible !== 0;
      };

      if (searchBox) searchBox.addEventListener("input", applyFilters);
      selects.forEach((select) => select.addEventListener("change", applyFilters));
      applyFilters();
    });
  }

  // ------------------------------------------------------------ Sidebar (mobile)
  function initSidebar() {
    const sidebar = document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    const toggle = document.getElementById("sidebarToggle");
    if (!sidebar || !toggle) return;
    const setOpen = (open) => {
      sidebar.classList.toggle("open", open);
      if (backdrop) backdrop.classList.toggle("show", open);
    };
    toggle.addEventListener("click", () => setOpen(!sidebar.classList.contains("open")));
    if (backdrop) backdrop.addEventListener("click", () => setOpen(false));
  }

  // ------------------------------------------------------------ Session countdown
  // Display only. The SERVER enforces expiry on every request.
  function initSessionTimer() {
    const expiresAt = Number(docBody.dataset.sessionExpires);
    const label = document.getElementById("sessionTimerText");
    const chip = document.getElementById("sessionChip");
    if (!expiresAt || !label) return;

    let warned = false;
    const pad = (n) => String(n).padStart(2, "0");

    const tick = () => {
      const remaining = Math.floor(expiresAt - Date.now() / 1000);
      if (remaining <= 0) {
        label.textContent = "00:00";
        window.showToast("Your access token has expired. Redirecting to login...", "warning");
        clearInterval(timer);
        setTimeout(() => { window.location.href = docBody.dataset.loginUrl || "/login"; }, 2000);
        return;
      }
      const hours = Math.floor(remaining / 3600);
      const minutes = Math.floor((remaining % 3600) / 60);
      const seconds = remaining % 60;
      label.textContent = (hours ? pad(hours) + ":" : "") + pad(minutes) + ":" + pad(seconds);

      if (remaining <= 120 && chip) chip.classList.add("expiring");
      if (remaining <= 60 && !warned) {
        warned = true;
        window.showToast("Your session expires in less than a minute.", "warning");
      }
    };
    const timer = setInterval(tick, 1000);
    tick();
  }

  // ------------------------------------------------------------ Login page helpers
  function initPasswordToggle() {
    document.querySelectorAll("[data-toggle-password]").forEach((button) => {
      button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.togglePassword);
        if (!input) return;
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        button.textContent = show ? "Hide" : "Show";
      });
    });
  }

  function initDemoFill() {
    document.querySelectorAll("[data-fill-username]").forEach((button) => {
      button.addEventListener("click", () => {
        const usernameInput = document.getElementById("username");
        const passwordInput = document.getElementById("password");
        if (usernameInput) usernameInput.value = button.dataset.fillUsername;
        if (passwordInput) { passwordInput.value = button.dataset.fillPassword; passwordInput.focus(); }
      });
    });
  }

  // ------------------------------------------------------------ Start-up
  document.addEventListener("DOMContentLoaded", function () {
    window.refreshIcons();
    showFlashMessages();
    initSidebar();
    initSessionTimer();
    initPasswordToggle();
    initDemoFill();
    initTableFilters();
  });
})();