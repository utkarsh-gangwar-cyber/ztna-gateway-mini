/* ==========================================================================
   admin-pages.js - Small helpers shared by the Users, Policies and Devices pages.

     showModal(el)                   open a Bootstrap modal
     hideModal(el) -> Promise        close a modal and wait until it is fully gone
                                     (Bootstrap cannot show two modals at once, so we
                                      close the edit modal BEFORE opening the confirm dialog)
     postAction(url, data, opts)     POST JSON, show a toast with the server's message and,
                                     on success, reload the page so the tables are fresh.
                                     opts: { reload: true, delay: 1200 }

   Relies on app.js (api, showToast).
   ========================================================================== */
(function () {
  "use strict";

  window.showModal = function (modalEl) {
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
  };

  window.hideModal = function (modalEl) {
    return new Promise((resolve) => {
      if (!modalEl.classList.contains("show")) { resolve(); return; }
      modalEl.addEventListener("hidden.bs.modal", () => resolve(), { once: true });
      bootstrap.Modal.getOrCreateInstance(modalEl).hide();
    });
  };

  window.postAction = async function (url, payload, options) {
    const settings = Object.assign({ reload: true, delay: 1200 }, options || {});
    const result = await window.api(url, "POST", payload || {});

    // api() already showed a message for "session ended" (401) and "network error" (0).
    if (result.status === 401 || result.status === 0) return result;

    window.showToast(result.message || (result.ok ? "Done." : "Action failed."),
                     result.ok ? "success" : "danger");
    if (result.ok && settings.reload) {
      setTimeout(() => window.location.reload(), settings.delay);
    }
    return result;
  };
})();