// app.js — widgetul de scanare (polling /scan/status) și tooltip-ul
// graficului de disc din fișa stației. Fără framework, cod simplu.
(function () {
  "use strict";

  var form = document.getElementById("scan-form");
  var startBtn = document.getElementById("scan-start-btn");
  var stopBtn = document.getElementById("scan-stop-btn");
  var progressBox = document.getElementById("scan-progress");
  var progressFill = document.getElementById("scan-progress-fill");
  var progressText = document.getElementById("scan-progress-text");
  var errorBox = document.getElementById("scan-error");

  var pollTimer = null;
  var wasRunning = false;

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }
  function clearError() {
    errorBox.hidden = true;
    errorBox.textContent = "";
  }

  function renderStatus(state) {
    if (state.running) {
      startBtn.hidden = true;
      stopBtn.hidden = false;
      progressBox.hidden = false;
      var pct = state.total > 0 ? Math.round((state.done / state.total) * 100) : 0;
      progressFill.style.width = pct + "%";
      var hostPart = state.current_host ? " — " + state.current_host : "";
      progressText.textContent = state.done + "/" + state.total + hostPart + " (" + state.elapsed_sec + "s)";
    } else {
      startBtn.hidden = false;
      stopBtn.hidden = true;
      progressBox.hidden = true;
    }

    if (wasRunning && !state.running) {
      // Scanarea tocmai s-a terminat — reîncărcăm pagina curentă ca datele
      // proaspăt ingerate să apară fără o acțiune manuală a utilizatorului.
      window.location.reload();
      return;
    }
    wasRunning = state.running;
  }

  function poll() {
    fetch("/scan/status")
      .then(function (r) { return r.json(); })
      .then(renderStatus)
      .catch(function () { /* pauză de rețea trecătoare — reîncercăm la următorul tick */ });
  }

  function startPolling() {
    if (pollTimer) return;
    poll();
    pollTimer = setInterval(poll, 1500);
  }

  if (form) {
    form.addEventListener("submit", function (evt) {
      evt.preventDefault();
      clearError();
      var level = document.getElementById("scan-level").value;
      var ouBase = document.getElementById("scan-ou").value.trim();
      fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ level: parseInt(level, 10), ou_base: ouBase }),
      })
        .then(function (r) {
          return r.json().then(function (data) { return { ok: r.ok, data: data }; });
        })
        .then(function (result) {
          if (!result.ok) {
            showError(result.data.error || "Nu s-a putut porni scanarea.");
            return;
          }
          wasRunning = true;
          startPolling();
        })
        .catch(function () { showError("Eroare de rețea la pornirea scanării."); });
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", function () {
      fetch("/scan/stop", { method: "POST" }).then(poll);
    });
  }

  // Polling permanent (nu doar după submit): dacă utilizatorul reîncarcă
  // pagina în timpul unei scanări pornite anterior, widgetul trebuie să
  // reflecte starea reală, nu să pretindă că nimic nu rulează.
  startPolling();

  // ---------------------------------------------------------------------
  // Tooltip pentru graficul de disc (fișa stației)
  // ---------------------------------------------------------------------
  var tooltip = document.getElementById("chart-tooltip");
  if (tooltip) {
    var dots = document.querySelectorAll(".chart-dot");
    var chartWrap = tooltip.parentElement;

    function showTooltip(dot) {
      var date = dot.getAttribute("data-date");
      var pct = dot.getAttribute("data-pct");
      tooltip.textContent = date + " — " + pct;
      var wrapRect = chartWrap.getBoundingClientRect();
      var dotRect = dot.getBoundingClientRect();
      tooltip.style.left = (dotRect.left - wrapRect.left + dotRect.width / 2) + "px";
      tooltip.style.top = (dotRect.top - wrapRect.top) + "px";
      tooltip.hidden = false;
    }
    function hideTooltip() {
      tooltip.hidden = true;
    }

    dots.forEach(function (dot) {
      dot.addEventListener("mouseenter", function () { showTooltip(dot); });
      dot.addEventListener("mouseleave", hideTooltip);
      dot.addEventListener("focus", function () { showTooltip(dot); });
      dot.addEventListener("blur", hideTooltip);
    });
  }
})();
