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

  // ---------------------------------------------------------------------
  // Elevare: cont AD separat pentru scanare (§8) — ascuns implicit, pentru
  // cazul obișnuit când serverul rulează deja sub un cont cu drepturi.
  // ---------------------------------------------------------------------
  var elevateToggle = document.getElementById("elevate-toggle");
  var elevateFields = document.getElementById("elevate-fields");
  var adminUserInput = document.getElementById("scan-admin-user");
  var adminPassInput = document.getElementById("scan-admin-pass");

  if (elevateToggle && elevateFields) {
    elevateToggle.addEventListener("click", function (evt) {
      evt.stopPropagation();
      elevateFields.hidden = !elevateFields.hidden;
    });
    elevateFields.addEventListener("click", function (evt) { evt.stopPropagation(); });
    document.addEventListener("click", function () {
      elevateFields.hidden = true;
    });
  }

  if (form) {
    form.addEventListener("submit", function (evt) {
      evt.preventDefault();
      clearError();
      var level = document.getElementById("scan-level").value;
      var ouBase = document.getElementById("scan-ou").value.trim();
      var payload = { level: parseInt(level, 10), ou_base: ouBase };
      var adminUser = adminUserInput ? adminUserInput.value.trim() : "";
      var adminPass = adminPassInput ? adminPassInput.value : "";
      if (adminUser) {
        payload.admin_user = adminUser;
        payload.admin_pass = adminPass;
      }
      fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
        .then(function (r) {
          return r.json().then(function (data) { return { ok: r.ok, data: data }; });
        })
        .then(function (result) {
          // Parola nu rămâne în formular mai mult decât e nevoie, indiferent
          // de rezultat — o singură folosire, mereu retastată dacă mai e nevoie.
          if (adminPassInput) adminPassInput.value = "";
          if (!result.ok) {
            showError(result.data.error || "Nu s-a putut porni scanarea.");
            return;
          }
          wasRunning = true;
          startPolling();
        })
        .catch(function () {
          if (adminPassInput) adminPassInput.value = "";
          showError("Eroare de rețea la pornirea scanării.");
        });
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
  // Selector de OU (ruta /ous — rulează colectorul cu -ListOusOnly, doar
  // interogări AD, fără contact cu stațiile) — operatorul altfel ar trebui
  // să afle DN-ul corect manual din ADUC/PowerShell.
  // ---------------------------------------------------------------------
  var ouInput = document.getElementById("scan-ou");
  var ouToggle = document.getElementById("ou-picker-toggle");
  var ouPanel = document.getElementById("ou-picker-panel");
  var ouBreadcrumb = document.getElementById("ou-picker-breadcrumb");
  var ouCurrentCard = document.getElementById("ou-picker-current-card");
  var ouListBox = document.getElementById("ou-picker-list");
  var ouError = document.getElementById("ou-picker-error");

  if (ouToggle && ouPanel) {

    function ouTrail(dn) {
      // Reconstruiește lanțul de la rădăcina domeniului până la dn, ca
      // breadcrumb navigabil — mult mai clar decât un singur buton "Urcă",
      // pentru că arată dintr-o privire tot drumul, nu doar pasul următor.
      if (!dn) return [];
      var parts = dn.split(",");
      var dcStart = parts.length;
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].trim().indexOf("OU=") !== 0) { dcStart = i; break; }
      }
      var rootDn = parts.slice(dcStart).join(",");
      var ouSegs = parts.slice(0, dcStart).slice().reverse();
      var trail = [{ label: "Domeniu", dn: rootDn }];
      var cumulative = rootDn;
      ouSegs.forEach(function (seg) {
        cumulative = seg + "," + cumulative;
        trail.push({ label: seg.replace(/^OU=/, ""), dn: cumulative });
      });
      return trail;
    }

    function renderBreadcrumb(dn) {
      ouBreadcrumb.innerHTML = "";
      var trail = ouTrail(dn);
      trail.forEach(function (step, idx) {
        if (idx > 0) {
          var sep = document.createElement("span");
          sep.className = "ou-breadcrumb-sep";
          sep.textContent = "›";
          ouBreadcrumb.appendChild(sep);
        }
        var isLast = idx === trail.length - 1;
        if (isLast) {
          var current = document.createElement("span");
          current.className = "ou-breadcrumb-current";
          current.textContent = step.label;
          current.title = step.dn;
          ouBreadcrumb.appendChild(current);
        } else {
          var link = document.createElement("button");
          link.type = "button";
          link.className = "ou-breadcrumb-link";
          link.textContent = step.label;
          link.title = step.dn;
          link.addEventListener("click", function () { loadOus(step.dn); });
          ouBreadcrumb.appendChild(link);
        }
      });
    }

    function renderCurrentCard(dn, count) {
      ouCurrentCard.innerHTML = "";
      var info = document.createElement("span");
      info.className = "ou-current-info";
      info.innerHTML = (count === null || count === undefined ? "" : "<strong>" + count + " stații</strong> în ") +
        "acest OU";
      info.title = dn || "";

      var selectBtn = document.createElement("button");
      selectBtn.type = "button";
      selectBtn.className = "ou-current-select";
      selectBtn.textContent = "Selectează acest OU";
      selectBtn.addEventListener("click", function () {
        ouInput.value = dn;
        ouPanel.hidden = true;
      });

      ouCurrentCard.appendChild(info);
      ouCurrentCard.appendChild(selectBtn);
    }

    function renderChildren(children) {
      ouListBox.innerHTML = "";
      if (children.length === 0) {
        ouListBox.innerHTML = '<p class="empty-state">Niciun sub-OU aici.</p>';
        return;
      }
      var subHeading = document.createElement("p");
      subHeading.className = "ou-list-heading";
      subHeading.textContent = "Sub-OU-uri:";
      ouListBox.appendChild(subHeading);

      children.forEach(function (row) {
        var el = document.createElement("div");
        el.className = "ou-row";
        el.title = "Click pentru a intra în " + row.dn;

        var label = document.createElement("span");
        label.className = "ou-row-dn";
        // Doar ultimul segment (numele OU-ului), pentru lizibilitate — DN-ul
        // complet rămâne disponibil ca tooltip și e folosit intern la selecție.
        var shortName = (row.dn.match(/^OU=([^,]+)/) || [null, row.dn])[1];
        label.textContent = shortName;

        var count = document.createElement("span");
        count.className = "ou-row-count";
        count.textContent = row.count + " stații";

        var selectBtn = document.createElement("button");
        selectBtn.type = "button";
        selectBtn.className = "btn-secondary ou-row-select";
        selectBtn.textContent = "Selectează";
        selectBtn.addEventListener("click", function (evt) {
          evt.stopPropagation();
          ouInput.value = row.dn;
          ouPanel.hidden = true;
        });

        el.appendChild(label);
        el.appendChild(count);
        el.appendChild(selectBtn);
        // Click oriunde pe rând (în afara butonului Selectează) = intră în acel OU.
        el.addEventListener("click", function () { loadOus(row.dn); });

        ouListBox.appendChild(el);
      });
    }

    function loadOus(baseDn) {
      ouError.hidden = true;
      ouCurrentCard.innerHTML = "";
      ouListBox.innerHTML = '<p class="empty-state">Se încarcă…</p>';
      var url = "/ous" + (baseDn ? "?ou_base=" + encodeURIComponent(baseDn) : "");
      fetch(url)
        .then(function (r) { return r.json().then(function (data) { return { ok: r.ok, data: data }; }); })
        .then(function (result) {
          if (!result.ok) {
            ouListBox.innerHTML = "";
            ouError.textContent = result.data.error || "Nu s-au putut încărca OU-urile.";
            ouError.hidden = false;
            return;
          }
          var rows = result.data.ous;
          // Primul rând întors de /ous e mereu OU-ul de bază însuși (§ colector,
          // Get-OuInventoryList) — restul sunt sub-OU-uri directe.
          var resolvedBase = rows.length > 0 ? rows[0].dn : baseDn;
          var resolvedCount = rows.length > 0 ? rows[0].count : null;
          renderBreadcrumb(resolvedBase);
          renderCurrentCard(resolvedBase, resolvedCount);
          renderChildren(rows.slice(1));
        })
        .catch(function () {
          ouListBox.innerHTML = "";
          ouError.textContent = "Eroare de rețea la interogarea AD.";
          ouError.hidden = false;
        });
    }

    ouToggle.addEventListener("click", function (evt) {
      evt.stopPropagation();
      var willOpen = ouPanel.hidden;
      ouPanel.hidden = !willOpen;
      if (willOpen) {
        // Pornim de la ce e deja scris în câmp (dacă operatorul a editat
        // manual un DN), altfel de la auto-detecția OU-ului curent.
        loadOus(ouInput.value.trim() || null);
      }
    });

    ouPanel.addEventListener("click", function (evt) { evt.stopPropagation(); });

    // Click oriunde în afara panoului îl închide.
    document.addEventListener("click", function () {
      ouPanel.hidden = true;
    });
  }

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

  // ---------------------------------------------------------------------
  // Mesaj către o stație (pagina /statii) — POST /statie/<nume>/mesaj,
  // care pornește msg.exe pe stație prin CIM/DCOM (vezi messenger.py).
  // Restricționat la 127.0.0.1 în webapp.py, ca la scanare.
  // ---------------------------------------------------------------------
  var msgBackdrop = document.getElementById("msg-modal-backdrop");

  if (msgBackdrop) {
    var msgHostLabel = document.getElementById("msg-modal-host");
    var msgText = document.getElementById("msg-modal-text");
    var msgError = document.getElementById("msg-modal-error");
    var msgSuccess = document.getElementById("msg-modal-success");
    var msgSendBtn = document.getElementById("msg-modal-send");
    var msgCancelBtn = document.getElementById("msg-modal-cancel");
    var msgAdminUser = document.getElementById("msg-admin-user");
    var msgAdminPass = document.getElementById("msg-admin-pass");
    var msgElevateToggle = document.getElementById("msg-elevate-toggle");
    var msgElevateFields = document.getElementById("msg-elevate-fields");
    var currentMsgHost = null;

    // Text implicit (§ cerință): pornește de la formularea standard cerută,
    // completată cu datele reale ale stației (ultima pornire, uptime, reboot
    // în așteptare) — rămâne complet editabil înainte de trimitere.
    function buildDefaultMessage(lastBoot, uptime, rebootLabel) {
      return "Mesaj din partea Administratorului de Active Directory.\n\n" +
        "Conform ultimei interogări de inventariere: ultima pornire a stației a fost la " +
        lastBoot + ", cu un uptime curent de " + uptime + " zile. Reboot în așteptare: " +
        rebootLabel + ".\n\n" +
        "Vă rugăm ca în perioada următoare să efectuați un Restart al stației dumneavoastră.\n\n" +
        "Vă rugăm să urmați această procedură atunci când aveți un interval de timp în care nu " +
        "este strict necesară utilizarea PC-ului.\n\n" +
        "Vă mulțumim pentru înțelegere.";
    }

    function closeMsgModal() {
      msgBackdrop.hidden = true;
    }

    document.querySelectorAll(".msg-open-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        currentMsgHost = btn.getAttribute("data-host");
        msgHostLabel.textContent = currentMsgHost;
        msgText.value = buildDefaultMessage(
          btn.getAttribute("data-last-boot"),
          btn.getAttribute("data-uptime"),
          btn.getAttribute("data-reboot")
        );
        msgError.hidden = true;
        msgSuccess.hidden = true;
        msgAdminUser.value = "";
        msgAdminPass.value = "";
        msgElevateFields.hidden = true;
        msgBackdrop.hidden = false;
      });
    });

    msgCancelBtn.addEventListener("click", closeMsgModal);
    msgBackdrop.addEventListener("click", function (evt) {
      if (evt.target === msgBackdrop) closeMsgModal();
    });
    msgElevateToggle.addEventListener("click", function (evt) {
      evt.stopPropagation();
      msgElevateFields.hidden = !msgElevateFields.hidden;
    });
    msgElevateFields.addEventListener("click", function (evt) { evt.stopPropagation(); });

    msgSendBtn.addEventListener("click", function () {
      msgError.hidden = true;
      msgSuccess.hidden = true;
      var payload = { message: msgText.value };
      var au = msgAdminUser.value.trim();
      if (au) {
        payload.admin_user = au;
        payload.admin_pass = msgAdminPass.value;
      }
      msgSendBtn.disabled = true;
      msgSendBtn.textContent = "Se trimite…";

      fetch("/statie/" + encodeURIComponent(currentMsgHost) + "/mesaj", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
        .then(function (r) {
          return r.json()
            .catch(function () { return { error: "Acțiunea merge doar de pe calculatorul cu serverul (127.0.0.1)." }; })
            .then(function (data) { return { ok: r.ok, data: data }; });
        })
        .then(function (result) {
          msgAdminPass.value = "";
          if (!result.ok) {
            msgError.textContent = result.data.error || "Trimiterea mesajului a eșuat.";
            msgError.hidden = false;
            return;
          }
          msgSuccess.textContent = "Mesaj trimis către " + currentMsgHost + ".";
          msgSuccess.hidden = false;
        })
        .catch(function () {
          msgAdminPass.value = "";
          msgError.textContent = "Eroare de rețea la trimiterea mesajului.";
          msgError.hidden = false;
        })
        .then(function () {
          msgSendBtn.disabled = false;
          msgSendBtn.textContent = "Trimite mesajul";
        });
    });
  }

  // ---------------------------------------------------------------------
  // Export .xlsx într-un folder ales de utilizator (pagina /export) —
  // File System Access API (Chrome/Edge) când e disponibilă; altfel cade pe
  // descărcarea obișnuită a browserului (folderul implicit de descărcări).
  // ---------------------------------------------------------------------
  var exportBtn = document.getElementById("export-xlsx-btn");
  var exportStatus = document.getElementById("export-status");

  if (exportBtn) {
    exportBtn.addEventListener("click", function () {
      exportStatus.hidden = true;
      var url = exportBtn.getAttribute("data-url");
      var originalText = exportBtn.textContent;
      exportBtn.disabled = true;
      exportBtn.textContent = "Se pregătește exportul…";

      fetch(url)
        .then(function (r) {
          if (!r.ok) throw new Error("Serverul a răspuns cu eroare (" + r.status + ").");
          return r.blob();
        })
        .then(function (blob) {
          var suggestedName = "inventar-" + new Date().toISOString().slice(0, 10) + ".xlsx";
          if (window.showSaveFilePicker) {
            return window.showSaveFilePicker({
              suggestedName: suggestedName,
              types: [{
                description: "Registru Excel",
                accept: { "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"] },
              }],
            }).then(function (handle) {
              return handle.createWritable().then(function (writable) {
                return writable.write(blob).then(function () { return writable.close(); });
              });
            });
          }
          // Fallback fără alegere de folder: descărcare obișnuită a browserului.
          var link = document.createElement("a");
          link.href = URL.createObjectURL(blob);
          link.download = suggestedName;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setTimeout(function () { URL.revokeObjectURL(link.href); }, 5000);
        })
        .catch(function (err) {
          // Renunțarea la dialogul de salvare (Anulează) nu e o eroare reală.
          if (err && err.name === "AbortError") return;
          exportStatus.textContent = "Exportul a eșuat: " + (err && err.message ? err.message : "eroare necunoscută.");
          exportStatus.hidden = false;
        })
        .then(function () {
          exportBtn.disabled = false;
          exportBtn.textContent = originalText;
        });
    });
  }
})();
