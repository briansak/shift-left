(function () {
  "use strict";

  function requiresRationale(status) {
    return status === "false_positive" || status === "accepted_risk";
  }

  document.querySelectorAll("[data-status-form]").forEach(function (form) {
    var select = form.querySelector("[name=status]");
    var rationale = form.querySelector("[name=rationale]");
    if (!select || !rationale) return;
    function sync() {
      var needed = requiresRationale(select.value);
      rationale.required = needed;
      rationale.setAttribute("aria-required", needed ? "true" : "false");
    }
    select.addEventListener("change", sync);
    sync();
    form.addEventListener("submit", function (event) {
      if (requiresRationale(select.value) && !rationale.value.trim()) {
        event.preventDefault();
        rationale.focus();
      }
    });
  });
})();

(function () {
  "use strict";

  var dataNode = document.getElementById("cwe-dictionary-data");
  if (!dataNode) return;

  var dictionary = {};
  try {
    dictionary = JSON.parse(dataNode.textContent || "{}");
  } catch (_err) {
    dictionary = {};
  }

  var popover = document.createElement("div");
  popover.className = "cwe-popover";
  popover.setAttribute("role", "dialog");
  popover.setAttribute("aria-modal", "false");
  popover.hidden = true;
  document.body.appendChild(popover);

  function esc(text) {
    var node = document.createElement("span");
    node.textContent = text == null ? "" : String(text);
    return node.innerHTML;
  }

  var activeTrigger = null;
  var hoverOpen = false;
  var focusOpen = false;

  function popoverIdFor(cweId) {
    return "cwe-popover-" + cweId.replace(/[^A-Za-z0-9_-]/g, "-");
  }

  function renderPopover(cweId, trigger) {
    var entry = dictionary[cweId];
    var popoverDomId = popoverIdFor(cweId);
    popover.id = popoverDomId;
    var unrecognized =
      trigger && trigger.getAttribute("data-cwe-unrecognized") === "true";
    if (!entry) {
      var body =
        '<p class="cwe-popover-id">' +
        esc(cweId) +
        '</p><p class="cwe-popover-description">No local description available</p>';
      if (unrecognized) {
        body +=
          '<p class="cwe-popover-unrecognized">Unrecognized identifier — asserted by model, not in local CWE dictionary</p>';
      }
      popover.innerHTML = body;
      return popoverDomId;
    }
    var abstraction = entry.abstraction
      ? '<span class="cwe-popover-abstraction">' + esc(entry.abstraction) + "</span>"
      : "";
    var url = entry.url
      ? '<span class="cwe-popover-url">' + esc(entry.url) + "</span>"
      : "";
    popover.innerHTML =
      '<p class="cwe-popover-id">' +
      esc(entry.id) +
      '</p><p class="cwe-popover-name">' +
      esc(entry.name) +
      "</p>" +
      abstraction +
      '<p class="cwe-popover-description">' +
      esc(entry.short_description) +
      '</p><p class="cwe-popover-source">Source: MITRE CWE' +
      url +
      "</p>";
    return popoverDomId;
  }

  function positionPopover(trigger) {
    var rect = trigger.getBoundingClientRect();
    var margin = 8;
    popover.hidden = false;
    popover.style.visibility = "hidden";
    popover.style.left = "0px";
    popover.style.top = "0px";
    var popRect = popover.getBoundingClientRect();
    var left = rect.left + rect.width / 2 - popRect.width / 2;
    left = Math.max(margin, Math.min(left, window.innerWidth - popRect.width - margin));
    var top = rect.top - popRect.height - margin;
    if (top < margin) {
      top = rect.bottom + margin;
    }
    popover.style.left = Math.round(left) + "px";
    popover.style.top = Math.round(top) + "px";
    popover.style.visibility = "visible";
  }

  function openPopover(trigger) {
    var cweId = trigger.getAttribute("data-cwe-id");
    if (!cweId) return;
    activeTrigger = trigger;
    var popoverDomId = renderPopover(cweId, trigger);
    trigger.setAttribute("aria-describedby", popoverDomId);
    trigger.setAttribute("aria-expanded", "true");
    positionPopover(trigger);
    popover.hidden = false;
  }

  function closePopover() {
    if (activeTrigger) {
      activeTrigger.setAttribute("aria-expanded", "false");
      activeTrigger.removeAttribute("aria-describedby");
    }
    activeTrigger = null;
    hoverOpen = false;
    focusOpen = false;
    popover.hidden = true;
  }

  function shouldStayOpen() {
    return hoverOpen || focusOpen;
  }

  document.querySelectorAll(".cwe-ref-trigger").forEach(function (trigger) {
    trigger.addEventListener("mouseenter", function () {
      hoverOpen = true;
      openPopover(trigger);
    });
    trigger.addEventListener("mouseleave", function () {
      hoverOpen = false;
      if (!shouldStayOpen()) {
        closePopover();
      }
    });
    trigger.addEventListener("focus", function () {
      focusOpen = true;
      openPopover(trigger);
    });
    trigger.addEventListener("blur", function () {
      focusOpen = false;
      window.setTimeout(function () {
        if (!shouldStayOpen() && !popover.contains(document.activeElement)) {
          closePopover();
        }
      }, 0);
    });
    trigger.addEventListener("click", function (event) {
      event.preventDefault();
      if (activeTrigger === trigger && !popover.hidden) {
        closePopover();
        return;
      }
      focusOpen = true;
      openPopover(trigger);
    });
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closePopover();
    }
  });

  document.addEventListener("mousedown", function (event) {
    if (popover.hidden) return;
    var target = event.target;
    if (!(target instanceof Node)) return;
    if (popover.contains(target)) return;
    if (activeTrigger && activeTrigger.contains(target)) return;
    closePopover();
  });

  window.addEventListener(
    "scroll",
    function () {
      if (!activeTrigger || popover.hidden) return;
      positionPopover(activeTrigger);
    },
    true
  );
  window.addEventListener("resize", function () {
    if (!activeTrigger || popover.hidden) return;
    positionPopover(activeTrigger);
  });
})();

(function () {
  "use strict";

  var busy = document.getElementById("system-lifecycle-busy");
  var busyLabel = busy ? busy.querySelector("[data-lifecycle-busy-label]") : null;
  var forms = document.querySelectorAll("[data-system-lifecycle-form]");
  if (!forms.length) return;

  var PENDING_KEY = "shift-left:system-lifecycle-pending";

  function clearBusyState() {
    if (busy) busy.hidden = true;
    forms.forEach(function (form) {
      form.querySelectorAll("[data-lifecycle-submit]").forEach(function (button) {
        button.disabled = false;
        button.removeAttribute("aria-busy");
        if (button.dataset.lifecycleOriginal) {
          button.textContent = button.dataset.lifecycleOriginal;
          delete button.dataset.lifecycleOriginal;
        }
      });
    });
    var refreshBtn = document.querySelector(".system-page-header button[type='submit']");
    if (refreshBtn) refreshBtn.disabled = false;
  }

  function initLifecycleUi() {
    try {
      sessionStorage.removeItem(PENDING_KEY);
    } catch (e) {
      /* ignore */
    }
    clearBusyState();
  }

  function setBusy(message) {
    if (!busy) return;
    busy.hidden = false;
    if (busyLabel) busyLabel.textContent = message;
  }

  function disableLifecycleControls(exceptForm) {
    forms.forEach(function (form) {
      var isActive = form === exceptForm;
      form.querySelectorAll("[data-lifecycle-submit]").forEach(function (button) {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        if (isActive) {
          button.dataset.lifecycleOriginal = button.textContent || "";
          button.textContent = "Starting…";
        }
      });
    });
    var refreshBtn = document.querySelector(".system-page-header button[type='submit']");
    if (refreshBtn) refreshBtn.disabled = true;
  }

  initLifecycleUi();
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) initLifecycleUi();
  });

  forms.forEach(function (form) {
    form.addEventListener("submit", function () {
      try {
        sessionStorage.setItem(PENDING_KEY, "1");
      } catch (e) {
        /* ignore */
      }
      var service = form.getAttribute("data-service") || "service";
      var action = form.getAttribute("data-action") || "start";
      var message = action === "start" && service.indexOf("all") !== -1
        ? "Starting all prerequisites in dependency order…"
        : action.charAt(0).toUpperCase() + action.slice(1) + " " + service + "…";
      setBusy(message);
      disableLifecycleControls(form);
    });
  });
})();

(function () {
  var openBtn = document.querySelector("[data-investigation-trace-open]");
  var closeBtn = document.querySelector("[data-investigation-trace-close]");
  var drawer = document.getElementById("investigation-trace-drawer");
  if (!openBtn || !drawer) return;

  var body = drawer.querySelector("[data-investigation-trace-body]");
  var fetchUrl = openBtn.getAttribute("data-investigation-trace-fetch");
  var loaded = false;
  var loading = false;

  function openDrawer() {
    drawer.removeAttribute("hidden");
    drawer.classList.add("is-open");
    openBtn.setAttribute("aria-expanded", "true");
    if (!fetchUrl || loaded || loading || !body) return;
    loading = true;
    body.innerHTML = "<p class=\"helper\">Loading trace…</p>";
    fetch(fetchUrl, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("trace fetch failed");
        return response.text();
      })
      .then(function (html) {
        body.innerHTML = html;
        loaded = true;
      })
      .catch(function () {
        body.innerHTML = "<p class=\"helper\">Failed to load trace. Try the full trace page.</p>";
      })
      .finally(function () {
        loading = false;
      });
  }

  function closeDrawer() {
    drawer.classList.remove("is-open");
    drawer.setAttribute("hidden", "");
    openBtn.setAttribute("aria-expanded", "false");
  }

  openBtn.addEventListener("click", openDrawer);
  if (closeBtn) closeBtn.addEventListener("click", closeDrawer);
})();

