(function () {
  "use strict";

  var form = document.querySelector("[data-investigation-launch='true']");
  if (!form) return;

  var median = Number(form.getAttribute("data-median-seconds") || "62");
  var confirmThreshold = Number(form.getAttribute("data-confirm-threshold") || "10");

  function selectedSource() {
    var input = form.querySelector("[name=source]:checked");
    return input ? input.value : "single";
  }

  function panelVisible(panel) {
    var source = selectedSource();
    var kind = panel.getAttribute("data-launch-panel");
    if (kind === "single") return source === "single";
    if (kind === "custom") return source === "custom";
    if (kind === "preview") return source === "top25" || source === "profiled";
    return false;
  }

  function syncPanels() {
    var source = selectedSource();
    form.querySelectorAll("[data-launch-panel]").forEach(function (panel) {
      var on = panelVisible(panel);
      panel.querySelectorAll("input, textarea, select, button").forEach(function (el) {
        el.disabled = !on;
      });
    });
    var previewButton = form.querySelector("[data-launch-preview-button]");
    if (previewButton) {
      previewButton.hidden = source === "single";
      previewButton.disabled = source === "single";
    }
    var queueButton = form.querySelector("[data-launch-queue-button]");
    if (queueButton) {
      queueButton.textContent =
        source === "single" ? "Queue investigation" : "Queue batch";
    }
    var baseRef = form.querySelector("[data-launch-base-ref]");
    var scope = form.querySelector("[name=snapshot_scope]:checked");
    if (baseRef) {
      baseRef.hidden = !scope || scope.value !== "pr_changed";
    }
    syncEstimates();
  }

  function selectedMemberCount() {
    var source = selectedSource();
    if (source === "single") return 1;
    var selector =
      source === "custom"
        ? "[data-catalog-cwe]:checked:not(:disabled)"
        : "[data-launch-member]:checked:not(:disabled)";
    return form.querySelectorAll(selector).length;
  }

  function formatWallClock(count) {
    if (count <= 0) return "—";
    var total = count * median;
    if (total < 60) {
      return "~" + total + "s sequential (" + median + "s median × " + count + ")";
    }
    return "~" + Math.floor(total / 60) + " min sequential (" + median + "s median × " + count + ")";
  }

  function syncEstimates() {
    var count = selectedMemberCount();
    var clock = form.querySelector("[data-launch-wall-clock]");
    if (clock) clock.textContent = formatWallClock(count);
    var confirm = form.querySelector("[data-launch-confirm]");
    if (confirm) {
      var show = selectedSource() !== "single" && count > confirmThreshold;
      confirm.hidden = !show;
    }
  }

  function filterCatalog() {
    var search = form.querySelector("[data-catalog-search]");
    if (!search) return;
    var query = search.value.trim().toLowerCase();
    form.querySelectorAll("[data-catalog-picker] .investigation-catalog-row").forEach(function (row) {
      if (!query) {
        row.hidden = false;
        return;
      }
      var hay =
        (row.getAttribute("data-cwe-id") || "").toLowerCase() +
        " " +
        (row.getAttribute("data-cwe-name") || "").toLowerCase();
      row.hidden = hay.indexOf(query) === -1;
    });
  }

  form.querySelectorAll("[name=source], [name=snapshot_scope]").forEach(function (input) {
    input.addEventListener("change", syncPanels);
  });
  form.addEventListener("change", function (event) {
    if (
      event.target &&
      (event.target.getAttribute("data-launch-member") !== null ||
        event.target.getAttribute("data-catalog-cwe") !== null)
    ) {
      syncEstimates();
    }
  });
  var search = form.querySelector("[data-catalog-search]");
  if (search) search.addEventListener("input", filterCatalog);

  syncPanels();
  filterCatalog();
})();
