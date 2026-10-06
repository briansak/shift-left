/* Investigation list/detail live polling — targeted DOM updates only (no full reload). */
(function () {
  var root = document.querySelector('[data-investigation-live-poll="true"]');
  if (!root) return;

  var pollUrl = root.getAttribute("data-investigation-live-url");
  var intervalMs = parseInt(root.getAttribute("data-investigation-poll-interval") || "5000", 10);
  if (!pollUrl) return;
  if (!intervalMs || intervalMs < 1000) intervalMs = 5000;

  var timerId = null;

  function updateRunnerCard(runner) {
    var card = document.querySelector("[data-live-runner-card]");
    if (!card || !runner) return;
    card.classList.toggle("investigation-runner-card--warn", !!runner.show_warn);
    var pill = card.querySelector("[data-live-runner-worker-pill]");
    if (pill) {
      pill.className = "status-pill " + runner.status_pill_class;
      var workerLabel = pill.querySelector("[data-live-runner-worker-label]");
      if (workerLabel) workerLabel.textContent = runner.worker_label;
    }
    var warn = card.querySelector("[data-live-runner-warn]");
    if (warn) {
      if (runner.show_warn) {
        warn.removeAttribute("hidden");
        var warnMessage = warn.querySelector("[data-live-runner-warn-message]");
        if (warnMessage) warnMessage.textContent = runner.warn_message || "";
        var systemLink = warn.querySelector("[data-live-runner-system-href]");
        if (systemLink && runner.system_href) systemLink.setAttribute("href", runner.system_href);
      } else {
        warn.setAttribute("hidden", "");
      }
    }
    var queueDepth = card.querySelector("[data-live-runner-queue-depth]");
    if (queueDepth) queueDepth.textContent = String(runner.queue_depth);
    var current = card.querySelector("[data-live-runner-current]");
    if (current) {
      if (runner.current_investigation_id) {
        current.textContent =
          (runner.current_investigation_short || "") +
          " · " +
          (runner.current_elapsed_label || "—");
      } else {
        current.textContent = "—";
      }
    }
    var healthGate = card.querySelector("[data-live-runner-health-gate]");
    if (healthGate) healthGate.textContent = runner.health_gate_reason || "—";
  }

  function updateListRow(row) {
    var tr = document.querySelector(
      '[data-investigation-row-id="' + row.investigation_id + '"]'
    );
    if (!tr) return;
    var pill = tr.querySelector("[data-live-state-pill]");
    if (pill) {
      pill.className = "status-pill " + row.state_pill_class;
      var stateText = pill.querySelector("[data-live-state-text]");
      if (stateText) stateText.textContent = row.state;
    }
    var waiting = tr.querySelector("[data-live-waiting-reason]");
    if (waiting) {
      if (row.waiting_reason) {
        waiting.textContent = row.waiting_reason;
        waiting.removeAttribute("hidden");
      } else {
        waiting.textContent = "";
        waiting.setAttribute("hidden", "");
      }
    }
    var queueCalls = tr.querySelector("[data-live-row-queue-calls]");
    if (queueCalls) queueCalls.textContent = row.queue_or_calls_label;
    var duration = tr.querySelector("[data-live-row-duration]");
    if (duration) duration.textContent = row.duration_label;
  }

  function updateDetailState(data) {
    var pill = document.querySelector("[data-live-detail-state-pill]");
    if (pill) {
      pill.className = "status-pill " + data.state_pill_class;
      var stateText = pill.querySelector("[data-live-detail-state-text]");
      if (stateText) stateText.textContent = data.state;
    }
    var waiting = document.querySelector("[data-live-detail-waiting-reason]");
    if (waiting) {
      if (data.waiting_reason) {
        waiting.textContent = data.waiting_reason;
        waiting.removeAttribute("hidden");
      } else {
        waiting.textContent = "";
        waiting.setAttribute("hidden", "");
      }
    }
    var duration = document.querySelector("[data-live-detail-duration]");
    if (duration) duration.textContent = data.duration_label;
    var terminalCalls = document.querySelector("[data-live-detail-terminal-calls]");
    if (terminalCalls) terminalCalls.textContent = data.terminal_calls_label;
  }

  function applyLiveState(data) {
    if (data.runner) updateRunnerCard(data.runner);
    if (Array.isArray(data.rows)) {
      data.rows.forEach(updateListRow);
    }
    if (data.investigation_id) {
      updateDetailState(data);
    }
    if (!data.active && timerId !== null) {
      window.clearInterval(timerId);
      timerId = null;
    }
  }

  function pollOnce() {
    fetch(pollUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("live poll failed");
        return response.json();
      })
      .then(applyLiveState)
      .catch(function () {
        /* ignore transient poll errors */
      });
  }

  timerId = window.setInterval(pollOnce, intervalMs);
})();
