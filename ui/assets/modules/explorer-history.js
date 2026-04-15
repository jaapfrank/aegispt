import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  findingKey,
  formatDateTime,
  groupBy,
  renderTargetSummary,
  severityRank,
  statusPill,
} from "./shared.js";

function compareRuns(currentRunId, baselineRunId) {
  if (!currentRunId || !baselineRunId) return null;
  const currentRun = state.mission.runs.find((run) => run.id === currentRunId);
  const baselineRun = state.mission.runs.find((run) => run.id === baselineRunId);
  if (!currentRun || !baselineRun) return null;
  const currentFindings = state.mission.findingsByRun[currentRunId] || [];
  const baselineFindings = state.mission.findingsByRun[baselineRunId] || [];
  const baselineMap = new Map(baselineFindings.map((finding) => [findingKey(finding), finding]));
  const currentMap = new Map(currentFindings.map((finding) => [findingKey(finding), finding]));
  let worsenedCount = 0;
  currentFindings.forEach((finding) => {
    const prior = baselineMap.get(findingKey(finding));
    if (!prior) return;
    const currentRank = severityRank(finding.severity);
    const priorRank = severityRank(prior.severity);
    if (currentRank < priorRank) worsenedCount += 1;
  });
  const newCount = currentFindings.filter((finding) => !baselineMap.has(findingKey(finding))).length;
  const fixedCount = baselineFindings.filter((finding) => !currentMap.has(findingKey(finding))).length;
  const persistingCount = currentFindings.filter((finding) => baselineMap.has(findingKey(finding))).length;
  return {
    newCount,
    fixedCount,
    persistingCount,
    worsenedCount,
    packChanged:
      (currentRun.pack_binding?.pack_version || null) !==
      (baselineRun.pack_binding?.pack_version || null),
    baselineLabel: `${baselineRun.profile.name} ${formatDateTime(baselineRun.created_at)}`,
    summary: `Compared against ${baselineRun.profile.name}, this run introduced ${newCount} new findings and closed ${fixedCount}.`,
  };
}

function buildNextStepsQueue() {
  return (runtime.actions.selectedRunFindings?.() || [])
    .filter((finding) => !["resolved", "accepted_risk", "false_positive"].includes(finding.status))
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
    .slice(0, 8)
    .map((finding) => ({
      title: finding.title,
      status: finding.status,
      priority: finding.severity.toUpperCase(),
      action: `Review ${finding.finding_origin === "adaptive_pack" ? "adaptive" : "standard"} evidence and start remediation planning for ${finding.target_id}.`,
      retest:
        "Retest is needed after remediation with the same methodology references still attached.",
    }));
}

export function createExplorerHistoryModule() {
  function renderExplorer() {
    const groupedByCustomer = groupBy(
      state.engagements,
      (engagement) => engagement.client || "Unassigned Customer"
    );
    dom.customerIndex.innerHTML = Object.entries(groupedByCustomer).length
      ? Object.entries(groupedByCustomer)
          .map(
            ([customer, engagements]) => `
              <div class="list-card">
                <h4>${escapeHtml(customer)}</h4>
                <p>${escapeHtml(`${engagements.length} engagement dossiers`)}</p>
              </div>
            `
          )
          .join("")
      : emptyState("Customers will populate as engagements are created.");

    dom.engagementDossiers.innerHTML = state.engagements.length
      ? state.engagements
          .map((engagement) => {
            const runs =
              engagement.id === state.selectedEngagementId
                ? state.mission.runs
                : [];
            return `
              <div class="list-card ${engagement.id === state.selectedEngagementId ? "selected" : ""}" data-engagement-pick="${engagement.id}" data-testid="explorer-engagement-card">
                <h4>${escapeHtml(engagement.name)}</h4>
                <p>${escapeHtml(engagement.client || "No customer")}</p>
                <p class="micro-copy">${escapeHtml(`${runs.length} runs · ${engagement.status}`)}</p>
              </div>
            `;
          })
          .join("")
      : emptyState("No engagement dossiers exist yet.");
    dom.engagementDossiers.querySelectorAll("[data-engagement-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedEngagementId = item.dataset.engagementPick;
        await runtime.actions.refreshSelectedEngagement?.();
        state.activeScreen = "explorer";
        runtime.actions.renderScreens?.();
      });
    });

    const run = state.selectedRun;
    if (!run) {
      dom.runDossier.innerHTML = emptyState("Select a run to inspect its dossier.");
      return;
    }
    const config = run.configuration_json || {};
    const protectedSecrets = config.access?.secret_storage?.binding_count || 0;
    dom.runDossier.innerHTML = `
      <h4>${escapeHtml(run.profile.name)} <span class="badge">${escapeHtml(run.status)}</span></h4>
      <p>${escapeHtml(`Requested by ${run.requested_by} · created ${formatDateTime(run.created_at)}`)}</p>
      <div class="detail-grid split-top">
        <div class="detail-surface">
          <h4>Configuration</h4>
          <p>${escapeHtml(config.assessment_type || "Not recorded")}</p>
          <p class="micro-copy">${escapeHtml(renderTargetSummary(config.targets || {}))}</p>
        </div>
        <div class="detail-surface">
          <h4>Capability Pack</h4>
          <p>${escapeHtml(run.pack_binding?.pack_version || "Standard baseline")}</p>
          <p class="micro-copy">${escapeHtml(`Inventory ${run.source_inventory_snapshot_id || "n/a"}`)}</p>
        </div>
        <div class="detail-surface">
          <h4>Findings</h4>
          <p>${escapeHtml(`${run.findings.finding_count} total findings`)}</p>
          <p class="micro-copy">${escapeHtml(JSON.stringify(run.findings.findings_by_severity || {}))}</p>
        </div>
        <div class="detail-surface">
          <h4>Protected Access</h4>
          <p>${escapeHtml(`${protectedSecrets} secret binding${protectedSecrets === 1 ? "" : "s"}`)}</p>
          <p class="micro-copy">${escapeHtml(config.access?.secret_storage?.storage_backends?.join(", ") || "No protected bindings recorded")}</p>
        </div>
      </div>
      <div class="detail-surface split-top">
        <h4>Approvals & Decisions</h4>
        ${
          run.approvals.length
            ? run.approvals
                .map(
                  (approval) =>
                    `<p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.step_id)}</p>`
                )
                .join("")
            : "<p>No approval records on this run.</p>"
        }
      </div>
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
        <button class="action ghost" type="button" data-nav-screen="findings-theater">Open Findings</button>
        <button class="action ghost" type="button" data-nav-screen="report-center">Open Reports</button>
      </div>
    `;
  }

  function renderHistoryComparison() {
    dom.historyToolbar.innerHTML = `
      <label class="field compact">
        <span>Current Run</span>
        <select id="history-current-run" data-testid="history-current-run">
          ${state.mission.runs
            .map(
              (run) =>
                `<option value="${run.id}" ${run.id === state.selectedRunId ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Baseline Run</span>
        <select id="history-baseline-run">
          <option value="">No baseline</option>
          ${state.mission.runs
            .filter((run) => run.id !== state.selectedRunId)
            .map(
              (run) =>
                `<option value="${run.id}" ${run.id === state.comparisonBaselineRunId ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`
            )
            .join("")}
        </select>
      </label>
    `;
    document.getElementById("history-current-run")?.addEventListener("change", async (event) => {
      state.selectedRunId = event.target.value;
      await runtime.actions.loadSelectedRun?.();
      runtime.actions.renderAll?.();
    });
    document.getElementById("history-baseline-run")?.addEventListener("change", (event) => {
      state.comparisonBaselineRunId = event.target.value || null;
      renderHistoryComparison();
      runtime.actions.renderReportCenter?.();
    });

    const comparison = compareRuns(state.selectedRunId, state.comparisonBaselineRunId);
    dom.comparisonSummary.innerHTML = comparison
      ? `
        <h4>${escapeHtml("Current vs baseline")}</h4>
        <p>${escapeHtml(`${comparison.newCount} new · ${comparison.fixedCount} fixed · ${comparison.persistingCount} still open`)}</p>
        <p>${escapeHtml(`${comparison.worsenedCount} worsened · pack changed ${comparison.packChanged ? "yes" : "no"}`)}</p>
        <p class="micro-copy">${escapeHtml(comparison.summary)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
          <button class="action ghost" type="button" data-nav-screen="findings-theater">Review Findings</button>
        </div>
      `
      : emptyState("Choose a baseline run to compare changes over time.");

    const sortedRuns = [...state.mission.runs].sort(
      (left, right) => new Date(left.created_at) - new Date(right.created_at)
    );
    dom.historyTrend.innerHTML = sortedRuns.length
      ? sortedRuns
          .map((run) => {
            const findings = state.mission.findingsByRun[run.id] || [];
            const open = findings.filter((finding) =>
              ["open", "triaged", "in_progress", "reopened"].includes(finding.status)
            ).length;
            const percent = Math.min(100, findings.length * 12);
            return `
              <div class="trend-card list-card ${run.id === state.selectedRunId ? "selected" : ""}" data-history-run-pick="${run.id}" data-testid="history-run-card">
                <h4>${escapeHtml(run.profile.name)}</h4>
                <p>${escapeHtml(`${findings.length} findings · ${open} still open`)}</p>
                <div class="history-bar split-top"><span style="width:${percent}%"></span></div>
                <p class="micro-copy split-top">${escapeHtml(formatDateTime(run.created_at))}</p>
              </div>
            `;
          })
          .join("")
      : emptyState("Run trend history appears after multiple runs exist in the engagement.");
    dom.historyTrend.querySelectorAll("[data-history-run-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedRunId = item.dataset.historyRunPick;
        if (!state.comparisonBaselineRunId || state.comparisonBaselineRunId === state.selectedRunId) {
          state.comparisonBaselineRunId =
            state.mission.runs.find((run) => run.id !== state.selectedRunId)?.id || null;
        }
        await runtime.actions.loadSelectedRun?.();
        renderHistoryComparison();
        runtime.actions.renderFlowOverview?.();
      });
    });

    const nextSteps = buildNextStepsQueue();
    dom.nextStepsQueue.innerHTML = nextSteps.length
      ? nextSteps
          .map(
            (item) => `
              <div class="list-card">
                <h4>${escapeHtml(item.title)}</h4>
                <p>${statusPill(item.status)} ${escapeHtml(item.priority)}</p>
                <p>${escapeHtml(item.action)}</p>
                <p class="micro-copy">${escapeHtml(item.retest)}</p>
              </div>
            `
          )
          .join("")
      : emptyState("Open findings and their recommended follow-up actions appear here.");
  }

  return {
    buildNextStepsQueue,
    compareRuns,
    renderExplorer,
    renderHistoryComparison,
  };
}
