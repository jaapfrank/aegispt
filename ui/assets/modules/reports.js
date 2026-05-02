import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  countMeaningfulAccessContexts,
  emptyState,
  escapeHtml,
  executionPlanForProfile,
  formatDateTime,
  followUpStrategyLabel,
  renderAccessContextSummary,
  renderBadgeList,
  renderTargetSummary,
  statusPill,
} from "./shared.js";

const REPORT_PLACEHOLDER_FONT_STACK =
  "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";

function reportPlaceholder(message, extraStyle = "") {
  const suffix = extraStyle ? `${extraStyle};` : "";
  return `<div style="padding:24px;font-family:${REPORT_PLACEHOLDER_FONT_STACK};${suffix}">${escapeHtml(message)}</div>`;
}

function renderEvidenceHashSummary(contentSha256) {
  if (!contentSha256) return "";
  return `
    <div class="report-hash-summary split-top" data-testid="report-evidence-hash">
      <div class="task-activity-header">
        <div>
          <strong>Evidence hash: verified</strong>
          <p class="micro-copy">The export is linked to a stored SHA-256 evidence hash. Expand only when you need the raw value.</p>
        </div>
        <button class="action ghost tiny" type="button" data-report-copy-hash="${escapeHtml(contentSha256)}" data-testid="report-copy-hash" aria-label="Copy full evidence hash">Copy</button>
      </div>
      <details class="report-hash-disclosure split-top">
        <summary>Show full SHA-256</summary>
        <code>${escapeHtml(contentSha256)}</code>
      </details>
    </div>
  `;
}

function reportCanPreview(report) {
  return report?.preview_allowed !== false;
}

function reportCanExport(report) {
  return report?.export_allowed !== false;
}

function reportCanDraft(report) {
  return report?.draft_allowed !== false;
}

function reportAvailabilityPill(report) {
  const status = String(report?.availability_status || "unknown").toLowerCase();
  const label = report?.availability_label || status.replaceAll("_", " ");
  const theme =
    status === "export_ready"
      ? "completed"
      : status === "draft_only"
        ? "review"
        : status === "unavailable"
          ? "blocked"
          : "unknown";
  return `<span class="status-pill status-${theme}">${escapeHtml(label)}</span>`;
}

function selectedReportQuery(format) {
  const variant = encodeURIComponent(state.reportVariant || "technical");
  const framework =
    state.reportVariant === "compliance"
      ? `&framework=${encodeURIComponent(state.reportComplianceFramework || "nis2")}`
      : "";
  return `format=${encodeURIComponent(format)}&variant=${variant}${framework}`;
}

export function createReportsModule() {
  function renderReportCenter() {
    if (
      !dom.reportCatalog ||
      !dom.reportMetadata ||
      !dom.reportActions ||
      !dom.reportPreview ||
      !dom.reportFrame ||
      !dom.reportCompare ||
      !dom.reportCenterTabs ||
      !dom.reportCenterReportsView ||
      !dom.reportCenterDossierView ||
      !dom.reportDossierContext ||
      !dom.reportDossierDetail
    ) {
      return;
    }

    renderReportCenterTabs();
    const showDossierView = state.reportCenterView === "dossier";
    dom.reportCenterReportsView.classList.toggle("hidden", showDossierView);
    dom.reportCenterDossierView.classList.toggle("hidden", !showDossierView);
    if (showDossierView) {
      renderReportDossierView();
      return;
    }

    dom.reportCatalog.innerHTML = state.reportCatalog.length
      ? state.reportCatalog
          .map(
            (report) => `
              <article class="report-card report-card-grid-item ${report.variant === state.reportVariant ? "selected" : ""}" data-report-variant="${report.variant}" data-testid="report-card">
                <div class="report-card-head">
                  <div>
                    <h4>${escapeHtml(report.title)}</h4>
                    <p class="micro-copy">${escapeHtml(report.version_label)}</p>
                  </div>
                  ${
                    report.variant === "attack_narrative"
                      ? `<span class="badge badge-violet">✨ AI</span>`
                      : reportAvailabilityPill(report)
                  }
                </div>
                <p>${escapeHtml(report.description)}</p>
                <p class="micro-copy">${escapeHtml(report.availability_reason || "Report availability follows the selected run lifecycle.")}</p>
                <div class="report-card-inline-actions">
                  <button class="dl-btn" type="button" data-report-select="${escapeHtml(report.variant)}">Open</button>
                  ${
                    reportCanExport(report)
                      ? `<a class="dl-btn" href="${report.export_paths.markdown}" download="${escapeHtml(report.download_names?.markdown || "")}" rel="noreferrer">↓ MD</a>
                         <a class="dl-btn" href="${report.export_paths.html}" download="${escapeHtml(report.download_names?.html || "")}" rel="noreferrer">↓ HTML</a>`
                      : `<button class="dl-btn" type="button" disabled title="${escapeHtml(report.availability_reason || "Export is unavailable for this run state.")}">MD</button>
                         <button class="dl-btn" type="button" disabled title="${escapeHtml(report.availability_reason || "Export is unavailable for this run state.")}">HTML</button>`
                  }
                  ${
                    report.export_paths.pdf && reportCanExport(report)
                      ? `<a class="dl-btn" href="${report.export_paths.pdf}" download="${escapeHtml(report.download_names?.pdf || "")}" rel="noreferrer">↓ PDF</a>`
                      : ""
                  }
                </div>
              </article>
            `
          )
          .join("")
      : emptyState("Report variants become available once a run dossier exists.");
    dom.reportCatalog.querySelectorAll("[data-report-variant]").forEach((item) => {
      item.addEventListener("click", () => {
        state.reportVariant = item.dataset.reportVariant;
        state.reportPreview = "";
        state.reportHtml = "";
        state.reportDraft = null;
        state.reportFormat = "markdown";
        renderReportCenter();
      });
    });

    const selectedReport =
      state.reportCatalog.find((report) => report.variant === state.reportVariant) || null;
    if (!selectedReport) {
      dom.reportMetadata.innerHTML = emptyState(
        state.selectedRun
          ? "Select an available report card to load its exports and preview actions for this run."
          : "Create a mission in Conversational Intake first. Report workflows unlock after a run dossier exists."
      );
      dom.reportActions.innerHTML = "";
      if (!state.reportPreview) {
        dom.reportPreview.textContent = state.selectedRun
          ? "Select a report card, then generate a preview for this run."
          : "Create a mission, then generate a report preview for its run.";
      }
      if (!state.reportHtml) {
        dom.reportFrame.srcdoc = reportPlaceholder(
          state.selectedRun
            ? "Select a report card, then generate an HTML preview here."
            : "Create a mission, then generate an HTML report preview here."
        );
      }
      dom.reportCompare.innerHTML = emptyState(
        state.selectedRun
          ? "Select a previous run to compare findings, coverage, and risk score changes."
          : "Create a second run, then compare findings, coverage, and risk score changes."
      );
      return;
    }

    const executionPlan = state.selectedRun
      ? executionPlanForProfile(state.selectedRun.profile?.name, state.runProfiles)
      : null;
    const followUp = getFollowUpMetadata(state.selectedRun);
    const adaptiveChange = selectedReport.adaptive_change_summary || null;
    const aiDraft = selectedReport.ai_draft_summary || null;
    const runNarrative = selectedReport.run_narrative_summary || null;
    const compliance = selectedReport.compliance_summary || null;
    const assurance = selectedReport.assurance_summary || null;
    const complianceFrameworks = selectedReport.compliance_summary?.available_frameworks || [
      "nis2",
      "dora",
      "soc2",
      "iso27001",
      "pci_dss",
      "nfir",
    ];
    const complianceSelector =
      selectedReport.variant === "compliance"
        ? `
          <label class="field-label compact" data-testid="report-compliance-framework">
            Framework
            <select data-report-compliance-framework>
              ${complianceFrameworks
                .map(
                  (framework) =>
                    `<option value="${escapeHtml(framework)}" ${
                      framework === state.reportComplianceFramework ? "selected" : ""
                    }>${escapeHtml(framework.toUpperCase().replace("_", " "))}</option>`
                )
                .join("")}
            </select>
          </label>
        `
        : "";
    const sourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;
    const discoveredAssetCount =
      Number(selectedReport.included_inventory.host_count || 0) +
      Number(selectedReport.included_inventory.service_count || 0) +
      Number(selectedReport.included_inventory.endpoint_count || 0) +
      Number(selectedReport.included_inventory.wireless_access_point_count || 0) +
      Number(selectedReport.included_inventory.wireless_network_count || 0);
    const wirelessMetric =
      Number(selectedReport.included_inventory.wireless_access_point_count || 0) > 0
        ? `<span class="metric-pill">${escapeHtml(`WiFi APs ${selectedReport.included_inventory.wireless_access_point_count}`)}</span>`
        : "";
    const discoveryOnlyNote =
      Number(selectedReport.included_findings.count || 0) === 0 && discoveredAssetCount
        ? `
            <div class="report-run-strip-notes split-top" data-testid="report-discovery-note">
              <span>${escapeHtml(`Discovery-only run discovered ${discoveredAssetCount} assets.`)}</span>
              <span>${escapeHtml("Use the generated report variants to review inventory-backed evidence even when no findings were created.")}</span>
            </div>
          `
        : "";
    const adaptiveChangeNote =
      adaptiveChange?.active
        ? `
            <div class="report-run-strip-notes split-top" data-testid="report-adaptive-change-note">
              <span><strong>${escapeHtml(adaptiveChange.summary_line || "Adaptive coverage is bound to this run.")}</strong></span>
              <span>${escapeHtml(adaptiveChange.governance_line || "Pack governance status is recorded in the run dossier.")}</span>
              ${
                adaptiveChange.latest_task
                  ? `<span>${escapeHtml(
                      `Latest build-lane task ${adaptiveChange.latest_task.id} (${adaptiveChange.latest_task.task_type}) is ${adaptiveChange.latest_task.status}.`
                    )}</span>`
                  : ""
              }
            </div>
          `
        : "";

    dom.reportMetadata.innerHTML = `
      <div class="report-run-strip-row">
        <div class="report-run-strip-copy">
          <strong>${escapeHtml(
            state.selectedRun?.profile?.name ||
              state.selectedRun?.configuration_json?.test_profile ||
              selectedReport.title
          )}</strong>
          <span>${escapeHtml(
            `${formatDateTime(state.selectedRun?.updated_at || state.selectedRun?.created_at)} · ${selectedReport.source_scope_profile.assessment_type || "assessment"}`
          )}</span>
        </div>
        <div class="inline-metrics">
          ${statusPill(state.selectedRun?.status || "unknown")}
          ${reportAvailabilityPill(selectedReport)}
          <span class="metric-pill">${escapeHtml(`${selectedReport.included_findings.count} findings`)}</span>
          <span class="metric-pill">${escapeHtml(`${state.reportCatalog.length} report variants`)}</span>
          <span class="metric-pill">${escapeHtml(`Assets ${discoveredAssetCount}`)}</span>
          <span class="metric-pill">${escapeHtml(`${selectedReport.included_inventory.host_count || 0} hosts`)}</span>
          <span class="metric-pill">${escapeHtml(`${selectedReport.included_inventory.endpoint_count || 0} endpoints`)}</span>
          ${wirelessMetric}
        </div>
      </div>
      <div class="report-run-strip-notes">
        <span>${escapeHtml(
          executionPlan
            ? `${executionPlan.profileName} · ${executionPlan.toolsLabel}`
            : `${selectedReport.source_scope_profile.run_profile} · ${selectedReport.version_label}`
        )}</span>
        <span>${escapeHtml(selectedReport.description)}</span>
        <span>${escapeHtml(selectedReport.availability_reason || "Report availability follows the selected run lifecycle.")}</span>
      </div>
      ${discoveryOnlyNote}
      ${adaptiveChangeNote}
      ${renderEvidenceHashSummary(selectedReport.content_sha256)}
      ${
        followUp
          ? `<div class="report-run-strip-notes split-top" data-testid="report-follow-up-note">
              <span><strong>${escapeHtml(followUpStrategyLabel(followUp.strategy))} lineage is attached</strong></span>
              <span>${escapeHtml(
                sourceRun
                  ? `Derived from ${sourceRun.profile?.name || sourceRun.id}`
                  : `Derived from inventory ${followUp.source_inventory_snapshot_id || "n/a"}`
              )}</span>
            </div>`
          : ""
      }
    `;

    dom.reportActions.innerHTML = `
      ${complianceSelector}
      ${
        state.loading.reportPreview
          ? `
            <div class="detail-surface" data-testid="report-preview-loading">
              <h4>Generating preview</h4>
              <p>The existing report service is rendering the ${escapeHtml(state.reportVariant)} report for this run.</p>
            </div>
          `
          : ""
      }
      <button class="action primary" data-report-preview="markdown" type="button" data-testid="report-preview-markdown" ${reportCanPreview(selectedReport) ? "" : "disabled"}>Generate Markdown Preview</button>
      <button class="action secondary" data-report-preview="html" type="button" data-testid="report-preview-html" ${reportCanPreview(selectedReport) ? "" : "disabled"}>Generate HTML Preview</button>
      <button class="action secondary" data-report-draft type="button" data-testid="report-draft-generate" ${reportCanDraft(selectedReport) ? "" : "disabled"}>${state.loading.reportDraft ? "Drafting…" : "Generate AI Draft"}</button>
      ${
        reportCanExport(selectedReport)
          ? `<a class="action ghost" href="/api/v1/runs/${state.selectedRunId}/report?${selectedReportQuery("markdown")}" download="${escapeHtml(selectedReport.download_names?.markdown || "")}" rel="noreferrer" data-testid="report-download-markdown">Download Markdown</a>
             <a class="action ghost" href="/api/v1/runs/${state.selectedRunId}/report?${selectedReportQuery("html")}" download="${escapeHtml(selectedReport.download_names?.html || "")}" rel="noreferrer" data-testid="report-download-html">Download HTML</a>`
          : `<button class="action ghost" type="button" disabled data-testid="report-download-markdown">Download Markdown</button>
             <button class="action ghost" type="button" disabled data-testid="report-download-html">Download HTML</button>`
      }
      ${
        selectedReport.export_paths.pdf && reportCanExport(selectedReport)
          ? `<a class="action ghost" href="/api/v1/runs/${state.selectedRunId}/report?${selectedReportQuery("pdf")}" download="${escapeHtml(selectedReport.download_names?.pdf || "")}" rel="noreferrer" data-testid="report-download-pdf">Download PDF</a>`
          : ""
      }
      ${renderReportDraftPanel(state.reportDraft, state.loading.reportDraft)}
    `;
    dom.reportCatalog.querySelectorAll("[data-report-select]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        state.reportVariant = button.dataset.reportSelect;
        renderReportCenter();
      });
    });
    dom.reportActions.querySelectorAll("[data-report-preview]").forEach((button) => {
      button.addEventListener("click", () =>
        previewReport(button.dataset.reportPreview).catch(runtime.actions.handleError)
      );
    });
    dom.reportActions.querySelectorAll("[data-report-draft]").forEach((button) => {
      button.addEventListener("click", () =>
        generateReportDraft().catch(runtime.actions.handleError)
      );
    });
    dom.reportActions.querySelector("[data-report-compliance-framework]")?.addEventListener("change", (event) => {
      state.reportComplianceFramework = event.target.value || "nis2";
      state.reportPreview = "";
      state.reportHtml = "";
      state.reportFormat = "markdown";
      renderReportCenter();
    });
    dom.reportMetadata.querySelectorAll("[data-report-copy-hash]").forEach((button) => {
      button.addEventListener("click", async () => {
        const hash = button.dataset.reportCopyHash || "";
        if (!hash) return;
        try {
          await navigator.clipboard?.writeText?.(hash);
          runtime.actions.pushStatus?.("Evidence hash copied to clipboard.", "success");
        } catch {
          runtime.actions.pushStatus?.("Unable to copy the evidence hash on this host.", "warning");
        }
      });
    });

    if (state.loading.reportPreview) {
      dom.reportPreview.textContent = "Generating report preview...";
      dom.reportFrame.srcdoc = reportPlaceholder("Generating HTML preview...", "color:#182535");
    } else if (!state.reportPreview) {
      dom.reportPreview.textContent =
        "Generate a markdown preview to review this report here.";
    } else {
      dom.reportPreview.textContent = state.reportPreview;
    }

    if (!state.loading.reportPreview && !state.reportHtml) {
      dom.reportFrame.srcdoc = reportPlaceholder(
        "Generate an HTML preview to review the rendered report here.",
        "color:#182535"
      );
    }
    dom.reportPreview.classList.toggle("hidden", state.reportFormat === "html");
    dom.reportFrame.classList.toggle("hidden", state.reportFormat !== "html");

    dom.reportCompare.innerHTML = renderReportComparison(selectedReport);
  }

  async function previewReport(format) {
    if (!state.selectedRunId) {
      throw new Error("Select a run before previewing reports.");
    }
    state.loading.reportPreview = true;
    renderReportCenter();
    try {
      if (format === "html") {
        state.reportHtml = await api(
          `/api/v1/runs/${state.selectedRunId}/report?${selectedReportQuery("html")}`,
          { raw: true }
        );
        dom.reportFrame.srcdoc = state.reportHtml;
        runtime.actions.pushStatus?.(
          `HTML preview generated for the ${state.reportVariant} report.`,
          "info"
        );
      } else {
        state.reportPreview = await api(
          `/api/v1/runs/${state.selectedRunId}/report?${selectedReportQuery("markdown")}`,
          { raw: true }
        );
        dom.reportPreview.textContent = state.reportPreview;
        runtime.actions.pushStatus?.(
          `Markdown preview generated for the ${state.reportVariant} report.`,
          "info"
        );
      }
      state.reportFormat = format;
    } finally {
      state.loading.reportPreview = false;
      renderReportCenter();
    }
  }

  async function generateReportDraft() {
    if (!state.selectedRunId) {
      throw new Error("Select a run before generating an AI-assisted report draft.");
    }
    state.loading.reportDraft = true;
    state.reportDraft = null;
    renderReportCenter();
    try {
      state.reportDraft = await api(`/api/v1/runs/${state.selectedRunId}/report-draft`, {
        method: "POST",
        body: {
          variant: state.reportVariant,
          sections: ["executive_summary", "risk_highlights", "remediation_overview"],
        },
      });
      runtime.actions.pushStatus?.(
        state.reportDraft.available
          ? "AI-assisted report draft generated for operator review."
          : "AI-assisted report draft is unavailable; normal report exports are unchanged.",
        state.reportDraft.available ? "success" : "info"
      );
    } finally {
      state.loading.reportDraft = false;
      renderReportCenter();
    }
  }

  function renderReportComparison(selectedReport) {
    const comparison = runtime.actions.compareRuns?.(
      state.selectedRunId,
      state.comparisonBaselineRunId
    );
    if (!comparison) {
      return emptyState("Select a previous run to compare findings, coverage, and risk score changes.");
    }
    return `
      <h4>${escapeHtml(selectedReport.title)}</h4>
      <p>${escapeHtml(`${comparison.newCount} new findings · ${comparison.resolvedCount || comparison.fixedCount} resolved since the previous run`)}</p>
      <p>${escapeHtml(`${comparison.persistingCount} persistent · ${comparison.changedCount || 0} changed · ${comparison.worsenedCount} worsened`)}</p>
      <p class="micro-copy">${escapeHtml(`Pack changed: ${comparison.packChanged ? "yes" : "no"} · previous run ${comparison.baselineLabel}`)}</p>
      ${renderReportContinuousTrendDelta(comparison)}
    `;
  }

  function renderReportCenterTabs() {
    dom.reportCenterTabs.innerHTML = [
      { view: "reports", label: "Reports", detail: "Preview, export, and compare deliverables." },
      { view: "dossier", label: "Dossier", detail: "Run context, scope, lineage, and access posture." },
    ]
      .map(
        (item) => `
          <button
            class="view-tab ${state.reportCenterView === item.view ? "active" : ""}"
            type="button"
            data-report-center-view="${escapeHtml(item.view)}"
            data-testid="report-center-tab-${escapeHtml(item.view)}"
            aria-current="${state.reportCenterView === item.view ? "page" : "false"}"
          >
            <strong>${escapeHtml(item.label)}</strong>
            <small>${escapeHtml(item.detail)}</small>
          </button>
        `
      )
      .join("");
  }

  function renderReportDossierView() {
    const engagement =
      state.engagements.find((candidate) => String(candidate.id) === String(state.selectedEngagementId || "")) || null;
    const run = state.selectedRun;
    if (!run) {
      dom.reportDossierContext.innerHTML = emptyState(
        state.selectedEngagementId
          ? "Select or create a run before opening the dossier tab."
          : "Create a mission first. The dossier tab appears once a run exists."
      );
      dom.reportDossierDetail.innerHTML = emptyState(
        "Run context, scope, access posture, and lineage will appear here for the selected run."
      );
      return;
    }

    const config = run.configuration_json || {};
    const followUp = getFollowUpMetadata(run);
    const sourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;
    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventorySummary = summarizeReportDossierInventory(inventorySnapshot);
    const tasks = Array.isArray(run.tasks) ? run.tasks : [];
    const taskSummary = summarizeReportRunTasks(tasks);
    const executionSummary = summarizeReportRunExecutions(tasks);
    const protectedSecrets = Number(config.access?.secret_storage?.binding_count || 0);
    const accessContextCount = countMeaningfulAccessContexts(config.access || {});
    const missionHandoff = String(config.intake?.confirmation_summary || "").trim();
    const acceptance = config.acceptance_metadata || null;
    const findings = state.mission.findingsByRun[run.id] || [];

    dom.reportDossierContext.innerHTML = `
      <div class="section-note" data-testid="report-dossier-orientation">
        <strong>Engagement orientation</strong>
        <p>Customer, engagement, ROE, and selected-run context are available here before export or comparison.</p>
      </div>
      ${renderBadgeList(
        [
          engagement?.name || "Selected engagement",
          engagement?.client || "Customer not recorded",
          engagement?.roe_ref || "ROE not recorded",
          run.profile?.name || "Profile not recorded",
        ],
        "compact-badge-list split-top"
      )}
      <div class="compact-definition-grid split-top">
        <div><span>Selected Run</span><strong>${escapeHtml(run.id)}</strong></div>
        <div><span>Status</span><strong>${escapeHtml(String(run.status || "unknown").replace(/_/g, " "))}</strong></div>
        <div><span>Runs in Engagement</span><strong>${escapeHtml(`${state.mission.runs.length}`)}</strong></div>
        <div><span>Findings</span><strong>${escapeHtml(`${findings.length}`)}</strong></div>
      </div>
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-report-center-view="reports" data-testid="report-dossier-open-reports">Open Reports</button>
        <button class="action ghost" type="button" data-nav-screen="explorer" data-testid="report-dossier-open-explorer">Open Explorer</button>
        <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
      </div>
    `;

    dom.reportDossierDetail.innerHTML = `
      <div class="detail-grid">
        <div class="detail-surface">
          <h4>Scope & Profile</h4>
          <p>${escapeHtml(config.assessment_type || "Assessment not recorded")}</p>
          <p class="micro-copy">${escapeHtml(renderTargetSummary(config.targets || {}))}</p>
          <p class="micro-copy">${escapeHtml(config.test_profile || run.profile?.name || "Profile not recorded")}</p>
        </div>
        <div class="detail-surface">
          <h4>Inventory & Evidence</h4>
          <p>${escapeHtml(`${inventorySummary.hosts} hosts · ${inventorySummary.services} services · ${inventorySummary.endpoints} endpoints`)}</p>
          <p class="micro-copy">${escapeHtml(`${executionSummary.executions} execution records · ${executionSummary.artifacts} artifacts`)}</p>
          <p class="micro-copy">${escapeHtml(`${taskSummary.completed} completed · ${taskSummary.failed} failed · ${taskSummary.queued} queued`)}</p>
        </div>
        <div class="detail-surface">
          <h4>Protected Access</h4>
          <p>${escapeHtml(`${protectedSecrets} secret binding${protectedSecrets === 1 ? "" : "s"}`)}</p>
          <p class="micro-copy">${escapeHtml(
            accessContextCount
              ? renderAccessContextSummary(config.access || {})
              : "No access context recorded for this run."
          )}</p>
        </div>
        <div class="detail-surface">
          <h4>Lineage</h4>
          <p>${escapeHtml(
            followUp
              ? `${followUpStrategyLabel(followUp.strategy)} from ${sourceRun?.profile?.name || "a prior run"}`
              : "Primary selected run"
          )}</p>
          <p class="micro-copy">${escapeHtml(
            followUp?.rationale || `Inventory ${run.source_inventory_snapshot_id || "n/a"} · pack ${run.pack_binding?.pack_version || "standard baseline"}`
          )}</p>
        </div>
      </div>
      <div class="section-note split-top">
        <strong>Mission handoff</strong>
        <p>${escapeHtml(missionHandoff || "No natural-language confirmation summary was recorded for this run.")}</p>
      </div>
      ${
        followUp
          ? `<div class="section-note split-top" data-testid="report-dossier-follow-up">
              <strong>${escapeHtml(followUpStrategyLabel(followUp.strategy))} lineage is attached</strong>
              <p>${escapeHtml(
                sourceRun
                  ? `This run derives from ${sourceRun.profile?.name || sourceRun.id} and stays tied to the earlier discovery context.`
                  : "This run derives from a prior inventory snapshot and remains lineage-aware."
              )}</p>
              <p class="micro-copy">${escapeHtml(
                `Source inventory ${followUp.source_inventory_snapshot_id || run.source_inventory_snapshot_id || "n/a"}`
              )}</p>
            </div>`
          : ""
      }
      ${
        acceptance
          ? `<div class="section-note split-top" data-testid="report-dossier-acceptance">
              <strong>Acceptance support is recorded</strong>
              <p>${escapeHtml(acceptance.scenario_name || acceptance.scenario_id || "Acceptance scenario")}</p>
              <p class="micro-copy">${escapeHtml(
                `${acceptance.target_label || acceptance.target_id || "Safe target"} · ${acceptance.target_classification || "classification not recorded"}`
              )}</p>
            </div>`
          : ""
      }
      <div class="panel-actions split-top">
        <button class="action primary" type="button" data-nav-screen="findings-theater">Open Findings + Evidence</button>
        <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence Replay</button>
      </div>
    `;
  }

  return {
    generateReportDraft,
    previewReport,
    renderReportCenter,
  };
}

function renderReportDraftPanel(draft, loading) {
  if (loading) {
    return `
      <div class="section-note split-top" data-testid="report-ai-draft-panel">
        <strong>Generating AI-assisted draft</strong>
        <p>The draft request is separate from canonical report export and remains review-only.</p>
      </div>
    `;
  }
  if (!draft) return "";
  if (!draft.available) {
    return `
      <div class="section-note split-top" data-testid="report-ai-draft-panel">
        <strong>AI-assisted draft unavailable</strong>
        <p>${escapeHtml(draft.failure_reason || "The provider is disabled or failed. Normal report exports are unchanged.")}</p>
        <p class="micro-copy">${escapeHtml(draft.boundary || "Canonical report facts remain unchanged.")}</p>
      </div>
    `;
  }
  return `
    <div class="section-note split-top" data-testid="report-ai-draft-panel">
      <strong>AI-assisted draft ready for operator review</strong>
      <p>${escapeHtml(draft.boundary || "Review is required before using this draft in a final report.")}</p>
      <p class="micro-copy">${escapeHtml(`Sources: ${(draft.source_data_categories || []).join(", ") || "stored run context"}`)}</p>
      <p class="micro-copy">${escapeHtml(`Evidence refs: ${(draft.source_evidence_refs || []).join(", ") || "no linked finding evidence refs recorded"}`)}</p>
      <pre class="report-preview split-top">${escapeHtml(draft.draft_markdown || "")}</pre>
    </div>
  `;
}

function renderReportContinuousTrendDelta(comparison) {
  const trend = comparison?.scheduledTrend || null;
  if (!trend) return "";
  if (!trend.comparable) {
    return `
      <div class="section-note split-top" data-testid="report-continuous-trend-delta">
        <strong>Scheduled trend unavailable</strong>
        <p>${escapeHtml(trend.reason || "The selected report baseline is not comparable for scheduled trend review.")}</p>
      </div>
    `;
  }
  const findingDelta = trend.findingDelta || {};
  return `
    <div class="section-note split-top" data-testid="report-continuous-trend-delta">
      <strong>Scheduled validation trend is comparable</strong>
      <p>${escapeHtml(`${findingDelta.new || 0} new · ${findingDelta.resolved || 0} resolved · ${findingDelta.persistent || 0} persistent · ${findingDelta.changed || 0} changed findings for the same schedule lineage.`)}</p>
      <p class="micro-copy">${escapeHtml("This report comparison uses stored run, finding, inventory, and report context only; it does not claim absolute risk reduction or launch scheduled work.")}</p>
    </div>
  `;
}

function renderReportRunDossierContext(selectedReport, executionPlan, followUp, sourceRun) {
  const run = state.selectedRun;
  if (!run) return "";
  const config = run.configuration_json || {};
  const inventory = selectedReport.included_inventory || {};
  const findings = selectedReport.included_findings || {};
  const tasks = Array.isArray(run.tasks) ? run.tasks : [];
  const taskSummary = summarizeReportRunTasks(tasks);
  const executionSummary = summarizeReportRunExecutions(tasks);
  const protectedSecrets = Number(config.access?.secret_storage?.binding_count || 0);
  const accessContextCount = countMeaningfulAccessContexts(config.access || {});
  const missionHandoff = String(config.intake?.confirmation_summary || "").trim();
  const sourceLine = followUp
    ? sourceRun
      ? `${followUpStrategyLabel(followUp.strategy)} follow-up from ${sourceRun.profile?.name || sourceRun.id}`
      : `${followUpStrategyLabel(followUp.strategy)} follow-up from prior inventory`
    : "Primary selected run";
  const reportCount = state.reportCatalog.length || 0;

  return `
    <section class="detail-surface split-top" data-testid="report-run-dossier-context">
      <div class="section-note">
        <strong>Run dossier context</strong>
        <p>Review scope, evidence, access context, inventory, and report readiness before export.</p>
      </div>
      ${renderBadgeList([
        run.status,
        config.assessment_type || "Assessment not recorded",
        config.test_profile || run.profile?.name || "Profile not recorded",
        sourceLine,
      ], "compact-badge-list split-top")}
      <div class="compact-definition-grid split-top">
        <div><span>Scope</span><strong>${escapeHtml(renderTargetSummary(config.targets || {}))}</strong></div>
        <div><span>Access Context</span><strong>${escapeHtml(accessContextCount ? renderAccessContextSummary(config.access || {}) : "No access context recorded")}</strong></div>
        <div><span>Protected Bindings</span><strong>${escapeHtml(`${protectedSecrets} secret binding${protectedSecrets === 1 ? "" : "s"}`)}</strong></div>
        <div><span>Report Variants</span><strong>${escapeHtml(`${reportCount} ready`)}</strong></div>
        <div><span>Inventory</span><strong>${escapeHtml(`${inventory.host_count || 0} hosts · ${inventory.service_count || 0} services · ${inventory.endpoint_count || 0} endpoints`)}</strong></div>
        <div><span>Findings</span><strong>${escapeHtml(`${findings.count || 0} finding${findings.count === 1 ? "" : "s"}`)}</strong></div>
        <div><span>Evidence</span><strong>${escapeHtml(`${executionSummary.executions} execution records · ${executionSummary.artifacts} artifacts`)}</strong></div>
        <div><span>Tasks</span><strong>${escapeHtml(`${taskSummary.completed} complete · ${taskSummary.failed} failed · ${taskSummary.queued} queued`)}</strong></div>
      </div>
      <p class="micro-copy split-top">${escapeHtml(
        missionHandoff || "No natural-language mission handoff was recorded for this run."
      )}</p>
      ${
        executionPlan
          ? `<p class="micro-copy">${escapeHtml(`Execution guardrail: ${executionPlan.profileName} with ${executionPlan.requiredApprovals} approval requirement.`)}</p>`
          : ""
      }
    </section>
  `;
}

function summarizeReportRunTasks(tasks) {
  return (tasks || []).reduce(
    (summary, task) => {
      const status = String(task.status || "unknown").toLowerCase();
      summary.total += 1;
      if (status === "completed") summary.completed += 1;
      else if (status === "failed") summary.failed += 1;
      else if (status === "running") summary.running += 1;
      else if (status === "queued") summary.queued += 1;
      return summary;
    },
    { total: 0, running: 0, queued: 0, completed: 0, failed: 0 }
  );
}

function summarizeReportRunExecutions(tasks) {
  return (tasks || []).reduce(
    (summary, task) => {
      const executions = Array.isArray(task.executions) ? task.executions : [];
      summary.executions += executions.length;
      summary.artifacts += executions.reduce(
        (artifactTotal, execution) =>
          artifactTotal + (Array.isArray(execution.artifacts) ? execution.artifacts.length : 0),
        0
      );
      return summary;
    },
    { executions: 0, artifacts: 0 }
  );
}

function summarizeReportDossierInventory(snapshot) {
  const normalized = snapshot?.normalized_inventory_json || {};
  const summary = snapshot?.summary_json || {};
  return {
    hosts: Number(summary.host_count || (normalized.hosts || []).length || 0),
    services: Number(summary.service_count || (normalized.services || []).length || 0),
    endpoints: Number(summary.endpoint_count || (normalized.http_endpoints || []).length || 0),
  };
}

function getFollowUpMetadata(run) {
  const followUp = run?.configuration_json?.follow_up;
  return typeof followUp === "object" && followUp !== null ? followUp : null;
}
