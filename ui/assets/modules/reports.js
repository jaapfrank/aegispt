import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  executionPlanForProfile,
  followUpStrategyLabel,
  statusPill,
} from "./shared.js";

const REPORT_PLACEHOLDER_FONT_STACK =
  "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";

function reportPlaceholder(message, extraStyle = "") {
  const suffix = extraStyle ? `${extraStyle};` : "";
  return `<div style="padding:24px;font-family:${REPORT_PLACEHOLDER_FONT_STACK};${suffix}">${escapeHtml(message)}</div>`;
}

export function createReportsModule() {
  function renderReportCenter() {
    if (
      !dom.reportCatalog ||
      !dom.reportMetadata ||
      !dom.reportActions ||
      !dom.reportPreview ||
      !dom.reportFrame ||
      !dom.reportCompare
    ) {
      return;
    }

    dom.reportCatalog.innerHTML = state.reportCatalog.length
      ? state.reportCatalog
          .map(
            (report) => `
              <div class="report-card ${report.variant === state.reportVariant ? "selected" : ""}" data-report-variant="${report.variant}" data-testid="report-card">
                <h4>${escapeHtml(report.title)}</h4>
                <p>${statusPill("complete")} ${escapeHtml(report.description)}</p>
                <p class="micro-copy">${escapeHtml(report.version_label)}</p>
              </div>
            `
          )
          .join("")
      : emptyState("Report variants become available once a run dossier exists.");
    dom.reportCatalog.querySelectorAll("[data-report-variant]").forEach((item) => {
      item.addEventListener("click", () => {
        state.reportVariant = item.dataset.reportVariant;
        state.reportPreview = "";
        state.reportHtml = "";
        state.reportFormat = "markdown";
        renderReportCenter();
      });
    });

    const selectedReport =
      state.reportCatalog.find((report) => report.variant === state.reportVariant) || null;
    if (!selectedReport) {
      dom.reportMetadata.innerHTML = emptyState(
        state.selectedRun
          ? "Select an available report variant to review metadata, downloads, and preview actions for this run."
          : "Create a mission in Conversational Intake first. Report workflows unlock after a run dossier exists."
      );
      dom.reportActions.innerHTML = "";
      if (!state.reportPreview) {
        dom.reportPreview.textContent = state.selectedRun
          ? "No report preview loaded yet. Generate a markdown or HTML preview for the selected run."
          : "No report preview is available yet. Create a mission first, then generate a preview from the selected run.";
      }
      if (!state.reportHtml) {
        dom.reportFrame.srcdoc = reportPlaceholder(
          state.selectedRun
            ? "No HTML report preview loaded."
            : "Create a mission first, then generate an HTML report preview from the selected run."
        );
      }
      dom.reportCompare.innerHTML = emptyState(
        state.selectedRun
          ? "Choose a current and baseline run to compare report posture."
          : "Create at least two run dossiers before comparing report posture."
      );
      return;
    }

    const executionPlan = state.selectedRun
      ? executionPlanForProfile(state.selectedRun.profile?.name, state.runProfiles)
      : null;
    const followUp = getFollowUpMetadata(state.selectedRun);
    const adaptiveChange = selectedReport.adaptive_change_summary || null;
    const sourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;

    dom.reportMetadata.innerHTML = `
      <h4>${escapeHtml(selectedReport.title)}</h4>
      <p>${escapeHtml(selectedReport.description)}</p>
      <div class="inline-metrics">
        <span class="metric-pill">${escapeHtml(`Run ${state.selectedRunId || "not selected"}`)}</span>
        <span class="metric-pill">${escapeHtml(selectedReport.version_label)}</span>
        <span class="metric-pill">${escapeHtml(`Findings ${selectedReport.included_findings.count}`)}</span>
        <span class="metric-pill">${escapeHtml(`Assets ${selectedReport.included_inventory.host_count || 0}`)}</span>
        <span class="metric-pill">${escapeHtml(`Services ${selectedReport.included_inventory.service_count || 0}`)}</span>
        <span class="metric-pill">${escapeHtml(`Endpoints ${selectedReport.included_inventory.endpoint_count || 0}`)}</span>
        <span class="metric-pill">${escapeHtml(`Evidence ${Math.round((selectedReport.evidence_status.completeness_ratio || 0) * 100)}%`)}</span>
      </div>
      <p class="split-top">${escapeHtml(`Hash ${selectedReport.content_sha256.slice(0, 16)}…`)}</p>
      <p class="micro-copy">${escapeHtml(`Run profile ${selectedReport.source_scope_profile.run_profile} · assessment ${selectedReport.source_scope_profile.assessment_type || "n/a"}`)}</p>
      ${
        executionPlan
          ? `<p class="micro-copy">${escapeHtml(`Execution lane ${executionPlan.profileName} · tools ${executionPlan.toolsLabel} · approvals ${executionPlan.requiredApprovals}`)}</p>`
          : ""
      }
      ${
        selectedReport.included_findings.count === 0 && (selectedReport.included_inventory.host_count || 0) > 0
          ? `<div class="section-note split-top" data-testid="report-discovery-note">
              <strong>Discovery-aware reporting is active</strong>
              <p>${escapeHtml(`This run discovered ${selectedReport.included_inventory.host_count || 0} assets even though no vulnerability findings were created yet. The report variants still include the mapped inventory, coverage context, and evidence posture.`)}</p>
            </div>`
          : ""
      }
      ${
        adaptiveChange?.active
          ? `<div class="section-note split-top" data-testid="report-adaptive-change-note">
              <strong>Codex-reviewed adaptive coverage</strong>
              <p>${escapeHtml(adaptiveChange.summary_line || "Adaptive change context is available for this report.")}</p>
              <p class="micro-copy">${escapeHtml(adaptiveChange.governance_line || "Pack governance remains tied to validation, approval, and deployment state.")}</p>
              ${
                adaptiveChange.latest_task
                  ? `<p class="micro-copy">${escapeHtml(
                      `Latest task ${adaptiveChange.latest_task.id} · ${adaptiveChange.latest_task.task_type} · ${adaptiveChange.latest_task.status} / ${adaptiveChange.latest_task.validation_status}`
                    )}</p>`
                  : ""
              }
              <p class="micro-copy">${escapeHtml(adaptiveChange.finding_line || "No pack-linked findings recorded yet.")}</p>
            </div>`
          : ""
      }
      ${
        followUp
          ? `<div class="section-note split-top" data-testid="report-follow-up-note">
              <strong>${escapeHtml(followUpStrategyLabel(followUp.strategy))} lineage is attached</strong>
              <p>${escapeHtml(
                sourceRun
                  ? `This report belongs to a controlled follow-up run derived from ${sourceRun.profile?.name || sourceRun.id}.`
                  : "This report belongs to a controlled follow-up run derived from an earlier inventory snapshot."
              )}</p>
              <p class="micro-copy">${escapeHtml(
                followUp.rationale || "The run reused prior discovery output so follow-up validation stayed targeted and reproducible."
              )}</p>
              <p class="micro-copy">${escapeHtml(
                `Source inventory ${followUp.source_inventory_snapshot_id || state.selectedRun?.source_inventory_snapshot_id || "n/a"}`
              )}</p>
              ${
                sourceRun
                  ? `<div class="panel-actions split-top">
                      <button class="action ghost" type="button" data-report-load-source-run="${escapeHtml(sourceRun.id)}" data-testid="report-load-source-run">Load Source Run</button>
                      <button class="action ghost" type="button" data-report-open-source-surface="${escapeHtml(sourceRun.id)}">Open Source Surface</button>
                    </div>`
                  : ""
              }
            </div>`
          : ""
      }
      <p class="micro-copy">${escapeHtml("Downloads always apply to the currently selected run in the active dossier.")}</p>
      <p class="micro-copy">${escapeHtml(selectedReport.methodology_references.join(" · "))}</p>
    `;

    dom.reportActions.innerHTML = `
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
      <button class="action primary" data-report-preview="markdown" type="button" data-testid="report-preview-markdown">Generate Markdown Preview</button>
      <button class="action secondary" data-report-preview="html" type="button" data-testid="report-preview-html">Generate HTML Preview</button>
      <a class="action ghost" href="${selectedReport.export_paths.markdown}" download="${escapeHtml(selectedReport.download_names?.markdown || "")}" rel="noreferrer" data-testid="report-download-markdown">Download Markdown</a>
      <a class="action ghost" href="${selectedReport.export_paths.html}" download="${escapeHtml(selectedReport.download_names?.html || "")}" rel="noreferrer" data-testid="report-download-html">Download HTML</a>
      ${
        selectedReport.export_paths.pdf
          ? `<a class="action ghost" href="${selectedReport.export_paths.pdf}" download="${escapeHtml(selectedReport.download_names?.pdf || "")}" rel="noreferrer" data-testid="report-download-pdf">Download PDF</a>`
          : ""
      }
    `;
    dom.reportActions.querySelectorAll("[data-report-preview]").forEach((button) => {
      button.addEventListener("click", () =>
        previewReport(button.dataset.reportPreview).catch(runtime.actions.handleError)
      );
    });
    dom.reportMetadata.querySelectorAll("[data-report-load-source-run]").forEach((button) => {
      button.addEventListener("click", async () => {
        state.selectedRunId = button.dataset.reportLoadSourceRun;
        await runtime.actions.loadSelectedRun?.();
        runtime.actions.renderAll?.();
      });
    });
    dom.reportMetadata.querySelectorAll("[data-report-open-source-surface]").forEach((button) => {
      button.addEventListener("click", async () => {
        state.selectedRunId = button.dataset.reportOpenSourceSurface;
        await runtime.actions.loadSelectedRun?.();
        runtime.actions.navigateToScreen?.("surface-map");
      });
    });

    if (state.loading.reportPreview) {
      dom.reportPreview.textContent = "Generating report preview...";
      dom.reportFrame.srcdoc = reportPlaceholder("Generating HTML preview…", "color:#182535");
    } else if (!state.reportPreview) {
      dom.reportPreview.textContent =
        "Generate a markdown preview to inspect the selected report variant here.";
    } else {
      dom.reportPreview.textContent = state.reportPreview;
    }

    if (!state.loading.reportPreview && !state.reportHtml) {
      dom.reportFrame.srcdoc = reportPlaceholder(
        "Generate an HTML preview to render the report here.",
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
          `/api/v1/runs/${state.selectedRunId}/report?format=html&variant=${state.reportVariant}`,
          { raw: true }
        );
        dom.reportFrame.srcdoc = state.reportHtml;
        runtime.actions.pushStatus?.(
          `HTML preview generated for the ${state.reportVariant} report.`,
          "info"
        );
      } else {
        state.reportPreview = await api(
          `/api/v1/runs/${state.selectedRunId}/report?format=markdown&variant=${state.reportVariant}`,
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

  function renderReportComparison(selectedReport) {
    const comparison = runtime.actions.compareRuns?.(
      state.selectedRunId,
      state.comparisonBaselineRunId
    );
    if (!comparison) {
      return emptyState("Select a baseline run in History & Comparison to compare report posture.");
    }
    return `
      <h4>${escapeHtml(selectedReport.title)}</h4>
      <p>${escapeHtml(`${comparison.newCount} new findings · ${comparison.fixedCount} fixed since the baseline run`)}</p>
      <p>${escapeHtml(`${comparison.persistingCount} findings still open · ${comparison.worsenedCount} worsened`)}</p>
      <p class="micro-copy">${escapeHtml(`Pack changed: ${comparison.packChanged ? "yes" : "no"} · baseline ${comparison.baselineLabel}`)}</p>
    `;
  }

  return {
    previewReport,
    renderReportCenter,
  };
}

function getFollowUpMetadata(run) {
  const followUp = run?.configuration_json?.follow_up;
  return typeof followUp === "object" && followUp !== null ? followUp : null;
}
