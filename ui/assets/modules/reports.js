import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import { emptyState, escapeHtml, statusPill } from "./shared.js";

export function createReportsModule() {
  function renderReportCenter() {
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
      dom.reportMetadata.innerHTML = emptyState("Select or create a run to unlock report workflows.");
      dom.reportActions.innerHTML = "";
      if (!state.reportPreview) dom.reportPreview.textContent = "No report preview loaded yet.";
      if (!state.reportHtml) {
        dom.reportFrame.srcdoc =
          "<div style='padding:24px;font-family:Aptos,sans-serif'>No HTML report preview loaded.</div>";
      }
      dom.reportCompare.innerHTML = emptyState(
        "Choose a current and baseline run to compare report posture."
      );
      return;
    }

    dom.reportMetadata.innerHTML = `
      <h4>${escapeHtml(selectedReport.title)}</h4>
      <p>${escapeHtml(selectedReport.description)}</p>
      <div class="inline-metrics">
        <span class="metric-pill">${escapeHtml(selectedReport.version_label)}</span>
        <span class="metric-pill">${escapeHtml(`Findings ${selectedReport.included_findings.count}`)}</span>
        <span class="metric-pill">${escapeHtml(`Evidence ${Math.round((selectedReport.evidence_status.completeness_ratio || 0) * 100)}%`)}</span>
      </div>
      <p class="split-top">${escapeHtml(`Hash ${selectedReport.content_sha256.slice(0, 16)}…`)}</p>
      <p class="micro-copy">${escapeHtml(`Run profile ${selectedReport.source_scope_profile.run_profile} · assessment ${selectedReport.source_scope_profile.assessment_type || "n/a"}`)}</p>
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
      <a class="action ghost" href="${selectedReport.export_paths.markdown}" target="_blank" rel="noreferrer">Download Markdown</a>
      <a class="action ghost" href="${selectedReport.export_paths.html}" target="_blank" rel="noreferrer">Download HTML</a>
      ${
        selectedReport.export_paths.pdf
          ? `<a class="action ghost" href="${selectedReport.export_paths.pdf}" target="_blank" rel="noreferrer" data-testid="report-download-pdf">Download PDF</a>`
          : ""
      }
    `;
    dom.reportActions.querySelectorAll("[data-report-preview]").forEach((button) => {
      button.addEventListener("click", () =>
        previewReport(button.dataset.reportPreview).catch(runtime.actions.handleError)
      );
    });

    if (state.loading.reportPreview) {
      dom.reportPreview.textContent = "Generating report preview...";
      dom.reportFrame.srcdoc =
        "<div style='padding:24px;font-family:Aptos,sans-serif;color:#182535'>Generating HTML preview…</div>";
    } else if (!state.reportPreview) {
      dom.reportPreview.textContent =
        "Generate a markdown preview to inspect the selected report variant here.";
    } else {
      dom.reportPreview.textContent = state.reportPreview;
    }

    if (!state.loading.reportPreview && !state.reportHtml) {
      dom.reportFrame.srcdoc =
        "<div style='padding:24px;font-family:Aptos,sans-serif;color:#182535'>Generate an HTML preview to render the report here.</div>";
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
