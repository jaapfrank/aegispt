import { emptyState, escapeHtml, renderBadgeList } from "./shared.js";

function normalizeProgress(progress) {
  if (!progress || typeof progress !== "object") return null;
  const stages = Array.isArray(progress.stages) ? progress.stages : [];
  if (!stages.length) return null;
  return {
    ...progress,
    stages,
    matrix: Array.isArray(progress.matrix) && progress.matrix.length ? progress.matrix : stages,
  };
}

function stageDisplayLabel(stage) {
  const displayState = String(stage?.display_state || "").toLowerCase();
  if (displayState === "complete") return "Complete";
  if (displayState === "current") return "Current";
  return "Untested";
}

function stageCoverageLabel(stage) {
  const status = String(stage?.status || "untested").toLowerCase();
  if (status === "confirmed") {
    const count = Number(stage?.finding_count || 0);
    return `${count} finding${count === 1 ? "" : "s"}`;
  }
  if (status === "tested") {
    const count = Number(stage?.task_count || 0) + Number(stage?.phase_count || 0);
    return `${count} tested source${count === 1 ? "" : "s"}`;
  }
  return "No coverage";
}

function techniqueStatusLabel(status) {
  const normalized = String(status || "untested").toLowerCase();
  if (normalized === "confirmed") return "Confirmed";
  if (normalized === "tested") return "Tested";
  return "Untested";
}

function matrixTechniqueCounts(matrix) {
  return matrix
    .flatMap((stage) => (Array.isArray(stage.techniques) ? stage.techniques : []))
    .reduce(
      (counts, technique) => {
        const status = String(technique?.status || "untested").toLowerCase();
        counts[status] = (counts[status] || 0) + 1;
        return counts;
      },
      { confirmed: 0, tested: 0, untested: 0 }
    );
}

export function renderKillChainProgressStrip(progress, options = {}) {
  const normalized = normalizeProgress(progress);
  if (!normalized) return "";
  const testId = options.testId || "kill-chain-progress";
  const title = options.title || "Kill Chain Progress";
  const progressPercentage = Math.max(0, Math.min(100, Number(normalized.progress_percentage || 0)));
  const currentLabel = normalized.current_stage_label || normalized.highest_reached_stage_label || "Recon";
  const completed = Number(normalized.completed_stage_count || 0);
  const total = Math.max(1, Number(normalized.total_stage_count || normalized.stages.length || 1));

  return `
    <div class="detail-surface emphasis-surface split-top kill-chain-panel" data-testid="${escapeHtml(testId)}">
      <div class="task-activity-header">
        <div>
          <h4>${escapeHtml(title)}</h4>
          <p class="mission-status-subline">${escapeHtml(`${completed} of ${total} stages reached · current ${currentLabel}`)}</p>
        </div>
        <div class="kill-chain-score" aria-label="${escapeHtml(`Kill chain progress ${progressPercentage}%`)}">
          <strong>${escapeHtml(String(progressPercentage))}</strong>
          <span>%</span>
        </div>
      </div>
      <div class="kill-chain-progress-track" aria-hidden="true">
        <span style="width:${progressPercentage}%"></span>
      </div>
      <div class="kill-chain-strip split-top" data-testid="${escapeHtml(`${testId}-strip`)}">
        ${normalized.stages
          .map((stage) => {
            const displayState = String(stage.display_state || "future").toLowerCase();
            const coverageStatus = String(stage.status || "untested").toLowerCase();
            return `
              <div
                class="kill-chain-stage ${escapeHtml(displayState)} coverage-${escapeHtml(coverageStatus)}"
                data-testid="kill-chain-stage"
                data-kill-chain-stage="${escapeHtml(stage.id || "")}"
                data-stage-display="${escapeHtml(displayState)}"
                data-stage-coverage="${escapeHtml(coverageStatus)}"
                title="${escapeHtml(stage.summary || "")}"
              >
                <span class="kill-chain-stage-dot" aria-hidden="true"></span>
                <div>
                  <strong>${escapeHtml(stage.label || stage.tactic_name || "Stage")}</strong>
                  <small>${escapeHtml(`${stage.tactic_id || ""} · ${stageDisplayLabel(stage)} · ${stageCoverageLabel(stage)}`)}</small>
                </div>
              </div>
            `;
          })
          .join("")}
      </div>
      ${renderBadgeList(
        [
          `${Number(normalized.confirmed_stage_count || 0)} confirmed`,
          `${Number(normalized.tested_stage_count || 0)} tested`,
          normalized.boundary?.advisory_only ? "Advisory only" : null,
        ],
        "compact-badge-list split-top"
      )}
    </div>
  `;
}

export function renderKillChainMatrix(progress, options = {}) {
  const normalized = normalizeProgress(progress);
  const testId = options.testId || "dossier-mitre-attack-matrix";
  if (!normalized) {
    return `
      <div class="detail-surface split-top" data-testid="${escapeHtml(testId)}">
        ${emptyState("MITRE ATT&CK coverage appears after mapped findings or completed assessment phases exist.")}
      </div>
    `;
  }
  const counts = matrixTechniqueCounts(normalized.matrix);
  return `
    <div class="detail-surface split-top attack-matrix-panel" data-testid="${escapeHtml(testId)}">
      <div class="task-activity-header">
        <div>
          <h4>MITRE ATT&CK Coverage</h4>
          <p class="mission-status-subline">${escapeHtml(`${normalized.progress_percentage || 0}% progress · ${normalized.current_stage_label || "No current stage"}`)}</p>
        </div>
        <div class="inline-metrics">
          <span class="metric-pill status-ok">${escapeHtml(`${counts.confirmed || 0} Confirmed`)}</span>
          <span class="metric-pill status-review">${escapeHtml(`${counts.tested || 0} Tested`)}</span>
          <span class="metric-pill">${escapeHtml(`${counts.untested || 0} Untested`)}</span>
        </div>
      </div>
      <div class="attack-matrix-grid split-top">
        ${normalized.matrix
          .map((stage) => {
            const techniques = Array.isArray(stage.techniques) ? stage.techniques : [];
            const coverageStatus = String(stage.status || "untested").toLowerCase();
            return `
              <section
                class="attack-matrix-tactic coverage-${escapeHtml(coverageStatus)}"
                data-testid="attack-matrix-tactic"
                data-attack-stage="${escapeHtml(stage.stage_id || stage.id || "")}"
                data-stage-coverage="${escapeHtml(coverageStatus)}"
              >
                <header>
                  <span>${escapeHtml(stage.tactic_id || "")}</span>
                  <strong>${escapeHtml(stage.tactic_name || stage.label || "ATT&CK tactic")}</strong>
                </header>
                <div class="attack-technique-list">
                  ${techniques
                    .map((technique) => {
                      const status = String(technique.status || "untested").toLowerCase();
                      return `
                        <div
                          class="attack-technique ${escapeHtml(status)}"
                          data-testid="attack-matrix-technique"
                          data-technique-status="${escapeHtml(status)}"
                        >
                          <span>${escapeHtml(technique.technique_id || "")}</span>
                          <strong>${escapeHtml(technique.name || "Technique")}</strong>
                          <small>${escapeHtml(`${techniqueStatusLabel(status)} · ${Number(technique.source_count || 0)} source${Number(technique.source_count || 0) === 1 ? "" : "s"}`)}</small>
                        </div>
                      `;
                    })
                    .join("")}
                </div>
              </section>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}
