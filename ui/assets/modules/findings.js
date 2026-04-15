import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  findingOriginLabel,
  renderSignalList,
  severityPill,
  severityRank,
  statusPill,
} from "./shared.js";

function filterFindings(allFindings) {
  return allFindings
    .filter((finding) => {
      if (state.findingFilters.runId !== "all" && finding._runId !== state.findingFilters.runId) return false;
      if (state.findingFilters.severity !== "all" && finding.severity !== state.findingFilters.severity) return false;
      if (state.findingFilters.origin !== "all" && finding.finding_origin !== state.findingFilters.origin) return false;
      if (state.findingFilters.status !== "all" && finding.status !== state.findingFilters.status) return false;
      if (
        state.findingFilters.methodology !== "all" &&
        !(finding.methodology_tags || []).includes(state.findingFilters.methodology)
      ) {
        return false;
      }
      return true;
    })
    .sort((left, right) => {
      const leftRank = severityRank(left.severity);
      const rightRank = severityRank(right.severity);
      if (leftRank !== rightRank) return leftRank - rightRank;
      return left.title.localeCompare(right.title);
    });
}

function groupFindings(findings, groupBy) {
  return findings.reduce((groups, finding) => {
    let key = "Ungrouped";
    if (groupBy === "severity") key = finding.severity;
    if (groupBy === "origin") key = finding.finding_origin;
    if (groupBy === "status") key = finding.status;
    if (groupBy === "methodology") key = finding.methodology_tags?.[0] || "Not tagged";
    if (groupBy === "run") {
      key = runtime.state.mission.runs.find((run) => run.id === finding._runId)?.profile?.name || "Unknown run";
    }
    groups[key] = groups[key] || [];
    groups[key].push(finding);
    return groups;
  }, {});
}

async function selectFinding(findingId) {
  state.selectedFindingId = findingId;
  state.loading.findingDetail = true;
  state.loading.evidenceDetail = true;
  renderFindingsTheater();
  renderEvidenceReplay();
  try {
    await runtime.actions.loadSelectedFinding?.();
  } finally {
    state.loading.findingDetail = false;
    state.loading.evidenceDetail = false;
    renderFindingsTheater();
    renderEvidenceReplay();
  }
}

export function createFindingsModule() {
  function renderFindingsTheater() {
    const allFindings = runtime.actions.engagementFindings?.() || [];
    const methodologyOptions = Array.from(
      new Set(allFindings.flatMap((finding) => finding.methodology_tags || []))
    ).sort();

    dom.findingsFilterBar.innerHTML = `
      <label class="field compact">
        <span>Run</span>
        <select id="finding-filter-run" data-testid="finding-filter-run">
          <option value="all">All Runs</option>
          ${state.mission.runs
            .map(
              (run) =>
                `<option value="${run.id}" ${state.findingFilters.runId === run.id ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Severity</span>
        <select id="finding-filter-severity">
          ${["all", "critical", "high", "medium", "low", "info", "unknown"]
            .map(
              (value) =>
                `<option value="${value}" ${state.findingFilters.severity === value ? "selected" : ""}>${escapeHtml(value)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Origin</span>
        <select id="finding-filter-origin">
          ${["all", "standard", "adaptive_pack"]
            .map(
              (value) =>
                `<option value="${value}" ${state.findingFilters.origin === value ? "selected" : ""}>${escapeHtml(value)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Status</span>
        <select id="finding-filter-status">
          ${["all", "open", "triaged", "in_progress", "resolved", "accepted_risk", "false_positive", "reopened"]
            .map(
              (value) =>
                `<option value="${value}" ${state.findingFilters.status === value ? "selected" : ""}>${escapeHtml(value)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Methodology</span>
        <select id="finding-filter-methodology">
          <option value="all">All</option>
          ${methodologyOptions
            .map(
              (value) =>
                `<option value="${escapeHtml(value)}" ${state.findingFilters.methodology === value ? "selected" : ""}>${escapeHtml(value)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Group By</span>
        <select id="finding-filter-group-by">
          ${["severity", "origin", "status", "methodology", "run"]
            .map(
              (value) =>
                `<option value="${value}" ${state.findingFilters.groupBy === value ? "selected" : ""}>${escapeHtml(value)}</option>`
            )
            .join("")}
        </select>
      </label>
    `;

    dom.findingsFilterBar.querySelectorAll("select").forEach((select) => {
      select.addEventListener("change", () => {
        state.findingFilters = {
          runId: document.getElementById("finding-filter-run").value,
          severity: document.getElementById("finding-filter-severity").value,
          origin: document.getElementById("finding-filter-origin").value,
          status: document.getElementById("finding-filter-status").value,
          methodology: document.getElementById("finding-filter-methodology").value,
          groupBy: document.getElementById("finding-filter-group-by").value,
        };
        renderFindingsTheater();
      });
    });

    const filtered = filterFindings(allFindings);
    if (!filtered.length) {
      state.selectedFindingId = null;
      state.selectedFindingTheater = null;
      state.selectedFindingEvidence = null;
    }
    if (filtered.length && !filtered.some((finding) => finding.id === state.selectedFindingId)) {
      selectFinding(filtered[0].id).catch(runtime.actions.handleError);
    }

    const grouped = groupFindings(filtered, state.findingFilters.groupBy);
    dom.findingsGroupList.innerHTML = Object.entries(grouped).length
      ? Object.entries(grouped)
          .map(
            ([group, items]) => `
              <div class="list-card">
                <h4>${escapeHtml(group)}</h4>
                <p class="micro-copy">${escapeHtml(`${items.length} finding${items.length === 1 ? "" : "s"}`)}</p>
                <div class="finding-stack split-top">
                  ${items
                    .map(
                      (finding) => `
                        <div class="list-card finding-card severity-${escapeHtml(String(finding.severity || "unknown").toLowerCase())} ${finding.id === state.selectedFindingId ? "selected" : ""}" data-finding-pick="${finding.id}" data-testid="finding-card">
                          <h4>${escapeHtml(finding.title)}</h4>
                          <div class="inline-metrics">
                            ${severityPill(finding.severity)}
                            ${statusPill(finding.status)}
                            <span class="metric-pill">${escapeHtml(findingOriginLabel(finding.finding_origin))}</span>
                          </div>
                          <p class="micro-copy">${escapeHtml(finding.target_id)}</p>
                        </div>
                      `
                    )
                    .join("")}
                </div>
              </div>
            `
          )
          .join("")
      : emptyState("No findings match the current filters.");

    dom.findingsGroupList.querySelectorAll("[data-finding-pick]").forEach((item) => {
      item.addEventListener("click", () => {
        selectFinding(item.dataset.findingPick).catch(runtime.actions.handleError);
      });
    });

    if (state.loading.findingDetail) {
      dom.findingTheaterDetail.innerHTML = `
        <div class="detail-surface" data-testid="finding-detail-loading">
          <h4>Loading selected finding</h4>
          <p>Refreshing business impact, methodology, remediation, and verification guidance.</p>
        </div>
      `;
      return;
    }

    if (!state.selectedFindingTheater) {
      dom.findingTheaterDetail.innerHTML = emptyState(
        "Select a finding to inspect impact, methodology, evidence posture, and next steps."
      );
      return;
    }

    const theater = state.selectedFindingTheater;
    dom.findingTheaterDetail.innerHTML = `
      <div class="panel-head">
        <div>
          <p class="eyebrow">Selected Finding</p>
          <h4>${escapeHtml(theater.finding.title)}</h4>
        </div>
        <div class="pill-grid">
          ${severityPill(theater.finding.severity)}
          ${statusPill(theater.finding.status)}
          <span class="badge">${escapeHtml(theater.confidence_label)} confidence</span>
        </div>
      </div>
      <p>${escapeHtml(theater.business_impact)}</p>
      <p>${escapeHtml(theater.technical_details)}</p>
      <div class="detail-grid split-top">
        <div class="detail-surface">
          <h4>Methodology</h4>
          <p>${escapeHtml(`PTES ${theater.methodology.ptes_label || "Not assigned"}`)}</p>
          <p>${escapeHtml(`NIST ${theater.methodology.nist_label || "Not assigned"}`)}</p>
          <p>${escapeHtml(`WSTG ${theater.methodology.wstg_reference || "Not assigned"}`)}</p>
          <p class="micro-copy">${escapeHtml(`Control family: ${theater.methodology.control_family || "Not assigned"}`)}</p>
        </div>
        <div class="detail-surface">
          <h4>Provenance</h4>
          <p>${escapeHtml(`Origin: ${theater.provenance.origin}`)}</p>
          <p>${escapeHtml(`Pack version: ${theater.provenance.source_pack_version || "Standard coverage"}`)}</p>
          <p class="micro-copy">${escapeHtml(`Inventory ${theater.provenance.source_inventory_snapshot_id || "n/a"} · Relevance ${theater.provenance.source_relevance_decision_id || "n/a"}`)}</p>
        </div>
        <div class="detail-surface">
          <h4>Remediation</h4>
          <p>${escapeHtml(theater.remediation.priority)}</p>
          <p>${escapeHtml(theater.remediation.summary)}</p>
          <p class="micro-copy">${escapeHtml(theater.remediation.detail)}</p>
        </div>
        <div class="detail-surface">
          <h4>Verification</h4>
          <p>${escapeHtml(theater.verification_status)}</p>
          <p>${escapeHtml(theater.evidence_summary)}</p>
          <p class="micro-copy">${escapeHtml(`Exploitability: ${theater.exploitability || "Not recorded"}`)}</p>
        </div>
      </div>
      <div class="section-note split-top">
        <strong>Operator Readout</strong>
        <p>${escapeHtml(`This item is currently ${theater.finding.status} and originated from ${findingOriginLabel(theater.provenance.origin)} coverage against ${theater.finding.target_id}.`)}</p>
      </div>
      <div class="detail-surface split-top">
        <h4>Next Steps</h4>
        <ul>${theater.next_steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
      </div>
      <div class="action-row split-top">
        ${["triaged", "in_progress", "resolved"]
          .map(
            (status) =>
              `<button class="action ghost finding-status-btn" type="button" data-status="${status}">Mark ${escapeHtml(status.replace("_", " "))}</button>`
          )
          .join("")}
        <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence Replay</button>
      </div>
    `;

    dom.findingTheaterDetail.querySelectorAll(".finding-status-btn").forEach((button) => {
      button.addEventListener("click", async () => {
        await api(`/api/v1/findings/${state.selectedFindingId}`, {
          method: "PATCH",
          body: { status: button.dataset.status },
        });
        runtime.actions.pushStatus?.(`Finding status updated to ${button.dataset.status}.`, "success");
        await runtime.actions.refreshSelectedEngagement?.();
      });
    });
  }

  function renderEvidenceReplay() {
    if (state.loading.evidenceDetail) {
      dom.evidenceOverview.innerHTML = `
        <div class="detail-surface" data-testid="evidence-loading">
          <h4>Loading evidence replay</h4>
          <p>Refreshing executions, artifacts, and provenance for the selected finding.</p>
        </div>
      `;
      dom.evidenceExecutions.innerHTML = emptyState("Related executions are loading.");
      dom.evidenceArtifacts.innerHTML = emptyState("Replay artifacts are loading.");
      dom.evidenceLineage.innerHTML = emptyState("Inventory, relevance, and pack lineage are loading.");
      return;
    }

    if (!state.selectedFindingEvidence) {
      dom.evidenceOverview.innerHTML = emptyState(
        "Select a finding in Findings Theater to inspect its evidence lineage."
      );
      dom.evidenceExecutions.innerHTML = emptyState("Related executions appear here.");
      dom.evidenceArtifacts.innerHTML = emptyState("Artifacts and replay details appear here.");
      dom.evidenceLineage.innerHTML = emptyState("Inventory, relevance, and pack lineage appear here.");
      return;
    }

    const evidence = state.selectedFindingEvidence;
    dom.evidenceOverview.innerHTML = `
      <h4>${escapeHtml(evidence.finding.title)}</h4>
      <div class="inline-metrics">
        ${severityPill(evidence.finding.severity)}
        ${statusPill(evidence.finding.status)}
        <span class="metric-pill">${escapeHtml(findingOriginLabel(evidence.finding.finding_origin))}</span>
      </div>
      <p>${escapeHtml(`Evidence ref: ${evidence.evidence_ref}`)}</p>
      <p class="micro-copy">${escapeHtml(`PTES ${evidence.methodology_references.ptes || "n/a"} · WSTG ${evidence.methodology_references.wstg || "n/a"}`)}</p>
      ${renderSignalList(
        [
          evidence.inventory_source.snapshot_id
            ? `Inventory snapshot ${evidence.inventory_source.snapshot_id} is linked to this replay trail.`
            : "Inventory snapshot provenance is not available for this finding.",
          evidence.pack_provenance.version
            ? `Adaptive pack ${evidence.pack_provenance.version} contributed to this finding path.`
            : "This evidence trail came from standard coverage rather than a generated pack.",
        ],
        "good",
        ""
      )}
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="findings-theater">Back to Finding</button>
        <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
      </div>
    `;

    dom.evidenceExecutions.innerHTML = evidence.related_executions.length
      ? evidence.related_executions
          .map(
            (execution) => `
              <div class="artifact-card ${execution.task_id === state.selectedTaskId ? "selected" : ""}" data-task-pick="${execution.task_id}" data-testid="evidence-execution">
                <h4>${escapeHtml(`${execution.tool} · ${execution.target_id}`)}</h4>
                <p>${statusPill(execution.task_status)} exit ${execution.exit_code} · ${escapeHtml(execution.tool_version)}</p>
                ${execution.stdout_excerpt ? `<pre class="report-preview split-top">${escapeHtml(execution.stdout_excerpt)}</pre>` : ""}
                ${execution.stderr_excerpt ? `<pre class="report-preview split-top">${escapeHtml(execution.stderr_excerpt)}</pre>` : ""}
              </div>
            `
          )
          .join("")
      : emptyState("No related task executions were matched to this finding.");
    dom.evidenceExecutions.querySelectorAll("[data-task-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedTaskId = item.dataset.taskPick;
        await runtime.actions.loadSelectedTask?.();
        renderEvidenceReplay();
      });
    });

    const artifacts = evidence.related_executions.flatMap((execution) => execution.artifacts);
    dom.evidenceArtifacts.innerHTML = artifacts.length
      ? artifacts
          .map(
            (artifact) => `
              <div class="artifact-card">
                <h4>${escapeHtml(artifact.name)}</h4>
                <p>${escapeHtml(`${artifact.kind} · ${artifact.redaction_state}`)}</p>
                <p class="micro-copy">${escapeHtml(artifact.uri)}</p>
                <a class="link-like" href="${artifact.download_path}" target="_blank" rel="noreferrer">Download Artifact</a>
              </div>
            `
          )
          .join("")
      : emptyState("No replay artifacts are attached to the selected finding.");

    dom.evidenceLineage.innerHTML = `
      <h4>Pack Provenance</h4>
      <p>${escapeHtml(evidence.pack_provenance.name ? `${evidence.pack_provenance.name} ${evidence.pack_provenance.version}` : "Standard coverage")}</p>
      <p class="micro-copy">${escapeHtml(`Inventory ${evidence.inventory_source.snapshot_id || "n/a"} · Relevance ${evidence.relevance_source.decision_id || "n/a"}`)}</p>
      <p class="micro-copy">${escapeHtml(`Validation history entries: ${evidence.validation_history.length}`)}</p>
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="pack-forge">Open Pack Forge</button>
      </div>
    `;
  }

  return {
    filterFindings,
    groupFindings,
    renderEvidenceReplay,
    renderFindingsTheater,
  };
}
