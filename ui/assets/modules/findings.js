import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  findingOriginLabel,
  followUpStrategyLabel,
  renderBadgeList,
  renderSignalList,
  renderTargetSummary,
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
    const selectedRun = state.selectedRun;
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
      : renderNoFindingsState(selectedRun, allFindings);

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
      dom.findingTheaterDetail.innerHTML = renderNoFindingDetailState(selectedRun, allFindings);
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
          ${renderRemediationTracking(theater.remediation)}
          ${renderLinkedRetests(theater.remediation)}
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
      const runEvidence = buildRunEvidenceContext();
      if (!runEvidence) {
        dom.evidenceOverview.innerHTML = emptyState(
          state.selectedRun
            ? "Select a finding in Findings Theater to inspect its evidence lineage, or open Explorer for run-level context."
            : "Create a mission first. Evidence Replay unlocks after a run or finding has recorded task, artifact, or inventory evidence."
        );
        dom.evidenceExecutions.innerHTML = emptyState(
          state.selectedRun
            ? "Related executions appear here after a finding or run-level evidence context is selected."
            : "Execution evidence appears here after the first mission is created and dispatched."
        );
        dom.evidenceArtifacts.innerHTML = emptyState(
          state.selectedRun
            ? "Artifacts and replay details appear here for the selected finding or run."
            : "Replay artifacts appear here after a run records tool output."
        );
        dom.evidenceLineage.innerHTML = emptyState(
          state.selectedRun
            ? "Inventory, relevance, and pack lineage appear here for the selected evidence context."
            : "Inventory, relevance, and pack lineage appear here after mission creation and run output."
        );
        return;
      }

      dom.evidenceOverview.innerHTML = `
        <div class="detail-surface" data-testid="evidence-run-summary">
          <h4>${escapeHtml(runEvidence.title)}</h4>
          <div class="inline-metrics">
            ${statusPill(runEvidence.run.status)}
            <span class="metric-pill">${escapeHtml(`${runEvidence.taskCount} planned check${runEvidence.taskCount === 1 ? "" : "s"}`)}</span>
            <span class="metric-pill">${escapeHtml(`${runEvidence.hostCount} hosts`)}</span>
            <span class="metric-pill">${escapeHtml(`${runEvidence.serviceCount} services`)}</span>
            <span class="metric-pill">${escapeHtml(`${runEvidence.endpointCount} endpoints`)}</span>
          </div>
          <p class="split-top">${escapeHtml(runEvidence.summary)}</p>
          <p class="micro-copy">${escapeHtml(runEvidence.detail)}</p>
          ${
            runEvidence.methodologyReferences.length
              ? `<p class="micro-copy">${escapeHtml(runEvidence.methodologyReferences.join(" · "))}</p>`
              : ""
          }
          ${renderSignalList(runEvidence.signals, "good", "Run-level evidence context will appear here once task or inventory data exists.")}
          <div class="panel-actions">
            <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
            <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
            <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
          </div>
        </div>
      `;

      dom.evidenceExecutions.innerHTML = runEvidence.taskSummaries.length
        ? runEvidence.taskSummaries
            .map(
              (task) => `
                <div
                  class="artifact-card ${task.id === runEvidence.selectedTaskId ? "selected" : ""}"
                  data-task-pick="${task.id}"
                  data-testid="evidence-run-task"
                >
                  <h4>${escapeHtml(`${task.tool} · ${task.target}`)}</h4>
                  <p>${statusPill(task.status)} ${escapeHtml(task.executionLabel)}</p>
                  <p class="micro-copy">${escapeHtml(task.detail)}</p>
                  ${task.stdoutExcerpt ? `<pre class="report-preview split-top">${escapeHtml(task.stdoutExcerpt)}</pre>` : ""}
                  ${task.stderrExcerpt ? `<pre class="report-preview split-top">${escapeHtml(task.stderrExcerpt)}</pre>` : ""}
                </div>
              `
            )
            .join("")
        : emptyState("Run-level task evidence is not available yet.");
      dom.evidenceExecutions.querySelectorAll("[data-task-pick]").forEach((item) => {
        item.addEventListener("click", async () => {
          state.selectedTaskId = item.dataset.taskPick;
          await runtime.actions.loadSelectedTask?.();
          renderEvidenceReplay();
        });
      });

      dom.evidenceArtifacts.innerHTML = runEvidence.artifacts.length
        ? runEvidence.artifacts
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
        : emptyState("No artifacts are attached to the currently selected check yet.");

      dom.evidenceLineage.innerHTML = `
        <div class="detail-surface" data-testid="evidence-run-lineage">
          <h4>${escapeHtml(runEvidence.lineageTitle)}</h4>
          <p>${escapeHtml(runEvidence.lineageSummary)}</p>
          <p class="micro-copy">${escapeHtml(runEvidence.lineageDetail)}</p>
          ${renderBadgeList(runEvidence.lineageBadges, "compact-badge-list split-top")}
          <div class="panel-actions split-top">
            <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
            <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
          </div>
        </div>
      `;
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

function formatOptional(value, fallback = "Not recorded") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function humanizeRemediationState(value) {
  return formatOptional(value).replace(/_/g, " ");
}

function renderRemediationTracking(remediation) {
  const record = remediation?.record || null;
  if (!record) {
    return `
      <div class="section-note split-top" data-testid="finding-remediation-record">
        <strong>Tracking Record</strong>
        <p>No additive remediation record is attached yet. Keep the finding status separate until retest evidence confirms closure.</p>
      </div>
    `;
  }

  return `
    <div class="split-top" data-testid="finding-remediation-record">
      <div class="compact-definition-grid">
        <div><span>State</span><strong>${escapeHtml(humanizeRemediationState(record.state))}</strong></div>
        <div><span>Owner</span><strong>${escapeHtml(formatOptional(record.owner, "Unassigned"))}</strong></div>
        <div><span>Updated By</span><strong>${escapeHtml(formatOptional(record.updated_by))}</strong></div>
        <div><span>Updated</span><strong>${escapeHtml(formatOptional(record.updated_at))}</strong></div>
      </div>
      <p class="micro-copy split-top">${escapeHtml(formatOptional(record.notes, "No remediation notes recorded yet."))}</p>
    </div>
  `;
}

function renderLinkedRetests(remediation) {
  const linkedRetests = Array.isArray(remediation?.linked_retests) ? remediation.linked_retests : [];
  if (!linkedRetests.length) {
    return `
      <div class="section-note split-top" data-testid="finding-retest-linkage">
        <strong>Retest Linkage</strong>
        <p>No linked single-finding retest run is recorded yet.</p>
      </div>
    `;
  }

  const latestStatus = remediation.latest_retest_status || linkedRetests[0]?.status || "unknown";
  const proofReady = remediation.proof_of_resolution_ready
    ? "Proof-of-resolution output is ready for report review."
    : "Proof-of-resolution output is waiting on completed retest evidence.";
  return `
    <div class="section-note split-top" data-testid="finding-retest-linkage">
      <strong>Retest Linkage</strong>
      <p>${escapeHtml(`${linkedRetests.length} linked retest run${linkedRetests.length === 1 ? "" : "s"} · latest ${latestStatus}.`)}</p>
      <p class="micro-copy">${escapeHtml(proofReady)}</p>
      <div class="finding-stack split-top">
        ${linkedRetests
          .slice(0, 3)
          .map((retest) => renderLinkedRetestCard(retest))
          .join("")}
      </div>
    </div>
  `;
}

function renderLinkedRetestCard(retest) {
  const proofHref = `/api/v1/runs/${encodeURIComponent(retest.run_id)}/report?format=html&variant=retest`;
  return `
    <div class="artifact-card" data-testid="finding-linked-retest">
      <h4>${escapeHtml(`Retest ${formatOptional(retest.run_id)}`)}</h4>
      <div class="inline-metrics">
        ${statusPill(retest.status || "unknown")}
        <span class="metric-pill">${escapeHtml(formatOptional(retest.verification_state, "verification pending"))}</span>
        <span class="metric-pill">${escapeHtml(formatOptional(retest.remediation_state, "remediation not recorded"))}</span>
      </div>
      <p class="micro-copy split-top">${escapeHtml(`Source run ${formatOptional(retest.source_run_id)}`)}</p>
      <p class="micro-copy">${escapeHtml(`Verification timestamp: ${formatOptional(retest.verification_timestamp, "Pending retest completion")}`)}</p>
      <p class="micro-copy">${escapeHtml(`Tasks completed ${retest.completed_task_count || 0}, queued ${retest.queued_task_count || 0}, failed ${retest.failed_task_count || 0}`)}</p>
      ${retest.operator_notes ? `<p class="micro-copy">${escapeHtml(retest.operator_notes)}</p>` : ""}
      <a class="link-like" href="${escapeHtml(proofHref)}" target="_blank" rel="noreferrer">Open Proof-of-Resolution Report</a>
    </div>
  `;
}

function renderNoFindingsState(selectedRun, allFindings) {
  if (!selectedRun) {
    return emptyState(
      "Create a mission in Conversational Intake first. Findings appear here after a run records evidence-backed results."
    );
  }
  const runGuidance = buildInventoryRunGuidance(selectedRun);
  if (runGuidance) {
    return `
      <div class="detail-surface emphasis-surface" data-testid="${escapeHtml(runGuidance.testId)}">
        <h4>${escapeHtml(runGuidance.heading)}</h4>
        <p>${escapeHtml(runGuidance.summary)}</p>
        ${renderBadgeList([
          runGuidance.assessment,
          runGuidance.profile,
          runGuidance.strategyLabel,
          `${runGuidance.hostCount} hosts`,
          `${runGuidance.serviceCount} services`,
        ], "compact-badge-list split-top")}
        <p class="micro-copy split-top">${escapeHtml(runGuidance.detail)}</p>
        <div class="panel-actions split-top">
          <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
          <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
          <button class="action ghost" type="button" data-nav-screen="${escapeHtml(runGuidance.thirdActionScreen)}">${escapeHtml(runGuidance.thirdActionLabel)}</button>
        </div>
      </div>
    `;
  }

  if (allFindings.length) {
    return emptyState("No findings match the current filters.");
  }
  return emptyState("No findings exist yet for this engagement.");
}

function renderNoFindingDetailState(selectedRun, allFindings) {
  if (!selectedRun) {
    return emptyState(
      "Start with Intake, create the first mission, then select a finding here to review impact, evidence, and next steps."
    );
  }
  const runGuidance = buildInventoryRunGuidance(selectedRun);
  if (runGuidance) {
    return `
      <div class="detail-surface" data-testid="${escapeHtml(runGuidance.detailTestId)}">
        <h4>${escapeHtml(runGuidance.detailHeading)}</h4>
        <p>${escapeHtml(runGuidance.summary)}</p>
        <p class="micro-copy split-top">${escapeHtml(runGuidance.detail)}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Assessment</span><strong>${escapeHtml(runGuidance.assessment)}</strong></div>
          <div><span>Profile</span><strong>${escapeHtml(runGuidance.profile)}</strong></div>
          <div><span>Stage</span><strong>${escapeHtml(runGuidance.strategyLabel)}</strong></div>
          <div><span>Scope</span><strong>${escapeHtml(runGuidance.scope)}</strong></div>
          <div><span>Hosts</span><strong>${escapeHtml(String(runGuidance.hostCount))}</strong></div>
          <div><span>Services</span><strong>${escapeHtml(String(runGuidance.serviceCount))}</strong></div>
          <div><span>Endpoints</span><strong>${escapeHtml(String(runGuidance.endpointCount))}</strong></div>
        </div>
        <div class="panel-actions split-top">
          <button class="action ghost" type="button" data-nav-screen="surface-map">${escapeHtml(runGuidance.primaryActionLabel)}</button>
          <button class="action ghost" type="button" data-nav-screen="${escapeHtml(runGuidance.secondaryActionScreen)}">${escapeHtml(runGuidance.secondaryActionLabel)}</button>
        </div>
      </div>
    `;
  }

  if (allFindings.length) {
    return emptyState(
      "Select a finding to inspect impact, methodology, evidence posture, and next steps."
    );
  }
  return emptyState("No findings exist yet for this engagement.");
}

function buildInventoryRunGuidance(selectedRun) {
  if (!selectedRun) return null;
  const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
  if (!inventorySnapshot) return null;
  const followUp = getFollowUpMetadata(selectedRun);
  const discoveryOnly = isDiscoveryOnlyRun(selectedRun);
  if (!discoveryOnly && !followUp) return null;
  const hostCount = Number(inventorySnapshot.summary_json?.host_count || 0);
  const serviceCount = Number(inventorySnapshot.summary_json?.service_count || 0);
  const endpointCount = Number(inventorySnapshot.summary_json?.endpoint_count || 0);
  const followUpStrategy = followUp ? followUpStrategyLabel(followUp.strategy) : null;
  if (followUp) {
    return {
      heading: `No vulnerability findings were created in this ${followUpStrategy.toLowerCase()} run`,
      detailHeading: `${followUpStrategy} run summary`,
      testId: "finding-empty-follow-up",
      detailTestId: "finding-detail-follow-up",
      assessment: selectedRun.configuration_json?.assessment_type || "Assessment not recorded",
      profile: selectedRun.configuration_json?.test_profile || selectedRun.profile?.name || "Profile not recorded",
      strategyLabel: followUpStrategy,
      scope: renderTargetSummary(selectedRun.configuration_json?.targets || {}),
      hostCount,
      serviceCount,
      endpointCount,
      summary: `This controlled ${followUpStrategy.toLowerCase()} run enriched the engagement dossier with ${hostCount} hosts, ${serviceCount} services, and ${endpointCount} endpoints, but this stage did not produce vulnerability findings by itself.`,
      detail: followUp.rationale || "Review the enriched surface, task evidence, and report outputs before deciding whether another approved validation step is necessary.",
      primaryActionLabel: "Review Enriched Assets",
      secondaryActionLabel: "Open Report Center",
      secondaryActionScreen: "report-center",
      thirdActionLabel: "Open History",
      thirdActionScreen: "history",
    };
  }
  return {
    heading: "No vulnerability findings were created in this run",
    detailHeading: "Discovery run summary",
    testId: "finding-empty-discovery",
    detailTestId: "finding-detail-discovery",
    assessment: selectedRun.configuration_json?.assessment_type || "Assessment not recorded",
    profile: selectedRun.configuration_json?.test_profile || selectedRun.profile?.name || "Profile not recorded",
    strategyLabel: "Discovery",
    scope: renderTargetSummary(selectedRun.configuration_json?.targets || {}),
    hostCount,
    serviceCount,
    endpointCount,
    summary: `This run completed inventory and discovery against the approved scope. It mapped ${hostCount} hosts, ${serviceCount} services, and ${endpointCount} endpoints, but discovery-only runs do not create findings by themselves.`,
    detail: "Use Surface / Attack Map or Explorer to inspect what was discovered. If you want actual findings, run a deeper assessment profile or enable additional validation modules against the same approved scope.",
    primaryActionLabel: "Review Discovered Assets",
    secondaryActionLabel: "Open History",
    secondaryActionScreen: "history",
    thirdActionLabel: "Open Mission Control",
    thirdActionScreen: "mission-control",
  };
}

function isDiscoveryOnlyRun(run) {
  const profileName = String(run?.profile?.name || run?.configuration_json?.execution_profile || "").toLowerCase();
  const modules = run?.configuration_json?.modules || {};
  const enabledModuleKeys = Object.entries(modules)
    .filter(([, enabled]) => Boolean(enabled))
    .map(([key]) => key);
  return profileName === "passive-network-discovery" ||
    (enabledModuleKeys.length === 1 && enabledModuleKeys[0] === "discovery");
}

function getFollowUpMetadata(run) {
  const followUp = run?.configuration_json?.follow_up;
  return typeof followUp === "object" && followUp !== null ? followUp : null;
}

function buildRunEvidenceContext() {
  const run = state.selectedRun;
  if (!run) return null;
  const runFindings = state.mission.findingsByRun[run.id] || [];
  if (runFindings.length) return null;

  const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
  const tasks = run.tasks || [];
  const followUp = getFollowUpMetadata(run);
  if (!inventorySnapshot && !tasks.length) return null;

  const selectedTaskSummary =
    tasks.find((task) => String(task.id) === String(state.selectedTaskId)) ||
    tasks[0] ||
    null;
  const selectedTask =
    state.selectedTask &&
    selectedTaskSummary &&
    String(state.selectedTask.run_id) === String(run.id) &&
    String(state.selectedTask.id) === String(selectedTaskSummary.id)
      ? state.selectedTask
      : null;
  const latestExecution = selectedTask?.executions?.length
    ? [...selectedTask.executions].sort(
        (left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime()
      )[0]
    : null;
  const artifacts = (selectedTask?.executions || []).flatMap((execution) =>
    (execution.artifacts || []).map((artifact) => ({
      id: artifact.id,
      kind: artifact.kind,
      uri: artifact.uri,
      download_path: `/api/v1/artifacts/${artifact.id}`,
      name: String(artifact.metadata_json?.name || artifact.id),
      redaction_state: artifact.redaction_state,
    }))
  );
  const reportVariant = state.reportCatalog.find((report) => report.variant === "evidence") || state.reportCatalog[0] || null;
  const methodologyReferences = reportVariant?.methodology_references || [];
  const hostCount = Number(inventorySnapshot?.summary_json?.host_count || 0);
  const serviceCount = Number(inventorySnapshot?.summary_json?.service_count || 0);
  const endpointCount = Number(inventorySnapshot?.summary_json?.endpoint_count || 0);
  const sourceRun = followUp?.source_run_id
    ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
    : null;

  const title = followUp
    ? `${followUpStrategyLabel(followUp.strategy)} evidence posture`
    : "Run evidence posture";
  const summary = followUp
    ? `${followUpStrategyLabel(followUp.strategy)} completed with ${hostCount} hosts, ${serviceCount} services, and ${endpointCount} endpoints in the linked inventory, but this follow-up stage did not create finding records.`
    : `This run recorded task and inventory evidence for ${hostCount} hosts, ${serviceCount} services, and ${endpointCount} endpoints, even though no finding records exist yet.`;
  const detail = followUp
    ? (followUp.rationale || "The run stayed inside the discovery-derived scope and should now be reviewed through task evidence, enriched inventory, and reports.")
    : "Use this screen to inspect the selected check, the captured artifacts, and the run-level lineage instead of assuming the absence of findings means nothing happened.";

  const taskSummaries = tasks.map((task) => {
    const hydratedTask =
      selectedTask && String(selectedTask.id) === String(task.id)
        ? selectedTask
        : null;
    const hydratedLatestExecution = hydratedTask?.executions?.length
      ? [...hydratedTask.executions].sort(
          (left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime()
        )[0]
      : null;
    const executionCount = hydratedTask?.executions?.length || 0;
    return {
      id: task.id,
      tool: task.tool,
      target: task.target_id,
      status: task.status,
      executionLabel: hydratedLatestExecution
        ? `exit ${hydratedLatestExecution.exit_code} · ${executionCount} execution${executionCount === 1 ? "" : "s"}`
        : executionCount
          ? `${executionCount} execution${executionCount === 1 ? "" : "s"} loaded`
          : "select to inspect the latest execution",
      detail: hydratedLatestExecution
        ? `${hydratedLatestExecution.tool_version} · ${(hydratedLatestExecution.artifacts || []).length} artifact${(hydratedLatestExecution.artifacts || []).length === 1 ? "" : "s"}`
        : "Use this card to review the loaded task execution and artifact trail for this run.",
      stdoutExcerpt: hydratedLatestExecution?.stdout_text || hydratedLatestExecution?.stdout_excerpt || null,
      stderrExcerpt: hydratedLatestExecution?.stderr_text || hydratedLatestExecution?.stderr_excerpt || null,
    };
  });

  return {
    run,
    title,
    summary,
    detail,
    taskCount: tasks.length,
    hostCount,
    serviceCount,
    endpointCount,
    methodologyReferences,
    taskSummaries,
    selectedTaskId: selectedTaskSummary?.id || null,
    artifacts,
    signals: [
      inventorySnapshot
        ? `Inventory snapshot ${inventorySnapshot.id} is linked to this run-level evidence view.`
        : "No inventory snapshot is linked to the selected run yet.",
      latestExecution
        ? `Selected check ${selectedTaskSummary?.tool || "task"} produced ${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"} in the latest execution.`
        : selectedTaskSummary
          ? "The selected check exists in the run dossier, but detailed execution output is not loaded yet."
          : "No task-level evidence is linked to this run yet.",
      reportVariant
        ? `The ${reportVariant.title} report variant is ready for preview or export from this same run dossier.`
        : "Report variants are not loaded for this run yet.",
    ],
    lineageTitle: followUp ? "Follow-Up Lineage" : "Run Lineage",
    lineageSummary: followUp
      ? `${followUpStrategyLabel(followUp.strategy)} derived from ${sourceRun?.profile?.name || "a prior discovery run"}.`
      : "Discovery and task evidence are attached directly to the selected run.",
    lineageDetail: followUp
      ? `${followUp.rationale || "The follow-up remained bounded to the source discovery output."} Source inventory ${followUp.source_inventory_snapshot_id || run.source_inventory_snapshot_id || "n/a"}.`
      : `Inventory ${inventorySnapshot?.id || run.source_inventory_snapshot_id || "n/a"} · Pack ${run.pack_binding?.pack_version || "standard baseline"}.`,
    lineageBadges: [
      followUp ? followUpStrategyLabel(followUp.strategy) : "Discovery / Validation Evidence",
      sourceRun?.profile?.name || null,
      inventorySnapshot?.id ? `Inventory ${inventorySnapshot.id}` : null,
      run.pack_binding?.pack_version ? `Pack ${run.pack_binding.pack_version}` : "Standard Coverage",
    ].filter(Boolean),
  };
}
