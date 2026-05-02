import { api, apiOrNull } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  formatDateTime,
  renderBadgeList,
  renderDisclosure,
  slugify,
  splitComma,
  statusPill,
  stringValue,
  valueOrNull,
} from "./shared.js";

function filteredCodexTasks() {
  const selectedPackIds = new Set(state.mission.packs.map((pack) => pack.id));
  return state.codexTasks.filter(
    (task) => !task.source_context?.pack_id || selectedPackIds.has(task.source_context.pack_id)
  );
}

function assertSelectedEngagement() {
  if (!state.selectedEngagementId) throw new Error("Select or create an engagement first.");
}

function assertSelectedPack() {
  if (!state.selectedPackId) throw new Error("Select or generate a pack first.");
}

function latestItem(items) {
  return Array.isArray(items) && items.length ? items[items.length - 1] : null;
}

function shortId(value) {
  return value ? String(value).slice(0, 8) : "Not recorded";
}

function findOperatorSettingValue(key) {
  const sections = Array.isArray(state.operatorSettings?.sections) ? state.operatorSettings.sections : [];
  for (const section of sections) {
    const settings = Array.isArray(section?.settings) ? section.settings : [];
    const match = settings.find((setting) => String(setting?.key || "") === String(key || ""));
    if (match) return match.value;
  }
  return null;
}

function buildLaneModeEnabled() {
  const value = findOperatorSettingValue("instance.build_lane_mode");
  if (typeof value === "boolean") return value;
  return ["true", "1", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function setBuildLanePanelVisibility() {
  const enabled = buildLaneModeEnabled();
  document.querySelectorAll(".pack-codex-panel").forEach((panel) => {
    panel.classList.toggle("hidden", !enabled);
    panel.setAttribute("aria-hidden", enabled ? "false" : "true");
  });
  return enabled;
}

function toneForStatus(status) {
  const normalized = String(status || "pending").toLowerCase();
  if (
    [
      "complete",
      "completed",
      "validated",
      "approved",
      "deployed",
      "passed",
      "prepared",
      "ready_for_existing_pipeline",
    ].includes(normalized)
  ) {
    return "complete";
  }
  if (["running", "active", "preparing", "in_progress"].includes(normalized)) {
    return "active";
  }
  if (
    [
      "failed",
      "blocked",
      "rejected",
      "cancelled",
      "validation_failed",
      "not_allowed",
      "pending_approval",
    ].includes(normalized)
  ) {
    return "blocked";
  }
  return "pending";
}

function summarizeArtifactsByType(artifacts) {
  return (artifacts || []).reduce((counts, artifact) => {
    const key = artifact.artifact_type || "artifact";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function reimportArtifactPayload(artifact) {
  return {
    artifact_type: artifact.artifact_type,
    logical_name: artifact.logical_name,
    content_text: artifact.content_text ?? null,
    content_json: artifact.content_json ?? null,
    methodology_tags: artifact.methodology_tags || [],
    provenance_json: {
      ...(artifact.provenance_json || {}),
      staged_from_pack_forge: true,
    },
  };
}

function renderLifecycleCard(title, status, summary) {
  return `
    <div class="status-count-card tone-${toneForStatus(status)}">
      <strong>${escapeHtml(title)}</strong>
      <small>${statusPill(status)}</small>
      <small>${escapeHtml(summary)}</small>
    </div>
  `;
}

function nextLifecycleSuggestion(bundle, relatedCodexTasks) {
  const latestTask = latestItem(relatedCodexTasks);
  const latestValidation = latestItem(bundle.validations);
  const latestApproval = latestItem(bundle.approvals);
  const latestDeployment = latestItem(bundle.deployments);
  const packStatus = String(bundle.pack.status || "").toLowerCase();

  if (!relatedCodexTasks.length) {
    return {
      title: "Create a supervised build-lane task if this pack needs operator-guided refinement.",
      detail:
        "The pack registry is already in place. A build-lane task is only needed when the operator wants a controlled artifact review or refinement pass.",
    };
  }
  if (!state.selectedCodexResult && latestTask && String(latestTask.status).toLowerCase() !== "prepared") {
    return {
      title: "Prepare the selected build-lane task before editing or exporting workspace artifacts.",
      detail:
        "This generates the dry-run commands, workspace path, and validation hooks without changing the active runtime.",
    };
  }
  if (!latestValidation || ["generated", "proposed"].includes(packStatus)) {
    return {
      title: "Validate the generated pack before approval.",
      detail:
        "Validation is the first gate. It syntax-checks and dry-runs the existing artifacts before any approval or deployment decision.",
    };
  }
  if (String(latestValidation.status || "").toLowerCase() !== "validated") {
    return {
      title: "Resolve validation blockers before moving to approval.",
      detail:
        "The validation lane reported a non-ready status. Review the blocking issues and rerun validation instead of bypassing the pack lifecycle.",
    };
  }
  if (!latestApproval || !["approved", "deployed"].includes(packStatus)) {
    return {
      title: "Approval is the next controlled step.",
      detail:
        "The pack has a passing validation result. Review the operator notes and approval trail, then approve if the pack is ready for deployment.",
    };
  }
  if (!latestDeployment || packStatus !== "deployed") {
    return {
      title: "Deploy the approved pack so runs can bind to a fixed version.",
      detail:
        "Deployment makes the reviewed pack version available to engagement runtime binding without changing the runtime in place.",
    };
  }
  return {
    title: "The pack is deployed. Review provenance and prepared tasks for future refinement.",
    detail:
      "This pack is already bound through the normal deployment lane. Any further build-lane work should remain a new supervised refinement cycle.",
  };
}

function renderArtifactPreview(artifact) {
  const provenanceSummary = Object.entries(artifact.provenance_json || {})
    .filter(([, value]) => value !== null && value !== undefined && value !== "" && value !== false)
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`);

  return renderDisclosure({
    title: artifact.logical_name,
    summary: `${artifact.artifact_type} · ${artifact.status}`,
    body: `
      <div class="info-pair-grid">
        <div>
          <p class="eyebrow">Checksum</p>
          <p>${escapeHtml(artifact.checksum_sha256)}</p>
        </div>
        <div>
          <p class="eyebrow">Content Shape</p>
          <p>${escapeHtml(
            [
              artifact.has_content_text || artifact.content_text ? "text" : null,
              artifact.has_content_json || artifact.content_json ? "json" : null,
            ]
              .filter(Boolean)
              .join(" + ") || "metadata only"
          )}</p>
        </div>
      </div>
      ${renderBadgeList(artifact.methodology_tags, "split-top")}
      ${
        provenanceSummary.length
          ? `<div class="split-top"><p class="eyebrow">Provenance</p><ul>${provenanceSummary
              .map((entry) => `<li>${escapeHtml(entry)}</li>`)
              .join("")}</ul></div>`
          : `<p class="micro-copy split-top">No explicit provenance highlights recorded on this artifact.</p>`
      }
      ${
        artifact.validation_checks?.length
          ? `<div class="split-top"><p class="eyebrow">Validation Expectations</p><ul>${artifact.validation_checks
              .map((entry) => `<li>${escapeHtml(entry)}</li>`)
              .join("")}</ul></div>`
          : ""
      }
    `,
  });
}

export function createPacksModule() {
  async function withPackAction(actionLabel, handler) {
    state.loading.packAction = actionLabel;
    renderPackForge();
    try {
      await handler();
    } finally {
      state.loading.packAction = null;
      renderPackForge();
    }
  }

  function renderPackSummary(bundle, relatedCodexTasks, busyAction) {
    const latestValidation = latestItem(bundle.validations);
    const latestApproval = latestItem(bundle.approvals);
    const latestDeployment = latestItem(bundle.deployments);

    const lifecycleCards = [
      renderLifecycleCard(
        "Proposal",
        relatedCodexTasks[0]?.status || bundle.pack.status,
        relatedCodexTasks.length
          ? `${relatedCodexTasks.length} linked build-lane task${relatedCodexTasks.length === 1 ? "" : "s"}`
          : "No linked build-lane task yet"
      ),
      renderLifecycleCard(
        "Validation",
        latestValidation?.status || "not_run",
        latestValidation?.summary || "Validation has not been executed yet."
      ),
      renderLifecycleCard(
        "Approval",
        latestApproval?.decision || "not_requested",
        latestApproval ? `Last reviewer: ${latestApproval.approver_id}` : "Approval has not been requested."
      ),
      renderLifecycleCard(
        "Deployment",
        latestDeployment?.status || "not_deployed",
        latestDeployment
          ? `${latestDeployment.deployment_target}${latestDeployment.run_profile_name ? ` · ${latestDeployment.run_profile_name}` : ""}`
          : "No deployment has been recorded."
      ),
    ].join("");

    return `
      <h4>${escapeHtml(bundle.pack.name)} <span class="badge">${escapeHtml(bundle.pack.version)}</span></h4>
      <p>${statusPill(bundle.pack.status)} ${escapeHtml(bundle.pack.generation_mode)}</p>
      <p>${escapeHtml(bundle.pack.description || "No description recorded.")}</p>
      <div class="info-pair-grid split-top" data-testid="codex-pack-overview">
        <div>
          <p class="eyebrow">Inventory Source</p>
          <p>${escapeHtml(shortId(bundle.context.source_inventory_snapshot_id))}</p>
        </div>
        <div>
          <p class="eyebrow">Relevance Decision</p>
          <p>${escapeHtml(shortId(bundle.context.relevance_decision_id))}</p>
        </div>
        <div>
          <p class="eyebrow">Threat Intel</p>
          <p>${escapeHtml(String(bundle.context.source_threat_intel_refs.length || 0))} reference(s)</p>
        </div>
        <div>
          <p class="eyebrow">Latest Validation</p>
          <p>${statusPill(bundle.context.latest_validation_status || "not_run")}</p>
        </div>
      </div>
      ${renderBadgeList(bundle.pack.methodology_tags, "split-top")}
      <div class="status-grid split-top" data-testid="codex-lifecycle">
        ${lifecycleCards}
      </div>
      ${
        busyAction
          ? `
            <div class="detail-surface split-top" data-testid="pack-action-status">
              <h4>Pack action in progress</h4>
              <p>${escapeHtml(busyAction)}</p>
              <p class="micro-copy">The promotion lane remains controlled while validation, approval, or deployment completes.</p>
            </div>
          `
          : ""
      }
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
        <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
      </div>
    `;
  }

  function renderPackRegistry(bundle, relatedCodexTasks) {
    return `
      <div class="stack-zone">
        <div class="list-card">
          <h4>Capability Packs</h4>
          <div class="stack-zone split-top">
            ${state.mission.packs
              .map(
                (pack) => `
                  <div class="list-card ${pack.id === state.selectedPackId ? "selected" : ""}" data-pack-pick="${pack.id}" data-testid="pack-card">
                    <h4>${escapeHtml(pack.name)} <span class="badge">${escapeHtml(pack.version)}</span></h4>
                    <p>${statusPill(pack.status)} ${escapeHtml(pack.generation_mode)}</p>
                  </div>
                `
              )
              .join("")}
          </div>
        </div>
        ${renderDisclosure({
          title: "Artifact Registry",
          summary: `${bundle.artifacts.length} artifact${bundle.artifacts.length === 1 ? "" : "s"} across ${Object.keys(summarizeArtifactsByType(bundle.artifacts)).length || 0} types`,
          open: true,
          testId: "pack-registry-artifacts",
          body: bundle.artifacts.length
            ? bundle.artifacts
                .map(
                  (artifact) => `
                    <div class="artifact-card split-top">
                      <h4>${escapeHtml(artifact.logical_name)}</h4>
                      <p>${escapeHtml(`${artifact.artifact_type} · ${artifact.status}`)}</p>
                      ${renderBadgeList(artifact.methodology_tags)}
                      <p class="micro-copy split-top">${escapeHtml(artifact.checksum_sha256)}</p>
                    </div>
                  `
                )
                .join("")
            : "<p>No pack artifacts recorded.</p>",
        })}
        <div class="wizard-panel-grid">
          <div class="detail-surface">
            <h4>Validation</h4>
            ${
              bundle.validations.length
                ? bundle.validations
                    .map((validation) => {
                      const blockingIssues = validation.blocking_issues_json || [];
                      return `
                        <div class="split-top">
                          <p>${statusPill(validation.status)} ${escapeHtml(validation.validator)} · ${escapeHtml(validation.summary || "No summary")}</p>
                          <p class="micro-copy">${escapeHtml(`${blockingIssues.length} blocking issue${blockingIssues.length === 1 ? "" : "s"} · ${formatDateTime(validation.created_at)}`)}</p>
                        </div>
                      `;
                    })
                    .join("")
                : "<p>No validation results yet.</p>"
            }
          </div>
          <div class="detail-surface">
            <h4>Approvals</h4>
            ${
              bundle.approvals.length
                ? bundle.approvals
                    .map(
                      (approval) => `
                        <div class="split-top">
                          <p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.notes || "No notes")}</p>
                          <p class="micro-copy">${escapeHtml(formatDateTime(approval.created_at))}</p>
                        </div>
                      `
                    )
                    .join("")
                : "<p>No pack approvals recorded.</p>"
            }
          </div>
        </div>
        <div class="detail-surface">
          <h4>Deployments & Linked Build-Lane Tasks</h4>
          <p>${escapeHtml(`${bundle.deployments.length} deployment${bundle.deployments.length === 1 ? "" : "s"} · ${relatedCodexTasks.length} linked build-lane task${relatedCodexTasks.length === 1 ? "" : "s"}`)}</p>
          ${
            bundle.deployments.length
              ? bundle.deployments
                  .map(
                    (deployment) => `
                      <p class="micro-copy split-top">${escapeHtml(
                        `${deployment.status} to ${deployment.deployment_target}${
                          deployment.run_profile_name ? ` · ${deployment.run_profile_name}` : ""
                        }`
                      )}</p>
                    `
                  )
                  .join("")
              : "<p class='micro-copy'>No deployment history yet.</p>"
          }
        </div>
      </div>
    `;
  }

  function renderCodexSuggestions(bundle, relatedCodexTasks) {
    const latestTask = relatedCodexTasks.find((task) => task.id === state.selectedCodexTaskId) || relatedCodexTasks[0] || null;
    const suggestion = nextLifecycleSuggestion(bundle, relatedCodexTasks);
    const visibility = bundle.context.operator_visibility;

    dom.codexSuggestions.innerHTML = `
      <h4>Operator Suggestions</h4>
      <p>${escapeHtml(suggestion.title)}</p>
      <p class="micro-copy">${escapeHtml(suggestion.detail)}</p>
      <div class="info-pair-grid split-top">
        <div>
          <p class="eyebrow">Linked Task</p>
          <p>${latestTask ? escapeHtml(`${latestTask.task_type} · ${latestTask.id}`) : "No build-lane task selected"}</p>
        </div>
        <div>
          <p class="eyebrow">Task Status</p>
          <p>${latestTask ? statusPill(latestTask.status) : statusPill("not_requested")}</p>
        </div>
        <div>
          <p class="eyebrow">Approval Lane</p>
          <p>${latestTask ? statusPill(latestTask.approval_status) : statusPill("not_requested")}</p>
        </div>
        <div>
          <p class="eyebrow">Runtime Safety</p>
          <p>${bundle.context.active_runtime_mutation_allowed ? "Runtime mutation allowed" : "Runtime mutation blocked"}</p>
        </div>
      </div>
      ${
        latestTask
          ? `
            <div class="split-top">
              <p class="eyebrow">Generation Reason</p>
              <p>${escapeHtml(latestTask.generation_reason || bundle.context.generation_reason || "No generation reason recorded.")}</p>
            </div>
          `
          : `
            <div class="split-top">
              <p class="eyebrow">Generation Reason</p>
              <p>${escapeHtml(bundle.context.generation_reason || "No build-lane task is linked yet, so only pack-level generation context is available.")}</p>
            </div>
          `
      }
      ${renderDisclosure({
        title: "Required Operator Visibility",
        summary: `${visibility.required_badges.length} badges · ${visibility.required_fields.length} required fields`,
        body: `
          <p class="eyebrow">Required badges</p>
          ${renderBadgeList(visibility.required_badges)}
          <p class="eyebrow split-top">Required fields</p>
          <ul>${visibility.required_fields.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        `,
      })}
      ${renderDisclosure({
        title: "Review Sections",
        summary: `${visibility.review_sections.length} controlled review sections`,
        body: `
          <ul>${visibility.review_sections.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          <p class="eyebrow split-top">Finding provenance remains visible via</p>
          <ul>${visibility.finding_provenance_fields.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        `,
      })}
    `;
  }

  function renderCodexPackPreview(bundle) {
    const artifactCounts = summarizeArtifactsByType(bundle.context.artifacts);
    const artifactBadges = Object.entries(artifactCounts).map(([artifactType, count]) => `${artifactType} (${count})`);

    dom.codexPackPreview.innerHTML = `
      <h4>Generated Pack Preview</h4>
      <p>${escapeHtml(
        `${bundle.context.artifacts.length} exportable artifact${bundle.context.artifacts.length === 1 ? "" : "s"} are tied to this pack review bundle.`
      )}</p>
      ${renderBadgeList(artifactBadges, "split-top")}
      <div class="artifact-preview-list split-top">
        ${
          bundle.context.artifacts.length
            ? bundle.context.artifacts.map((artifact) => renderArtifactPreview(artifact)).join("")
            : emptyState("No exported artifacts were recorded for this pack.")
        }
      </div>
      <p class="micro-copy split-top">The full artifact registry, validations, approvals, and deployment history remain visible in the registry panel to the left.</p>
    `;
  }

  function renderCodexContext(bundle) {
    dom.codexContext.innerHTML = `
      <h4>Build Lane Guardrails</h4>
      <p>${statusPill(bundle.context.pack_status)} ${escapeHtml(bundle.context.generation_mode)}</p>
      <div class="info-pair-grid split-top">
        <div>
          <p class="eyebrow">Suggested Branch</p>
          <p>${escapeHtml(bundle.context.repo_conventions.suggested_branch_name)}</p>
        </div>
        <div>
          <p class="eyebrow">Workspace Root</p>
          <p>${escapeHtml(bundle.context.repo_conventions.workspace_root)}</p>
        </div>
      </div>
      ${renderDisclosure({
        title: "Runtime Guardrails",
        summary: `${bundle.context.runtime_guardrails.length} rules that keep supervised build work out of the live runtime`,
        body: `<ul>${bundle.context.runtime_guardrails.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
      })}
      ${renderDisclosure({
        title: "Validation Hooks",
        summary: `${bundle.context.validation_hooks.length} existing pack lifecycle hooks`,
        body: bundle.context.validation_hooks
          .map(
            (hook) => `
              <div class="split-top">
                <p>${statusPill(hook.blocking ? "blocked" : "review")} ${escapeHtml(`${hook.name} · ${hook.method} ${hook.path}`)}</p>
                <p class="micro-copy">${escapeHtml(hook.description)}</p>
                ${
                  hook.artifact_types?.length
                    ? `<p class="micro-copy">Artifact focus: ${escapeHtml(hook.artifact_types.join(", "))}</p>`
                    : ""
                }
                ${
                  hook.expected_checks?.length
                    ? `<p class="micro-copy">Expected checks: ${escapeHtml(hook.expected_checks.join(" · "))}</p>`
                    : ""
                }
                ${
                  hook.workspace_files?.length
                    ? `<p class="micro-copy">Workspace files: ${escapeHtml(hook.workspace_files.join(" · "))}</p>`
                    : ""
                }
              </div>
            `
          )
          .join(""),
      })}
      ${renderDisclosure({
        title: "Repository Conventions",
        summary: `${bundle.context.repo_conventions.notes_file}, ${bundle.context.repo_conventions.change_summary_file}, ${bundle.context.repo_conventions.review_bundle_file}`,
        body: `
          <p class="micro-copy">${escapeHtml(bundle.context.repo_conventions.export_command)}</p>
          <p class="micro-copy split-top">${escapeHtml(bundle.context.repo_conventions.validation_command)}</p>
          <ul class="split-top">${bundle.context.repo_conventions.rules.map((rule) => `<li>${escapeHtml(rule)}</li>`).join("")}</ul>
        `,
      })}
    `;
  }

  function renderCodexTaskResult(bundle) {
    const latestValidation = bundle ? latestItem(bundle.validations) : null;
    const validationPassed = String(latestValidation?.status || "").toLowerCase() === "passed";
    const canStageReimport = Boolean(state.selectedCodexResult && validationPassed && bundle?.artifacts?.length);

    dom.codexTaskResult.innerHTML = state.selectedCodexResult
      ? `
        <h4>Prepared Task Output</h4>
        <p>${statusPill(state.selectedCodexResult.status)} dry run ${String(state.selectedCodexResult.dry_run)}</p>
        <p>${escapeHtml(state.selectedCodexResult.summary)}</p>
        ${renderDisclosure({
          title: "Prepared Commands",
          summary: `${state.selectedCodexResult.prepared_commands.length} commands`,
          open: true,
          body: `<ul>${state.selectedCodexResult.prepared_commands.map((command) => `<li>${escapeHtml(command)}</li>`).join("")}</ul>`,
          testId: "codex-prepared-commands",
        })}
        ${renderDisclosure({
          title: "Output Files",
          summary: `${state.selectedCodexResult.output_files.length} repo-backed artifacts`,
          body: `<ul>${state.selectedCodexResult.output_files.map((path) => `<li>${escapeHtml(path)}</li>`).join("")}</ul>`,
        })}
        ${renderDisclosure({
          title: "Task Guardrails",
          summary: `${state.selectedCodexResult.guardrails.length} execution guardrails`,
          body: `<ul>${state.selectedCodexResult.guardrails.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
        })}
        ${renderDisclosure({
          title: "Validation Handoff",
          summary: `${state.selectedCodexResult.validation_hooks.length} existing validation hooks`,
          body: state.selectedCodexResult.validation_hooks
            .map(
              (hook) => `
                <div class="split-top">
                  <p>${statusPill(hook.blocking ? "blocked" : "review")} ${escapeHtml(`${hook.name} · ${hook.method} ${hook.path}`)}</p>
                  <p class="micro-copy">${escapeHtml(hook.description)}</p>
                  ${
                    hook.artifact_types?.length
                      ? `<p class="micro-copy">Artifact focus: ${escapeHtml(hook.artifact_types.join(", "))}</p>`
                      : ""
                  }
                  ${
                    hook.expected_checks?.length
                      ? `<p class="micro-copy">Expected checks: ${escapeHtml(hook.expected_checks.join(" · "))}</p>`
                      : ""
                  }
                  ${
                    hook.workspace_files?.length
                      ? `<p class="micro-copy">Workspace files: ${escapeHtml(hook.workspace_files.join(" · "))}</p>`
                      : ""
                  }
                </div>
              `
            )
            .join(""),
          testId: "codex-validation-handoff",
        })}
        <div class="detail-surface split-top" data-testid="codex-reimport-panel">
          <h4>Controlled Artifact Reimport</h4>
          <p>
            ${statusPill(canStageReimport ? "ready" : "blocked")}
            ${escapeHtml(
              canStageReimport
                ? "Validation result is available. Reimport will create a generated child pack that still needs validation, approval, and deployment."
                : "Prepare a build-lane task and record a passing pack validation result before staging reimported artifacts."
            )}
          </p>
          <p class="micro-copy">
            Reimport never deploys automatically and never mutates a runtime-bound pack in place.
          </p>
          <button class="action secondary split-top" type="button" data-stage-codex-reimport ${canStageReimport ? "" : "disabled"}>
            Stage Validated Child Pack
          </button>
        </div>
      `
      : emptyState(
          bundle
            ? "Create or select a build-lane task to view prepared commands, output files, and validation hooks."
            : "Prepared task output appears here."
        );
  }

  function renderPackForge() {
    const buildLaneEnabled = setBuildLanePanelVisibility();

    renderAdaptiveForm();
    if (buildLaneEnabled) {
      renderCodexTaskForm();
    } else {
      dom.codexTaskForm.innerHTML = "";
      dom.codexTaskForm.onsubmit = null;
      dom.prepareCodexTaskBtn.disabled = true;
      dom.codexSuggestions.innerHTML = "";
      dom.codexPackPreview.innerHTML = "";
      dom.codexContext.innerHTML = "";
      dom.codexTaskResult.innerHTML = "";
    }

    if (!state.selectedPackBundle) {
      dom.validatePackBtn.disabled = true;
      dom.approvePackBtn.disabled = true;
      dom.deployPackBtn.disabled = true;
      dom.packSummary.innerHTML = emptyState(
        "Generate or select a capability pack to review promotion readiness."
      );
      dom.packForgeDetail.innerHTML = emptyState(
        "Pack artifacts, validations, approvals, deployments, and build-lane tasks appear here."
      );
      if (buildLaneEnabled) {
        dom.codexSuggestions.innerHTML = emptyState(
          "Operator suggestions appear once a pack and optional build-lane task are linked."
        );
        dom.codexPackPreview.innerHTML = emptyState(
          "Generated pack previews appear once a review bundle is available."
        );
        dom.codexContext.innerHTML = emptyState("Build-lane context is available once a pack is selected.");
        dom.codexTaskResult.innerHTML = emptyState(
          "Prepared task output appears here."
        );
        dom.prepareCodexTaskBtn.disabled = true;
      }
      return;
    }

    const bundle = state.selectedPackBundle;
    const busyAction = state.loading.packAction;
    const actionBusy = Boolean(busyAction);
    const relatedCodexTasks = filteredCodexTasks();
    if (relatedCodexTasks.length && !relatedCodexTasks.some((task) => task.id === state.selectedCodexTaskId)) {
      state.selectedCodexTaskId = relatedCodexTasks[0].id;
    }
    dom.validatePackBtn.disabled =
      actionBusy || ["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.approvePackBtn.disabled =
      actionBusy || !["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.deployPackBtn.disabled =
      actionBusy || !["approved", "deployed"].includes(bundle.pack.status);
    dom.prepareCodexTaskBtn.disabled = !buildLaneEnabled || actionBusy || !relatedCodexTasks.length;

    dom.packSummary.innerHTML = renderPackSummary(bundle, relatedCodexTasks, busyAction);
    dom.packForgeDetail.innerHTML = renderPackRegistry(bundle, relatedCodexTasks);
    dom.packForgeDetail.querySelectorAll("[data-pack-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedPackId = item.dataset.packPick;
        await runtime.actions.loadSelectedPack?.();
        renderPackForge();
        runtime.actions.renderMissionControl?.();
      });
    });

    if (buildLaneEnabled) {
      renderCodexSuggestions(bundle, relatedCodexTasks);
      renderCodexPackPreview(bundle);
      renderCodexContext(bundle);
      renderCodexTaskResult(bundle);
      dom.codexTaskResult.querySelector("[data-stage-codex-reimport]")?.addEventListener("click", async () => {
        try {
          await stageCodexReimport(bundle);
        } catch (error) {
          runtime.actions.pushStatus?.(error.message || "Unable to stage build-lane reimport.", "error");
        }
      });
    }
  }

  function renderAdaptiveForm() {
    const inventorySnapshot = runtime.actions.latestInventorySnapshot?.();
    dom.adaptiveForm.innerHTML = `
      <label class="field">
        <span>Inventory Basis</span>
        <div class="detail-surface">
          <p>${inventorySnapshot ? escapeHtml(`${inventorySnapshot.id} · ${inventorySnapshot.summary_json.endpoint_count} endpoints`) : "No inventory snapshot available."}</p>
          <p class="micro-copy">Adaptive planning uses the latest inventory snapshot and selected engagement scope.</p>
        </div>
      </label>
      <label class="field">
        <span>Advisory Source</span>
        <input name="source" type="text" value="vendor-advisory" />
      </label>
      <label class="field">
        <span>Advisory ID</span>
        <input name="advisory_id" type="text" placeholder="CVE-2026-1000" />
      </label>
      <label class="field">
        <span>Title</span>
        <input name="title" type="text" placeholder="Auth regression follow-up" />
      </label>
      <label class="field">
        <span>Summary</span>
        <textarea name="summary" rows="3" placeholder="Summarize the relevant advisory or testing pattern."></textarea>
      </label>
      <label class="field">
        <span>Affected Product</span>
        <input name="product" type="text" placeholder="grafana" />
      </label>
      <label class="field">
        <span>Product Match Hint</span>
        <input name="hint" type="text" placeholder="grafana labs" />
      </label>
      <label class="field">
        <span>Attack Surface Type</span>
        <input name="attack_surface_type" type="text" value="auth" />
      </label>
      <label class="field">
        <span>Severity</span>
        <input name="severity" type="text" value="high" />
      </label>
      <label class="field">
        <span>Suggested Patterns</span>
        <input name="patterns" type="text" value="playwright,zap" />
      </label>
      <label class="field">
        <span>Pack Name</span>
        <input name="pack_name" type="text" placeholder="customer-adaptive-pack" />
      </label>
      <button class="action primary" type="submit">Generate Adaptive Pack</button>
    `;
    dom.adaptiveForm.onsubmit = async (event) => {
      event.preventDefault();
      assertSelectedEngagement();
      const inventoryId = runtime.actions.latestInventorySnapshot?.()?.id;
      if (!inventoryId) {
        throw new Error("Create or seed an inventory snapshot before generating adaptive coverage.");
      }
      const form = new FormData(dom.adaptiveForm);
      await withPackAction("Generating adaptive pack", async () => {
        const threatIntel = await api("/api/v1/threat-intel/ingest", {
          method: "POST",
          body: {
            records: [
              {
                source: stringValue(form.get("source")) || "vendor-advisory",
                advisory_id: stringValue(form.get("advisory_id")),
                title: stringValue(form.get("title")) || "Adaptive testing advisory",
                summary: valueOrNull(form.get("summary")),
                affected_products: splitComma(form.get("product")),
                product_match_hints: splitComma(form.get("hint")),
                attack_surface_type: valueOrNull(form.get("attack_surface_type")),
                suggested_test_patterns: splitComma(form.get("patterns")),
                confidence: 0.9,
                severity: valueOrNull(form.get("severity")),
                references: [],
              },
            ],
          },
        });
        const relevance = await api("/api/v1/relevance/analyze", {
          method: "POST",
          body: {
            engagement_id: state.selectedEngagementId,
            inventory_snapshot_id: inventoryId,
            threat_intel_ids: [threatIntel[0].id],
            include_prior_findings: true,
          },
        });
        const pack = await api("/api/v1/packs/generate", {
          method: "POST",
          body: {
            engagement_id: state.selectedEngagementId,
            relevance_decision_id: relevance.id,
            name: valueOrNull(form.get("pack_name")) || undefined,
          },
        });
        state.selectedPackId = pack.id;
        runtime.actions.pushStatus?.(`Adaptive pack ${pack.name} ${pack.version} generated.`, "success");
        await runtime.actions.refreshSelectedEngagement?.();
      });
    };
  }

  function renderCodexTaskForm() {
    dom.codexTaskForm.innerHTML = `
      <label class="field">
        <span>Task Type</span>
        <input name="task_type" type="text" value="pack_refinement" />
      </label>
      <label class="field">
        <span>Scope</span>
        <textarea name="scope" rows="3" placeholder="Refine or review the selected adaptive pack."></textarea>
      </label>
      <label class="field">
        <span>Generation Reason</span>
        <textarea name="generation_reason" rows="3" placeholder="Explain why this supervised build-lane task is needed."></textarea>
      </label>
      <button class="action secondary" type="submit">Create Build-Lane Task</button>
      <div class="stack-zone split-top">
        ${filteredCodexTasks()
          .map(
            (task) => `
              <div class="list-card ${task.id === state.selectedCodexTaskId ? "selected" : ""}" data-codex-pick="${task.id}" data-testid="codex-task-card">
                <h4>${escapeHtml(task.task_type)}</h4>
                <p>${statusPill(task.status)} ${escapeHtml(task.validation_status)}</p>
                <p class="micro-copy">${escapeHtml(`Task ${task.id}`)}</p>
                <p class="micro-copy split-top">Select this task to inspect prepared output, controlled commands, and validation handoff.</p>
              </div>
            `
          )
          .join("") || emptyState("No build-lane tasks are linked to the selected pack yet.")}
      </div>
    `;
    dom.codexTaskForm.onsubmit = async (event) => {
      event.preventDefault();
      assertSelectedPack();
      const form = new FormData(dom.codexTaskForm);
      const task = await api("/api/v1/codex/tasks", {
        method: "POST",
        body: {
          task_type: stringValue(form.get("task_type")) || "pack_refinement",
          scope: stringValue(form.get("scope")) || "Review selected pack artifacts.",
          inputs: { selected_engagement_id: state.selectedEngagementId },
          constraints: { runtime_mutation: false, protected_runtime: true },
          expected_output: { review_bundle: true, validation_required: true },
          generation_reason: stringValue(form.get("generation_reason")) || "Operator requested pack review.",
          source_context: { pack_id: state.selectedPackId },
        },
      });
      state.selectedCodexTaskId = task.id;
      state.selectedCodexResult = null;
      runtime.actions.pushStatus?.("Build-lane task created in the supervised build lane.", "success");
      state.codexTasks = await api("/api/v1/codex/tasks");
      renderPackForge();
    };
    dom.codexTaskForm.querySelectorAll("[data-codex-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedCodexTaskId = item.dataset.codexPick;
        state.selectedCodexResult = await apiOrNull(`/api/v1/codex/tasks/${state.selectedCodexTaskId}/result`);
        renderPackForge();
      });
    });
  }

  async function validateSelectedPack() {
    assertSelectedPack();
    await withPackAction("Validating selected pack", async () => {
      await api(`/api/v1/packs/${state.selectedPackId}/validate`, { method: "POST" });
      runtime.actions.pushStatus?.("Pack validation completed.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function approveSelectedPack() {
    assertSelectedPack();
    await withPackAction("Promoting pack for approval", async () => {
      await api(
        `/api/v1/packs/${state.selectedPackId}/approve?notes=Approved%20from%20operator%20console`,
        { method: "POST" }
      );
      runtime.actions.pushStatus?.("Pack approved for promotion.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function deploySelectedPack() {
    assertSelectedPack();
    assertSelectedEngagement();
    await withPackAction("Deploying approved pack", async () => {
      await api(`/api/v1/packs/${state.selectedPackId}/deploy`, {
        method: "POST",
        body: {
          engagement_id: state.selectedEngagementId,
          deployment_target: "engagement-runtime",
          run_profile_name: state.selectedRun?.profile?.name || null,
        },
      });
      runtime.actions.pushStatus?.("Pack deployed and available for run binding.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function prepareSelectedCodexTask() {
    const taskId = state.selectedCodexTaskId || filteredCodexTasks()[0]?.id;
    if (!taskId) {
      throw new Error("Create or select a build-lane task first.");
    }
    await withPackAction("Preparing build-lane dry-run task", async () => {
      state.selectedCodexResult = await api(`/api/v1/codex/tasks/${taskId}/run`, {
        method: "POST",
        body: {
          base_url: window.location.origin,
          workspace_root: `./codex-workspaces/${slugify(runtime.actions.selectedPack?.()?.name || "pack")}`,
          dry_run: true,
        },
      });
      runtime.actions.pushStatus?.("Build-lane task prepared in dry-run mode.", "success");
      renderPackForge();
    });
  }

  async function stageCodexReimport(bundle) {
    assertSelectedPack();
    const latestValidation = latestItem(bundle.validations);
    if (!latestValidation || String(latestValidation.status || "").toLowerCase() !== "passed") {
      throw new Error("Run pack validation successfully before staging build-lane reimport.");
    }
    await withPackAction("Staging controlled build-lane reimport", async () => {
      const response = await api(`/api/v1/packs/${state.selectedPackId}/codex-reimport`, {
        method: "POST",
        body: {
          codex_task_id: state.selectedCodexTaskId,
          pack_version: bundle.pack.version,
          validation_result: latestValidation,
          change_summary: "Pack Forge staged validated build-lane workspace output for operator review.",
          operator_notes: "Staged from Pack Forge; runtime use still requires validation, approval, deployment, and binding.",
          artifacts: (bundle.artifacts || []).map((artifact) => reimportArtifactPayload(artifact)),
        },
      });
      state.selectedPackId = response.staged_pack.id;
      state.selectedCodexResult = null;
      runtime.actions.pushStatus?.("Build-lane reimport staged as a generated child pack.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  return {
    filteredCodexTasks,
    prepareSelectedCodexTask,
    renderPackForge,
    validateSelectedPack,
    approveSelectedPack,
    deploySelectedPack,
  };
}
