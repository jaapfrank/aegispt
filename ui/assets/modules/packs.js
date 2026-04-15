import { api, apiOrNull } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import { emptyState, escapeHtml, slugify, splitComma, statusPill, stringValue, valueOrNull } from "./shared.js";

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

export function createPacksModule() {
  function renderPackForge() {
    renderAdaptiveForm();
    renderCodexTaskForm();

    if (!state.selectedPackBundle) {
      dom.validatePackBtn.disabled = true;
      dom.approvePackBtn.disabled = true;
      dom.deployPackBtn.disabled = true;
      dom.packSummary.innerHTML = emptyState(
        "Generate or select a capability pack to review promotion readiness."
      );
      dom.packForgeDetail.innerHTML = emptyState(
        "Pack artifacts, validations, approvals, deployments, and Codex tasks appear here."
      );
      dom.codexContext.innerHTML = emptyState("Codex context is available once a pack is selected.");
      dom.codexTaskResult.innerHTML = emptyState(
        "Prepared task output appears here."
      );
      return;
    }

    const bundle = state.selectedPackBundle;
    const busyAction = state.loading.packAction;
    const actionBusy = Boolean(busyAction);
    dom.validatePackBtn.disabled =
      actionBusy || ["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.approvePackBtn.disabled =
      actionBusy || !["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.deployPackBtn.disabled =
      actionBusy || !["approved", "deployed"].includes(bundle.pack.status);

    dom.packSummary.innerHTML = `
      <h4>${escapeHtml(bundle.pack.name)} <span class="badge">${escapeHtml(bundle.pack.version)}</span></h4>
      <p>${statusPill(bundle.pack.status)} ${escapeHtml(bundle.pack.generation_mode)}</p>
      <p>${escapeHtml(bundle.pack.description || "No description recorded.")}</p>
      <p class="micro-copy">${escapeHtml(`Methodology tags: ${(bundle.pack.methodology_tags || []).join(", ") || "None"}`)}</p>
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

    const relatedCodexTasks = filteredCodexTasks();
    dom.packForgeDetail.innerHTML = `
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
        <div class="list-card">
          <h4>Artifacts</h4>
          ${
            bundle.artifacts.length
              ? bundle.artifacts
                  .map(
                    (artifact) => `
                      <div class="artifact-card split-top">
                        <h4>${escapeHtml(artifact.logical_name)}</h4>
                        <p>${escapeHtml(`${artifact.artifact_type} · ${artifact.status}`)}</p>
                        <p class="micro-copy">${escapeHtml(artifact.checksum_sha256)}</p>
                      </div>
                    `
                  )
                  .join("")
              : "<p>No pack artifacts recorded.</p>"
          }
        </div>
        <div class="wizard-panel-grid">
          <div class="detail-surface">
            <h4>Validation</h4>
            ${
              bundle.validations.length
                ? bundle.validations
                    .map(
                      (validation) =>
                        `<p>${statusPill(validation.status)} ${escapeHtml(validation.validator)} · ${escapeHtml(validation.summary || "No summary")}</p>`
                    )
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
                      (approval) =>
                        `<p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.notes || "No notes")}</p>`
                    )
                    .join("")
                : "<p>No pack approvals recorded.</p>"
            }
          </div>
        </div>
        <div class="detail-surface">
          <h4>Deployments & Codex Tasks</h4>
          <p>${escapeHtml(`${bundle.deployments.length} deployments · ${relatedCodexTasks.length} Codex tasks`)}</p>
          ${
            bundle.deployments
              .map(
                (deployment) =>
                  `<p class="micro-copy">${escapeHtml(`${deployment.status} to ${deployment.deployment_target}`)}</p>`
              )
              .join("") || "<p class='micro-copy'>No deployment history yet.</p>"
          }
        </div>
      </div>
    `;
    dom.packForgeDetail.querySelectorAll("[data-pack-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedPackId = item.dataset.packPick;
        await runtime.actions.loadSelectedPack?.();
        renderPackForge();
        runtime.actions.renderMissionControl?.();
      });
    });

    dom.codexContext.innerHTML = `
      <h4>${escapeHtml(bundle.context.pack_name)} <span class="badge">${escapeHtml(bundle.context.pack_version)}</span></h4>
      <p>${statusPill(bundle.context.pack_status)} ${escapeHtml(bundle.context.generation_mode)}</p>
      <p>${escapeHtml(bundle.context.runtime_guardrails.join(" | "))}</p>
      <p class="micro-copy">${escapeHtml(`Validation hooks: ${bundle.context.validation_hooks.map((hook) => hook.name).join(", ")}`)}</p>
    `;
    dom.codexTaskResult.innerHTML = state.selectedCodexResult
      ? `
        <h4>Prepared Task</h4>
        <p>${statusPill(state.selectedCodexResult.status)} dry run ${String(state.selectedCodexResult.dry_run)}</p>
        <p>${escapeHtml(state.selectedCodexResult.summary)}</p>
        <ul>${state.selectedCodexResult.prepared_commands.map((command) => `<li>${escapeHtml(command)}</li>`).join("")}</ul>
      `
      : emptyState("Create or select a Codex task to view prepared commands and validation hooks.");
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
        <textarea name="generation_reason" rows="3" placeholder="Explain why this supervised Codex task is needed."></textarea>
      </label>
      <button class="action secondary" type="submit">Create Codex Task</button>
      <div class="stack-zone split-top">
        ${filteredCodexTasks()
          .map(
            (task) => `
              <div class="list-card ${task.id === state.selectedCodexTaskId ? "selected" : ""}" data-codex-pick="${task.id}">
                <h4>${escapeHtml(task.task_type)}</h4>
                <p>${statusPill(task.status)} ${escapeHtml(task.validation_status)}</p>
                <p class="micro-copy">${escapeHtml(task.scope)}</p>
              </div>
            `
          )
          .join("") || emptyState("No Codex tasks are linked to the selected pack yet.")}
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
      runtime.actions.pushStatus?.("Codex task created in the supervised build lane.", "success");
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
      throw new Error("Create or select a Codex task first.");
    }
    await withPackAction("Preparing Codex dry-run task", async () => {
      state.selectedCodexResult = await api(`/api/v1/codex/tasks/${taskId}/run`, {
        method: "POST",
        body: {
          base_url: window.location.origin,
          workspace_root: `./codex-workspaces/${slugify(runtime.actions.selectedPack?.()?.name || "pack")}`,
          dry_run: true,
        },
      });
      runtime.actions.pushStatus?.("Codex task prepared in dry-run mode.", "success");
      renderPackForge();
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
