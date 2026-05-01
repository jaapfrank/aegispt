import { api } from "./api.js";
import { dom, patchState, runtime, state, statusFeed } from "./runtime.js";
import {
  countMeaningfulAccessContexts,
  countScopeTargets,
  emptyState,
  enabledModules,
  escapeHtml,
  exposureScoreTone,
  exposureTrendLabel,
  executionPlanForProfile,
  flattenTargetValues,
  formatExposureScore,
  formatDateTime,
  formatDurationLabel,
  formatElapsedMinutes,
  hasMeaningfulAccessContext,
  humanizeCheckMode,
  humanizeDepthLabel,
  isLikelyCidr,
  isLikelyDomain,
  isLikelyIp,
  isLikelyUrl,
  isSeedOnlyInventory,
  followUpStrategyLabel,
  lineSvg,
  minutesSince,
  renderExposureSparkline,
  renderSignalList,
  renderBadgeList,
  renderAccessContextSummary,
  renderDisclosure,
  renderStringCards,
  renderTargetSummary,
  requiresCredentials,
  statusPill,
  summarizeTaskStatuses,
  toPercent,
  capitalizeWord,
} from "./shared.js";
import { estimateMission } from "./wizard.js";

function normalizeTaskStatus(status) {
  const normalized = String(status || "unknown").toLowerCase();
  if (normalized === "error") return "failed";
  if (normalized === "pending") return "queued";
  return normalized || "unknown";
}

export function createMissionModule() {
  const severitySnapshots = new Map();
  const AI_SIGNAL_TYPING_RATES = {
    observation: 12,
    alert: 6,
    chain: 12,
    proposal: 12,
  };
  const AI_SIGNAL_IN_FLIGHT_STATUSES = new Set([
    "queued",
    "pending",
    "running",
    "in_progress",
    "started",
    "analyzing",
  ]);
  const DISABLED_PROVIDER_STATUSES = new Set(["disabled", "not_connected", "not-connected", "not connected", "off"]);
  let aiSignalEventSource = null;
  let aiSignalStreamKey = "";
  let aiSignalRenderTimer = null;

  function patchSurfaceBrowserState(fields, reason) {
    const hasField = (key) => Object.prototype.hasOwnProperty.call(fields, key);
    patchState(
      {
        selectedSurfaceAssetKey: hasField("selectedSurfaceAssetKey")
          ? fields.selectedSurfaceAssetKey
          : state.selectedSurfaceAssetKey,
        surfaceAssetFilter: hasField("surfaceAssetFilter") ? fields.surfaceAssetFilter : state.surfaceAssetFilter,
        surfaceAssetQuery: hasField("surfaceAssetQuery") ? fields.surfaceAssetQuery : state.surfaceAssetQuery,
      },
      reason
    );
  }

  function approvalStateForRun(run) {
    return {
      required: Math.max(0, Number(run?.required_approvals || 0)),
      granted: Math.max(0, Number(run?.granted_approvals || 0)),
      pending: Math.max(0, Number(run?.pending_approvals || 0)),
    };
  }

  function approvalWaitingSummary(run) {
    const approvals = approvalStateForRun(run);
    const approvalLabel = approvals.required === 1 ? "approval" : "approvals";
    const profileName =
      run?.profile?.name ||
      run?.configuration_json?.execution_profile ||
      "the selected execution lane";
    if (approvals.required <= 0) {
      return `Run launch is waiting for approval before ${profileName} can queue its planned active checks.`;
    }
    return `${approvals.pending} of ${approvals.required} required ${approvalLabel} remain before ${profileName} can queue its planned active checks.`;
  }

  function currentActorApproval(run) {
    const expectedStepId = String(run?.approval_step_id || "run.launch");
    const currentActor = String(state.actor || "").trim().toLowerCase();
    return (Array.isArray(run?.approvals) ? run.approvals : []).find((approval) => {
      const approvalActor = String(approval?.approver_id || "").trim().toLowerCase();
      return String(approval?.step_id || "") === expectedStepId && approvalActor === currentActor;
    }) || null;
  }

  function sortedRunApprovals(run) {
    return [...(Array.isArray(run?.approvals) ? run.approvals : [])].sort(
      (left, right) => timestampMs(right?.created_at) - timestampMs(left?.created_at)
    );
  }

  function selectedAssessmentChain(run = state.selectedRun) {
    const chain = run?.assessment_chain;
    return chain && chain.id ? chain : null;
  }

  function assessmentModeLabel(mode) {
    const mapping = {
      "FULL-INTERNAL-LAN": "Full Internal LAN",
      "FULL-EXTERNAL-WEB": "Full External Web",
      "FULL-AD-ASSESSMENT": "Full AD Assessment",
    };
    const normalized = String(mode || "").trim().toUpperCase();
    return mapping[normalized] || normalized || "Assessment Chain";
  }

  function currentAssessmentChainPhase(chain) {
    const phases = Array.isArray(chain?.phases) ? chain.phases : [];
    const index = Number(chain?.current_phase_index || 0);
    if (!phases.length) return null;
    if (index >= 0 && index < phases.length) return phases[index];
    return phases[Math.max(0, phases.length - 1)] || null;
  }

  function summarizeAssessmentChainSteps(steps) {
    return (Array.isArray(steps) ? steps : []).reduce(
      (counts, step) => {
        const normalized = String(step?.status || "pending").toLowerCase();
        counts[normalized] = (counts[normalized] || 0) + 1;
        return counts;
      },
      { pending: 0, running: 0, completed: 0, skipped: 0, failed: 0, cancelled: 0 }
    );
  }

  function assessmentChainStepStatus(step) {
    return String(step?.status || "pending").toLowerCase().replaceAll("_", "-");
  }

  function assessmentChainStepStatusLabel(step) {
    const status = assessmentChainStepStatus(step);
    const mapping = {
      pending: "Pending",
      requested: "Queued",
      queued: "Queued",
      running: "Running",
      active: "Running",
      completed: "Done",
      skipped: "Skipped",
      failed: "Failed",
      cancelled: "Cancelled",
    };
    return mapping[status] || capitalizeWord(status.replaceAll("-", " "));
  }

  function assessmentChainStepDetailLines(step) {
    const lines = [];
    const reason = step?.skip_reason || step?.evidence || step?.failure_triage?.reason;
    if (reason) lines.push(String(reason));
    if (step?.prerequisite && step.prerequisite !== reason) {
      lines.push(`Prerequisite: ${step.prerequisite}`);
    }
    if (step?.safe_next_action) {
      lines.push(`Safe next action: ${step.safe_next_action}`);
    }
    return lines;
  }

  function assessmentChainHasLifecycleRows(chain) {
    return Array.isArray(chain?.phases) && chain.phases.some((phase) => Array.isArray(phase?.steps) && phase.steps.length);
  }

  function assessmentChainRunnerLabel(profileName) {
    const cleaned = String(profileName || "Unnamed runner").replaceAll("_", "-");
    const acronyms = new Set(["ad", "api", "asrep", "easm", "http", "https", "lan", "ldap", "llmnr", "smb", "tls"]);
    return cleaned
      .split("-")
      .filter(Boolean)
      .map((part) => (acronyms.has(part.toLowerCase()) ? part.toUpperCase() : capitalizeWord(part)))
      .join(" ");
  }

  function flattenAssessmentChainSteps(chain) {
    const phases = Array.isArray(chain?.phases) ? chain.phases : [];
    const rows = [];
    phases.forEach((phase, phaseIndex) => {
      const steps = Array.isArray(phase?.steps) ? phase.steps : [];
      steps.forEach((step, stepIndex) => {
        rows.push({
          phase,
          phaseIndex,
          step,
          stepIndex,
          isCursor:
            Number(chain?.current_phase_index || 0) === phaseIndex &&
            Number(chain?.current_step_index || 0) === stepIndex,
          status: assessmentChainStepStatus(step),
        });
      });
    });
    return rows;
  }

  function isOpenAssessmentChainStep(row) {
    return ["pending", "requested", "queued", "running", "active"].includes(row.status);
  }

  function isActiveAssessmentChainStep(row) {
    return ["requested", "queued", "running", "active"].includes(row.status) || row.isCursor;
  }

  function renderAssessmentChainOperatorMap(chain) {
    const rows = flattenAssessmentChainSteps(chain);
    if (!rows.length) return "";
    const activeRow =
      rows.find((row) => ["running", "active"].includes(row.status)) ||
      rows.find((row) => ["requested", "queued"].includes(row.status)) ||
      rows.find((row) => row.isCursor && isOpenAssessmentChainStep(row)) ||
      null;
    const activeIndex = activeRow ? rows.indexOf(activeRow) : -1;
    const nextRow =
      rows.find((row, index) => index > activeIndex && ["pending", "requested", "queued"].includes(row.status)) ||
      (!activeRow ? rows.find((row) => ["pending", "requested", "queued"].includes(row.status)) || null : null);
    const openRows = rows.filter(isOpenAssessmentChainStep);
    const skippedRows = rows.filter((row) => row.status === "skipped");
    const failedRows = rows.filter((row) => row.status === "failed");
    const completedRows = rows.filter((row) => row.status === "completed");
    const nowLabel = activeRow
      ? assessmentChainRunnerLabel(activeRow.step?.profile_name)
      : String(chain?.status || "").toLowerCase() === "completed_with_gaps"
        ? "Runnable checks finished with gaps"
        : String(chain?.status || "").toLowerCase() === "completed"
          ? "All planned runners finished"
          : "Waiting for the next runner";
    const nextLabel = nextRow
      ? assessmentChainRunnerLabel(nextRow.step?.profile_name)
      : openRows.length
        ? "Open runners are being resolved"
        : "No queued runner remains";
    const remainingLabel = openRows.length
      ? `${openRows.length} open · ${completedRows.length} done · ${skippedRows.length} skipped`
      : `${completedRows.length} done · ${skippedRows.length} skipped${failedRows.length ? ` · ${failedRows.length} failed` : ""}`;

    return `
      <div class="assessment-chain-operator-map split-top" data-testid="assessment-chain-operator-map">
        <div class="chain-now-next-grid">
          <div>
            <span>Now</span>
            <strong>${escapeHtml(nowLabel)}</strong>
            <small>${escapeHtml(
              activeRow
                ? `${activeRow.phase?.label || `Phase ${activeRow.phaseIndex + 1}`} · ${assessmentChainStepStatusLabel(activeRow.step)}`
                : String(chain?.status || "unknown").replaceAll("_", " ")
            )}</small>
          </div>
          <div>
            <span>Next</span>
            <strong>${escapeHtml(nextLabel)}</strong>
            <small>${escapeHtml(nextRow ? `${nextRow.phase?.label || `Phase ${nextRow.phaseIndex + 1}`} waits after the current runner` : "Nothing else is queued from this plan")}</small>
          </div>
          <div>
            <span>Remaining Plan</span>
            <strong>${escapeHtml(remainingLabel)}</strong>
            <small>${escapeHtml("Runner states are live: queued, running, done, skipped, or failed.")}</small>
          </div>
        </div>
        <div class="chain-runner-roadmap" data-testid="assessment-chain-runner-roadmap">
          ${(Array.isArray(chain?.phases) ? chain.phases : [])
            .map((phase, phaseIndex) => {
              const steps = Array.isArray(phase?.steps) ? phase.steps : [];
              const counts = summarizeAssessmentChainSteps(steps);
              return `
                <section class="chain-phase-lane">
                  <header>
                    <span>${escapeHtml(`Phase ${phaseIndex + 1}`)}</span>
                    <strong>${escapeHtml(phase?.label || "Unnamed phase")}</strong>
                    <small>${escapeHtml(`${counts.completed || 0} done · ${counts.running || 0} running · ${counts.pending || 0} pending · ${counts.skipped || 0} skipped`)}</small>
                  </header>
                  <div class="chain-runner-list">
                    ${steps
                      .map((step, stepIndex) => {
                        const row = {
                          phase,
                          phaseIndex,
                          step,
                          stepIndex,
                          isCursor:
                            Number(chain?.current_phase_index || 0) === phaseIndex &&
                            Number(chain?.current_step_index || 0) === stepIndex,
                          status: assessmentChainStepStatus(step),
                        };
                        const currentClass = isActiveAssessmentChainStep(row) ? " current" : "";
                        return `
                          <div class="chain-runner-row status-${escapeHtml(row.status)}${currentClass}">
                            <span class="chain-runner-dot" aria-hidden="true"></span>
                            <div>
                              <strong>${escapeHtml(assessmentChainRunnerLabel(step?.profile_name))}</strong>
                              ${assessmentChainStepDetailLines(step)
                                .map((line) => `<small>${escapeHtml(line)}</small>`)
                                .join("")}
                            </div>
                            <span>${escapeHtml(assessmentChainStepStatusLabel(step))}</span>
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

  function assessmentChainPhaseProgress(phase) {
    const steps = Array.isArray(phase?.steps) ? phase.steps : [];
    const counts = summarizeAssessmentChainSteps(steps);
    const resolved = counts.completed + counts.skipped + counts.failed + counts.cancelled;
    const normalizedStatus = String(phase?.status || "pending").toLowerCase();
    if (["completed", "completed_with_gaps"].includes(normalizedStatus)) return 100;
    if (!steps.length) {
      if (normalizedStatus === "pending_approval") return 12;
      if (["blocked", "rejected", "cancelled", "halted"].includes(normalizedStatus)) return 20;
      return normalizedStatus === "active" ? 25 : 0;
    }
    let progress = Math.round((resolved / steps.length) * 100);
    if (normalizedStatus === "active" && counts.running) {
      progress = Math.max(progress, Math.round(((resolved + 0.5) / steps.length) * 100), 20);
    } else if (normalizedStatus === "pending_approval") {
      progress = Math.max(progress, 12);
    } else if (["blocked", "rejected", "cancelled", "halted"].includes(normalizedStatus)) {
      progress = Math.max(progress, 20);
    }
    return Math.max(0, Math.min(100, progress));
  }

  function assessmentChainPhaseCardStatus(phase) {
    const normalizedStatus = String(phase?.status || "pending").toLowerCase();
    if (["completed", "completed_with_gaps"].includes(normalizedStatus)) return "complete";
    if (["active", "running"].includes(normalizedStatus)) return "active";
    if (["pending_approval", "blocked", "rejected", "cancelled", "halted"].includes(normalizedStatus)) {
      return "blocked";
    }
    return "pending";
  }

  function assessmentChainPhaseSummary(phase) {
    const steps = Array.isArray(phase?.steps) ? phase.steps : [];
    const counts = summarizeAssessmentChainSteps(steps);
    const plannedCount = steps.length;
    const resolvedCount = counts.completed + counts.skipped;
    const nextStep =
      steps.find((step) => !["completed", "skipped"].includes(String(step?.status || "").toLowerCase())) || null;
    const normalizedStatus = String(phase?.status || "pending").toLowerCase();
    if (normalizedStatus === "pending_approval") {
      return `${plannedCount} planned runner${plannedCount === 1 ? "" : "s"} ready. Approval starts ${nextStep?.profile_name || "the next step"}.`;
    }
    if (["completed", "completed_with_gaps"].includes(normalizedStatus)) {
      return plannedCount
        ? `${counts.completed} completed${counts.skipped ? ` · ${counts.skipped} skipped` : ""}.`
        : "Phase completed.";
    }
    if (normalizedStatus === "active") {
      return plannedCount
        ? `${resolvedCount} of ${plannedCount} runner${plannedCount === 1 ? "" : "s"} resolved${counts.running ? ` · ${counts.running} running` : ""}.`
        : "Phase is active.";
    }
    if (normalizedStatus === "blocked") {
      return `${counts.failed || 0} failed runner${counts.failed === 1 ? "" : "s"} blocked this phase.`;
    }
    if (normalizedStatus === "rejected") {
      return "This phase was explicitly rejected and the chain stopped here.";
    }
    if (normalizedStatus === "cancelled") {
      return "This phase was cancelled before the full runner plan completed.";
    }
    return plannedCount
      ? `Waiting for the earlier phase to finish before ${plannedCount} planned runner${plannedCount === 1 ? "" : "s"} can begin.`
      : "Waiting for the earlier phase to finish.";
  }

  function failedAssessmentChainStep(phase) {
    const steps = Array.isArray(phase?.steps) ? phase.steps : [];
    return steps.find((step) => String(step?.status || "").toLowerCase() === "failed") || null;
  }

  function renderAssessmentChainPhaseDetail(phase) {
    const steps = Array.isArray(phase?.steps) ? phase.steps : [];
    if (!steps.length) return "";
    const isBlocked = String(phase?.status || "").toLowerCase() === "blocked";
    const failedStep = failedAssessmentChainStep(phase);
    return renderDisclosure({
      title: "Phase Runners",
      summary: failedStep
        ? `${failedStep.profile_name || "A runner"} failed; review or continue after acknowledging it`
        : `${steps.length} runner${steps.length === 1 ? "" : "s"} in this tier`,
      open: isBlocked,
      testId: "assessment-chain-phase-runners",
      body: `
        ${
          failedStep
            ? `
              <div class="callout warning split-bottom">
                <strong>${escapeHtml(failedStep.profile_name || "Runner")} blocked auto-advance.</strong>
                <span>${escapeHtml(
                  failedStep.run_id
                    ? `Run ${failedStep.run_id} did not complete cleanly. This is not an authorization issue; it is a runner outcome that needs operator review.`
                    : "This runner did not complete cleanly. This is not an authorization issue; it is a runner outcome that needs operator review."
                )}</span>
                ${
                  failedStep.safe_next_action
                    ? `<span>${escapeHtml(`Safe next action: ${failedStep.safe_next_action}`)}</span>`
                    : ""
                }
              </div>
            `
            : ""
        }
        <div class="compact-definition-grid">
          ${steps
            .map(
              (step, index) => `
                <div>
                  <span>${escapeHtml(`Step ${index + 1}`)}</span>
                  <strong>${escapeHtml(step.profile_name || "Unnamed profile")} · ${escapeHtml(String(step.status || "pending"))}</strong>
                  ${assessmentChainStepDetailLines(step)
                    .map((line) => `<small>${escapeHtml(line)}</small>`)
                    .join("")}
                </div>
              `
            )
            .join("")}
        </div>
      `,
    });
  }

  function renderAssessmentChainPanel(chain) {
    if (!chain) return "";
    const phase = currentAssessmentChainPhase(chain);
    const phases = Array.isArray(chain.phases) ? chain.phases : [];
    const totalPhases = Number(chain.phase_count || (Array.isArray(chain.phases) ? chain.phases.length : 0));
    const completedPhases = Number(chain.completed_phase_count || 0);
    const modeLabel = assessmentModeLabel(chain.assessment_mode);
    const failedStep = failedAssessmentChainStep(phase);
    const normalizedChainStatus = String(chain.status || "").toLowerCase();
    const boundaryReady =
      !chain.current_run_id &&
      !["completed", "completed_with_gaps", "cancelled", "rejected"].includes(normalizedChainStatus);
    const summary =
      normalizedChainStatus === "pending_phase_approval"
        ? `${modeLabel} paused at the ${String(phase?.label || "next phase").toLowerCase()} boundary. Approve this tier once and AegisPT will queue the next runner automatically.`
        : normalizedChainStatus === "active"
          ? `${modeLabel} is auto-chaining the approved runner sequence. Mission Control follows the current phase and the current run dossier together.`
          : normalizedChainStatus === "halted"
            ? `${modeLabel} is halted. No new phase will start until the operator intentionally relaunches or replaces the chain.`
            : normalizedChainStatus === "completed"
              ? `${modeLabel} finished all planned phases.`
              : normalizedChainStatus === "completed_with_gaps"
                ? `${modeLabel} finished every runnable check, but some phase runners were skipped because required inputs were missing or no eligible evidence existed. Expand Phase Runners to see exactly what was not run.`
              : normalizedChainStatus === "blocked" && failedStep
                ? `${modeLabel} stopped because ${failedStep.profile_name || "a runner"} failed. Your mission authorization is still recorded; this is a runner failure, not a missing approval.`
                : `${modeLabel} is currently ${String(chain.status || "unknown").replaceAll("_", " ")}.`;
    return `
      <div class="detail-surface emphasis-surface split-top" data-testid="assessment-chain-panel">
        <div class="task-activity-header">
          <h4>${escapeHtml(modeLabel)}</h4>
          <div class="inline-metrics">
            ${statusPill(String(chain.status || "unknown"))}
          </div>
        </div>
        <p>${escapeHtml(summary)}</p>
        ${renderBadgeList(
          [
            `${completedPhases} of ${Math.max(totalPhases, 1)} phase${Math.max(totalPhases, 1) === 1 ? "" : "s"} complete`,
            phase?.label || null,
            chain.auto_advance_on_phase_complete ? "Auto-advance enabled" : "Boundary approvals only",
            chain.halt_requested ? "Halt requested" : null,
          ],
          "compact-badge-list split-top"
        )}
        ${
          phases.length
            ? `
              <div class="mission-phase-stepper split-top" data-testid="assessment-chain-phase-strip">
                ${phases
                  .map((chainPhase) =>
                    renderPhaseCard({
                      label: chainPhase.label || "Unnamed phase",
                      status: assessmentChainPhaseCardStatus(chainPhase),
                      progress: assessmentChainPhaseProgress(chainPhase),
                      elapsed: formatElapsedMinutes(chainPhase.started_at || chain?.created_at, 0),
                      summary: assessmentChainPhaseSummary(chainPhase),
                      nfirPhase: nfirPhaseForAssessmentChainPhase(chainPhase),
                    })
                  )
                  .join("")}
              </div>
            `
            : ""
        }
        ${
          phase
            ? `
              ${renderAssessmentChainOperatorMap(chain)}
              <div class="compact-definition-grid split-top">
                <div><span>Current Phase</span><strong>${escapeHtml(phase.label || "Unknown phase")}</strong></div>
                <div><span>Tier</span><strong>${escapeHtml(capitalizeWord(phase.tier || "unknown"))}</strong></div>
                <div><span>Boundary</span><strong>${escapeHtml(String(phase.status || "pending").replaceAll("_", " "))}</strong></div>
                <div><span>Current Run</span><strong>${escapeHtml(chain.current_run_id || chain.last_completed_run_id || "No active run")}</strong></div>
              </div>
              ${renderAssessmentChainPhaseDetail(phase)}
            `
            : ""
        }
        <div class="panel-actions split-top">
          ${
            String(chain.status || "").toLowerCase() === "pending_phase_approval" && phase
              ? `
                <button
                  class="action primary"
                  type="button"
                  data-assessment-chain-id="${escapeHtml(chain.id)}"
                  data-assessment-chain-phase-key="${escapeHtml(phase.key || "")}"
                  data-assessment-chain-phase-decision="approved"
                  data-testid="assessment-chain-approve"
                >
                  Approve Phase
                </button>
                <button
                  class="action ghost"
                  type="button"
                  data-assessment-chain-id="${escapeHtml(chain.id)}"
                  data-assessment-chain-phase-key="${escapeHtml(phase.key || "")}"
                  data-assessment-chain-phase-decision="rejected"
                  data-testid="assessment-chain-reject"
                >
                  Reject Phase
                </button>
              `
              : ""
          }
          ${
            boundaryReady
              ? `
                ${
                  String(chain.status || "").toLowerCase() === "blocked"
                    ? `
                      <button
                        class="action primary"
                        type="button"
                        data-assessment-chain-id="${escapeHtml(chain.id)}"
                        data-assessment-chain-continue="true"
                        data-testid="assessment-chain-continue"
                      >
                        Review Failure & Continue
                      </button>
                    `
                    : ""
                }
                <button
                  class="action ghost"
                  type="button"
                  data-assessment-chain-id="${escapeHtml(chain.id)}"
                  data-assessment-chain-halt="true"
                  data-testid="assessment-chain-halt"
                >
                  Halt At Boundary
                </button>
              `
              : ""
          }
        </div>
      </div>
    `;
  }

  function renderPendingApprovalRunActivity(run) {
    const approvals = approvalStateForRun(run);
    const approvalLabel = approvals.required === 1 ? "approval" : "approvals";
    const profileName =
      run?.profile?.name ||
      run?.configuration_json?.execution_profile ||
      "the selected execution lane";
    const approvalStepId = String(run?.approval_step_id || "run.launch");
    const actorApproval = currentActorApproval(run);
    const approvalHistory = sortedRunApprovals(run);
    const approvalSubmitting = String(state.loading.approvalRunId || "") === String(run?.id || "");
    const submittingDecision = String(state.loading.approvalDecision || "").toLowerCase();
    const actorAlreadyDecided = Boolean(actorApproval);
    const actorStatusNote = actorAlreadyDecided
      ? actorApproval.decision === "approved"
        ? approvals.pending > 0
          ? `Actor ${state.actor} already approved this gate. Change the actor in the top bar to record the remaining approval.`
          : `Actor ${state.actor} already approved this gate. Mission Control will queue the planned checks as soon as the approval state clears.`
        : `Actor ${state.actor} already rejected this gate. This actor cannot submit a second decision on the same gate.`
      : approvals.pending > 1
        ? `Approval decisions are tied to the actor field in the top bar. Use a different actor for the additional required approval.`
        : `Approval decisions are tied to the actor field in the top bar.`;
    return `
      <h4>${escapeHtml("Approval is still required before active checks can be queued")}</h4>
      <p>${escapeHtml(approvalWaitingSummary(run))}</p>
      <div class="detail-surface emphasis-surface split-top" data-testid="pending-approval-run-activity">
        <h4>Approval Status</h4>
        <div class="compact-definition-grid">
          <div><span>Execution Lane</span><strong>${escapeHtml(profileName)}</strong></div>
          <div><span>Approval Gate</span><strong>${escapeHtml(approvalStepId)}</strong></div>
          <div><span>Required</span><strong>${escapeHtml(String(approvals.required))}</strong></div>
          <div><span>Granted</span><strong>${escapeHtml(String(approvals.granted))}</strong></div>
          <div><span>Pending</span><strong>${escapeHtml(String(approvals.pending))}</strong></div>
          <div><span>Current Actor</span><strong>${escapeHtml(state.actor)}</strong></div>
        </div>
        <p class="micro-copy">${escapeHtml(
          approvals.pending > 0
            ? `This mission is approval-gated, so AegisPT will only queue the planned active checks after the remaining ${approvals.pending} ${approvalLabel} are recorded.`
            : "This mission is approval-gated, and Mission Control will queue the planned active checks as soon as the approval state is fully cleared."
        )}</p>
        <p class="micro-copy split-top" data-testid="run-approval-actor-note">${escapeHtml(actorStatusNote)}</p>
        ${
          actorApproval
            ? `
              <div class="inline-metrics split-top">
                <span class="metric-pill">${escapeHtml(`Current actor decision · ${actorApproval.decision}`)}</span>
                <span class="metric-pill">${escapeHtml(formatDateTime(actorApproval.created_at))}</span>
              </div>
            `
            : ""
        }
        ${renderDisclosure({
          title: "Recorded Decisions",
          summary: approvalHistory.length
            ? `${approvalHistory.length} decision${approvalHistory.length === 1 ? "" : "s"} on this gate`
            : "No decisions recorded yet",
          open: false,
          testId: "run-approval-history",
          body: approvalHistory.length
            ? `
                <div class="approval-history-list">
                  ${approvalHistory
                    .map(
                      (approval) => `
                        <div class="approval-history-item">
                          <div>
                            <strong>${escapeHtml(approval.approver_id || "unknown actor")}</strong>
                            <span>${escapeHtml(formatDateTime(approval.created_at))}</span>
                          </div>
                          ${statusPill(approval.decision || "unknown")}
                        </div>
                      `
                    )
                    .join("")}
                </div>
              `
            : `<p class="micro-copy">No approval decisions were recorded yet.</p>`,
        })}
        <div class="panel-actions split-top">
          <button
            class="action primary"
            type="button"
            data-run-approval-run-id="${escapeHtml(String(run?.id || ""))}"
            data-run-approval-step-id="${escapeHtml(approvalStepId)}"
            data-run-approval-decision="approved"
            data-testid="run-approval-approve"
            ${approvalSubmitting || actorAlreadyDecided ? "disabled" : ""}
          >
            ${escapeHtml(approvalSubmitting && submittingDecision === "approved" ? "Recording approval..." : "Approve Run")}
          </button>
          <button
            class="action ghost"
            type="button"
            data-run-approval-run-id="${escapeHtml(String(run?.id || ""))}"
            data-run-approval-step-id="${escapeHtml(approvalStepId)}"
            data-run-approval-decision="rejected"
            data-testid="run-approval-reject"
            ${approvalSubmitting || actorAlreadyDecided ? "disabled" : ""}
          >
            ${escapeHtml(approvalSubmitting && submittingDecision === "rejected" ? "Rejecting run..." : "Reject Run")}
          </button>
          ${
            approvals.pending > 0
              ? `
                <button
                  class="action ghost"
                  type="button"
                  data-focus-actor-input="true"
                  data-testid="run-approval-focus-actor"
                >
                  ${escapeHtml(actorAlreadyDecided ? "Change Actor" : "Review Actor")}
                </button>
              `
              : ""
          }
        </div>
      </div>
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
        <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
      </div>
    `;
  }

  function currentRunLabel(run) {
    return (
      run?.profile?.name ||
      run?.configuration_json?.execution_profile ||
      run?.configuration_json?.test_profile ||
      "Selected run"
    );
  }

  function currentRunPhaseLabel(run) {
    const chain = selectedAssessmentChain(run);
    return (
      currentAssessmentChainPhase(chain)?.label ||
      run?.configuration_json?.assessment_type ||
      "Execution"
    );
  }

  function renderMissionKpi(label, value, tone = "neutral") {
    return `
      <div class="mission-kpi-card tone-${escapeHtml(tone)}">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(String(value || 0))}</strong>
      </div>
    `;
  }

  function renderCurrentActivityOverview(activity) {
    const run = state.selectedRun;
    if (!run) {
      return emptyState(activity?.summary || "No mission is active yet.", {
        label: activity?.primaryAction?.label || "Start a mission",
        screen: activity?.primaryAction?.screen || "wizard",
        testId: "mission-activity-empty-action",
      });
    }
    const tasks = Array.isArray(run.tasks) ? run.tasks : [];
    const counts = summarizeTaskStatuses(tasks);
    const resolved = Number(counts.completed || 0) + Number(counts.failed || 0) + Number(counts.cancelled || 0);
    const status = String(run.status || "unknown").toLowerCase();
    const engagement = runtime.actions.selectedEngagement?.();
    return `
      <div class="mission-status-overview" data-testid="mission-current-activity-overview">
        <div class="mission-status-head">
        <div class="chip-row compact">
          ${statusPill(run.status || "unknown")}
          <span class="metric-pill">${escapeHtml(currentRunPhaseLabel(run))}</span>
        </div>
        <h4>${escapeHtml(currentRunLabel(run))}</h4>
        <span class="mission-status-subline">${escapeHtml(
          activity?.title || engagement?.name || run.configuration_json?.engagement_name || "Selected engagement"
        )}</span>
      </div>
      <div class="mission-kpi-grid">
          ${renderMissionKpi("Queued", counts.queued || 0, "pending")}
          ${renderMissionKpi("Running", counts.running || 0, "active")}
          ${renderMissionKpi("Done", resolved, ["failed", "cancelled"].includes(status) ? "blocked" : "complete")}
        </div>
        ${
          activity?.primaryAction || activity?.secondaryAction
            ? `
              <div class="panel-actions">
                ${renderActivityAction(activity?.primaryAction, "primary")}
                ${renderActivityAction(activity?.secondaryAction, "ghost")}
              </div>
            `
            : ""
        }
      </div>
    `;
  }

  function renderMissionControl() {
    const phases = buildMissionPhases();
    const activity = deriveCurrentActivity(phases);
    const run = state.selectedRun;
    const tasks = [...(run?.tasks || [])];
    const findings = selectedRunFindingsForMission();
    const counts = summarizeTaskStatuses(tasks);
    dom.missionActivity.innerHTML = renderMissionMapColumn({ activity, run, tasks, findings, counts });
    dom.missionTimeline.innerHTML = "";

    const statusBoard = deriveStatusBoard();
    dom.missionGood.innerHTML = renderSignalList(statusBoard.good, "good", "Healthy signals appear here after scope and mission activity are available.");
    dom.missionBad.innerHTML = renderSignalList(statusBoard.bad, "critical", "No blocking issues detected right now.");
    dom.missionUnknown.innerHTML = renderSignalList(statusBoard.unknown, "unknown", "No unknowns are currently flagged.");

    const eta = deriveMissionEta(phases);
    dom.missionEta.innerHTML = `
      <h4>${escapeHtml(`${eta.elapsed_label} elapsed`)}</h4>
      <p>${escapeHtml(`${eta.remaining_label} remaining · ${eta.confidence_label}`)}</p>
      <div class="progress-track"><div class="progress-bar" style="width:${eta.percent_complete}%"></div></div>
    `;

    const pulse = buildFindingsPulse();
    if (pulse.mode === "inventory") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.host_count} hosts discovered`)}</h4>
        <p>${escapeHtml(`${pulse.service_count} services mapped · confidence ${toPercent(pulse.confidence_score)}`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
          <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
        </div>
      `;
    } else if (pulse.mode === "inventory-pending") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml("Discovery is running")}</h4>
        <p>${escapeHtml("Inventory-first runs do not create findings until the sweep completes.")}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="mission-control">Stay in Mission Control</button>
          <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
        </div>
      `;
    } else if (pulse.mode === "inventory-follow-up") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.host_count} hosts discovered`)}</h4>
        <p>${escapeHtml(`${pulse.service_count} services mapped · deeper follow-up is ready.`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="mission-control">Open Next Steps</button>
          <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
        </div>
      `;
    } else {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.confirmed} confirmed`)}</h4>
        <p>${escapeHtml(`${pulse.critical} critical/high priority · ${pulse.evidence_completeness}% evidence completeness`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="findings-theater">Open Findings Theater</button>
          <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence Replay</button>
        </div>
      `;
    }

    if (dom.missionExposureScore) {
      dom.missionExposureScore.innerHTML = renderMissionExposureScore();
    }
    dom.missionAiNarrative.innerHTML = renderMissionGuidanceCard();
    dom.missionPackStatus.innerHTML = renderEngagementRunQueueSummary();
    dom.missionScopeSummary.innerHTML = renderScopeProfileSummary();
    dom.missionRunActivity.innerHTML = renderRunActivitySummary();
    attachMissionAiProposalHandlers();
    attachMissionRunActivityHandlers();
    attachMissionSupportHandlers();
    ensureAiSignalStream();
  }

  function renderMissionMapColumn({ activity, run, tasks, findings, counts }) {
    if (!run) {
      return emptyState(activity?.summary || "No mission is active yet.", {
        label: activity?.primaryAction?.label || "Start a mission",
        screen: activity?.primaryAction?.screen || "wizard",
        testId: "mission-activity-empty-action",
      });
    }
    const activeTargetMap = renderActiveTargetScanMap({ run, tasks, findings, counts });
    const findingsSummary =
      findings.length
        ? renderSeverityCounters(run, findings)
        : `
            <div class="mission-findings-inline" data-testid="mission-findings-inline-empty">
              <h4>Findings so far</h4>
              <p class="micro-copy">No persisted findings yet. Discovery and queued checks stay visible while evidence lands.</p>
            </div>
          `;
    return `
      <div class="mission-column-stack" data-testid="mission-current-activity-overview">
        ${activeTargetMap}
        ${findingsSummary}
      </div>
    `;
  }

  function renderMissionLaunchSequence() {
    const run = state.selectedRun;
    if (!run) {
      return `
        <div class="mission-launch-card is-empty" data-testid="mission-launch-sequence" data-launch-state="idle">
          <p class="eyebrow">Mission Launch</p>
          <h4>${escapeHtml("Launch sequence waits for a confirmed mission")}</h4>
          <p>${escapeHtml("No queued work, runner motion, or execution status is shown until Intake creates a real run dossier.")}</p>
        </div>
      `;
    }

    const tasks = run.tasks || [];
    const counts = summarizeTaskStatuses(tasks);
    const normalizedStatus = String(run.status || "unknown").toLowerCase();
    const runId = String(run.id || "selected run");
    const profileName =
      run.profile?.name ||
      run.configuration_json?.execution_profile ||
      run.configuration_json?.test_profile ||
      "selected execution lane";
    const dispatching =
      state.loading.dispatchRunId === run.id &&
      normalizedStatus === "queued";
    const approvalBlocked = normalizedStatus === "pending_approval";
    const running = counts.running > 0 || normalizedStatus === "running";
    const completed = ["completed", "completed_with_errors", "failed", "cancelled"].includes(normalizedStatus);
    const ready = canDispatchSelectedRun();
    const launchState = dispatching
      ? "dispatching"
      : approvalBlocked
        ? "blocked"
        : running
          ? "active"
          : completed
            ? "complete"
            : ready
              ? "ready"
              : normalizedStatus;
    const headline = dispatching
      ? "Mission launch is dispatching"
      : approvalBlocked
        ? "Mission accepted; approval is required"
        : running
          ? "Mission is active"
          : completed
            ? "Mission execution state is recorded"
            : ready
              ? "Mission accepted and queued"
              : "Mission dossier is open";
    const summary = dispatching
      ? `${counts.queued} queued check${counts.queued === 1 ? "" : "s"} are crossing the controlled runtime boundary now.`
      : approvalBlocked
        ? approvalWaitingSummary(run)
        : running
          ? `${counts.running} check${counts.running === 1 ? "" : "s"} are running from persisted task state.`
          : completed
            ? `Run ${runId} is ${normalizedStatus}; Mission Control is showing stored run and task state.`
            : ready
              ? `${counts.queued} queued check${counts.queued === 1 ? "" : "s"} are attached to ${profileName}. Starting queued checks remains an explicit operator action.`
              : `Run ${runId} is ${normalizedStatus}; no additional launch motion is implied.`;
    const steps = [
      {
        label: "Dossier",
        state: "complete",
        detail: `Run ${runId} created`,
      },
      {
        label: "Queue",
        state: approvalBlocked ? "blocked" : tasks.length ? "complete" : "pending",
        detail: approvalBlocked
          ? "Waiting for approval"
          : tasks.length
            ? `${tasks.length} planned check${tasks.length === 1 ? "" : "s"}`
            : "No queued checks recorded",
      },
      {
        label: "Runtime",
        state: dispatching || running ? "active" : completed ? "complete" : approvalBlocked ? "blocked" : ready ? "pending" : "pending",
        detail: dispatching
          ? "Dispatch in progress"
          : running
            ? "Runner active"
            : completed
              ? "Execution recorded"
              : approvalBlocked
                ? "Approval gate"
                : ready
                  ? "Operator start required"
                  : normalizedStatus,
      },
    ];

    const justCreated = String(state.missionLaunch?.runId || "") === String(run.id || "");
    return `
      <div class="mission-launch-card is-${escapeHtml(launchState)} ${justCreated ? "just-created" : ""}" data-testid="mission-launch-sequence" data-launch-state="${escapeHtml(launchState)}">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Mission Launch</p>
            <h4>${escapeHtml(headline)}</h4>
          </div>
          <span class="metric-pill">${escapeHtml(profileName)}</span>
        </div>
        <p>${escapeHtml(summary)}</p>
        <div class="mission-launch-steps split-top">
          ${steps.map(renderMissionLaunchStep).join("")}
        </div>
      </div>
    `;
  }

  function renderMissionExposureScore() {
    const exposure = state.exposureScore;
    const current = exposure?.current || null;
    const history = Array.isArray(exposure?.history) ? exposure.history : [];
    if (!current) {
      return emptyState("Exposure score appears after the engagement posture has been computed.");
    }
    const score = Math.max(0, Math.min(100, Number(current.score || 0)));
    const tone = exposureScoreTone(score);
    const toneLabels = {
      healthy: "Lower stored exposure",
      watch: "Moderate stored exposure",
      warning: "Elevated stored exposure",
      critical: "High stored exposure",
    };
    return `
      <div class="exposure-panel" data-testid="mission-exposure-score">
        <div class="exposure-gauge tone-${escapeHtml(tone)}" style="--exposure-score:${score};">
          <div class="exposure-gauge-inner">
            <strong>${escapeHtml(formatExposureScore(score))}</strong>
            <span>/100</span>
          </div>
        </div>
        <div class="exposure-copy">
          <h4>${escapeHtml(toneLabels[tone] || "Stored exposure score")}</h4>
          <p>${escapeHtml(`${current.open_critical_count} critical open · ${current.open_high_count} high open · ${current.verified_count} verified`)}</p>
          <p class="micro-copy">${escapeHtml("Advisory only. This score summarizes stored findings and remediation progress; it never gates runs or approvals.")}</p>
          ${renderBadgeList([
            `Trend · ${exposureTrendLabel(current.trend)}`,
            `Remediated · ${current.remediated_count}`,
            `Computed · ${formatDateTime(current.computed_at)}`,
          ])}
          ${renderExposureSparkline(history, {
            width: 220,
            height: 40,
            className: "mission-exposure-sparkline",
            testId: "mission-exposure-sparkline",
          })}
        </div>
      </div>
    `;
  }

  function renderMissionLaunchStep(step) {
    return `
      <div class="mission-launch-step ${escapeHtml(step.state)}">
        <span>${escapeHtml(step.label)}</span>
        <strong>${escapeHtml(step.detail)}</strong>
      </div>
    `;
  }

  function buildMissionPhases() {
    const run = state.selectedRun;
    const assessmentChain = selectedAssessmentChain(run);
    if (assessmentChain) {
      const chainPhases = Array.isArray(assessmentChain.phases) ? assessmentChain.phases : [];
      return chainPhases.map((phase, index) => ({
        key: phase.key || `phase-${index + 1}`,
        label: phase.label || `Phase ${index + 1}`,
        status: assessmentChainPhaseCardStatus(phase),
        progress: assessmentChainPhaseProgress(phase),
        summary: assessmentChainPhaseSummary(phase),
        elapsed: formatElapsedMinutes(phase.started_at || run?.created_at, index * 4),
      }));
    }
    const config = run?.configuration_json || {};
    const inventory = runtime.actions.selectedRunInventorySnapshot?.();
    const inventorySeedOnly = isSeedOnlyInventory(inventory);
    const dispatching =
      state.loading.dispatchRunId === run?.id &&
      String(run?.status || "").toLowerCase() === "queued";
    const relevance = runtime.actions.latestRelevanceDecision?.();
    const pack = runtime.actions.selectedPack?.();
    const tasks = run?.tasks || [];
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const hasAccessContext = hasMeaningfulAccessContext(config.access || {});
    const accessContextCount = countMeaningfulAccessContexts(config.access || {});
    const activeProfileNeedsAuth = requiresCredentials(config);
    const taskCounts = summarizeTaskStatuses(tasks);
    const deepProgress = tasks.length ? Math.round(((taskCounts.completed + taskCounts.failed + taskCounts.cancelled) / tasks.length) * 100) : 0;
    const adaptiveProgress = pack ? packProgress(pack.status) : (config.safety?.adaptive_generation === false ? 100 : relevance ? 45 : 0);
    const verificationResolved = findings.length ? Math.round((findings.filter((finding) => finding.status === "resolved").length / findings.length) * 100) : 0;
    const phases = [
      {
        key: "recon",
        label: "Recon",
        status: inventory ? "complete" : run ? "active" : "pending",
        progress: inventory ? 100 : run ? 25 : 0,
        summary: inventory
          ? inventorySeedOnly
            ? `${inventory.summary_json.host_count} hosts were seeded from reviewed wizard scope.`
            : `${inventory.summary_json.host_count} hosts were discovered or confirmed.`
          : "Waiting for inventory seed or discovery activity.",
      },
      {
        key: "surface",
        label: "Surface Mapping",
        status: inventory ? "complete" : "pending",
        progress: inventory ? 100 : 0,
        summary: inventory
          ? inventorySeedOnly
            ? `${inventory.summary_json.endpoint_count} targets and ${inventory.summary_json.technology_count} stack hints were seeded for later confirmation.`
            : `${inventory.summary_json.endpoint_count} endpoints and ${inventory.summary_json.technology_count} technologies were mapped.`
          : "No mapped surface yet.",
      },
      {
        key: "auth",
        label: "Auth Access",
        status: activeProfileNeedsAuth && !hasAccessContext ? "blocked" : (hasAccessContext || !activeProfileNeedsAuth ? "complete" : "pending"),
        progress: hasAccessContext || !activeProfileNeedsAuth ? 100 : 10,
        summary: hasAccessContext
          ? `${accessContextCount} access context${accessContextCount === 1 ? "" : "s"} loaded.`
          : activeProfileNeedsAuth
            ? "Assessment expects authenticated access but no access context is configured."
            : "No dedicated auth context required.",
      },
      {
        key: "analysis",
        label: "Deep Analysis",
        status: dispatching
          ? "active"
          : run?.status === "pending_approval"
            ? "blocked"
            : tasks.length
              ? (deepProgress >= 100 ? "complete" : "active")
              : (run ? "pending" : "pending"),
        progress: dispatching ? Math.max(15, deepProgress) : (run?.status === "pending_approval" ? 10 : deepProgress),
        summary: dispatching
          ? `Dispatching ${tasks.length} queued check${tasks.length === 1 ? "" : "s"} now. Inventory-first LAN discovery can take a short while before hosts appear.`
          : run?.status === "pending_approval"
            ? approvalWaitingSummary(run)
          : tasks.length
            ? `${taskCounts.completed} complete, ${taskCounts.queued} queued, ${taskCounts.running} running.`
            : "Run exists but no deep-analysis tasks are queued yet.",
      },
      {
        key: "adaptive",
        label: "Adaptive Testing",
        status: config.safety?.adaptive_generation === false ? "complete" : pack ? packStatusToPhaseStatus(pack.status) : relevance ? "active" : "pending",
        progress: adaptiveProgress,
        summary: pack ? `${pack.name} ${pack.version} is ${pack.status}.` : config.safety?.adaptive_generation === false ? "Adaptive generation was disabled in the wizard." : "No adaptive pack has been generated yet.",
      },
      {
        key: "verification",
        label: "Verification",
        status: findings.length ? (verificationResolved === 100 ? "complete" : "active") : (run?.status === "pending_approval" ? "blocked" : "pending"),
        progress: findings.length ? Math.max(20, verificationResolved) : 0,
        summary: findings.length ? `${findings.length} findings need verification-state review.` : "No findings exist yet for replay or retest handling.",
      },
      {
        key: "reporting",
        label: "Reporting",
        status: state.reportCatalog.length ? "complete" : run ? "active" : "pending",
        progress: state.reportCatalog.length ? 100 : run ? 35 : 0,
        summary: state.reportCatalog.length ? `${state.reportCatalog.length} report variants are ready for preview and export.` : "No run report is available yet.",
      },
    ];
    return phases.map((phase, index) => ({
      ...phase,
      elapsed: formatElapsedMinutes(run?.created_at, index * 3),
    }));
  }

  function renderPhaseCard(phase) {
    const nfirPhase = String(phase.nfirPhase || "").trim();
    const tooltip = [phase.summary, nfirPhase ? `NFIR mapping: ${nfirPhase}` : null]
      .filter(Boolean)
      .join(" | ");
    return `
      <div
        class="mission-phase-step ${escapeHtml(phase.status)}"
        style="--phase-progress:${phase.progress}%"
        data-testid="mission-phase-card"
        ${nfirPhase ? `data-nfir-phase-label="${escapeHtml(nfirPhase)}"` : ""}
        title="${escapeHtml(tooltip)}"
      >
        <div class="mission-phase-step-dot" aria-hidden="true">
          ${phase.status === "complete" ? "✓" : escapeHtml(String(Math.max(0, Math.min(100, phase.progress || 0))))}
        </div>
        <div class="mission-phase-step-copy">
          <strong>${escapeHtml(phase.label)}</strong>
          <span>${escapeHtml(statusLabelForPhase(phase.status))} · ${escapeHtml(`Elapsed ${phase.elapsed}`)}</span>
        </div>
      </div>
    `;
  }

  function nfirPhaseForAssessmentChainPhase(phase) {
    const label = String(phase?.label || phase?.phase_id || phase?.tier || "").toLowerCase();
    const runnerText = Array.isArray(phase?.runners)
      ? phase.runners.map((runner) => `${runner.runner_id || ""} ${runner.tool || ""} ${runner.profile_name || ""}`).join(" ")
      : "";
    const text = `${label} ${runnerText}`.toLowerCase();
    if (text.includes("prepar") || text.includes("author")) {
      return "NFIR Phase 1 - Preparation and Authorization";
    }
    if (text.includes("discover") || text.includes("passive") || text.includes("nmap") || text.includes("httpx") || text.includes("easm")) {
      return "NFIR Phase 2 - Intelligence Gathering";
    }
    if (text.includes("analysis") || text.includes("enrichment") || text.includes("vulnerability") || text.includes("nuclei") || text.includes("zap") || text.includes("smb")) {
      return "NFIR Phase 3 - Vulnerability Analysis";
    }
    if (text.includes("exploit") || text.includes("metasploit")) {
      return "NFIR Phase 4 - Exploitation";
    }
    if (text.includes("credential") || text.includes("post") || text.includes("bloodhound") || text.includes("ldap") || text.includes("impacket") || text.includes("kerberoast") || text.includes("asreproast")) {
      return "NFIR Phase 5 - Post-Exploitation";
    }
    if (text.includes("risk") || text.includes("remediation")) {
      return "NFIR Phase 6 - Risk Analysis and Remediation Planning";
    }
    if (text.includes("report") || text.includes("retest") || text.includes("audit")) {
      return "NFIR Phase 7 - Reporting and Re-Audit Tracking";
    }
    return "NFIR Phase - Evidence mapping pending";
  }

  function statusLabelForPhase(status) {
    const mapping = {
      complete: "Complete",
      active: "Active",
      blocked: "Blocked",
      pending: "Pending",
    };
    return mapping[String(status || "pending").toLowerCase()] || "Pending";
  }

  function deriveCurrentActivity(phases) {
    const run = state.selectedRun;
    const assessmentChain = selectedAssessmentChain(run);
    const chainPhase = currentAssessmentChainPhase(assessmentChain);
    const manualHint = manualDispatchHintForSelectedRun();
    const tasks = run?.tasks || [];
    const taskCounts = summarizeTaskStatuses(tasks);
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const inventory = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventorySeedOnly = isSeedOnlyInventory(inventory);
    const followUp = getFollowUpMetadata(run);
    const followUpSummary = summarizeFollowUpInventory(followUp, inventory);
    const sourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;
    const discoveryOnly = isDiscoveryOnlyRun(run);
    const dispatching =
      state.loading.dispatchRunId === run?.id &&
      String(run?.status || "").toLowerCase() === "queued";
    const hostCount = Number(inventory?.summary_json?.host_count || 0);
    const serviceCount = Number(inventory?.summary_json?.service_count || 0);
    const meaningfulOutput = findings.length > 0 || (inventory && !inventorySeedOnly);
    const stagedInternalValidation =
      run?.configuration_json?.assessment_type === "Internal Range / LAN" &&
      run?.configuration_json?.test_profile === "Internal Validation";

    if (assessmentChain && String(assessmentChain.status || "").toLowerCase() === "pending_phase_approval" && chainPhase) {
      return {
        title: `${chainPhase.label} is waiting for approval`,
        status: "blocked",
        health: "Phase boundary",
        next: "Approve, reject, or halt this tier",
        summary: `${assessmentModeLabel(assessmentChain.assessment_mode)} stopped at a higher-tier boundary before ${chainPhase.label.toLowerCase()} can begin.`,
        why: "Assessment Mode removes per-run launch clicks, but it still requires an explicit operator decision when the next phase becomes more intrusive or reaches an exploitation gate.",
        expectation: "Use the chain controls below to approve the next phase, reject it, or halt the chain cleanly at this boundary.",
        primaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
        secondaryAction: { label: "Open Run Dossier", screen: "explorer" },
      };
    }

    if (assessmentChain && String(assessmentChain.status || "").toLowerCase() === "halted") {
      return {
        title: "Assessment chain is halted",
        status: "blocked",
        health: "Operator stop recorded",
        next: "Review the last completed phase",
        summary: `${assessmentModeLabel(assessmentChain.assessment_mode)} is halted and will not queue another phase automatically.`,
        why: "The chain kill boundary is meant to stop follow-up automation cleanly without erasing the run dossier or earlier evidence.",
        expectation: "Review Explorer, Findings, and Reports, then create a deliberate follow-up if you want to continue with a different plan.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Open Report Center", screen: "report-center" },
      };
    }

    if (assessmentChain && String(assessmentChain.status || "").toLowerCase() === "blocked" && chainPhase) {
      return {
        title: `${chainPhase.label} is blocked`,
        status: "blocked",
        health: "Runner review needed",
        next: "Inspect the failed phase runner",
        summary: `${assessmentModeLabel(assessmentChain.assessment_mode)} stopped because ${chainPhase.label.toLowerCase()} did not complete cleanly.`,
        why: "Assessment chains only auto-advance when the current phase finishes successfully. A blocked phase needs operator review before you trust the chain outcome.",
        expectation: "Open the run dossier and task detail for the failed runner, then decide whether to create a new follow-up or hold here.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
      };
    }

    if (assessmentChain && String(assessmentChain.status || "").toLowerCase() === "completed") {
      return {
        title: "Assessment chain is complete",
        status: "complete",
        health: "All phases finished",
        next: "Review evidence and reports",
        summary: `${assessmentModeLabel(assessmentChain.assessment_mode)} finished its full planned sequence.`,
        why: "Mission Control keeps the final run selected, but the entire multi-phase path has already been recorded in the linked run dossiers.",
        expectation: "Use Findings, Reports, and History to review the full chain outcome and decide whether a separate retest is needed.",
        primaryAction: { label: "Open Report Center", screen: "report-center" },
        secondaryAction: { label: "Review Findings", screen: "findings-theater" },
      };
    }

    if (!run && !state.engagements.length) {
      return {
        title: "Start in Conversational Intake",
        status: "pending",
        health: "First mission required",
        next: "Answer the first intake question",
        summary: "No engagement exists yet. Answer the intake question first so AegisPT can create the first engagement and run dossier.",
        why: "Execution, analysis, reports, and Surface Map intentionally depend on a created mission instead of showing empty operational controls.",
        expectation: "Stay in Intake, describe the target, confirm scope and safety, then use Create Mission & Open Mission Control.",
        primaryAction: { label: "Start Mission Intake", screen: "wizard" },
        secondaryAction: null,
      };
    }

    if (run && manualHint?.dispatch_mode === "manual" && String(run.status || "").toLowerCase() === "queued") {
      return {
        title: "Dispatch is waiting on a worker",
        status: "blocked",
        health: "Host execution not attached",
        next: "Attach inline or worker execution",
        summary: "The API accepted the dispatch request, but this host is still in manual dispatch mode so the queued checks cannot start by themselves.",
        why: "Direct-host operator installs are meant to run inline. A stale or incomplete host service environment can leave TASK_DISPATCH_MODE on manual, which makes queued-start controls feel like dead buttons.",
        expectation: "Restart the host with TASK_DISPATCH_MODE=inline, or attach a background worker, then refresh Mission Control and dispatch again.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Open Report Center", screen: "report-center" },
      };
    }

    if (run && String(run.status || "").toLowerCase() === "pending_approval") {
      return {
        title: "Run launch is blocked pending approval",
        status: "blocked",
        health: "Approval required",
        next: "Review approval state",
        summary: approvalWaitingSummary(run),
        why: "Approval-gated active profiles do not queue execution tasks until the required launch approval is recorded.",
        expectation: "Open the run dossier to review approval records. As soon as approval clears, Mission Control will show the queued checks and the explicit dispatch path.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
      };
    }

    if (dispatching && run) {
      return {
        title: "Validation is starting",
        status: "active",
        health: "Dispatch in progress",
        next: "Wait for runner output",
        summary: discoveryOnly
          ? stagedInternalValidation
            ? "AegisPT is starting the discovery stage of this internal validation mission now. Host and service follow-up options appear after the sweep confirms the estate."
            : "AegisPT is launching the network discovery task now. A LAN sweep usually needs a little time before the discovered hosts appear."
          : "AegisPT is dispatching the queued validation tasks now.",
        why: "This run uses controlled execution, so the operator still sees an explicit start boundary before the runtime begins.",
        expectation: discoveryOnly
          ? "As soon as the discovery snapshot is stored, the UI will point you to the Surface Map and Explorer views."
          : "Mission Control will refresh as soon as the first task results are recorded.",
        primaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
        secondaryAction: { label: "Open Explorer", screen: "explorer" },
      };
    }

    if (
      run &&
      discoveryOnly &&
      ["completed", "completed_with_errors"].includes(run.status) &&
      inventory &&
      !inventorySeedOnly
    ) {
      return {
        title: "Inventory is complete",
        status: "complete",
        health: "Discovery results ready",
        next: "Review discovered assets",
        summary: `${hostCount} hosts and ${serviceCount} services were mapped across the approved scope.`,
        why: stagedInternalValidation
          ? "Internal LAN validation starts with controlled discovery. That first stage builds a real estate map before deeper follow-up runs are launched."
          : "This profile inventories the network and records the discovered surface. It does not create vulnerability findings by itself.",
        expectation: stagedInternalValidation
          ? "Open Mission Control for the follow-up run cards, or open Surface Map to review the discovered estate first."
          : "Open Surface Map for the discovered estate, or open Explorer for the run dossier and raw execution detail.",
        primaryAction: { label: stagedInternalValidation ? "Review Mission Control" : "Open Surface Map", screen: stagedInternalValidation ? "mission-control" : "surface-map" },
        secondaryAction: { label: "Open Explorer", screen: "explorer" },
      };
    }

    if (run && taskCounts.failed && !taskCounts.running && !taskCounts.queued) {
      return {
        title: "Execution finished with failures",
        status: "blocked",
        health: "Runner review needed",
        next: "Inspect failed task output",
        summary: `${taskCounts.failed} task${taskCounts.failed === 1 ? "" : "s"} failed after dispatch. Mission Control is keeping the run visible, but you should inspect the selected task detail and dossier before trusting the result.`,
        why: "A completed run is not automatically a healthy run. Failure output, missing artifacts, or unsupported target behavior still need operator review.",
        expectation: "Open the run dossier or selected task detail to inspect stderr, artifacts, and the exact tool/target combination that failed.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
      };
    }

    if (
      run &&
      followUp &&
      followUpSummary &&
      ["completed", "completed_with_errors"].includes(run.status) &&
      !taskCounts.running &&
      !taskCounts.queued
    ) {
      return {
        title: `${followUpStrategyLabel(followUp.strategy)} is complete`,
        status: "complete",
        health: "Follow-up results ready",
        next: followUpSummary.next,
        summary: followUpSummary.summary,
        why: followUp.rationale || "This follow-up run was generated from earlier discovery so the next stage stayed targeted and inside the approved scope.",
        expectation: sourceRun
          ? `Open Surface Map to review the enriched estate, or open Explorer to trace this run back to ${sourceRun.profile?.name || sourceRun.id}.`
          : "Open Surface Map to review the enriched estate, or open Explorer to inspect the run lineage and task evidence.",
        primaryAction: { label: "Open Surface Map", screen: "surface-map" },
        secondaryAction: { label: "Open Explorer", screen: "explorer" },
      };
    }

    if (
      run &&
      tasks.length &&
      !taskCounts.running &&
      !taskCounts.queued &&
      !meaningfulOutput
    ) {
      return {
        title: "Execution finished with limited analyst output",
        status: "unknown",
        health: "Review required",
        next: "Inspect task output",
        summary: "The queued work finished, but there are no findings and no discovery-confirmed inventory yet. That does not always mean the run was useless, but it does mean the operator should review task-level output before treating the mission as complete.",
        why: "Some runs can complete with thin or target-specific output, especially when tooling returns little signal or when the scope does not expose the expected surface.",
        expectation: "Open the selected task detail or Explorer to review exit codes, artifacts, and the exact target coverage before deciding on the next step.",
        primaryAction: { label: "Open Run Dossier", screen: "explorer" },
        secondaryAction: { label: "Open Report Center", screen: "report-center" },
      };
    }

    if (canDispatchSelectedRun()) {
      const queuedTasks = (state.selectedRun?.tasks || []).filter((task) => task.status === "queued").length;
      return {
        title: "Run is ready to start",
        status: "queued",
        health: "Operator start required",
        next: "Dispatch queued tasks",
        summary: `${queuedTasks} queued task${queuedTasks === 1 ? "" : "s"} are ready for controlled execution.`,
        why: "The wizard created the mission record and queued the validation work, but dispatch is still an explicit operator action.",
        expectation: "Press Start Queued Checks to launch the queued tasks with the current run profile, scope, and safety settings.",
        primaryAction: { label: "Start Queued Checks", action: "dispatch-run" },
        secondaryAction: { label: "Open Explorer", screen: "explorer" },
      };
    }

    const blocked = phases.find((phase) => phase.status === "blocked");
    if (blocked) {
      return {
        title: `${blocked.label} is blocked`,
        status: "blocked",
        health: "Needs operator action",
        next: "Resolve blocker",
        summary: blocked.summary,
        why: "The current mission configuration requires an operator input or approval before the flow can continue.",
        expectation: "Clear the blocker, refresh Mission Control, and the phase will resume under the same run dossier.",
        primaryAction: { label: "Stay in Mission Control", screen: "mission-control" },
        secondaryAction: { label: "Open Pack Forge", screen: "pack-forge" },
      };
    }
    const active = phases.find((phase) => phase.status === "active");
    if (active) {
      return {
        title: `${active.label} is active`,
        status: "active",
        health: "Operational",
        next: active.key === "reporting" ? "Generate report preview" : "Monitor progress",
        summary: active.summary,
        why: "This phase currently has the highest operational weight in the selected mission.",
        expectation: "Expect progress, ETA changes, and evidence accumulation as the underlying tasks complete.",
        primaryAction: {
          label: active.key === "adaptive" ? "Open Pack Forge" : active.key === "verification" ? "Review Findings" : "Stay in Mission Control",
          screen: active.key === "adaptive" ? "pack-forge" : active.key === "verification" ? "findings-theater" : "mission-control",
        },
        secondaryAction: {
          label: active.key === "reporting" ? "Open Report Center" : "Open Explorer",
          screen: active.key === "reporting" ? "report-center" : "explorer",
        },
      };
    }
    if (state.selectedRun) {
      return {
        title: "Mission is standing by",
        status: state.selectedRun.status,
        health: "Stable",
        next: "Choose the next operator workflow",
        summary: `Run ${state.selectedRun.id} is ${state.selectedRun.status}.`,
        why: "No phase currently needs special attention, or the run is waiting for the next operator action.",
        expectation: "Use Pack Forge, Report Center, or History to continue the mission lifecycle.",
        primaryAction: { label: "Open Report Center", screen: "report-center" },
        secondaryAction: { label: "Compare History", screen: "history" },
      };
    }
    return {
      title: "Wizard first",
      status: "pending",
      health: "Setup required",
      next: "Create mission",
      summary: "Complete the Assessment Wizard to create the mission and unlock live operations.",
      why: "Mission Control depends on a real run and its inherited configuration.",
      expectation: "The wizard will seed scope, access context, modules, limits, and ETA before the first run exists.",
      primaryAction: { label: "Open Wizard", screen: "wizard" },
      secondaryAction: { label: "Open Explorer", screen: "explorer" },
    };
  }

  function deriveStatusBoard() {
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const pack = runtime.actions.selectedPack?.();
    const inventory = runtime.actions.selectedRunInventorySnapshot?.();
    const inventorySeedOnly = isSeedOnlyInventory(inventory);
    const config = state.selectedRun?.configuration_json || {};
    const good = [];
    const bad = [];
    const unknown = [];

    if (inventory) {
      if (inventorySeedOnly) {
        good.push("Operator-reviewed scope was seeded into inventory so the mission has a controlled starting surface.");
      } else {
        good.push(`Inventory confidence is ${toPercent(inventory.confidence_score)} and the surface model is ready for mapping.`);
      }
    }
    if (pack && ["validated", "approved", "deployed"].includes(pack.status)) good.push(`Selected adaptive pack ${pack.version} is ${pack.status}.`);
    if (state.selectedRun?.status === "queued") good.push("Run tasks are queued and ready for dispatch.");
    if (findings.some((finding) => finding.evidence_ref)) good.push("Evidence-linked findings are already available for replay.");

    if (state.selectedRun?.status === "pending_approval") bad.push("Run launch is blocked pending approval.");
    if (pack && pack.status === "validation_failed") bad.push("The latest adaptive pack failed validation and cannot be promoted.");
    if (requiresCredentials(config) && !hasMeaningfulAccessContext(config.access || {})) bad.push("The mission profile expects authenticated access but no usable access context is stored.");
    if (findings.some((finding) => finding.severity === "critical")) bad.push("Critical findings are present and should be prioritized in remediation and reporting.");
    if (state.selectedRun?.tasks?.some((task) => task.status === "failed")) bad.push("At least one planned check failed. Review the selected task detail before trusting the mission state.");

    if (!inventory) unknown.push("No inventory snapshot exists yet for attack-map and coverage decisions.");
    if (inventorySeedOnly) unknown.push("The current inventory view is still wizard-seeded and has not yet been replaced by discovery-confirmed inventory.");
    if (!state.mission.relevance.length && config.safety?.adaptive_generation !== false) unknown.push("No relevance analysis exists yet for adaptive testing decisions.");
    if (!state.reportCatalog.length && state.selectedRun) unknown.push("Reports have not been previewed yet for this run.");
    if (findings.some((finding) => finding.severity === "unknown")) unknown.push("At least one finding still has unknown severity and needs analyst review.");
    if (
      state.selectedRun &&
      state.selectedRun.tasks?.length &&
      !findings.length &&
      (!inventory || inventorySeedOnly) &&
      !isDiscoveryOnlyRun(state.selectedRun)
    ) {
      unknown.push("Execution finished without findings or discovery-confirmed inventory. Review task-level output to confirm what actually happened.");
    }

    return { good, bad, unknown };
  }

  function deriveMissionEta(phases) {
    const configEta = state.selectedRun?.configuration_json?.eta || estimateMission(state.wizard.data);
    const baselineTotal = Number(configEta.estimated_total_minutes || 90);
    const elapsed = state.selectedRun ? minutesSince(state.selectedRun.created_at) : 0;
    const percentComplete = Math.round(phases.reduce((sum, phase) => sum + phase.progress, 0) / Math.max(phases.length, 1));
    const projectedTotal = state.selectedRun && percentComplete > 0
      ? Math.max(baselineTotal, Math.round(elapsed / Math.max(percentComplete / 100, 0.2)))
      : baselineTotal;
    const remaining = Math.max(0, projectedTotal - elapsed);
    const confidence = state.selectedRun
      ? percentComplete >= 70 ? "high" : percentComplete >= 35 ? "medium" : "low"
      : configEta.confidence || "medium";
    return {
      elapsed_minutes: elapsed,
      remaining_minutes: remaining,
      total_minutes: projectedTotal,
      elapsed_label: formatDurationLabel(elapsed),
      remaining_label: formatDurationLabel(remaining),
      total_label: formatDurationLabel(projectedTotal),
      confidence,
      confidence_label: `${capitalizeWord(confidence)} confidence`,
      percent_complete: percentComplete,
      detail: "ETA blends the original wizard estimate with live phase completion so the projected total stays readable and less erratic.",
    };
  }

  function buildFindingsPulse() {
    const run = state.selectedRun;
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventorySeedOnly = isSeedOnlyInventory(inventorySnapshot);
    const dispatching =
      state.loading.dispatchRunId === run?.id &&
      String(run?.status || "").toLowerCase() === "queued";
    const stagedInternalValidation =
      run?.configuration_json?.assessment_type === "Internal Range / LAN" &&
      run?.configuration_json?.test_profile === "Internal Validation";

    if (run && isDiscoveryOnlyRun(run) && !findings.length) {
      if (dispatching) {
        return { mode: "inventory-pending" };
      }
      if (inventorySnapshot && !inventorySeedOnly) {
        return {
          mode: stagedInternalValidation ? "inventory-follow-up" : "inventory",
          host_count: Number(inventorySnapshot.summary_json?.host_count || 0),
          service_count: Number(inventorySnapshot.summary_json?.service_count || 0),
          confidence_score: Number(inventorySnapshot.confidence_score || inventorySnapshot.summary_json?.confidence_score || 0),
        };
      }
    }

    const linked = findings.filter((finding) => Boolean(finding.evidence_ref)).length;
    const tags = new Set();
    findings.forEach((finding) => (finding.methodology_tags || []).forEach((tag) => tags.add(tag)));
    return {
      confirmed: findings.filter((finding) => ["open", "triaged", "in_progress", "resolved", "reopened"].includes(finding.status)).length,
      suspected: findings.filter((finding) => finding.status === "triaged").length,
      dismissed: findings.filter((finding) => ["accepted_risk", "false_positive"].includes(finding.status)).length,
      critical: findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length,
      evidence_completeness: findings.length ? Math.round((linked / findings.length) * 100) : 0,
      coverage: tags.size ? `${tags.size} methodology tags linked` : "Coverage will populate as findings arrive",
    };
  }

  function buildNarratives() {
    const narratives = [];
    const relevance = runtime.actions.latestRelevanceDecision?.();
    const pack = state.selectedPackBundle?.pack || runtime.actions.selectedPack?.();
    const findings = runtime.actions.selectedRunFindings?.() || [];
    if (relevance) {
      const relevantCount = relevance.recommendations_json?.relevant_advisories?.length || 0;
      narratives.push(`AI matched ${relevantCount} relevant advisories against the latest inventory snapshot.`);
    }
    if (pack) {
      narratives.push(`Capability pack ${pack.name} ${pack.version} is ${pack.status} and carries ${pack.methodology_tags.length} methodology tags.`);
    }
    if (state.selectedPackBundle?.artifacts?.length) {
      narratives.push(`Pack Forge has ${state.selectedPackBundle.artifacts.length} generated artifacts ready for review or promotion.`);
    }
    if (findings.length) {
      narratives.push(`Evidence-first replay lifted confidence across ${findings.length} findings in the selected run.`);
    }
    if (state.selectedFindingTheater?.finding?.finding_origin === "adaptive_pack") {
      narratives.push("The selected finding was produced through adaptive pack coverage rather than baseline tooling alone.");
    }
    return narratives;
  }

  function renderMissionGuidanceCard() {
    return renderAiSignalPanel();
  }

  function renderAiSignalPanel() {
    const guidance = state.selectedRun?.ai_mission_guidance || null;
    const insights = state.selectedAiInsights || null;
    const workbench = insights?.operator_workbench || null;
    const liveStream =
      state.selectedAiSignalStream && String(state.selectedAiSignalStream.runId || "") === String(state.selectedRunId || "")
        ? state.selectedAiSignalStream
        : null;
    const reasoningRecords = Array.isArray(insights?.reasoning_records)
      ? insights.reasoning_records
      : [];
    const proposals = Array.isArray(insights?.proposals) ? insights.proposals : [];
    const autonomousMode = Boolean(state.selectedRun?.autonomous_mode);
    const autonomousAgents = autonomousMode
      ? buildAutonomousAgentCards(state.selectedRun?.tasks || [], selectedRunFindingsForMission())
      : [];
    const pendingCount = countPendingAiProposals(proposals);
    const provider = aiSignalProviderStatus({ guidance, insights, liveStream, useGlobalFallback: !state.selectedRun });
    const providerStatus = String(provider.status || "").trim().toLowerCase();
    const providerDisabled = DISABLED_PROVIDER_STATUSES.has(providerStatus);
    const providerNotConnected = providerStatus === "not_connected" || providerStatus === "not-connected" || providerStatus === "not connected";
    const entries = collapseAiSignalEntries([
      ...buildAiSignalEntries({ guidance, insights, reasoningRecords, proposals }),
      ...buildAiSignalLiveEntries(liveStream),
    ]);
    const compactFailureMode = entries.some((entry) => entry.tone === "alert" || entry.kind === "alert");
    const visibleEntries = entries.slice(-(compactFailureMode ? 1 : 2)).reverse();
    const hiddenEntryCount = Math.max(0, entries.length - visibleEntries.length);
    const liveThinking = ["connecting", "streaming"].includes(String(liveStream?.status || "").toLowerCase());
    const thinking = liveThinking || reasoningRecords.some((record) =>
      AI_SIGNAL_IN_FLIGHT_STATUSES.has(String(record.status || "").toLowerCase())
    );
    const boundary = insights?.review_boundary || {};
    const boundaryMessage =
      boundary.message ||
      "AI suggestions are review-only. They do not queue tasks, dispatch tools, or expand scope.";
    const contractBadges = autonomousMode
      ? [
          "In-scope autonomous follow-up only",
          "Kill switch still applies",
          "Intrusive stays gated",
        ]
      : [
          "Suggestion, not an executed task",
          "No task queued",
          "Existing approvals still apply",
        ];
    const contractLabel = autonomousMode
      ? `${autonomousAgents.length} autonomous agent card${autonomousAgents.length === 1 ? "" : "s"} · ${reasoningRecords.length} reasoning record${reasoningRecords.length === 1 ? "" : "s"}`
      : `${pendingCount} pending suggestion${pendingCount === 1 ? "" : "s"} · ${reasoningRecords.length} reasoning record${reasoningRecords.length === 1 ? "" : "s"}`;
    const stateLabel = !state.selectedRun
      ? "No run selected"
      : providerDisabled && !reasoningRecords.length && !proposals.length
        ? "Provider disabled"
      : thinking
        ? "Review in progress"
        : pendingCount
          ? `${pendingCount} pending`
          : entries.length
            ? "Review ready"
            : "Standing by";
    const headerTone = thinking ? "running" : pendingCount ? "review" : entries.length ? "active" : "unknown";

    return `
      <section class="ai-signal-panel" data-testid="ai-signal-panel" data-ai-signal-state="${escapeHtml(stateLabel.toLowerCase().replace(/[^a-z0-9]+/g, "-"))}">
        ${autonomousMode ? renderAutonomousAgentFeed(autonomousAgents) : ""}
        <div class="ai-signal-header">
          <div class="inline-metrics">
            ${statusPill(headerTone)}
            ${renderAiProviderBadge(provider)}
            <span class="metric-pill">${escapeHtml(stateLabel)}</span>
            ${entries.length ? `<span class="metric-pill">${escapeHtml(`${entries.length} entries`)}</span>` : ""}
          </div>
          ${pendingCount ? `<span class="ai-signal-count" data-testid="ai-signal-pending-count">${escapeHtml(String(pendingCount))}</span>` : ""}
        </div>
        ${renderAiOperatorWorkbench(workbench, provider)}
        <div class="ai-signal-review-contract" data-testid="ai-proposal-insights-card">
          <div class="ai-signal-inbox-title" data-testid="ai-signal-inbox">
            <span>AI Signal Inbox</span>
            <small>${escapeHtml("review signals, repair actions, and coverage gaps")}</small>
          </div>
          <div class="ai-signal-stream" data-testid="ai-signal-stream">
            ${thinking ? renderAiThinkingIndicator() : ""}
            ${
              providerDisabled && !entries.length
                ? providerNotConnected || provider.mode === "deterministic"
                  ? emptyState("ChatGPT OAuth is not connected for AI features on this run.", {
                      label: "Connect ChatGPT in Settings",
                      screen: "settings",
                      className: "primary",
                      testId: "ai-signal-open-settings",
                    })
                  : emptyState("AI Signal is disabled for this run. Enable post-task analysis in Settings to store AI review records.", {
                      label: "Open Settings",
                      screen: "settings",
                      className: "primary",
                      testId: "ai-signal-open-settings",
                    })
                : entries.length
                ? `
                    ${visibleEntries.map(renderAiSignalEntry).join("")}
                    ${hiddenEntryCount ? `<div class="ai-signal-compact-more">${escapeHtml(`${hiddenEntryCount} older AI signal ${hiddenEntryCount === 1 ? "entry" : "entries"} collapsed`)}</div>` : ""}
                  `
                : emptyState(
                    state.selectedRun
                      ? provider.connected
                        ? "ChatGPT is connected. No AI signal is stored for this run yet."
                        : "No AI signal is stored for this run yet."
                      : "Select a run to view AI Signal.",
                    state.selectedRun
                      ? { label: "Open Run Dossier", screen: "explorer" }
                      : { label: "Start a mission", screen: "wizard" }
                  )
            }
          </div>
          <div class="ai-signal-contract-line">
            <span>${escapeHtml(contractLabel)}</span>
            ${renderBadgeList(contractBadges, "compact-badge-list")}
          </div>
        </div>
        ${renderAiGuidanceSignal(guidance)}
      </section>
    `;
  }

  function renderAiOperatorWorkbench(workbench, provider) {
    const safeWorkbench = workbench && typeof workbench === "object" ? workbench : {};
    const summary = safeWorkbench.summary || {};
    const features = safeWorkbench.features || {};
    const buildLaneTasks = Array.isArray(safeWorkbench.build_lane_tasks) ? safeWorkbench.build_lane_tasks : [];
    const signals = Array.isArray(safeWorkbench.signals) ? safeWorkbench.signals : [];
    const boundary = safeWorkbench.boundary || {};
    const needsConnection = Boolean(safeWorkbench.provider?.needs_connection) || !provider?.connected;
    const featureRows = [
      ["Signal inbox", features.signal_inbox],
      ["Repair proposals", features.repair_proposals],
      ["Finding enrichment", features.finding_enrichment],
      ["Report draft", features.report_draft],
      ["Build-lane handoff", features.build_lane_handoff],
    ];
    const latestBuildLaneTask = buildLaneTasks[0] || null;
    return `
      <div class="ai-operator-workbench" data-testid="ai-operator-workbench">
        <div class="ai-signal-inbox-title">
          <span>${escapeHtml(safeWorkbench.title || "AI Operator Workbench")}</span>
          <small>${escapeHtml(boundary.message || "AI is review-only and cannot mutate active runtime state.")}</small>
        </div>
        <div class="compact-definition-grid split-top">
          <div data-testid="ai-workbench-provider-status">
            <span>Provider</span>
            <strong>${escapeHtml(provider?.label || safeWorkbench.provider?.label || "Deterministic mode")}</strong>
          </div>
          <div>
            <span>Signals</span>
            <strong>${escapeHtml(String(summary.signals ?? signals.length ?? 0))}</strong>
          </div>
          <div>
            <span>Repairs</span>
            <strong>${escapeHtml(`${summary.pending_repair_proposals ?? 0} pending`)}</strong>
          </div>
          <div>
            <span>Build Lane</span>
            <strong>${escapeHtml(`${summary.build_lane_tasks ?? buildLaneTasks.length} tasks`)}</strong>
          </div>
        </div>
        <div class="compact-badge-list split-top">
          ${featureRows
            .map(([label, feature]) => {
              const enabled = Boolean(feature?.enabled);
              const count = feature?.count ?? feature?.pending ?? feature?.created;
              const suffix = typeof count === "number" ? ` · ${count}` : "";
              return `<span class="metric-pill ${enabled ? "connected" : "deterministic"}">${escapeHtml(`${label}${suffix}`)}</span>`;
            })
            .join("")}
        </div>
        ${
          latestBuildLaneTask
            ? `
              <div class="ai-repair-summary split-top" data-testid="ai-workbench-build-lane-task">
                <p class="micro-copy success-copy">${escapeHtml("Build-lane repair task created. Active runtime was not changed.")}</p>
                <code>${escapeHtml(latestBuildLaneTask.task_file || latestBuildLaneTask.codex_task_id || "Build-lane task recorded")}</code>
              </div>
            `
            : needsConnection
              ? `<p class="micro-copy split-top">ChatGPT OAuth is not connected. Deterministic triage still records review-only signals and build-lane handoffs.</p>`
              : `<p class="micro-copy split-top">AI workbench is ready. Repair actions, report help, and finding enrichment stay grounded in stored evidence.</p>`
        }
        ${
          signals.length
            ? `
              <div class="ai-workbench-signal-list split-top">
                ${signals.slice(0, 2).map((signal) => `
                  <div class="ai-signal-entry tone-muted" data-testid="ai-workbench-signal-row">
                    <div class="ai-signal-entry-meta">
                      <span>${escapeHtml(signal.status || "stored")}</span>
                      <span>${escapeHtml(signal.kind || "signal")}</span>
                    </div>
                    <h4>${escapeHtml(signal.title || "AI signal")}</h4>
                    <p>${escapeHtml(signal.summary || "Stored AI signal is available for review.")}</p>
                  </div>
                `).join("")}
              </div>
            `
            : ""
        }
      </div>
    `;
  }

  function aiSignalProviderStatus({ guidance, insights, liveStream, useGlobalFallback = false }) {
    const streamProvider = liveStream?.provider || null;
    if (streamProvider) {
      return {
        mode: streamProvider.mode || "deterministic",
        label: streamProvider.label || (streamProvider.connected ? "ChatGPT connected" : "Deterministic mode"),
        status: streamProvider.status || (streamProvider.connected ? "connected" : "fallback"),
        connected: Boolean(streamProvider.connected),
      };
    }
    const insightProvider = insights?.provider_status || null;
    if (insightProvider) {
      const connected = Boolean(insightProvider.connected);
      return {
        mode: insightProvider.mode || (connected ? "chatgpt_oauth" : "deterministic"),
        label: insightProvider.label || (connected ? "ChatGPT connected" : "Deterministic mode"),
        status: insightProvider.status || (connected ? "connected" : "fallback"),
        connected,
      };
    }
    if (useGlobalFallback) {
      const globalProvider = globalChatGptProviderStatus();
      if (globalProvider) return globalProvider;
    }
    const providerName = String(insights?.provider || guidance?.provider?.name || "").trim().toLowerCase();
    const guidanceStatus = String(guidance?.provider?.status || "").trim().toLowerCase();
    const connected = providerName === "chatgpt_oauth" && !DISABLED_PROVIDER_STATUSES.has(guidanceStatus);
    return {
      mode: connected ? "chatgpt_oauth" : "deterministic",
      label: connected ? "ChatGPT connected" : "Deterministic mode",
      status: connected ? "connected" : guidanceStatus || providerName || "fallback",
      connected,
    };
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

  function globalChatGptProviderStatus() {
    const configuredProvider = String(findOperatorSettingValue("ai.provider") || "disabled").trim().toLowerCase();
    if (configuredProvider === "disabled" || configuredProvider === "off") {
      return {
        mode: "deterministic",
        label: "Deterministic mode",
        status: "disabled",
        connected: false,
      };
    }
    if (configuredProvider !== "chatgpt_oauth") return null;
    const status = state.chatgptOAuthStatus && typeof state.chatgptOAuthStatus === "object"
      ? state.chatgptOAuthStatus
      : {};
    const connected = Boolean(status.connected);
    return {
      mode: "chatgpt_oauth",
      label: connected ? "ChatGPT connected" : "ChatGPT OAuth",
      status: connected ? "connected" : "not_connected",
      connected,
    };
  }

  function renderAiProviderBadge(provider) {
    const connected = Boolean(provider?.connected);
    const label = provider?.label || (connected ? "ChatGPT connected" : "Deterministic mode");
    const icon = connected ? "◆" : "◇";
    return `<span class="metric-pill ai-provider-badge ${connected ? "connected" : "deterministic"}" data-testid="ai-signal-provider-badge">${escapeHtml(`${icon} ${label}`)}</span>`;
  }

  function buildAiSignalLiveEntries(liveStream) {
    if (!liveStream || !String(liveStream.text || "").trim()) return [];
    const status = String(liveStream.status || "").toLowerCase();
    return [
      {
        id: `live-ai-signal-${liveStream.taskId || "run"}`,
        kind: status === "error" ? "alert" : "observation",
        tone: status === "error" ? "alert" : "observation",
        time: liveStream.updatedAt || liveStream.startedAt || new Date().toISOString(),
        title: status === "streaming" || status === "connecting" ? "Live ChatGPT Signal" : "AI Signal",
        text: liveStream.text,
        source: liveStream.provider?.label || "live AI signal",
        instant: status !== "streaming",
        detail: liveStream.detail || "",
      },
    ];
  }

  function renderAutonomousAgentFeed(agentCards) {
    return `
      <section class="autonomous-agent-feed" data-testid="mission-agent-activity-feed">
        <div class="ai-signal-header">
          <div class="inline-metrics">
            ${statusPill(agentCards.length ? "running" : "pending")}
            <span class="metric-pill">${escapeHtml("Agent Activity")}</span>
          </div>
          <span class="ai-signal-count" data-testid="mission-agent-activity-count">${escapeHtml(String(agentCards.length))}</span>
        </div>
        ${
          agentCards.length
            ? `
              <div class="autonomous-agent-grid">
                ${agentCards.map(renderAutonomousAgentCard).join("")}
              </div>
            `
            : `
              <div class="autonomous-agent-empty">
                ${emptyState("No agent cards are active for this run yet.", {
                  label: "Open Run Dossier",
                  screen: "explorer",
                })}
              </div>
            `
        }
      </section>
    `;
  }

  function buildAutonomousAgentCards(tasks, findings) {
    return [...(tasks || [])]
      .filter((task) => {
        const params = task?.params_json || {};
        return Boolean(params.autonomous_agent?.enabled);
      })
      .map((task, index) => {
        const params = task.params_json || {};
        const autonomous = params.autonomous_agent || {};
        const matchedFindings = findingsForTask(task, findings);
        return {
          id: task.id,
          label: `Agent #${autonomous.sequence || index + 1}`,
          tool: formatToolLabel(task.tool),
          target: task.target_id || "No target recorded",
          status: normalizeTaskStatus(task.status),
          statusLabel: String(task.status || "unknown"),
          findingsCount: matchedFindings.length,
          findingSeverity: highestFindingSeverity(matchedFindings),
          riskTier: autonomous.risk_tier || params.run_class || "passive",
          sourceTool: autonomous.source_tool || params.source_tool || "",
          updatedAt: task.updated_at || task.created_at || null,
        };
      })
      .sort((left, right) => {
        const leftNumber = Number(String(left.label).replace(/[^0-9]+/g, "") || 0);
        const rightNumber = Number(String(right.label).replace(/[^0-9]+/g, "") || 0);
        if (leftNumber !== rightNumber) return leftNumber - rightNumber;
        return timestampMs(right.updatedAt) - timestampMs(left.updatedAt);
      });
  }

  function renderAutonomousAgentCard(agent) {
    const severity = agent.findingsCount ? agent.findingSeverity : "none";
    return `
      <button
        class="autonomous-agent-card status-${escapeHtml(agent.status)} severity-${escapeHtml(severity)}"
        type="button"
        data-testid="mission-agent-activity-card"
        data-mission-task-pick="${escapeHtml(String(agent.id || ""))}"
      >
        <div class="ai-signal-entry-meta">
          <span>${escapeHtml(agent.label)}</span>
          ${statusPill(agent.statusLabel)}
        </div>
        <h4>${escapeHtml(`${agent.tool} on ${agent.target}`)}</h4>
        <div class="autonomous-agent-metrics">
          <span class="metric-pill">${escapeHtml(`Risk ${agent.riskTier}`)}</span>
          <span class="metric-pill">${escapeHtml(`${agent.findingsCount} finding${agent.findingsCount === 1 ? "" : "s"}`)}</span>
          ${agent.sourceTool ? `<span class="metric-pill">${escapeHtml(`From ${agent.sourceTool}`)}</span>` : ""}
        </div>
        <p class="micro-copy">${escapeHtml(
          `${describeTaskStatus(agent.statusLabel)} · Last change ${formatDateTime(agent.updatedAt)}`
        )}</p>
      </button>
    `;
  }

  function renderAiGuidanceSignal(guidance) {
    if (!guidance?.available) {
      const legacySignals = buildNarratives();
      if (!legacySignals.length) return "";
      return `
        <div class="ai-guidance-compact" data-testid="mission-guidance-signals">
          <p class="eyebrow">Deterministic Signals</p>
          ${renderStringCards(
            legacySignals.slice(0, 2),
            "AI narrative appears as soon as inventory, adaptive decisions, or findings exist."
          )}
          ${
            legacySignals.length > 2
              ? `<p class="micro-copy">${escapeHtml(`${legacySignals.length - 2} additional supporting signal${legacySignals.length - 2 === 1 ? "" : "s"} are available in the run dossier.`)}</p>`
              : ""
          }
        </div>
      `;
    }

    const recommendations = Array.isArray(guidance.follow_up_recommendations)
      ? guidance.follow_up_recommendations
      : [];
    const inputs = guidance.deterministic_inputs || {};
    const provider = guidance.provider || {};
    const scopeBoundary = guidance.scope_boundary || {};
    const grounding = Array.isArray(guidance.grounding) ? guidance.grounding : [];
    const targetCount = Number(inputs.target_count || 0);
    const allowedTargetCount = Array.isArray(scopeBoundary.allowed_targets)
      ? scopeBoundary.allowed_targets.length
      : targetCount;

    return `
      <div class="ai-guidance-compact" data-testid="mission-guidance-card">
        <p class="eyebrow">Grounded Mission Guidance</p>
        <h4>${escapeHtml(guidance.title || "Grounded Mission Guidance")}</h4>
        <p>${escapeHtml(guidance.summary || "Guidance is derived from deterministic run context.")}</p>
        ${renderBadgeList([
          guidance.mode ? `Mode ${guidance.mode}` : null,
          provider.status ? `Provider ${provider.status}` : null,
          `${allowedTargetCount} in-scope target${allowedTargetCount === 1 ? "" : "s"}`,
          scopeBoundary.expands_scope === false ? "No scope expansion" : null,
        ], "compact-badge-list split-top")}
        <div class="compact-definition-grid split-top">
          <div><span>Profile Basis</span><strong>${escapeHtml(guidance.profile_explanation || "Profile context not recorded.")}</strong></div>
          <div><span>Safety Basis</span><strong>${escapeHtml(guidance.safety_explanation || "Safety context not recorded.")}</strong></div>
        </div>
        <p class="micro-copy split-top" data-testid="mission-guidance-boundary">${escapeHtml(
          scopeBoundary.message ||
            "Guidance is advisory only and cannot add targets, authorization, run class, approvals, or runtime work."
        )}</p>
        <div class="ai-guidance-recommendations split-top" data-testid="mission-guidance-recommendations">
          ${recommendations
            .map(
              (item) => `
                <div class="ai-guidance-note">
                  <h4>${escapeHtml(item.title || "Review recommendation")}</h4>
                  <p>${escapeHtml(item.rationale || "Grounded rationale was not recorded.")}</p>
                  <p class="micro-copy">${escapeHtml(item.operator_action || "Operator remains in control.")}</p>
                  <p class="micro-copy">${escapeHtml(
                    `Grounded by ${(item.grounding || []).join(", ") || grounding.join(", ") || "selected run context"}`
                  )}</p>
                </div>
              `
            )
            .join("")}
        </div>
      </div>
    `;
  }

  function buildAiSignalEntries({ guidance, insights, reasoningRecords, proposals }) {
    const entries = [];
    reasoningRecords.forEach((record, index) => {
      const status = String(record.status || "").toLowerCase();
      if (["succeeded", "completed", "complete"].includes(status)) {
        entries.push(buildToolCompletionEntry(record, index));
      } else if (["failed", "error", "blocked"].includes(status)) {
        entries.push({
          id: `reasoning-${record.id || index}-failure`,
          kind: "alert",
          tone: "alert",
          time: record.updated_at || record.created_at,
          title: "Reasoning needs review",
          text: summarizeAiFailureReason(record.failure_reason),
          detail: record.failure_reason ? String(record.failure_reason) : "",
          source: record.provider || insights?.provider || "provider",
        });
      }

      extractAiSignalPayloads(record.observations_json, record, "observation").forEach((entry) => entries.push(entry));
      extractAiSignalPayloads(record.hypotheses_json, record, "observation").forEach((entry) => entries.push(entry));
    });

    proposals.forEach((proposal, index) => {
      entries.push({
        id: `proposal-${proposal.id || index}`,
        kind: "proposal",
        tone: "proposal",
        time: proposal.updated_at || proposal.created_at,
        proposal,
      });
    });

    if (
      !entries.length &&
      guidance?.available &&
      !DISABLED_PROVIDER_STATUSES.has(String(guidance?.provider?.status || "").trim().toLowerCase())
    ) {
      entries.push({
        id: "guidance-summary",
        kind: "observation",
        tone: "observation",
        time: state.selectedRun?.updated_at || state.selectedRun?.created_at,
        title: "Guidance ready",
        text: guidance.summary || "Grounded mission guidance is available for this run.",
        source: guidance.provider?.status ? `provider ${guidance.provider.status}` : "deterministic",
        instant: true,
      });
    }

    return entries
      .filter(Boolean)
      .sort((left, right) => new Date(left.time || 0) - new Date(right.time || 0))
      .slice(-10);
  }

  function collapseAiSignalEntries(entries) {
    const seen = new Set();
    return entries.filter((entry) => {
      const key = [
        entry.kind || "",
        entry.tone || "",
        entry.title || "",
        entry.text || "",
        entry.source || "",
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function summarizeAiFailureReason(reason) {
    const raw = String(reason || "").trim();
    if (!raw) {
      return "Stored AI reasoning did not complete cleanly. Open technical detail if you need the raw diagnostic.";
    }
    const statusMatch = raw.match(/\b(?:HTTP\s*)?([45][0-9]{2})\b/i);
    const providerLabel = /chatgpt|openai|oauth|provider|backend/i.test(raw)
      ? "AI provider"
      : "Stored AI reasoning";
    const operationalHint = /rate\s*limit|quota/i.test(raw)
      ? "rate limiting"
      : /timeout|timed out/i.test(raw)
        ? "a timeout"
        : /unauthori[sz]ed|forbidden|token|oauth/i.test(raw)
          ? "an authentication issue"
          : /connect|connection|refused|dns|network/i.test(raw)
            ? "a connectivity issue"
            : "";
    if (statusMatch) {
      return `${providerLabel} returned HTTP ${statusMatch[1]}. Open technical detail if you need the raw diagnostic.`;
    }
    if (operationalHint) {
      return `${providerLabel} reported ${operationalHint}. Open technical detail if you need the raw diagnostic.`;
    }
    return `${providerLabel} did not complete cleanly. Open technical detail if you need the raw diagnostic.`;
  }

  function buildToolCompletionEntry(record, index) {
    const task = state.selectedRun?.tasks?.find((item) => String(item.id || "") === String(record.task_id || "")) || null;
    const tool = task?.tool || record.context_snapshot_json?.tool || "tool";
    const target = task?.target_id || record.context_snapshot_json?.target_id || record.context_snapshot_json?.target || "target";
    return {
      id: `reasoning-${record.id || index}-tool`,
      kind: "tool",
      tone: "muted",
      time: record.updated_at || record.created_at,
      title: "Tool completion",
      text: `${tool} completed on ${target}.`,
      source: record.provider || "stored reasoning",
    };
  }

  function extractAiSignalPayloads(payloads, record, fallbackKind) {
    if (!Array.isArray(payloads)) return [];
    return payloads
      .map((payload, index) => {
        const text = aiSignalPayloadText(payload);
        if (!text) return null;
        const kind = classifyAiSignalPayload(payload, record, fallbackKind);
        return {
          id: `${record.id || "reasoning"}-${kind}-${index}`,
          kind,
          tone: kind,
          time: payload.created_at || payload.updated_at || record.updated_at || record.created_at,
          title: aiSignalPayloadTitle(payload, kind),
          text,
          source: payload.evidence_ref || payload.source || record.reasoning_type || record.provider || "stored evidence",
          findingId: payload.finding_id || payload.findingId || payload.finding_ref || null,
        };
      })
      .filter(Boolean);
  }

  function aiSignalPayloadText(payload) {
    if (!payload || typeof payload !== "object") return "";
    return String(
      payload.summary ||
        payload.message ||
        payload.rationale ||
        payload.description ||
        payload.title ||
        ""
    ).trim();
  }

  function aiSignalPayloadTitle(payload, kind) {
    if (payload?.title) return String(payload.title);
    if (kind === "alert") return "Priority alert";
    if (kind === "chain") return "Chain signal";
    return "Observation";
  }

  function classifyAiSignalPayload(payload, record, fallbackKind) {
    const joined = [
      payload?.type,
      payload?.category,
      payload?.kind,
      payload?.severity,
      payload?.risk_tier,
      payload?.summary,
      payload?.message,
      payload?.title,
      record?.reasoning_type,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (joined.includes("chain")) return "chain";
    if (
      joined.includes("kev") ||
      joined.includes("critical") ||
      joined.includes("cve-") ||
      joined.includes("actively exploited")
    ) {
      return "alert";
    }
    return fallbackKind;
  }

  function renderAiSignalEntry(entry) {
    if (entry.kind === "proposal") {
      return renderAiProposalCard(entry.proposal, entry);
    }
    const typing = typingMetadataForEntry(entry);
    const instant = entry.instant !== false;
    const findingExists =
      entry.findingId &&
      selectedRunFindingsForMission().some((finding) => String(finding.id || "") === String(entry.findingId));
    return `
      <article
        class="ai-signal-entry tone-${escapeHtml(entry.tone || entry.kind)} ${instant ? "is-instant" : "is-typed"}"
        data-testid="ai-signal-entry"
        data-ai-signal-kind="${escapeHtml(entry.kind)}"
      >
        <div class="ai-signal-entry-meta">
          <span>${escapeHtml(formatAiSignalTime(entry.time))}</span>
          <span>${escapeHtml(entry.title || "Signal")}</span>
        </div>
        <p>
          ${renderAiTypedText(entry.text, typing, instant)}
        </p>
        ${
          entry.detail
            ? `
              <details class="ai-signal-disclosure">
                <summary>Technical detail</summary>
                <pre>${escapeHtml(entry.detail)}</pre>
              </details>
            `
            : ""
        }
        <div class="ai-signal-entry-footer">
          <span>${escapeHtml(entry.source || "stored signal")}</span>
          ${
            entry.kind === "chain" && findingExists
              ? `<button class="inline-link" type="button" data-nav-screen="findings-theater" data-ai-signal-finding="${escapeHtml(String(entry.findingId))}">Open Finding Theater</button>`
              : ""
          }
        </div>
      </article>
    `;
  }

  function renderAiProposalCard(proposal, entry = null) {
    const status = String(proposal.status || "unknown").toLowerCase();
    const pending = status === "pending_review";
    const params = proposal.proposed_params_json || {};
    const metadata = proposal.metadata_json || {};
    const repairProposal = metadata.proposal_kind === "ai_repair" || params.boundary?.isolated_draft_only === true;
    const dispatchesWork = Boolean(metadata.dispatches_work);
    const repairActions = repairProposal
      ? Array.isArray(metadata.available_actions)
        ? metadata.available_actions
        : Array.isArray(params.available_actions)
          ? params.available_actions
          : []
      : [];
    const repairActionResult = metadata.repair_action_result || params.repair_action_result || null;
    const confidence = Number(proposal.confidence_score);
    const sourceTaskId = params.source_task_id || metadata.source_task_id || "";
    const title = repairProposal
      ? params.title || "AI repair proposal"
      : `${proposal.proposed_tool || "tool"} on ${proposal.proposed_target || "target"}`;
    const draftPath = metadata.draft_path || params.isolated_draft?.path || "";
    const validationCommands = Array.isArray(params.validation_commands) ? params.validation_commands : [];
    const typing = typingMetadataForEntry({
      kind: "proposal",
      text: proposal.reasoning_text || "No proposal rationale was recorded.",
    });
    return `
      <article
        class="ai-signal-entry tone-proposal"
        data-testid="ai-proposal-card"
        data-ai-proposal-status="${escapeHtml(status)}"
        data-ai-signal-kind="proposal"
        ${status === "approved" ? 'data-ai-proposal-confirmed="true"' : ""}
      >
        <div class="ai-signal-entry-meta">
          <span>${escapeHtml(formatAiSignalTime(entry?.time || proposal.updated_at || proposal.created_at))}</span>
          <span>${escapeHtml("Proposal")}</span>
          ${statusPill(status)}
        </div>
        <h4>${escapeHtml(title)}</h4>
        <p>${renderAiTypedText(proposal.reasoning_text || "No proposal rationale was recorded.", typing, true)}</p>
        ${renderBadgeList(
          [
            repairProposal ? "AI repair lane" : null,
            proposal.risk_tier ? `Risk ${proposal.risk_tier}` : null,
            Number.isFinite(confidence) ? `Confidence ${toPercent(confidence)}` : null,
            sourceTaskId ? `Source task ${sourceTaskId}` : null,
            draftPath ? "Isolated draft" : null,
            dispatchesWork ? "Autonomous dispatch" : "Review-only",
          ],
          "compact-badge-list split-top"
        )}
        ${
          repairProposal
            ? `
              <div class="ai-repair-summary split-top">
                <p class="micro-copy">${escapeHtml(params.summary || "Review the isolated repair draft before making code, pack, or runtime changes.")}</p>
                ${draftPath ? `<code>${escapeHtml(draftPath)}</code>` : ""}
                ${
                  validationCommands.length
                    ? `<p class="micro-copy">${escapeHtml(`Validate with: ${validationCommands.slice(0, 2).join(" · ")}`)}</p>`
                    : ""
                }
                ${repairActionResult ? `<p class="micro-copy success-copy">${escapeHtml(`Recorded action: ${repairActionResult.label || repairActionResult.action || "repair action"}`)}</p>` : ""}
                ${repairActions.length ? renderAiRepairActionContract(proposal, repairActions, pending) : ""}
              </div>
            `
            : ""
        }
        <p class="micro-copy split-top">${escapeHtml(
          dispatchesWork && status === "approved"
            ? "Autonomously approved and linked to a queued follow-up task under the current scope and kill-switch guardrails."
            : pending
            ? repairProposal
              ? "Pending repair: approval alone is only a note. Pick a recovery action below so the gap is either recorded or turned into build-lane work."
              : "Pending review: accepting this suggestion only records approval intent. It does not create, queue, or dispatch a task."
            : status === "approved"
              ? repairProposal
                ? "Repair action recorded. No runtime work was launched by this decision."
                : "Confirmed by operator. No execution was launched by this decision."
              : `Reviewed as ${status}. No execution was launched by this decision.`
        )}</p>
        ${
          pending
            ? `
              <div class="panel-actions ai-signal-actions">
                <button class="action primary" type="button" data-ai-proposal-review="approved" data-ai-proposal-id="${escapeHtml(String(proposal.id || ""))}">
                  Approve suggestion
                </button>
                <button class="action ghost" type="button" data-ai-proposal-review="rejected" data-ai-proposal-id="${escapeHtml(String(proposal.id || ""))}">
                  Skip suggestion
                </button>
              </div>
            `
            : ""
        }
      </article>
    `;
  }

  function renderAiRepairActionContract(proposal, actions, pending) {
    const proposalId = String(proposal.id || "");
    return `
      <div class="ai-repair-action-contract split-top" data-testid="ai-repair-action-contract">
        <strong>Recovery actions</strong>
        <p class="micro-copy">AI cannot silently fix or continue the run. These actions make the next operator step explicit.</p>
        <div class="panel-actions ai-signal-actions">
          ${actions
            .map((action) => {
              const available = Boolean(action.available) && pending;
              const label = action.label || action.id || "Repair action";
              const reason = action.unavailable_reason || (pending ? "" : "This proposal is already reviewed.");
              return `
                <button
                  class="action ${available ? "primary" : "ghost"}"
                  type="button"
                  ${available ? "" : "disabled"}
                  data-ai-repair-action="${escapeHtml(String(action.id || ""))}"
                  data-ai-proposal-id="${escapeHtml(proposalId)}"
                  title="${escapeHtml(reason || action.description || label)}"
                >
                  ${escapeHtml(label)}
                </button>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function typingMetadataForEntry(entry) {
    const text = String(entry.text || "");
    const rate = AI_SIGNAL_TYPING_RATES[entry.kind] || AI_SIGNAL_TYPING_RATES.observation;
    const chars = Math.max(1, text.length);
    return {
      rate,
      chars,
      duration: chars * rate,
    };
  }

  function renderAiTypedText(text, typing, instant = true) {
    return `
      <span
        class="ai-signal-typed-text ${instant ? "is-static" : ""}"
        data-testid="ai-signal-typed-text"
        data-typing-rate="${escapeHtml(String(typing.rate))}"
        data-typing-chars="${escapeHtml(String(typing.chars))}"
        style="--typing-duration: ${escapeHtml(String(typing.duration))}ms; --typing-steps: ${escapeHtml(String(typing.chars))};"
      >${escapeHtml(text)}</span>
    `;
  }

  function renderAiThinkingIndicator() {
    return `
      <div class="ai-signal-thinking" data-testid="ai-signal-thinking-indicator">
        <span>${escapeHtml("AI reasoning in progress")}</span>
        <i></i><i></i><i></i>
      </div>
    `;
  }

  function countPendingAiProposals(proposals = null) {
    const source = Array.isArray(proposals)
      ? proposals
      : Array.isArray(state.selectedAiInsights?.proposals)
        ? state.selectedAiInsights.proposals
        : [];
    return source.filter((proposal) => String(proposal.status || "").toLowerCase() === "pending_review").length;
  }

  function selectedRunFindingsForMission() {
    return state.selectedRunId ? state.mission.findingsByRun[state.selectedRunId] || [] : [];
  }

  function formatAiSignalTime(value) {
    if (!value) return "now";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "now";
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function attachMissionAiProposalHandlers() {
    dom.missionAiNarrative?.querySelectorAll("[data-ai-proposal-review]").forEach((button) => {
      button.addEventListener("click", () => {
        reviewAiProposal(button.dataset.aiProposalId, button.dataset.aiProposalReview).catch((error) => {
          runtime.actions.handleError?.(error);
        });
      });
    });
    dom.missionAiNarrative?.querySelectorAll("[data-ai-repair-action]").forEach((button) => {
      button.addEventListener("click", () => {
        recordAiRepairAction(button.dataset.aiProposalId, button.dataset.aiRepairAction).catch((error) => {
          runtime.actions.handleError?.(error);
        });
      });
    });
    dom.missionAiNarrative?.querySelectorAll("[data-mission-task-pick]").forEach((button) => {
      button.addEventListener("click", async () => {
        patchState({ selectedTaskId: button.dataset.missionTaskPick || null }, "mission.agent.task.select");
        await runtime.actions.loadSelectedTask?.();
        renderMissionControl();
      });
    });
  }

  function ensureAiSignalStream() {
    const runId = String(state.selectedRunId || "");
    const task = latestCompletedTaskForAiSignal(state.selectedRun);
    const taskId = String(task?.id || "");
    const nextKey = runId && taskId ? `${runId}:${taskId}` : "";
    if (!nextKey || typeof EventSource === "undefined") {
      closeAiSignalStream();
      return;
    }
    if (aiSignalStreamKey === nextKey) return;

    closeAiSignalStream();
    aiSignalStreamKey = nextKey;
    patchState(
      {
        selectedAiSignalStream: {
          runId,
          taskId,
          status: "connecting",
          text: "",
          provider: { label: "Connecting AI Signal", status: "connecting", connected: false },
          startedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      },
      "mission.aiSignal.connect"
    );
    const url = `/api/v1/runs/${encodeURIComponent(runId)}/ai-signal/stream?task_id=${encodeURIComponent(taskId)}`;
    aiSignalEventSource = new EventSource(url);
    aiSignalEventSource.addEventListener("status", (event) => {
      const payload = parseAiSignalEvent(event);
      patchAiSignalStream({
        status: payload.connected ? "streaming" : "streaming",
        provider: payload,
        updatedAt: new Date().toISOString(),
      });
    });
    aiSignalEventSource.addEventListener("token", (event) => {
      const payload = parseAiSignalEvent(event);
      patchAiSignalStream({
        status: "streaming",
        text: `${state.selectedAiSignalStream?.text || ""}${payload.text || ""}`,
        updatedAt: new Date().toISOString(),
      });
    });
    aiSignalEventSource.addEventListener("complete", (event) => {
      const payload = parseAiSignalEvent(event);
      patchAiSignalStream({
        status: "complete",
        provider: payload.provider || state.selectedAiSignalStream?.provider,
        text: payload.text || state.selectedAiSignalStream?.text || "",
        reasoningId: payload.reasoning_id || state.selectedAiSignalStream?.reasoningId || null,
        updatedAt: new Date().toISOString(),
      });
      closeAiSignalEventSourceOnly();
      refreshAiInsightsAfterSignal();
    });
    aiSignalEventSource.addEventListener("error", (event) => {
      const payload = parseAiSignalEvent(event);
      patchAiSignalStream({
        status: "error",
        text: payload.message || state.selectedAiSignalStream?.text || "AI Signal stream is unavailable.",
        detail: payload.detail || "",
        updatedAt: new Date().toISOString(),
      });
      closeAiSignalEventSourceOnly();
      refreshAiInsightsAfterSignal();
    });
  }

  function latestCompletedTaskForAiSignal(run) {
    const tasks = Array.isArray(run?.tasks) ? run.tasks : [];
    return tasks
      .filter((task) => normalizeTaskStatus(task?.status) === "completed")
      .sort((left, right) => timestampMs(right?.updated_at || right?.created_at) - timestampMs(left?.updated_at || left?.created_at))[0] || null;
  }

  function parseAiSignalEvent(event) {
    try {
      const payload = JSON.parse(event?.data || "{}");
      return payload && typeof payload === "object" ? payload : {};
    } catch (_error) {
      return {};
    }
  }

  function patchAiSignalStream(fields) {
    patchState(
      {
        selectedAiSignalStream: {
          ...(state.selectedAiSignalStream || {}),
          ...fields,
        },
      },
      "mission.aiSignal.stream"
    );
    queueAiSignalPanelRender();
  }

  function queueAiSignalPanelRender() {
    window.clearTimeout(aiSignalRenderTimer);
    aiSignalRenderTimer = window.setTimeout(() => {
      if (!dom.missionAiNarrative) return;
      dom.missionAiNarrative.innerHTML = renderMissionGuidanceCard();
      attachMissionAiProposalHandlers();
    }, 120);
  }

  function closeAiSignalStream() {
    closeAiSignalEventSourceOnly();
    aiSignalStreamKey = "";
  }

  function closeAiSignalEventSourceOnly() {
    if (aiSignalEventSource) {
      aiSignalEventSource.close();
      aiSignalEventSource = null;
    }
  }

  function refreshAiInsightsAfterSignal() {
    if (!state.selectedRunId) return;
    api(`/api/v1/runs/${state.selectedRunId}/ai-insights`)
      .then((insights) => {
        patchState({ selectedAiInsights: insights }, "mission.aiSignal.insightsRefreshed");
        queueAiSignalPanelRender();
      })
      .catch((error) => runtime.actions.handleError?.(error));
  }

  async function reviewAiProposal(proposalId, decision) {
    if (!state.selectedRunId || !proposalId || !decision) {
      throw new Error("Select a run and proposal before recording AI proposal review.");
    }
    runtime.actions.pushStatus?.(`Recording AI proposal ${decision} review.`, "info");
    const proposal = await api(`/api/v1/runs/${state.selectedRunId}/ai-proposals/${proposalId}/review`, {
      method: "POST",
      body: {
        decision,
        note: "Reviewed from Mission Control AI proposal insights panel.",
      },
    });
    const insights = state.selectedAiInsights || {};
    const proposals = Array.isArray(insights.proposals) ? insights.proposals : [];
    const reasoningRecords = Array.isArray(insights.reasoning_records) ? insights.reasoning_records : [];
    patchState(
      {
        selectedAiInsights: {
          ...insights,
          proposals: proposals.map((item) => (String(item.id) === String(proposal.id) ? proposal : item)),
          reasoning_records: reasoningRecords.map((record) => ({
            ...record,
            proposals: Array.isArray(record.proposals)
              ? record.proposals.map((item) => (String(item.id) === String(proposal.id) ? proposal : item))
              : [],
          })),
        },
      },
      "mission.aiProposal.reviewed"
    );
    runtime.actions.pushStatus?.(`AI proposal marked ${proposal.status}; no task was queued.`, "success");
    renderMissionControl();
  }

  async function recordAiRepairAction(proposalId, action) {
    if (!state.selectedRunId || !proposalId || !action) {
      throw new Error("Select a run and AI repair action before recording recovery.");
    }
    runtime.actions.pushStatus?.("Recording explicit AI repair recovery action.", "info");
    const outcome = await api(`/api/v1/runs/${state.selectedRunId}/ai-proposals/${proposalId}/repair-action`, {
      method: "POST",
      body: {
        action,
        note: "Recorded from Mission Control AI Signal Inbox.",
      },
    });
    const proposal = outcome.proposal;
    const insights = state.selectedAiInsights || {};
    const proposals = Array.isArray(insights.proposals) ? insights.proposals : [];
    const reasoningRecords = Array.isArray(insights.reasoning_records) ? insights.reasoning_records : [];
    patchState(
      {
        selectedAiInsights: {
          ...insights,
          proposals: proposals.map((item) => (String(item.id) === String(proposal.id) ? proposal : item)),
          reasoning_records: reasoningRecords.map((record) => ({
            ...record,
            proposals: Array.isArray(record.proposals)
              ? record.proposals.map((item) => (String(item.id) === String(proposal.id) ? proposal : item))
              : [],
          })),
        },
      },
      "mission.aiRepair.actionRecorded"
    );
    runtime.actions.pushStatus?.(outcome.message || "AI repair recovery action recorded.", "success");
    renderMissionControl();
  }

  function renderPackStatusSummary() {
    const bound = state.selectedRun?.pack_binding;
    const boundPackId = String(bound?.pack_id || "");
    const boundPack =
      boundPackId && Array.isArray(state.mission?.packs)
        ? state.mission.packs.find((candidate) => String(candidate.id) === boundPackId) || null
        : null;
    const pack = state.selectedPackBundle?.pack || runtime.actions.selectedPack?.() || boundPack;
    const deployments = state.selectedPackBundle?.deployments || [];
    const validations = state.selectedPackBundle?.validations || [];
    if (!pack) {
      return emptyState("No adaptive pack has been selected for this engagement yet.");
    }
    return `
      <h4>${escapeHtml(pack.name)} <span class="badge">${escapeHtml(pack.version)}</span></h4>
      <p>${statusPill(pack.status)} ${escapeHtml(pack.generation_mode)}</p>
      ${renderBadgeList([
        `${validations.length} validations`,
        `${deployments.length} deployments`,
        `Runtime ${bound?.pack_version || "standard baseline"}`,
      ], "compact-badge-list split-top")}
      ${renderDisclosure({
        title: "Pack Detail",
        summary: `${pack.status} · ${pack.methodology_tags.length} methodology tag${pack.methodology_tags.length === 1 ? "" : "s"}`,
        open: false,
        body: `
          <div class="compact-definition-grid">
            <div><span>Generation Mode</span><strong>${escapeHtml(pack.generation_mode)}</strong></div>
            <div><span>Runtime Binding</span><strong>${escapeHtml(bound?.pack_version || "standard baseline")}</strong></div>
            <div><span>Validation Count</span><strong>${escapeHtml(String(validations.length))}</strong></div>
            <div><span>Deployment Count</span><strong>${escapeHtml(String(deployments.length))}</strong></div>
          </div>
        `,
      })}
    `;
  }

  function renderChainLifecycleTaskFallback(chain) {
    const operatorState = chain?.operator_state || {};
    const current = operatorState.now || {};
    const next = operatorState.next || {};
    const status = String(chain?.status || "unknown").replaceAll("_", " ");
    const currentLabel = current.profile_name || current.phase_label || "No runner is active";
    const nextLabel = next.profile_name || next.phase_label || "No further runner is currently queued";
    const safeAction =
      operatorState.safe_next_action ||
      "Review the chain plan and selected run state before taking action.";
    return `
      <div class="mission-run-summary split-top" data-testid="mission-chain-lifecycle-fallback">
        <div class="task-activity-header">
          <div>
            <h4>Chain Lifecycle</h4>
            <p class="mission-status-subline">${escapeHtml(`Run task cards are not attached to this dossier, but the assessment chain is ${status}.`)}</p>
          </div>
          <div class="inline-metrics">
            ${statusPill(chain?.status || "unknown")}
            <span class="metric-pill">${escapeHtml(`${Number(operatorState.running_count || 0)} running`)}</span>
            <span class="metric-pill">${escapeHtml(`${Number(operatorState.pending_count || 0)} pending`)}</span>
            <span class="metric-pill">${escapeHtml(`${Number(operatorState.skipped_count || 0)} skipped`)}</span>
          </div>
        </div>
        <div class="compact-definition-grid split-top">
          <div><span>Current</span><strong>${escapeHtml(currentLabel)}</strong></div>
          <div><span>Next</span><strong>${escapeHtml(nextLabel)}</strong></div>
          <div><span>Primary Action</span><strong>${escapeHtml(operatorState.primary_action || "Review Chain")}</strong></div>
          <div><span>Safe Next Action</span><strong>${escapeHtml(safeAction)}</strong></div>
        </div>
      </div>
    `;
  }

  function renderRunActivitySummary() {
    const run = state.selectedRun;
    if (!run) {
      return emptyState("No run activity is available yet.", {
        label: "Start a mission",
        screen: "wizard",
      });
    }

    const assessmentChain = selectedAssessmentChain(run);
    const tasks = [...(run.tasks || [])];
    if (!tasks.length) {
      if (String(run.status || "").toLowerCase() === "pending_approval") {
        return `${renderDriftSummaryBanner(run)}${renderAssessmentChainPanel(assessmentChain)}${renderPendingApprovalRunActivity(run)}`;
      }
      if (assessmentChainHasLifecycleRows(assessmentChain)) {
        return `${renderDriftSummaryBanner(run)}${renderAssessmentChainPanel(assessmentChain)}${renderChainLifecycleTaskFallback(assessmentChain)}`;
      }
      return `${renderDriftSummaryBanner(run)}${renderAssessmentChainPanel(assessmentChain)}${emptyState("This run exists, but no execution tasks were queued yet.")}`;
    }

    const dispatching =
      state.loading.dispatchRunId === run.id &&
      String(run?.status || "").toLowerCase() === "queued";
    const manualHint = manualDispatchHintForSelectedRun();
    const discoveryOnly = isDiscoveryOnlyRun(run);
    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventorySeedOnly = isSeedOnlyInventory(inventorySnapshot);
    const discoveryInventoryReady = discoveryOnly && inventorySnapshot && !isSeedOnlyInventory(inventorySnapshot);
    const followUp = getFollowUpMetadata(run);
    const followUpSummary = summarizeFollowUpInventory(followUp, inventorySnapshot);
    const followUpSourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;
    const hostCount = Number(inventorySnapshot?.summary_json?.host_count || 0);
    const serviceCount = Number(inventorySnapshot?.summary_json?.service_count || 0);
    const stagedInternalValidation =
      run.configuration_json?.assessment_type === "Internal Range / LAN" &&
      run.configuration_json?.test_profile === "Internal Validation";
    const counts = summarizeTaskStatuses(tasks);
    const summary = dispatching
      ? "Dispatching queued checks now."
      : manualHint?.dispatch_mode === "manual" && counts.queued
        ? "Queued checks are waiting on a worker."
        : counts.running
          ? "Validation is actively running."
          : counts.queued
            ? "Queued checks are ready to start."
            : counts.failed
              ? "Last execution completed with errors."
              : "Stored run activity is available.";
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
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const meaningfulOutput = findings.length > 0 || (inventorySnapshot && !inventorySeedOnly);
    const toolCount = new Set(tasks.map((task) => task.tool)).size;
    const compactTaskList = renderMissionTaskList(tasks, findings);

    return `
      <div class="mission-run-summary" data-testid="mission-run-summary">
        <div class="task-activity-header">
          <div>
            <h4>${escapeHtml(currentRunLabel(run))}</h4>
            <p class="mission-status-subline">${escapeHtml(summary)}</p>
          </div>
          <div class="inline-metrics">
            ${statusPill(run.status || "unknown")}
            <span class="metric-pill">${escapeHtml(`${tasks.length} task${tasks.length === 1 ? "" : "s"}`)}</span>
            <span class="metric-pill">${escapeHtml(`${toolCount} tool${toolCount === 1 ? "" : "s"}`)}</span>
          </div>
          ${
            canDispatchSelectedRun()
              ? `<div class="screen-actions"><button class="action primary" type="button" data-run-dispatch="selected">Start Queued Checks</button></div>`
              : ""
          }
        </div>
        ${renderRunStreamStatus(run)}
      </div>
      ${renderDriftSummaryBanner(run)}
      ${compactTaskList}
      ${renderMissionTaskFocus(selectedTaskSummary, selectedTask, latestExecution)}
      ${renderCveIntelligencePanel()}
      ${renderAssessmentChainPanel(assessmentChain)}
      ${
        manualHint?.dispatch_mode === "manual" && counts.queued
          ? `
            <div class="detail-surface emphasis-surface split-top" data-testid="manual-dispatch-warning">
              <h4>Manual Dispatch Detected</h4>
              <p>${escapeHtml(manualHint.message)}</p>
              <p class="micro-copy">${escapeHtml("For direct-host use, restart the service with TASK_DISPATCH_MODE=inline. For queued-worker mode, make sure the worker is actually running before dispatching again.")}</p>
            </div>
          `
          : ""
      }
      ${findings.length ? renderSeverityCounters(run, findings) : ""}
      ${
        discoveryInventoryReady
          ? `
            <div class="detail-surface emphasis-surface split-top" data-testid="discovery-complete-summary">
              <h4>Discovery Result</h4>
              <p>${escapeHtml(`${hostCount} hosts and ${serviceCount} services were mapped from the approved scope.`)}</p>
              <p class="micro-copy">${escapeHtml(
                stagedInternalValidation
                  ? "This internal validation mission is now ready for the next controlled follow-up run. Open the cards below to map services or continue into deeper validation from real inventory."
                  : "Inventory-first discovery completes with asset visibility, not vulnerability findings. Open the Surface Map or Explorer to inspect what was found."
              )}</p>
              ${renderInventoryFollowUpPanel("mission")}
              <div class="panel-actions split-top">
                <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
                <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
              </div>
            </div>
          `
          : ""
      }
      ${
        !discoveryInventoryReady && followUpSummary
          ? `
            <div class="detail-surface emphasis-surface split-top" data-testid="follow-up-complete-summary">
              <h4>${escapeHtml(followUpStrategyLabel(followUp?.strategy))}</h4>
              <p>${escapeHtml(followUpSummary.summary)}</p>
              <p class="micro-copy">${escapeHtml(
                followUp?.rationale || "This controlled follow-up reused the prior discovery output instead of broadening scope or guessing new targets."
              )}</p>
              <p class="micro-copy">${escapeHtml(
                followUpSourceRun
                  ? `Source run ${followUpSourceRun.profile?.name || followUpSourceRun.id} · inventory ${followUp?.source_inventory_snapshot_id || run.source_inventory_snapshot_id || "n/a"}`
                  : `Source inventory ${followUp?.source_inventory_snapshot_id || run.source_inventory_snapshot_id || "n/a"}`
              )}</p>
              <div class="panel-actions split-top">
                <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
                <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
              </div>
            </div>
          `
          : ""
      }
      ${
        !discoveryOnly &&
        !counts.running &&
        !counts.queued &&
        !meaningfulOutput
          ? `
            <div class="detail-surface emphasis-surface split-top" data-testid="thin-output-run-activity">
              <h4>Execution finished with limited analyst output</h4>
              <p>${escapeHtml("The queued work finished, but there are no findings and no discovery-confirmed inventory yet.")}</p>
              <div class="panel-actions split-top">
                <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
                <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
              </div>
            </div>
          `
          : ""
      }
    `;
  }

  function renderDriftSummaryBanner(run) {
    const drift = run?.drift_summary;
    if (!drift) return "";
    const delta = Number(drift.exposure_delta || 0);
    const deltaLabel = `${delta > 0 ? "+" : ""}${delta.toFixed(1)}`;
    const deltaTone = delta > 0 ? "critical" : delta < 0 ? "good" : "unknown";
    return `
      <div class="detail-surface emphasis-surface mission-drift-summary split-top" data-testid="mission-drift-summary">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Continuous Drift</p>
            <h4>Change since previous baseline</h4>
          </div>
          <span class="metric-pill">${escapeHtml(`Exposure ${deltaLabel}`)}</span>
        </div>
        <div class="inline-metrics">
          <span class="metric-pill">${escapeHtml(`${drift.new_finding_count || 0} new findings`)}</span>
          <span class="metric-pill">${escapeHtml(`${drift.resolved_finding_count || 0} resolved`)}</span>
          <span class="metric-pill status-${escapeHtml(deltaTone)}">${escapeHtml(`Score ${deltaLabel}`)}</span>
        </div>
        <p class="micro-copy">${escapeHtml(`Compared with run ${drift.previous_run_id}. Drift is informational and does not create findings automatically.`)}</p>
      </div>
    `;
  }

  function renderMissionTaskList(tasks, findings) {
    if (!tasks.length) return "";
    const orderedTasks = [...tasks].sort(compareTaskActivity);
    return `
      <div class="telemetry-section split-top" data-testid="mission-task-swimlanes">
        <div class="task-activity-header">
          <h4>Task List</h4>
          <span class="metric-pill">${escapeHtml(`${orderedTasks.length} task${orderedTasks.length === 1 ? "" : "s"}`)}</span>
        </div>
        <div class="mission-task-list" data-testid="mission-task-list">
          ${orderedTasks
            .map((task) => {
              const normalized = normalizeTaskStatus(task.status);
              return `
                <button
                  class="mission-task-row status-${escapeHtml(normalized)} ${String(state.selectedTaskId || "") === String(task.id || "") ? "selected" : ""} ${normalized === "running" ? "is-live" : ""}"
                  type="button"
                  data-mission-task-pick="${escapeHtml(String(task.id || ""))}"
                  data-testid="mission-task-row"
                >
                  <span class="mission-task-dot status-${escapeHtml(normalized)}" aria-hidden="true"></span>
                  <span class="mission-task-tool">${escapeHtml(formatToolLabel(task.tool))}</span>
                  <span class="mission-task-target">${escapeHtml(task.target_id || "No target recorded")}</span>
                  <span class="mission-task-meta">
                    ${renderTaskFindingBadge(task, findings)}
                    ${statusPill(task.status)}
                  </span>
                </button>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function renderCveIntelligencePanel() {
    const intel = state.selectedCveIntelligence;
    const rows = Array.isArray(intel?.rows) ? intel.rows : [];
    const products = Array.isArray(intel?.products) ? intel.products : [];
    const failures = Array.isArray(intel?.failures) ? intel.failures : [];
    const boundary = intel?.boundary || {};
    const status = String(intel?.status || (products.length ? "no_high_risk_cves" : "no_products"));
    const topRows = rows.slice(0, 5);
    const statusCopy = rows.length
      ? `${rows.length} high-risk CVE${rows.length === 1 ? "" : "s"} matched from discovered product/version evidence.`
      : products.length
        ? "Products were discovered, but no locally cached high-risk CVE match is ready yet."
        : "No product/version fingerprints are available yet. Service detection output will populate this panel.";
    return `
      <div class="detail-surface split-top cve-intel-panel" data-testid="on-demand-cve-intelligence">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Discovered Vulnerabilities</p>
            <h4>On-demand CVE Intelligence</h4>
            <p class="mission-status-subline">${escapeHtml(statusCopy)}</p>
          </div>
          <div class="inline-metrics">
            <span class="metric-pill">${escapeHtml(`${products.length} products`)}</span>
            <span class="metric-pill">${escapeHtml(`${rows.length} CVEs`)}</span>
            <span class="metric-pill">${escapeHtml(status.replace(/_/g, " "))}</span>
          </div>
          <div class="screen-actions">
            <button class="action ghost compact-action" type="button" data-cve-intel-refresh="local">Refresh Cache</button>
            <button class="action secondary compact-action" type="button" data-cve-intel-refresh="nvd">Bounded NVD</button>
          </div>
        </div>
        <p class="micro-copy">${escapeHtml(
          boundary.live_nvd_lookup_performed
            ? "Bounded NVD lookup was used for this view. Tests still require an explicit operator action."
            : "This view uses discovered inventory plus local intelligence/template state. No test is started automatically."
        )}</p>
        ${
          topRows.length
            ? `
              <div class="cve-intel-list">
                ${topRows.map(renderCveIntelligenceRow).join("")}
              </div>
            `
            : `
              <div class="empty-inline">
                <strong>${escapeHtml(products.length ? "No high-risk CVE match yet" : "Waiting for service fingerprints")}</strong>
                <span>${escapeHtml(products.slice(0, 3).map((item) => item.query).join(" · ") || "Run discovery/service identification to create product evidence.")}</span>
              </div>
            `
        }
        ${
          failures.length
            ? `<p class="micro-copy danger-text">${escapeHtml(failures.map((failure) => failure.message || failure.source).join(" · "))}</p>`
            : ""
        }
      </div>
    `;
  }

  function renderCveIntelligenceRow(row) {
    const product = row.affected_product || {};
    const severity = String(row.severity || "high").replace(/_/g, " ");
    const cveId = String(row.cve_id || "");
    const canRun = (row.actions || []).some((action) => action.id === "run_test") && row.test_status === "ready";
    const canGenerate = Boolean(row.record_id);
    return `
      <article class="cve-intel-row status-${escapeHtml(row.test_status || "informational")}">
        <div>
          <div class="cve-intel-title">
            <span class="severity-dot ${escapeHtml(row.kev ? "critical" : severity)}"></span>
            <strong>${escapeHtml(cveId)}</strong>
            <span>${escapeHtml(row.title || "")}</span>
          </div>
          <p class="micro-copy">${escapeHtml(`${product.query || product.product || "Detected product"}${product.host ? ` · ${product.host}` : ""}`)}</p>
          <p class="micro-copy">${escapeHtml(row.fix_guidance || "Apply vendor guidance and retest with an approved targeted check.")}</p>
        </div>
        <div class="cve-intel-actions">
          ${row.kev ? `<span class="metric-pill critical">KEV</span>` : ""}
          ${row.cvss_score ? `<span class="metric-pill">${escapeHtml(`CVSS ${row.cvss_score}`)}</span>` : ""}
          <span class="metric-pill">${escapeHtml(row.test_status || "unknown")}</span>
          <button class="action primary compact-action" type="button" data-cve-intel-run-test="${escapeHtml(cveId)}" ${canRun ? "" : "disabled"}>Run Test</button>
          <button class="action ghost compact-action" type="button" data-cve-intel-generate-template="${escapeHtml(String(row.record_id || ""))}" ${canGenerate ? "" : "disabled"}>Generate Template</button>
        </div>
      </article>
    `;
  }

  function renderRunStreamStatus(run) {
    const stream = state.runStream || {};
    if (!run || String(stream.runId || "") !== String(run.id || "")) {
      return "";
    }
    if (stream.status === "connected") {
      return `
        <p class="micro-copy" data-testid="mission-run-stream-state">${escapeHtml(
          "Live run stream connected. Mission Control is using persisted run/task deltas while polling remains available as fallback."
        )}</p>
      `;
    }
    if (stream.status === "fallback") {
      return `
        <p class="micro-copy" data-testid="mission-run-stream-state">${escapeHtml(
          stream.fallbackReason || "Live run stream unavailable; Mission Control is using polling fallback."
        )}</p>
      `;
    }
    if (stream.status === "connecting") {
      return `
        <p class="micro-copy" data-testid="mission-run-stream-state">${escapeHtml(
          "Connecting to the live run stream while polling remains available as fallback."
        )}</p>
      `;
    }
    return "";
  }

  function renderLiveTelemetryPanel({ run, tasks, findings, counts, meaningfulOutput, discoveryOnly }) {
    const thinOutput =
      !discoveryOnly &&
      !counts.running &&
      !counts.queued &&
      !meaningfulOutput;
    const stream = summarizeRunStreamTruth(run);
    const activeCount = Number(counts.running || 0) + Number(counts.queued || 0);
    const outputState = thinOutput
      ? "Thin output"
      : meaningfulOutput
        ? "Reviewable output"
        : "Awaiting output";
    const outputDetail = thinOutput
      ? "No findings or discovery-confirmed inventory are persisted for this finished execution."
      : meaningfulOutput
        ? "Findings or discovery-confirmed inventory are persisted for this run."
        : "Mission Control is waiting for persisted findings or inventory from the selected run.";

    return `
      <div class="live-telemetry-board split-top" data-testid="mission-live-telemetry">
        <div class="compact-head">
          <p class="eyebrow">Live Operations Telemetry</p>
          <h4>Persisted run, task, and finding state</h4>
        </div>
        <div class="telemetry-summary-grid">
          ${renderTelemetryKpi("Run State", run.status || "unknown", `${activeCount} active or queued task${activeCount === 1 ? "" : "s"}`, "mission-run-state-kpi")}
          ${renderTelemetryKpi("Stream Truth", stream.label, stream.detail, "mission-stream-truth")}
          ${renderTelemetryKpi("Output Signal", outputState, outputDetail, "mission-output-signal")}
        </div>
        ${renderActiveTargetScanMap({ run, tasks, findings, counts })}
        ${renderSeverityCounters(run, findings)}
        ${renderTaskSwimlanes(tasks, findings)}
        ${renderActivityDeltas(tasks, findings)}
      </div>
    `;
  }

  function renderTelemetryKpi(label, value, detail, testId) {
    return `
      <div class="telemetry-kpi-card" data-testid="${escapeHtml(testId)}">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(String(value || "unknown"))}</strong>
        <small>${escapeHtml(detail || "No detail recorded.")}</small>
      </div>
    `;
  }

  function renderActiveTargetScanMap({ run, tasks, findings, counts }) {
    const targetCards = buildActiveTargetCards(tasks, findings);
    const stream = state.runStream || {};
    const selectedStream = run && String(stream.runId || "") === String(run.id || "");
    const streamStatus = selectedStream ? String(stream.status || "idle").toLowerCase() : "idle";
    const hasLiveEvents = selectedStream && ["connected", "connecting"].includes(streamStatus);
    const activeCount = Number(counts.running || 0) + Number(counts.queued || 0);
    const blockedCount = Number(counts.failed || 0) + Number(counts.blocked || 0);
    const completedCount = Number(counts.completed || 0);
    const mapState = activeCount > 0
      ? hasLiveEvents
        ? "live"
        : "static"
      : blockedCount > 0
        ? "blocked"
        : completedCount > 0
          ? "completed"
          : "empty";
    const headline = {
      live: "Live target scan map",
      static: "Static target scan map",
      blocked: "Blocked target scan map",
      completed: "Completed target scan map",
      empty: "Target scan map unavailable",
    }[mapState];
    const detail = {
      live: "Run-level SSE is contributing persisted task deltas; highlights still come only from stored task and finding state.",
      static: "No live event feed is attached right now, so this map is a static target/task summary from the latest selected-run snapshot.",
      blocked: "At least one target/tool lane is failed or blocked. The map keeps that terminal state visible instead of showing success motion.",
      completed: "All visible target/tool lanes are terminal; severity color still comes only from stored findings.",
      empty: "No task targets are recorded for this selected run yet.",
    }[mapState];

    const visibleTargetCards = targetCards.slice(0, 10);
    const hiddenTargetCount = Math.max(0, targetCards.length - visibleTargetCards.length);

    return `
      <div class="telemetry-section active-target-scan-map split-top state-${escapeHtml(mapState)}" data-testid="mission-active-target-scan-map">
        <div class="task-activity-header">
          <div>
            <h4>Active Target Scan Map</h4>
            <p class="micro-copy">${escapeHtml(detail)}</p>
          </div>
          <span class="metric-pill">${escapeHtml(headline)}</span>
        </div>
        ${
          visibleTargetCards.length
            ? `
              ${renderActiveTargetSvg(visibleTargetCards, mapState)}
              <div class="active-target-map-footer">
                <span>${escapeHtml(
                  hiddenTargetCount
                    ? `Showing 10 of ${targetCards.length} mapped targets.`
                    : `${targetCards.length} mapped target${targetCards.length === 1 ? "" : "s"} shown.`
                )}</span>
                <button class="inline-link" type="button" data-nav-screen="surface-map">Open full map</button>
              </div>
              <div class="active-target-grid">
                ${targetCards.map(renderActiveTargetCard).join("")}
              </div>
            `
            : emptyState("No task targets are available for an active target scan map.")
        }
      </div>
    `;
  }

  function renderActiveTargetSvg(targetCards, mapState) {
    const model = buildScanMapSvgModel(targetCards);
    if (!model.targets.length || !model.tools.length) {
      return "";
    }

    return `
      <div class="active-target-svg-shell" data-testid="mission-active-target-svg" data-map-state="${escapeHtml(mapState)}">
        <svg
          class="active-target-svg"
          viewBox="0 0 ${model.width} ${model.height}"
          role="img"
          aria-label="Stored task and finding state scan map"
        >
          <defs>
            <filter id="mission-critical-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="4" result="blur"></feGaussianBlur>
              <feMerge>
                <feMergeNode in="blur"></feMergeNode>
                <feMergeNode in="SourceGraphic"></feMergeNode>
              </feMerge>
            </filter>
          </defs>
          <g class="mission-scan-threads">
            ${model.threads.map(renderScanMapThread).join("")}
          </g>
          <g class="mission-scan-tools">
            ${model.tools.map(renderScanMapTool).join("")}
          </g>
          <g class="mission-scan-targets">
            ${model.targets.map(renderScanMapTarget).join("")}
          </g>
        </svg>
      </div>
    `;
  }

  function buildScanMapSvgModel(targetCards) {
    const width = 920;
    const toolKeys = [];
    const toolLabels = new Map();
    const targets = targetCards.map((target, index) => ({
      ...target,
      index,
      state: scanMapTargetState(target),
    }));

    targets.forEach((target) => {
      target.tasks.forEach((task) => {
        const toolKey = String(task.tool || "unknown").toLowerCase();
        if (!toolKeys.includes(toolKey)) {
          toolKeys.push(toolKey);
          toolLabels.set(toolKey, formatToolLabel(task.tool));
        }
      });
    });

    const rowCount = Math.max(toolKeys.length, targets.length, 1);
    const height = Math.max(260, rowCount * 68 + 72);
    const top = 52;
    const bottom = height - 42;
    const spread = Math.max(1, rowCount - 1);
    const yForIndex = (index, count) => {
      if (count <= 1) return Math.round(height / 2);
      const localSpread = Math.max(1, count - 1);
      return Math.round(top + ((bottom - top) * index) / localSpread);
    };
    const toolPositions = new Map(
      toolKeys.map((tool, index) => [
        tool,
        {
          key: tool,
          label: toolLabels.get(tool) || tool,
          shortLabel: scanToolShortLabel(tool),
          x: 86,
          y: yForIndex(index, toolKeys.length),
        },
      ])
    );
    const targetPositions = targets.map((target, index) => ({
      ...target,
      x: width - 112,
      y: yForIndex(index, targets.length),
    }));
    const threads = [];

    targetPositions.forEach((target) => {
      target.tasks.forEach((task, taskIndex) => {
        const tool = toolPositions.get(String(task.tool || "unknown").toLowerCase());
        if (!tool) return;
        const stateName = scanMapThreadState(task);
        const path = scanMapThreadPath(tool, target, taskIndex);
        threads.push({
          id: String(task.id || `${tool.key}-${target.targetId}-${taskIndex}`),
          tool,
          target,
          task,
          path,
          state: stateName,
          severity: target.severity || "none",
          delay: threads.length * 70,
        });
      });
    });

    return {
      width,
      height,
      tools: [...toolPositions.values()],
      targets: targetPositions,
      threads,
    };
  }

  function scanMapThreadPath(tool, target, taskIndex) {
    const startX = tool.x + 38;
    const startY = tool.y;
    const endX = target.x - 40;
    const endY = target.y;
    const laneOffset = ((taskIndex % 3) - 1) * 10;
    const controlA = Math.round(startX + 190);
    const controlB = Math.round(endX - 190);
    return `M ${startX} ${startY} C ${controlA} ${startY + laneOffset}, ${controlB} ${endY - laneOffset}, ${endX} ${endY}`;
  }

  function renderScanMapThread(thread) {
    const status = normalizeTaskStatus(thread.task.status);
    const pulse = thread.state === "scanning"
      ? `
        <circle
          class="mission-scan-thread-pulse severity-${escapeHtml(thread.severity)}"
          r="4.5"
          data-testid="mission-scan-thread-pulse"
          style="--thread-delay: ${thread.delay}ms"
        >
          <animateMotion dur="1.8s" repeatCount="indefinite" path="${escapeHtml(thread.path)}"></animateMotion>
        </circle>
      `
      : "";
    return `
      <g class="mission-scan-thread-group" data-task-id="${escapeHtml(thread.id)}" data-status="${escapeHtml(status)}">
        <path
          class="mission-scan-thread state-${escapeHtml(thread.state)} severity-${escapeHtml(thread.severity)}"
          d="${escapeHtml(thread.path)}"
          data-testid="mission-scan-thread"
          data-thread-state="${escapeHtml(thread.state)}"
          data-task-tool="${escapeHtml(thread.tool.key)}"
          data-task-target="${escapeHtml(thread.target.targetId)}"
          style="--thread-delay: ${thread.delay}ms"
        ></path>
        ${pulse}
      </g>
    `;
  }

  function renderScanMapTool(tool) {
    return `
      <g class="mission-scan-tool-node" transform="translate(${tool.x} ${tool.y})" data-tool="${escapeHtml(tool.key)}">
        <circle r="28"></circle>
        <text class="mission-scan-tool-short" y="-2">${escapeHtml(tool.shortLabel)}</text>
        <text class="mission-scan-tool-label" y="38">${escapeHtml(tool.label)}</text>
      </g>
    `;
  }

  function renderScanMapTarget(target) {
    const severity = target.severity || "none";
    const findingCount = target.findings.length;
    const label = compactScanMapLabel(target.targetId);
    const summary = target.state === "critical"
      ? "critical finding"
      : target.state === "finding"
        ? `${findingCount} finding${findingCount === 1 ? "" : "s"}`
        : target.state === "scanning"
          ? "scanning"
          : target.state === "clean"
            ? "completed clean"
            : target.state === "blocked"
              ? "blocked"
              : "undiscovered";
    return `
      <g
        class="mission-scan-target-node state-${escapeHtml(target.state)} severity-${escapeHtml(severity)}"
        transform="translate(${target.x} ${target.y})"
        data-testid="mission-scan-target-node"
        data-node-state="${escapeHtml(target.state)}"
        data-target-id="${escapeHtml(target.targetId)}"
      >
        <title>${escapeHtml(`${target.targetId} - ${summary}`)}</title>
        <circle class="mission-scan-node-ripple" r="34"></circle>
        <circle class="mission-scan-node-ring" r="28"></circle>
        <circle class="mission-scan-node-core" r="16"></circle>
        <text class="mission-scan-target-label" x="-46" y="-34">${escapeHtml(label)}</text>
        ${
          findingCount
            ? `
              <g transform="translate(22 -22)">
                <g class="mission-scan-finding-badge severity-${escapeHtml(severity)}" data-testid="mission-scan-finding-badge">
                  <circle r="13"></circle>
                  <text y="4">${escapeHtml(String(findingCount))}</text>
                </g>
              </g>
            `
            : ""
        }
      </g>
    `;
  }

  function scanMapTargetState(target) {
    const status = normalizeTaskStatus(target.status);
    const severity = String(target.severity || "none").toLowerCase();
    if (status === "running") return "scanning";
    if (["failed", "blocked", "cancelled"].includes(status)) return "blocked";
    if (status === "completed") {
      if (severity === "critical") return "critical";
      if (severity !== "none") return "finding";
      return "clean";
    }
    return "undiscovered";
  }

  function scanMapThreadState(task) {
    const status = normalizeTaskStatus(task.status);
    if (status === "running") return "scanning";
    if (status === "completed") return "completed";
    if (["failed", "blocked", "cancelled"].includes(status)) return "blocked";
    return "queued";
  }

  function scanToolShortLabel(tool) {
    const mapping = {
      httpx: "httpx",
      nmap: "nmap",
      nuclei: "nuc",
      semgrep: "sem",
      zap: "zap",
      "ldap-enum": "ldap",
      "aws-inventory": "aws",
      "llm-probe": "llm",
    };
    const normalized = String(tool || "tool").toLowerCase();
    return mapping[normalized] || normalized.slice(0, 5);
  }

  function compactScanMapLabel(value) {
    const raw = String(value || "target");
    let label = raw;
    try {
      const url = new URL(raw);
      label = `${url.hostname}${url.pathname && url.pathname !== "/" ? url.pathname : ""}`;
    } catch {
      label = raw.replace(/^https?:\/\//i, "");
    }
    return label.length > 24 ? `${label.slice(0, 21)}...` : label;
  }

  function buildActiveTargetCards(tasks, findings) {
    const targetsById = new Map();
    (tasks || []).forEach((task) => {
      const targetId = String(task.target_id || "No target recorded");
      if (!targetsById.has(targetId)) {
        targetsById.set(targetId, {
          targetId,
          tasks: [],
          findings: [],
        });
      }
      targetsById.get(targetId).tasks.push(task);
    });

    const findingTargets = (findings || []).map((finding) => ({
      finding,
      target: normalizeScanTarget(finding.target_id),
    }));
    targetsById.forEach((target) => {
      const normalizedTarget = normalizeScanTarget(target.targetId);
      target.findings = findingTargets
        .filter(({ target: findingTarget }) => findingTarget && scanTargetsMatch(normalizedTarget, findingTarget))
        .map(({ finding }) => finding);
    });

    return [...targetsById.values()]
      .map((target) => ({
        ...target,
        status: dominantTargetStatus(target.tasks),
        severity: highestFindingSeverity(target.findings),
      }))
      .sort((left, right) => {
        const statusOrder = targetStatusRank(left.status) - targetStatusRank(right.status);
        if (statusOrder !== 0) return statusOrder;
        const severityOrder = severityRank(left.severity) - severityRank(right.severity);
        if (severityOrder !== 0) return severityOrder;
        return left.targetId.localeCompare(right.targetId);
      });
  }

  function renderActiveTargetCard(target) {
    const normalizedStatus = normalizeTaskStatus(target.status);
    const severity = target.severity || "none";
    const findingSummary = target.findings.length
      ? `${target.findings.length} stored ${severity} finding signal${target.findings.length === 1 ? "" : "s"}`
      : "No stored finding signal";
    const sortedTasks = target.tasks.slice().sort(compareTaskActivity);

    return `
      <div class="active-target-card status-${escapeHtml(normalizedStatus)} severity-${escapeHtml(severity)}" data-testid="mission-active-target-card">
        <div class="active-target-node">
          <span>${escapeHtml(normalizedStatus)}</span>
          <strong>${escapeHtml(target.targetId)}</strong>
          <small>${escapeHtml(findingSummary)}</small>
        </div>
        <div class="active-target-tool-track">
          ${sortedTasks
            .map((task) => {
              const taskStatus = normalizeTaskStatus(task.status);
              return `
                <button
                  class="active-target-tool-chip status-${escapeHtml(taskStatus)} ${String(state.selectedTaskId || "") === String(task.id || "") ? "selected" : ""}"
                  type="button"
                  data-mission-task-pick="${escapeHtml(task.id)}"
                  data-testid="mission-active-target-tool"
                >
                  <span>${escapeHtml(formatToolLabel(task.tool))}</span>
                  <small>${escapeHtml(`${taskStatus} · ${formatDateTime(task.updated_at || task.created_at)}`)}</small>
                </button>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function normalizeScanTarget(value) {
    return String(value || "").trim().toLowerCase().replace(/\/+$/, "");
  }

  function scanTargetsMatch(runTarget, findingTarget) {
    if (!runTarget || !findingTarget) return false;
    return (
      runTarget === findingTarget ||
      findingTarget.startsWith(`${runTarget}/`) ||
      runTarget.startsWith(`${findingTarget}/`)
    );
  }

  function highestFindingSeverity(findings) {
    return (findings || [])
      .map((finding) => String(finding.severity || "unknown").toLowerCase())
      .sort((left, right) => severityRank(left) - severityRank(right))[0] || "none";
  }

  function severityRank(severity) {
    const order = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
      unknown: 5,
      none: 6,
    };
    return order[String(severity || "none").toLowerCase()] ?? 5;
  }

  function dominantTargetStatus(tasks) {
    return tasks
      .map((task) => normalizeTaskStatus(task.status))
      .sort((left, right) => targetStatusRank(left) - targetStatusRank(right))[0] || "unknown";
  }

  function targetStatusRank(status) {
    const order = {
      running: 0,
      queued: 1,
      failed: 2,
      blocked: 3,
      cancelled: 4,
      completed: 5,
      unknown: 6,
    };
    return order[String(status || "unknown").toLowerCase()] ?? 6;
  }

  function summarizeRunStreamTruth(run) {
    const stream = state.runStream || {};
    const selected = run && String(stream.runId || "") === String(run.id || "");
    if (!selected) {
      return {
        label: "Polling idle",
        detail: "No live stream is attached to this selected run right now.",
      };
    }
    if (stream.status === "connected") {
      return {
        label: "SSE connected",
        detail: stream.lastEventAt
          ? `Last persisted stream event ${formatDateTime(stream.lastEventAt)}.`
          : "Live run stream is connected; polling remains available as fallback.",
      };
    }
    if (stream.status === "fallback") {
      return {
        label: "Polling fallback",
        detail: stream.fallbackReason || "Live run stream unavailable; Mission Control is using polling fallback.",
      };
    }
    if (stream.status === "connecting") {
      return {
        label: "Connecting",
        detail: "Connecting to the live run stream while polling remains available.",
      };
    }
    return {
      label: String(stream.status || "Idle"),
      detail: "Live stream is not currently contributing selected-run updates.",
    };
  }

  function renderSeverityCounters(run, findings) {
    const order = ["critical", "high", "medium", "low", "info", "unknown"];
    const counts = order.reduce((result, severity) => ({ ...result, [severity]: 0 }), {});
    findings.forEach((finding) => {
      const severity = String(finding.severity || "unknown").toLowerCase();
      counts[order.includes(severity) ? severity : "unknown"] += 1;
    });
    const animationState = buildSeverityAnimationState(run?.id, counts);
    const maxCount = Math.max(1, ...order.map((severity) => counts[severity]));
    const totalCount = order.reduce((total, severity) => total + counts[severity], 0);

    return `
      <div class="telemetry-section split-top" data-testid="mission-severity-counters">
        <div class="task-activity-header">
          <h4>Severity Counters</h4>
          <span class="metric-pill finding-total-count ${animationState.totalIncreased ? "count-bump" : ""}">${escapeHtml(`${findings.length} finding${findings.length === 1 ? "" : "s"}`)}</span>
        </div>
        <div class="severity-counter-grid">
          ${order
            .map((severity) => {
              const count = counts[severity];
              const fillWidth = totalCount ? Math.max(6, Math.round((count / maxCount) * 100)) : 0;
              const increased = animationState.increasedSeverities.has(severity);
              return `
                <div
                  class="severity-counter-card severity-${escapeHtml(severity)} ${increased ? "count-bump" : ""} ${severity === "critical" && animationState.criticalIncreased ? "critical-pulse" : ""}"
                  data-severity="${escapeHtml(severity)}"
                  data-count="${escapeHtml(String(count))}"
                >
                  <strong class="${increased ? "counter-flip" : ""}">${escapeHtml(String(count))}</strong>
                  <span class="severity-bar-track" aria-hidden="true">
                    <span class="severity-bar-fill" style="width:${escapeHtml(String(fillWidth))}%"></span>
                  </span>
                  <small>${escapeHtml(capitalizeWord(severity))}</small>
                </div>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function buildSeverityAnimationState(runId, counts) {
    const key = String(runId || "no-run");
    const previous = severitySnapshots.get(key);
    const total = Object.values(counts).reduce((sum, count) => sum + Number(count || 0), 0);
    const increasedSeverities = new Set();
    let totalIncreased = false;
    let criticalIncreased = false;
    if (previous) {
      totalIncreased = total > previous.total;
      Object.entries(counts).forEach(([severity, count]) => {
        if (Number(count || 0) > Number(previous.counts?.[severity] || 0)) {
          increasedSeverities.add(severity);
        }
      });
      criticalIncreased = increasedSeverities.has("critical");
    }
    severitySnapshots.set(key, {
      total,
      counts: { ...counts },
    });
    return { totalIncreased, criticalIncreased, increasedSeverities };
  }

  function renderTaskSwimlanes(tasks, findings) {
    const swimlanes = buildTaskSwimlanes(tasks);
    if (!swimlanes.length) {
      return "";
    }

    return `
      <div class="telemetry-section split-top" data-testid="mission-task-swimlanes">
        <div class="task-activity-header">
          <h4>Task Swimlanes</h4>
          <span class="metric-pill">${escapeHtml(`${swimlanes.length} lane${swimlanes.length === 1 ? "" : "s"}`)}</span>
        </div>
        <div class="task-swimlane-grid">
          ${swimlanes.map((lane) => renderTaskSwimlane(lane, findings)).join("")}
        </div>
      </div>
    `;
  }

  function buildTaskSwimlanes(tasks) {
    const lanesByKey = new Map();
    tasks.forEach((task) => {
      const lane = taskSwimlaneIdentity(task);
      if (!lanesByKey.has(lane.key)) {
        lanesByKey.set(lane.key, {
          ...lane,
          tasks: [],
        });
      }
      lanesByKey.get(lane.key).tasks.push(task);
    });

    return [...lanesByKey.values()]
      .map((lane) => ({
        ...lane,
        tasks: lane.tasks.slice().sort(compareTaskActivity),
      }))
      .sort((left, right) => {
        const leftHot = laneHeat(left.tasks);
        const rightHot = laneHeat(right.tasks);
        if (leftHot !== rightHot) return rightHot - leftHot;
        return left.label.localeCompare(right.label);
      });
  }

  function taskSwimlaneIdentity(task) {
    const params = task.params_json || {};
    const profileName = params.profile_name || task.execution_lane || task.execution_profile;
    if (profileName) {
      return {
        key: `lane:${profileName}`,
        label: profileName,
        meta: "Execution lane",
      };
    }
    const tool = task.tool || "unknown";
    return {
      key: `tool:${tool}`,
      label: formatToolLabel(tool),
      meta: "Tool lane",
    };
  }

  function laneHeat(tasks) {
    const statuses = tasks.map((task) => normalizeTaskStatus(task.status));
    if (statuses.includes("running")) return 5;
    if (statuses.includes("queued")) return 4;
    if (statuses.includes("blocked")) return 3;
    if (statuses.includes("failed")) return 2;
    if (statuses.includes("completed")) return 1;
    return 0;
  }

  function renderTaskSwimlane(lane, findings) {
    const counts = summarizeTelemetryTaskStatuses(lane.tasks);
    const statusSummary = [
      counts.running ? `${counts.running} running` : null,
      counts.queued ? `${counts.queued} queued` : null,
      counts.completed ? `${counts.completed} completed` : null,
      counts.failed ? `${counts.failed} failed` : null,
      counts.blocked ? `${counts.blocked} blocked` : null,
      counts.cancelled ? `${counts.cancelled} cancelled` : null,
    ].filter(Boolean);

    return `
      <div class="task-swimlane" data-testid="mission-task-swimlane">
        <div class="task-swimlane-header">
          <div>
            <h5>${escapeHtml(lane.label)}</h5>
            <p class="micro-copy">${escapeHtml(`${lane.meta} · ${lane.tasks.length} task${lane.tasks.length === 1 ? "" : "s"}`)}</p>
          </div>
          <span class="metric-pill">${escapeHtml(statusSummary.join(" · ") || "state updating")}</span>
        </div>
        <div class="task-swimlane-track">
          ${lane.tasks
            .map((task) => {
              const normalized = normalizeTaskStatus(task.status);
              return `
                <button
                  class="task-swimlane-chip status-${escapeHtml(normalized)} ${String(state.selectedTaskId || "") === String(task.id || "") ? "selected" : ""}"
                  type="button"
                  data-status="${escapeHtml(normalized)}"
                  data-mission-task-pick="${escapeHtml(task.id)}"
                  data-testid="mission-task-swimlane-chip"
                >
                  <span>${escapeHtml(formatToolLabel(task.tool))}</span>
                  ${renderTaskFindingBadge(task, findings)}
                  ${statusPill(task.status)}
                  <small>${escapeHtml(`${task.target_id || "No target recorded"} · ${formatDateTime(task.updated_at || task.created_at)}`)}</small>
                </button>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function renderTaskFindingBadge(task, findings = []) {
    if (normalizeTaskStatus(task.status) !== "completed") return "";
    const matchedFindings = findingsForTask(task, findings);
    if (!matchedFindings.length) return "";
    const severity = highestFindingSeverity(matchedFindings);
    return `<span class="finding-count-badge severity-${escapeHtml(severity)}" data-testid="task-finding-badge">+${escapeHtml(String(matchedFindings.length))}</span>`;
  }

  function findingsForTask(task, findings = []) {
    const taskTarget = String(task?.target_id || "").trim().toLowerCase();
    if (!taskTarget) return [];
    return findings.filter((finding) => targetMatchesTask(taskTarget, finding?.target_id));
  }

  function targetMatchesTask(taskTarget, findingTarget) {
    const normalizedFindingTarget = String(findingTarget || "").trim().toLowerCase();
    if (!normalizedFindingTarget) return false;
    return normalizedFindingTarget === taskTarget ||
      normalizedFindingTarget.startsWith(`${taskTarget}/`) ||
      taskTarget.startsWith(`${normalizedFindingTarget}/`);
  }

  function summarizeTelemetryTaskStatuses(tasks) {
    return tasks.reduce(
      (counts, task) => {
        const status = normalizeTaskStatus(task.status);
        counts[status] = (counts[status] || 0) + 1;
        return counts;
      },
      { running: 0, queued: 0, completed: 0, failed: 0, blocked: 0, cancelled: 0, unknown: 0 }
    );
  }

  function renderActivityDeltas(tasks, findings) {
    const deltas = [
      ...tasks.map((task) => ({
        type: "Task",
        label: formatToolLabel(task.tool),
        detail: `${normalizeTaskStatus(task.status)} · ${task.target_id || "No target recorded"}`,
        timestamp: task.updated_at || task.created_at || null,
      })),
      ...findings.map((finding) => ({
        type: "Finding",
        label: finding.title || finding.id || "Finding",
        detail: `${finding.severity || "unknown"} · ${finding.target_id || "No target recorded"}`,
        timestamp: finding.updated_at || finding.created_at || null,
      })),
    ]
      .sort((left, right) => timestampMs(right.timestamp) - timestampMs(left.timestamp))
      .slice(0, 5);

    return `
      <div class="telemetry-section split-top" data-testid="mission-activity-deltas">
        <div class="task-activity-header">
          <h4>Persisted Activity Deltas</h4>
          <span class="metric-pill">${escapeHtml(`${deltas.length} recent signal${deltas.length === 1 ? "" : "s"}`)}</span>
        </div>
        ${
          deltas.length
            ? `
              <div class="activity-delta-list">
                ${deltas
                  .map(
                    (delta) => `
                      <div class="activity-delta-card">
                        <span>${escapeHtml(delta.type)}</span>
                        <strong>${escapeHtml(delta.label)}</strong>
                        <small>${escapeHtml(`${delta.detail} · ${formatDateTime(delta.timestamp)}`)}</small>
                      </div>
                    `
                  )
                  .join("")}
              </div>
            `
            : emptyState("No persisted task or finding activity is available for this run yet.")
        }
      </div>
    `;
  }

  function timestampMs(value) {
    if (!value) return 0;
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function attachMissionRunActivityHandlers() {
    dom.missionRunActivity.querySelectorAll("[data-mission-task-pick]").forEach((button) => {
      button.addEventListener("click", async () => {
        patchState({ selectedTaskId: button.dataset.missionTaskPick || null }, "mission.task.select");
        await runtime.actions.loadSelectedTask?.();
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-ai-repair-task-id]").forEach((button) => {
      button.addEventListener("click", async () => {
        await draftAiRepairProposal(button.dataset.aiRepairTaskId);
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-assessment-chain-phase-decision]").forEach((button) => {
      button.addEventListener("click", async () => {
        const chainId = button.dataset.assessmentChainId;
        const phaseKey = button.dataset.assessmentChainPhaseKey;
        const decision = button.dataset.assessmentChainPhaseDecision;
        if (!chainId || !phaseKey || !decision) return;
        await api(`/api/v1/assessment-chains/${chainId}/phases/${phaseKey}/decision`, {
          method: "POST",
          body: { decision },
        });
        runtime.actions.pushStatus?.(
          decision === "approved"
            ? `Phase ${phaseKey} approved. The chain is queuing the next runner now.`
            : `Phase ${phaseKey} rejected. The assessment chain is now stopped at that boundary.`,
          decision === "approved" ? "success" : "warning"
        );
        await runtime.actions.refreshSelectedEngagement?.();
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-assessment-chain-halt]").forEach((button) => {
      button.addEventListener("click", async () => {
        const chainId = button.dataset.assessmentChainId;
        if (!chainId) return;
        await api(`/api/v1/assessment-chains/${chainId}/halt`, {
          method: "POST",
        });
        runtime.actions.pushStatus?.("Assessment chain halted at the current boundary.", "warning");
        await runtime.actions.refreshSelectedEngagement?.();
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-assessment-chain-continue]").forEach((button) => {
      button.addEventListener("click", async () => {
        const chainId = button.dataset.assessmentChainId;
        if (!chainId) return;
        await api(`/api/v1/assessment-chains/${chainId}/continue`, {
          method: "POST",
        });
        runtime.actions.pushStatus?.(
          "Blocked runner reviewed. AegisPT is continuing with the next safe chain step.",
          "success"
        );
        await runtime.actions.refreshSelectedEngagement?.();
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-cve-intel-refresh]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!state.selectedRunId) return;
        const liveNvd = button.dataset.cveIntelRefresh === "nvd";
        runtime.actions.pushStatus?.(
          liveNvd ? "Running bounded NVD lookup for discovered products." : "Refreshing local CVE intelligence from discovered inventory.",
          "info"
        );
        const payload = await api(`/api/v1/runs/${state.selectedRunId}/cve-intelligence/refresh`, {
          method: "POST",
          body: { live_nvd_lookup: liveNvd },
        });
        patchState({ selectedCveIntelligence: payload }, "mission.cveIntel.refresh");
        runtime.actions.pushStatus?.(
          `CVE intelligence refreshed: ${payload.cve_count || 0} high-risk item${payload.cve_count === 1 ? "" : "s"}.`,
          "success"
        );
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-cve-intel-run-test]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!state.selectedRunId) return;
        const cveId = button.dataset.cveIntelRunTest;
        if (!cveId) return;
        runtime.actions.pushStatus?.(`Queueing approved targeted detection for ${cveId}.`, "info");
        const payload = await api(`/api/v1/runs/${state.selectedRunId}/cve-intelligence/${encodeURIComponent(cveId)}/queue-test`, {
          method: "POST",
        });
        patchState({
          selectedRun: payload.run,
          selectedCveIntelligence: payload.cve_intelligence,
          selectedTaskId: payload.task?.id || state.selectedTaskId,
        }, "mission.cveIntel.queueTest");
        await runtime.actions.refreshSelectedEngagement?.();
        runtime.actions.pushStatus?.(`${cveId} targeted detection is queued. Dispatch remains explicit.`, "success");
        renderMissionControl();
      });
    });
    dom.missionRunActivity.querySelectorAll("[data-cve-intel-generate-template]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!state.selectedEngagementId) return;
        const recordId = button.dataset.cveIntelGenerateTemplate;
        if (!recordId) return;
        runtime.actions.pushStatus?.("Generating a review-only Nuclei template through the existing pack lifecycle.", "info");
        const result = await api(`/api/v1/threat-intel/${encodeURIComponent(recordId)}/generate-template`, {
          method: "POST",
          body: { engagement_id: state.selectedEngagementId },
        });
        runtime.actions.pushStatus?.(result.message || "Template generation request finished.", result.status === "generated" ? "success" : "warning");
        const refreshed = await api(`/api/v1/runs/${state.selectedRunId}/cve-intelligence/refresh`, {
          method: "POST",
          body: { live_nvd_lookup: false },
        });
        patchState({ selectedCveIntelligence: refreshed }, "mission.cveIntel.generateTemplate");
        renderMissionControl();
      });
    });
  }

  async function draftAiRepairProposal(taskId) {
    if (!state.selectedRunId || !taskId) {
      throw new Error("Select a run and failed, blocked, or skipped task before drafting an AI repair proposal.");
    }
    runtime.actions.pushStatus?.("Drafting isolated AI repair proposal. No runtime work is being queued.", "info");
    await api(`/api/v1/runs/${state.selectedRunId}/tasks/${taskId}/ai-repair`, {
      method: "POST",
      body: {
        note: "Requested from Mission Control selected task focus.",
      },
    });
    const insights = await api(`/api/v1/runs/${state.selectedRunId}/ai-insights`);
    patchState({ selectedAiInsights: insights }, "mission.aiRepair.drafted");
    runtime.actions.pushStatus?.("AI repair proposal is ready for review in AI Signal.", "success");
    renderMissionControl();
  }

  function focusActorInputForApproval() {
    dom.actorInput?.focus();
    dom.actorInput?.select?.();
    runtime.actions.pushStatus?.(
      "Update the actor field in the top bar before recording the next approval decision.",
      "info"
    );
  }

  async function recordRunApprovalDecision({ runId, stepId, decision }) {
    if (!runId) {
      throw new Error("Select a run before recording approval.");
    }
    if (!decision) {
      throw new Error("Choose an approval decision before submitting.");
    }
    patchState(
      {
        loading: {
          ...state.loading,
          approvalRunId: runId,
          approvalDecision: decision,
        },
      },
      "mission.approval.start"
    );
    runtime.actions.pushStatus?.(
      decision === "approved" ? "Recording run approval." : "Recording run rejection.",
      "info"
    );
    runtime.actions.renderAll?.();

    try {
      const updatedRun = await api(`/api/v1/runs/${runId}/approvals`, {
        method: "POST",
        body: {
          step_id: stepId || "run.launch",
          decision,
        },
      });
      patchState(
        {
          selectedRun:
            String(state.selectedRunId || "") === String(updatedRun.id || "")
              ? updatedRun
              : state.selectedRun,
          selectedTaskId:
            String(state.selectedRunId || "") === String(updatedRun.id || "")
              ? updatedRun.tasks?.[0]?.id || state.selectedTaskId
              : state.selectedTaskId,
          mission: {
            ...state.mission,
            runs: (Array.isArray(state.mission.runs) ? state.mission.runs : []).map((candidate) =>
              String(candidate.id || "") === String(updatedRun.id || "") ? updatedRun : candidate
            ),
          },
        },
        "mission.approval.updatedRun"
      );
      try {
        await runtime.actions.refreshSelectedEngagement?.();
      } catch (refreshError) {
        runtime.actions.pushStatus?.(
          "Approval was recorded, but Mission Control could not fully refresh. The latest run state is shown from the approval response.",
          "warning"
        );
      }
      if (decision === "rejected") {
        runtime.actions.pushStatus?.("Run rejected. No queued checks will be launched from this dossier.", "warning");
        return;
      }
      const pending = Math.max(0, Number(updatedRun?.pending_approvals || 0));
      if (pending > 0) {
        runtime.actions.pushStatus?.(
          `${pending} approval${pending === 1 ? "" : "s"} still remain. Change the actor in the top bar for the next approver.`,
          "info"
        );
        return;
      }
      runtime.actions.pushStatus?.("Approval recorded. The planned checks are now queued and ready for dispatch.", "success");
    } finally {
      patchState(
        {
          loading: {
            ...state.loading,
            approvalRunId: null,
            approvalDecision: null,
          },
        },
        "mission.approval.finish"
      );
      runtime.actions.renderAll?.();
    }
  }

  function attachMissionSupportHandlers() {
    dom.missionPackStatus?.querySelectorAll("[data-mission-run-pick]").forEach((button) => {
      button.addEventListener("click", async () => {
        const runId = button.dataset.missionRunPick || null;
        if (!runId || String(runId) === String(state.selectedRunId || "")) return;
        patchState({ selectedRunId: runId, selectedTaskId: null }, "mission.run.select");
        await runtime.actions.loadSelectedRun?.();
        renderMissionControl();
      });
    });
  }

  function renderEngagementRunQueueSummary() {
    const runs = Array.isArray(state.mission.runs) ? state.mission.runs : [];
    if (!runs.length) {
      return emptyState("No runs exist for this engagement yet.", {
        label: "Start a mission",
        screen: "wizard",
      });
    }
    const visibleRuns = runs.slice(0, 6);
    const activeCount = runs.filter((run) =>
      ["queued", "running", "pending_approval"].includes(String(run.status || "").toLowerCase())
    ).length;
    const bound = state.selectedRun?.pack_binding || null;
    const boundPackId = String(bound?.pack_id || "");
    const boundPack =
      boundPackId && Array.isArray(state.mission?.packs)
        ? state.mission.packs.find((candidate) => String(candidate.id || "") === boundPackId) || null
        : null;
    const boundPackSummary = bound
      ? `
        <div class="detail-surface compact-surface" data-testid="mission-bound-pack-summary">
          <div class="task-activity-header">
            <div>
              <p class="eyebrow">Runtime Pack</p>
              <h4>${escapeHtml(boundPack?.name || "Bound adaptive pack")}</h4>
            </div>
            ${statusPill(bound.deployment_status || boundPack?.status || "bound")}
          </div>
          ${renderBadgeList([
            `Runtime ${bound.pack_version || "standard baseline"}`,
            bound.deployment_target ? `Target ${bound.deployment_target}` : "",
            bound.run_profile_name ? `Profile ${bound.run_profile_name}` : "",
          ].filter(Boolean), "compact-badge-list split-top")}
        </div>
      `
      : "";
    const selectedDeleteRunIds = new Set(state.deleteUi?.selectedRunIds || []);
    const selectedCount = runs.filter((run) => selectedDeleteRunIds.has(String(run.id))).length;
    return `
      <div class="mission-run-queue" data-testid="mission-run-queue">
        ${boundPackSummary}
        <h4>${escapeHtml(activeCount ? `${activeCount} active or waiting` : "Recent runs")}</h4>
        ${
          selectedCount
            ? `
              <div class="bulk-delete-bar compact-bulk-delete-bar" data-testid="mission-bulk-delete-bar">
                <strong>${escapeHtml(`${selectedCount} selected`)}</strong>
                <button class="action secondary tiny danger-action" type="button" data-run-delete-preview="selected" data-testid="mission-bulk-delete-runs">Delete selected</button>
              </div>
            `
            : ""
        }
        <div class="mission-run-queue-list split-top">
          ${visibleRuns.map(renderMissionRunQueueCard).join("")}
        </div>
      </div>
    `;
  }

  function renderMissionRunQueueCard(run) {
    const counts = summarizeTaskStatuses(run.tasks || []);
    const selected = String(run.id || "") === String(state.selectedRunId || "");
    const status = String(run.status || "unknown").toLowerCase();
    const checked = new Set(state.deleteUi?.selectedRunIds || []).has(String(run.id || ""));
    const label = currentRunLabel(run);
    const phase = currentRunPhaseLabel(run);
    const summary = counts.running
      ? `${counts.running} running`
      : counts.queued
        ? `${counts.queued} queued`
        : counts.failed
          ? `${counts.failed} failed`
          : counts.completed
            ? `${counts.completed} completed`
            : "No task signal yet";
    return `
      <article class="mission-run-queue-card ${selected ? "is-selected" : ""}" data-testid="mission-run-card">
        <label class="delete-checkline mission-run-delete-toggle" data-run-delete-control>
          <input
            type="checkbox"
            data-run-delete-toggle="${escapeHtml(String(run.id || ""))}"
            ${checked ? "checked" : ""}
            aria-label="Select run for deletion"
          />
          <span class="sr-only">Select run</span>
        </label>
        <button
          class="mission-run-queue-card-button"
          type="button"
          data-mission-run-pick="${escapeHtml(String(run.id || ""))}"
        >
          <div class="ai-signal-entry-meta">
            <span>${escapeHtml(label)}</span>
            ${statusPill(run.status || "unknown")}
          </div>
          <strong>${escapeHtml(phase)}</strong>
          <p class="micro-copy">${escapeHtml(summary)}</p>
        </button>
        <details class="run-card-menu" data-run-delete-control>
          <summary aria-label="Run actions">...</summary>
          <button class="action ghost tiny danger-action" type="button" data-run-delete-preview="${escapeHtml(String(run.id || ""))}" data-testid="mission-delete-run">Delete</button>
        </details>
      </article>
    `;
  }

  function renderMissionLatestEventSummary() {
    const latest = statusFeed[0] || null;
    if (!latest) {
      return emptyState("Run events appear here as soon as work is queued or dispatched.", {
        label: "Open Mission Control",
        screen: "mission-control",
      });
    }
    const history = statusFeed.slice(1, 4);
    return `
      <div class="mission-event-summary" data-testid="mission-event-summary">
        <h4>${escapeHtml(latest.message || "Latest event")}</h4>
        <p>${escapeHtml(`${latest.timestamp || "Now"} · ${latest.tone || "info"}${latest.count > 1 ? ` · x${latest.count}` : ""}`)}</p>
        ${
          history.length
            ? renderDisclosure({
                title: "Recent events",
                summary: `${history.length} earlier update${history.length === 1 ? "" : "s"}`,
                open: false,
                testId: "mission-event-history",
                body: history
                  .map(
                    (item) => `
                      <div class="feed-item tone-${escapeHtml(String(item.tone || "info").toLowerCase())}">
                        <strong>${escapeHtml(item.timestamp || "Now")} · ${escapeHtml(item.tone || "info")}</strong>
                        <p>${escapeHtml(item.message || "No event message recorded.")}</p>
                      </div>
                    `
                  )
                  .join(""),
              })
            : ""
        }
      </div>
    `;
  }

  function renderScopeProfileSummary() {
    const run = state.selectedRun;
    if (!run) {
      return emptyState("Wizard-defined scope, modules, accounts, and limits appear here once a run exists.");
    }
    const config = run.configuration_json || {};
    const targets = config.targets || {};
    const accounts = config.access?.accounts || [];
    const accessContextCount = countMeaningfulAccessContexts(config.access || {});
    const accessSummary = renderAccessContextSummary(config.access || {});
    const plan = executionPlanForProfile(run.profile.name, state.runProfiles);
    const modules = enabledModules(config.modules || {});
    const acceptance = config.acceptance_metadata || null;
    const intakeInterpretation = config.intake?.llm_interpretation || null;
    const exactTargets = flattenTargetValues(targets);
    const targetPreview = exactTargets.length
      ? exactTargets.slice(0, 3).join(", ")
      : "No explicit targets recorded";
    return `
      <h4>${escapeHtml(config.assessment_type || "Assessment not recorded")}</h4>
      <p>${escapeHtml(config.test_profile || run.profile.name)}</p>
      ${renderBadgeList([
        renderTargetSummary(targets),
        accounts.length
          ? `${accounts.length} account / role context${accounts.length === 1 ? "" : "s"}`
          : `${accessContextCount} access context${accessContextCount === 1 ? "" : "s"}`,
        `Execution ${plan.profileName}`,
        `RPS ${config.safety?.rate_limit_rps || "n/a"}`,
        `ETA ${config.eta?.estimated_total_minutes || "n/a"}m`,
        acceptance?.scenario_id ? `Acceptance ${acceptance.scenario_id}` : null,
      ], "compact-badge-list split-top")}
      <p class="micro-copy split-top">${escapeHtml(targetPreview)}${exactTargets.length > 3 ? `, plus ${exactTargets.length - 3} more` : ""}</p>
      ${renderIntakeIntelligenceSummary(intakeInterpretation)}
      ${renderDisclosure({
        title: "Coverage & Guardrails",
        summary: `${modules.length} modules · ${plan.toolsLabel} · depth ${humanizeDepthLabel(config.safety?.max_validation_depth)}`,
        open: false,
        testId: "mission-scope-context",
        body: `
          <div class="compact-definition-grid">
            <div><span>Targets</span><strong>${escapeHtml(renderTargetSummary(targets))}</strong></div>
            <div><span>Exact Scope</span><strong>${escapeHtml(exactTargets.join(", ") || "No explicit targets recorded")}</strong></div>
            <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
            <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
            <div><span>Modules</span><strong>${escapeHtml(modules.join(", ") || "No modules recorded")}</strong></div>
            <div><span>Access</span><strong>${escapeHtml(accessSummary)}</strong></div>
            <div><span>Check Mode</span><strong>${escapeHtml(humanizeCheckMode(config.safety?.active_checks))}</strong></div>
            <div><span>Depth</span><strong>${escapeHtml(humanizeDepthLabel(config.safety?.max_validation_depth))}</strong></div>
            <div><span>Concurrency</span><strong>${escapeHtml(String(config.safety?.concurrency || "n/a"))}</strong></div>
            <div><span>Time Budget</span><strong>${escapeHtml(`${config.safety?.time_budget_minutes || "n/a"} minutes`)}</strong></div>
            <div><span>Boundary Notes</span><strong>${escapeHtml(config.exclusions?.notes || "Not recorded")}</strong></div>
          </div>
        `,
      })}
      ${
        acceptance
          ? renderDisclosure({
              title: "Acceptance Scenario Context",
              summary: `${acceptance.scenario_id || "scenario"} · ${acceptance.target_label || acceptance.target_id || "safe target"}`,
              open: false,
              testId: "mission-acceptance-context",
              body: `
                <div class="compact-definition-grid">
                  <div><span>Scenario</span><strong>${escapeHtml(acceptance.scenario_id || "Not recorded")}</strong></div>
                  <div><span>Target</span><strong>${escapeHtml(acceptance.target_label || acceptance.target_id || "Not recorded")}</strong></div>
                  <div><span>Classification</span><strong>${escapeHtml(acceptance.target_classification || "Not recorded")}</strong></div>
                  <div><span>Expected Outputs</span><strong>${escapeHtml((acceptance.expected_outputs || []).join(", ") || "Not recorded")}</strong></div>
                </div>
              `,
            })
          : ""
      }
    `;
  }

  function renderIntakeIntelligenceSummary(interpretation) {
    if (!interpretation || typeof interpretation !== "object") return "";
    const warnings = Array.isArray(interpretation.warnings) ? interpretation.warnings : [];
    const blocked = Array.isArray(interpretation.blocked_suggestions) ? interpretation.blocked_suggestions : [];
    const questions = Array.isArray(interpretation.follow_up_questions)
      ? interpretation.follow_up_questions
      : [];
    const boundary = interpretation.boundary || {};
    return `
      <div class="section-note split-top" data-testid="mission-intake-intelligence">
        <strong>LLM intake intelligence requires operator confirmation</strong>
        <p>${escapeHtml(
          boundary.message ||
            "Intake intelligence is advisory only and cannot add targets, assume access, approve packs, deploy packs, or dispatch work."
        )}</p>
        ${renderBadgeList([
          `Status ${interpretation.status || "unknown"}`,
          `Provider ${interpretation.provider || "unknown"}`,
          interpretation.scope_expansion_blocked !== false ? "No scope expansion" : null,
          interpretation.deterministic_intake_preserved !== false ? "Deterministic fallback preserved" : null,
          blocked.length ? `${blocked.length} blocked suggestion${blocked.length === 1 ? "" : "s"}` : null,
          questions.length ? `${questions.length} follow-up question${questions.length === 1 ? "" : "s"}` : null,
        ], "compact-badge-list split-top")}
        ${
          warnings.length
            ? `<p class="micro-copy split-top">${escapeHtml(warnings.slice(0, 2).join(" "))}</p>`
            : ""
        }
      </div>
    `;
  }

  function renderInventoryFollowUpPanel(context = "surface") {
    const plans = buildInventoryFollowUpPlans();
    if (!plans.length) {
      return `
        <div class="section-note split-top" data-testid="inventory-follow-up-empty">
          <strong>Next-step automation is waiting for more signal</strong>
          <p>Once services, web endpoints, or additional approved internal ranges are available, AegisPT will show concrete follow-up actions here.</p>
        </div>
      `;
    }

    return `
      <div class="surface-follow-up split-top" data-testid="inventory-follow-up-panel">
        <div class="compact-head">
          <h4>Operational Next Steps</h4>
          <p class="micro-copy">Follow-up runs stay inside the current authorized scope and create real deterministic run dossiers for the discovered estate.</p>
        </div>
        <div class="surface-follow-up-grid">
          ${plans
            .map(
              (plan) => `
                <div class="detail-surface">
                  <h4>${escapeHtml(plan.label)}</h4>
                  <p>${escapeHtml(plan.summary)}</p>
                  <p class="micro-copy split-top">${escapeHtml(plan.detail)}</p>
                  ${renderBadgeList(
                    [
                      `${plan.targetCount} target${plan.targetCount === 1 ? "" : "s"}`,
                      plan.profileName,
                      `${plan.etaMinutes}m ETA`,
                    ],
                    "compact-badge-list split-top"
                  )}
                  <div class="panel-actions split-top">
                    <button
                      class="action primary"
                      type="button"
                      data-follow-up-launch="${escapeHtml(plan.id)}"
                      data-testid="follow-up-${escapeHtml(plan.id)}-${escapeHtml(context)}"
                    >
                      ${escapeHtml(plan.actionLabel)}
                    </button>
                    ${
                      context === "mission"
                        ? '<button class="action ghost" type="button" data-nav-screen="surface-map">Review Assets</button>'
                        : '<button class="action ghost" type="button" data-nav-screen="mission-control">Back to Mission Control</button>'
                    }
                  </div>
                </div>
              `
            )
            .join("")}
        </div>
      </div>
    `;
  }

  function buildInventoryFollowUpPlans() {
    const run = state.selectedRun;
    const scope = state.mission.scope;
    const snapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    if (!run || !snapshot) return [];

    const inventory = snapshot.normalized_inventory_json || {};
    const baseConfig = run.configuration_json || {};
    const baseSafety = typeof baseConfig.safety === "object" && baseConfig.safety !== null
      ? baseConfig.safety
      : {};
    const baseModules = typeof baseConfig.modules === "object" && baseConfig.modules !== null
      ? baseConfig.modules
      : {};
    const baseTargets = typeof baseConfig.targets === "object" && baseConfig.targets !== null
      ? baseConfig.targets
      : {};
    const baseAccess = typeof baseConfig.access === "object" && baseConfig.access !== null
      ? baseConfig.access
      : {};
    const baseExclusions = typeof baseConfig.exclusions === "object" && baseConfig.exclusions !== null
      ? baseConfig.exclusions
      : {};
    const basePreferences =
      typeof baseConfig.intake_preferences === "object" && baseConfig.intake_preferences !== null
        ? baseConfig.intake_preferences
        : {};
    const stagedInternalValidation =
      baseConfig.assessment_type === "Internal Range / LAN" &&
      baseConfig.test_profile === "Internal Validation";

    const discoveredHosts = uniqueStrings([
      ...(inventory.hosts || []).map((host) => host.host),
      ...(inventory.services || []).map((service) => service.host),
    ]);
    const webTargets = uniqueStrings([
      ...(inventory.http_endpoints || []).map((endpoint) => endpoint.url),
      ...deriveWebTargetsFromServices(inventory.services || []),
    ]);
    const approvedCidrs = Array.isArray(scope?.allowlist_json?.cidr_ranges)
      ? scope.allowlist_json.cidr_ranges.filter((value) => typeof value === "string" && value.trim())
      : [];
    const currentCidrs = Array.isArray(baseTargets.cidr_ranges)
      ? baseTargets.cidr_ranges.filter((value) => typeof value === "string" && value.trim())
      : [];
    const remainingApprovedCidrs = approvedCidrs.filter((cidr) => !currentCidrs.includes(cidr));

    const plans = [];
    if (discoveredHosts.length) {
      plans.push({
        id: "service-enumeration",
        label: "Identify services on discovered hosts",
        actionLabel: "Run Service Identification",
        summary: `Create a passive follow-up run across ${discoveredHosts.length} discovered host${discoveredHosts.length === 1 ? "" : "s"} to map listening services and product hints.`,
        detail: stagedInternalValidation
          ? "This is the next operational step for internal LAN validation. It maps real services first so deeper follow-up stays targeted and explainable."
          : "This adds top-port and service-detection coverage without broadening scope or enabling exploitation-style checks.",
        profileName: "passive-network-service-enumeration",
        targetCount: discoveredHosts.length,
        etaMinutes: Math.max(15, Math.ceil(discoveredHosts.length / 8) * 5),
        configurationJson: {
          assessment_type: baseConfig.assessment_type || "Internal Range / LAN",
          test_profile: "Inventory Follow-Up: Service Identification",
          execution_profile: "passive-network-service-enumeration",
          targets: { ip_addresses: discoveredHosts },
          access: baseAccess,
          exclusions: baseExclusions,
          intake_preferences: {
            ...basePreferences,
            mission_intent: basePreferences.mission_intent || "inventory-follow-up",
            primary_goal: "inventory-follow-up",
            output_style: basePreferences.output_style || "per-asset",
          },
          modules: {
            ...baseModules,
            discovery: true,
            inventory_follow_up: true,
          },
          safety: {
            ...baseSafety,
            active_checks: "passive",
            concurrency: Math.min(Number(baseSafety.concurrency || 1), 1),
            rate_limit_rps: Math.min(Number(baseSafety.rate_limit_rps || 1), 1),
          },
          eta: {
            estimated_total_minutes: Math.max(15, Math.ceil(discoveredHosts.length / 8) * 5),
            estimated_impact: "low",
            confidence: "medium",
          },
          follow_up: {
            strategy: "service-enumeration",
            source_run_id: run.id,
            source_inventory_snapshot_id: snapshot.id,
            rationale: "Discovery confirmed live hosts and service identification is the next passive step.",
          },
        },
      });
    }

    if (webTargets.length) {
      plans.push({
        id: "web-baseline",
        label: "Profile discovered web assets",
        actionLabel: "Run Web Profiling",
        summary: `Create a passive HTTP profiling run for ${webTargets.length} discovered URL${webTargets.length === 1 ? "" : "s"} so titles, status codes, and technology hints are recorded.`,
        detail: "This is the safest next step for discovered web services before choosing deeper validation or approval-gated active checks.",
        profileName: "passive-web-baseline",
        targetCount: webTargets.length,
        etaMinutes: Math.max(10, Math.ceil(webTargets.length / 10) * 4),
        configurationJson: {
          assessment_type: "Mixed Assessment",
          test_profile: "Inventory Follow-Up: Web Profiling",
          execution_profile: "passive-web-baseline",
          targets: { urls: webTargets },
          access: baseAccess,
          exclusions: baseExclusions,
          intake_preferences: {
            ...basePreferences,
            mission_intent: basePreferences.mission_intent || "inventory-follow-up",
            primary_goal: "web-profiling-follow-up",
            output_style: basePreferences.output_style || "per-asset",
          },
          modules: {
            ...baseModules,
            web_crawling: true,
            inventory_follow_up: true,
          },
          safety: {
            ...baseSafety,
            active_checks: "passive",
          },
          eta: {
            estimated_total_minutes: Math.max(10, Math.ceil(webTargets.length / 10) * 4),
            estimated_impact: "low",
            confidence: "medium",
          },
          follow_up: {
            strategy: "web-baseline",
            source_run_id: run.id,
            source_inventory_snapshot_id: snapshot.id,
            rationale: "Inventory exposed web-capable targets that need HTTP fingerprinting before deeper validation.",
          },
        },
      });
    }

    if (remainingApprovedCidrs.length) {
      plans.push({
        id: "approved-range-discovery",
        label: "Continue discovery in other approved internal ranges",
        actionLabel: "Run Additional Range Discovery",
        summary: `Queue discovery for ${remainingApprovedCidrs.length} additional approved CIDR range${remainingApprovedCidrs.length === 1 ? "" : "s"} already present in the engagement scope.`,
        detail: "AegisPT will not guess or broaden scope. It only reuses extra CIDRs that are already explicitly allowlisted for this engagement.",
        profileName: "passive-network-discovery",
        targetCount: remainingApprovedCidrs.length,
        etaMinutes: Math.max(10, remainingApprovedCidrs.length * 8),
        configurationJson: {
          assessment_type: "Internal Range / LAN",
          test_profile: "Inventory Follow-Up: Additional Approved Ranges",
          execution_profile: "passive-network-discovery",
          targets: { cidr_ranges: remainingApprovedCidrs },
          access: baseAccess,
          exclusions: baseExclusions,
          intake_preferences: {
            ...basePreferences,
            mission_intent: basePreferences.mission_intent || "inventory-follow-up",
            primary_goal: "inventory-follow-up",
            lateral_discovery: "authorized-allowlist-only",
          },
          modules: {
            ...baseModules,
            discovery: true,
          },
          safety: {
            ...baseSafety,
            active_checks: "passive",
            concurrency: Math.min(Number(baseSafety.concurrency || 1), 1),
          },
          eta: {
            estimated_total_minutes: Math.max(10, remainingApprovedCidrs.length * 8),
            estimated_impact: "low",
            confidence: "medium",
          },
          follow_up: {
            strategy: "approved-range-discovery",
            source_run_id: run.id,
            source_inventory_snapshot_id: snapshot.id,
            rationale: "The engagement scope already includes additional approved internal ranges that have not yet been inventoried.",
          },
        },
      });
    }

    return plans;
  }

  function buildSurfaceAssets(snapshot) {
    const inventory = snapshot?.normalized_inventory_json || {};
    const servicesByHost = new Map();
    const endpointsByHost = new Map();
    const technologies = Array.isArray(inventory.technologies) ? inventory.technologies : [];
    const fingerprints = Array.isArray(inventory.vendor_product_fingerprints)
      ? inventory.vendor_product_fingerprints
      : [];
    const endpoints = Array.isArray(inventory.http_endpoints) ? inventory.http_endpoints : [];
    const services = Array.isArray(inventory.services) ? inventory.services : [];
    const hosts = Array.isArray(inventory.hosts) ? inventory.hosts : [];

    services.forEach((service) => {
      const bucket = servicesByHost.get(service.host) || [];
      bucket.push(service);
      servicesByHost.set(service.host, bucket);
    });
    endpoints.forEach((endpoint) => {
      const hostname = hostFromUrl(endpoint.url);
      if (!hostname) return;
      const bucket = endpointsByHost.get(hostname) || [];
      bucket.push(endpoint);
      endpointsByHost.set(hostname, bucket);
    });

    const assets = [
      ...hosts.map((host) => {
        const relatedServices = servicesByHost.get(host.host) || [];
        const relatedEndpoints = endpointsByHost.get(host.host) || [];
        return {
          key: `host:${host.host}`,
          type: "host",
          title: host.host,
          summary: `${relatedServices.length} service${relatedServices.length === 1 ? "" : "s"} · ${relatedEndpoints.length} endpoint${relatedEndpoints.length === 1 ? "" : "s"}`,
          meta: host.source === "wizard-input"
            ? "Seeded from reviewed scope"
            : host.source === "easm-discover"
              ? `EASM candidate · ${toPercent(host.confidence)} confidence`
              : `${toPercent(host.confidence)} confidence`,
          payload: { ...host, services: relatedServices, endpoints: relatedEndpoints },
        };
      }),
      ...services.map((service) => ({
        key: `service:${service.host}:${service.port}/${service.protocol}`,
        type: "service",
        title: `${service.host}:${service.port}/${service.protocol}`,
        summary: [service.service, service.product, service.version].filter(Boolean).join(" · "),
        meta: service.source === "easm-discover"
          ? `EASM candidate · ${toPercent(service.confidence)} confidence`
          : `${toPercent(service.confidence)} confidence`,
        payload: service,
      })),
      ...endpoints.map((endpoint) => ({
        key: `endpoint:${endpoint.url}`,
        type: "endpoint",
        title: endpoint.url,
        summary: `${endpoint.status_code || "unknown"} · ${(endpoint.methods || []).join(", ") || "observed route"}`,
        meta: endpoint.source === "easm-discover"
          ? endpoint.title || `EASM candidate · ${toPercent(endpoint.confidence)} confidence`
          : endpoint.title || `${toPercent(endpoint.confidence)} confidence`,
        payload: endpoint,
      })),
      ...technologies.map((tech) => ({
        key: `tech:${tech.vendor || "unknown"}:${tech.name}:${tech.version || "none"}`,
        type: "technology",
        title: tech.name,
        summary: `${tech.vendor || "Unknown vendor"}${tech.version ? ` · ${tech.version}` : ""}`,
        meta: `${toPercent(tech.confidence)} confidence`,
        payload: tech,
      })),
      ...fingerprints.map((fingerprint) => ({
        key: `fingerprint:${fingerprint.vendor || "unknown"}:${fingerprint.product}:${fingerprint.version || "none"}`,
        type: "product",
        title: fingerprint.product,
        summary: `${fingerprint.vendor || "Unknown vendor"}${fingerprint.version ? ` · ${fingerprint.version}` : ""}`,
        meta: `${toPercent(fingerprint.confidence)} confidence`,
        payload: fingerprint,
      })),
    ];

    return assets;
  }

  function attackPathStatusLabel(status) {
    const mapping = {
      ready: "Ready",
      low_confidence: "Low Confidence",
      empty: "Empty",
    };
    return mapping[String(status || "").toLowerCase()] || "Unknown";
  }

  function renderAttackPathSummaryPanel(summary) {
    if (!state.selectedRun) {
      return "";
    }
    const payload = summary || {};
    const status = String(payload.status || "unknown");
    const counts = payload.summary || {};
    const candidatePaths = Array.isArray(payload.candidate_paths) ? payload.candidate_paths : [];
    const chokePoints = Array.isArray(payload.choke_points) ? payload.choke_points : [];
    const pathCount = Number(counts.candidate_path_count ?? candidatePaths.length) || 0;
    const chokeCount = Number(counts.choke_point_count ?? chokePoints.length) || 0;
    const confirmedEdgeCount = Number(counts.confirmed_edge_count ?? 0) || 0;
    const inferredEdgeCount = Number(counts.inferred_edge_count ?? (Array.isArray(payload.inferred_edges) ? payload.inferred_edges.length : 0)) || 0;
    const lateralNoteCount = Number(counts.lateral_analysis_note_count ?? (Array.isArray(payload.lateral_analysis?.notes) ? payload.lateral_analysis.notes.length : 0)) || 0;
    const nodeCount = Number(counts.node_count ?? (Array.isArray(payload.nodes) ? payload.nodes.length : 0)) || 0;
    const edgeCount = Number(counts.edge_count ?? (Array.isArray(payload.edges) ? payload.edges.length : 0)) || 0;
    const threshold = Number(payload.choke_point_threshold || 3);
    const reason = String(
      counts.reason ||
        "Attack-path summary is not available for this selected run yet."
    );
    const topChokePoints = chokePoints.slice(0, 3);
    const topPaths = candidatePaths.slice(0, 4);

    return `
      <div class="detail-surface emphasis-surface split-top" data-testid="attack-path-summary">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Attack-Path Summary</p>
            <h4>${escapeHtml(pathCount ? `${pathCount} candidate path${pathCount === 1 ? "" : "s"}` : "No candidate paths yet")}</h4>
          </div>
          ${statusPill(attackPathStatusLabel(status))}
        </div>
        <p>${escapeHtml(reason)}</p>
        ${renderBadgeList(
          [
            `${nodeCount} graph nodes`,
            `${edgeCount} graph edges`,
            `${confirmedEdgeCount} confirmed edge${confirmedEdgeCount === 1 ? "" : "s"}`,
            `${inferredEdgeCount} inferred edge${inferredEdgeCount === 1 ? "" : "s"}`,
            `${lateralNoteCount} lateral note${lateralNoteCount === 1 ? "" : "s"}`,
            `${chokeCount} choke point${chokeCount === 1 ? "" : "s"}`,
            `threshold ${threshold} paths`,
          ],
          "compact-badge-list split-top"
        )}
        <div class="compact-definition-grid split-top">
          <div><span>Inventory Source</span><strong>${escapeHtml(payload.sources?.inventory_snapshot_id || "Not linked")}</strong></div>
          <div><span>Findings</span><strong>${escapeHtml(String(payload.sources?.finding_count ?? 0))}</strong></div>
          <div><span>Mean Confidence</span><strong>${escapeHtml(toPercent(counts.mean_path_confidence || 0))}</strong></div>
          <div><span>Model</span><strong>${escapeHtml(payload.evaluation_model || "Not available")}</strong></div>
        </div>
        ${renderAttackPathRelationshipView(payload, candidatePaths, chokePoints, threshold)}
        ${renderInferredAttackPathAnalysis(payload)}
        <div class="split-top">
          <h4>Choke Points</h4>
          <div data-testid="attack-path-choke-points">
            ${
              topChokePoints.length
                ? topChokePoints.map(renderAttackPathChokePointCard).join("")
                : emptyState(`No choke point reached the ${threshold}-path threshold for this run.`)
            }
          </div>
        </div>
        <div class="split-top">
          <h4>Candidate Paths</h4>
          <div data-testid="attack-path-candidate-paths">
            ${
              topPaths.length
                ? topPaths.map(renderAttackPathCandidateCard).join("")
                : emptyState("No candidate paths are available yet for this selected run.")
            }
          </div>
        </div>
      </div>
    `;
  }

  function renderInferredAttackPathAnalysis(payload) {
    const inferredEdges = Array.isArray(payload.inferred_edges) ? payload.inferred_edges : [];
    const lateral = payload.lateral_analysis || {};
    const notes = Array.isArray(lateral.notes) ? lateral.notes : [];
    const boundary = lateral.boundary || {};
    const nodesById = new Map((Array.isArray(payload.nodes) ? payload.nodes : []).map((node) => [String(node.id || ""), node]));
    return `
      <div class="attack-path-inferred-analysis split-top" data-testid="attack-path-inferred-analysis">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Inferred Lateral Analysis</p>
            <h4>${escapeHtml(inferredEdges.length ? `${inferredEdges.length} review-only inferred edge${inferredEdges.length === 1 ? "" : "s"}` : "Confirmed path data only")}</h4>
          </div>
          <span class="metric-pill">${escapeHtml(lateral.status || "confirmed_only")}</span>
        </div>
        <p class="micro-copy">${escapeHtml(
          boundary.message ||
            "Inferred analysis is review-only and does not authorize new scope, pivoting, credential testing, task dispatch, or runtime mutation."
        )}</p>
        ${renderBadgeList(
          [
            boundary.operator_review_required === true ? "Review only" : null,
            boundary.active_pivoting_performed === false ? "No active pivoting" : null,
            boundary.credential_testing_performed === false ? "No credential testing" : null,
            boundary.lateral_movement_performed === false ? "No lateral movement" : null,
            boundary.scope_expansion_performed === false ? "No scope expansion" : null,
            boundary.automatic_dispatch_performed === false ? "No auto dispatch" : null,
          ],
          "compact-badge-list split-top"
        )}
        ${
          inferredEdges.length
            ? `
              <div class="attack-path-inferred-list split-top">
                ${inferredEdges.slice(0, 6).map((edge) => renderInferredAttackPathEdge(edge, nodesById)).join("")}
              </div>
            `
            : emptyState("No inferred lateral context is available beyond the confirmed deterministic attack-path data.")
        }
        ${
          notes.length
            ? `
              <div class="compact-definition-grid split-top" data-testid="attack-path-lateral-notes">
                ${notes
                  .slice(0, 4)
                  .map(
                    (note) => `
                      <div data-testid="attack-path-lateral-note">
                        <span>${escapeHtml(note.title || "Review note")}</span>
                        <strong>${escapeHtml(note.description || "Review-only lateral context.")}</strong>
                      </div>
                    `
                  )
                  .join("")}
              </div>
            `
            : ""
        }
      </div>
    `;
  }

  function renderInferredAttackPathEdge(edge, nodesById) {
    const source = nodesById.get(String(edge.source || "")) || {};
    const target = nodesById.get(String(edge.target || "")) || {};
    const evidenceRefs = Array.isArray(edge.evidence_refs) ? edge.evidence_refs.filter(Boolean) : [];
    return `
      <div class="list-card inferred-edge-card" data-testid="attack-path-inferred-edge">
        <div class="task-activity-header">
          <h4>${escapeHtml(edge.type || "inferred relationship")}</h4>
          <span class="metric-pill">${escapeHtml(`Inferred · ${toPercent(edge.confidence || 0)}`)}</span>
        </div>
        <p>${escapeHtml(edge.rationale || "Stored evidence supports this review-only inferred relationship.")}</p>
        <div class="attack-path-chain-line" aria-label="Inferred relationship">
          <span class="attack-path-segment inferred type-${escapeHtml(normalizeAttackPathNodeType(source.type || "node"))}">
            <strong>${escapeHtml(source.label || edge.source || "source")}</strong>
            <small>${escapeHtml(attackPathNodeTypeLabel(normalizeAttackPathNodeType(source.type || "node")))}</small>
          </span>
          <span class="attack-path-chain-arrow">&rarr;</span>
          <span class="attack-path-segment inferred type-${escapeHtml(normalizeAttackPathNodeType(target.type || "node"))}">
            <strong>${escapeHtml(target.label || edge.target || "target")}</strong>
            <small>${escapeHtml(attackPathNodeTypeLabel(normalizeAttackPathNodeType(target.type || "node")))}</small>
          </span>
        </div>
        <div class="compact-definition-grid split-top">
          <div><span>Classification</span><strong>${escapeHtml(edge.classification || "inferred")}</strong></div>
          <div><span>Evidence Refs</span><strong>${escapeHtml(evidenceRefs.join(", ") || "Not exposed by API")}</strong></div>
          <div><span>Operator Review</span><strong>${escapeHtml(edge.operator_review_required ? "Required" : "Not recorded")}</strong></div>
          <div><span>Runtime Effect</span><strong>${escapeHtml(edge.automatic_dispatch_performed === false ? "No automatic dispatch" : "Not recorded")}</strong></div>
        </div>
      </div>
    `;
  }

  function renderAttackPathRelationshipView(payload, candidatePaths, chokePoints, threshold) {
    const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
    const edges = Array.isArray(payload.edges) ? payload.edges : [];
    const confirmedEdges = edges.filter((edge) => String(edge.classification || "confirmed") !== "inferred");
    const visiblePaths = candidatePaths.slice(0, 6);

    return `
      <div class="attack-path-relationship-view split-top" data-testid="attack-path-relationship-view">
        <div class="task-activity-header">
          <div>
            <p class="eyebrow">Relationship View</p>
            <h4>${escapeHtml(visiblePaths.length ? `${visiblePaths.length} evidence-backed path chain${visiblePaths.length === 1 ? "" : "s"}` : "No relationship chain yet")}</h4>
          </div>
          <span class="metric-pill">${escapeHtml(`${nodes.length} API node${nodes.length === 1 ? "" : "s"} · ${confirmedEdges.length} confirmed edge${confirmedEdges.length === 1 ? "" : "s"}`)}</span>
        </div>
        <p class="micro-copy">${escapeHtml(
          "This dependency-free view traces confirmed attack-path API labels, node ids, confidence, evidence refs, and choke-point summaries. Inferred context stays in the review-only panel below and does not add path inference or scoring."
        )}</p>
        ${
          visiblePaths.length
            ? `
              <div class="attack-path-chain-list">
                ${visiblePaths
                  .map((path) => renderAttackPathRelationshipRow(path, payload, chokePoints, threshold))
                  .join("")}
              </div>
            `
            : emptyState("No visual relationship chain is available because the attack-path API returned zero candidate paths.")
        }
      </div>
    `;
  }

  function renderAttackPathRelationshipRow(path, payload, chokePoints, threshold) {
    const segments = attackPathRelationshipSegments(path, payload, chokePoints);
    const evidenceRefs = Array.isArray(path.evidence_refs) ? path.evidence_refs.filter(Boolean) : [];
    const nodeIds = Array.isArray(path.node_ids) ? path.node_ids.filter(Boolean) : [];
    const confidence = Number(path.confidence || 0);
    const isLowConfidence = nodeIds.length <= 1 || confidence < 0.5;

    return `
      <div class="attack-path-chain-card ${isLowConfidence ? "low-confidence" : ""}" data-testid="attack-path-relationship-row">
        <div class="task-activity-header">
          <div>
            <h5>${escapeHtml(path.finding_title || "Candidate path")}</h5>
            <p class="micro-copy">${escapeHtml(path.explanation || "Evidence-backed relationship from existing API output.")}</p>
          </div>
          <span class="metric-pill">${escapeHtml(`${path.severity || "unknown"} · ${toPercent(confidence)}`)}</span>
        </div>
        <div class="attack-path-chain-line" aria-label="Candidate path relationship chain">
          ${segments
            .map(
              (segment, index) => `
                ${index ? '<span class="attack-path-chain-arrow">&rarr;</span>' : ""}
                <span class="attack-path-segment type-${escapeHtml(segment.type)} ${segment.isChoke ? "choke" : ""}">
                  <strong>${escapeHtml(segment.label)}</strong>
                  <small>${escapeHtml(segment.isChoke ? `${attackPathNodeTypeLabel(segment.type)} · choke point` : attackPathNodeTypeLabel(segment.type))}</small>
                </span>
              `
            )
            .join("")}
        </div>
        <div class="compact-definition-grid split-top">
          <div><span>Target</span><strong>${escapeHtml(path.target_id || "Not recorded")}</strong></div>
          <div><span>Confidence</span><strong>${escapeHtml(toPercent(confidence))}</strong></div>
          <div><span>Evidence Refs</span><strong>${escapeHtml(evidenceRefs.length ? evidenceRefs.join(", ") : "Not exposed by API")}</strong></div>
          <div><span>API Node Trace</span><strong>${escapeHtml(nodeIds.length ? nodeIds.join(" > ") : "Label-only candidate path")}</strong></div>
        </div>
        ${
          isLowConfidence
            ? `<p class="micro-copy split-top">${escapeHtml("Low-confidence paths stay visible, but the view does not claim more certainty than the source API provides.")}</p>`
            : ""
        }
      </div>
    `;
  }

  function attackPathRelationshipSegments(path, payload, chokePoints) {
    const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
    const nodesById = new Map(nodes.map((node) => [String(node.id || ""), node]));
    const chokeKeys = new Set(
      (chokePoints || []).flatMap((chokePoint) => [
        String(chokePoint.node_id || "").toLowerCase(),
        String(chokePoint.label || "").toLowerCase(),
      ])
    );
    const nodeIds = Array.isArray(path.node_ids) ? path.node_ids.filter(Boolean) : [];
    if (nodeIds.length) {
      return nodeIds.map((nodeId) => {
        const node = nodesById.get(String(nodeId)) || {};
        const label = node.label || nodeId;
        const type = normalizeAttackPathNodeType(node.type || "node");
        return {
          label,
          type,
          isChoke: chokeKeys.has(String(nodeId).toLowerCase()) || chokeKeys.has(String(label).toLowerCase()),
        };
      });
    }

    const labels = Array.isArray(path.labels) ? path.labels.filter(Boolean) : [];
    if (labels.length) {
      return labels.map((label, index) => ({
        label,
        type: index === labels.length - 1 ? "finding" : "api-label",
        isChoke: chokeKeys.has(String(label).toLowerCase()),
      }));
    }

    return [
      {
        label: path.finding_title || "Candidate path",
        type: "finding",
        isChoke: false,
      },
    ];
  }

  function normalizeAttackPathNodeType(type) {
    const normalized = String(type || "node").toLowerCase().replace(/_/g, "-").replace(/[^a-z0-9-]+/g, "-");
    return [
      "host",
      "service",
      "endpoint",
      "finding",
      "node",
      "identity-subject",
      "identity-group",
      "cloud-resource",
      "cloud-security-group",
      "cloud-iam-principal",
      "cloud-iam-policy",
      "kubernetes-cluster",
      "kubernetes-workload",
    ].includes(normalized)
      ? normalized
      : "api-label";
  }

  function attackPathNodeTypeLabel(type) {
    const labels = {
      host: "Host",
      service: "Service",
      endpoint: "Endpoint",
      finding: "Finding",
      node: "API node",
      "identity-subject": "Identity subject",
      "identity-group": "Identity group",
      "cloud-resource": "Cloud resource",
      "cloud-security-group": "Cloud security group",
      "cloud-iam-principal": "Cloud IAM principal",
      "cloud-iam-policy": "Cloud IAM policy",
      "kubernetes-cluster": "Kubernetes cluster",
      "kubernetes-workload": "Kubernetes workload",
      "api-label": "API label",
    };
    return labels[type] || "API label";
  }

  function renderAttackPathChokePointCard(chokePoint) {
    return `
      <div class="list-card" data-testid="attack-path-choke-card">
        <div class="task-activity-header">
          <h4>${escapeHtml(chokePoint.label || "Unnamed node")}</h4>
          <span class="metric-pill">${escapeHtml(chokePoint.type || "node")}</span>
        </div>
        <p>${escapeHtml(chokePoint.summary || "This node appears across multiple candidate paths.")}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Paths</span><strong>${escapeHtml(String(chokePoint.path_count || 0))}</strong></div>
          <div><span>Findings</span><strong>${escapeHtml(String(chokePoint.finding_count || 0))}</strong></div>
          <div><span>Severity Mix</span><strong>${escapeHtml(formatSeverityBreakdown(chokePoint.severity_breakdown))}</strong></div>
        </div>
      </div>
    `;
  }

  function renderAttackPathCandidateCard(path) {
    const labels = Array.isArray(path.labels) ? path.labels.filter(Boolean) : [];
    return `
      <div class="list-card" data-testid="attack-path-candidate-card">
        <div class="task-activity-header">
          <h4>${escapeHtml(path.finding_title || "Candidate path")}</h4>
          <span class="metric-pill">${escapeHtml(path.severity || "unknown")}</span>
        </div>
        <p>${escapeHtml(path.explanation || labels.join(" > ") || "Evidence-backed path candidate.")}</p>
        <p class="micro-copy">${escapeHtml(labels.join(" > ") || path.target_id || "No path labels available")}</p>
      </div>
    `;
  }

  function formatSeverityBreakdown(breakdown) {
    if (!breakdown || typeof breakdown !== "object") {
      return "not recorded";
    }
    const entries = Object.entries(breakdown)
      .filter(([, count]) => Number(count) > 0)
      .map(([severity, count]) => `${severity}: ${count}`);
    return entries.length ? entries.join(", ") : "not recorded";
  }

  function renderSurfaceMap() {
    const selectedRun = resolvedSelectedRun();
    const snapshot = runtime.actions.selectedRunInventorySnapshot?.();
    const attackPathSummary = runtime.actions.selectedRunAttackPathSummary?.() || null;
    const supportedSurfaceViews = ["hotspots", "packZones"];
    const requestedSurfaceView = Object.prototype.hasOwnProperty.call(state, "surfaceView")
      ? String(state.surfaceView || "hotspots")
      : "hotspots";
    const activeSurfaceView = supportedSurfaceViews.includes(requestedSurfaceView)
      ? requestedSurfaceView
      : "hotspots";
    if (requestedSurfaceView !== activeSurfaceView) {
      patchState(
        {
          surfaceView: activeSurfaceView,
          surfaceOverlays: {
            ...state.surfaceOverlays,
            hotspots: activeSurfaceView === "hotspots",
            packZones: activeSurfaceView === "packZones",
            futureAttackPaths: false,
            futureIdentityGraph: false,
            futureRiskOverlay: false,
          },
        },
        "mission.surface.normalizeView"
      );
    }
    dom.surfaceToggleBar.innerHTML = supportedSurfaceViews
      .map(
        (key) => `
          <button class="action ${key === activeSurfaceView ? "secondary" : "ghost"} surface-toggle" data-surface-view="${key}" type="button" data-testid="surface-view-${escapeHtml(key)}">
            ${escapeHtml(surfaceOverlayLabel(key))}
          </button>
        `
      )
      .join("");
    dom.surfaceToggleBar.querySelectorAll(".surface-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const overlayKey = button.dataset.surfaceView;
        patchState(
          {
            surfaceView: overlayKey || "hotspots",
            surfaceOverlays: {
              ...state.surfaceOverlays,
              hotspots: overlayKey === "hotspots",
              packZones: overlayKey === "packZones",
              futureAttackPaths: false,
              futureIdentityGraph: false,
              futureRiskOverlay: false,
            },
          },
          "mission.surface.toggleOverlay"
        );
        renderSurfaceMap();
      });
    });

    if (!snapshot) {
      const emptyAction = selectedRun
        ? { label: "Open Mission Control", screen: "mission-control" }
        : { label: "Start a mission", screen: "wizard" };
      dom.surfaceMapCanvas.innerHTML = renderSurfaceMapCanvasEmptyState({
        message: selectedRun
          ? "No inventory snapshot is available for this run yet."
          : "No inventory snapshot is available yet.",
        detail: selectedRun
          ? "Run a Passive Network Discovery scan to map your assets here."
          : "Create a mission and run Passive Network Discovery to map your assets here.",
        actionLabel: canDispatchSelectedRun() ? "Start a discovery scan →" : selectedRun ? "Open Mission Control" : "Start a mission",
        actionScreen: canDispatchSelectedRun() ? null : selectedRun ? "mission-control" : "wizard",
        dispatchSelected: canDispatchSelectedRun(),
      });
      dom.surfaceAssetBrowser.innerHTML = emptyState("No mapped assets are available yet.", emptyAction);
      dom.surfaceAssetDetail.innerHTML = emptyState("No asset is selected yet.", emptyAction);
      dom.surfaceInsights.innerHTML =
        renderAttackPathSummaryPanel(attackPathSummary) ||
        emptyState(
          "No surface insights are available yet.",
          selectedRun
            ? { label: "Open Mission Control", screen: "mission-control" }
            : { label: "Start a mission", screen: "wizard" }
        );
      dom.surfaceLegend.innerHTML = emptyState("No legend data is available yet.", emptyAction);
      return;
    }

    const inventory = snapshot.normalized_inventory_json || {};
    const hosts = Array.isArray(inventory.hosts) ? inventory.hosts : [];
    const services = Array.isArray(inventory.services) ? inventory.services : [];
    const endpoints = Array.isArray(inventory.http_endpoints) ? inventory.http_endpoints : [];
    const technologies = Array.isArray(inventory.technologies) ? inventory.technologies : [];
    const fingerprints = Array.isArray(inventory.vendor_product_fingerprints)
      ? inventory.vendor_product_fingerprints
      : [];
    const surfaceAssets = buildSurfaceAssets(snapshot);
    const assetTypes = ["all", "host", "service", "endpoint", "technology", "product"];
    const activeFilter = assetTypes.includes(state.surfaceAssetFilter) ? state.surfaceAssetFilter : "all";
    const rawQuery = String(state.surfaceAssetQuery || "").trim();
    const normalizedQuery = rawQuery.toLowerCase();
    const filteredAssets = surfaceAssets.filter((asset) => {
      const matchesType = activeFilter === "all" || asset.type === activeFilter;
      if (!matchesType) return false;
      if (!normalizedQuery) return true;
      return surfaceAssetSearchText(asset).includes(normalizedQuery);
    });
    const selectedAsset =
      filteredAssets.find((asset) => asset.key === state.selectedSurfaceAssetKey) ||
      filteredAssets[0] ||
      null;
    const selectedIndex = selectedAsset
      ? filteredAssets.findIndex((asset) => asset.key === selectedAsset.key) + 1
      : 0;
    const assetTypeBreakdown = summarizeSurfaceAssetTypes(surfaceAssets);
    const mapHosts = deriveSurfaceMapHosts(hosts, services);
    const hasRenderableSurfaceData =
      mapHosts.length > 0 ||
      services.length > 0 ||
      endpoints.length > 0 ||
      technologies.length > 0 ||
      fingerprints.length > 0;

    patchSurfaceBrowserState(
      {
        selectedSurfaceAssetKey: selectedAsset?.key || null,
        surfaceAssetFilter: activeFilter,
        surfaceAssetQuery: rawQuery,
      },
      "mission.surface.normalizeBrowser"
    );

    if (!hasRenderableSurfaceData) {
      dom.surfaceMapCanvas.innerHTML = renderSurfaceMapCanvasEmptyState({
        message: "No host or service inventory is available for this run yet.",
        detail: canDispatchSelectedRun()
          ? "Run a Passive Network Discovery scan to map your assets here."
          : "Surface Map needs a completed discovery snapshot with hosts, services, endpoints, technologies, or product fingerprints.",
        actionLabel: canDispatchSelectedRun() ? "Start a discovery scan →" : "Open Mission Control",
        actionScreen: canDispatchSelectedRun() ? null : "mission-control",
        dispatchSelected: canDispatchSelectedRun(),
      });
      dom.surfaceAssetBrowser.innerHTML = emptyState(
        "No asset records are available yet.",
        canDispatchSelectedRun()
          ? { label: "Open Mission Control", screen: "mission-control" }
          : { label: "Open Mission Control", screen: "mission-control" }
      );
      dom.surfaceAssetDetail.innerHTML = emptyState(
        "Select a mapped asset once discovery has created inventory.",
        { label: "Open Mission Control", screen: "mission-control" }
      );
      dom.surfaceInsights.innerHTML = `
        <div class="detail-surface compact-surface">
          <h4>Surface state</h4>
          <p>There is no normalized inventory to visualize yet. Dispatch a discovery run first, then return here for the live surface view.</p>
        </div>
        ${renderInventoryFollowUpPanel("surface")}
      `;
      dom.surfaceLegend.innerHTML = `
        <div class="pill-grid">
          <span class="legend-chip">Surface map idle</span>
          <span class="legend-chip">No inventory yet</span>
          <span class="legend-chip">Current View ${surfaceOverlayLabel(activeSurfaceView)}</span>
        </div>
      `;
      return;
    }

    const mapNodes = buildSurfaceMapNodes({
      hosts: mapHosts,
      endpoints,
      technologies,
      fingerprints,
      selectedAssetKey: selectedAsset?.key || null,
      hotspotTargets: new Set((runtime.actions.selectedRunFindings?.() || []).map((finding) => finding.target_id)),
    });
    const svgLines = buildSurfaceLines(mapNodes);

    dom.surfaceMapCanvas.innerHTML = `
      <svg viewBox="0 0 100 100" preserveAspectRatio="none">${svgLines.join("")}</svg>
      <div class="map-column hosts"><p class="map-column-label">Hosts</p></div>
      <div class="map-column endpoints"><p class="map-column-label">Apps / APIs</p></div>
      <div class="map-column tech"><p class="map-column-label">Stacks / Pack Zones</p></div>
      ${mapNodes
        .map((node) => {
          const hotspot = activeSurfaceView === "hotspots" && node.hotspot;
          const packZone = activeSurfaceView === "packZones" && node.kind === "tech" && Boolean(runtime.actions.selectedPack?.());
          return `
            <button
              class="map-node ${hotspot ? "hotspot" : ""} ${packZone ? "pack-zone" : ""} ${node.key === selectedAsset?.key ? "active" : ""}"
              type="button"
              style="left:${node.left}%; top:${node.top}%"
              data-surface-asset-key="${escapeHtml(node.key)}"
            >
              <strong>${escapeHtml(node.title)}</strong>
              <div class="node-meta">${escapeHtml(node.meta)}</div>
            </button>
          `;
        })
        .join("")}
    `;
    dom.surfaceMapCanvas.querySelectorAll("[data-surface-asset-key]").forEach((button) => {
      button.addEventListener("click", () => {
        patchSurfaceBrowserState(
          { selectedSurfaceAssetKey: button.dataset.surfaceAssetKey || null },
          "mission.surface.selectMapAsset"
        );
        renderSurfaceMap();
      });
    });
    dom.surfaceMapCanvas.querySelector("[data-surface-view-reset]")?.addEventListener("click", () => {
      patchState(
        {
          surfaceView: "hotspots",
          surfaceOverlays: {
            ...state.surfaceOverlays,
            hotspots: true,
            packZones: false,
            futureAttackPaths: false,
            futureIdentityGraph: false,
            futureRiskOverlay: false,
          },
        },
        "mission.surface.resetView"
      );
      renderSurfaceMap();
    });

    dom.surfaceAssetBrowser.innerHTML = `
      <div class="surface-browser-toolbar">
        <label class="field compact surface-browser-search">
          <span>Find asset</span>
          <input
            id="surface-asset-search"
            type="search"
            value="${escapeHtml(rawQuery)}"
            placeholder="Search by host, port, URL, technology, vendor, or product"
            data-testid="surface-asset-search"
          />
        </label>
        <div class="surface-browser-filter-row">
          ${assetTypes
            .map(
              (type) => `
                <button
                  class="action ${type === activeFilter ? "secondary" : "ghost"}"
                  type="button"
                  data-surface-filter="${escapeHtml(type)}"
                >
                  ${escapeHtml(surfaceAssetFilterLabel(type, assetTypeBreakdown, surfaceAssets.length))}
                </button>
              `
            )
            .join("")}
          ${
            rawQuery
              ? '<button class="action ghost" type="button" data-surface-clear-search="true">Clear Search</button>'
              : ""
          }
        </div>
      </div>
      <div class="surface-browser-summary" data-testid="surface-browser-summary">
        <p>${escapeHtml(`${surfaceAssets.length} total asset records · showing ${filteredAssets.length} ${surfaceAssetTypeLabel(activeFilter).toLowerCase()}${rawQuery ? ` for "${rawQuery}"` : ""}`)}</p>
        <p class="micro-copy">${escapeHtml(selectedAsset ? `Selected ${selectedIndex} of ${filteredAssets.length} visible assets.` : "Use the browser for the full estate. The map stays intentionally high-level so large inventories remain readable.")}</p>
        ${renderBadgeList(
          [
            `${assetTypeBreakdown.host} hosts`,
            `${assetTypeBreakdown.service} services`,
            `${assetTypeBreakdown.endpoint} endpoints`,
            `${assetTypeBreakdown.technology} technologies`,
            `${assetTypeBreakdown.product} products`,
          ],
          "compact-badge-list split-top"
        )}
      </div>
      <div class="surface-asset-list">
        ${filteredAssets.length
          ? filteredAssets
              .map((asset) => renderSurfaceAssetCard(asset, selectedAsset))
              .join("")
          : emptyState(
              rawQuery
                ? `No asset records match "${rawQuery}" inside the current browser filter.`
                : "No asset records match the selected browser filter."
            )}
      </div>
    `;
    document.getElementById("surface-asset-search")?.addEventListener("input", (event) => {
      patchSurfaceBrowserState(
        { surfaceAssetQuery: event.target.value || "" },
        "mission.surface.searchAssets"
      );
      renderSurfaceMap();
    });
    dom.surfaceAssetBrowser.querySelectorAll("[data-surface-filter]").forEach((button) => {
      button.addEventListener("click", () => {
        patchSurfaceBrowserState(
          { surfaceAssetFilter: button.dataset.surfaceFilter || "all" },
          "mission.surface.filterAssets"
        );
        renderSurfaceMap();
      });
    });
    dom.surfaceAssetBrowser.querySelector("[data-surface-clear-search]")?.addEventListener("click", () => {
      patchSurfaceBrowserState({ surfaceAssetQuery: "" }, "mission.surface.clearSearch");
      renderSurfaceMap();
    });
    dom.surfaceAssetBrowser.querySelectorAll("[data-surface-asset-key]").forEach((button) => {
      button.addEventListener("click", () => {
        patchSurfaceBrowserState(
          { selectedSurfaceAssetKey: button.dataset.surfaceAssetKey || null },
          "mission.surface.selectBrowserAsset"
        );
        renderSurfaceMap();
      });
    });

    dom.surfaceAssetDetail.innerHTML = selectedAsset
      ? renderSurfaceAssetDetail(selectedAsset, state.mission.scope)
      : emptyState(
          rawQuery
            ? `No asset records match "${rawQuery}". Clear or widen the search to inspect a mapped record.`
            : "Select an asset in the browser or map to inspect the normalized inventory record."
        );
    dom.surfaceAssetDetail.querySelector("[data-surface-add-scope]")?.addEventListener("click", async () => {
      try {
        await addSurfaceAssetToScope(selectedAsset);
      } catch (error) {
        runtime.actions.pushStatus?.(error?.message || "Unable to add the selected asset to scope.", "error");
      }
    });

    const previousSnapshot = state.mission.inventory[1] || null;
    dom.surfaceInsights.innerHTML = `
      <div class="detail-surface compact-surface">
        <h4>${escapeHtml(surfaceOverlayLabel(activeSurfaceView))}</h4>
        <p>${escapeHtml(surfaceViewInsight(activeSurfaceView, attackPathSummary))}</p>
      </div>
      ${renderStringCards(
        [
          `${mapHosts.length} hosts or network objects are visible in the current surface model.`,
          `${endpoints.length} HTTP or API endpoints are mapped for the selected engagement.`,
          `${technologies.length || fingerprints.length} stack indicators are available for adaptive relevance decisions.`,
          isSeedOnlyInventory(snapshot) ? "The current surface model is wizard-seeded input, not discovery-confirmed telemetry yet." : "This surface model reflects discovery-confirmed inventory inputs.",
          previousSnapshot ? `${Math.max(0, (snapshot.summary_json.host_count || 0) - (previousSnapshot.summary_json.host_count || 0))} new host-level items were discovered since the previous snapshot.` : "No prior inventory snapshot exists for delta analysis yet.",
        ],
        "Insights appear after inventory normalization runs."
      )}
      ${attackPathSummary ? renderAttackPathSummaryPanel(attackPathSummary) : ""}
      ${renderInventoryFollowUpPanel("surface")}
    `;
    dom.surfaceLegend.innerHTML = `
      <div class="pill-grid">
        <span class="legend-chip">Hosts</span>
        <span class="legend-chip">Apps / APIs</span>
        <span class="legend-chip">Stacks / Products</span>
        <span class="legend-chip">Current View ${surfaceOverlayLabel(activeSurfaceView)}</span>
        <span class="legend-chip">Hotspots ${state.surfaceOverlays.hotspots ? "Active" : "Hidden"}</span>
        <span class="legend-chip">Pack Zones ${state.surfaceOverlays.packZones ? "Active" : "Hidden"}</span>
        ${attackPathSummary ? '<span class="legend-chip">Attack-path summary available below</span>' : ""}
      </div>
    `;
  }

  async function launchInventoryFollowUp(strategy) {
    const run = state.selectedRun;
    const snapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const engagementId = state.selectedEngagementId;
    const plan = buildInventoryFollowUpPlans().find((candidate) => candidate.id === strategy) || null;
    if (!run || !snapshot || !engagementId || !plan) {
      throw new Error("No compatible inventory follow-up plan is available for this run.");
    }

    runtime.actions.pushStatus?.(`Preparing ${plan.label.toLowerCase()} from the current inventory snapshot.`, "info");
    const createdRun = await api(`/api/v1/engagements/${engagementId}/runs`, {
      method: "POST",
      body: {
        profile_name: plan.profileName,
        source_inventory_snapshot_id: snapshot.id,
        configuration_json: plan.configurationJson,
      },
    });

    patchState({ selectedRunId: createdRun.id }, "mission.followUp.createdRun");
    const queuedTaskCount = (createdRun.tasks || []).filter((task) => task.status === "queued").length;
    if (queuedTaskCount) {
      const dispatchResponse = await api(`/api/v1/runs/${createdRun.id}/dispatch`, {
        method: "POST",
      });
      runtime.actions.pushStatus?.(
        `${plan.actionLabel} started in ${dispatchResponse.dispatch_mode} mode against ${plan.targetCount} target${plan.targetCount === 1 ? "" : "s"}.`,
        "success"
      );
    } else {
      runtime.actions.pushStatus?.(
        `${plan.label} was created, but no queued tasks were generated from the selected inventory.`,
        "error"
      );
    }

    await runtime.actions.refreshSelectedEngagement?.();
    patchState({ activeScreen: "mission-control" }, "mission.followUp.openMissionControl");
    runtime.actions.renderAll?.();
  }

  async function addSurfaceAssetToScope(asset) {
    const candidate = deriveScopeCandidateForAsset(asset);
    if (!candidate) {
      throw new Error("The selected asset does not have a direct scope target.");
    }
    if (!state.selectedEngagementId) {
      throw new Error("Select an engagement before updating scope.");
    }

    const currentScope = state.mission.scope || { allowlist_json: {}, denylist_json: {} };
    if (scopeAllowlistContainsExact(currentScope, candidate)) {
      runtime.actions.pushStatus?.(`${candidate.value} is already explicitly in the approved scope.`, "info");
      return;
    }

    await api(`/api/v1/engagements/${state.selectedEngagementId}/scope`, {
      method: "POST",
      body: {
        allowlist_json: mergeScopeAllowlistCandidate(currentScope.allowlist_json || {}, candidate),
        denylist_json: currentScope.denylist_json || {},
      },
    });
    runtime.actions.pushStatus?.(
      `${candidate.value} was added to the approved scope as a ${candidate.label.toLowerCase()}.`,
      "success"
    );
    await runtime.actions.refreshSelectedEngagement?.();
  }

  return {
    canDispatchSelectedRun,
    dispatchSelectedRun,
    focusActorInputForApproval,
    launchInventoryFollowUp,
    recordRunApprovalDecision,
    renderMissionControl,
    renderSurfaceMap,
    buildMissionPhases,
  };
}

function renderSurfaceAssetCard(asset, selectedAsset) {
  const selectedClass = asset.key === selectedAsset?.key ? "selected" : "";
  if (asset.type === "host") {
    const services = asset.payload.services || [];
    const endpoints = asset.payload.endpoints || [];
    return `
      <button
        class="list-card ${selectedClass} surface-host-card"
        type="button"
        data-surface-asset-key="${escapeHtml(asset.key)}"
        data-surface-kind="host"
        data-testid="surface-asset-card"
      >
        <div class="task-activity-header">
          <h4>${escapeHtml(asset.title)}</h4>
          <span class="metric-pill">Host Card</span>
        </div>
        <p>${escapeHtml(asset.summary || "Host inventory record")}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Source</span><strong>${escapeHtml(asset.payload.source || "unknown")}</strong></div>
          <div><span>Services</span><strong>${escapeHtml(String(services.length))}</strong></div>
          <div><span>Endpoints</span><strong>${escapeHtml(String(endpoints.length))}</strong></div>
          <div><span>Confidence</span><strong>${escapeHtml(asset.meta)}</strong></div>
        </div>
      </button>
    `;
  }
  return `
    <button
      class="list-card ${selectedClass}"
      type="button"
      data-surface-asset-key="${escapeHtml(asset.key)}"
      data-surface-kind="${escapeHtml(asset.type)}"
      data-testid="surface-asset-card"
    >
      <div class="task-activity-header">
        <h4>${escapeHtml(asset.title)}</h4>
        <span class="metric-pill">${escapeHtml(surfaceAssetTypeLabel(asset.type))}</span>
      </div>
      <p>${escapeHtml(asset.summary || "No further detail recorded")}</p>
      <p class="micro-copy split-top">${escapeHtml(asset.meta)}</p>
    </button>
  `;
}

function manualDispatchHintForSelectedRun() {
  const runId = state.selectedRunId ? String(state.selectedRunId) : "";
  if (!runId) return null;
  return state.dispatchHintsByRunId[runId] || null;
}

function resolvedSelectedRun() {
  if (state.selectedRun) return state.selectedRun;
  const selectedRunId = String(state.selectedRunId || "");
  const runs = Array.isArray(state.mission.runs) ? state.mission.runs : [];
  if (selectedRunId) {
    return runs.find((run) => String(run.id || "") === selectedRunId) || null;
  }
  return runs[0] || null;
}

function canDispatchSelectedRun() {
  const run = resolvedSelectedRun();
  if (!run) return false;
  const runStatus = String(run.status || "").toLowerCase();
  if (["cancelled", "cancelling", "rejected", "completed", "completed_with_errors", "failed"].includes(runStatus)) {
    return false;
  }
  if (!["queued", "requested"].includes(runStatus)) {
    return false;
  }
  const manualHint = manualDispatchHintForSelectedRun();
  if (manualHint?.dispatch_mode === "manual" && runStatus === "queued") {
    return false;
  }
  return (run.tasks || []).some((task) => String(task.status || "").toLowerCase() === "queued");
}

function renderActivityAction(action, buttonClass) {
  if (!action) return "";
  if (action.action === "dispatch-run") {
    const dispatching = String(state.loading.dispatchRunId || "") === String(state.selectedRun?.id || "");
    const launchPulse = String(state.missionLaunch?.runId || "") === String(state.selectedRun?.id || "")
      ? "launch-cta-pulse"
      : "";
    return `<button class="action ${buttonClass} ${launchPulse}" type="button" data-run-dispatch="selected" ${dispatching ? "disabled" : ""}>${escapeHtml(dispatching ? "Dispatching..." : action.label)}</button>`;
  }
  return `<button class="action ${buttonClass}" type="button" data-nav-screen="${escapeHtml(action.screen)}">${escapeHtml(action.label)}</button>`;
}

async function dispatchSelectedRun() {
  if (!state.selectedRunId) {
    throw new Error("Select a run before starting validation.");
  }

  const run = resolvedSelectedRun();
  const discoveryOnly = isDiscoveryOnlyRun(run);
  patchState(
    {
      loading: {
        ...state.loading,
        dispatchRunId: state.selectedRunId,
      },
    },
    "mission.dispatch.start"
  );
  runtime.actions.pushStatus?.(
    discoveryOnly
      ? "Starting LAN discovery. Asset results appear after the controlled nmap sweep returns."
      : "Dispatching queued validation tasks.",
    "info"
  );
  runtime.actions.renderAll?.();

  try {
    const response = await api(`/api/v1/runs/${state.selectedRunId}/dispatch`, {
      method: "POST",
    });
    await runtime.actions.refreshSelectedEngagement?.();

    if (response.dispatch_mode === "manual") {
      patchState(
        {
          dispatchHintsByRunId: {
            ...state.dispatchHintsByRunId,
            [String(state.selectedRunId)]: {
              dispatch_mode: "manual",
              message: "This host accepted the dispatch request in manual mode, but no inline runner or background worker is attached to start the queued checks.",
            },
          },
        },
        "mission.dispatch.manualHint"
      );
      runtime.actions.pushStatus?.(
        "Dispatch reached the API in manual mode, but this host has no active worker. Start a worker or switch the host service to TASK_DISPATCH_MODE=inline.",
        "error"
      );
      runtime.actions.renderAll?.();
      return;
    }

    const { [String(state.selectedRunId)]: _removedHint, ...dispatchHintsByRunId } = state.dispatchHintsByRunId;
    patchState({ dispatchHintsByRunId }, "mission.dispatch.clearHint");

    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventoryReady = discoveryOnly && inventorySnapshot && !isSeedOnlyInventory(inventorySnapshot);
    if (inventoryReady) {
      const hostCount = Number(inventorySnapshot.summary_json?.host_count || 0);
      runtime.actions.pushStatus?.(
        `Discovery completed in ${response.dispatch_mode} mode. ${hostCount} host${hostCount === 1 ? "" : "s"} were mapped and Surface Map is ready.`,
        "success"
      );
      patchState({ activeScreen: "surface-map" }, "mission.dispatch.openSurfaceMap");
      runtime.actions.renderAll?.();
      return;
    }

    runtime.actions.pushStatus?.(
      `Validation started in ${response.dispatch_mode} mode for ${response.dispatched_task_ids.length} queued task${response.dispatched_task_ids.length === 1 ? "" : "s"}.`,
      "success"
    );
  } finally {
    patchState(
      {
        loading: {
          ...state.loading,
          dispatchRunId: null,
        },
      },
      "mission.dispatch.finish"
    );
    runtime.actions.renderAll?.();
  }
}

function surfaceOverlayLabel(key) {
  const mapping = {
    hotspots: "Hotspots",
    packZones: "Pack Impact Zones",
    futureAttackPaths: "Attack Paths",
    futureIdentityGraph: "Identity Graph",
    futureRiskOverlay: "Risk Overlay",
  };
  return mapping[key] || key;
}

function surfaceViewInsight(key, attackPathSummary = null) {
  const mapping = {
    hotspots: "Highlighting hosts and endpoints that already have linked finding pressure in the selected run.",
    packZones: "Highlighting technologies and products that overlap with adaptive pack or relevance context.",
  };
  if (attackPathSummary) {
    return `${mapping[key] || "Surface context is available for the selected run."} Attack-path summary stays available below the surface map when recorded.`;
  }
  return mapping[key] || "Surface context is available for the selected run.";
}

function renderSurfaceMapCanvasEmptyState({ message, detail, actionLabel, actionScreen, dispatchSelected = false }) {
  return `
    <div class="surface-map-empty-state detail-surface" data-testid="surface-map-empty-state">
      <div class="surface-map-empty-icon" aria-hidden="true">◎</div>
      <h4>${escapeHtml(message)}</h4>
      <p>${escapeHtml(detail)}</p>
      <div class="panel-actions split-top">
        ${
          dispatchSelected
            ? `<button class="action primary" type="button" data-run-dispatch="selected" data-testid="surface-map-empty-action">${escapeHtml(actionLabel || "Start a discovery scan →")}</button>`
            : `<button class="action primary" type="button" data-nav-screen="${escapeHtml(actionScreen || "wizard")}" data-testid="surface-map-empty-action">${escapeHtml(actionLabel || "Start a mission")}</button>`
        }
      </div>
    </div>
  `;
}

function uniqueStrings(values) {
  return [...new Set((values || []).filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim()))];
}

function hostFromUrl(value) {
  try {
    const url = new URL(value);
    return url.hostname || "";
  } catch {
    return "";
  }
}

function deriveWebTargetsFromServices(services) {
  const webPorts = new Set([80, 81, 443, 444, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888]);
  return (services || []).flatMap((service) => {
    const port = Number(service.port || 0);
    const serviceName = String(service.service || "").toLowerCase();
    const isHttps = [443, 444, 8443].includes(port) || serviceName.includes("https") || serviceName.includes("ssl");
    const isWebService = webPorts.has(port) || /http|https|nginx|apache|tomcat|iis|gunicorn|uvicorn/.test(serviceName);
    if (!isWebService || !service.host) return [];
    const defaultPort = isHttps ? 443 : 80;
    const suffix = port && port !== defaultPort ? `:${port}` : "";
    return [`${isHttps ? "https" : "http"}://${service.host}${suffix}`];
  });
}

function deriveSurfaceMapHosts(hosts, services) {
  const normalizedHosts = Array.isArray(hosts) ? hosts.filter((host) => host?.host) : [];
  const seenHosts = new Set(normalizedHosts.map((host) => String(host.host || "").toLowerCase()));
  const derivedHosts = [];
  (Array.isArray(services) ? services : []).forEach((service) => {
    const host = String(service?.host || "").trim();
    const key = host.toLowerCase();
    if (!host || seenHosts.has(key)) return;
    seenHosts.add(key);
    derivedHosts.push({
      host,
      source: service.source || "service-inventory",
      confidence: service.confidence,
      _serviceInferred: true,
    });
  });
  return [...normalizedHosts, ...derivedHosts];
}

function buildSurfaceMapNodes({ hosts, endpoints, technologies, fingerprints, selectedAssetKey, hotspotTargets }) {
  const hostNodes = spreadColumnNodes(
    hosts.map((host) => ({
      key: `host:${host.host}`,
      kind: "host",
      title: host.host,
      meta: host._serviceInferred
        ? "Derived from mapped services"
        : host.source === "wizard-input" ? "Seeded from reviewed scope" : `${toPercent(host.confidence)} confidence`,
      hotspot: hotspotTargets.has(host.host),
    })),
    8
  ).map((node) => ({ ...node, left: 8 }));

  const endpointNodes = spreadColumnNodes(
    endpoints.map((endpoint) => ({
      key: `endpoint:${endpoint.url}`,
      kind: "endpoint",
      title: endpoint.url,
      meta: endpoint.source === "wizard-input" && endpoint.status_code == null
        ? "Wizard-seeded target"
        : `${(endpoint.methods || []).join(", ") || "observed route"} · ${endpoint.status_code || "unknown"}`,
      hotspot: hotspotTargets.has(endpoint.url),
    })),
    8
  ).map((node) => ({ ...node, left: 40 }));

  const technologyInput = technologies.length
    ? technologies.map((tech) => ({
        key: `tech:${tech.vendor || "unknown"}:${tech.name}:${tech.version || "none"}`,
        kind: "tech",
        title: tech.name,
        meta: `${tech.vendor || "unknown vendor"} · ${toPercent(tech.confidence)}`,
        hotspot: false,
      }))
    : fingerprints.map((fingerprint) => ({
        key: `fingerprint:${fingerprint.vendor || "unknown"}:${fingerprint.product}:${fingerprint.version || "none"}`,
        kind: "tech",
        title: fingerprint.product,
        meta: `${fingerprint.vendor || "fingerprint"} · ${toPercent(fingerprint.confidence)}`,
        hotspot: false,
      }));
  const technologyNodes = spreadColumnNodes(technologyInput, 8).map((node) => ({ ...node, left: 72 }));

  return [...hostNodes, ...endpointNodes, ...technologyNodes].map((node) => ({
    ...node,
    selected: node.key === selectedAssetKey,
  }));
}

function spreadColumnNodes(items, limit = 8) {
  const visible = items.slice(0, limit);
  const overflow = items.length - visible.length;
  const allVisible = overflow > 0
    ? [
        ...visible,
        {
          key: `${visible[0]?.kind || "asset"}:overflow`,
          kind: visible[0]?.kind || "asset",
          title: `+${overflow} more`,
          meta: "Open the asset browser for the full list",
          hotspot: false,
        },
      ]
    : visible;
  const count = Math.max(allVisible.length, 1);
  return allVisible.map((item, index) => ({
    ...item,
    top: 14 + (index * 70) / Math.max(count - 1, 1),
  }));
}

function buildSurfaceLines(nodes) {
  const svgLines = [];
  const hostNodes = nodes.filter((node) => node.kind === "host" && !node.key.endsWith(":overflow"));
  const endpointNodes = nodes.filter((node) => node.kind === "endpoint" && !node.key.endsWith(":overflow"));
  const techNodes = nodes.filter((node) => node.kind === "tech" && !node.key.endsWith(":overflow"));

  hostNodes.forEach((hostNode, index) => {
    const endpointNode = endpointNodes[index];
    if (endpointNode) {
      svgLines.push(lineSvg(hostNode.left + 16, hostNode.top + 3, endpointNode.left + 8, endpointNode.top + 3));
    }
  });
  endpointNodes.forEach((endpointNode, index) => {
    const techNode = techNodes[index];
    if (techNode) {
      svgLines.push(lineSvg(endpointNode.left + 16, endpointNode.top + 3, techNode.left + 8, techNode.top + 3));
    }
  });
  return svgLines;
}

function renderSurfaceAssetDetail(asset, scope) {
  const scopeAction = renderSurfaceScopeAction(asset, scope);
  if (asset.type === "host") {
    const services = asset.payload.services || [];
    const endpoints = asset.payload.endpoints || [];
    const notes = Array.isArray(asset.payload.notes) ? asset.payload.notes.filter(Boolean) : [];
    return `
      <div class="detail-surface emphasis-surface" data-testid="surface-asset-detail-card">
        <h4>${escapeHtml(asset.title)}</h4>
        <p>${escapeHtml(asset.summary)}</p>
        <p class="micro-copy split-top">${escapeHtml(asset.meta)}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Asset Type</span><strong>Host</strong></div>
          <div><span>Source</span><strong>${escapeHtml(asset.payload.source || "unknown")}</strong></div>
          <div><span>Services</span><strong>${escapeHtml(String(services.length))}</strong></div>
          <div><span>Endpoints</span><strong>${escapeHtml(String(endpoints.length))}</strong></div>
        </div>
        ${
          services.length
            ? renderDisclosure({
                title: "Services on this host",
                summary: `${services.length} mapped service${services.length === 1 ? "" : "s"}`,
                open: true,
                body: services
                  .map(
                    (service) => `
                      <div class="section-note split-top">
                        <strong>${escapeHtml(`${service.port}/${service.protocol} · ${service.service}`)}</strong>
                        <p>${escapeHtml([service.product, service.version].filter(Boolean).join(" · ") || "No product/version detail recorded")}</p>
                      </div>
                    `
                  )
                  .join(""),
              })
            : ""
        }
        ${
          endpoints.length
            ? renderDisclosure({
                title: "HTTP endpoints on this host",
                summary: `${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}`,
                open: false,
                body: endpoints
                  .map(
                    (endpoint) => `
                      <div class="section-note split-top">
                        <strong>${escapeHtml(endpoint.url)}</strong>
                        <p>${escapeHtml(`${endpoint.status_code || "unknown"} · ${(endpoint.methods || []).join(", ") || "observed route"}`)}</p>
                      </div>
                    `
                  )
                  .join(""),
              })
            : ""
        }
        ${
          notes.length
            ? renderDisclosure({
                title: "Discovery Notes",
                summary: `${notes.length} note${notes.length === 1 ? "" : "s"}`,
                open: false,
                body: notes
                  .map((note) => `<div class="section-note split-top"><p>${escapeHtml(note)}</p></div>`)
                  .join(""),
              })
            : ""
        }
        <div class="panel-actions split-top">
          ${scopeAction}
          <button class="action primary" type="button" data-follow-up-launch="service-enumeration">Run Service Identification</button>
          <button class="action ghost" type="button" data-nav-screen="mission-control">Back to Mission Control</button>
        </div>
      </div>
    `;
  }

  if (asset.type === "service") {
    return `
      <div class="detail-surface" data-testid="surface-asset-detail-card">
        <h4>${escapeHtml(asset.title)}</h4>
        <p>${escapeHtml(asset.summary || "Mapped service record")}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Host</span><strong>${escapeHtml(asset.payload.host)}</strong></div>
          <div><span>Port</span><strong>${escapeHtml(String(asset.payload.port))}</strong></div>
          <div><span>Protocol</span><strong>${escapeHtml(asset.payload.protocol || "tcp")}</strong></div>
          <div><span>Confidence</span><strong>${escapeHtml(toPercent(asset.payload.confidence))}</strong></div>
        </div>
        ${scopeAction ? `<div class="panel-actions split-top">${scopeAction}</div>` : ""}
      </div>
    `;
  }

  if (asset.type === "endpoint") {
    return `
      <div class="detail-surface" data-testid="surface-asset-detail-card">
        <h4>${escapeHtml(asset.title)}</h4>
        <p>${escapeHtml(asset.summary)}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Status</span><strong>${escapeHtml(String(asset.payload.status_code || "unknown"))}</strong></div>
          <div><span>Methods</span><strong>${escapeHtml((asset.payload.methods || []).join(", ") || "Observed route")}</strong></div>
          <div><span>Title</span><strong>${escapeHtml(asset.payload.title || "Not recorded")}</strong></div>
          <div><span>Confidence</span><strong>${escapeHtml(toPercent(asset.payload.confidence))}</strong></div>
        </div>
        <div class="panel-actions split-top">
          ${scopeAction}
          <button class="action primary" type="button" data-follow-up-launch="web-baseline">Run Web Profiling</button>
        </div>
      </div>
    `;
  }

  return `
    <div class="detail-surface" data-testid="surface-asset-detail-card">
      <h4>${escapeHtml(asset.title)}</h4>
      <p>${escapeHtml(asset.summary || "Inventory detail")}</p>
      <p class="micro-copy split-top">${escapeHtml(asset.meta)}</p>
    </div>
  `;
}

function surfaceAssetSearchText(asset) {
  const payload = asset?.payload || {};
  return [
    asset?.type,
    asset?.title,
    asset?.summary,
    asset?.meta,
    payload.host,
    payload.service,
    payload.product,
    payload.version,
    payload.vendor,
    payload.url,
    payload.title,
    payload.source,
    Array.isArray(payload.notes) ? payload.notes.join(" ") : "",
    Array.isArray(payload.methods) ? payload.methods.join(" ") : "",
    Array.isArray(payload.endpoints) ? payload.endpoints.map((endpoint) => endpoint.url).join(" ") : "",
    Array.isArray(payload.services)
      ? payload.services
          .map((service) => [service.port, service.protocol, service.service, service.product, service.version].filter(Boolean).join(" "))
          .join(" ")
      : "",
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function isEasmAsset(asset) {
  return String(asset?.payload?.source || "").toLowerCase() === "easm-discover";
}

function classifyScopeCandidate(value) {
  const normalizedValue = String(value || "").trim();
  if (!normalizedValue) return null;
  if (isLikelyUrl(normalizedValue)) {
    return { key: "urls", value: normalizedValue, label: "URL" };
  }
  if (isLikelyCidr(normalizedValue)) {
    return { key: "cidr_ranges", value: normalizedValue, label: "CIDR range" };
  }
  if (isLikelyIp(normalizedValue)) {
    return { key: "ip_addresses", value: normalizedValue, label: "IP address" };
  }
  if (isLikelyDomain(normalizedValue)) {
    const normalizedHost = normalizedValue.toLowerCase();
    const label = normalizedHost.split(".").length > 2 ? "Subdomain" : "Domain";
    return {
      key: label === "Subdomain" ? "subdomains" : "domains",
      value: normalizedHost,
      label,
    };
  }
  return { key: "targets", value: normalizedValue, label: "Target" };
}

function deriveScopeCandidateForAsset(asset) {
  if (!isEasmAsset(asset)) return null;
  if (asset.type === "endpoint") {
    return classifyScopeCandidate(asset.payload.url);
  }
  if (asset.type === "host" || asset.type === "service") {
    return classifyScopeCandidate(asset.payload.host);
  }
  return null;
}

function scopeAllowlistContainsExact(scope, candidate) {
  const values = Array.isArray(scope?.allowlist_json?.[candidate.key]) ? scope.allowlist_json[candidate.key] : [];
  return values.some((value) => String(value || "").trim().toLowerCase() === String(candidate.value || "").trim().toLowerCase());
}

function mergeScopeAllowlistCandidate(allowlist, candidate) {
  const nextAllowlist = { ...(allowlist || {}) };
  const existing = Array.isArray(nextAllowlist[candidate.key]) ? [...nextAllowlist[candidate.key]] : [];
  if (!existing.some((value) => String(value || "").trim().toLowerCase() === String(candidate.value || "").trim().toLowerCase())) {
    existing.push(candidate.value);
  }
  nextAllowlist[candidate.key] = existing;
  return nextAllowlist;
}

function renderSurfaceScopeAction(asset, scope) {
  const candidate = deriveScopeCandidateForAsset(asset);
  if (!candidate) return "";
  const alreadyInScope = scopeAllowlistContainsExact(scope, candidate);
  return `
    <button
      class="action secondary"
      type="button"
      data-surface-add-scope="${escapeHtml(candidate.value)}"
      data-testid="surface-add-to-scope"
      ${alreadyInScope ? "disabled" : ""}
    >
      ${escapeHtml(alreadyInScope ? "Already in scope" : `Add ${candidate.label} to scope`)}
    </button>
  `;
}

function summarizeSurfaceAssetTypes(surfaceAssets) {
  return (surfaceAssets || []).reduce(
    (summary, asset) => {
      if (asset?.type && asset.type in summary) summary[asset.type] += 1;
      return summary;
    },
    { host: 0, service: 0, endpoint: 0, technology: 0, product: 0 }
  );
}

function surfaceAssetTypeLabel(type) {
  const labels = {
    all: "All",
    host: "Hosts",
    service: "Services",
    endpoint: "Endpoints",
    technology: "Technologies",
    product: "Products",
  };
  return labels[type] || type;
}

function surfaceAssetFilterLabel(type, breakdown, totalCount) {
  if (type === "all") return `All (${Number(totalCount || 0)})`;
  const count = Number(breakdown?.[type] || 0);
  return `${surfaceAssetTypeLabel(type)} (${count})`;
}

function getFollowUpMetadata(run) {
  const followUp = run?.configuration_json?.follow_up;
  return typeof followUp === "object" && followUp !== null ? followUp : null;
}

function summarizeFollowUpInventory(followUp, inventorySnapshot) {
  if (!followUp || !inventorySnapshot || isSeedOnlyInventory(inventorySnapshot)) {
    return null;
  }

  const hostCount = Number(inventorySnapshot.summary_json?.host_count || 0);
  const serviceCount = Number(inventorySnapshot.summary_json?.service_count || 0);
  const endpointCount = Number(inventorySnapshot.summary_json?.endpoint_count || 0);
  const technologyCount = Number(inventorySnapshot.summary_json?.technology_count || 0);
  const strategy = String(followUp.strategy || "").toLowerCase();

  if (strategy === "service-enumeration") {
    return {
      next: "Review mapped services",
      summary: `${serviceCount} services were identified across ${hostCount} discovered host${hostCount === 1 ? "" : "s"}.`,
      detail: `${technologyCount} technology hint${technologyCount === 1 ? "" : "s"} are now available for the next bounded step.`,
    };
  }

  if (strategy === "web-baseline") {
    return {
      next: "Review profiled web assets",
      summary: `${endpointCount} web endpoint${endpointCount === 1 ? "" : "s"} were profiled across ${hostCount || "the selected"} asset${hostCount === 1 ? "" : "s"}.`,
      detail: `${technologyCount} stack hint${technologyCount === 1 ? "" : "s"} and HTTP metadata are now ready for controlled deeper validation.`,
    };
  }

  if (strategy === "approved-range-discovery") {
    return {
      next: "Review newly approved internal ranges",
      summary: `${hostCount} hosts and ${serviceCount} services were mapped across the additional approved ranges.`,
      detail: `${endpointCount} HTTP endpoint${endpointCount === 1 ? "" : "s"} are now visible inside the already allowlisted estate.`,
    };
  }

  return {
    next: "Review follow-up output",
    summary: `${hostCount} hosts, ${serviceCount} services, and ${endpointCount} endpoints are linked to this follow-up run.`,
    detail: `${technologyCount} technology hint${technologyCount === 1 ? "" : "s"} are available for the next review step.`,
  };
}

function packProgress(status) {
  const mapping = {
    proposed: 10,
    generated: 40,
    validation_failed: 35,
    validated: 60,
    approved: 80,
    deployed: 100,
    retired: 100,
    superseded: 100,
  };
  return mapping[status] || 0;
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

function packStatusToPhaseStatus(status) {
  if (["validation_failed", "retired"].includes(status)) return "blocked";
  if (["deployed", "approved", "validated", "superseded"].includes(status)) return "complete";
  if (["generated", "proposed"].includes(status)) return "active";
  return "pending";
}

function compareTaskActivity(left, right) {
  const byStatus = taskStatusPriority(left.status) - taskStatusPriority(right.status);
  if (byStatus !== 0) return byStatus;
  return new Date(right.created_at).getTime() - new Date(left.created_at).getTime();
}

function taskStatusPriority(status) {
  const order = {
    running: 0,
    queued: 1,
    failed: 2,
    completed: 3,
    cancelled: 4,
  };
  return order[String(status || "unknown").toLowerCase()] ?? 5;
}

function taskReasonSummary(task) {
  const params = task?.params_json || {};
  const profileName = params.profile_name || "selected profile";
  const targetKind = humanizeTargetKind(params.target_kind);
  const multiTargetCount = Array.isArray(params.targets) ? params.targets.length : 0;
  if (multiTargetCount > 1) {
    return `${profileName} queued this as a ${targetKind.toLowerCase()} batch across ${multiTargetCount} approved targets.`;
  }
  return `${profileName} queued this against a ${targetKind.toLowerCase()} target inside the current mission limits.`;
}

function renderMissionTaskFocus(selectedTaskSummary, selectedTask, latestExecution) {
  if (!selectedTaskSummary) {
    return "";
  }

  const params = selectedTaskSummary.params_json || {};
  const artifactCount = latestExecution?.artifacts?.length || 0;
  const latestExecutionLine = latestExecution
    ? `Latest execution finished with exit ${latestExecution.exit_code} using ${latestExecution.tool_version} and produced ${artifactCount} artifact${artifactCount === 1 ? "" : "s"}.`
    : String(selectedTaskSummary.status || "").toLowerCase() === "queued"
      ? "Waiting for explicit operator dispatch. Detailed execution data will appear here as soon as the selected check starts."
      : String(selectedTaskSummary.status || "").toLowerCase() === "running"
        ? "This selected check is currently running. Detailed execution data will appear here as the task completes and records artifacts."
        : selectedTask
          ? "Detailed execution data is still being collected for this task."
          : "Detailed execution data loads when the selected task record is refreshed.";

  return `
    <div class="detail-surface mission-task-focus-card split-top" data-testid="mission-task-focus">
      <h4>Selected Check Focus</h4>
      <p>${escapeHtml(`${formatToolLabel(selectedTaskSummary.tool)} · ${selectedTaskSummary.target_id}`)}</p>
      <p class="micro-copy">${escapeHtml(latestExecutionLine)}</p>
      ${renderTaskStdoutTerminal(selectedTaskSummary)}
      ${renderAiRepairAction(selectedTaskSummary)}
      <div class="compact-definition-grid split-top">
        <div><span>Status</span><strong>${escapeHtml(String(selectedTaskSummary.status || "unknown"))}</strong></div>
        <div><span>Target Type</span><strong>${escapeHtml(humanizeTargetKind(params.target_kind))}</strong></div>
        <div><span>Execution Lane</span><strong>${escapeHtml(params.profile_name || "Not recorded")}</strong></div>
        <div><span>Last Change</span><strong>${escapeHtml(formatDateTime(selectedTaskSummary.updated_at || selectedTaskSummary.created_at))}</strong></div>
        <div><span>Reason</span><strong>${escapeHtml(taskReasonSummary(selectedTaskSummary))}</strong></div>
        <div><span>Artifacts</span><strong>${escapeHtml(String(artifactCount))}</strong></div>
      </div>
      ${renderWirelessTaskFocus(selectedTaskSummary)}
      ${
        latestExecution
          ? renderDisclosure({
              title: "Latest Execution Detail",
              summary: `Exit ${latestExecution.exit_code} · ${artifactCount} artifact${artifactCount === 1 ? "" : "s"}`,
              open: false,
              testId: "mission-task-execution-detail",
              body: `
                <div class="compact-definition-grid">
                  <div><span>Tool Version</span><strong>${escapeHtml(latestExecution.tool_version)}</strong></div>
                  <div><span>Runner Digest</span><strong>${escapeHtml(latestExecution.runner_digest)}</strong></div>
                  <div><span>Completed</span><strong>${escapeHtml(formatDateTime(latestExecution.created_at))}</strong></div>
                  <div><span>Artifacts</span><strong>${escapeHtml(String(artifactCount))}</strong></div>
                </div>
                ${
                  latestExecution.stderr_text
                    ? `<pre class="report-preview split-top">${escapeHtml(latestExecution.stderr_text)}</pre>`
                    : ""
                }
              `,
            })
          : ""
      }
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
        <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
      </div>
    </div>
  `;
}

function renderWirelessTaskFocus(task) {
  if (String(task?.tool || "").toLowerCase() !== "wifi-survey") return "";
  const params = task?.params_json || {};
  const ssids = Array.isArray(params.approved_ssids) ? params.approved_ssids.filter(Boolean) : [];
  const bssids = Array.isArray(params.approved_bssids) ? params.approved_bssids.filter(Boolean) : [];
  return `
    <div class="compact-definition-grid split-top" data-testid="mission-wireless-task-focus">
      <div><span>Wireless Site</span><strong>${escapeHtml(params.site || task.target_id || "Not recorded")}</strong></div>
      <div><span>Adapter</span><strong>${escapeHtml(params.adapter || "Not recorded")}</strong></div>
      <div><span>Approved SSIDs</span><strong>${escapeHtml(ssids.length ? ssids.join(", ") : "Not recorded")}</strong></div>
      <div><span>Approved BSSIDs</span><strong>${escapeHtml(bssids.length ? bssids.join(", ") : "Not recorded")}</strong></div>
      <div><span>Boundary</span><strong>${escapeHtml("Passive only")}</strong></div>
      <div><span>RF Actions</span><strong>${escapeHtml("No deauth / no capture")}</strong></div>
    </div>
  `;
}

function renderAiRepairAction(selectedTaskSummary) {
  if (!canDraftAiRepairForTask(selectedTaskSummary)) {
    return "";
  }
  return `
    <div class="ai-repair-action split-top" data-testid="mission-ai-repair-action">
      <div>
        <strong>${escapeHtml("AI repair lane")}</strong>
        <p class="micro-copy">${escapeHtml("Draft a review-only repair proposal from this failed, blocked, or skipped runner outcome. No task is queued and active runtime state is not changed.")}</p>
      </div>
      <button class="action secondary" type="button" data-ai-repair-task-id="${escapeHtml(String(selectedTaskSummary.id || ""))}">
        Draft Repair
      </button>
    </div>
  `;
}

function canDraftAiRepairForTask(task) {
  return ["failed", "blocked", "skipped"].includes(normalizeTaskStatus(task?.status));
}

function renderTaskStdoutTerminal(selectedTaskSummary) {
  const stream = state.taskStdoutStream || {};
  const selectedTaskId = String(selectedTaskSummary?.id || "");
  const streamTaskId = String(stream.taskId || "");
  const attached = selectedTaskId && streamTaskId === selectedTaskId;
  const status = attached ? String(stream.status || "idle").toLowerCase() : "idle";
  const lines = attached && Array.isArray(stream.lines) ? stream.lines : [];
  const terminalOutput = lines.map((line) => String(line?.text || "")).join("\n");
  const sourceLabel = taskStdoutSourceLabel(stream.sourceLabel);
  const lineSummary = `${Number(stream.lineCount || lines.length || 0)} line${Number(stream.lineCount || lines.length || 0) === 1 ? "" : "s"}`;
  const isRunning = String(selectedTaskSummary?.status || "").toLowerCase() === "running";
  const liveIndicator =
    isRunning
      ? `<span class="task-stdout-live-indicator" data-testid="mission-task-stdout-live-indicator"><i></i>Live</span>`
      : "";
  const title =
    status === "completed"
      ? "Captured task stdout"
      : status === "streaming" || status === "running"
        ? "Task stdout stream"
        : status === "connecting"
          ? "Connecting task stdout"
          : status === "missing"
            ? "Task stream stopped"
            : "Task stdout unavailable";
  const detail =
    status === "completed"
      ? "Runner stdout has been captured through the bounded task stream."
      : (status === "streaming" || status === "running") && lines.length
        ? "Mission Control is rendering captured stdout from the selected task only."
        : status === "streaming" || status === "running"
          ? "The selected task stream is attached. Output appears only when the existing runner safely captures stdout."
          : status === "connecting"
            ? "Connecting to the selected task stdout endpoint."
            : status === "fallback"
              ? stream.fallbackReason || "Task stdout stream is unavailable; use stored execution detail if present."
              : status === "missing"
                ? stream.fallbackReason || "Selected task no longer exists."
                : stream.fallbackReason || "No safe stdout capture is available yet for this selected task.";

  return `
    <div class="task-stdout-terminal split-top status-${escapeHtml(status)}" data-testid="mission-task-stdout-terminal">
      <div class="task-stdout-terminal-bar">
        <div>
          <span>${escapeHtml(title)}${liveIndicator}</span>
          <code>${escapeHtml(sourceLabel)}</code>
        </div>
        <strong>${escapeHtml(`${lineSummary}${stream.truncated ? " · bounded" : ""}`)}</strong>
      </div>
      <p class="micro-copy">${escapeHtml(detail)}</p>
      ${
        terminalOutput
          ? `<pre class="task-stdout-output" data-testid="mission-task-stdout-output">${escapeHtml(terminalOutput)}</pre>`
          : `<p class="task-stdout-empty" data-testid="mission-task-stdout-empty">${escapeHtml("No captured stdout lines are available for this task stream.")}</p>`
      }
    </div>
  `;
}

function taskStdoutSourceLabel(source) {
  const mapping = {
    "runner-buffer": "Bounded runner buffer",
    "stored-execution": "Stored execution stdout",
    "no-stream": "No stream available",
  };
  return mapping[String(source || "")] || "Task stdout endpoint";
}

function renderStatusCount(label, value, tone) {
  return `
    <div class="status-count-card tone-${escapeHtml(tone)}">
      <strong>${escapeHtml(String(value || 0))}</strong>
      <small>${escapeHtml(label)}</small>
    </div>
  `;
}

function describeTaskStatus(status) {
  const normalized = String(status || "unknown").toLowerCase();
  const mapping = {
    queued: "Waiting for explicit operator dispatch.",
    running: "Executing now against approved scope. Live refresh is temporarily faster while the run is active.",
    completed: "Execution finished and evidence may now be available.",
    failed: "Execution returned errors; inspect the dossier or evidence views.",
    cancelled: "Execution was stopped before completion.",
  };
  return mapping[normalized] || "Execution state is being updated.";
}

function formatToolLabel(tool) {
  const mapping = {
    httpx: "HTTP probe",
    nmap: "Network discovery",
    nuclei: "Template validation",
    semgrep: "Code pattern check",
    zap: "Active web validation",
    "wifi-survey": "WiFi passive survey",
  };
  return mapping[String(tool || "").toLowerCase()] || String(tool || "Unknown tool");
}

function humanizeTargetKind(kind) {
  const mapping = {
    url: "URL",
    domain: "Domain",
    host: "Host",
    cidr: "CIDR",
    "multi-target": "Multi Target",
    target: "Target",
  };
  return mapping[String(kind || "").toLowerCase()] || String(kind || "Target");
}
