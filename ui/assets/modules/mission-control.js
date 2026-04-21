import { api } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  countMeaningfulAccessContexts,
  countScopeTargets,
  emptyState,
  enabledModules,
  escapeHtml,
  executionPlanForProfile,
  flattenTargetValues,
  formatDateTime,
  formatDurationLabel,
  formatElapsedMinutes,
  hasMeaningfulAccessContext,
  humanizeCheckMode,
  humanizeDepthLabel,
  isSeedOnlyInventory,
  followUpStrategyLabel,
  lineSvg,
  minutesSince,
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

export function createMissionModule() {
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

  function renderPendingApprovalRunActivity(run) {
    const approvals = approvalStateForRun(run);
    const approvalLabel = approvals.required === 1 ? "approval" : "approvals";
    const profileName =
      run?.profile?.name ||
      run?.configuration_json?.execution_profile ||
      "the selected execution lane";
    return `
      <h4>${escapeHtml("Approval is still required before active checks can be queued")}</h4>
      <p>${escapeHtml(approvalWaitingSummary(run))}</p>
      <div class="detail-surface emphasis-surface split-top" data-testid="pending-approval-run-activity">
        <h4>Approval Status</h4>
        <div class="compact-definition-grid">
          <div><span>Execution Lane</span><strong>${escapeHtml(profileName)}</strong></div>
          <div><span>Required</span><strong>${escapeHtml(String(approvals.required))}</strong></div>
          <div><span>Granted</span><strong>${escapeHtml(String(approvals.granted))}</strong></div>
          <div><span>Pending</span><strong>${escapeHtml(String(approvals.pending))}</strong></div>
        </div>
        <p class="micro-copy">${escapeHtml(
          approvals.pending > 0
            ? `This mission is approval-gated, so AegisPT will only queue the planned active checks after the remaining ${approvals.pending} ${approvalLabel} are recorded.`
            : "This mission is approval-gated, and Mission Control will queue the planned active checks as soon as the approval state is fully cleared."
        )}</p>
      </div>
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
        <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
      </div>
    `;
  }

  function renderMissionControl() {
    const phases = buildMissionPhases();
    const activity = deriveCurrentActivity(phases);
    dom.missionActivity.innerHTML = `
      <h4>${escapeHtml(activity.title)}</h4>
      <div class="inline-metrics">
        ${statusPill(activity.status)}
        <span class="metric-pill">${escapeHtml(activity.health)}</span>
        <span class="metric-pill">${escapeHtml(activity.next)}</span>
      </div>
      <p class="split-top">${escapeHtml(activity.summary)}</p>
      <p class="micro-copy split-top">${escapeHtml(activity.why)}</p>
      <p class="micro-copy">${escapeHtml(activity.expectation)}</p>
      <div class="panel-actions">
        ${renderActivityAction(activity.primaryAction, "primary")}
        ${renderActivityAction(activity.secondaryAction, "ghost")}
      </div>
    `;
    dom.missionTimeline.innerHTML = phases.map(renderPhaseCard).join("");

    const statusBoard = deriveStatusBoard();
    dom.missionGood.innerHTML = renderSignalList(statusBoard.good, "good", "Healthy signals appear here after scope and mission activity are available.");
    dom.missionBad.innerHTML = renderSignalList(statusBoard.bad, "critical", "No blocking issues detected right now.");
    dom.missionUnknown.innerHTML = renderSignalList(statusBoard.unknown, "unknown", "No unknowns are currently flagged.");

    const eta = deriveMissionEta(phases);
    dom.missionEta.innerHTML = `
      <h4>${escapeHtml(`${eta.elapsed_label} elapsed · ${eta.remaining_label} remaining`)}</h4>
      <p>${escapeHtml(`${eta.total_label} projected total · ${eta.confidence_label}`)}</p>
      <p class="micro-copy">${escapeHtml(eta.detail)}</p>
      <div class="progress-track"><div class="progress-bar" style="width:${eta.percent_complete}%"></div></div>
    `;

    const pulse = buildFindingsPulse();
    if (pulse.mode === "inventory") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.host_count} hosts discovered · ${pulse.service_count} services mapped`)}</h4>
        <p>${escapeHtml("This inventory-first profile is working as designed. Discovery data is ready even though vulnerability findings are still empty.")}</p>
        <p class="micro-copy">${escapeHtml(`Inventory confidence ${toPercent(pulse.confidence_score)} · open Surface Map or Explorer to review the discovered estate.`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
          <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
        </div>
      `;
    } else if (pulse.mode === "inventory-pending") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml("Discovery is running")}</h4>
        <p>${escapeHtml("Inventory-first runs do not create findings while the network sweep is still in progress.")}</p>
        <p class="micro-copy">${escapeHtml("Stay in Mission Control for live status, or open Explorer once the discovery snapshot is ready.")}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="mission-control">Stay in Mission Control</button>
          <button class="action ghost" type="button" data-nav-screen="explorer">Open Explorer</button>
        </div>
      `;
    } else if (pulse.mode === "inventory-follow-up") {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.host_count} hosts discovered · ${pulse.service_count} services mapped`)}</h4>
        <p>${escapeHtml("This internal validation mission is now past the discovery stage. Use the follow-up run cards to map services, profile web assets, and continue deeper validation safely.")}</p>
        <p class="micro-copy">${escapeHtml(`Inventory confidence ${toPercent(pulse.confidence_score)} · vulnerability findings stay empty until a deeper follow-up run is launched from the discovered estate.`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="mission-control">Open Next Steps</button>
          <button class="action ghost" type="button" data-nav-screen="surface-map">Open Surface Map</button>
        </div>
      `;
    } else {
      dom.missionFindingsPulse.innerHTML = `
        <h4>${escapeHtml(`${pulse.confirmed} confirmed · ${pulse.suspected} suspected · ${pulse.dismissed} dismissed`)}</h4>
        <p>${escapeHtml(`${pulse.critical} high-priority items · ${pulse.evidence_completeness}% evidence completeness`)}</p>
        <p class="micro-copy">${escapeHtml(`Methodology coverage: ${pulse.coverage}`)}</p>
        <div class="panel-actions">
          <button class="action ghost" type="button" data-nav-screen="findings-theater">Open Findings Theater</button>
          <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence Replay</button>
        </div>
      `;
    }

    dom.missionAiNarrative.innerHTML = renderStringCards(buildNarratives(), "AI narrative appears as soon as inventory, adaptive decisions, or findings exist.");
    dom.missionPackStatus.innerHTML = renderPackStatusSummary();
    dom.missionScopeSummary.innerHTML = renderScopeProfileSummary();
    dom.missionRunActivity.innerHTML = renderRunActivitySummary();
    attachMissionRunActivityHandlers();
  }

  function buildMissionPhases() {
    const run = state.selectedRun;
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
    return `
      <div class="phase-card ${phase.status}" style="--phase-progress:${phase.progress}%" data-testid="mission-phase-card">
        <p class="eyebrow">${escapeHtml(phase.label)}</p>
        <h4>${escapeHtml(`${phase.progress}%`)}</h4>
        <p>${statusPill(phase.status)}</p>
        <p>${escapeHtml(phase.summary)}</p>
        <p class="micro-copy">${escapeHtml(`Elapsed ${phase.elapsed}`)}</p>
      </div>
    `;
  }

  function deriveCurrentActivity(phases) {
    const run = state.selectedRun;
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
        why: "Direct-host operator installs are meant to run inline. A stale or incomplete host service environment can leave TASK_DISPATCH_MODE on manual, which makes Start Validation feel like a dead button.",
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
        expectation: "Press Start Validation to launch the queued tasks with the current run profile, scope, and safety settings.",
        primaryAction: { label: "Start Validation", action: "dispatch-run" },
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

  function renderPackStatusSummary() {
    const pack = state.selectedPackBundle?.pack || runtime.actions.selectedPack?.();
    const deployments = state.selectedPackBundle?.deployments || [];
    const validations = state.selectedPackBundle?.validations || [];
    const bound = state.selectedRun?.pack_binding;
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

  function renderRunActivitySummary() {
    const run = state.selectedRun;
    if (!run) {
      return emptyState("Create a mission first. The queue, active scans, and recent completions appear here.");
    }

    const tasks = [...(run.tasks || [])];
    if (!tasks.length) {
      if (String(run.status || "").toLowerCase() === "pending_approval") {
        return renderPendingApprovalRunActivity(run);
      }
      return emptyState("This run exists, but no execution tasks were queued yet.");
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
    const counts = summarizeTaskStatuses(tasks);
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const meaningfulOutput = findings.length > 0 || (inventorySnapshot && !inventorySeedOnly);
    const summary = dispatching
      ? "Queued checks are being dispatched now. Discovery and replay data appear after the runner returns."
      : manualHint?.dispatch_mode === "manual" && counts.queued
        ? "The API received the dispatch request, but this host is still configured for manual execution so the queued checks cannot start here."
      : counts.running
      ? "Validation is actively running against the selected scope."
      : counts.queued
        ? "Queued checks are ready. Press Start Validation to launch them."
        : counts.failed
          ? "The last execution completed with errors. Open the dossier for detail."
          : "Execution history is available below.";
    const toolCount = new Set(tasks.map((task) => task.tool)).size;
    const sortedTasks = tasks.slice().sort(compareTaskActivity);
    const visibleTasks = sortedTasks.slice(0, 2);
    const remainingTasks = sortedTasks.slice(2);

    return `
      <h4>${escapeHtml(`${tasks.length} planned checks across ${toolCount} tool${toolCount === 1 ? "" : "s"}`)}</h4>
      <p>${escapeHtml(summary)}</p>
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
              <p class="micro-copy">${escapeHtml("Review the selected task execution, artifacts, and exact target coverage before treating this run as complete or deciding on the next follow-up step.")}</p>
              <div class="panel-actions split-top">
                <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
                <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
              </div>
            </div>
          `
          : ""
      }
      <div class="status-grid split-top">
        ${renderStatusCount("Running", counts.running, "active")}
        ${renderStatusCount("Queued", counts.queued, "pending")}
        ${renderStatusCount("Completed", counts.completed, "complete")}
        ${renderStatusCount("Failed", counts.failed, "blocked")}
      </div>
        <div class="task-activity-list split-top">
        ${visibleTasks
          .map(
            (task) => `
              <button
                class="task-activity-card ${escapeHtml(String(task.status || "unknown").toLowerCase())} ${selectedTaskSummary?.id === task.id ? "selected" : ""}"
                type="button"
                data-mission-task-pick="${escapeHtml(task.id)}"
                data-testid="mission-task-card"
              >
                <div class="task-activity-header">
                  <h4>${escapeHtml(formatToolLabel(task.tool))}</h4>
                  ${statusPill(task.status)}
                </div>
                <p>${escapeHtml(task.target_id)}</p>
                <p class="micro-copy">${escapeHtml(taskReasonSummary(task))}</p>
                <p class="micro-copy">${escapeHtml(`${describeTaskStatus(task.status)} · Last change ${formatDateTime(task.updated_at || task.created_at)}`)}</p>
              </button>
            `
          )
          .join("")}
      </div>
      ${renderMissionTaskFocus(selectedTaskSummary, selectedTask, latestExecution)}
      ${
        remainingTasks.length
          ? renderDisclosure({
              title: "Remaining Planned Checks",
              summary: `${remainingTasks.length} additional check${remainingTasks.length === 1 ? "" : "s"} remain available`,
              open: false,
              testId: "mission-run-activity-more",
              body: `
                <div class="task-activity-list">
                  ${remainingTasks
                    .map(
                      (task) => `
                        <button
                          class="task-activity-card ${escapeHtml(String(task.status || "unknown").toLowerCase())} ${selectedTaskSummary?.id === task.id ? "selected" : ""}"
                          type="button"
                          data-mission-task-pick="${escapeHtml(task.id)}"
                        >
                          <div class="task-activity-header">
                            <h4>${escapeHtml(formatToolLabel(task.tool))}</h4>
                            ${statusPill(task.status)}
                          </div>
                          <p>${escapeHtml(task.target_id)}</p>
                          <p class="micro-copy">${escapeHtml(taskReasonSummary(task))}</p>
                          <p class="micro-copy">${escapeHtml(`${describeTaskStatus(task.status)} · Last change ${formatDateTime(task.updated_at || task.created_at)}`)}</p>
                        </button>
                      `
                    )
                    .join("")}
                </div>
              `,
            })
          : ""
      }
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-nav-screen="explorer">Open Run Dossier</button>
      </div>
    `;
  }

  function attachMissionRunActivityHandlers() {
    dom.missionRunActivity.querySelectorAll("[data-mission-task-pick]").forEach((button) => {
      button.addEventListener("click", async () => {
        state.selectedTaskId = button.dataset.missionTaskPick || null;
        await runtime.actions.loadSelectedTask?.();
        renderMissionControl();
      });
    });
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
    const exactTargets = flattenTargetValues(targets);
    const targetPreview = exactTargets.length
      ? exactTargets.slice(0, 3).join(", ")
      : "No explicit targets recorded";
    return `
      <h4>${escapeHtml(config.assessment_type || "Assessment not recorded")}</h4>
      <p>${escapeHtml(config.test_profile || run.profile.name)}</p>
      <p class="micro-copy">${escapeHtml(targetPreview)}${exactTargets.length > 3 ? `, plus ${exactTargets.length - 3} more` : ""}</p>
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
          meta: host.source === "wizard-input" ? "Seeded from reviewed scope" : `${toPercent(host.confidence)} confidence`,
          payload: { ...host, services: relatedServices, endpoints: relatedEndpoints },
        };
      }),
      ...services.map((service) => ({
        key: `service:${service.host}:${service.port}/${service.protocol}`,
        type: "service",
        title: `${service.host}:${service.port}/${service.protocol}`,
        summary: [service.service, service.product, service.version].filter(Boolean).join(" · "),
        meta: `${toPercent(service.confidence)} confidence`,
        payload: service,
      })),
      ...endpoints.map((endpoint) => ({
        key: `endpoint:${endpoint.url}`,
        type: "endpoint",
        title: endpoint.url,
        summary: `${endpoint.status_code || "unknown"} · ${(endpoint.methods || []).join(", ") || "observed route"}`,
        meta: endpoint.title || `${toPercent(endpoint.confidence)} confidence`,
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

  function renderSurfaceMap() {
    const snapshot = runtime.actions.selectedRunInventorySnapshot?.();
    dom.surfaceToggleBar.innerHTML = Object.entries(state.surfaceOverlays)
      .map(
        ([key, enabled]) => `
          <button class="action ${enabled ? "secondary" : "ghost"} surface-toggle" data-overlay="${key}" type="button">
            ${escapeHtml(surfaceOverlayLabel(key))}
          </button>
        `
      )
      .join("");
    dom.surfaceToggleBar.querySelectorAll(".surface-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        state.surfaceOverlays[button.dataset.overlay] = !state.surfaceOverlays[button.dataset.overlay];
        renderSurfaceMap();
      });
    });

    if (!snapshot) {
      const noInventoryAction = state.selectedRun
        ? "Open Mission Control to start or refresh the selected run; Surface Map will render host cards as soon as inventory is recorded."
        : "Create a mission in Conversational Intake first; Surface Map unlocks after the first run has inventory.";
      dom.surfaceMapCanvas.innerHTML = emptyState(`No inventory snapshot is available yet. ${noInventoryAction}`);
      dom.surfaceAssetBrowser.innerHTML = emptyState("The asset browser needs inventory before it can list host cards, services, endpoints, and stack hints.");
      dom.surfaceAssetDetail.innerHTML = emptyState("Select a mapped asset after inventory exists to inspect host-card detail and available follow-up actions.");
      dom.surfaceInsights.innerHTML = emptyState("Surface insights will appear after inventory is available; start from Intake or Mission Control to create that inventory.");
      dom.surfaceLegend.innerHTML = emptyState("Legend data will populate after mapped assets and overlays exist.");
      return;
    }

    const inventory = snapshot.normalized_inventory_json || {};
    const hosts = Array.isArray(inventory.hosts) ? inventory.hosts : [];
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

    state.selectedSurfaceAssetKey = selectedAsset?.key || null;
    state.surfaceAssetFilter = activeFilter;
    state.surfaceAssetQuery = rawQuery;

    const mapNodes = buildSurfaceMapNodes({
      hosts,
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
          const hotspot = state.surfaceOverlays.hotspots && node.hotspot;
          const packZone = state.surfaceOverlays.packZones && node.kind === "tech" && Boolean(runtime.actions.selectedPack?.());
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
        state.selectedSurfaceAssetKey = button.dataset.surfaceAssetKey || null;
        renderSurfaceMap();
      });
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
                  ${escapeHtml(surfaceAssetTypeLabel(type))}
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
      state.surfaceAssetQuery = event.target.value || "";
      renderSurfaceMap();
    });
    dom.surfaceAssetBrowser.querySelectorAll("[data-surface-filter]").forEach((button) => {
      button.addEventListener("click", () => {
        state.surfaceAssetFilter = button.dataset.surfaceFilter || "all";
        renderSurfaceMap();
      });
    });
    dom.surfaceAssetBrowser.querySelector("[data-surface-clear-search]")?.addEventListener("click", () => {
      state.surfaceAssetQuery = "";
      renderSurfaceMap();
    });
    dom.surfaceAssetBrowser.querySelectorAll("[data-surface-asset-key]").forEach((button) => {
      button.addEventListener("click", () => {
        state.selectedSurfaceAssetKey = button.dataset.surfaceAssetKey || null;
        renderSurfaceMap();
      });
    });

    dom.surfaceAssetDetail.innerHTML = selectedAsset
      ? renderSurfaceAssetDetail(selectedAsset)
      : emptyState(
          rawQuery
            ? `No asset records match "${rawQuery}". Clear or widen the search to inspect a mapped record.`
            : "Select an asset in the browser or map to inspect the normalized inventory record."
        );

    const previousSnapshot = state.mission.inventory[1] || null;
    dom.surfaceInsights.innerHTML = `
      ${renderStringCards(
        [
          `${hosts.length} hosts or network objects are visible in the current surface model.`,
          `${endpoints.length} HTTP or API endpoints are mapped for the selected engagement.`,
          `${technologies.length || fingerprints.length} stack indicators are available for adaptive relevance decisions.`,
          isSeedOnlyInventory(snapshot) ? "The current surface model is wizard-seeded input, not discovery-confirmed telemetry yet." : "This surface model reflects discovery-confirmed inventory inputs.",
          previousSnapshot ? `${Math.max(0, (snapshot.summary_json.host_count || 0) - (previousSnapshot.summary_json.host_count || 0))} new host-level items were discovered since the previous snapshot.` : "No prior inventory snapshot exists for delta analysis yet.",
        ],
        "Insights appear after inventory normalization runs."
      )}
      ${renderInventoryFollowUpPanel("surface")}
    `;
    dom.surfaceLegend.innerHTML = `
      <div class="pill-grid">
        <span class="legend-chip">Hosts</span>
        <span class="legend-chip">Apps / APIs</span>
        <span class="legend-chip">Stacks / Products</span>
        <span class="legend-chip">Hotspots ${state.surfaceOverlays.hotspots ? "On" : "Off"}</span>
        <span class="legend-chip">Pack Zones ${state.surfaceOverlays.packZones ? "On" : "Off"}</span>
        <span class="legend-chip">Future Attack Paths ${state.surfaceOverlays.futureAttackPaths ? "Reserved" : "Prepared"}</span>
        <span class="legend-chip">Future Identity Graph ${state.surfaceOverlays.futureIdentityGraph ? "Reserved" : "Prepared"}</span>
        <span class="legend-chip">Future Risk Overlay ${state.surfaceOverlays.futureRiskOverlay ? "Reserved" : "Prepared"}</span>
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

    state.selectedRunId = createdRun.id;
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
    state.activeScreen = "mission-control";
    runtime.actions.renderAll?.();
  }

  return {
    canDispatchSelectedRun,
    dispatchSelectedRun,
    launchInventoryFollowUp,
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

function canDispatchSelectedRun() {
  const run = state.selectedRun;
  if (!run) return false;
  if (["cancelled", "cancelling", "rejected", "completed", "completed_with_errors", "failed"].includes(run.status)) {
    return false;
  }
  const manualHint = manualDispatchHintForSelectedRun();
  if (manualHint?.dispatch_mode === "manual" && String(run.status || "").toLowerCase() === "queued") {
    return false;
  }
  return (run.tasks || []).some((task) => task.status === "queued");
}

function renderActivityAction(action, buttonClass) {
  if (!action) return "";
  if (action.action === "dispatch-run") {
    return `<button class="action ${buttonClass}" type="button" data-run-dispatch="selected" data-testid="mission-dispatch">${escapeHtml(action.label)}</button>`;
  }
  return `<button class="action ${buttonClass}" type="button" data-nav-screen="${escapeHtml(action.screen)}">${escapeHtml(action.label)}</button>`;
}

async function dispatchSelectedRun() {
  if (!state.selectedRunId) {
    throw new Error("Select a run before starting validation.");
  }

  const run = state.selectedRun;
  const discoveryOnly = isDiscoveryOnlyRun(run);
  state.loading.dispatchRunId = state.selectedRunId;
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
      state.dispatchHintsByRunId[String(state.selectedRunId)] = {
        dispatch_mode: "manual",
        message: "This host accepted the dispatch request in manual mode, but no inline runner or background worker is attached to start the queued checks.",
      };
      runtime.actions.pushStatus?.(
        "Dispatch reached the API in manual mode, but this host has no active worker. Start a worker or switch the host service to TASK_DISPATCH_MODE=inline.",
        "error"
      );
      runtime.actions.renderAll?.();
      return;
    }

    delete state.dispatchHintsByRunId[String(state.selectedRunId)];

    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const inventoryReady = discoveryOnly && inventorySnapshot && !isSeedOnlyInventory(inventorySnapshot);
    if (inventoryReady) {
      const hostCount = Number(inventorySnapshot.summary_json?.host_count || 0);
      runtime.actions.pushStatus?.(
        `Discovery completed in ${response.dispatch_mode} mode. ${hostCount} host${hostCount === 1 ? "" : "s"} were mapped and Surface Map is ready.`,
        "success"
      );
      state.activeScreen = "surface-map";
      runtime.actions.renderAll?.();
      return;
    }

    runtime.actions.pushStatus?.(
      `Validation started in ${response.dispatch_mode} mode for ${response.dispatched_task_ids.length} queued task${response.dispatched_task_ids.length === 1 ? "" : "s"}.`,
      "success"
    );
  } finally {
    state.loading.dispatchRunId = null;
    runtime.actions.renderAll?.();
  }
}

function surfaceOverlayLabel(key) {
  const mapping = {
    hotspots: "Hotspots",
    packZones: "Pack Impact Zones",
    futureAttackPaths: "Future Attack Paths",
    futureIdentityGraph: "Future Identity Graph",
    futureRiskOverlay: "Future Risk Overlay",
  };
  return mapping[key] || key;
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

function buildSurfaceMapNodes({ hosts, endpoints, technologies, fingerprints, selectedAssetKey, hotspotTargets }) {
  const hostNodes = spreadColumnNodes(
    hosts.map((host) => ({
      key: `host:${host.host}`,
      kind: "host",
      title: host.host,
      meta: host.source === "wizard-input" ? "Seeded from reviewed scope" : `${toPercent(host.confidence)} confidence`,
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

function renderSurfaceAssetDetail(asset) {
  if (asset.type === "host") {
    const services = asset.payload.services || [];
    const endpoints = asset.payload.endpoints || [];
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
        <div class="panel-actions split-top">
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
    <div class="detail-surface split-top" data-testid="mission-task-focus">
      <h4>Selected Check Focus</h4>
      <p>${escapeHtml(`${formatToolLabel(selectedTaskSummary.tool)} · ${selectedTaskSummary.target_id}`)}</p>
      <p class="micro-copy">${escapeHtml(latestExecutionLine)}</p>
      <div class="compact-definition-grid split-top">
        <div><span>Status</span><strong>${escapeHtml(String(selectedTaskSummary.status || "unknown"))}</strong></div>
        <div><span>Target Type</span><strong>${escapeHtml(humanizeTargetKind(params.target_kind))}</strong></div>
        <div><span>Execution Lane</span><strong>${escapeHtml(params.profile_name || "Not recorded")}</strong></div>
        <div><span>Last Change</span><strong>${escapeHtml(formatDateTime(selectedTaskSummary.updated_at || selectedTaskSummary.created_at))}</strong></div>
        <div><span>Reason</span><strong>${escapeHtml(taskReasonSummary(selectedTaskSummary))}</strong></div>
        <div><span>Artifacts</span><strong>${escapeHtml(String(artifactCount))}</strong></div>
      </div>
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
