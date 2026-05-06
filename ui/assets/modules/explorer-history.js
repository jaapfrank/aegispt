import { dom, runtime, state } from "./runtime.js";
import {
  countMeaningfulAccessContexts,
  emptyState,
  escapeHtml,
  exposureTrendLabel,
  findingKey,
  followUpStrategyLabel,
  formatExposureScore,
  formatDateTime,
  groupBy,
  hasMeaningfulAccount,
  renderBadgeList,
  renderAccessContextSummary,
  renderDisclosure,
  renderExposureSparkline,
  renderTargetSummary,
  severityRank,
  statusPill,
} from "./shared.js";
import { renderKillChainMatrix } from "./kill-chain.js";

function summarizeDossierExclusions(exclusions) {
  const values = [
    ...(exclusions?.domains || []),
    ...(exclusions?.urls || []),
    ...(exclusions?.ip_addresses || []),
    ...(exclusions?.cidr_ranges || []),
    ...(exclusions?.api_base_urls || []),
  ].filter((value) => typeof value === "string" && value.trim());
  if (!values.length && !String(exclusions?.notes || "").trim()) return "No denylist recorded";
  if (!values.length) return "Boundary notes only";
  return `${values.length} explicit exclusion${values.length === 1 ? "" : "s"}`;
}

function humanizeBoundaryHandling(value, exclusions) {
  const exclusionSummary = summarizeDossierExclusions(exclusions);
  const explicit = String(value || "").trim() || (
    exclusionSummary === "Boundary notes only"
      ? "notes-only-boundaries"
      : exclusionSummary !== "No denylist recorded"
        ? "custom-exclusions"
        : "standard-scope-only"
  );
  const mapping = {
    "standard-scope-only": "Standard Scope Only",
    "report-adjacent-ranges-only": "Report Adjacent Ranges Only",
    "approved-lateral-discovery": "Approved Lateral Discovery",
    "custom-exclusions": "Custom Exclusions Recorded",
    "notes-only-boundaries": "Boundary Notes Recorded",
  };
  return mapping[explicit] || explicit;
}

function humanizeOutputStyle(value) {
  const mapping = {
    "detailed-per-item": "Detailed Per Item",
    "balanced-technical": "Balanced Technical",
    "technical-detail": "Technical Detail",
    "executive-summary": "Executive Summary",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeAuthStrategy(value) {
  const mapping = {
    unauthenticated: "Unauthenticated",
    credentialed: "Credentialed Login",
    "api-access": "API Token / Key",
    "session-access": "Session / Cookie",
    "advanced-details": "Advanced Access Detail",
  };
  return mapping[String(value || "").trim()] || String(value || "Not recorded");
}

function summarizeAccountBindingKinds(account) {
  const bindings = account?.secret_bindings || {};
  const kinds = Object.values(bindings)
    .map((binding) => binding?.secret_kind)
    .filter((value) => typeof value === "string" && value.trim());
  if (!kinds.length) return "No protected binding recorded";
  return kinds.join(", ");
}

function compareRuns(currentRunId, baselineRunId) {
  if (!currentRunId || !baselineRunId) return null;
  const currentRun = state.mission.runs.find((run) => run.id === currentRunId);
  const baselineRun = state.mission.runs.find((run) => run.id === baselineRunId);
  if (!currentRun || !baselineRun) return null;
  const currentFindings = state.mission.findingsByRun[currentRunId] || [];
  const baselineFindings = state.mission.findingsByRun[baselineRunId] || [];
  const baselineMap = new Map(baselineFindings.map((finding) => [findingKey(finding), finding]));
  const currentMap = new Map(currentFindings.map((finding) => [findingKey(finding), finding]));
  let worsenedCount = 0;
  let changedCount = 0;
  let resolvedCount = 0;
  currentFindings.forEach((finding) => {
    const prior = baselineMap.get(findingKey(finding));
    if (!prior) return;
    const currentRank = severityRank(finding.severity);
    const priorRank = severityRank(prior.severity);
    if (currentRank < priorRank) worsenedCount += 1;
    if (
      String(finding.severity || "").toLowerCase() !== String(prior.severity || "").toLowerCase() ||
      String(finding.status || "").toLowerCase() !== String(prior.status || "").toLowerCase()
    ) {
      changedCount += 1;
    }
    if (!isResolvedFindingStatus(prior.status) && isResolvedFindingStatus(finding.status)) {
      resolvedCount += 1;
    }
  });
  const newCount = currentFindings.filter((finding) => !baselineMap.has(findingKey(finding))).length;
  const fixedCount = baselineFindings.filter((finding) => !currentMap.has(findingKey(finding))).length;
  resolvedCount += fixedCount;
  const persistingCount = currentFindings.filter((finding) => baselineMap.has(findingKey(finding))).length;
  const currentInventory = summarizeInventorySnapshot(runtime.actions.inventorySnapshotForRun?.(currentRunId) || null);
  const baselineInventory = summarizeInventorySnapshot(runtime.actions.inventorySnapshotForRun?.(baselineRunId) || null);
  const inventoryDelta = {
    hosts: currentInventory.hosts - baselineInventory.hosts,
    services: currentInventory.services - baselineInventory.services,
    endpoints: currentInventory.endpoints - baselineInventory.endpoints,
  };
  const primaryAction =
    newCount || worsenedCount
      ? { label: "Review Findings", screen: "findings-theater" }
      : inventoryDelta.services > 0 || inventoryDelta.endpoints > 0 || inventoryDelta.hosts > 0
        ? { label: "Inspect Surface", screen: "surface-map" }
        : { label: "Open Explorer", screen: "explorer" };
  return {
    newCount,
    fixedCount,
    persistingCount,
    worsenedCount,
    inventoryCurrent: currentInventory,
    inventoryBaseline: baselineInventory,
    inventoryDelta,
    inventorySummary: formatInventoryDeltaSummary(inventoryDelta),
    packChanged:
      (currentRun.pack_binding?.pack_version || null) !==
      (baselineRun.pack_binding?.pack_version || null),
    baselineLabel: `${baselineRun.profile.name} ${formatDateTime(baselineRun.created_at)}`,
    primaryAction,
    scheduledTrend: buildScheduledTrendComparison({
      currentRun,
      baselineRun,
      currentInventory,
      baselineInventory,
      inventoryDelta,
      newCount,
      fixedCount,
      resolvedCount,
      persistingCount,
      changedCount,
      worsenedCount,
    }),
    changedCount,
    resolvedCount,
    summary: `Compared against ${baselineRun.profile.name}, this run introduced ${newCount} new findings, resolved ${resolvedCount}, kept ${persistingCount} persistent, changed ${changedCount}, and changed inventory by ${formatInventoryDeltaSummary(inventoryDelta).toLowerCase()}.`,
  };
}

function buildScheduledTrendComparison({
  currentRun,
  baselineRun,
  currentInventory,
  baselineInventory,
  inventoryDelta,
  newCount,
  resolvedCount,
  persistingCount,
  changedCount,
  worsenedCount,
}) {
  const currentSchedule = getScheduleMetadata(currentRun);
  const baselineSchedule = getScheduleMetadata(baselineRun);
  if (!currentSchedule && !baselineSchedule) {
    return {
      comparable: false,
      label: "Trend unavailable",
      reason: "Neither run carries scheduled-validation lineage, so AegisPT will not claim continuous drift from this comparison.",
    };
  }
  if (!currentSchedule) {
    return {
      comparable: false,
      label: "Trend unavailable",
      reason: "The current run is not linked to a scheduled-validation record.",
    };
  }
  if (!baselineSchedule) {
    return {
      comparable: false,
      label: "Trend unavailable",
      reason: "The baseline run is not linked to a scheduled-validation record.",
      currentSchedule,
    };
  }
  if (currentSchedule.id !== baselineSchedule.id) {
    return {
      comparable: false,
      label: "Trend unavailable",
      reason: "The selected runs belong to different schedule lineage, so their drift is not treated as a continuous trend.",
      currentSchedule,
      baselineSchedule,
    };
  }
  return {
    comparable: true,
    label: "Comparable scheduled validation",
    reason: `${currentSchedule.cadenceLabel} schedule ${currentSchedule.shortId} has two stored runs available for trend review.`,
    currentSchedule,
    baselineSchedule,
    findingDelta: {
      new: newCount,
      resolved: resolvedCount,
      persistent: persistingCount,
      changed: changedCount,
      worsened: worsenedCount,
    },
    inventoryDelta,
    currentInventory,
    baselineInventory,
  };
}

function buildNextStepsQueue() {
  const findings = runtime.actions.selectedRunFindings?.() || [];
  if (!findings.length) {
    const run = state.selectedRun;
    const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
    const followUp = getFollowUpMetadata(run);
    const hostCount = Number(inventorySnapshot?.summary_json?.host_count || 0);
    const serviceCount = Number(inventorySnapshot?.summary_json?.service_count || 0);
    const endpointCount = Number(inventorySnapshot?.summary_json?.endpoint_count || 0);
    if (run && followUp && inventorySnapshot) {
      const strategy = String(followUp.strategy || "").toLowerCase();
      if (strategy === "service-enumeration" && (serviceCount || hostCount)) {
        return [
          {
            title: "Service identification enriched the discovery estate",
            status: "completed",
            priority: "FOLLOW-UP",
            action: `${serviceCount} services are now linked to ${hostCount} discovered hosts. Review the mapped ports and product hints before choosing deeper internal validation or web profiling.`,
            retest: "Open Surface / Attack Map for the enriched host detail, or trace back to the source discovery run in Explorer and History.",
            actions: [
              { label: "Open Surface Map", screen: "surface-map" },
              { label: "Open Explorer", screen: "explorer" },
              { label: "Open History", screen: "history" },
            ],
          },
        ];
      }
      if (strategy === "web-baseline" && (endpointCount || serviceCount)) {
        return [
          {
            title: "Web profiling is ready for deeper validation review",
            status: "completed",
            priority: "FOLLOW-UP",
            action: `${endpointCount} endpoints and ${serviceCount} linked services were profiled. Review the HTTP titles, status codes, and stack hints before enabling deeper approved web validation.`,
            retest: "Use Explorer or Report Center to review the lineage and evidence context before launching the next bounded run.",
            actions: [
              { label: "Open Surface Map", screen: "surface-map" },
              { label: "Open Reports", screen: "report-center" },
              { label: "Open Explorer", screen: "explorer" },
            ],
          },
        ];
      }
      if (strategy === "approved-range-discovery" && hostCount) {
        return [
          {
            title: "Additional approved-range discovery completed",
            status: "completed",
            priority: "FOLLOW-UP",
            action: `${hostCount} hosts across extra approved CIDR ranges are now available for review. Compare them against the original discovery run before deciding on another controlled follow-up.`,
            retest: "Open History to trace origin and compare runs, or open Surface / Attack Map to inspect the newly mapped ranges.",
            actions: [
              { label: "Open History", screen: "history" },
              { label: "Open Surface Map", screen: "surface-map" },
              { label: "Open Explorer", screen: "explorer" },
            ],
          },
        ];
      }
    }
    if (run && isDiscoveryOnlyRun(run) && (hostCount || serviceCount)) {
      return [
        {
          title: "Inventory run completed without vulnerability findings",
          status: "completed",
          priority: "DISCOVERY",
          action: `${hostCount} hosts and ${serviceCount} services were mapped. Review the discovered surface first, then run a deeper profile if you want actual findings.`,
          retest: "Open Surface / Attack Map for discovered assets or relaunch with broader validation modules.",
          actions: [
            { label: "Open Surface Map", screen: "surface-map" },
            { label: "Open Explorer", screen: "explorer" },
            { label: "Review Mission Control", screen: "mission-control" },
          ],
        },
      ];
    }
    return [];
  }

  return findings
    .filter((finding) => !["resolved", "accepted_risk", "false_positive"].includes(finding.status))
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
    .slice(0, 8)
    .map((finding) => ({
      title: finding.title,
      status: finding.status,
      priority: finding.severity.toUpperCase(),
      action: `Review ${finding.finding_origin === "adaptive_pack" ? "adaptive" : "standard"} evidence and start remediation planning for ${finding.target_id}.`,
      retest:
        "Retest is needed after remediation with the same methodology references still attached.",
    }));
}

function renderComparisonEmptyState() {
  return `
    <div class="comparison-empty-state" data-testid="comparison-empty-guidance">
      <div class="comparison-empty-icon" aria-hidden="true">⇄</div>
      <div class="comparison-empty-copy">
        <h4>Pick a baseline run to compare</h4>
        <p>Choose an earlier run to see finding delta, inventory drift, and whether the selected run expanded or reduced coverage.</p>
      </div>
      <div class="comparison-empty-actions split-top">
        <div class="comparison-empty-action">
          <strong>1</strong>
          <span>Load the current run</span>
        </div>
        <div class="comparison-empty-arrow" aria-hidden="true">→</div>
        <div class="comparison-empty-action">
          <strong>2</strong>
          <span>Set a baseline run</span>
        </div>
      </div>
    </div>
  `;
}

export function createExplorerHistoryModule() {
  function renderExplorer() {
    const groupedByCustomer = groupBy(
      state.engagements,
      (engagement) => engagement.client || "Unassigned Customer"
    );
    dom.customerIndex.innerHTML = Object.entries(groupedByCustomer).length
      ? Object.entries(groupedByCustomer)
          .map(
            ([customer, engagements]) => `
              <div class="list-card">
                <h4>${escapeHtml(customer)}</h4>
                <p>${escapeHtml(`${engagements.length} engagement dossiers`)}</p>
              </div>
            `
          )
          .join("")
      : emptyState("Create a mission in Conversational Intake first. Customers and engagement dossiers populate after the first mission is created.");

    dom.engagementDossiers.innerHTML = state.engagements.length
      ? state.engagements
          .map((engagement) => {
            const runs =
              engagement.id === state.selectedEngagementId
                ? state.mission.runs
                : [];
            return `
              <div class="list-card ${engagement.id === state.selectedEngagementId ? "selected" : ""}" data-engagement-pick="${engagement.id}" data-testid="explorer-engagement-card">
                <h4>${escapeHtml(engagement.name)}</h4>
                <p>${escapeHtml(engagement.client || "No customer")}</p>
                <p class="micro-copy">${escapeHtml(`${runs.length} runs · ${engagement.status}`)}</p>
              </div>
            `;
          })
          .join("")
      : emptyState("No engagement dossiers exist yet. Start in Conversational Intake to create the first mission.");
    dom.engagementDossiers.querySelectorAll("[data-engagement-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedEngagementId = item.dataset.engagementPick;
        await runtime.actions.refreshSelectedEngagement?.();
        state.activeScreen = "explorer";
        runtime.actions.renderScreens?.();
      });
    });

    const run = state.selectedRun;
    if (!run) {
      dom.runDossier.innerHTML = emptyState(
        state.engagements.length
          ? "Select a run to inspect its dossier."
          : "Create a mission first, then load a run here to inspect its dossier."
      );
      return;
    }
    const config = run.configuration_json || {};
    const protectedSecrets = config.access?.secret_storage?.binding_count || 0;
    const missionHandoff = String(config.intake?.confirmation_summary || "").trim();
    const engagementRoute = String(config.intake?.engagement_route || "create-new-engagement");
    const engagementContext = config.intake?.engagement_context || null;
    const intakePreferences = config.intake?.preferences || {};
    const accessAccounts = (config.access?.accounts || []).filter((account) => hasMeaningfulAccount([account]));
    const accessSummary = renderAccessContextSummary(config.access || {});
    const accessContextCount = countMeaningfulAccessContexts(config.access || {});
    const exclusionSummary = summarizeDossierExclusions(config.exclusions || {});
    const acceptance = config.acceptance_metadata || null;
    const followUp = getFollowUpMetadata(run);
    const sourceRun = followUp?.source_run_id
      ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
      : null;
    const inventorySnapshot = runtime.actions.inventorySnapshotForRun?.(run.id) || null;
    const inventorySummary = summarizeInventorySnapshot(inventorySnapshot);
    const findings = state.mission.findingsByRun[run.id] || [];
    const tasks = [...(run.tasks || [])].sort(compareRunTasks);
    const taskSummary = summarizeRunTasks(tasks);
    const executionSummary = summarizeRunExecutions(tasks);
    const dossierFocus = deriveDossierFocus({
      run,
      findings,
      inventorySummary,
      taskSummary,
      followUp,
      sourceRun,
    });
    const selectedTask =
      state.selectedTask && String(state.selectedTask.run_id) === String(run.id)
        ? state.selectedTask
        : null;
    const latestExecution = selectedTask?.executions?.length
      ? [...selectedTask.executions].sort(
          (left, right) => new Date(right.created_at) - new Date(left.created_at)
        )[0]
      : null;
    const selectedReportStatus = state.reportCatalog[0]?.availability_label || (
      state.reportCatalog.length ? "Report lifecycle available" : "No report catalog loaded"
    );
    dom.runDossier.innerHTML = `
      <div class="section-note split-top" data-testid="explorer-consolidation-note">
        <strong>Run dossier review is now report-adjacent</strong>
        <p>Explorer remains available for compatibility and deep inspection, while the practical export-ready dossier summary now appears in Report Center for the selected run.</p>
      </div>
      <div class="detail-surface emphasis-surface split-top" data-testid="dossier-summary-card">
        <h4>Dossier Summary</h4>
        <p>${escapeHtml(dossierFocus.summary)}</p>
        <p class="micro-copy split-top">${escapeHtml(dossierFocus.detail)}</p>
        <div class="detail-grid split-top dossier-summary-grid">
          <div class="detail-surface">
            <h4>Inventory</h4>
            <p>${escapeHtml(`${inventorySummary.hosts} hosts · ${inventorySummary.services} services · ${inventorySummary.endpoints} endpoints`)}</p>
            <p class="micro-copy">${escapeHtml(`${inventorySummary.technologies} technologies · ${inventorySummary.products} product hints`)}</p>
          </div>
          <div class="detail-surface">
            <h4>Evidence</h4>
            <p>${escapeHtml(`${executionSummary.executions} execution records · ${executionSummary.artifacts} artifacts`)}</p>
            <p class="micro-copy">${escapeHtml(`${taskSummary.completed} completed · ${taskSummary.failed} failed · ${taskSummary.queued} queued`)}</p>
          </div>
          <div class="detail-surface">
            <h4>Reports & Pack</h4>
            <p>${escapeHtml(state.reportCatalog.length ? `${state.reportCatalog.length} report variants · ${selectedReportStatus}` : "Report catalog unavailable for this run state")}</p>
            <p class="micro-copy">${escapeHtml(state.reportCatalog[0]?.availability_reason || run.pack_binding?.pack_version || "Standard baseline pack")}</p>
          </div>
          <div class="detail-surface">
            <h4>Next Review</h4>
            <p>${escapeHtml(dossierFocus.nextLabel)}</p>
            <p class="micro-copy">${escapeHtml(dossierFocus.nextDetail)}</p>
          </div>
        </div>
        <div class="panel-actions split-top">
          <button class="action primary" type="button" data-nav-screen="${escapeHtml(dossierFocus.primaryScreen)}">${escapeHtml(dossierFocus.primaryLabel)}</button>
          <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
          <button class="action ghost" type="button" data-nav-screen="report-center">Open Reports</button>
        </div>
      </div>
      ${renderKillChainMatrix(run.kill_chain_progress, { testId: "dossier-mitre-attack-matrix" })}
      <h4>${escapeHtml(run.profile.name)} <span class="badge">${escapeHtml(run.status)}</span></h4>
      <p>${escapeHtml(`Requested by ${run.requested_by} · created ${formatDateTime(run.created_at)}`)}</p>
      ${renderBadgeList([
        config.assessment_type || "Assessment not recorded",
        config.test_profile || run.profile.name,
        `${run.findings.finding_count} findings`,
        `${taskSummary.total} task${taskSummary.total === 1 ? "" : "s"}`,
        acceptance?.scenario_id ? `Acceptance ${acceptance.scenario_id}` : null,
      ], "compact-badge-list split-top")}
      <div class="detail-grid split-top">
        <div class="detail-surface">
          <h4>Configuration</h4>
          <p>${escapeHtml(config.assessment_type || "Not recorded")}</p>
          <p class="micro-copy">${escapeHtml(renderTargetSummary(config.targets || {}))}</p>
        </div>
        <div class="detail-surface">
          <h4>Capability Pack</h4>
          <p>${escapeHtml(run.pack_binding?.pack_version || "Standard baseline")}</p>
          <p class="micro-copy">${escapeHtml(`Inventory ${run.source_inventory_snapshot_id || "n/a"}`)}</p>
        </div>
        <div class="detail-surface">
          <h4>Findings</h4>
          <p>${escapeHtml(`${run.findings.finding_count} total findings`)}</p>
          <p class="micro-copy">${escapeHtml(JSON.stringify(run.findings.findings_by_severity || {}))}</p>
        </div>
        <div class="detail-surface">
          <h4>Protected Access</h4>
          <p>${escapeHtml(`${protectedSecrets} secret binding${protectedSecrets === 1 ? "" : "s"}`)}</p>
          <p class="micro-copy">${escapeHtml(config.access?.secret_storage?.storage_backends?.join(", ") || "No protected bindings recorded")}</p>
        </div>
      </div>
      <div class="detail-surface split-top" data-testid="dossier-mission-handoff">
        <h4>Mission Handoff</h4>
        ${
          missionHandoff
            ? `<p>${escapeHtml(missionHandoff)}</p>`
            : "<p>No natural-language confirmation summary was recorded for this run.</p>"
        }
        <div class="compact-definition-grid split-top" data-testid="dossier-engagement-route">
          <div>
            <span>Engagement Route</span>
            <strong>${escapeHtml(engagementRoute === "reuse-selected-engagement" ? "Reuse existing dossier" : "Create new dossier")}</strong>
          </div>
          <div>
            <span>Engagement Context</span>
            <strong>${escapeHtml(engagementContext?.engagement_name || "Not recorded")}</strong>
          </div>
        </div>
        <div class="compact-definition-grid split-top" data-testid="dossier-authorization-context">
          <div>
            <span>Customer</span>
            <strong>${escapeHtml(engagementContext?.client || run.engagement?.client || "Not recorded")}</strong>
          </div>
          <div>
            <span>ROE Reference</span>
            <strong>${escapeHtml(engagementContext?.roe_ref || run.engagement?.roe_ref || "Not recorded")}</strong>
          </div>
        </div>
        <div class="compact-definition-grid split-top" data-testid="dossier-scope-guardrails">
          <div>
            <span>Output Style</span>
            <strong>${escapeHtml(humanizeOutputStyle(intakePreferences.output_style))}</strong>
          </div>
          <div>
            <span>Boundary Handling</span>
            <strong>${escapeHtml(humanizeBoundaryHandling(intakePreferences.boundary_handling, config.exclusions || {}))}</strong>
          </div>
          <div>
            <span>Exclusions</span>
            <strong>${escapeHtml(exclusionSummary)}</strong>
          </div>
          <div>
            <span>Boundary Notes</span>
            <strong>${escapeHtml(String(config.exclusions?.notes || "").trim() || "Not recorded")}</strong>
          </div>
        </div>
        <p class="micro-copy split-top">${escapeHtml("This is the stored wizard handoff that the deterministic run dossier carried forward after mission creation.")}</p>
      </div>
      <div class="detail-surface split-top" data-testid="dossier-access-contexts">
        <h4>Access Contexts</h4>
        <p>${escapeHtml(accessContextCount ? `${accessContextCount} access context${accessContextCount === 1 ? "" : "s"} recorded` : "No access context recorded")}</p>
        <p class="micro-copy">${escapeHtml(accessSummary)}</p>
        <div class="compact-definition-grid split-top">
          <div>
            <span>Auth Strategy</span>
            <strong>${escapeHtml(humanizeAuthStrategy(intakePreferences.auth_strategy))}</strong>
          </div>
          <div>
            <span>Protected Bindings</span>
            <strong>${escapeHtml(`${protectedSecrets} secret binding${protectedSecrets === 1 ? "" : "s"}`)}</strong>
          </div>
          <div>
            <span>Manual Auth</span>
            <strong>${escapeHtml(String(config.access?.manual_auth_steps || "").trim() || "Not recorded")}</strong>
          </div>
          <div>
            <span>Session Notes</span>
            <strong>${escapeHtml(String(config.access?.cookie_notes || "").trim() || "Not recorded")}</strong>
          </div>
        </div>
        ${
          accessAccounts.length
            ? renderDisclosure({
                title: "Access Detail",
                summary: accessSummary,
                open: false,
                testId: "dossier-access-detail",
                body: accessAccounts
                  .map(
                    (account) => `
                      <div class="detail-surface split-top">
                        <h4>${escapeHtml(account.label || account.username || "Access Context")}</h4>
                        <div class="compact-definition-grid">
                          <div><span>Username</span><strong>${escapeHtml(account.username || "Not recorded")}</strong></div>
                          <div><span>Role</span><strong>${escapeHtml(account.role || "Not recorded")}</strong></div>
                          <div><span>Protected Binding Types</span><strong>${escapeHtml(summarizeAccountBindingKinds(account))}</strong></div>
                          <div><span>MFA Notes</span><strong>${escapeHtml(account.mfa_notes || "Not recorded")}</strong></div>
                        </div>
                      </div>
                    `
                  )
                  .join(""),
              })
            : ""
        }
      </div>
      ${
        followUp
          ? `
            <div class="detail-surface split-top" data-testid="follow-up-lineage-card">
              <h4>Follow-Up Lineage</h4>
              <p>${escapeHtml(`${followUpStrategyLabel(followUp.strategy)} from ${sourceRun?.profile?.name || "a prior run"}`)}</p>
              ${renderBadgeList([
                "Inventory Follow-Up",
                followUpStrategyLabel(followUp.strategy),
                followUp.source_inventory_snapshot_id ? `Inventory ${followUp.source_inventory_snapshot_id}` : null,
                sourceRun?.status ? `Source ${sourceRun.status}` : null,
              ], "compact-badge-list split-top")}
              ${renderDisclosure({
                title: "Lineage Detail",
                summary: sourceRun
                  ? `Derived from ${sourceRun.profile?.name || sourceRun.id}`
                  : "Derived from a prior inventory snapshot",
                open: false,
                testId: "follow-up-lineage-detail",
                body: `
                  <div class="compact-definition-grid">
                    <div><span>Strategy</span><strong>${escapeHtml(followUpStrategyLabel(followUp.strategy))}</strong></div>
                    <div><span>Source Run</span><strong>${escapeHtml(sourceRun?.profile?.name || followUp.source_run_id || "Not recorded")}</strong></div>
                    <div><span>Source Inventory</span><strong>${escapeHtml(followUp.source_inventory_snapshot_id || run.source_inventory_snapshot_id || "Not recorded")}</strong></div>
                    <div><span>Rationale</span><strong>${escapeHtml(followUp.rationale || "Not recorded")}</strong></div>
                  </div>
                `,
              })}
              <div class="panel-actions split-top">
                ${
                  sourceRun
                    ? `
                      <button class="action ghost" type="button" data-follow-up-load-source-run="${escapeHtml(sourceRun.id)}" data-testid="follow-up-load-source-run">Load Source Run</button>
                      <button class="action ghost" type="button" data-follow-up-open-source-surface="${escapeHtml(sourceRun.id)}">Open Source Surface</button>
                    `
                    : ""
                }
              </div>
            </div>
          `
          : ""
      }
      ${
        acceptance
          ? `
            <div class="detail-surface split-top" data-testid="acceptance-support">
              <h4>Acceptance Validation Support</h4>
              <p>${escapeHtml(acceptance.scenario_name || acceptance.scenario_id || "Acceptance scenario")}</p>
              ${renderBadgeList([
                acceptance.target_label || acceptance.target_id || "Safe target",
                acceptance.target_classification || "safe target",
                acceptance.lab_profile || run.profile.name,
                run.status,
              ], "compact-badge-list split-top")}
              ${renderDisclosure({
                title: "Acceptance Detail",
                summary: `${run.findings.finding_count} findings · ${state.reportCatalog.length} report variant${state.reportCatalog.length === 1 ? "" : "s"} · ${selectedTask?.executions?.length || 0} execution record${selectedTask?.executions?.length === 1 ? "" : "s"}`,
                open: false,
                testId: "acceptance-support-detail",
                body: `
                  <div class="compact-definition-grid">
                    <div><span>Scenario</span><strong>${escapeHtml(acceptance.scenario_id || "Not recorded")}</strong></div>
                    <div><span>Safe Target</span><strong>${escapeHtml(acceptance.target_label || acceptance.target_id || "Not recorded")}</strong></div>
                    <div><span>Classification</span><strong>${escapeHtml(acceptance.target_classification || "Not recorded")}</strong></div>
                    <div><span>Profile</span><strong>${escapeHtml(acceptance.lab_profile || run.profile.name)}</strong></div>
                    <div><span>Expected Outputs</span><strong>${escapeHtml((acceptance.expected_outputs || []).join(", ") || "Not recorded")}</strong></div>
                    <div><span>Evidence Linkage</span><strong>${escapeHtml((state.mission.findingsByRun[run.id] || []).some((finding) => finding.evidence_ref) ? "Evidence-linked findings present" : "Open Evidence Replay for direct execution detail")}</strong></div>
                  </div>
                  <div class="panel-actions split-top">
                    <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence</button>
                    <button class="action ghost" type="button" data-nav-screen="report-center">Open Reports</button>
                    <button class="action ghost" type="button" data-nav-screen="history">Open History</button>
                  </div>
                `,
              })}
            </div>
          `
          : ""
      }
      <div class="detail-surface split-top">
        <h4>Run Activity</h4>
        <p>${escapeHtml(`${taskSummary.total} task${taskSummary.total === 1 ? "" : "s"} · ${taskSummary.running} running · ${taskSummary.queued} queued · ${taskSummary.completed} completed · ${taskSummary.failed} failed`)}</p>
        <div class="task-activity-list split-top">
          ${
            tasks.length
              ? tasks
                  .slice(0, 8)
                  .map(
                    (task) => `
                      <button class="task-activity-card ${escapeHtml(String(task.status || "unknown").toLowerCase())} ${task.id === state.selectedTaskId ? "selected" : ""}" type="button" data-run-task-pick="${task.id}">
                        <div class="task-activity-header">
                          <h4>${escapeHtml(task.tool)}</h4>
                          ${statusPill(task.status)}
                        </div>
                        <p>${escapeHtml(task.target_id)}</p>
                        <p class="micro-copy">${escapeHtml(`Queued ${formatDateTime(task.created_at)}`)}</p>
                      </button>
                    `
                  )
                  .join("")
              : emptyState("No run tasks are recorded for this mission.")
          }
        </div>
      </div>
      <div class="detail-grid split-top">
        <div class="detail-surface">
          <h4>Selected Task Detail</h4>
          ${
            selectedTask
              ? `
                <p>${escapeHtml(`${selectedTask.tool} · ${selectedTask.target_id}`)}</p>
                <p class="micro-copy">${escapeHtml(`${selectedTask.executions.length} execution record${selectedTask.executions.length === 1 ? "" : "s"}`)}</p>
                <p class="micro-copy">${escapeHtml(latestExecution ? `Latest exit ${latestExecution.exit_code} · ${latestExecution.tool_version} · ${latestExecution.artifacts.length} artifacts` : "No execution output recorded yet.")}</p>
              `
              : "<p>Select a task above to inspect its latest execution detail.</p>"
          }
        </div>
        <div class="detail-surface">
          <h4>Approvals & Decisions</h4>
        ${
          run.approvals.length
            ? run.approvals
                .map(
                  (approval) =>
                    `<p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.step_id)}</p>`
                )
                .join("")
            : "<p>No approval records on this run.</p>"
        }
        </div>
      </div>
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
        <button class="action ghost" type="button" data-nav-screen="findings-theater">Open Findings</button>
        <button class="action ghost" type="button" data-nav-screen="report-center">Open Reports</button>
      </div>
    `;
    dom.runDossier.querySelectorAll("[data-run-task-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedTaskId = item.dataset.runTaskPick;
        await runtime.actions.loadSelectedTask?.();
        renderExplorer();
      });
    });
    dom.runDossier.querySelectorAll("[data-follow-up-load-source-run]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedRunId = item.dataset.followUpLoadSourceRun;
        await runtime.actions.loadSelectedRun?.();
        runtime.actions.renderAll?.();
      });
    });
    dom.runDossier.querySelectorAll("[data-follow-up-open-source-surface]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedRunId = item.dataset.followUpOpenSourceSurface;
        await runtime.actions.loadSelectedRun?.();
        runtime.actions.navigateToScreen?.("surface-map");
      });
    });
  }

  function renderHistoryRunBulkDeleteBar(selectedCount) {
    if (!selectedCount) return "";
    return `
      <div class="bulk-delete-bar" data-testid="history-bulk-delete-bar">
        <div>
          <strong>${escapeHtml(`${selectedCount} run${selectedCount === 1 ? "" : "s"} selected`)}</strong>
          <p class="micro-copy">Soft-delete keeps evidence recoverable during the 30-day retention window.</p>
        </div>
        <button class="action secondary danger-action" type="button" data-run-delete-preview="selected" data-testid="bulk-delete-runs">
          Delete selected runs
        </button>
      </div>
    `;
  }

  function renderSingleCompletedRunSummary(run) {
    const findings = state.mission.findingsByRun[run.id] || [];
    const open = findings.filter((finding) =>
      ["open", "triaged", "in_progress", "reopened"].includes(finding.status)
    ).length;
    const inventorySummary = summarizeInventorySnapshot(runtime.actions.inventorySnapshotForRun?.(run.id) || null);
    const targetSummary = renderTargetSummary(run.configuration_json?.targets || {});
    return `
      <div data-testid="history-single-run-summary">
        <h4>One completed run available</h4>
        <p>${escapeHtml(`${run.profile?.name || run.id} is ready for review, but posture comparison needs a second completed run.`)}</p>
        <div class="compact-definition-grid split-top">
          <div><span>Status</span><strong>${escapeHtml(run.status || "completed")}</strong></div>
          <div><span>Findings</span><strong>${escapeHtml(`${findings.length} total · ${open} open`)}</strong></div>
          <div><span>Inventory</span><strong>${escapeHtml(`${inventorySummary.hosts} hosts · ${inventorySummary.services} services`)}</strong></div>
          <div><span>Scope</span><strong>${escapeHtml(targetSummary || "Run scope not recorded")}</strong></div>
        </div>
      </div>
      ${renderHistoryComparisonDisabled()}
    `;
  }

  function renderHistoryComparisonDisabled() {
    const reason = "Complete a second run to compare posture changes.";
    return `
      <div class="detail-surface split-top" data-testid="history-comparison-disabled" title="${escapeHtml(reason)}">
        <h4>Comparison unavailable</h4>
        <p>${escapeHtml(reason)}</p>
      </div>
    `;
  }

  function renderHistoryComparison() {
    const sortedRuns = [...state.mission.runs].sort(
      (left, right) => new Date(right.created_at) - new Date(left.created_at)
    );
    const completedRuns = sortedRuns.filter(isCompletedHistoryRun);
    const currentHistoryRunId = completedRuns.some((run) => run.id === state.selectedRunId)
      ? state.selectedRunId
      : completedRuns[0]?.id || null;
    const baselineHistoryRunId = completedRuns.some(
      (run) => run.id === state.comparisonBaselineRunId && run.id !== currentHistoryRunId
    )
      ? state.comparisonBaselineRunId
      : completedRuns.find((run) => run.id !== currentHistoryRunId)?.id || null;
    const historyQuery = String(state.historyQuery || "").trim();
    const normalizedHistoryQuery = historyQuery.toLowerCase();
    const filteredRuns = completedRuns.filter((run) => {
      if (!normalizedHistoryQuery) return true;
      const followUp = getFollowUpMetadata(run);
      const sourceRun = followUp?.source_run_id
        ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
        : null;
      const inventorySummary = summarizeInventorySnapshot(runtime.actions.inventorySnapshotForRun?.(run.id) || null);
      return historySearchText(run, sourceRun, inventorySummary).includes(normalizedHistoryQuery);
    });
    const selectedDeleteRunIds = new Set(state.deleteUi?.selectedRunIds || []);
    const visibleSelectedCount = filteredRuns.filter((run) => selectedDeleteRunIds.has(String(run.id))).length;
    const currentRunDisabled = completedRuns.length <= 1 ? "disabled" : "";
    const baselineDisabled = completedRuns.length < 2
      ? `disabled title="${escapeHtml("Complete a second run to compare posture changes.")}"`
      : "";
    dom.historyToolbar.innerHTML = `
      <label class="field compact">
        <span>Current Run</span>
        <select id="history-current-run" data-testid="history-current-run" ${currentRunDisabled}>
          ${completedRuns.length
            ? completedRuns
                .map(
                  (run) =>
                    `<option value="${run.id}" ${run.id === currentHistoryRunId ? "selected" : ""}>${escapeHtml(run.profile?.name || run.id)} · ${escapeHtml(run.status)}</option>`
                )
                .join("")
            : '<option value="">No completed runs</option>'}
        </select>
      </label>
      <label class="field compact">
        <span>Baseline Run</span>
        <select id="history-baseline-run" ${baselineDisabled}>
          <option value="">No baseline</option>
          ${completedRuns
            .filter((run) => run.id !== currentHistoryRunId)
            .map(
              (run) =>
                `<option value="${run.id}" ${run.id === baselineHistoryRunId ? "selected" : ""}>${escapeHtml(run.profile?.name || run.id)} · ${escapeHtml(run.status)}</option>`
            )
            .join("")}
        </select>
      </label>
      <label class="field compact">
        <span>Find Run</span>
        <input
          id="history-search"
          type="search"
          value="${escapeHtml(historyQuery)}"
          placeholder="Search by profile, status, target, or follow-up lineage"
          data-testid="history-search"
        />
      </label>
      <div class="section-note toolbar-note" data-testid="history-toolbar-summary">
        <strong>${escapeHtml(`${filteredRuns.length} of ${completedRuns.length} completed runs visible`)}</strong>
        <p>${escapeHtml("Filter the dossier history without losing direct load, compare, or surface actions.")}</p>
      </div>
    `;
    document.getElementById("history-current-run")?.addEventListener("change", async (event) => {
      state.selectedRunId = event.target.value;
      await runtime.actions.loadSelectedRun?.();
      await runtime.actions.ensureComparisonFindings?.();
      runtime.actions.renderAll?.();
    });
    document.getElementById("history-baseline-run")?.addEventListener("change", async (event) => {
      state.comparisonBaselineRunId = event.target.value || null;
      await runtime.actions.ensureComparisonFindings?.();
      renderHistoryComparison();
      runtime.actions.renderReportCenter?.();
    });
    document.getElementById("history-search")?.addEventListener("input", (event) => {
      state.historyQuery = event.target.value || "";
      renderHistoryComparison();
    });

    const comparison = completedRuns.length >= 2 ? compareRuns(currentHistoryRunId, baselineHistoryRunId) : null;
    const exposure = state.exposureScore;
    dom.comparisonSummary.innerHTML = comparison
      ? `
        <h4>${escapeHtml("Current vs baseline")}</h4>
        <p>${escapeHtml(`${comparison.newCount} new · ${comparison.resolvedCount} resolved · ${comparison.persistingCount} persistent · ${comparison.changedCount} changed`)}</p>
        <p>${escapeHtml(`${comparison.worsenedCount} worsened · pack changed ${comparison.packChanged ? "yes" : "no"}`)}</p>
        <div class="detail-grid split-top comparison-grid">
          <div class="detail-surface">
            <h4>Finding Delta</h4>
            <p>${escapeHtml(`${comparison.newCount} new · ${comparison.resolvedCount} resolved · ${comparison.persistingCount} persistent · ${comparison.changedCount} changed`)}</p>
            <p class="micro-copy">${escapeHtml(`${comparison.worsenedCount} worsened findings compared with ${comparison.baselineLabel}. Missing baseline findings count as resolved only for this stored comparison, not as guaranteed remediation.`)}</p>
          </div>
          <div class="detail-surface" data-testid="comparison-inventory-delta">
            <h4>Inventory Delta</h4>
            <p>${escapeHtml(comparison.inventorySummary)}</p>
            <p class="micro-copy">${escapeHtml(`Current ${comparison.inventoryCurrent.hosts} hosts / ${comparison.inventoryCurrent.services} services / ${comparison.inventoryCurrent.endpoints} endpoints · baseline ${comparison.inventoryBaseline.hosts} / ${comparison.inventoryBaseline.services} / ${comparison.inventoryBaseline.endpoints}`)}</p>
          </div>
        </div>
        ${renderContinuousTrendDeltaPanel(comparison)}
        <p class="micro-copy">${escapeHtml(comparison.summary)}</p>
        <div class="panel-actions">
          <button class="action primary" type="button" data-nav-screen="${escapeHtml(comparison.primaryAction.screen)}">${escapeHtml(comparison.primaryAction.label)}</button>
          <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
          <button class="action ghost" type="button" data-nav-screen="findings-theater">Review Findings</button>
        </div>
      `
      : completedRuns.length === 1
        ? renderSingleCompletedRunSummary(completedRuns[0])
        : renderHistoryComparisonDisabled();

    dom.historyTrend.innerHTML = filteredRuns.length
      ? [
          renderHistoryRunBulkDeleteBar(visibleSelectedCount),
          renderExposureHistoryPanel(exposure),
          ...filteredRuns
          .map((run) => {
            const findings = state.mission.findingsByRun[run.id] || [];
            const open = findings.filter((finding) =>
              ["open", "triaged", "in_progress", "reopened"].includes(finding.status)
            ).length;
            const inventorySnapshot = runtime.actions.inventorySnapshotForRun?.(run.id) || null;
            const inventorySummary = summarizeInventorySnapshot(inventorySnapshot);
            const followUp = getFollowUpMetadata(run);
            const schedule = getScheduleMetadata(run);
            const sourceRun = followUp?.source_run_id
              ? state.mission.runs.find((candidate) => String(candidate.id) === String(followUp.source_run_id)) || null
              : null;
            const targetSummary = renderTargetSummary(run.configuration_json?.targets || {});
            const percent = Math.min(100, findings.length * 12);
            const reviewHint = deriveHistoryReviewHint(run, findings, inventorySummary, followUp);
            return `
              <div class="trend-card list-card ${run.id === currentHistoryRunId ? "selected" : ""}" data-history-run-pick="${run.id}" data-testid="history-run-card">
                <div class="panel-head compact-head">
                  <div>
                    <label class="delete-checkline history-run-delete-toggle" data-run-delete-control>
                      <input
                        type="checkbox"
                        data-run-delete-toggle="${escapeHtml(run.id)}"
                        ${selectedDeleteRunIds.has(String(run.id)) ? "checked" : ""}
                        aria-label="Select run for deletion"
                      />
                      <span>
                        <strong class="history-run-title">${escapeHtml(run.profile?.name || run.id)}</strong>
                        <small>${escapeHtml(run.id === currentHistoryRunId ? "Current run loaded in the operator views." : "Click to load this run across Mission Control, Findings, Surface Map, and Reports.")}</small>
                      </span>
                    </label>
                  </div>
                  <div class="pill-grid">
                    ${run.id === currentHistoryRunId ? '<span class="badge">Current Run</span>' : ""}
                    ${run.id === baselineHistoryRunId ? '<span class="badge">Baseline</span>' : ""}
                    ${schedule ? `<span class="badge">${escapeHtml(`Scheduled ${schedule.cadenceLabel}`)}</span>` : ""}
                    <details class="run-card-menu" data-run-delete-control>
                      <summary aria-label="Run actions">...</summary>
                      <button class="action ghost tiny danger-action" type="button" data-run-delete-preview="${escapeHtml(run.id)}" data-testid="history-delete-run" aria-label="${escapeHtml(`Delete run ${run.name || run.id}`)}">Delete</button>
                    </details>
                  </div>
                </div>
                <p>${statusPill(run.status)} ${escapeHtml(`${findings.length} findings · ${open} still open`)}</p>
                ${
                  schedule
                    ? `<p class="micro-copy">${escapeHtml(`Scheduled validation ${schedule.shortId} · due ${formatDateTime(schedule.dueAt)}`)}</p>`
                    : ""
                }
                ${
                  followUp
                    ? `<p class="micro-copy">${escapeHtml(`${followUpStrategyLabel(followUp.strategy)} from ${sourceRun?.profile?.name || followUp.source_run_id || "a prior run"}`)}</p>`
                    : ""
                }
                <p class="micro-copy">${escapeHtml(targetSummary || "Run scope not recorded")}</p>
                <p class="micro-copy">${escapeHtml(`${inventorySummary.hosts} hosts and ${inventorySummary.services} services in linked inventory snapshot`)}</p>
                <p class="micro-copy">${escapeHtml(`Pack ${run.pack_binding?.pack_version || "standard baseline"}`)}</p>
                <p class="micro-copy">${escapeHtml(reviewHint)}</p>
                <div class="history-bar split-top"><span style="width:${percent}%"></span></div>
                <div class="panel-actions split-top history-run-actions">
                  <button class="action ghost tiny" type="button" data-history-load-run="${run.id}" data-testid="history-load-run">Load Run</button>
                  <button class="action ghost tiny" type="button" data-history-set-baseline="${run.id}" data-testid="history-set-baseline">Set Baseline</button>
                  <button class="action ghost tiny" type="button" data-history-open-surface="${run.id}" data-testid="history-open-surface">Open Surface</button>
                  ${
                    sourceRun
                      ? `<button class="action ghost tiny" type="button" data-history-trace-origin="${escapeHtml(sourceRun.id)}" data-testid="history-trace-origin">Trace Origin</button>`
                      : ""
                  }
                </div>
                <p class="micro-copy split-top">${escapeHtml(formatDateTime(run.created_at))}</p>
              </div>
            `;
          }),
        ].join("")
      : emptyState(
          historyQuery
            ? `No runs match "${historyQuery}". Clear or widen the history search.`
            : "Completed runs appear here after an assessment finishes.",
          historyQuery
            ? null
            : { label: "Go to Mission Control", screen: "mission-control", className: "primary", testId: "history-empty-mission-control" }
        );
    dom.historyTrend.querySelectorAll("[data-history-run-pick]").forEach((item) => {
      item.addEventListener("click", async (event) => {
        if (event.target.closest("[data-run-delete-control]")) return;
        state.selectedRunId = item.dataset.historyRunPick;
        if (!state.comparisonBaselineRunId || state.comparisonBaselineRunId === state.selectedRunId) {
          state.comparisonBaselineRunId =
            state.mission.runs.find((run) => run.id !== state.selectedRunId)?.id || null;
        }
        await runtime.actions.loadSelectedRun?.();
        await runtime.actions.ensureComparisonFindings?.();
        renderHistoryComparison();
        runtime.actions.renderFlowOverview?.();
      });
    });
    dom.historyTrend.querySelectorAll("[data-history-load-run]").forEach((item) => {
      item.addEventListener("click", async (event) => {
        event.stopPropagation();
        state.selectedRunId = item.dataset.historyLoadRun;
        if (!state.comparisonBaselineRunId || state.comparisonBaselineRunId === state.selectedRunId) {
          state.comparisonBaselineRunId =
            state.mission.runs.find((run) => run.id !== state.selectedRunId)?.id || null;
        }
        await runtime.actions.loadSelectedRun?.();
        await runtime.actions.ensureComparisonFindings?.();
        renderHistoryComparison();
        runtime.actions.renderFlowOverview?.();
      });
    });
    dom.historyTrend.querySelectorAll("[data-history-set-baseline]").forEach((item) => {
      item.addEventListener("click", async (event) => {
        event.stopPropagation();
        const baselineId = item.dataset.historySetBaseline;
        if (baselineId === state.selectedRunId) {
          state.selectedRunId =
            state.mission.runs.find((run) => run.id !== baselineId)?.id || state.selectedRunId;
          await runtime.actions.loadSelectedRun?.();
        }
        state.comparisonBaselineRunId = baselineId;
        await runtime.actions.ensureComparisonFindings?.();
        renderHistoryComparison();
        runtime.actions.renderFlowOverview?.();
      });
    });
    dom.historyTrend.querySelectorAll("[data-history-open-surface]").forEach((item) => {
      item.addEventListener("click", async (event) => {
        event.stopPropagation();
        state.selectedRunId = item.dataset.historyOpenSurface;
        await runtime.actions.loadSelectedRun?.();
        await runtime.actions.ensureComparisonFindings?.();
        runtime.actions.navigateToScreen?.("surface-map");
      });
    });
    dom.historyTrend.querySelectorAll("[data-history-trace-origin]").forEach((item) => {
      item.addEventListener("click", async (event) => {
        event.stopPropagation();
        state.selectedRunId = item.dataset.historyTraceOrigin;
        await runtime.actions.loadSelectedRun?.();
        await runtime.actions.ensureComparisonFindings?.();
        runtime.actions.navigateToScreen?.("explorer");
      });
    });

    const nextSteps = buildNextStepsQueue();
    dom.nextStepsQueue.innerHTML = nextSteps.length
      ? nextSteps
          .map(
            (item) => `
              <div class="list-card">
                <h4>${escapeHtml(item.title)}</h4>
                <p>${statusPill(item.status)} ${escapeHtml(item.priority)}</p>
                <p>${escapeHtml(item.action)}</p>
                <p class="micro-copy">${escapeHtml(item.retest)}</p>
                ${
                  item.actions?.length
                    ? `
                      <div class="panel-actions split-top">
                        ${item.actions
                          .map(
                            (action) =>
                              `<button class="action ghost" type="button" data-nav-screen="${escapeHtml(action.screen)}">${escapeHtml(action.label)}</button>`
                          )
                          .join("")}
                      </div>
                    `
                    : ""
                }
              </div>
            `
          )
          .join("")
      : emptyState("Open findings and their recommended follow-up actions appear here.");
  }

  function renderExposureHistoryPanel(exposure) {
    const current = exposure?.current || null;
    const history = Array.isArray(exposure?.history) ? exposure.history : [];
    if (!current) {
      return `
        <div class="detail-surface split-top" data-testid="exposure-history-panel">
          <h4>Exposure Score History</h4>
          <p>Exposure history appears after posture scoring has been computed for the engagement.</p>
          <p class="micro-copy">Advisory only; this summary never gates runs or approvals.</p>
        </div>
      `;
    }
    return `
      <div class="detail-surface split-top exposure-history-panel" data-testid="exposure-history-panel">
        <div class="panel-head compact-head">
          <div>
            <h4>Exposure Score History</h4>
            <p class="micro-copy">Advisory only; this score summarizes stored posture and does not guarantee security improvement.</p>
          </div>
          <span class="metric-pill">${escapeHtml(`${formatExposureScore(current.score)}/100 · ${exposureTrendLabel(current.trend)}`)}</span>
        </div>
        ${renderExposureSparkline(history, {
          width: 520,
          height: 52,
          className: "history-exposure-sparkline",
          testId: "history-exposure-sparkline",
        })}
        <div class="compact-definition-grid split-top">
          <div><span>Critical Open</span><strong>${escapeHtml(String(current.open_critical_count))}</strong></div>
          <div><span>High Open</span><strong>${escapeHtml(String(current.open_high_count))}</strong></div>
          <div><span>Remediated</span><strong>${escapeHtml(String(current.remediated_count))}</strong></div>
          <div><span>Verified</span><strong>${escapeHtml(String(current.verified_count))}</strong></div>
        </div>
        <div class="split-top exposure-history-points">
          ${history
            .map(
              (point) => `
                <div class="metric-pill exposure-history-point">
                  ${escapeHtml(`${formatDateTime(point.computed_at)} · ${formatExposureScore(point.score)}/100 · ${exposureTrendLabel(point.trend)}`)}
                </div>
              `
            )
            .join("")}
        </div>
      </div>
    `;
  }

  return {
    buildNextStepsQueue,
    compareRuns,
    renderExplorer,
    renderHistoryComparison,
  };
}

function compareRunTasks(left, right) {
  const statusOrder = {
    running: 0,
    queued: 1,
    failed: 2,
    completed: 3,
    cancelled: 4,
  };
  const leftScore = statusOrder[String(left.status || "unknown").toLowerCase()] ?? 5;
  const rightScore = statusOrder[String(right.status || "unknown").toLowerCase()] ?? 5;
  if (leftScore !== rightScore) return leftScore - rightScore;
  return new Date(right.created_at) - new Date(left.created_at);
}

function summarizeRunTasks(tasks) {
  return tasks.reduce(
    (summary, task) => {
      summary.total += 1;
      const normalized = String(task.status || "unknown").toLowerCase();
      if (normalized in summary) summary[normalized] += 1;
      return summary;
    },
    { total: 0, running: 0, queued: 0, completed: 0, failed: 0, cancelled: 0 }
  );
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

function summarizeInventorySnapshot(snapshot) {
  const normalized = snapshot?.normalized_inventory_json || {};
  const summary = snapshot?.summary_json || {};
  return {
    hosts: Number(summary.host_count || (normalized.hosts || []).length || 0),
    services: Number(summary.service_count || (normalized.services || []).length || 0),
    endpoints: Number(summary.endpoint_count || (normalized.http_endpoints || []).length || 0),
    technologies: Number(summary.technology_count || (normalized.technologies || []).length || 0),
    products: Number(summary.vendor_product_count || (normalized.vendor_product_fingerprints || []).length || 0),
  };
}

function summarizeRunExecutions(tasks) {
  return (tasks || []).reduce(
    (summary, task) => {
      const executions = Array.isArray(task.executions) ? task.executions : [];
      summary.executions += executions.length;
      summary.artifacts += executions.reduce(
        (artifactTotal, execution) => artifactTotal + (Array.isArray(execution.artifacts) ? execution.artifacts.length : 0),
        0
      );
      return summary;
    },
    { executions: 0, artifacts: 0 }
  );
}

function deriveDossierFocus({ run, findings, inventorySummary, taskSummary, followUp, sourceRun }) {
  if (findings.length) {
    return {
      summary: `${findings.length} findings are attached to this run dossier and evidence is ready for triage, replay, and reporting.`,
      detail: "Use Findings Theater for prioritization, then keep Evidence Replay and Report Center nearby for validation and communication.",
      nextLabel: "Review findings and evidence",
      nextDetail: "Open Findings Theater first, then move into Evidence Replay for reproduction detail.",
      primaryLabel: "Open Findings",
      primaryScreen: "findings-theater",
    };
  }
  if (followUp) {
    return {
      summary: `${followUpStrategyLabel(followUp.strategy)} stayed tied to discovery-confirmed inventory instead of broadening scope silently.`,
      detail: sourceRun
        ? `The run is derived from ${sourceRun.profile?.name || sourceRun.id} and should be reviewed as a follow-up enrichment step, not a standalone empty run.`
        : "The run is tied to a prior inventory snapshot and should be reviewed through lineage-aware surfaces.",
      nextLabel: "Inspect enriched estate context",
      nextDetail: "Open Surface Map or History to see what the follow-up added before launching deeper validation.",
      primaryLabel: "Open Surface Map",
      primaryScreen: "surface-map",
    };
  }
  if (isDiscoveryOnlyRun(run) && (inventorySummary.hosts || inventorySummary.services || inventorySummary.endpoints)) {
    return {
      summary: "This dossier represents a discovery-first run, so the operator value is the mapped estate and the next bounded follow-up action.",
      detail: "Zero findings are expected here until a deeper controlled follow-up run is launched from the discovered surface.",
      nextLabel: "Review discovered assets",
      nextDetail: "Open Surface Map or History to move from inventory into service identification or web profiling.",
      primaryLabel: "Open Surface Map",
      primaryScreen: "surface-map",
    };
  }
  if (taskSummary.running || taskSummary.queued) {
    return {
      summary: "Execution is still active or queued, so this dossier should be used as a live control surface instead of a finished review pack.",
      detail: "Mission Control will show the clearest live run state while the dossier keeps task, approval, and configuration context nearby.",
      nextLabel: "Return to live execution",
      nextDetail: "Use Mission Control for the current activity, ETA, and blocked/failure reasons.",
      primaryLabel: "Open Mission Control",
      primaryScreen: "mission-control",
    };
  }
  return {
    summary: "This run dossier is complete enough for post-run review across inventory, evidence, approvals, and report preparation.",
    detail: "Use History for delta review or Report Center for a client-facing output built from the same run context.",
    nextLabel: "Review reports and history",
    nextDetail: "Open History for change tracking or Report Center for export-ready variants.",
    primaryLabel: "Open History",
    primaryScreen: "history",
  };
}

function deriveHistoryReviewHint(run, findings, inventorySummary, followUp) {
  const schedule = getScheduleMetadata(run);
  if (schedule) {
    return "Compare this scheduled validation run against another run from the same schedule before claiming trend or drift.";
  }
  if (findings.length) {
    return "Load this run for finding triage, evidence replay, and report export.";
  }
  if (followUp) {
    return "Trace origin or open Surface Map to review what this follow-up added to the discovered estate.";
  }
  if (isDiscoveryOnlyRun(run) && (inventorySummary.hosts || inventorySummary.services || inventorySummary.endpoints)) {
    return "Open Surface Map to inspect discovered assets and choose the next controlled follow-up.";
  }
  return "Load this run to review its dossier, task state, and available next actions.";
}

function historySearchText(run, sourceRun, inventorySummary) {
  const schedule = getScheduleMetadata(run);
  return [
    run.profile?.name,
    run.status,
    run.id,
    run.configuration_json?.assessment_type,
    run.configuration_json?.test_profile,
    renderTargetSummary(run.configuration_json?.targets || {}),
    sourceRun?.profile?.name,
    sourceRun?.id,
    getFollowUpMetadata(run)?.strategy ? followUpStrategyLabel(getFollowUpMetadata(run).strategy) : "",
    schedule ? "scheduled validation" : "",
    schedule?.id,
    schedule?.cadence,
    schedule?.shortId,
    `${inventorySummary.hosts} hosts`,
    `${inventorySummary.services} services`,
    `${inventorySummary.endpoints} endpoints`,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function formatInventoryDeltaSummary(delta) {
  return [
    formatNamedDelta(delta.hosts, "host"),
    formatNamedDelta(delta.services, "service"),
    formatNamedDelta(delta.endpoints, "endpoint"),
  ].join(" · ");
}

function formatNamedDelta(value, label) {
  const abs = Math.abs(Number(value || 0));
  const plural = abs === 1 ? label : `${label}s`;
  if (value > 0) return `+${abs} ${plural}`;
  if (value < 0) return `-${abs} ${plural}`;
  return `${plural} unchanged`;
}

function renderContinuousTrendDeltaPanel(comparison) {
  const trend = comparison?.scheduledTrend || null;
  if (!trend) return "";
  if (!trend.comparable) {
    return `
      <div class="detail-surface split-top" data-testid="continuous-trend-delta">
        <div class="task-activity-header">
          <div>
            <h4>Scheduled Validation Trend</h4>
            <p class="micro-copy">${escapeHtml(trend.reason || "This baseline is not comparable for scheduled trend review.")}</p>
          </div>
          <span class="metric-pill">${escapeHtml(trend.label || "Trend unavailable")}</span>
        </div>
      </div>
    `;
  }
  const findingDelta = trend.findingDelta || {};
  return `
    <div class="detail-surface split-top" data-testid="continuous-trend-delta">
      <div class="task-activity-header">
        <div>
          <h4>Scheduled Validation Trend</h4>
          <p class="micro-copy">${escapeHtml(trend.reason)}</p>
        </div>
        <span class="metric-pill">${escapeHtml(trend.label)}</span>
      </div>
      <div class="compact-definition-grid split-top">
        <div><span>New Findings</span><strong>${escapeHtml(String(findingDelta.new || 0))}</strong></div>
        <div><span>Resolved Findings</span><strong>${escapeHtml(String(findingDelta.resolved || 0))}</strong></div>
        <div><span>Persistent Findings</span><strong>${escapeHtml(String(findingDelta.persistent || 0))}</strong></div>
        <div><span>Changed Findings</span><strong>${escapeHtml(String(findingDelta.changed || 0))}</strong></div>
        <div><span>Inventory Drift</span><strong>${escapeHtml(formatInventoryDeltaSummary(trend.inventoryDelta || {}))}</strong></div>
        <div><span>Due Window</span><strong>${escapeHtml(formatDateTime(trend.currentSchedule?.dueAt))}</strong></div>
      </div>
      <p class="micro-copy split-top">${escapeHtml("Trend output is limited to comparable stored runs from the same schedule lineage. It is not a risk-reduction guarantee and does not launch or schedule work.")}</p>
    </div>
  `;
}

function getScheduleMetadata(run) {
  const schedule = run?.configuration_json?.schedule;
  if (!schedule || typeof schedule !== "object") return null;
  const source = String(schedule.source || "").toLowerCase();
  const id = String(schedule.scheduled_run_id || "").trim();
  if (source !== "scheduled-validation" || !id) return null;
  const cadence = String(schedule.cadence || "scheduled").trim() || "scheduled";
  return {
    id,
    shortId: id.length > 12 ? `${id.slice(0, 8)}…` : id,
    cadence,
    cadenceLabel: cadence.replace(/[-_]/g, " "),
    cron: schedule.cron_expression || "",
    dueAt: schedule.scheduled_due_at || run.created_at || null,
  };
}

function isResolvedFindingStatus(status) {
  return ["resolved", "accepted_risk", "false_positive", "dismissed"].includes(
    String(status || "").toLowerCase()
  );
}

function isCompletedHistoryRun(run) {
  const normalized = String(run?.status || "").toLowerCase().replace(/[\s-]+/g, "_");
  return normalized === "complete" || normalized === "completed" || normalized.startsWith("completed_");
}
