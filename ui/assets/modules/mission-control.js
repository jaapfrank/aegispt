import { dom, runtime, state } from "./runtime.js";
import {
  countScopeTargets,
  emptyState,
  enabledModules,
  escapeHtml,
  formatDurationLabel,
  formatElapsedMinutes,
  hasMeaningfulAccount,
  lineSvg,
  minutesSince,
  renderSignalList,
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
        <button class="action ghost" type="button" data-nav-screen="${escapeHtml(activity.primaryAction.screen)}">${escapeHtml(activity.primaryAction.label)}</button>
        <button class="action ghost" type="button" data-nav-screen="${escapeHtml(activity.secondaryAction.screen)}">${escapeHtml(activity.secondaryAction.label)}</button>
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
    dom.missionFindingsPulse.innerHTML = `
      <h4>${escapeHtml(`${pulse.confirmed} confirmed · ${pulse.suspected} suspected · ${pulse.dismissed} dismissed`)}</h4>
      <p>${escapeHtml(`${pulse.critical} high-priority items · ${pulse.evidence_completeness}% evidence completeness`)}</p>
      <p class="micro-copy">${escapeHtml(`Methodology coverage: ${pulse.coverage}`)}</p>
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="findings-theater">Open Findings Theater</button>
        <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Evidence Replay</button>
      </div>
    `;

    dom.missionAiNarrative.innerHTML = renderStringCards(buildNarratives(), "AI narrative appears as soon as inventory, adaptive decisions, or findings exist.");
    dom.missionPackStatus.innerHTML = renderPackStatusSummary();
    dom.missionScopeSummary.innerHTML = renderScopeProfileSummary();
  }

  function buildMissionPhases() {
    const run = state.selectedRun;
    const config = run?.configuration_json || {};
    const inventory = runtime.actions.latestInventorySnapshot?.();
    const relevance = runtime.actions.latestRelevanceDecision?.();
    const pack = runtime.actions.selectedPack?.();
    const tasks = run?.tasks || [];
    const findings = runtime.actions.selectedRunFindings?.() || [];
    const hasAccounts = hasMeaningfulAccount(config.access?.accounts || []);
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
        summary: inventory ? `${inventory.summary_json.host_count} hosts seeded or discovered.` : "Waiting for inventory seed or discovery activity.",
      },
      {
        key: "surface",
        label: "Surface Mapping",
        status: inventory ? "complete" : "pending",
        progress: inventory ? 100 : 0,
        summary: inventory ? `${inventory.summary_json.endpoint_count} endpoints and ${inventory.summary_json.technology_count} technologies mapped.` : "No mapped surface yet.",
      },
      {
        key: "auth",
        label: "Auth Access",
        status: activeProfileNeedsAuth && !hasAccounts ? "blocked" : (hasAccounts || !activeProfileNeedsAuth ? "complete" : "pending"),
        progress: hasAccounts || !activeProfileNeedsAuth ? 100 : 10,
        summary: hasAccounts ? `${config.access.accounts.length} role contexts loaded.` : activeProfileNeedsAuth ? "Assessment expects authenticated access but no credentials are configured." : "No dedicated auth context required.",
      },
      {
        key: "analysis",
        label: "Deep Analysis",
        status: run?.status === "pending_approval" ? "blocked" : tasks.length ? (deepProgress >= 100 ? "complete" : "active") : (run ? "pending" : "pending"),
        progress: run?.status === "pending_approval" ? 10 : deepProgress,
        summary: tasks.length ? `${taskCounts.completed} complete, ${taskCounts.queued} queued, ${taskCounts.running} running.` : "Run exists but no deep-analysis tasks are queued yet.",
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
    const inventory = runtime.actions.latestInventorySnapshot?.();
    const config = state.selectedRun?.configuration_json || {};
    const good = [];
    const bad = [];
    const unknown = [];

    if (inventory) good.push(`Inventory confidence is ${toPercent(inventory.confidence_score)} and the surface model is ready for mapping.`);
    if (pack && ["validated", "approved", "deployed"].includes(pack.status)) good.push(`Selected adaptive pack ${pack.version} is ${pack.status}.`);
    if (state.selectedRun?.status === "queued") good.push("Run tasks are queued and ready for dispatch.");
    if (findings.some((finding) => finding.evidence_ref)) good.push("Evidence-linked findings are already available for replay.");

    if (state.selectedRun?.status === "pending_approval") bad.push("Run launch is blocked pending approval.");
    if (pack && pack.status === "validation_failed") bad.push("The latest adaptive pack failed validation and cannot be promoted.");
    if (requiresCredentials(config) && !hasMeaningfulAccount(config.access?.accounts || [])) bad.push("The mission profile expects authenticated access but no usable account context is stored.");
    if (findings.some((finding) => finding.severity === "critical")) bad.push("Critical findings are present and should be prioritized in remediation and reporting.");

    if (!inventory) unknown.push("No inventory snapshot exists yet for attack-map and coverage decisions.");
    if (!state.mission.relevance.length && config.safety?.adaptive_generation !== false) unknown.push("No relevance analysis exists yet for adaptive testing decisions.");
    if (!state.reportCatalog.length && state.selectedRun) unknown.push("Reports have not been previewed yet for this run.");
    if (findings.some((finding) => finding.severity === "unknown")) unknown.push("At least one finding still has unknown severity and needs analyst review.");

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
    const findings = runtime.actions.selectedRunFindings?.() || [];
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
      <p>${escapeHtml(`${validations.length} validations · ${deployments.length} deployments`)}</p>
      <p class="micro-copy">${escapeHtml(`Runtime binding: ${bound?.pack_version || "standard baseline"}`)}</p>
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
    return `
      <h4>${escapeHtml(config.assessment_type || "Assessment not recorded")}</h4>
      <p>${escapeHtml(config.test_profile || run.profile.name)}</p>
      <p>${escapeHtml(renderTargetSummary(targets))}</p>
      <p>${escapeHtml(`${enabledModules(config.modules || {}).join(", ") || "No modules recorded"}`)}</p>
      <p class="micro-copy">${escapeHtml(`${accounts.length} account / role contexts · RPS ${config.safety?.rate_limit_rps || "n/a"} · concurrency ${config.safety?.concurrency || "n/a"}`)}</p>
    `;
  }

  function renderSurfaceMap() {
    const snapshot = runtime.actions.latestInventorySnapshot?.();
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
      dom.surfaceMapCanvas.innerHTML = emptyState("The surface map needs an inventory snapshot. The wizard seeds one automatically for new missions.");
      dom.surfaceInsights.innerHTML = emptyState("Surface insights will appear after inventory is available.");
      dom.surfaceLegend.innerHTML = emptyState("Legend data will populate with mapped assets and overlays.");
      return;
    }

    const inventory = snapshot.normalized_inventory_json || {};
    const hosts = inventory.hosts || [];
    const endpoints = inventory.http_endpoints || [];
    const technologies = inventory.technologies || [];
    const fingerprints = inventory.vendor_product_fingerprints || [];
    const nodes = [
      ...hosts.map((host, index) => ({ kind: "host", title: host.host, meta: `${toPercent(host.confidence)} confidence`, left: 8, top: 18 + index * 16 })),
      ...endpoints.map((endpoint, index) => ({ kind: "endpoint", title: endpoint.url, meta: `${(endpoint.methods || []).join(", ") || "GET"} · ${endpoint.status_code || "unknown"}`, left: 40, top: 18 + index * 16 })),
      ...technologies.map((tech, index) => ({ kind: "tech", title: tech.name, meta: `${tech.vendor || "unknown vendor"} · ${toPercent(tech.confidence)}`, left: 72, top: 18 + index * 16 })),
    ];
    if (!technologies.length) {
      fingerprints.slice(0, 3).forEach((fingerprint, index) => {
        nodes.push({
          kind: "tech",
          title: fingerprint.product,
          meta: `${fingerprint.vendor || "fingerprint"} · ${toPercent(fingerprint.confidence)}`,
          left: 72,
          top: 18 + (technologies.length + index) * 16,
        });
      });
    }

    const hotspotTargets = new Set((runtime.actions.selectedRunFindings?.() || []).map((finding) => finding.target_id));
    const svgLines = [];
    nodes.filter((node) => node.kind === "host").forEach((hostNode, index) => {
      const endpointNode = nodes.filter((node) => node.kind === "endpoint")[index];
      if (endpointNode) {
        svgLines.push(lineSvg(hostNode.left + 14, hostNode.top + 2, endpointNode.left + 6, endpointNode.top + 2));
      }
    });
    nodes.filter((node) => node.kind === "endpoint").forEach((endpointNode, index) => {
      const techNode = nodes.filter((node) => node.kind === "tech")[index];
      if (techNode) {
        svgLines.push(lineSvg(endpointNode.left + 14, endpointNode.top + 2, techNode.left + 6, techNode.top + 2));
      }
    });

    dom.surfaceMapCanvas.innerHTML = `
      <svg viewBox="0 0 100 100" preserveAspectRatio="none">${svgLines.join("")}</svg>
      <div class="map-column hosts"><p class="map-column-label">Hosts</p></div>
      <div class="map-column endpoints"><p class="map-column-label">Apps / APIs</p></div>
      <div class="map-column tech"><p class="map-column-label">Stacks / Pack Zones</p></div>
      ${nodes.map((node) => {
        const hotspot = state.surfaceOverlays.hotspots && hotspotTargets.has(node.title);
        const packZone = state.surfaceOverlays.packZones && Boolean(runtime.actions.selectedPack?.());
        return `
          <div class="map-node ${hotspot ? "hotspot" : ""} ${packZone ? "pack-zone" : ""} ${hotspot ? "active" : ""}" style="left:${node.left}%; top:${node.top}%">
            <strong>${escapeHtml(node.title)}</strong>
            <div class="node-meta">${escapeHtml(node.meta)}</div>
          </div>
        `;
      }).join("")}
    `;

    const previousSnapshot = state.mission.inventory[1] || null;
    dom.surfaceInsights.innerHTML = renderStringCards(
      [
        `${hosts.length} hosts or network objects are visible in the current surface model.`,
        `${endpoints.length} HTTP or API endpoints are mapped for the selected engagement.`,
        `${technologies.length || fingerprints.length} stack indicators are available for adaptive relevance decisions.`,
        previousSnapshot ? `${Math.max(0, (snapshot.summary_json.host_count || 0) - (previousSnapshot.summary_json.host_count || 0))} new host-level items were discovered since the previous snapshot.` : "No prior inventory snapshot exists for delta analysis yet.",
      ],
      "Insights appear after inventory normalization runs."
    );
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

  return {
    renderMissionControl,
    renderSurfaceMap,
    buildMissionPhases,
  };
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

function packStatusToPhaseStatus(status) {
  if (["validation_failed", "retired"].includes(status)) return "blocked";
  if (["deployed", "approved", "validated", "superseded"].includes(status)) return "complete";
  if (["generated", "proposed"].includes(status)) return "active";
  return "pending";
}
