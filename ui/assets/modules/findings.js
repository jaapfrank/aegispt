import { api, apiOrNull } from "./api.js";
import { dom, patchState, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  findingOriginLabel,
  followUpStrategyLabel,
  renderDisclosure,
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

function findingsUiState() {
  return { filtersOpen: false, remediationOpen: false, view: "list", ...(state.findingsUi || {}) };
}

function setFindingsUi(patch, reason) {
  patchState(
    {
      findingsUi: {
        ...findingsUiState(),
        ...patch,
      },
    },
    reason
  );
}

function jiraLinkForFinding(findingId) {
  if (!findingId) return null;
  return state.jiraFindingLinks?.[String(findingId)] || null;
}

function rememberJiraLink(findingId, link) {
  if (!findingId || !link) return;
  state.jiraFindingLinks = {
    ...(state.jiraFindingLinks || {}),
    [String(findingId)]: link,
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

function operatorSettingBoolean(key) {
  const value = findOperatorSettingValue(key);
  if (typeof value === "boolean") return value;
  return ["true", "1", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function hasConfiguredJiraBaseUrlHint() {
  const value = findOperatorSettingValue("integrations.jira_base_url");
  return Boolean(String(value || "").trim());
}

function isFindingAiProviderReady() {
  const provider = String(findOperatorSettingValue("ai.provider") || "disabled").trim().toLowerCase();
  if (!provider || ["disabled", "none", "off"].includes(provider)) return false;
  if (provider !== "chatgpt_oauth") return true;

  return (
    state.chatgptOAuthStatus?.connected === true ||
    state.selectedAiInsights?.provider_status?.connected === true ||
    state.selectedRun?.ai_mission_guidance?.provider?.status === "connected" ||
    state.selectedRun?.ai_mission_guidance?.provider?.connected === true
  );
}

function canRequestFindingAiEnrichment(aiEnrichment) {
  const status = String(aiEnrichment?.status || "disabled").toLowerCase();
  return (
    operatorSettingBoolean("ai.finding_enrichment_enabled") &&
    isFindingAiProviderReady() &&
    ["disabled", "missing", "unavailable"].includes(status)
  );
}

function ensureJiraConfigurationLoaded() {
  if (!state.selectedEngagementId) return;
  if (state.jiraIntegrationLoading) return;
  if (state.jiraIntegrationLoadedEngagementId === state.selectedEngagementId) return;
  if (state.operatorSettings && !hasConfiguredJiraBaseUrlHint()) {
    patchState(
      {
        jiraIntegrationConfiguration: null,
        jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
        jiraIntegrationLoading: false,
        jiraIntegrationError: null,
      },
      "findings.jira.config.unconfigured"
    );
    return;
  }
  state.jiraIntegrationLoading = true;
  apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/integrations/jira`)
    .then((configuration) => {
      patchState(
        {
          jiraIntegrationConfiguration: configuration,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
          jiraIntegrationError: null,
        },
        "findings.jira.config.loaded"
      );
      if (state.activeScreen === "findings-theater") runtime.actions.renderAll?.();
    })
    .catch((error) => {
      patchState(
        {
          jiraIntegrationConfiguration: null,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
          jiraIntegrationError: String(error?.message || error),
        },
        "findings.jira.config.error"
      );
    });
}

async function pushFindingToJira(findingId) {
  if (!findingId) return;
  patchState({ jiraPushFindingId: findingId, jiraIntegrationError: null }, "findings.jira.push.start");
  runtime.actions.renderAll?.();
  try {
    const link = await api(`/api/v1/findings/${findingId}/handoff-jira`, { method: "POST" });
    rememberJiraLink(findingId, link);
    runtime.actions.pushStatus?.(`Finding pushed to Jira handoff ${link.issue_key}.`, "success");
    await runtime.actions.loadSelectedFinding?.();
    await runtime.actions.refreshSelectedEngagement?.();
  } catch (error) {
    patchState({ jiraIntegrationError: String(error?.message || error) }, "findings.jira.push.error");
    runtime.actions.handleError?.(error);
  } finally {
    patchState({ jiraPushFindingId: null }, "findings.jira.push.complete");
    runtime.actions.renderAll?.();
  }
}

async function requestFindingAiEnrichment(findingId) {
  if (!findingId) return;
  try {
    const enrichment = await api(`/api/v1/findings/${findingId}/ai-enrich`, { method: "POST" });
    if (state.selectedFindingTheater?.finding?.id === findingId) {
      state.selectedFindingTheater.ai_enrichment = enrichment;
      runtime.actions.renderAll?.();
    }
    runtime.actions.pushStatus?.("AI enrichment started for this finding.", "success");
  } catch (error) {
    runtime.actions.handleError?.(error);
  }
}

function renderFindingJiraBadge(finding) {
  const link = jiraLinkForFinding(finding?.id);
  if (!link) return "";
  return `<span class="badge finding-badge-jira" data-testid="finding-jira-badge">${escapeHtml(link.issue_key || "Jira")}</span>`;
}

function renderActionEmptyCard(message, action) {
  return `<div class="detail-surface empty-detail-surface">${emptyState(message, action)}</div>`;
}

const MOLECULE_SEVERITY = {
  critical: { radius: 22, color: "#ef4444", fill: "rgba(239, 68, 68, 0.14)", label: "Critical" },
  high: { radius: 17, color: "#f59e0b", fill: "rgba(245, 158, 11, 0.14)", label: "High" },
  medium: { radius: 13, color: "#facc15", fill: "rgba(250, 204, 21, 0.14)", label: "Medium" },
  low: { radius: 11, color: "#10b981", fill: "rgba(16, 185, 129, 0.12)", label: "Low" },
  info: { radius: 9, color: "#5ecfff", fill: "rgba(94, 207, 255, 0.12)", label: "Info" },
  unknown: { radius: 9, color: "#94a3b8", fill: "rgba(148, 163, 184, 0.12)", label: "Unknown" },
};

function normalizeSeverity(value) {
  const normalized = String(value || "unknown").toLowerCase();
  return MOLECULE_SEVERITY[normalized] ? normalized : "unknown";
}

function moleculeMetaForSeverity(value) {
  return MOLECULE_SEVERITY[normalizeSeverity(value)];
}

function extractFindingId(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "object") {
    return String(value.finding_id || value.id || "").trim() || null;
  }
  return String(value).trim() || null;
}

function appendChainReferencesFromObject(references, value) {
  if (!value || typeof value !== "object") return;
  [
    value.component_finding_ids,
    value.related_finding_ids,
    value.chain_finding_ids,
    value.finding_ids,
    value.chains,
  ].forEach((candidate) => appendChainReferences(references, candidate));
  appendChainReferences(references, value.component_findings);
  if (Array.isArray(value.chains)) {
    value.chains.forEach((chain) => appendChainReferencesFromObject(references, chain));
  }
}

function appendChainReferences(references, candidate) {
  if (!candidate) return;
  if (Array.isArray(candidate)) {
    candidate.forEach((item) => {
      if (item && typeof item === "object") {
        appendChainReferencesFromObject(references, item);
      }
      const id = extractFindingId(item);
      if (id) references.push(id);
    });
    return;
  }
  if (typeof candidate === "object") {
    appendChainReferencesFromObject(references, candidate);
    const id = extractFindingId(candidate);
    if (id) references.push(id);
    return;
  }
  const id = extractFindingId(candidate);
  if (id) references.push(id);
}

function chainReferencesForFinding(finding) {
  const references = [];
  [
    finding.chains,
    finding.chain_ids,
    finding.chain_finding_ids,
    finding.related_finding_ids,
    finding.component_finding_ids,
    finding.vulnerability_chain_summary,
    finding.chain_summary,
    finding.vulnerability_chains,
    finding.chain_context,
  ].forEach((candidate) => appendChainReferences(references, candidate));
  return Array.from(new Set(references.filter((id) => id && id !== String(finding.id))));
}

function addMoleculeLink(linkMap, sourceId, targetId, label = "Stored chain relationship") {
  if (!sourceId || !targetId || sourceId === targetId) return;
  const pair = [String(sourceId), String(targetId)].sort();
  const key = pair.join("::");
  if (!linkMap.has(key)) {
    linkMap.set(key, { source: pair[0], target: pair[1], label });
  }
}

function addSelectedTheaterChainLinks(linkMap, visibleFindingIds) {
  const chainContext = state.selectedFindingTheater?.vulnerability_chains;
  const chains = Array.isArray(chainContext?.chains) ? chainContext.chains : [];
  chains.forEach((chain) => {
    const components = Array.isArray(chain.component_findings) ? chain.component_findings : [];
    const componentIds = components.length
      ? components.map((component) => extractFindingId(component)).filter(Boolean)
      : (Array.isArray(chain.component_finding_ids) ? chain.component_finding_ids.map((item) => extractFindingId(item)).filter(Boolean) : []);
    const visibleIds = componentIds.filter((id) => visibleFindingIds.has(String(id)));
    for (let index = 0; index < visibleIds.length - 1; index += 1) {
      addMoleculeLink(linkMap, visibleIds[index], visibleIds[index + 1], chain.title || "Selected chain context");
    }
    if (state.selectedFindingId && visibleIds.includes(String(state.selectedFindingId))) {
      visibleIds.forEach((id) => addMoleculeLink(linkMap, state.selectedFindingId, id, chain.title || "Selected chain context"));
    }
  });
}

function buildMoleculeGraph(findings) {
  const visibleFindingIds = new Set(findings.map((finding) => String(finding.id)));
  const linkMap = new Map();
  findings.forEach((finding) => {
    chainReferencesForFinding(finding)
      .filter((targetId) => visibleFindingIds.has(String(targetId)))
      .forEach((targetId) => addMoleculeLink(linkMap, finding.id, targetId));
  });
  addSelectedTheaterChainLinks(linkMap, visibleFindingIds);

  const links = Array.from(linkMap.values());
  const count = Math.max(1, findings.length);
  const nodes = findings.map((finding, index) => {
    const severity = normalizeSeverity(finding.severity);
    const meta = moleculeMetaForSeverity(severity);
    const rank = severityRank(severity);
    const angle = (index / count) * Math.PI * 2 - Math.PI / 2;
    const radius = 80 + Math.min(rank, 4) * 34 + (index % 2) * 12;
    return {
      finding,
      id: String(finding.id),
      severity,
      meta,
      x: Math.round(Math.cos(angle) * radius),
      y: Math.round(Math.sin(angle) * radius),
      selected: String(finding.id) === String(state.selectedFindingId || ""),
    };
  });
  return { nodes, links };
}

function renderMoleculeLegend(findings, linkCount) {
  const counts = findings.reduce((memo, finding) => {
    const severity = normalizeSeverity(finding.severity);
    memo[severity] = (memo[severity] || 0) + 1;
    return memo;
  }, {});
  return `
    <div class="risk-molecule-legend" data-testid="risk-molecule-legend">
      ${["critical", "high", "medium", "low", "info"].map((severity) => {
        const meta = moleculeMetaForSeverity(severity);
        return `
          <span class="risk-molecule-legend-item">
            <span class="risk-molecule-legend-dot" style="background: ${meta.color}"></span>
            ${escapeHtml(`${meta.label} (${counts[severity] || 0})`)}
          </span>
        `;
      }).join("")}
      <span class="risk-molecule-legend-item">
        <span class="risk-molecule-chain-swatch"></span>
        ${escapeHtml(`Chain links (${linkCount})`)}
      </span>
    </div>
  `;
}

function renderRiskMoleculeView(findings, selectedRun, allFindings) {
  if (!findings.length) {
    return `
      <section class="risk-molecule-empty" data-testid="risk-molecule-empty">
        ${renderNoFindingsState(selectedRun, allFindings)}
      </section>
    `;
  }

  const graph = buildMoleculeGraph(findings);
  const chainNote = graph.links.length
    ? `${graph.links.length} stored chain link${graph.links.length === 1 ? "" : "s"} visible from current finding data.`
    : "No stored chain relationship is available in the current browser finding data; standalone nodes are shown without invented links.";
  const subtitle = `${findings.length} finding${findings.length === 1 ? "" : "s"} · ${chainNote}`;
  return `
    <section class="risk-molecule-shell" data-testid="risk-molecule-view">
      <div class="risk-molecule-canvas">
        <svg class="risk-molecule-svg" data-testid="risk-molecule-svg" viewBox="-360 -280 720 560" role="img" aria-label="Risk Molecule">
          <defs>
            <filter id="risk-molecule-glow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect class="risk-molecule-grid" x="-360" y="-280" width="720" height="560"></rect>
          ${graph.links.map((link) => {
            const source = graph.nodes.find((node) => node.id === link.source);
            const target = graph.nodes.find((node) => node.id === link.target);
            if (!source || !target) return "";
            return `<line class="risk-molecule-link" data-testid="risk-molecule-link" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"></line>`;
          }).join("")}
          ${graph.nodes.map((node) => `
            <g
              class="risk-molecule-node severity-${escapeHtml(node.severity)} ${node.selected ? "selected" : ""}"
              data-risk-node="true"
              data-finding-pick="${escapeHtml(node.id)}"
              data-risk-title="${escapeHtml(node.finding.title)}"
              data-risk-target="${escapeHtml(node.finding.target_id || "target not recorded")}"
              data-testid="risk-molecule-node"
              role="button"
              tabindex="0"
              transform="translate(${node.x} ${node.y})"
              aria-label="${escapeHtml(`${node.finding.title} on ${node.finding.target_id || "target not recorded"}`)}"
            >
              <circle class="risk-molecule-node-glow" r="${node.meta.radius + 8}" stroke="${node.meta.color}"></circle>
              ${node.severity === "critical" ? `<circle class="risk-molecule-node-pulse" r="${node.meta.radius}" stroke="${node.meta.color}"></circle>` : ""}
              <circle class="risk-molecule-node-core" r="${node.meta.radius}" fill="${node.meta.fill}" stroke="${node.meta.color}"></circle>
              <text class="risk-molecule-node-label" y="4">${escapeHtml(node.severity === "critical" ? "!" : node.severity[0].toUpperCase())}</text>
            </g>
          `).join("")}
        </svg>
        <div class="risk-molecule-tooltip" data-testid="risk-molecule-tooltip" hidden></div>
      </div>
      <aside class="risk-molecule-detail" data-testid="risk-molecule-detail">
        <div>
          <p class="eyebrow">Finding Relationships</p>
          <h3>Risk Molecule</h3>
          <p>${escapeHtml(subtitle)}</p>
        </div>
        ${renderMoleculeLegend(findings, graph.links.length)}
        <div class="section-note">
          <strong>Interaction</strong>
          <p>Hover a node for title and target. Click a node to open the existing finding detail drawer.</p>
        </div>
        <div class="risk-molecule-card-list">
          ${findings.map((finding) => {
            const severity = normalizeSeverity(finding.severity);
            const hasChain = chainReferencesForFinding(finding).some((targetId) => graph.nodes.some((node) => node.id === String(targetId)));
            return `
              <button
                class="risk-molecule-card ${String(finding.id) === String(state.selectedFindingId || "") ? "selected" : ""}"
                type="button"
                data-finding-pick="${escapeHtml(String(finding.id))}"
                data-testid="risk-molecule-card"
              >
                <span class="finding-severity-dot severity-${escapeHtml(severity)}" aria-hidden="true"></span>
                <span>
                  <strong>${escapeHtml(finding.title)}</strong>
                  <small>${escapeHtml(finding.target_id || "target not recorded")}</small>
                </span>
                <span class="badge severity-${escapeHtml(severity)}">${escapeHtml(severity)}</span>
                ${hasChain ? `<span class="badge finding-badge-chain">chain</span>` : ""}
              </button>
            `;
          }).join("")}
        </div>
      </aside>
    </section>
  `;
}

function positionMoleculeTooltip(event, tooltip) {
  const host = tooltip.closest(".risk-molecule-canvas");
  const bounds = host?.getBoundingClientRect();
  if (!bounds) return;
  tooltip.style.left = `${Math.min(bounds.width - 40, Math.max(12, event.clientX - bounds.left + 14))}px`;
  tooltip.style.top = `${Math.min(bounds.height - 40, Math.max(12, event.clientY - bounds.top - 8))}px`;
}

function bindRiskMoleculeTooltip(container) {
  const tooltip = container.querySelector("[data-testid='risk-molecule-tooltip']");
  if (!tooltip) return;
  container.querySelectorAll("[data-risk-node]").forEach((node) => {
    const show = (event) => {
      tooltip.hidden = false;
      tooltip.innerHTML = `<strong>${escapeHtml(node.dataset.riskTitle || "Finding")}</strong><span>${escapeHtml(node.dataset.riskTarget || "target not recorded")}</span>`;
      if (event instanceof MouseEvent) positionMoleculeTooltip(event, tooltip);
    };
    const hide = () => {
      tooltip.hidden = true;
      tooltip.innerHTML = "";
    };
    node.addEventListener("mouseenter", show);
    node.addEventListener("mousemove", (event) => positionMoleculeTooltip(event, tooltip));
    node.addEventListener("mouseleave", hide);
    node.addEventListener("focus", show);
    node.addEventListener("blur", hide);
    node.addEventListener("keydown", (event) => {
      if (!["Enter", " "].includes(event.key)) return;
      event.preventDefault();
      selectFinding(node.getAttribute("data-finding-pick") || node.dataset.findingPick).catch(runtime.actions.handleError);
    });
  });
}

async function selectFinding(findingId) {
  state.selectedFindingId = findingId;
  state.loading.findingDetail = true;
  state.loading.evidenceDetail = true;
  runtime.actions.renderAll?.();
  try {
    await runtime.actions.loadSelectedFinding?.();
  } finally {
    state.loading.findingDetail = false;
    state.loading.evidenceDetail = false;
    runtime.actions.renderAll?.();
  }
}

export function createFindingsModule() {
  function renderFindingsTheater() {
    ensureJiraConfigurationLoaded();
    const allFindings = runtime.actions.engagementFindings?.() || [];
    const selectedRun = state.selectedRun;
    const methodologyOptions = Array.from(
      new Set(allFindings.flatMap((finding) => finding.methodology_tags || []))
    ).sort();
    const filtered = filterFindings(allFindings);
    const activeView = findingsUiState().view === "molecule" ? "molecule" : "list";
    const filterSummary = [
      `${filtered.length} visible`,
      state.findingFilters.groupBy ? `grouped by ${state.findingFilters.groupBy}` : null,
    ]
      .filter(Boolean)
      .join(" · ");

    dom.findingsFilterBar.innerHTML = `
        <div class="findings-toolbar-row">
          ${renderDisclosure({
            title: "Filters",
            summary: filterSummary,
            open: findingsUiState().filtersOpen,
            testId: "finding-filters-disclosure",
            className: "finding-filters-disclosure",
            body: `
              <div class="findings-filter-grid">
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
                <label class="field compact finding-group-selector">
                  <span>Group by</span>
                  <select id="finding-filter-group-by" data-testid="finding-group-by">
                    ${["severity", "origin", "status", "methodology", "run"]
                      .map(
                        (value) =>
                          `<option value="${value}" ${state.findingFilters.groupBy === value ? "selected" : ""}>${escapeHtml(value)}</option>`
                      )
                      .join("")}
                  </select>
                </label>
              </div>
            `,
          })}
          <div class="findings-view-toggle" data-testid="findings-view-toggle" aria-label="Findings view">
            <button
              class="${activeView === "list" ? "active" : ""}"
              type="button"
              data-findings-view="list"
              data-testid="findings-view-list"
            >List View</button>
            <button
              class="${activeView === "molecule" ? "active" : ""}"
              type="button"
              data-findings-view="molecule"
              data-testid="findings-view-molecule"
            >Molecule View</button>
          </div>
          ${
            selectedRun?.id
              ? `<button class="action ghost compact-action" type="button" data-run-verify-evidence="${escapeHtml(selectedRun.id)}">Verify All Evidence</button>`
              : ""
          }
        </div>
      `;

    dom.findingsFilterBar.querySelector('[data-testid="finding-filters-disclosure"]')?.addEventListener("toggle", (event) => {
      setFindingsUi({ filtersOpen: event.currentTarget.open }, "findings.ui.filters");
    });
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
    dom.findingsFilterBar.querySelectorAll("[data-findings-view]").forEach((button) => {
      button.addEventListener("click", () => {
        setFindingsUi({ view: button.dataset.findingsView === "molecule" ? "molecule" : "list" }, "findings.ui.view");
        renderFindingsTheater();
      });
    });
    dom.findingsFilterBar.querySelector("[data-run-verify-evidence]")?.addEventListener("click", async (event) => {
      const runId = event.currentTarget.getAttribute("data-run-verify-evidence");
      if (!runId) return;
      const button = event.currentTarget;
      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = "Verifying...";
      try {
        const result = await api(`/api/v1/runs/${runId}/evidence/verify`, { method: "POST" });
        runtime.actions.pushStatus?.(
          `Evidence verification ${result.status}: ${result.verified}/${result.total_findings} verified.`,
          result.integrity_failures ? "error" : "success"
        );
        await runtime.actions.refreshSelectedEngagement?.();
        if (state.selectedFindingId) await runtime.actions.loadSelectedFinding?.();
      } catch (error) {
        runtime.actions.handleError?.(error);
      } finally {
        button.disabled = false;
        button.textContent = originalLabel;
      }
    });

    dom.remediationPortfolio.classList.add("hidden");
    dom.remediationPortfolio.innerHTML = "";
    if (!filtered.length) {
      state.selectedFindingId = null;
      state.selectedFindingTheater = null;
      state.selectedFindingEvidence = null;
    }
    if (state.selectedFindingId && !filtered.some((finding) => finding.id === state.selectedFindingId)) {
      state.selectedFindingId = null;
      state.selectedFindingTheater = null;
      state.selectedFindingEvidence = null;
    }

    const grouped = groupFindings(filtered, state.findingFilters.groupBy);
    const orderedGroups = Object.entries(grouped).sort((left, right) => {
      if (state.findingFilters.groupBy === "severity") {
        return severityRank(left[0]) - severityRank(right[0]);
      }
      return left[0].localeCompare(right[0]);
    });
    dom.findingsGroupList.innerHTML = activeView === "molecule"
      ? renderRiskMoleculeView(filtered, selectedRun, allFindings)
      : orderedGroups.length
        ? orderedGroups
            .map(
              ([group, items]) => `
                <section class="finding-group" data-testid="finding-group">
                  <div class="finding-group-head">
                    <div class="finding-group-title-row">
                      <span class="finding-severity-dot severity-${escapeHtml(String(items[0]?.severity || group || "unknown").toLowerCase())}" aria-hidden="true"></span>
                      <h4>${escapeHtml(group)}</h4>
                      <span class="finding-group-count">${escapeHtml(`${items.length}`)}</span>
                    </div>
                  </div>
                  <div class="finding-list-rows">
                    ${items
                      .map(
                        (finding) => `
                          <button
                            class="finding-row-card severity-${escapeHtml(String(finding.severity || "unknown").toLowerCase())} ${finding.id === state.selectedFindingId ? "selected" : ""}"
                            type="button"
                            data-finding-pick="${finding.id}"
                            data-testid="finding-card"
                          >
                            <span class="finding-severity-dot severity-${escapeHtml(String(finding.severity || "unknown").toLowerCase())}" aria-hidden="true"></span>
                            <div class="finding-row-copy">
                              <strong>${escapeHtml(finding.title)}</strong>
                              <span>${escapeHtml(
                                [finding.target_id, finding.tool_name || finding.tool || findingOriginLabel(finding.finding_origin)]
                                  .filter(Boolean)
                                  .join(" · ")
                              )}</span>
                            </div>
                            <div class="finding-row-badges">
                              ${(finding.threat_intel_badges || [])
                                .filter((badge) => String(badge || "").toLowerCase().includes("kev"))
                                .slice(0, 1)
                                .map((badge) => `<span class="badge finding-badge-kev">${escapeHtml(badge)}</span>`)
                                .join("")}
                              ${(finding.vulnerability_chain_summary || finding.chain_summary || finding.has_chain)
                                ? `<span class="badge finding-badge-chain">chain</span>`
                                : ""}
                              ${renderFindingJiraBadge(finding)}
                            </div>
                            <span class="finding-row-arrow" aria-hidden="true">›</span>
                          </button>
                        `
                      )
                      .join("")}
                  </div>
                </section>
              `
            )
            .join("")
        : renderNoFindingsState(selectedRun, allFindings);

    dom.findingsGroupList.querySelectorAll("[data-finding-pick]").forEach((item) => {
      item.addEventListener("click", () => {
        selectFinding(item.getAttribute("data-finding-pick") || item.dataset.findingPick).catch(runtime.actions.handleError);
      });
    });
    if (activeView === "molecule") {
      bindRiskMoleculeTooltip(dom.findingsGroupList);
    }
    dom.findingsGroupList.querySelector("[data-findings-reset-filters]")?.addEventListener("click", () => {
      state.findingFilters = {
        runId: "all",
        severity: "all",
        origin: "all",
        status: "all",
        methodology: "all",
        groupBy: "severity",
      };
      renderFindingsTheater();
    });

    if (state.loading.findingDetail) {
      dom.findingTheaterDetail.classList.add("is-open");
      dom.findingTheaterDetail.innerHTML = `
        <div class="finding-drawer-panel" data-testid="finding-detail-loading">
          <div class="finding-drawer-head">
            <h3>Loading selected finding</h3>
            <button class="action ghost compact-action" type="button" data-finding-drawer-close>Close</button>
          </div>
          <p>Refreshing business impact, methodology, remediation, and verification guidance.</p>
        </div>
      `;
      dom.findingTheaterDetail.querySelector("[data-finding-drawer-close]")?.addEventListener("click", closeFindingDrawer);
      return;
    }

    if (!state.selectedFindingTheater) {
      dom.findingTheaterDetail.classList.remove("is-open");
      dom.findingTheaterDetail.innerHTML = "";
      return;
    }

    const theater = state.selectedFindingTheater;
    const evidence = state.selectedFindingEvidence;
    rememberJiraLink(theater.finding?.id, theater.remediation?.integrations?.jira);
    dom.findingTheaterDetail.classList.add("is-open");
    dom.findingTheaterDetail.innerHTML = `
      <div class="finding-drawer-panel">
        <div class="finding-drawer-head">
          <div class="finding-drawer-title">
            ${severityPill(theater.finding?.severity || theater.severity)}
            <h3>${escapeHtml(theater.finding?.title || theater.title || "Selected finding")}</h3>
          </div>
          <button class="action ghost compact-action" type="button" data-finding-drawer-close aria-label="Close finding drawer">Close</button>
        </div>
        ${renderFindingBrief(theater, evidence)}
        ${renderFalsePositiveDecision(theater.finding)}
        ${renderThreatIntelBadges(theater.threat_intel_badges)}
        ${renderVulnerabilityChains(theater.vulnerability_chains)}
        ${renderAutoFix(theater.autofix)}
        ${renderRepositoryContext(theater.repository_context)}
        ${renderAiEnrichment(theater.ai_enrichment)}
        ${renderContextualIntelligence(theater.ai_enrichment?.contextual_intelligence)}
        ${renderThreatContext(theater.threat_context)}
        ${renderDetectionEngineering(theater.detection_engineering)}
        <div class="detail-grid split-top">
          <div class="detail-surface">
            <h4>Remediation</h4>
            <p>${escapeHtml(theater.remediation.priority)}</p>
            <p>${escapeHtml(theater.remediation.summary)}</p>
            <p class="micro-copy">${escapeHtml(theater.remediation.detail)}</p>
            ${renderRemediationTracking(theater.remediation)}
            ${renderJiraHandoffAction(theater)}
            ${renderJiraLinkage(theater.remediation)}
            ${renderWorkflowHandoffs(theater.remediation)}
            ${renderLinkedRetests(theater.remediation)}
          </div>
          ${renderFindingValidationCard(theater.validation)}
          ${renderFindingMethodologyCard(theater)}
        </div>
        ${renderFindingEvidencePanel(theater, evidence)}
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
          <button class="action ghost" type="button" data-finding-fp-open>Mark false positive</button>
          <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open Legacy Evidence Replay</button>
        </div>
        ${renderFalsePositiveReviewPanel()}
      </div>
    `;
    dom.findingTheaterDetail.querySelector("[data-finding-drawer-close]")?.addEventListener("click", closeFindingDrawer);

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

    dom.findingTheaterDetail.querySelector("[data-finding-fp-open]")?.addEventListener("click", () => {
      const panel = dom.findingTheaterDetail.querySelector("[data-finding-fp-panel]");
      panel?.classList.remove("hidden");
      panel?.querySelector("[data-finding-fp-reason]")?.focus();
    });

    dom.findingTheaterDetail.querySelector("[data-jira-push-finding]")?.addEventListener("click", (event) => {
      const findingId = event.currentTarget.getAttribute("data-jira-push-finding");
      pushFindingToJira(findingId).catch(runtime.actions.handleError || (() => {}));
    });

    dom.findingTheaterDetail.querySelector("[data-finding-ai-enrich]")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const findingId = button.getAttribute("data-finding-ai-enrich") || state.selectedFindingId;
      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = "Enriching...";
      try {
        await requestFindingAiEnrichment(findingId);
      } finally {
        button.disabled = false;
        button.textContent = originalLabel;
      }
    });

    dom.findingTheaterDetail.querySelector("[data-finding-fp-submit]")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const input = dom.findingTheaterDetail.querySelector("[data-finding-fp-reason]");
      const reason = String(input?.value || "").trim();
      if (!reason) {
        runtime.actions.pushStatus?.("False-positive reason is required before closing this finding.", "error");
        input?.focus();
        return;
      }
      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = "Saving...";
      try {
        await api(`/api/v1/findings/${state.selectedFindingId}`, {
          method: "PATCH",
          body: { status: "false_positive", false_positive_reason: reason },
        });
        runtime.actions.pushStatus?.("Finding marked false positive with recorded rationale.", "success");
        await runtime.actions.refreshSelectedEngagement?.();
        if (state.selectedFindingId) await runtime.actions.loadSelectedFinding?.();
      } finally {
        button.disabled = false;
        button.textContent = originalLabel;
      }
    });

    dom.findingTheaterDetail.querySelectorAll("[data-finding-verify-evidence]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!state.selectedFindingId) return;
        const originalLabel = button.textContent;
        button.disabled = true;
        button.textContent = "Verifying...";
        try {
          const result = await api(`/api/v1/findings/${state.selectedFindingId}/evidence/verify`, {
            method: "POST",
          });
          runtime.actions.pushStatus?.(
            result.detail || `Evidence verification: ${result.status}`,
            result.status === "integrity-failure" ? "error" : "success"
          );
          await runtime.actions.loadSelectedFinding?.();
        } catch (error) {
          runtime.actions.handleError?.(error);
        } finally {
          button.disabled = false;
          button.textContent = originalLabel;
        }
      });
    });

    dom.findingTheaterDetail.querySelectorAll("[data-copy-fix]").forEach((button) => {
      button.addEventListener("click", async () => {
        const patchAfter = state.selectedFindingTheater?.autofix?.patch_after;
        if (!patchAfter) {
          runtime.actions.pushStatus?.("No advisory fix is available to copy yet.", "warning");
          return;
        }
        try {
          await copyTextToClipboard(patchAfter);
          runtime.actions.pushStatus?.("Suggested fix copied to clipboard.", "success");
        } catch (error) {
          runtime.actions.handleError?.(error);
        }
      });
    });

    dom.findingTheaterDetail.querySelectorAll("[data-create-fix-pr]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!state.selectedFindingId) return;
        const originalLabel = button.textContent;
        button.disabled = true;
        button.textContent = "Creating PR...";
        try {
          const pullRequest = await api(`/api/v1/findings/${state.selectedFindingId}/repository/fix-pr`, {
            method: "POST",
          });
          const repositoryContext = state.selectedFindingTheater?.repository_context;
          if (repositoryContext) {
            repositoryContext.latest_pull_request = {
              provider: pullRequest.provider,
              branch_name: pullRequest.branch_name,
              pull_request_url: pullRequest.pull_request_url,
              pull_request_id: pullRequest.pull_request_id,
              auto_merge_enabled: pullRequest.auto_merge_enabled,
              created_by: state.actor,
            };
          }
          runtime.actions.pushStatus?.(`Fix PR created on branch ${pullRequest.branch_name}.`, "success");
          renderFindingsTheater();
        } catch (error) {
          runtime.actions.handleError?.(error);
        } finally {
          button.disabled = false;
          button.textContent = originalLabel;
        }
      });
    });
  }

  function closeFindingDrawer() {
    state.selectedFindingId = null;
    state.selectedFindingTheater = null;
    state.selectedFindingEvidence = null;
    renderFindingsTheater();
    renderEvidenceReplay();
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
          <div class="section-note" data-testid="evidence-consolidation-note">
            <strong>Consolidated review path</strong>
            <p>Finding-level replay stays inside Finding Theater. Evidence Replay remains available for run-level task and artifact inspection.</p>
          </div>
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
      <div class="section-note" data-testid="evidence-consolidation-note">
        <strong>Consolidated review path</strong>
        <p>This finding's replay summary is embedded in Finding Theater so triage, evidence, remediation, and next steps stay together. Evidence Replay remains available for deeper artifact inspection.</p>
      </div>
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

function renderRemediationPortfolio() {
  if (!dom.remediationPortfolio) return;
  const portfolio = state.remediationPortfolio;
  if (!portfolio) {
    dom.remediationPortfolio.innerHTML = renderActionEmptyCard(
      "No remediation queue is available yet.",
      state.selectedRun ? { label: "Open Mission Control", screen: "mission-control" } : { label: "Start a mission", screen: "wizard" }
    );
    return;
  }

  const summary = portfolio.summary || {};
  const items = Array.isArray(portfolio.items) ? portfolio.items : [];
  const plan = portfolio.retest_plan || {};
  const groups = Array.isArray(plan.groups) ? plan.groups : [];
  const policy = portfolio.policy || {};
  dom.remediationPortfolio.innerHTML = renderDisclosure({
    title: "SLA & Retest Planning Queue",
    summary: `${summary.total_items || 0} items · ${summary.eligible_for_retest || 0} ready for retest planning`,
    open: findingsUiState().remediationOpen,
    testId: "remediation-portfolio-disclosure",
    className: "remediation-portfolio-disclosure",
    body: `
      <section class="detail-surface remediation-portfolio-panel" data-testid="remediation-portfolio-summary">
        <div class="inline-metrics">
          <span class="metric-pill">${escapeHtml(`SLA ${policy.sla_days || 30}d`)}</span>
          <span class="metric-pill">${escapeHtml(`${summary.overdue || 0} overdue`)}</span>
          <span class="metric-pill">${escapeHtml(`${summary.due_soon || 0} due soon`)}</span>
          <span class="metric-pill">${escapeHtml(`${summary.verified || 0} verified`)}</span>
        </div>
        <div class="detail-grid split-top">
          <div class="detail-surface" data-testid="remediation-retest-plan">
            <h4>Batch Retest Plan</h4>
            ${
              groups.length
                ? `<div class="finding-stack split-top">
                    ${groups.map((group) => renderRetestPlanGroup(group)).join("")}
                  </div>`
                : emptyState("No findings are ready for batch retest planning.", {
                    label: "Open Findings",
                    screen: "findings-theater",
                  })
            }
          </div>
          <div class="detail-surface" data-testid="remediation-portfolio-items">
            <h4>Portfolio Queue</h4>
            ${
              items.length
                ? `<div class="finding-stack split-top">
                    ${items.slice(0, 5).map((item) => renderRemediationPortfolioItem(item)).join("")}
                  </div>`
                : emptyState("No remediation items match this engagement.", {
                    label: "Open Findings",
                    screen: "findings-theater",
                  })
            }
          </div>
        </div>
      </section>
    `,
  });
  dom.remediationPortfolio.querySelector('[data-testid="remediation-portfolio-disclosure"]')?.addEventListener(
    "toggle",
    (event) => {
      setFindingsUi({ remediationOpen: event.currentTarget.open }, "findings.ui.remediation");
    }
  );
}

function renderRetestPlanGroup(group) {
  return `
    <article class="artifact-card" data-testid="remediation-retest-plan-group">
      <h4>${escapeHtml(formatOptional(group.profile_name, "Unknown profile"))}</h4>
      <div class="inline-metrics">
        <span class="metric-pill">${escapeHtml(`${(group.finding_ids || []).length} finding${(group.finding_ids || []).length === 1 ? "" : "s"}`)}</span>
        <span class="metric-pill">${escapeHtml(`requires ${group.approval_required_count || 0} approval${group.approval_required_count === 1 ? "" : "s"}`)}</span>
      </div>
      <p class="micro-copy split-top">${escapeHtml(group.next_operator_action || "Plan explicitly before creating retests.")}</p>
      ${renderBadgeList(group.targets || [], "compact-badge-list split-top")}
    </article>
  `;
}

function renderRemediationPortfolioItem(item) {
  const owner = formatOptional(item.remediation_owner, "Unassigned");
  const retestLabel = item.eligible_for_retest ? "eligible for retest plan" : "not retest-plan eligible";
  return `
    <article class="artifact-card" data-testid="remediation-portfolio-item">
      <h4>${escapeHtml(item.finding?.title || "Finding")}</h4>
      <div class="inline-metrics">
        ${severityPill(item.finding?.severity || "unknown")}
        ${statusPill(item.sla_status || "unknown")}
        <span class="metric-pill">${escapeHtml(humanizeValue(item.remediation_state))}</span>
        <span class="metric-pill">${escapeHtml(owner)}</span>
      </div>
      <p class="micro-copy split-top">${escapeHtml(`${retestLabel} · ${formatOptional(item.retest_planning_reason, "No retest reason recorded.")}`)}</p>
      <p class="micro-copy">${escapeHtml(`Due: ${formatOptional(item.sla_due_at, "No SLA due date")} · Verification: ${humanizeValue(item.verification_state)}`)}</p>
    </article>
  `;
}

function formatOptional(value, fallback = "Not recorded") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function humanizeValue(value, fallback = "Not recorded") {
  return formatOptional(value, fallback).replace(/_/g, " ");
}

function renderBriefMetric(label, value) {
  return `
    <div>
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(formatOptional(value))}</strong>
    </div>
  `;
}

function evidenceReadiness(theater, evidence) {
  const integrity = theater?.evidence_integrity || {};
  if (integrity.ready_for_replay) {
    return {
      label: "Hash verified recipe ready",
      detail: "Stored SHA-256 and replay recipe are present for operator reproduction.",
      tone: "ready",
    };
  }
  const executions = Array.isArray(evidence?.related_executions) ? evidence.related_executions : [];
  if (executions.length) {
    return {
      label: `${executions.length} execution${executions.length === 1 ? "" : "s"} matched`,
      detail: "Stored task output and artifact links are available for replay.",
      tone: "ready",
    };
  }
  if (theater.finding.evidence_ref) {
    return {
      label: "Evidence ref recorded",
      detail: "No related task excerpt matched this finding yet; use Evidence Replay for the stored reference.",
      tone: "partial",
    };
  }
  return {
    label: "Evidence incomplete",
    detail: "No evidence reference or related execution excerpt is attached to this finding.",
    tone: "missing",
  };
}

function renderSeverityMeter(theater) {
  const rank = Number.isFinite(Number(theater.severity_rank))
    ? Math.max(0, Math.min(5, Number(theater.severity_rank)))
    : severityRank(theater.finding.severity);
  const width = Math.max(10, Math.round(((5 - rank) / 5) * 100));
  return `
    <div class="brief-meter" aria-label="${escapeHtml(`Severity posture: ${theater.finding.severity || "unknown"}`)}">
      <span style="width: ${width}%"></span>
    </div>
  `;
}

function renderValidationBadge(validation) {
  if (!validation || !validation.status || validation.status === "unvalidated") return "";

  const tone = String(validation.tone || "neutral");
  const label = String(validation.label || "Validation");
  const suffix = validation.status === "validated_confirmed" ? " \u2713" : "";
  return `<span class="badge validation-badge validation-badge-${escapeHtml(tone)}">${escapeHtml(`${label}${suffix}`)}</span>`;
}

function renderFindingBrief(theater, evidence) {
  const readiness = evidenceReadiness(theater, evidence);
  const integrity = theater.evidence_integrity || {};
  const finding = theater.finding || {};
  const methodologyTags = Array.isArray(theater.methodology?.methodology_tags)
    ? theater.methodology.methodology_tags
    : finding.methodology_tags || [];
  const owaspMapping = finding.owasp_mapping || theater.methodology?.owasp || {};
  const proofReference = finding.proof_reference || {};
  const cvssScore =
    finding?.cvss_score !== null && finding?.cvss_score !== undefined
      ? Number(finding.cvss_score).toFixed(1)
      : null;
  const cvssLabel = cvssScore
    ? `${cvssScore}${finding?.cvss_vector ? ` · ${finding.cvss_vector}` : ""}`
    : null;
  const owaspLabel = owaspMapping.category || finding.owasp_category || "OWASP mapping pending";
  const owaspFramework = owaspMapping.framework || finding.owasp_framework || "OWASP";
  const proofLabel = proofReference.replay_recipe_available
    ? "Replay recipe stored"
    : proofReference.evidence_ref
      ? "Evidence reference stored"
      : "Proof reference pending";
  return `
    <section class="finding-brief" data-testid="finding-brief">
      <div class="finding-brief-hero">
        <div>
          <p class="eyebrow">Evidence Brief</p>
          <h4>${escapeHtml(theater.finding.title)}</h4>
          <p>${escapeHtml(theater.business_impact)}</p>
        </div>
        <div class="pill-grid">
          ${severityPill(theater.finding.severity)}
          ${statusPill(theater.finding.status)}
          ${renderValidationBadge(theater.validation)}
          <span class="badge">${escapeHtml(theater.confidence_label)} confidence</span>
        </div>
      </div>

      <div class="finding-quality-strip split-top" data-testid="finding-quality-strip">
        <article class="finding-quality-card" data-testid="finding-cvss-gauge">
          <p class="eyebrow">CVSS</p>
          <div class="cvss-gauge" style="--cvss-score: ${escapeHtml(String(Math.max(0, Math.min(10, Number(cvssScore || 0))) * 10))}%">
            <strong>${escapeHtml(cvssScore || "0.0")}</strong>
            <span>${escapeHtml(finding.cvss_source || "deterministic")}</span>
          </div>
          <p class="micro-copy">${escapeHtml(finding.cvss_vector || "Deterministic CVSS fallback applied.")}</p>
        </article>
        <article class="finding-quality-card" data-testid="finding-owasp-badge">
          <p class="eyebrow">OWASP</p>
          <h5>${escapeHtml(owaspLabel)}</h5>
          <p>${escapeHtml(owaspFramework)}</p>
          <p class="micro-copy">${escapeHtml(owaspMapping.reference || finding.owasp_reference || "Deterministic finding-type mapping")}</p>
        </article>
        <article class="finding-quality-card" data-testid="finding-proof-reference">
          <p class="eyebrow">Reproduce</p>
          <h5>${escapeHtml(proofLabel)}</h5>
          <p>${escapeHtml(proofReference.evidence_ref || finding.evidence_ref || "No evidence ref recorded")}</p>
          <button class="action primary compact-action split-top" type="button" data-nav-screen="evidence-replay" data-testid="finding-reproduce-button">Reproduce</button>
        </article>
      </div>

      <div class="finding-brief-grid split-top">
        <article class="brief-card" data-testid="finding-risk-brief">
          <p class="eyebrow">Risk Posture</p>
          <h5>${escapeHtml(humanizeValue(finding.severity, "unknown"))}</h5>
          ${renderSeverityMeter(theater)}
          <div class="compact-definition-grid split-top">
            ${renderBriefMetric("Exploitability", humanizeValue(theater.exploitability))}
            ${renderBriefMetric("Status", humanizeValue(finding.status))}
            ${renderBriefMetric("Validation", theater.validation?.label || "Pending review")}
            ${renderBriefMetric("Target", finding.target_id)}
            ${cvssLabel ? renderBriefMetric("CVSS", cvssLabel) : ""}
            ${renderBriefMetric("Confidence", `${formatOptional(theater.confidence_label, "review")} confidence`)}
          </div>
        </article>

        <article class="brief-card" data-testid="finding-evidence-readiness">
          <p class="eyebrow">Evidence Readiness</p>
          <h5>${escapeHtml(readiness.label)}</h5>
          <p>${escapeHtml(readiness.detail)}</p>
          <div class="inline-metrics split-top">
            <span class="metric-pill evidence-${escapeHtml(readiness.tone)}">${escapeHtml(formatOptional(finding.evidence_ref, "No evidence ref"))}</span>
            <span class="metric-pill">${escapeHtml(integrity.hash_status || "hash unknown")}</span>
            <span class="metric-pill">${escapeHtml(integrity.timestamp_status || "timestamp n/a")}</span>
          </div>
          <p class="micro-copy split-top">${escapeHtml(theater.evidence_summary)}</p>
          <button class="action ghost compact-action split-top" type="button" data-finding-verify-evidence>Verify Evidence</button>
        </article>

        <article class="brief-card" data-testid="finding-methodology-brief">
          <p class="eyebrow">Methodology Lineage</p>
          <h5>${escapeHtml(theater.methodology?.control_family || "Not assigned")}</h5>
          <p>${escapeHtml(`PTES ${theater.methodology?.ptes_label || "Not assigned"} · NIST ${theater.methodology?.nist_label || "Not assigned"}`)}</p>
          <p class="micro-copy">${escapeHtml(`WSTG ${theater.methodology?.wstg_reference || "Not assigned"} · ASVS ${theater.methodology?.asvs_reference || "Not assigned"}`)}</p>
          ${renderBadgeList(methodologyTags, "compact-badge-list split-top")}
        </article>

        <article class="brief-card" data-testid="finding-provenance-brief">
          <p class="eyebrow">Provenance</p>
          <h5>${escapeHtml(findingOriginLabel(theater.provenance?.origin))}</h5>
          <p>${escapeHtml(`Pack version: ${theater.provenance?.source_pack_version || "Standard coverage"}`)}</p>
          <p class="micro-copy">${escapeHtml(`Inventory ${theater.provenance?.source_inventory_snapshot_id || "n/a"} · Relevance ${theater.provenance?.source_relevance_decision_id || "n/a"}`)}</p>
        </article>
      </div>

      <div class="section-note split-top">
        <strong>Operator Readout</strong>
        <p>${escapeHtml(`This item is currently ${finding.status} and originated from ${findingOriginLabel(theater.provenance?.origin)} coverage against ${finding.target_id}.`)}</p>
        <p class="micro-copy">${escapeHtml(theater.technical_details)}</p>
      </div>
    </section>
  `;
}

function renderFalsePositiveDecision(finding) {
  if (!finding?.false_positive_reason) return "";
  const reviewer = finding.false_positive_confirmed_by || "operator";
  return `
    <div class="detail-surface split-top" data-testid="finding-false-positive-decision">
      <div class="panel-header-row">
        <div>
          <p class="eyebrow">False Positive Decision</p>
          <h4>Confirmed by ${escapeHtml(reviewer)}</h4>
        </div>
        ${statusPill("false_positive")}
      </div>
      <p>${escapeHtml(finding.false_positive_reason)}</p>
    </div>
  `;
}

function renderFalsePositiveReviewPanel() {
  return `
    <div class="detail-surface split-top hidden" data-finding-fp-panel data-testid="finding-false-positive-panel">
      <div class="panel-header-row">
        <div>
          <p class="eyebrow">False Positive Review</p>
          <h4>Reason required before closing</h4>
        </div>
      </div>
      <textarea
        class="settings-textarea"
        data-finding-fp-reason
        data-testid="finding-false-positive-reason"
        rows="3"
        placeholder="Explain why this finding is not exploitable or not applicable in the approved scope."
      ></textarea>
      <div class="action-row split-top">
        <button class="action primary" type="button" data-finding-fp-submit>Confirm false positive</button>
      </div>
    </div>
  `;
}

function renderFindingValidationCard(validation) {
  if (!validation) return "";

  const latest = validation.latest_attempt || null;
  return `
    <div class="detail-surface" data-testid="finding-validation-card">
      <div class="panel-header-row">
        <div>
          <p class="eyebrow">Validation</p>
          <h4>${escapeHtml(validation.label || "Pending review")}</h4>
        </div>
        <div class="inline-metrics">
          ${renderValidationBadge(validation)}
        </div>
      </div>
      <p>${escapeHtml(formatOptional(validation.note, "No automated re-probe has been recorded for this finding yet."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Lifecycle", humanizeValue(validation.status))}
        ${renderBriefMetric("Tool", formatOptional(latest?.validator_tool, "not recorded"))}
        ${renderBriefMetric("Target", formatOptional(latest?.validator_target_id, "not recorded"))}
        ${renderBriefMetric("Profile", formatOptional(latest?.validation_profile_name, "not recorded"))}
      </div>
    </div>
  `;
}

function renderFindingMethodologyCard(theater) {
  return `
    <div class="detail-surface" data-testid="finding-verification-card">
      <h4>Verification</h4>
      <p>${escapeHtml(theater.verification_status)}</p>
      <p>${escapeHtml(theater.evidence_summary)}</p>
      <p class="micro-copy">${escapeHtml(`Exploitability: ${humanizeValue(theater.exploitability)}`)}</p>
    </div>
  `;
}

function renderFindingEvidenceTerminal(theater, evidence) {
  const executions = Array.isArray(evidence?.related_executions) ? evidence.related_executions : [];
  const header = executions.length
    ? `${executions.length} matched task execution${executions.length === 1 ? "" : "s"}`
    : "No matched execution excerpt";
  return `
    <section class="evidence-terminal split-top ${executions.length ? "" : "is-empty"}" data-testid="finding-evidence-terminal">
      <div class="evidence-terminal-bar">
        <span>Evidence Terminal</span>
        <code>${escapeHtml(header)}</code>
      </div>
      ${
        executions.length
          ? executions.slice(0, 2).map((execution) => renderTerminalExecution(execution)).join("")
          : `<p>${escapeHtml(theater.finding.evidence_ref ? "This finding has an evidence reference, but no related execution excerpt is currently matched to it." : "This sparse finding does not have an evidence reference or related execution excerpt yet.")}</p>`
      }
    </section>
  `;
}

function renderFindingReplayContext(theater, evidence) {
  const executions = Array.isArray(evidence?.related_executions) ? evidence.related_executions : [];
  const artifacts = executions.flatMap((execution) => Array.isArray(execution.artifacts) ? execution.artifacts : []);
  const validationHistory = Array.isArray(evidence?.validation_history) ? evidence.validation_history : [];
  const packLabel = evidence?.pack_provenance?.name
    ? `${evidence.pack_provenance.name} ${evidence.pack_provenance.version || ""}`.trim()
    : "Standard coverage";
  const inventoryLabel = evidence?.inventory_source?.snapshot_id || theater.provenance?.source_inventory_snapshot_id || "n/a";
  const relevanceLabel = evidence?.relevance_source?.decision_id || theater.provenance?.source_relevance_decision_id || "n/a";
  const evidenceRef = evidence?.evidence_ref || theater.finding.evidence_ref || "No evidence ref recorded";
  const replayRecipe = theater.evidence_integrity?.replay_recipe || theater.finding.replay_recipe_json || null;

  return `
    <section class="detail-surface split-top" data-testid="finding-evidence-replay-context">
      <div class="section-note">
        <strong>Evidence Replay context is attached here</strong>
        <p>Finding Theater now carries the replay summary operators need for triage, so reproduction evidence, artifacts, provenance, remediation, and next steps stay in one decision surface.</p>
      </div>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Evidence Ref", evidenceRef)}
        ${renderBriefMetric("Executions", `${executions.length}`)}
        ${renderBriefMetric("Artifacts", `${artifacts.length}`)}
        ${renderBriefMetric("Validation History", `${validationHistory.length}`)}
        ${renderBriefMetric("Replay Recipe", replayRecipe ? "Stored" : "Missing")}
      </div>
      <div class="detail-grid split-top">
        <div class="detail-surface" data-testid="finding-evidence-replay-executions">
          <h4>Replay Executions</h4>
          ${
            executions.length
              ? executions
                  .slice(0, 3)
                  .map(
                    (execution) => `
                      <div class="artifact-card">
                        <h4>${escapeHtml(`${execution.tool} · ${execution.target_id}`)}</h4>
                        <p>${statusPill(execution.task_status)} ${escapeHtml(`exit ${formatOptional(execution.exit_code, "n/a")} · ${formatOptional(execution.tool_version, "version n/a")}`)}</p>
                        <p class="micro-copy">${escapeHtml(`${(execution.artifacts || []).length} artifact${(execution.artifacts || []).length === 1 ? "" : "s"} linked`)}</p>
                      </div>
                    `
                  )
                  .join("")
              : "<p>No matched replay executions are currently attached to this finding.</p>"
          }
        </div>
        <div class="detail-surface" data-testid="finding-evidence-replay-artifacts">
          <h4>Artifacts & Lineage</h4>
          <p>${escapeHtml(`${artifacts.length} replay artifact${artifacts.length === 1 ? "" : "s"} linked to this finding.`)}</p>
          <p class="micro-copy">${escapeHtml(`Pack ${packLabel} · Inventory ${inventoryLabel} · Relevance ${relevanceLabel}`)}</p>
          ${
            artifacts.length
              ? `<div class="finding-stack split-top">
                  ${artifacts
                    .slice(0, 3)
                    .map(
                      (artifact) => `
                        <div class="artifact-card">
                          <h4>${escapeHtml(artifact.name || artifact.kind || "Evidence artifact")}</h4>
                          <p>${escapeHtml(`${artifact.kind || "artifact"} · ${artifact.redaction_state || "redaction unknown"}`)}</p>
                          <p class="micro-copy">${escapeHtml(`SHA-256 ${artifact.sha256 || "not recorded"} · ${artifact.timestamp_status || "timestamp n/a"}`)}</p>
                          <p class="micro-copy">${escapeHtml(artifact.uri || artifact.download_path || "No artifact URI recorded")}</p>
                        </div>
                      `
                    )
                    .join("")}
                </div>`
              : ""
          }
        </div>
      </div>
      <div class="panel-actions split-top">
        <button class="action ghost" type="button" data-nav-screen="evidence-replay">Open full replay route</button>
        <button class="action primary" type="button" data-finding-verify-evidence>Verify Evidence</button>
        <button class="action ghost" type="button" data-report-center-view="dossier">Open report dossier</button>
      </div>
    </section>
  `;
}

function renderFindingEvidencePanel(theater, evidence) {
  const executions = Array.isArray(evidence?.related_executions) ? evidence.related_executions : [];
  const artifacts = executions.flatMap((execution) => Array.isArray(execution.artifacts) ? execution.artifacts : []);
  const evidenceRef = evidence?.evidence_ref || theater.finding.evidence_ref || "No evidence ref recorded";
  return renderDisclosure({
    title: "Evidence Replay Panel",
    summary: `${executions.length} execution${executions.length === 1 ? "" : "s"} · ${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"} · ${evidenceRef}`,
    open: true,
    className: "split-top",
    testId: "finding-evidence-panel",
    body: `${renderFindingEvidenceTerminal(theater, evidence)}${renderFindingReplayContext(theater, evidence)}`,
  });
}

function renderAutoFix(autofix) {
  const enabled =
    typeof autofix?.enabled === "boolean" ? autofix.enabled : operatorSettingBoolean("ai.autofix_enabled");
  if (!enabled) {
    return `
      <section class="detail-surface split-top" data-testid="finding-autofix">
        <div class="panel-header-row">
          <div>
            <p class="eyebrow">Suggested Fix</p>
            <h4>AutoFix is disabled</h4>
          </div>
          <span class="badge">Advisory only</span>
        </div>
        <p>AutoFix is disabled - enable in Settings &gt; AI Provider.</p>
        <div class="action-row split-top">
          <button class="action secondary compact-action" type="button" data-nav-screen="settings" data-testid="finding-autofix-settings">
            Open Settings
          </button>
        </div>
      </section>
    `;
  }

  if (!autofix || autofix.available !== true || !String(autofix.ai_fix_suggestion || autofix.patch_after || "").trim()) {
    return `
      <section class="detail-surface split-top" data-testid="finding-autofix">
        <div class="panel-header-row">
          <div>
            <p class="eyebrow">Suggested Fix</p>
            <h4>AutoFix suggested fix</h4>
          </div>
          <span class="badge">Advisory only</span>
        </div>
        <p>No suggestion available - re-run with AutoFix enabled.</p>
      </section>
    `;
  }

  const aiGenerated = Boolean(
    autofix.ai_generated ||
      autofix.ai_fix_suggestion ||
      String(autofix.provider || "").toLowerCase() === "chatgpt_oauth"
  );
  const disclaimer =
    autofix.disclaimer ||
    "This is an AI-generated suggestion. Review before applying. Do not apply to production without testing.";
  const eyebrow = aiGenerated ? "Suggested Fix" : "AutoFix";
  const heading = aiGenerated ? "AI-generated remediation suggestion" : "Advisory patch";

  return `
    <section class="detail-surface split-top" data-testid="finding-autofix">
      <div class="panel-header-row">
        <div>
          <p class="eyebrow">${escapeHtml(eyebrow)}</p>
          <h4>${escapeHtml(heading)}</h4>
        </div>
        <div class="inline-metrics">
          <span class="badge">Advisory only</span>
          ${aiGenerated ? `<span class="badge">AI generated</span>` : ""}
          <span class="metric-pill">${escapeHtml(formatOptional(autofix.confidence, "review"))} confidence</span>
          <span class="metric-pill">${escapeHtml(formatOptional(autofix.patch_language, "text"))}</span>
        </div>
      </div>
      ${
        aiGenerated
          ? `<div class="section-note autofix-ai-disclaimer" data-testid="finding-autofix-ai-disclaimer">${escapeHtml(disclaimer)}</div>`
          : ""
      }
      <p>${escapeHtml(formatOptional(autofix.patch_explanation, "No patch explanation recorded."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Provider", formatOptional(autofix.provider, "not recorded"))}
        ${renderBriefMetric("Model", formatOptional(autofix.model, "not recorded"))}
        ${renderBriefMetric("Verification", formatOptional(autofix.verification_command, "manual review"))}
      </div>
      <pre class="report-preview autofix-diff" data-testid="finding-autofix-diff"><code>${buildAutofixDiff(autofix)}</code></pre>
      <div class="action-row split-top">
        <button class="action ghost" type="button" data-copy-fix data-testid="copy-fix-button">Copy Fix</button>
      </div>
    </section>
  `;
}

function renderRepositoryContext(repositoryContext) {
  if (!repositoryContext || repositoryContext.available !== true) return "";

  const lineSummary =
    Number(repositoryContext.line_start) === Number(repositoryContext.line_end)
      ? `${formatOptional(repositoryContext.line_start, "?")}`
      : `${formatOptional(repositoryContext.line_start, "?")}-${formatOptional(repositoryContext.line_end, "?")}`;
  const latestPullRequest = repositoryContext.latest_pull_request;

  return `
    <section class="detail-surface split-top" data-testid="finding-repository-context">
      <div class="panel-header-row">
        <div>
          <p class="eyebrow">Repository Context</p>
          <h4>${escapeHtml(formatOptional(repositoryContext.repository_path, "Matched source file"))}</h4>
        </div>
        <div class="inline-metrics">
          <span class="metric-pill">${escapeHtml(formatOptional(repositoryContext.provider, "repository"))}</span>
          <span class="metric-pill">line ${escapeHtml(formatOptional(repositoryContext.highlighted_line, "?"))}</span>
        </div>
      </div>
      <p>${escapeHtml(formatOptional(repositoryContext.detail, "Connected repository context is available for this finding."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Repository", formatOptional(repositoryContext.repository_url, "not recorded"))}
        ${renderBriefMetric("Branch", formatOptional(repositoryContext.repository_branch, "main"))}
        ${renderBriefMetric("Snippet Range", lineSummary)}
      </div>
      <pre class="report-preview repository-snippet" data-testid="finding-repository-snippet"><code>${buildRepositorySnippet(repositoryContext)}</code></pre>
      ${
        latestPullRequest
          ? `<div class="section-note split-top" data-testid="finding-repository-pr-note">
              <strong>Latest Fix PR</strong>
              <p>${escapeHtml(`PR ${formatOptional(latestPullRequest.pull_request_id, "created")} on branch ${formatOptional(latestPullRequest.branch_name, "not recorded")}`)}</p>
              <p class="micro-copy">${escapeHtml(`Auto-merge: ${latestPullRequest.auto_merge_enabled ? "enabled" : "disabled"} · created by ${formatOptional(latestPullRequest.created_by, "operator")}`)}</p>
            </div>`
          : ""
      }
      <div class="action-row split-top">
        <a class="action ghost" href="${escapeHtml(formatOptional(repositoryContext.external_url, "#"))}" target="_blank" rel="noreferrer">View in ${escapeHtml(formatOptional(repositoryContext.provider, "repository"))}</a>
        ${
          repositoryContext.pull_request_supported
            ? `<button class="action ghost" type="button" data-create-fix-pr data-testid="create-fix-pr-button">Create Fix PR</button>`
            : ""
        }
        ${
          latestPullRequest?.pull_request_url
            ? `<a class="action ghost" href="${escapeHtml(latestPullRequest.pull_request_url)}" target="_blank" rel="noreferrer">Open Latest PR</a>`
            : ""
        }
      </div>
    </section>
  `;
}

function buildAutofixDiff(autofix) {
  const patchLanguage = String(autofix.patch_language || "txt").trim() || "txt";
  const beforeLines = String(autofix.patch_before || "")
    .split("\n")
    .map((line) => `<span class="autofix-diff-line autofix-diff-line-remove">- ${escapeHtml(line)}</span>`)
    .join("");
  const afterLines = String(autofix.patch_after || "")
    .split("\n")
    .map((line) => `<span class="autofix-diff-line autofix-diff-line-add">+ ${escapeHtml(line)}</span>`)
    .join("");
  return [
    `<span class="autofix-diff-line autofix-diff-line-meta">--- vulnerable.${escapeHtml(patchLanguage)}</span>`,
    `<span class="autofix-diff-line autofix-diff-line-meta">+++ suggested.${escapeHtml(patchLanguage)}</span>`,
    `<span class="autofix-diff-line autofix-diff-line-meta">@@ advisory patch @@</span>`,
    beforeLines,
    afterLines,
  ].join("");
}

function buildRepositorySnippet(repositoryContext) {
  const highlightedLine = Number(repositoryContext.highlighted_line || 0);
  return String(repositoryContext.snippet_text || "")
    .split("\n")
    .map((line) => {
      const match = line.match(/^(\d+):\s?(.*)$/);
      const lineNumber = match ? Number(match[1]) : null;
      const code = match ? match[2] : line;
      const highlighted = lineNumber !== null && lineNumber === highlightedLine;
      return `
        <span class="repository-snippet-line ${highlighted ? "repository-snippet-line-highlight" : ""}">
          <span class="repository-snippet-line-number">${escapeHtml(match ? match[1] : "")}</span>
          <span class="repository-snippet-line-code">${escapeHtml(code)}</span>
        </span>
      `;
    })
    .join("");
}

function renderTerminalExecution(execution) {
  const stdout = formatOptional(execution.stdout_excerpt, "");
  const stderr = formatOptional(execution.stderr_excerpt, "");
  const hasOutput = Boolean(stdout || stderr);
  const transcript = [
    `$ ${execution.tool} ${execution.target_id}`,
    `status=${execution.task_status} exit=${execution.exit_code} version=${execution.tool_version}`,
    stdout ? `\n[stdout]\n${stdout}` : "",
    stderr ? `\n[stderr]\n${stderr}` : "",
  ]
    .filter(Boolean)
    .join("\n");
  return `
    <article class="evidence-terminal-entry">
      <div class="compact-definition-grid">
        ${renderBriefMetric("Tool", execution.tool)}
        ${renderBriefMetric("Target", execution.target_id)}
        ${renderBriefMetric("Task Status", humanizeValue(execution.task_status))}
        ${renderBriefMetric("Artifacts", `${(execution.artifacts || []).length}`)}
      </div>
      ${
        hasOutput
          ? `<pre class="evidence-terminal-output"><code>${escapeHtml(transcript)}</code></pre>`
          : `<p class="micro-copy split-top">Execution metadata is matched, but no stdout or stderr excerpt was stored for this finding.</p>`
      }
    </article>
  `;
}

function renderAiEnrichment(aiEnrichment) {
  const status = String(aiEnrichment?.status || "disabled").toLowerCase();
  const available = aiEnrichment?.available === true;
  const canEnrich = canRequestFindingAiEnrichment(aiEnrichment);
  const findingId = state.selectedFindingTheater?.finding?.id || state.selectedFindingId || "";
  const label = available
    ? aiEnrichment.label || `Enriched by ${formatOptional(aiEnrichment.provider, "AI")}`
    : status === "enriching" || status === "queued"
      ? "Enriching"
      : canEnrich
        ? "Not yet enriched"
        : "Enrichment unavailable";
  const badgeTone = available ? "success" : status === "enriching" || status === "queued" ? "info" : "muted";
  const idleCopy = canEnrich
    ? "This finding has not been enriched yet."
    : "Connect or enable an AI provider to add advisory business impact and remediation guidance.";

  return `
    <div class="section-note split-top" data-testid="finding-ai-enrichment">
      <div class="ai-enrichment-head">
        <strong>AI Enrichment</strong>
        <span class="ai-enrichment-status ${badgeTone}" data-testid="finding-ai-enrichment-status">${escapeHtml(label)}</span>
      </div>
      ${
        available
          ? `
            <p>${escapeHtml(formatOptional(aiEnrichment.business_impact, "No enriched business impact recorded."))}</p>
            <p>${escapeHtml(formatOptional(aiEnrichment.technical_context, "No enriched technical context recorded."))}</p>
            <p class="micro-copy">${escapeHtml(formatOptional(aiEnrichment.remediation_narrative, "No enriched remediation narrative recorded."))}</p>
            <p class="micro-copy">${escapeHtml(`Provider: ${formatOptional(aiEnrichment.provider, "not recorded")}`)}</p>
          `
          : `<p class="micro-copy">${escapeHtml(
              status === "enriching" || status === "queued"
                ? "AegisPT is preparing business impact and remediation guidance in the background."
                : idleCopy
            )}</p>`
      }
      ${
        canEnrich
          ? `<button class="action secondary compact-action split-top" type="button" data-finding-ai-enrich="${escapeHtml(findingId)}" data-testid="finding-ai-enrich-now">Enrich Now</button>`
          : ""
      }
    </div>
  `;
}

async function copyTextToClipboard(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const helper = document.createElement("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "readonly");
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.appendChild(helper);
  helper.select();
  document.execCommand("copy");
  document.body.removeChild(helper);
}

function renderContextualIntelligence(contextualIntelligence) {
  if (!contextualIntelligence || contextualIntelligence.available !== true) return "";

  const prerequisites = Array.isArray(contextualIntelligence.prerequisites)
    ? contextualIntelligence.prerequisites
    : [];
  const exploitability = contextualIntelligence.exploitability || {};
  const remediation = contextualIntelligence.remediation || {};
  const boundaries = contextualIntelligence.boundaries || {};
  const environmentContext = contextualIntelligence.environment_context || {};
  const threatIntelContext = contextualIntelligence.threat_intel_context || {};
  const immediateActions = Array.isArray(remediation.immediate_actions) ? remediation.immediate_actions : [];
  const verificationSteps = Array.isArray(remediation.verification_steps) ? remediation.verification_steps : [];
  const rollbackCautions = Array.isArray(remediation.rollback_cautions) ? remediation.rollback_cautions : [];
  const prioritizationNotes = Array.isArray(remediation.prioritization_notes)
    ? remediation.prioritization_notes
    : [];

  return `
    <section class="detail-surface split-top" data-testid="finding-contextual-intelligence">
      <p class="eyebrow">Contextual Intelligence</p>
      <h4>Exploitability and Remediation Context</h4>
      <p>${escapeHtml(formatOptional(exploitability.rationale, "Exploitability remains operator-reviewable guidance."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Status", humanizeValue(contextualIntelligence.status))}
        ${renderBriefMetric("Exploitability", humanizeValue(exploitability.label))}
        ${renderBriefMetric("Confidence", `${formatOptional(exploitability.confidence, "review")} · ${Math.round(Number(exploitability.confidence_score || 0) * 100)}%`)}
        ${renderBriefMetric("Environment", environmentContext.available ? "Inventory-grounded" : "No inventory context")}
        ${renderBriefMetric("Threat Intel", threatIntelContext.available ? `${threatIntelContext.matched_badge_count || 0} local badge(s)` : "No local badge")}
        ${renderBriefMetric("Automation", boundaries.automatic_exploitation === false ? "No exploit execution" : "Review required")}
      </div>
      <div class="finding-stack split-top">
        ${prerequisites
          .map(
            (item) => `
              <article class="artifact-card" data-testid="finding-contextual-prerequisite">
                <h4>${escapeHtml(formatOptional(item.title, "Prerequisite"))}</h4>
                <p>${escapeHtml(formatOptional(item.basis, "No prerequisite basis recorded."))}</p>
                <div class="inline-metrics split-top">
                  <span class="metric-pill">${escapeHtml(humanizeValue(item.status, "review"))}</span>
                  <span class="metric-pill">${escapeHtml(formatOptional(item.id, "prerequisite"))}</span>
                </div>
              </article>
            `
          )
          .join("")}
      </div>
      <div class="detail-grid split-top">
        ${renderGuidanceList("Immediate Remediation", immediateActions, "No immediate remediation guidance recorded.")}
        ${renderGuidanceList("Verification Steps", verificationSteps, "No verification steps recorded.")}
        ${renderGuidanceList("Rollback Cautions", rollbackCautions, "No rollback cautions recorded.")}
        ${renderGuidanceList("Prioritization Notes", prioritizationNotes, "No prioritization notes recorded.")}
      </div>
      <p class="micro-copy split-top">${escapeHtml(formatOptional(boundaries.message, "Guidance is review-only and does not mutate findings."))}</p>
    </section>
  `;
}

function renderGuidanceList(title, items, fallback) {
  const values = Array.isArray(items) ? items.filter((item) => item !== null && item !== undefined && item !== "") : [];
  return `
    <div class="section-note">
      <strong>${escapeHtml(title)}</strong>
      ${
        values.length
          ? `<ul>${values.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
          : `<p>${escapeHtml(fallback)}</p>`
      }
    </div>
  `;
}

function renderThreatContext(threatContext) {
  if (!threatContext) return "";

  const mappings = Array.isArray(threatContext.mappings) ? threatContext.mappings : [];
  const boundary = threatContext.attribution_boundary || {};
  const evidenceBasis = threatContext.evidence_basis || {};
  const referenceList = Array.isArray(evidenceBasis.detected_references)
    ? evidenceBasis.detected_references
    : [];

  if (threatContext.available !== true) {
    return `
      <section class="detail-surface split-top" data-testid="finding-threat-context">
        <p class="eyebrow">Threat Context</p>
        <h4>Threat context not mapped</h4>
        <p>${escapeHtml(formatOptional(threatContext.detail, "Stored evidence did not support a curated threat-context mapping."))}</p>
        <p class="micro-copy">${escapeHtml(formatOptional(boundary.statement, "No actor attribution is claimed."))}</p>
      </section>
    `;
  }

  return `
    <section class="detail-surface split-top" data-testid="finding-threat-context">
      <p class="eyebrow">Threat Context</p>
      <h4>${escapeHtml(threatContext.status === "low_confidence" ? "Low-confidence technique context" : "Technique context")}</h4>
      <p>${escapeHtml(formatOptional(threatContext.summary, "Technique context is contextual guidance only."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Mode", threatContext.mode)}
        ${renderBriefMetric("Source", threatContext.source?.name)}
        ${renderBriefMetric("Actor Attribution", boundary.claims_actor_attribution === false ? "Not claimed" : "Review required")}
        ${renderBriefMetric("Severity Impact", boundary.changes_severity === false ? "No severity change" : "Review required")}
      </div>
      ${
        referenceList.length
          ? `<div class="split-top">${renderBadgeList(referenceList, "compact-badge-list")}</div>`
          : ""
      }
      <div class="finding-stack split-top">
        ${mappings
          .map(
            (mapping) => `
              <article class="artifact-card">
                <h4>${escapeHtml(`${mapping.technique_id || "Technique"} · ${mapping.technique_name || "Context mapping"}`)}</h4>
                <p>${escapeHtml(formatOptional(mapping.relevance, "No relevance note recorded."))}</p>
                <div class="inline-metrics split-top">
                  <span class="metric-pill">${escapeHtml(formatOptional(mapping.tactic, "tactic n/a"))}</span>
                  <span class="metric-pill">${escapeHtml(`${formatOptional(mapping.confidence, "review")} confidence`)}</span>
                  <span class="metric-pill">${escapeHtml(formatOptional(mapping.actor_attribution, "not assessed"))}</span>
                </div>
                ${renderBadgeList(mapping.matched_signals || [], "compact-badge-list split-top")}
                <p class="micro-copy split-top">${escapeHtml(formatOptional(mapping.source_taxonomy, "Curated mapping source not recorded."))}</p>
              </article>
            `
          )
          .join("")}
      </div>
      <p class="micro-copy split-top">${escapeHtml(formatOptional(boundary.statement, "No actor attribution is claimed."))}</p>
    </section>
  `;
}

function renderThreatIntelBadges(threatIntelBadges) {
  if (!threatIntelBadges) return "";

  const badges = Array.isArray(threatIntelBadges.badges) ? threatIntelBadges.badges : [];
  const boundary = threatIntelBadges.boundary || {};
  if (!badges.length) {
    return `
      <section class="detail-surface split-top" data-testid="finding-threat-intel-badges">
        <p class="eyebrow">Threat Intel Badges</p>
        <h4>No local threat-intel badge</h4>
        <p>${escapeHtml(formatOptional(threatIntelBadges.no_badge_reason, "No approved local feed record matched this finding."))}</p>
        <p class="micro-copy">${escapeHtml(formatOptional(boundary.message, "Threat-intel matching is local-cache only."))}</p>
      </section>
    `;
  }

  return `
    <section class="detail-surface split-top" data-testid="finding-threat-intel-badges">
      <p class="eyebrow">Threat Intel Badges</p>
      <h4>Local feed matches</h4>
      <p>${escapeHtml(formatOptional(boundary.message, "Threat-intel matching is local-cache only."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Matched Badges", `${badges.length}`)}
        ${renderBriefMetric("External Lookup", boundary.external_lookup_performed === false ? "Not performed" : "Review required")}
        ${renderBriefMetric("Actor Attribution", boundary.claims_actor_attribution === false ? "Not claimed" : "Review required")}
        ${renderBriefMetric("Severity Change", boundary.changes_finding_severity === false ? "No severity change" : "Review required")}
      </div>
      <div class="finding-stack split-top">
        ${badges.map((badge) => renderThreatIntelBadgeCard(badge)).join("")}
      </div>
    </section>
  `;
}

function renderThreatIntelBadgeCard(badge) {
  const references = Array.isArray(badge.references) ? badge.references : [];
  const matchedTerms = Array.isArray(badge.matched_terms) ? badge.matched_terms : [];
  const generatedTemplate = badge.generated_template || null;
  return `
    <article class="artifact-card" data-testid="finding-threat-intel-badge">
      <h4>${escapeHtml(formatOptional(badge.label, "Threat-intel badge"))}</h4>
      <p>${escapeHtml(formatOptional(badge.title, "No local feed title recorded."))}</p>
      <div class="inline-metrics split-top">
        <span class="metric-pill">${escapeHtml(formatOptional(badge.source, "source n/a"))}</span>
        <span class="metric-pill">${escapeHtml(formatOptional(badge.advisory_id, "advisory n/a"))}</span>
        <span class="metric-pill">${escapeHtml(`${humanizeValue(badge.cache_status || "unknown")} cache`)}</span>
        <span class="metric-pill">${escapeHtml(formatOptional(badge.severity, "severity n/a"))}</span>
        ${
          generatedTemplate?.tested_via_generated_template
            ? `<span class="metric-pill success">Tested via generated template</span>`
            : generatedTemplate?.pack_id
              ? `<span class="metric-pill warning">Generated template pending review</span>`
              : ""
        }
      </div>
      ${matchedTerms.length ? `<div class="split-top">${renderBadgeList(matchedTerms, "compact-badge-list")}</div>` : ""}
      ${references.length ? `<div class="split-top">${renderBadgeList(references, "compact-badge-list")}</div>` : ""}
      ${
        generatedTemplate?.pack_id
          ? `<button class="action ghost compact-action split-top" type="button" data-nav-screen="pack-forge">Review generated template in Pack Forge</button>`
          : ""
      }
      <p class="micro-copy split-top">${escapeHtml(formatOptional(badge.cache_detail, "Cache freshness was not recorded."))}</p>
    </article>
  `;
}

function renderDetectionEngineering(detectionEngineering) {
  if (!detectionEngineering) return "";

  const boundary = detectionEngineering.review_boundary || {};
  const suggestions = Array.isArray(detectionEngineering.suggestions)
    ? detectionEngineering.suggestions
    : [];
  const evidenceBasis = detectionEngineering.evidence_basis || {};
  const references = Array.isArray(evidenceBasis.detected_references)
    ? evidenceBasis.detected_references
    : [];
  const sourceTools = Array.isArray(evidenceBasis.source_tools) ? evidenceBasis.source_tools : [];
  const attackScenarios = Array.isArray(evidenceBasis.attack_scenarios)
    ? evidenceBasis.attack_scenarios
    : [];
  const primaryScenario = attackScenarios[0] || {};
  const unsupportedTelemetry = Array.isArray(detectionEngineering.unsupported_telemetry)
    ? detectionEngineering.unsupported_telemetry
    : [];

  if (detectionEngineering.available !== true) {
    return `
      <section class="detail-surface split-top" data-testid="finding-detection-engineering">
        <p class="eyebrow">Detection Engineering</p>
        <h4>Detection guidance unavailable</h4>
        <p>${escapeHtml(formatOptional(detectionEngineering.detail, "Stored evidence did not support a curated detection-engineering suggestion."))}</p>
        <div class="compact-definition-grid split-top">
          ${renderBriefMetric("Reason", humanizeValue(detectionEngineering.reason))}
          ${renderBriefMetric("Mode", detectionEngineering.mode)}
          ${renderBriefMetric("Deploys Rules", boundary.deploys_rules === false || boundary.deploys_siem_rules === false ? "No rule was deployed" : "Review required")}
          ${renderBriefMetric("Production Ready", boundary.production_ready === false || boundary.production_ready_claim === false ? "No" : "Review required")}
        </div>
        <p class="micro-copy split-top">${escapeHtml(formatOptional(boundary.statement, "Detection guidance is advisory only."))}</p>
      </section>
    `;
  }

  return `
    <section class="detail-surface split-top" data-testid="finding-detection-engineering">
      <p class="eyebrow">Detection Engineering</p>
      <h4>Detection Engineering Assistant</h4>
      <p>${escapeHtml(formatOptional(detectionEngineering.summary, "Detection ideas are advisory starting points only."))}</p>
      <div class="section-note split-top">
        <strong>Non-production draft</strong>
        <p>${escapeHtml(formatOptional(boundary.statement, "Operator review is required before any detection content is used."))}</p>
      </div>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Status", humanizeValue(detectionEngineering.status))}
        ${renderBriefMetric("Source", detectionEngineering.source?.name)}
        ${renderBriefMetric("Evidence Ref", evidenceBasis.evidence_ref || "No evidence ref")}
        ${renderBriefMetric("Scenario", primaryScenario.technique_id ? `${primaryScenario.technique_id} ${primaryScenario.technique_name || ""}`.trim() : "No mapped scenario")}
        ${renderBriefMetric("Deploys Rules", boundary.deploys_rules === false || boundary.deploys_siem_rules === false ? "No rule was deployed" : "Review required")}
        ${renderBriefMetric("Production Ready", boundary.production_ready === false || boundary.production_ready_claim === false ? "No" : "Review required")}
      </div>
      ${
        references.length || sourceTools.length
          ? `<div class="split-top">
              ${references.length ? renderBadgeList(references, "compact-badge-list") : ""}
              ${sourceTools.length ? renderBadgeList(sourceTools, "compact-badge-list split-top") : ""}
            </div>`
          : ""
      }
      <div class="finding-stack split-top">
        ${suggestions.map((suggestion) => renderDetectionSuggestion(suggestion)).join("")}
      </div>
      ${
        unsupportedTelemetry.length
          ? `<div class="section-note split-top" data-testid="finding-detection-unsupported-telemetry">
              <strong>Unsupported telemetry marked</strong>
              <p>${escapeHtml(unsupportedTelemetry.map((item) => `${item.source}: ${item.support_status || item.status}`).join("; "))}</p>
            </div>`
          : ""
      }
    </section>
  `;
}

function renderVulnerabilityChains(chainContext) {
  if (!chainContext) return "";

  const chains = Array.isArray(chainContext.chains) ? chainContext.chains : [];
  const boundary = chainContext.boundary || {};

  if (!chains.length) {
    return `
      <section class="detail-surface split-top" data-testid="finding-chain-context">
        <p class="eyebrow">Vulnerability Chains</p>
        <h4>No vulnerability chain detected</h4>
        <p>${escapeHtml(formatOptional(chainContext.no_chain_reason, "No known chain pattern links this finding to another component finding."))}</p>
        <p class="micro-copy">${escapeHtml(formatOptional(boundary.message, "Chain analysis is additive and does not change finding severity."))}</p>
      </section>
    `;
  }

  return `
    <section class="detail-surface split-top" data-testid="finding-chain-context">
      <p class="eyebrow">Vulnerability Chains</p>
      <h4>Evidence-linked chain context</h4>
      <p>${escapeHtml(formatOptional(boundary.message, "Chain analysis is additive and does not change finding severity."))}</p>
      <div class="compact-definition-grid split-top">
        ${renderBriefMetric("Chains", `${chains.length}`)}
        ${renderBriefMetric("Severity Mutation", boundary.auto_escalates_severity === false ? "No auto-escalation" : "Review required")}
        ${renderBriefMetric("Finding Mutation", boundary.mutates_component_findings === false ? "Component findings unchanged" : "Review required")}
        ${renderBriefMetric("Exploit Execution", boundary.executes_exploits === false ? "No chained exploitation" : "Review required")}
      </div>
      <div class="finding-stack split-top">
        ${chains.map((chain) => renderVulnerabilityChainCard(chain)).join("")}
      </div>
    </section>
  `;
}

function renderVulnerabilityChainCard(chain) {
  const components = Array.isArray(chain.component_findings) ? chain.component_findings : [];
  const evidenceRefs = Array.isArray(chain.evidence_refs) ? chain.evidence_refs : [];
  const metadata = chain.metadata || {};
  return `
    <article class="artifact-card" data-testid="finding-chain-card">
      <h4>${escapeHtml(formatOptional(chain.title, "Vulnerability chain"))}</h4>
      <p>${escapeHtml(formatOptional(chain.combined_impact, "Combined impact narrative was not recorded."))}</p>
      <div class="inline-metrics split-top">
        <span class="metric-pill">${escapeHtml(`${humanizeValue(chain.status || "review")} status`)}</span>
        <span class="metric-pill">${escapeHtml(`${Math.round(Number(chain.confidence_score || 0) * 100)}% confidence`)}</span>
        <span class="metric-pill">${escapeHtml(formatOptional(chain.pattern_id, "pattern n/a"))}</span>
      </div>
      ${
        evidenceRefs.length
          ? `<div class="split-top">${renderBadgeList(evidenceRefs, "compact-badge-list")}</div>`
          : `<p class="micro-copy split-top">No shared evidence references were recorded for this chain.</p>`
      }
      <div class="finding-stack split-top">
        ${components
          .map((component) => {
            if (component.missing) {
              return `
                <div class="section-note">
                  <strong>${escapeHtml(component.finding_id)}</strong>
                  <p>Component finding is no longer available in the selected run.</p>
                </div>
              `;
            }
            return `
              <div class="section-note">
                <strong>${escapeHtml(formatOptional(component.title, component.finding_id))}</strong>
                <p>${escapeHtml(`${humanizeValue(component.severity || "unknown")} · ${formatOptional(component.target_id, "target n/a")}`)}</p>
                <p class="micro-copy">${escapeHtml(formatOptional(component.evidence_ref, "No evidence ref"))}</p>
              </div>
            `;
          })
          .join("")}
      </div>
      <p class="micro-copy split-top">${escapeHtml(formatOptional(metadata.operator_note, "Operator review is required before using this chain in a report narrative."))}</p>
    </article>
  `;
}

function renderDetectionSuggestion(suggestion) {
  const telemetrySources = Array.isArray(suggestion.telemetry_sources) ? suggestion.telemetry_sources : [];
  const ruleStartingPoints = Array.isArray(suggestion.rule_starting_points)
    ? suggestion.rule_starting_points
    : [];
  const sourceTrace = Array.isArray(suggestion.source_trace) ? suggestion.source_trace : [];
  return `
    <article class="artifact-card" data-testid="finding-detection-suggestion">
      <h4>${escapeHtml(formatOptional(suggestion.title, "Detection idea"))}</h4>
      <p>${escapeHtml(formatOptional(suggestion.description, "No detection description recorded."))}</p>
      <div class="inline-metrics split-top">
        <span class="metric-pill">${escapeHtml(`${formatOptional(suggestion.confidence, "review")} confidence`)}</span>
        <span class="metric-pill">${escapeHtml(suggestion.operator_review_required ? "operator review required" : "review status unknown")}</span>
        <span class="metric-pill">${escapeHtml(suggestion.production_ready === false ? "non-production draft" : "review production readiness")}</span>
      </div>
      ${
        telemetrySources.length
          ? `<div class="finding-stack split-top">
              ${telemetrySources
                .map(
                  (source) => `
                    <div class="section-note">
                      <strong>${escapeHtml(formatOptional(source.source, "Telemetry source"))}</strong>
                      <p>${escapeHtml(`${formatOptional(source.support_status || source.status, "review")} · ${formatOptional(source.rationale, "No rationale recorded.")}`)}</p>
                    </div>
                  `
                )
                .join("")}
            </div>`
          : ""
      }
      ${
        ruleStartingPoints.length
          ? `<div class="finding-stack split-top">
              ${ruleStartingPoints
                .map(
                  (rule) => `
                    <div class="artifact-card">
                      <h4>${escapeHtml(formatOptional(rule.title, "Rule starting point"))}</h4>
                      <p>${escapeHtml(formatOptional(rule.draft, "No draft logic recorded."))}</p>
                      <p class="micro-copy">${escapeHtml(rule.production_ready === false ? "This rule starting point is not production-ready and was not deployed." : "Production readiness requires review.")}</p>
                    </div>
                  `
                )
                .join("")}
            </div>`
          : ""
      }
      ${sourceTrace.length ? renderBadgeList(sourceTrace, "compact-badge-list split-top") : ""}
    </article>
  `;
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

function renderJiraLinkage(remediation) {
  const jira = remediation?.integrations?.jira || null;
  if (!jira) return "";

  const syncState = formatOptional(jira.last_sync_state, "not synced");
  const issueStatus = formatOptional(jira.issue_status, "Status not synced yet");
  const syncDetail =
    jira.last_sync_state === "failed" && jira.last_sync_error
      ? `Last sync failed: ${jira.last_sync_error}`
      : `Last synced: ${formatOptional(jira.last_synced_at, "Not synced yet")}`;
  return `
    <div class="section-note split-top" data-testid="finding-jira-linkage">
      <strong>Jira Linkage</strong>
      <p>${escapeHtml(`${jira.issue_key} · ${issueStatus}`)}</p>
      <div class="inline-metrics split-top">
        <span class="metric-pill">${escapeHtml(syncState)}</span>
        <span class="metric-pill">${escapeHtml(formatOptional(jira.updated_by, "operator not recorded"))}</span>
      </div>
      <p class="micro-copy">${escapeHtml(syncDetail)}</p>
      <a class="link-like" href="${escapeHtml(jira.issue_url)}" target="_blank" rel="noreferrer">Open Jira Issue</a>
    </div>
  `;
}

function renderJiraHandoffAction(theater) {
  const findingId = theater?.finding?.id;
  if (!findingId) return "";
  const link = theater?.remediation?.integrations?.jira || jiraLinkForFinding(findingId);
  const configured = Boolean(state.jiraIntegrationConfiguration?.id);
  const pushing = state.jiraPushFindingId === findingId;
  if (link) {
    return `
      <div class="section-note split-top" data-testid="finding-jira-pushed">
        <strong>Jira handoff ready</strong>
        <p>${escapeHtml(`${link.issue_key} is linked to this finding.`)}</p>
        <div class="inline-metrics split-top">
          <span class="metric-pill success">Jira</span>
          <span class="metric-pill">${escapeHtml(link.last_sync_state || "not synced")}</span>
        </div>
      </div>
    `;
  }
  if (!configured) {
    return `
      <div class="section-note split-top" data-testid="finding-jira-not-configured">
        <strong>Jira handoff unavailable</strong>
        <p>Configure Jira in Settings before pushing findings to Jira.</p>
        <button class="action ghost compact-action" type="button" data-nav-screen="settings">Open Settings</button>
      </div>
    `;
  }
  return `
    <div class="section-note split-top" data-testid="finding-jira-action">
      <strong>Jira handoff</strong>
      <p>Prepare a Jira ticket link for this finding using the selected engagement configuration.</p>
      <button
        class="action primary compact-action"
        type="button"
        data-jira-push-finding="${escapeHtml(findingId)}"
        data-testid="finding-push-jira"
        ${pushing ? "disabled" : ""}
      >
        ${pushing ? "Pushing..." : "Push to Jira"}
      </button>
    </div>
  `;
}

function workflowProviderLabel(provider, link) {
  const configuredName = link?.display_name || "";
  if (configuredName.trim()) return configuredName.trim();
  const labels = {
    webhook: "Webhook",
    slack: "Slack",
    teams: "Microsoft Teams",
    servicenow: "ServiceNow",
    splunk: "Splunk HEC",
    elastic: "Elastic",
    sentinel: "Azure Sentinel",
  };
  return labels[provider] || formatOptional(provider, "Workflow");
}

function workflowHandoffDetail(link) {
  if (link?.last_sync_state === "failed" && link.last_sync_error) {
    return `Handoff failed: ${link.last_sync_error}`;
  }
  if (link?.last_sync_state === "blocked" && link.last_sync_error) {
    return `Handoff blocked: ${link.last_sync_error}`;
  }
  if (link?.last_sync_state === "prepared") {
    return "Prepared for explicit operator handoff; no background delivery is running.";
  }
  if (link?.last_sync_state === "delivered") {
    return `Delivered at ${formatOptional(link.last_synced_at, "unknown time")}`;
  }
  return `Last updated: ${formatOptional(link?.updated_at, "not recorded")}`;
}

function renderWorkflowHandoffs(remediation) {
  const integrations = remediation?.integrations || {};
  const handoffs = Object.entries(integrations).filter(
    ([provider, link]) => provider !== "jira" && link
  );
  if (!handoffs.length) return "";

  return `
    <div class="section-note split-top" data-testid="finding-workflow-handoffs">
      <strong>Workflow Handoffs</strong>
      <p>${escapeHtml(`${handoffs.length} controlled handoff reference${handoffs.length === 1 ? "" : "s"} recorded.`)}</p>
      <div class="finding-stack split-top">
        ${handoffs
          .map(([provider, link]) => {
            const handoffUrl = String(link.issue_url || "");
            const canOpen = handoffUrl.startsWith("https://") || handoffUrl.startsWith("http://");
            return `
              <div class="artifact-card" data-testid="finding-workflow-handoff-${escapeHtml(provider)}">
                <h4>${escapeHtml(workflowProviderLabel(provider, link))}</h4>
                <p>${escapeHtml(`${formatOptional(link.issue_key, "handoff reference")} · ${humanizeValue(link.issue_status, "status pending")}`)}</p>
                <div class="inline-metrics split-top">
                  <span class="metric-pill">${escapeHtml(formatOptional(link.last_sync_state, "not synced"))}</span>
                  <span class="metric-pill">${escapeHtml(formatOptional(link.updated_by, "operator not recorded"))}</span>
                </div>
                <p class="micro-copy">${escapeHtml(workflowHandoffDetail(link))}</p>
                ${canOpen ? `<a class="link-like" href="${escapeHtml(handoffUrl)}" target="_blank" rel="noreferrer">Open Handoff Reference</a>` : ""}
              </div>
            `;
          })
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
    return renderActionEmptyCard("No findings are available yet.", {
      label: "Start a mission",
      screen: "wizard",
    });
  }
  if (allFindings.length) {
    return `
      <div class="detail-surface empty-detail-surface">
        <div class="empty-state">
          <div class="empty-state-copy">
            <span class="empty-icon" aria-hidden="true"></span>
            <span>No findings match the current filters.</span>
          </div>
          <button class="action ghost empty-state-action" type="button" data-findings-reset-filters="true">Clear filters</button>
        </div>
      </div>
    `;
  }
  const runStatus = String(selectedRun.status || "unknown").toLowerCase();
  const inProgressStatuses = new Set(["queued", "running", "pending_approval", "cancelling"]);
  const terminalGapStatuses = new Set(["failed", "cancelled", "rejected", "completed_with_errors"]);
  if (inProgressStatuses.has(runStatus)) {
    return renderActionEmptyCard(
      `No findings are stored yet because this run is ${runStatus.replaceAll("_", " ")}.`,
      {
        label: "Open Mission Control",
        screen: "mission-control",
      }
    );
  }
  if (terminalGapStatuses.has(runStatus)) {
    return renderActionEmptyCard(
      `No findings are stored for this ${runStatus.replaceAll("_", " ")} run. Review the execution evidence before creating a follow-up.`,
      {
        label: "Open Evidence Replay",
        screen: "evidence-replay",
      }
    );
  }
  const runGuidance = buildInventoryRunGuidance(selectedRun);
  if (runGuidance) {
    return `
      <div class="detail-surface emphasis-surface empty-detail-surface" data-testid="${escapeHtml(runGuidance.testId)}">
        ${emptyState("No findings were created in this run.", {
          label: "Open Surface Map",
          screen: "surface-map",
        })}
      </div>
    `;
  }

  return renderActionEmptyCard("No findings exist yet for this engagement.", {
    label: "Open Mission Control",
    screen: "mission-control",
  });
}

function renderNoFindingDetailState(selectedRun, allFindings) {
  if (!selectedRun) {
    return renderActionEmptyCard("No finding is selected yet.", {
      label: "Start a mission",
      screen: "wizard",
    });
  }
  if (allFindings.length) {
    return renderActionEmptyCard("Select a finding to inspect it.", {
      label: "Review the queue",
      screen: "findings-theater",
    });
  }
  const runStatus = String(selectedRun.status || "unknown").toLowerCase();
  if (["queued", "running", "pending_approval", "cancelling"].includes(runStatus)) {
    return renderActionEmptyCard(
      `Finding detail unlocks after this ${runStatus.replaceAll("_", " ")} run stores evidence-backed findings.`,
      {
        label: "Open Mission Control",
        screen: "mission-control",
      }
    );
  }
  if (["failed", "cancelled", "rejected", "completed_with_errors"].includes(runStatus)) {
    return renderActionEmptyCard(
      "No finding detail is available for this run outcome. Evidence Replay keeps the execution trail.",
      {
        label: "Open Evidence Replay",
        screen: "evidence-replay",
      }
    );
  }
  const runGuidance = buildInventoryRunGuidance(selectedRun);
  if (runGuidance) {
    return `
      <div class="detail-surface empty-detail-surface" data-testid="${escapeHtml(runGuidance.detailTestId)}">
        ${emptyState("No finding detail is available for this run yet.", {
          label: "Open Surface Map",
          screen: "surface-map",
        })}
      </div>
    `;
  }

  return renderActionEmptyCard("No findings exist yet for this engagement.", {
    label: "Open Mission Control",
    screen: "mission-control",
  });
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
