import { api, apiOrNull } from "./api.js";
import { dom, patchState, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  formatExposureScore,
  renderDisclosure,
  severityPill,
  statusPill,
} from "./shared.js";

const DEFAULT_FILTERS = {
  severity: "critical,high",
  status: "open",
  engagementId: "all",
  assignee: "all",
  age: "all",
  methodology: "all",
};

function problemsUi() {
  if (!state.problemsUi) {
    state.problemsUi = {
      selectedIds: [],
      forecastSelectedIds: [],
      expandedId: null,
      recentlyResolvedOpen: true,
      filters: { ...DEFAULT_FILTERS },
    };
  }
  return state.problemsUi;
}

function setProblemsUi(patch, reason) {
  patchState(
    {
      problemsUi: {
        ...problemsUi(),
        ...patch,
      },
    },
    reason
  );
}

function setProblemFilters(patch) {
  setProblemsUi(
    {
      selectedIds: [],
      filters: {
        ...DEFAULT_FILTERS,
        ...(problemsUi().filters || {}),
        ...patch,
      },
    },
    "problems.filters"
  );
}

function problemQuery() {
  const filters = { ...DEFAULT_FILTERS, ...(problemsUi().filters || {}) };
  const params = new URLSearchParams();
  params.set("severity", filters.severity || DEFAULT_FILTERS.severity);
  params.set("status", filters.status || DEFAULT_FILTERS.status);
  if (filters.engagementId && filters.engagementId !== "all") params.set("engagement_id", filters.engagementId);
  if (filters.assignee && filters.assignee !== "all") params.set("assignee", filters.assignee);
  if (filters.age && filters.age !== "all") params.set("age", filters.age);
  if (filters.methodology && filters.methodology !== "all") params.set("methodology", filters.methodology);
  return params.toString();
}

function selectedSet() {
  return new Set(problemsUi().selectedIds || []);
}

function forecastSelectedSet() {
  return new Set(problemsUi().forecastSelectedIds || []);
}

function updateSelected(findingId, checked) {
  const next = selectedSet();
  if (checked) {
    next.add(String(findingId));
  } else {
    next.delete(String(findingId));
  }
  setProblemsUi({ selectedIds: [...next] }, "problems.selection");
}

function updateForecastSelected(findingId, checked) {
  const next = forecastSelectedSet();
  if (checked) {
    next.add(String(findingId));
  } else {
    next.delete(String(findingId));
  }
  setProblemsUi({ forecastSelectedIds: [...next] }, "problems.forecast.selection");
}

function groupBySeverity(items) {
  return (items || []).reduce((groups, item) => {
    const key = String(item.severity || "unknown").toLowerCase();
    groups[key] = groups[key] || [];
    groups[key].push(item);
    return groups;
  }, {});
}

function renderStat(label, value, tone = "") {
  return `
    <div class="problem-stat ${tone ? `tone-${escapeHtml(tone)}` : ""}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value ?? 0))}</strong>
    </div>
  `;
}

function renderProblemsLifecycleNote(payload) {
  const stats = payload.stats || {};
  const summary = payload.lifecycle_summary || {};
  const visible = Number(stats.total_filtered ?? (payload.items || []).length);
  const total = Number(stats.total_findings ?? summary.total_findings ?? visible);
  const resolved = Number(stats.total_resolved || 0);
  const falsePositive = Number(stats.total_false_positive || 0);
  const verified = Number(stats.total_verified || 0);
  const scope = summary.default_scope || "current filters";
  const truth =
    summary.count_truth ||
    "Problems Center separates the filtered queue from the full finding lifecycle for the selected scope.";
  return `
    <article class="panel problems-lifecycle-note" data-testid="problems-lifecycle-note">
      <div>
        <p class="eyebrow">Lifecycle scope</p>
        <h3>${escapeHtml(`${visible} visible · ${total} total findings`)}</h3>
        <p>${escapeHtml(truth)}</p>
      </div>
      <div class="inline-metrics">
        <span class="metric-pill">${escapeHtml(scope)}</span>
        <span class="metric-pill">${escapeHtml(`${resolved} resolved`)}</span>
        <span class="metric-pill">${escapeHtml(`${verified} verified`)}</span>
        <span class="metric-pill">${escapeHtml(`${falsePositive} false positive`)}</span>
      </div>
    </article>
  `;
}

function renderOption(value, label, selected) {
  return `<option value="${escapeHtml(value)}" ${String(value) === String(selected) ? "selected" : ""}>${escapeHtml(label)}</option>`;
}

function renderFilterBar(payload) {
  const filters = { ...DEFAULT_FILTERS, ...(problemsUi().filters || {}) };
  const options = payload.filters || {};
  return `
    <article class="panel problems-filter-panel" data-testid="problems-filter-bar">
      <div class="problems-filter-grid">
        <label class="field compact">
          <span>Engagement</span>
          <select data-problem-filter="engagementId" data-testid="problem-filter-engagement">
            ${renderOption("all", "All engagements", filters.engagementId)}
            ${(options.engagements || []).map((item) => renderOption(item.id, item.name, filters.engagementId)).join("")}
          </select>
        </label>
        <label class="field compact">
          <span>Severity</span>
          <select data-problem-filter="severity" data-testid="problem-filter-severity">
            ${renderOption("critical,high", "Critical + High", filters.severity)}
            ${renderOption("all", "All severities", filters.severity)}
            ${(options.severities || []).map((severity) => renderOption(severity, severity, filters.severity)).join("")}
          </select>
        </label>
        <label class="field compact">
          <span>Status</span>
          <select data-problem-filter="status" data-testid="problem-filter-status">
            ${renderOption("open", "Open", filters.status)}
            ${renderOption("open,in_progress,reoccurred", "Unresolved", filters.status)}
            ${renderOption("resolved,verified", "Resolved + Verified", filters.status)}
            ${renderOption("all", "All statuses", filters.status)}
            ${(options.statuses || []).map((status) => renderOption(status, status.replaceAll("_", " "), filters.status)).join("")}
          </select>
        </label>
        <label class="field compact">
          <span>Assignee</span>
          <select data-problem-filter="assignee" data-testid="problem-filter-assignee">
            ${renderOption("all", "All assignees", filters.assignee)}
            ${renderOption("unassigned", "Unassigned", filters.assignee)}
            ${(options.assignees || []).map((assignee) => renderOption(assignee, assignee, filters.assignee)).join("")}
          </select>
        </label>
        <label class="field compact">
          <span>Age</span>
          <select data-problem-filter="age" data-testid="problem-filter-age">
            ${renderOption("all", "Any age", filters.age)}
            ${renderOption("overdue", "Overdue", filters.age)}
            ${renderOption("due_soon", "Due soon", filters.age)}
            ${renderOption("recent", "Recent", filters.age)}
          </select>
        </label>
        <label class="field compact">
          <span>Methodology</span>
          <select data-problem-filter="methodology" data-testid="problem-filter-methodology">
            ${renderOption("all", "All methodology", filters.methodology)}
            ${(options.methodologies || []).map((tag) => renderOption(tag, tag, filters.methodology)).join("")}
          </select>
        </label>
      </div>
    </article>
  `;
}

const SEVERITY_WEIGHTS = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 0.5,
  info: 0,
  unknown: 0,
};

const FORECAST_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
const CLOSED_STATUSES = new Set(["resolved", "verified", "accepted_risk", "false_positive"]);
const PROBLEM_STATUS_LABELS = {
  open: "Open",
  in_progress: "In Progress",
  reoccurred: "Reoccurred",
  resolved: "Resolved",
  verified: "Verified",
};

function normalizeSeverity(value) {
  const severity = String(value || "unknown").toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_WEIGHTS, severity) ? severity : "unknown";
}

function problemId(problem) {
  return String(problem.finding_id || problem.id || "");
}

function isOpenForecastItem(item) {
  const problemStatus = String(item.problem_status || item.status || "open").toLowerCase();
  const findingStatus = String(item.status || "open").toLowerCase();
  return !CLOSED_STATUSES.has(problemStatus) && !CLOSED_STATUSES.has(findingStatus);
}

function selectedRunFindingFallback() {
  return (runtime.actions.selectedRunFindings?.() || [])
    .filter(isOpenForecastItem)
    .map((finding) => ({
      ...finding,
      finding_id: finding.id,
      engagement_name: "Selected run",
      problem_status: finding.status || "open",
      days_open: 0,
    }));
}

function forecastItems(payload) {
  const problems = (payload.items || []).filter(isOpenForecastItem);
  return problems.length ? problems : selectedRunFindingFallback();
}

function forecastWeight(items, selectedIds = new Set()) {
  return items.reduce((total, item) => {
    if (selectedIds.has(problemId(item))) return total;
    return total + (SEVERITY_WEIGHTS[normalizeSeverity(item.severity)] || 0);
  }, 0);
}

function forecastScore(items, selectedIds = new Set()) {
  const score = Math.min(100, (forecastWeight(items, selectedIds) / 40) * 100);
  return Math.round(score * 10) / 10;
}

function severityCounts(items, selectedIds = new Set()) {
  return items.reduce((counts, item) => {
    if (selectedIds.has(problemId(item))) return counts;
    const severity = normalizeSeverity(item.severity);
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {});
}

function formatImpact(value) {
  const rounded = Math.round(Number(value || 0) * 10) / 10;
  return formatExposureScore(rounded);
}

function renderForecastBars(items, selectedIds = new Set(), testId = "") {
  const counts = severityCounts(items, selectedIds);
  const maxCount = Math.max(1, ...Object.values(counts).map((value) => Number(value || 0)));
  return `
    <div class="forecast-severity-bars" ${testId ? `data-testid="${escapeHtml(testId)}"` : ""}>
      ${FORECAST_SEVERITY_ORDER.map((severity) => {
        const count = Number(counts[severity] || 0);
        if (!count && !["critical", "high", "medium"].includes(severity)) return "";
        const width = Math.max(count ? 8 : 0, Math.round((count / maxCount) * 100));
        return `
          <div class="forecast-severity-row severity-${escapeHtml(severity)}">
            <span>${escapeHtml(severity)}</span>
            <div class="forecast-severity-track"><i style="width:${escapeHtml(String(width))}%"></i></div>
            <strong>${escapeHtml(String(count))}</strong>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function impactForItem(items, item) {
  const id = problemId(item);
  const withoutItem = new Set([id]);
  return Math.max(0, forecastScore(items) - forecastScore(items, withoutItem));
}

function thresholdLabel(score) {
  if (score < 30) return "Below 30 threshold";
  if (score < 50) return "Below 50 threshold";
  if (score < 75) return "Below 75 threshold";
  return "Critical posture";
}

function renderForecastNotes(currentScore, projectedScore, selectedCount, totalCount) {
  if (!selectedCount) {
    return `
      <div class="forecast-diff-note is-muted" data-testid="fix-forecast-diff-note">
        Select fixes to model the impact. This does not change finding status.
      </div>
    `;
  }
  const reduction = Math.max(0, currentScore - projectedScore);
  const thresholdCrossed = thresholdLabel(currentScore) !== thresholdLabel(projectedScore);
  return `
    <div class="forecast-diff-stack" data-testid="fix-forecast-diff-notes">
      <div class="forecast-diff-note">Risk score drops from <strong>${escapeHtml(formatExposureScore(currentScore))}</strong> to <strong>${escapeHtml(formatExposureScore(projectedScore))}</strong> (${escapeHtml(`-${formatImpact(reduction)} pts`)})</div>
      <div class="forecast-diff-note">${escapeHtml(String(selectedCount))} finding${selectedCount === 1 ? "" : "s"} projected resolved · ${escapeHtml(String(Math.max(0, totalCount - selectedCount)))} remaining</div>
      ${thresholdCrossed ? `<div class="forecast-diff-note">${escapeHtml(thresholdLabel(projectedScore))} achieved</div>` : ""}
    </div>
  `;
}

function renderForecastNowItem(item, selected, impact) {
  const id = problemId(item);
  const severity = normalizeSeverity(item.severity);
  return `
    <article class="forecast-finding ${selected ? "is-fixed" : ""}" data-testid="fix-forecast-current-item">
      <span class="finding-severity-dot severity-${escapeHtml(severity)}" aria-hidden="true"></span>
      <div>
        <strong>${escapeHtml(item.title || "Untitled finding")}</strong>
        <p>${escapeHtml(`${item.target_id || "target n/a"} · ${item.engagement_name || "engagement n/a"}`)}</p>
      </div>
      <span class="forecast-impact">${escapeHtml(`-${formatImpact(impact)} pts`)}</span>
      ${selected ? `<span class="forecast-fixed-mark" aria-label="Projected fixed">Fixed</span>` : ""}
      <input type="hidden" value="${escapeHtml(id)}" />
    </article>
  `;
}

function renderForecastFixItem(item, selected, impact) {
  const id = problemId(item);
  const severity = normalizeSeverity(item.severity);
  return `
    <label class="forecast-fix-item ${selected ? "checked" : ""}" data-testid="fix-forecast-selector-item">
      <input
        type="checkbox"
        data-forecast-select="${escapeHtml(id)}"
        ${selected ? "checked" : ""}
        aria-label="Forecast fix for ${escapeHtml(item.title || "finding")}"
      />
      <span class="forecast-check" aria-hidden="true">${selected ? "✓" : ""}</span>
      <span class="finding-severity-dot severity-${escapeHtml(severity)}" aria-hidden="true"></span>
      <span class="forecast-fix-name">${escapeHtml(item.title || "Untitled finding")}</span>
      <span class="forecast-impact">${escapeHtml(`-${formatImpact(impact)} pts`)}</span>
    </label>
  `;
}

function renderProjectedFixes(items, selectedIds) {
  const selectedItems = items.filter((item) => selectedIds.has(problemId(item)));
  if (!selectedItems.length) {
    return `<div class="forecast-diff-note is-muted">No projected fixes selected yet.</div>`;
  }
  return `
    <div class="forecast-resolved-list" data-testid="fix-forecast-projected-list">
      ${selectedItems.map((item) => `
        <div class="forecast-resolved-item">
          <span>✓</span>
          <strong>${escapeHtml(item.title || "Untitled finding")}</strong>
        </div>
      `).join("")}
    </div>
  `;
}

function renderFixForecast(payload) {
  const items = forecastItems(payload);
  if (!items.length) {
    return `
      <article class="panel fix-forecast-panel" data-testid="fix-forecast">
        <div class="panel-head compact-head">
          <div>
            <p class="eyebrow">Fix Forecast</p>
            <h3>Remediation Impact</h3>
          </div>
        </div>
        ${emptyState("No open findings are available for a remediation forecast.")}
      </article>
    `;
  }
  const availableIds = new Set(items.map(problemId));
  const selectedIds = new Set([...forecastSelectedSet()].filter((id) => availableIds.has(String(id))));
  const currentScore = forecastScore(items);
  const projectedScore = forecastScore(items, selectedIds);
  const selectedCount = selectedIds.size;
  const currentWidth = Math.max(0, Math.min(100, currentScore));
  const projectedWidth = Math.max(0, Math.min(100, projectedScore));
  return `
    <article class="panel fix-forecast-panel" data-testid="fix-forecast">
      <div class="panel-head compact-head">
        <div>
          <p class="eyebrow">Fix Forecast</p>
          <h3>Remediation Impact</h3>
        </div>
        <span class="badge">Session only</span>
      </div>
      <div class="fix-forecast-split">
        <section class="fix-forecast-side is-now" data-testid="fix-forecast-now">
          <span class="forecast-state-badge bad">Current State</span>
          <div class="forecast-score-display">
            <strong class="forecast-score bad" data-testid="fix-forecast-current-score">${escapeHtml(formatExposureScore(currentScore))}</strong>
            <span>Risk Score</span>
            <div class="forecast-score-bar"><i class="bad" style="width:${escapeHtml(String(currentWidth))}%"></i></div>
          </div>
          ${renderForecastBars(items, new Set(), "fix-forecast-current-bars")}
          <div class="forecast-list-head">Open findings</div>
          <div class="forecast-current-list">
            ${items.map((item) => renderForecastNowItem(item, selectedIds.has(problemId(item)), impactForItem(items, item))).join("")}
          </div>
        </section>
        <section class="fix-forecast-side is-after" data-testid="fix-forecast-after">
          <span class="forecast-state-badge good">After Fixes Selected</span>
          <div class="forecast-score-display">
            <strong class="forecast-score good" data-testid="fix-forecast-projected-score">${escapeHtml(formatExposureScore(projectedScore))}</strong>
            <span>Projected Risk Score</span>
            <div class="forecast-score-bar"><i class="good" style="width:${escapeHtml(String(projectedWidth))}%"></i></div>
          </div>
          ${renderForecastNotes(currentScore, projectedScore, selectedCount, items.length)}
          ${renderForecastBars(items, selectedIds, "fix-forecast-projected-bars")}
          <div class="forecast-list-head">Select fixes to apply</div>
          <div class="forecast-fix-list">
            ${items.map((item) => renderForecastFixItem(item, selectedIds.has(problemId(item)), impactForItem(items, item))).join("")}
          </div>
          <div class="forecast-list-head">Projected resolved</div>
          ${renderProjectedFixes(items, selectedIds)}
          <button
            class="action primary compact-action"
            type="button"
            data-forecast-create-retest="true"
            data-testid="fix-forecast-create-retest"
            ${selectedCount ? "" : "disabled"}
          >
            Create Retest Plan →
          </button>
        </section>
      </div>
    </article>
  `;
}

function renderBulkBar() {
  const selectedCount = selectedSet().size;
  if (!selectedCount) return "";
  const jiraConfigured = Boolean(state.jiraIntegrationConfiguration?.id);
  return `
    <div class="bulk-delete-bar problems-bulk-bar" data-testid="problems-bulk-bar">
      <div>
        <strong>${escapeHtml(`${selectedCount} selected`)}</strong>
        <p class="micro-copy">Bulk actions update existing finding status and remediation owner records.</p>
      </div>
      <label class="field compact problem-bulk-assignee">
        <span>Assignee</span>
        <input type="text" data-problem-bulk-assignee-input placeholder="team or owner" />
      </label>
      <div class="panel-actions">
        <button class="action ghost compact-action" type="button" data-problem-bulk-action="assign" data-testid="problems-bulk-assign">Assign</button>
        <button class="action ghost compact-action" type="button" data-problem-bulk-action="resolve" data-testid="problems-bulk-resolve">Mark resolved</button>
        <button class="action ghost compact-action" type="button" data-problem-bulk-action="schedule_retest" data-testid="problems-bulk-retest">Schedule retest</button>
        <button class="action ghost compact-action" type="button" data-problem-bulk-action="push_jira" data-testid="problems-bulk-jira" ${jiraConfigured && !state.jiraBulkPushing ? "" : "disabled"}>
          ${state.jiraBulkPushing ? "Pushing..." : "Push to Jira"}
        </button>
        <button class="action ghost compact-action danger-action" type="button" disabled title="Finding delete is blocked until a finding soft-delete marker exists.">Delete</button>
      </div>
    </div>
  `;
}

function totalFindingCount(payload) {
  const stats = payload?.stats || {};
  const summary = payload?.lifecycle_summary || {};
  return Number(stats.total_findings ?? summary.total_findings ?? (payload?.items || []).length);
}

function problemStatusCounts(payload) {
  const stats = payload?.stats || {};
  const byProblemStatus = stats.by_problem_status || {};
  return {
    open: Number(byProblemStatus.open ?? stats.total_open ?? 0),
    in_progress: Number(byProblemStatus.in_progress ?? stats.total_in_progress ?? 0),
    reoccurred: Number(byProblemStatus.reoccurred ?? 0),
    resolved: Number(byProblemStatus.resolved ?? stats.total_resolved ?? 0),
    verified: Number(byProblemStatus.verified ?? stats.total_verified ?? 0),
  };
}

function openProblemCount(payload) {
  const counts = problemStatusCounts(payload);
  return counts.open + counts.in_progress + counts.reoccurred;
}

function renderProblemCountSummary(payload) {
  const counts = problemStatusCounts(payload);
  const rows = Object.entries(PROBLEM_STATUS_LABELS)
    .map(([status, label]) => ({ status, label, count: counts[status] || 0 }))
    .filter((item) => item.count > 0);
  if (!rows.length) return "";
  return `
    <section class="problems-status-summary" data-testid="problems-status-summary" aria-label="Problem status summary">
      ${rows
        .map(
          (item) =>
            `<span class="metric-pill" data-problem-status-count="${escapeHtml(item.status)}">${escapeHtml(`${item.count} ${item.label}`)}</span>`
        )
        .join("")}
    </section>
  `;
}

function renderProblemsEmptyState() {
  return `
    <div class="problems-shell">
      <article class="panel dashboard-empty" data-testid="problems-empty-state">
        <p class="eyebrow">Problems</p>
        <h3>No open problems</h3>
        ${emptyState("No open problems — findings from completed runs appear here.", {
          label: "Go to Mission Control",
          screen: "mission-control",
          className: "primary",
          testId: "problems-empty-mission-control",
        })}
      </article>
    </div>
  `;
}

function renderProblemsResolvedState(payload) {
  return `
    <div class="problems-shell">
      ${renderProblemCountSummary(payload)}
      <article class="panel dashboard-empty" data-testid="problems-resolved-state">
        <p class="eyebrow">Problems</p>
        <h3>All problems resolved</h3>
        ${emptyState("All problems resolved. Start a new run to re-validate.", {
          label: "Go to Mission Control",
          screen: "mission-control",
          className: "primary",
          testId: "problems-resolved-mission-control",
        })}
      </article>
      ${renderRecentlyResolved(payload)}
    </div>
  `;
}

function renderLifecycle(problem) {
  return `
    <div class="problem-lifecycle" aria-label="Problem lifecycle">
      ${(problem.lifecycle || [])
        .map(
          (step) => `
            <span class="problem-lifecycle-pill state-${escapeHtml(step.state || "pending")}">
              ${escapeHtml(step.label || step.key)}
            </span>
          `
        )
        .join("")}
    </div>
  `;
}

function renderProblemRow(problem) {
  const selected = selectedSet().has(String(problem.finding_id));
  const expanded = String(problemsUi().expandedId || "") === String(problem.finding_id);
  const assignee = problem.assignee || "Unassigned";
  return `
    <article class="problem-row ${expanded ? "is-expanded" : ""}" data-testid="problem-row">
      <div class="problem-row-main">
        <label class="delete-checkline problem-checkline" data-problem-row-control>
          <input
            type="checkbox"
            data-problem-select="${escapeHtml(problem.finding_id)}"
            ${selected ? "checked" : ""}
            aria-label="Select ${escapeHtml(problem.title)}"
          />
        </label>
        <span class="finding-severity-dot severity-${escapeHtml(problem.severity || "unknown")}" aria-hidden="true"></span>
        <button class="problem-row-button" type="button" data-problem-expand="${escapeHtml(problem.finding_id)}">
          <span class="problem-title">${escapeHtml(problem.title)}</span>
          <span class="problem-meta">
            ${escapeHtml(problem.engagement_name)} · ${escapeHtml(problem.target_id)} · ${escapeHtml(`${problem.days_open}d open`)}
          </span>
        </button>
        <div class="problem-row-state">
          ${severityPill(problem.severity)}
          ${statusPill(problem.problem_status)}
          <span class="badge">${escapeHtml(assignee)}</span>
        </div>
        <div class="problem-row-actions" data-problem-row-control>
          <button class="action ghost tiny" type="button" data-problem-row-action="assign" data-problem-id="${escapeHtml(problem.finding_id)}">Assign</button>
          <button class="action ghost tiny" type="button" data-problem-row-action="schedule_retest" data-problem-id="${escapeHtml(problem.finding_id)}">Retest</button>
          <button class="action ghost tiny" type="button" data-problem-row-action="resolve" data-problem-id="${escapeHtml(problem.finding_id)}">Resolve</button>
          <button class="action ghost tiny danger-action" type="button" disabled title="Finding delete requires a future finding soft-delete marker.">Delete</button>
        </div>
      </div>
      ${
        expanded
          ? `
            <div class="problem-row-detail" data-testid="problem-expanded-row">
              ${renderLifecycle(problem)}
              <div class="compact-definition-grid">
                <div><span>Status</span><strong>${escapeHtml(problem.problem_status.replaceAll("_", " "))}</strong></div>
                <div><span>Verification</span><strong>${escapeHtml(problem.verification_status)}</strong></div>
                <div><span>Retest</span><strong>${escapeHtml(problem.latest_retest_status || "Not scheduled")}</strong></div>
                <div><span>Methodology</span><strong>${escapeHtml((problem.methodology_tags || []).join(", ") || "Not tagged")}</strong></div>
              </div>
            </div>
          `
          : ""
      }
    </article>
  `;
}

function renderProblemGroups(items) {
  if (!items.length) {
    return emptyState("No problems match the current filters.", { label: "Show all problems", screen: "" });
  }
  const groups = groupBySeverity(items);
  const order = ["critical", "high", "medium", "low", "info", "unknown"].filter((severity) => groups[severity]?.length);
  return order
    .map(
      (severity) => `
        <section class="problem-group" data-testid="problem-group">
          <div class="finding-group-head">
            <div class="finding-group-title-row">
              <span class="finding-severity-dot severity-${escapeHtml(severity)}" aria-hidden="true"></span>
              <h4>${escapeHtml(severity)}</h4>
              <span class="finding-group-count">${escapeHtml(String(groups[severity].length))}</span>
            </div>
          </div>
          <div class="problem-row-list">${groups[severity].map(renderProblemRow).join("")}</div>
        </section>
      `
    )
    .join("");
}

function renderRecentlyResolved(payload) {
  const resolved = payload.recently_resolved || [];
  return renderDisclosure({
    title: "Recently Resolved (30 days)",
    summary: `${resolved.length} fixed item${resolved.length === 1 ? "" : "s"} with verification context`,
    open: problemsUi().recentlyResolvedOpen,
    testId: "problems-recently-resolved",
    className: "problems-resolved-disclosure",
    body: resolved.length
      ? `<div class="problem-resolved-list">${resolved.map(renderProblemRow).join("")}</div>`
      : emptyState("Resolved and verified items from the last 30 days will appear here."),
  });
}

async function runBulkAction(action, ids) {
  const findingIds = ids || [...selectedSet()];
  if (!findingIds.length) {
    runtime.actions.pushStatus?.("Select at least one problem first.", "warning");
    return;
  }
  if (action === "push_jira") {
    if (!state.jiraIntegrationConfiguration?.id) {
      runtime.actions.pushStatus?.("Configure Jira in Settings before bulk pushing findings.", "warning");
      return;
    }
    patchState({ jiraBulkPushing: true, jiraIntegrationError: null }, "problems.jira.bulk.start");
    runtime.actions.renderProblemsCenter?.();
    const results = [];
    for (const findingId of findingIds) {
      try {
        const link = await api(`/api/v1/findings/${findingId}/handoff-jira`, { method: "POST" });
        state.jiraFindingLinks = {
          ...(state.jiraFindingLinks || {}),
          [String(findingId)]: link,
        };
        results.push({ findingId, ok: true, link });
      } catch (error) {
        results.push({ findingId, ok: false, error: String(error?.message || error) });
      }
    }
    const okCount = results.filter((result) => result.ok).length;
    const failedCount = results.length - okCount;
    patchState({ jiraBulkPushing: false }, "problems.jira.bulk.complete");
    runtime.actions.pushStatus?.(
      `Jira handoff prepared for ${okCount}/${results.length} selected finding${results.length === 1 ? "" : "s"}${failedCount ? `; ${failedCount} failed` : ""}.`,
      failedCount ? "warning" : "success"
    );
    setProblemsUi({ selectedIds: [] }, "problems.jira.bulk.clear");
    await runtime.actions.loadProblems?.();
    runtime.actions.renderProblemsCenter?.();
    return;
  }
  const body = { finding_ids: findingIds, action };
  if (action === "assign") {
    const input = document.querySelector("[data-problem-bulk-assignee-input]");
    const assignee = input?.value?.trim() || state.actor || "operator-ui";
    body.assignee = assignee;
  }
  if (action === "resolve") {
    body.action = "resolve";
  }
  if (action === "schedule_retest") {
    body.retest_notes = "Scheduled from Problems Center.";
  }
  const result = await api("/api/v1/problems/bulk", { method: "PATCH", body });
  runtime.actions.pushStatus?.(result.message || "Problems updated.", "success");
  setProblemsUi({ selectedIds: [] }, "problems.bulk.complete");
  await runtime.actions.loadProblems?.();
  runtime.actions.renderProblemsCenter?.();
}

async function runRowAction(action, findingId) {
  if (action === "assign") {
    const assignee = window.prompt("Assign problem to", state.actor || "operator-ui");
    if (assignee === null) return;
    await api("/api/v1/problems/bulk", {
      method: "PATCH",
      body: { finding_ids: [findingId], action: "assign", assignee },
    });
    runtime.actions.pushStatus?.("Problem assigned.", "success");
  } else {
    await runBulkAction(action, [findingId]);
    return;
  }
  await runtime.actions.loadProblems?.();
  runtime.actions.renderProblemsCenter?.();
}

async function createForecastRetestPlan() {
  const ids = [...forecastSelectedSet()];
  if (!ids.length) {
    runtime.actions.pushStatus?.("Select at least one forecast fix first.", "warning");
    return;
  }
  await runBulkAction("schedule_retest", ids);
  setProblemsUi({ forecastSelectedIds: [] }, "problems.forecast.retestPlan");
  runtime.actions.renderProblemsCenter?.();
}

export function createProblemsModule() {
  async function loadProblemJiraConfiguration() {
    if (!state.selectedEngagementId) return;
    if (state.jiraIntegrationLoadedEngagementId === state.selectedEngagementId) return;
    patchState({ jiraIntegrationLoading: true, jiraIntegrationError: null }, "problems.jira.load.start");
    try {
      const configuration = await apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/integrations/jira`);
      patchState(
        {
          jiraIntegrationConfiguration: configuration,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
        },
        "problems.jira.load.complete"
      );
    } catch (error) {
      patchState(
        {
          jiraIntegrationConfiguration: null,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
          jiraIntegrationError: String(error?.message || error),
        },
        "problems.jira.load.error"
      );
    }
  }

  async function loadProblems() {
    state.problemsLoading = true;
    state.problemsError = null;
    try {
      const [problems] = await Promise.all([
        api(`/api/v1/problems?${problemQuery()}`),
        loadProblemJiraConfiguration(),
      ]);
      state.problems = problems;
      const availableIds = new Set((state.problems.items || []).map((item) => String(item.finding_id)));
      state.problemsUi = {
        ...problemsUi(),
        selectedIds: (problemsUi().selectedIds || []).filter((id) => availableIds.has(String(id))),
        forecastSelectedIds: (problemsUi().forecastSelectedIds || []).filter((id) => availableIds.has(String(id))),
      };
    } catch (error) {
      state.problemsError = String(error?.message || "Problems Center unavailable.");
      throw error;
    } finally {
      state.problemsLoading = false;
    }
  }

  function renderProblemsCenter() {
    if (!dom.problemsContent) return;
    if (state.problemsLoading && !state.problems) {
      dom.problemsContent.innerHTML = `<article class="panel dashboard-empty">Loading problems...</article>`;
      return;
    }
    if (state.problemsError && !state.problems) {
      dom.problemsContent.innerHTML = `
        <article class="panel dashboard-empty" data-testid="problems-error">
          <p class="eyebrow">Problems</p>
          <h3>Problems Center unavailable</h3>
          <p>${escapeHtml(state.problemsError)}</p>
        </article>
      `;
      return;
    }
    const payload = state.problems;
    if (!payload) {
      dom.problemsContent.innerHTML = `
        <article class="panel dashboard-empty" data-testid="problems-empty-state">
          <p class="eyebrow">Problems</p>
          <h3>No problem data loaded</h3>
          <p>Open Problems Center again or refresh the operator console.</p>
        </article>
      `;
      return;
    }
    if (totalFindingCount(payload) <= 0) {
      dom.problemsContent.innerHTML = renderProblemsEmptyState();
      return;
    }
    if (openProblemCount(payload) <= 0) {
      dom.problemsContent.innerHTML = renderProblemsResolvedState(payload);
      dom.problemsContent.querySelector('[data-testid="problems-recently-resolved"]')?.addEventListener("toggle", (event) => {
        setProblemsUi({ recentlyResolvedOpen: event.currentTarget.open }, "problems.resolved.toggle");
      });
      return;
    }
    const stats = payload.stats || {};
    dom.problemsContent.innerHTML = `
      <div class="problems-shell">
        ${renderProblemCountSummary(payload)}
        <section class="problems-stats" data-testid="problems-stats">
          ${renderStat("Open critical", stats.open_critical, "critical")}
          ${renderStat("Open high", stats.open_high, "high")}
          ${renderStat("Visible", stats.total_filtered ?? (payload.items || []).length, "neutral")}
          ${renderStat("All findings", stats.total_findings ?? (payload.items || []).length, "neutral")}
          ${renderStat("Avg resolve 30d", `${stats.avg_days_to_resolve_30d || 0}d`, "neutral")}
          ${renderStat("Resolved this week", stats.resolved_this_week, "good")}
        </section>
        ${renderProblemsLifecycleNote(payload)}
        ${renderFilterBar(payload)}
        ${renderFixForecast(payload)}
        ${renderBulkBar()}
        <article class="panel problems-list-panel">
          <div class="panel-head compact-head">
            <div>
              <p class="eyebrow">Backlog</p>
              <h3>Open Problem Queue</h3>
            </div>
            <span class="badge">${escapeHtml(`${(payload.items || []).length} visible`)}</span>
          </div>
          <div class="problems-list" data-testid="problems-list">
            ${renderProblemGroups(payload.items || [])}
          </div>
        </article>
        ${renderRecentlyResolved(payload)}
      </div>
    `;

    dom.problemsContent.querySelectorAll("[data-problem-filter]").forEach((control) => {
      control.addEventListener("change", async () => {
        setProblemFilters({ [control.dataset.problemFilter]: control.value });
        await loadProblems();
        renderProblemsCenter();
      });
    });
    dom.problemsContent.querySelectorAll("[data-problem-select]").forEach((checkbox) => {
      checkbox.addEventListener("change", () => {
        updateSelected(checkbox.dataset.problemSelect, checkbox.checked);
        renderProblemsCenter();
      });
    });
    dom.problemsContent.querySelectorAll("[data-forecast-select]").forEach((checkbox) => {
      checkbox.addEventListener("change", () => {
        updateForecastSelected(checkbox.dataset.forecastSelect, checkbox.checked);
        renderProblemsCenter();
      });
    });
    dom.problemsContent.querySelector("[data-forecast-create-retest]")?.addEventListener("click", () => {
      createForecastRetestPlan().catch(runtime.actions.handleError);
    });
    dom.problemsContent.querySelectorAll("[data-problem-expand]").forEach((button) => {
      button.addEventListener("click", () => {
        const current = String(problemsUi().expandedId || "");
        const next = current === String(button.dataset.problemExpand || "") ? null : button.dataset.problemExpand;
        setProblemsUi({ expandedId: next }, "problems.expand");
        renderProblemsCenter();
      });
    });
    dom.problemsContent.querySelectorAll("[data-problem-bulk-action]").forEach((button) => {
      button.addEventListener("click", () => runBulkAction(button.dataset.problemBulkAction).catch(runtime.actions.handleError));
    });
    dom.problemsContent.querySelectorAll("[data-problem-row-action]").forEach((button) => {
      button.addEventListener("click", () =>
        runRowAction(button.dataset.problemRowAction, button.dataset.problemId).catch(runtime.actions.handleError)
      );
    });
    dom.problemsContent.querySelector('[data-testid="problems-recently-resolved"]')?.addEventListener("toggle", (event) => {
      setProblemsUi({ recentlyResolvedOpen: event.currentTarget.open }, "problems.resolved.toggle");
    });
  }

  return {
    loadProblems,
    renderProblemsCenter,
  };
}
