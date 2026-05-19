import { api } from "./api.js";
import { dom, patchState, state } from "./runtime.js";
import {
  escapeHtml,
  exposureScoreTone,
  exposureTrendLabel,
  formatDateTime,
  formatExposureScore,
  renderExposureSparkline,
} from "./shared.js";

function severityBadge(severity, count) {
  return `
    <span class="dashboard-severity-pill severity-${escapeHtml(severity)}">
      <strong>${escapeHtml(String(count || 0))}</strong>
      <span>${escapeHtml(severity)}</span>
    </span>
  `;
}

function statusTone(status) {
  const normalized = String(status || "").toLowerCase();
  if (["running", "queued", "pending_approval"].includes(normalized)) return "info";
  if (["completed"].includes(normalized)) return "good";
  if (["failed", "cancelled", "rejected"].includes(normalized)) return "bad";
  return "neutral";
}

function dashboardEndpoint() {
  return state.selectedEngagementId
    ? `/api/v1/dashboard?engagement_id=${encodeURIComponent(state.selectedEngagementId)}`
    : "/api/v1/dashboard";
}

function selectedScopeLabel() {
  const selected = state.engagements.find((engagement) => String(engagement.id) === String(state.selectedEngagementId));
  return selected?.name || "Portfolio";
}

function pluralizeTask(count) {
  return Number(count) === 1 ? "task" : "tasks";
}

function renderAction(action) {
  return `
    <button
      class="dashboard-action"
      type="button"
      data-nav-screen="${escapeHtml(action.target_screen || "wizard")}"
      ${action.enabled ? "" : "disabled"}
    >
      <strong>${escapeHtml(action.label || "Action")}</strong>
      <span>${escapeHtml(action.description || "")}</span>
    </button>
  `;
}

function renderActiveRunTile(dashboard) {
  const run = dashboard.active_run;
  if (!run) {
    return `
      <article class="panel dashboard-tile dashboard-active-run" data-testid="dashboard-active-run-tile">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Active Run</p>
            <h3>No run active</h3>
          </div>
        </div>
        <p class="dashboard-muted">Create or dispatch a mission to populate live task progress here.</p>
      </article>
    `;
  }
  const total = Math.max(Number(run.tasks_total || 0), 1);
  const completed = Math.min(100, Math.round((Number(run.tasks_completed || 0) / total) * 100));
  const severities = ["critical", "high", "medium", "low"]
    .map((severity) => severityBadge(severity, run.findings_by_severity?.[severity] || 0))
    .join("");
  return `
    <article class="panel dashboard-tile dashboard-active-run span-2" data-testid="dashboard-active-run-tile">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Active Run</p>
          <h3>${escapeHtml(run.engagement_name || "Engagement")}</h3>
        </div>
        <span class="dashboard-status tone-${statusTone(run.status)}">${escapeHtml(run.status || "unknown")}</span>
      </div>
      <div class="dashboard-active-run-grid">
        <div>
          <p class="dashboard-label">Profile</p>
          <strong>${escapeHtml(run.profile_name || "Unknown profile")}</strong>
          <p class="dashboard-muted">${escapeHtml(run.phase_label || "Assessment")} &middot; ${escapeHtml(run.phase_progress_label || "Progress pending")}</p>
        </div>
        <div class="dashboard-task-meter">
          <div>
            <span>Tasks</span>
            <strong>${escapeHtml(String(run.tasks_completed || 0))}/${escapeHtml(String(run.tasks_total || 0))}</strong>
          </div>
          <div class="dashboard-meter-track" aria-hidden="true">
            <span style="width: ${completed}%"></span>
          </div>
          <small>${escapeHtml(String(run.tasks_running || 0))} queued/running &middot; ${escapeHtml(String(run.finding_count || 0))} findings</small>
        </div>
      </div>
      <div class="dashboard-severity-row">${severities}</div>
    </article>
  `;
}

function renderRiskTile(dashboard) {
  const risk = dashboard.risk_score || {};
  const tone = exposureScoreTone(risk.score);
  return `
    <article class="panel dashboard-tile dashboard-risk" data-testid="dashboard-risk-score-tile">
      <div class="panel-head">
        <div>
          <p class="eyebrow">${escapeHtml(state.selectedEngagementId ? "Selected Risk" : "Portfolio Risk")}</p>
          <h3>Exposure Score</h3>
        </div>
        <span class="dashboard-status tone-${escapeHtml(tone)}">${escapeHtml(exposureTrendLabel(risk.trend))}</span>
      </div>
      <div class="dashboard-risk-layout">
        <div class="exposure-gauge tone-${escapeHtml(tone)}" style="--exposure-score: ${Number(risk.score || 0)}">
          <div class="exposure-gauge-inner">
            <strong>${escapeHtml(formatExposureScore(risk.score))}</strong>
            <span>/100</span>
          </div>
        </div>
        <div>
          ${renderExposureSparkline(risk.history || [], { className: "dashboard-sparkline", testId: "dashboard-risk-sparkline" })}
          <p class="dashboard-muted">${escapeHtml(risk.advisory_note || "Advisory score based on stored findings.")}</p>
        </div>
      </div>
    </article>
  `;
}

function renderOpenProblemsTile(dashboard) {
  const open = dashboard.open_problems || {};
  const overdueCount = Number(open.overdue_critical_count || 0) + Number(open.overdue_high_count || 0);
  return `
    <article class="panel dashboard-tile" data-testid="dashboard-open-problems-tile">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Problems</p>
          <h3>Open Problems</h3>
        </div>
        <div class="dashboard-tile-stack">
          <strong class="dashboard-large-number">${escapeHtml(String(open.total || 0))}</strong>
          ${
            overdueCount > 0
              ? `<span class="dashboard-status tone-bad" data-testid="dashboard-overdue-badge">${escapeHtml(String(overdueCount))} overdue</span>`
              : `<span class="dashboard-status tone-ready" data-testid="dashboard-overdue-badge">0 overdue</span>`
          }
        </div>
      </div>
      <div class="dashboard-severity-row">
        ${severityBadge("critical", open.critical || 0)}
        ${severityBadge("high", open.high || 0)}
        ${severityBadge("medium", open.medium || 0)}
      </div>
    </article>
  `;
}

function renderUpcomingScansTile(dashboard) {
  const scans = dashboard.upcoming_scans || [];
  return `
    <article class="panel dashboard-tile" data-testid="dashboard-upcoming-scans-tile">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Schedule</p>
          <h3>Upcoming Scans</h3>
        </div>
      </div>
      <div class="dashboard-list">
        ${
          scans.length
            ? scans
                .map(
                  (scan) => `
                    <div class="dashboard-list-row">
                      <strong>${escapeHtml(scan.profile_name || "Scan")}</strong>
                      <span>${escapeHtml(scan.engagement_name || "Engagement")} &middot; ${escapeHtml(scan.eta_label || formatDateTime(scan.next_run_at))}</span>
                    </div>
                  `
                )
                .join("")
            : `<p class="dashboard-muted">No enabled schedules yet.</p>`
        }
      </div>
    </article>
  `;
}

function renderRecentActivity(dashboard) {
  const activity = dashboard.activity_feed || dashboard.recent_activity || [];
  return `
    <article class="panel dashboard-tile dashboard-activity span-2" data-testid="dashboard-recent-activity">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Recent</p>
          <h3>Activity</h3>
        </div>
      </div>
      <div class="dashboard-activity-list">
        ${
          activity.length
            ? activity
                .map(
                  (item) => `
                    <div class="dashboard-activity-row">
                      <span class="dashboard-activity-dot severity-${escapeHtml(item.severity || "info")}" title="${escapeHtml(item.icon || "activity")}"></span>
                      <div>
                        <strong>${escapeHtml(item.label || "Activity")}</strong>
                        <span>${escapeHtml(item.detail || item.engagement_name || "")}</span>
                      </div>
                      <time>${escapeHtml(formatDateTime(item.timestamp || item.happened_at))}</time>
                    </div>
                  `
                )
                .join("")
            : `<p class="dashboard-muted">No audited activity yet.</p>`
        }
      </div>
    </article>
  `;
}

function renderQuickActions(dashboard) {
  return `
    <article class="panel dashboard-tile" data-testid="dashboard-quick-actions">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Command</p>
          <h3>Quick Actions</h3>
        </div>
      </div>
      <div class="dashboard-actions">${(dashboard.quick_actions || []).map(renderAction).join("")}</div>
    </article>
  `;
}

function renderSetupChecklist(dashboard) {
  const items = dashboard.setup_checklist || [];
  if (!items.length || dashboard.setup_checklist_dismissed) return "";
  const completed = items.filter((item) => item.done).length;
  return `
    <article class="panel dashboard-tile" data-testid="dashboard-setup-checklist">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Setup</p>
          <h3>Checklist</h3>
        </div>
        <div class="onboarding-checklist-head-actions">
          <span class="badge" data-testid="dashboard-setup-checklist-count">${escapeHtml(`${completed}/${items.length}`)}</span>
          <button class="action ghost compact-action" type="button" data-dashboard-dismiss-checklist data-testid="dashboard-dismiss-checklist">
            Dismiss
          </button>
        </div>
      </div>
      <div class="dashboard-checklist">
        ${items
          .map(
            (item) => `
              <div class="dashboard-check-row ${item.done ? "is-done" : ""}">
                <span>${item.done ? "&#10003;" : "&#9679;"}</span>
                <div>
                  <strong>${escapeHtml(item.label || "Checklist item")}</strong>
                  <small>${escapeHtml(item.detail || "")}</small>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </article>
  `;
}

function renderFirstRunOnboarding(dashboard) {
  const onboarding = dashboard.first_run_onboarding || {};
  if (!onboarding.show) return "";
  const cards = Array.isArray(onboarding.cards) ? onboarding.cards : [];
  return `
    <article class="panel dashboard-first-run" data-testid="dashboard-first-run-onboarding">
      <div class="panel-head">
        <div>
          <p class="eyebrow">First Run</p>
          <h3>${escapeHtml(onboarding.title || "Start AegisPT")}</h3>
        </div>
      </div>
      <p class="dashboard-muted">${escapeHtml(onboarding.detail || "Create your first scoped mission to unlock live operations.")}</p>
      <div class="dashboard-first-run-grid">
        ${cards
          .map(
            (card) => `
              <button class="dashboard-first-run-card ${card.done ? "is-done" : ""}" type="button" data-nav-screen="${escapeHtml(card.target_screen || "wizard")}">
                <span class="onboarding-checklist-mark" aria-hidden="true">${card.done ? "✓" : "○"}</span>
                <strong>${escapeHtml(card.label || "Setup step")}</strong>
                <small>${escapeHtml(card.detail || "")}</small>
              </button>
            `
          )
          .join("")}
      </div>
    </article>
  `;
}

function renderFirstRunEmptyState() {
  return `
    <article class="panel dashboard-empty dashboard-first-run-empty" data-testid="dashboard-first-run-empty-state">
      <div class="panel-head">
        <div>
          <p class="eyebrow">First Assessment</p>
          <h3>Welcome to AegisPT</h3>
        </div>
      </div>
      <p class="dashboard-muted">Create a scoped assessment to collect evidence, track findings, and produce reports.</p>
      <button
        class="action primary dashboard-first-run-cta"
        type="button"
        data-nav-screen="wizard"
        data-testid="dashboard-start-first-assessment"
      >
        Start Your First Assessment
      </button>
      <div class="dashboard-zero-stats" aria-label="Empty dashboard summary">
        <div class="dashboard-zero-stat" data-testid="dashboard-zero-active-runs">
          <span>Active Runs</span>
          <strong>0</strong>
        </div>
        <div class="dashboard-zero-stat" data-testid="dashboard-zero-open-findings">
          <span>Open Findings</span>
          <strong>0</strong>
        </div>
        <div class="dashboard-zero-stat" data-testid="dashboard-zero-engagements">
          <span>Engagements</span>
          <strong>0</strong>
        </div>
      </div>
    </article>
  `;
}

function renderEngagementSummary(dashboard) {
  const engagements = dashboard.engagements || [];
  return `
    <article class="panel dashboard-tile dashboard-engagement-summary span-full" data-testid="dashboard-engagement-summary">
      <div class="panel-head">
        <div>
          <p class="eyebrow">${escapeHtml(state.selectedEngagementId ? "Engagement" : "Portfolio")}</p>
          <h3>Engagement Summary</h3>
        </div>
      </div>
      <div class="dashboard-table">
        ${
          engagements.length
            ? engagements
                .map(
                  (engagement) => `
                    <button class="dashboard-table-row" type="button" data-dashboard-engagement-id="${escapeHtml(engagement.id)}">
                      <span>
                        <strong>${escapeHtml(engagement.name || "Untitled engagement")}</strong>
                        <small>${escapeHtml(engagement.client || "No client")} &middot; ${escapeHtml(String(engagement.run_count || 0))} runs</small>
                      </span>
                      <span>${escapeHtml(engagement.last_run_status || "No runs")}</span>
                      <span>${escapeHtml(formatExposureScore(engagement.risk_score))}</span>
                      <span>${escapeHtml(String(engagement.open_critical_count || 0))}C / ${escapeHtml(String(engagement.open_high_count || 0))}H</span>
                    </button>
                  `
                )
                .join("")
            : `<p class="dashboard-muted">No engagement dossiers exist yet.</p>`
        }
      </div>
    </article>
  `;
}

function renderCommandCenterStrip(dashboard) {
  const activeRun = dashboard.active_run || {};
  const open = dashboard.open_problems || {};
  const risk = dashboard.risk_score || {};
  const activeTaskCount = Number(activeRun.tasks_running || 0);
  const reportCount = Array.isArray(state.reportCatalog) ? state.reportCatalog.length : 0;
  const scopeLabel = selectedScopeLabel();
  const cards = [
    {
      label: state.selectedEngagementId ? "Selected Engagement" : "Portfolio",
      value: dashboard.active_run ? activeRun.status || "running" : state.selectedEngagementId ? "selected" : "none",
      detail: dashboard.active_run ? activeRun.engagement_name || scopeLabel : scopeLabel,
      screen: dashboard.active_run ? "mission-control" : "wizard",
      tone: dashboard.active_run ? "info" : "neutral",
    },
    {
      label: "Active Tasks",
      value: dashboard.active_run ? String(activeTaskCount) : "0",
      detail: dashboard.active_run
        ? `${activeTaskCount} queued/running ${pluralizeTask(activeTaskCount)} from the selected run.`
        : "No queued or running tasks.",
      screen: "agents",
      tone: activeTaskCount ? "info" : "neutral",
    },
    {
      label: state.selectedEngagementId ? "Run Risk" : "Portfolio Risk",
      value: formatExposureScore(risk.score),
      detail: state.selectedEngagementId ? "Selected engagement finding posture." : "Portfolio finding posture.",
      screen: "problems-center",
      tone: exposureScoreTone(risk.score),
    },
    {
      label: "Open Problems",
      value: String(open.total || 0),
      detail: `${Number(open.critical || 0)} critical · ${Number(open.high || 0)} high`,
      screen: "problems-center",
      tone: Number(open.critical || 0) ? "bad" : Number(open.high || 0) ? "warning" : "good",
    },
    {
      label: "Reports",
      value: String(reportCount),
      detail: reportCount ? "Report catalog for the selected run." : "Reports appear after run evidence.",
      screen: "report-center",
      tone: reportCount ? "good" : "neutral",
    },
  ];
  return `
    <section class="dashboard-command-strip" data-testid="dashboard-command-strip">
      ${cards.map((card) => `
        <button class="dashboard-command-card tone-${escapeHtml(card.tone)}" type="button" data-nav-screen="${escapeHtml(card.screen)}">
          <span>${escapeHtml(card.label)}</span>
          <strong>${escapeHtml(card.value)}</strong>
          <small>${escapeHtml(card.detail)}</small>
        </button>
      `).join("")}
    </section>
  `;
}

function renderEmptyDashboard(dashboard) {
  return `
    ${renderFirstRunEmptyState(dashboard)}
  `;
}

export function createDashboardModule() {
  async function loadDashboard() {
    state.dashboardLoading = true;
    state.dashboardError = null;
    try {
      state.dashboard = await api(dashboardEndpoint());
    } catch (error) {
      state.dashboardError = String(error?.message || "Dashboard unavailable.");
      throw error;
    } finally {
      state.dashboardLoading = false;
    }
  }

  async function dismissSetupChecklist() {
    patchState({ dashboardChecklistDismissing: true }, "dashboard.setupChecklist.dismiss.start");
    try {
      const operatorSettings = await api("/api/v1/settings", {
        method: "PATCH",
        body: { settings: { "instance.setup_checklist_dismissed": true } },
      });
      const dashboard = await api(dashboardEndpoint());
      patchState(
        { operatorSettings, dashboard, dashboardChecklistDismissing: false },
        "dashboard.setupChecklist.dismiss.complete"
      );
      renderDashboard();
    } catch (error) {
      patchState({ dashboardChecklistDismissing: false }, "dashboard.setupChecklist.dismiss.error");
      throw error;
    }
  }

  function renderDashboard() {
    if (!dom.dashboardContent) return;
    if (state.dashboardLoading && !state.dashboard) {
      dom.dashboardContent.innerHTML = `<article class="panel dashboard-empty">Loading dashboard...</article>`;
      return;
    }
    if (state.dashboardError && !state.dashboard) {
      dom.dashboardContent.innerHTML = `
        <article class="panel dashboard-empty" data-testid="dashboard-error">
          <p class="eyebrow">Home</p>
          <h3>Dashboard unavailable</h3>
          <p>${escapeHtml(state.dashboardError)}</p>
        </article>
      `;
      return;
    }
    const dashboard = state.dashboard;
    if (!dashboard) {
      dom.dashboardContent.innerHTML = `<article class="panel dashboard-empty">Dashboard data is not loaded yet.</article>`;
      return;
    }
    if (!dashboard.has_engagements) {
      dom.dashboardContent.innerHTML = renderEmptyDashboard(dashboard);
      return;
    }
    dom.dashboardContent.innerHTML = `
      ${renderCommandCenterStrip(dashboard)}
      <div class="dashboard-grid">
        ${renderActiveRunTile(dashboard)}
        ${renderRiskTile(dashboard)}
        ${renderOpenProblemsTile(dashboard)}
        ${renderUpcomingScansTile(dashboard)}
        ${renderRecentActivity(dashboard)}
        ${renderQuickActions(dashboard)}
        ${renderSetupChecklist(dashboard)}
        ${renderEngagementSummary(dashboard)}
      </div>
    `;
  }

  return {
    loadDashboard,
    renderDashboard,
    dismissSetupChecklist,
  };
}
