import { MODULES, SEVERITY_RANK } from "./constants.js";

export function splitLines(value) {
  return String(value || "")
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function splitComma(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function stringValue(value) {
  return String(value || "").trim();
}

export function numberValue(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function valueOrNull(value) {
  const normalized = stringValue(value);
  return normalized ? normalized : null;
}

export function slugify(value) {
  return String(value || "workspace")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "workspace";
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatDateTime(value) {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString();
}

export function formatDurationLabel(value) {
  const minutes = Math.max(0, Number(value || 0));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder ? `${hours}h ${remainder}m` : `${hours}h`;
}

export function minutesSince(value) {
  if (!value) return 0;
  return Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000));
}

export function formatElapsedMinutes(value, offset = 0) {
  return formatDurationLabel(minutesSince(value) + offset);
}

export function toPercent(value) {
  const number = Number(value || 0);
  return `${Math.round(number * 100)}%`;
}

export function isLikelyUrl(value) {
  try {
    const url = new URL(value);
    return Boolean(url.protocol && url.host);
  } catch {
    return false;
  }
}

export function isLikelyIp(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || "").trim());
}

export function isLikelyCidr(value) {
  return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(String(value || "").trim());
}

export function isLikelyDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(value || "").trim());
}

export function groupBy(items, selector) {
  return items.reduce((groups, item) => {
    const key = selector(item);
    groups[key] = groups[key] || [];
    groups[key].push(item);
    return groups;
  }, {});
}

export function capitalizeWord(value) {
  const normalized = String(value || "");
  return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : normalized;
}

export function flattenTargetValues(targets) {
  return Object.values(targets || {}).flatMap((values) => Array.isArray(values) ? values.filter(Boolean) : []);
}

export function renderTargetSummary(targets) {
  const normalized = typeof targets === "object" && targets !== null ? targets : {};
  const pieces = [];
  Object.entries(normalized).forEach(([key, values]) => {
    if (!Array.isArray(values) || !values.length) return;
    pieces.push(`${values.length} ${key.replaceAll("_", " ")}`);
  });
  return pieces.join(" · ") || "No targets yet";
}

export function enabledModules(modules) {
  if (!modules || typeof modules !== "object") return [];
  return MODULES.filter(([key]) => Boolean(modules[key])).map(([, label]) => label);
}

export function hasMeaningfulAccount(accounts) {
  return (accounts || []).some((account) =>
    Boolean(
      account &&
      (
        account.username ||
        account.secret_ref ||
        account.api_key_ref ||
        account.bearer_token_ref ||
        account.session_ref ||
        (account.secret_bindings && Object.keys(account.secret_bindings).length)
      )
    )
  );
}

export function renderAccountSummary(accounts) {
  const meaningful = (accounts || []).filter((account) => hasMeaningfulAccount([account]));
  if (!meaningful.length) return "No account context recorded";
  return meaningful.map((account) => `${account.label || account.username || "Account"} (${account.role || "role not set"})`).join(", ");
}

export function readinessSummary(data) {
  const targetCount = flattenTargetValues(data.targets).length;
  const accountCount = (data.access.accounts || []).filter((account) => hasMeaningfulAccount([account])).length;
  const moduleCount = enabledModules(data.modules).length;
  return `${targetCount} scoped target${targetCount === 1 ? "" : "s"} · ${accountCount} access context${accountCount === 1 ? "" : "s"} · ${moduleCount} enabled module${moduleCount === 1 ? "" : "s"}`;
}

export function requiresCredentials(config) {
  const profile = config.test_profile || "";
  const assessmentType = config.assessment_type || "";
  return ["Authenticated Only", "Authenticated App", "Internal Validation"].includes(profile) ||
    ["Authenticated App"].includes(assessmentType) ||
    Boolean(config.modules?.auth_flows);
}

export function countScopeTargets(scope) {
  if (!scope) return 0;
  return Object.values(scope.allowlist_json || {}).reduce((count, values) => count + (Array.isArray(values) ? values.length : 0), 0);
}

export function summarizeTaskStatuses(tasks) {
  return tasks.reduce((counts, task) => {
    counts[task.status] = (counts[task.status] || 0) + 1;
    return counts;
  }, { completed: 0, failed: 0, cancelled: 0, queued: 0, running: 0 });
}

export function findingKey(finding) {
  return `${finding.title}::${finding.target_id}`;
}

export function severityRank(severity) {
  return SEVERITY_RANK[String(severity || "unknown").toLowerCase()] ?? SEVERITY_RANK.unknown;
}

export function lineSvg(x1, y1, x2, y2) {
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="rgba(107,215,255,0.18)" stroke-width="0.4" stroke-dasharray="1 1" />`;
}

export function heroChip(label, meta) {
  return `<div class="hero-chip">${escapeHtml(label)} · ${escapeHtml(meta)}</div>`;
}

export function textareaField(id, label, values, placeholder) {
  return `
    <label class="field">
      <span>${escapeHtml(label)}</span>
      <textarea id="${id}" rows="6" placeholder="${escapeHtml(placeholder)}">${escapeHtml((values || []).join("\n"))}</textarea>
    </label>
  `;
}

export function emptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

export function statusPill(status) {
  const normalized = String(status || "unknown").toLowerCase().replace(/\s+/g, "-");
  const theme = ["complete", "completed", "validated", "approved", "deployed", "passed", "resolved"].includes(normalized)
    ? normalized
    : ["pending", "pending_approval", "requested", "generated", "queued", "draft", "review", "triaged", "in_progress", "open"].includes(normalized)
      ? (normalized === "in_progress" ? "active" : normalized === "pending_approval" ? "blocked" : normalized)
      : ["failed", "blocked", "rejected", "cancelled", "critical"].includes(normalized)
        ? normalized
        : normalized === "running"
          ? "running"
          : "unknown";
  return `<span class="status-pill status-${theme}">${escapeHtml(status || "unknown")}</span>`;
}

export function severityPill(severity) {
  const normalized = String(severity || "unknown").toLowerCase();
  return `<span class="severity-pill severity-${normalized}">${escapeHtml(normalized)}</span>`;
}

export function findingOriginLabel(origin) {
  const mapping = {
    standard: "Standard Coverage",
    adaptive_pack: "Adaptive Pack",
  };
  return mapping[String(origin || "").toLowerCase()] || String(origin || "Unknown Origin");
}

export function renderStringList(items, emptyMessage) {
  return items.length
    ? items.map((item) => `<div class="list-card"><p>${escapeHtml(item)}</p></div>`).join("")
    : emptyState(emptyMessage);
}

export function renderStringCards(items, emptyMessage) {
  return renderStringList(items, emptyMessage);
}

export function renderSignalList(items, tone, emptyMessage) {
  return items.length
    ? items.map((item) => `<div class="signal-card ${tone}"><p>${escapeHtml(item)}</p></div>`).join("")
    : emptyState(emptyMessage);
}
