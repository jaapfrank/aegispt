import { MODULES, SEVERITY_RANK } from "./constants.js";

const RUN_PROFILE_PLAN_FALLBACKS = {
  "passive-network-discovery": {
    run_class: "passive",
    limits_json: {
      description: "Passive-safe host and range discovery using Nmap ping scan semantics.",
      required_approvals: 0,
      tools: ["nmap"],
    },
  },
  "passive-network-service-enumeration": {
    run_class: "passive",
    limits_json: {
      description: "Passive-safe service identification across discovered hosts using Nmap top-port and service detection.",
      required_approvals: 0,
      tools: ["nmap"],
    },
  },
  "passive-web-baseline": {
    run_class: "passive",
    limits_json: {
      description: "Passive HTTP fingerprinting with the Python httpx runner.",
      required_approvals: 0,
      tools: ["httpx"],
    },
  },
  "passive-easm-discovery": {
    run_class: "passive",
    limits_json: {
      description: "Passive external attack-surface discovery from approved root domains.",
      required_approvals: 0,
      tools: ["easm-discover"],
    },
  },
  "passive-external-infrastructure": {
    run_class: "passive",
    limits_json: {
      description: "Passive external infrastructure assessment with EASM-assisted expansion, full-port service detection, HTTP follow-up, SSH audit, and optional passive SMB checks.",
      required_approvals: 0,
      tools: ["external-infra"],
    },
  },
  "passive-code-semgrep-audit": {
    run_class: "passive",
    limits_json: {
      description: "Passive Semgrep scan over allowlisted local code paths with curated rules.",
      required_approvals: 0,
      tools: ["semgrep"],
    },
  },
  "passive-web-nuclei-audit": {
    run_class: "passive",
    limits_json: {
      description: "Passive-safe nuclei validation with a pinned local template.",
      required_approvals: 0,
      tools: ["nuclei"],
    },
  },
  "active-web-safe": {
    run_class: "active",
    limits_json: {
      description: "Approval-gated ZAP crawl and passive validation with safer defaults.",
      required_approvals: 1,
      tools: ["zap"],
    },
  },
  "active-external-infrastructure": {
    run_class: "active",
    limits_json: {
      description: "Approval-gated external infrastructure assessment that adds infrastructure-focused nuclei validation after the passive service baseline.",
      required_approvals: 1,
      tools: ["external-infra"],
    },
  },
  "active-web-zap-active": {
    run_class: "active",
    limits_json: {
      description: "Approval-gated ZAP spider plus active scan against allowlisted web targets.",
      required_approvals: 1,
      tools: ["zap"],
    },
  },
  "active-lan-ssh-brute": {
    run_class: "active",
    limits_json: {
      description: "Approval-gated Hydra weak-credential validation for approved SSH, FTP, Telnet, and RDP services.",
      required_approvals: 1,
      tools: ["ssh-brute"],
    },
  },
  "passive-lan-network-capture": {
    run_class: "passive",
    limits_json: {
      description: "Passive LAN tcpdump capture and ARP consistency review with redacted credential evidence.",
      required_approvals: 0,
      tools: ["network-capture"],
    },
  },
  "intrusive-validation": {
    run_class: "intrusive",
    limits_json: {
      description: "Higher-risk internal validation flow with two-person approval.",
      required_approvals: 2,
      tools: ["zap", "nuclei"],
    },
  },
};

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
  const timestamp = parseBackendTimestamp(value);
  if (!Number.isFinite(timestamp)) return 0;
  return Math.max(0, Math.round((Date.now() - timestamp) / 60000));
}

export function formatElapsedMinutes(value, offset = 0) {
  return formatDurationLabel(minutesSince(value) + offset);
}

export function parseBackendTimestamp(value) {
  if (!value) return NaN;
  if (value instanceof Date) return value.getTime();
  const raw = String(value).trim();
  if (!raw) return NaN;
  if (/^\d{4}-\d{2}-\d{2}T/.test(raw) && !/(Z|[+-]\d{2}:?\d{2})$/.test(raw)) {
    return new Date(`${raw}Z`).getTime();
  }
  return new Date(raw).getTime();
}

export function toPercent(value) {
  const number = Number(value || 0);
  return `${Math.round(number * 100)}%`;
}

export function formatExposureScore(value) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric)) return "0";
  return Number.isInteger(numeric) ? String(numeric) : numeric.toFixed(1);
}

export function exposureTrendLabel(value) {
  const normalized = String(value || "stable").trim().toLowerCase();
  const labels = {
    improving: "Improving",
    worsening: "Worsening",
    stable: "Stable",
  };
  return labels[normalized] || "Stable";
}

export function exposureScoreTone(value) {
  const score = Number(value || 0);
  if (score >= 75) return "critical";
  if (score >= 50) return "warning";
  if (score >= 20) return "watch";
  return "healthy";
}

export function renderExposureSparkline(history, options = {}) {
  const points = Array.isArray(history) ? history : [];
  const width = Math.max(40, Number(options.width || 160));
  const height = Math.max(20, Number(options.height || 34));
  const className = String(options.className || "").trim();
  const testId = String(options.testId || "").trim();
  if (!points.length) {
    return `
      <div class="exposure-sparkline is-empty ${escapeHtml(className)}" ${testId ? `data-testid="${escapeHtml(testId)}"` : ""}>
        <span>No score history yet</span>
      </div>
    `;
  }
  const values = points.map((point) => Math.max(0, Math.min(100, Number(point?.score || 0))));
  const denominator = Math.max(values.length - 1, 1);
  const coordinates = values.map((value, index) => {
    const x = (index / denominator) * width;
    const y = height - (value / 100) * height;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const area = [`0,${height}`, ...coordinates, `${width},${height}`].join(" ");
  const line = coordinates.join(" ");
  return `
    <svg
      class="exposure-sparkline ${escapeHtml(className)}"
      ${testId ? `data-testid="${escapeHtml(testId)}"` : ""}
      width="${width}"
      height="${height}"
      viewBox="0 0 ${width} ${height}"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <polygon points="${area}" class="exposure-sparkline-area"></polygon>
      <polyline points="${line}" class="exposure-sparkline-line"></polyline>
    </svg>
  `;
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
  const normalized = String(value || "").trim();
  const octets = normalized.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });
}

export function isLikelyCidr(value) {
  const normalized = String(value || "").trim();
  const [host, prefix] = normalized.split("/");
  if (!host || prefix === undefined) return false;
  if (!isLikelyIp(host) || !/^\d{1,2}$/.test(prefix)) return false;
  const mask = Number(prefix);
  return mask >= 0 && mask <= 32;
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
        account.mfa_notes ||
        (account.secret_bindings && Object.keys(account.secret_bindings).length)
      )
    )
  );
}

export function hasSharedAccessGuidance(access) {
  return Boolean(
    stringValue(access?.manual_auth_steps) ||
    stringValue(access?.cookie_notes)
  );
}

export function hasMeaningfulAccessContext(access) {
  return hasMeaningfulAccount(access?.accounts || []) || hasSharedAccessGuidance(access);
}

export function countMeaningfulAccessContexts(access) {
  const accountCount = (access?.accounts || []).filter((account) => hasMeaningfulAccount([account])).length;
  if (accountCount) return accountCount;
  return hasSharedAccessGuidance(access) ? 1 : 0;
}

export function inferAuthStrategyFromAccess(access) {
  const meaningfulAccounts = (access?.accounts || []).filter((account) => hasMeaningfulAccount([account]));
  if (meaningfulAccounts.some((account) => account.api_key_ref || account.bearer_token_ref)) return "api-access";
  if (meaningfulAccounts.some((account) => account.session_ref)) return "session-access";
  if (meaningfulAccounts.length) return "credentialed";
  if (stringValue(access?.manual_auth_steps)) return "credentialed";
  if (stringValue(access?.cookie_notes)) return "session-access";
  return "";
}

export function renderAccountSummary(accounts) {
  const meaningful = (accounts || []).filter((account) => hasMeaningfulAccount([account]));
  if (!meaningful.length) return "No account context recorded";
  return meaningful.map((account) => `${account.label || account.username || "Account"} (${account.role || "role not set"})`).join(", ");
}

export function renderAccessContextSummary(access) {
  const accountSummary = renderAccountSummary(access?.accounts || []);
  if (accountSummary !== "No account context recorded") return accountSummary;
  const hasManualAuth = Boolean(stringValue(access?.manual_auth_steps));
  const hasCookieNotes = Boolean(stringValue(access?.cookie_notes));
  if (hasManualAuth && hasCookieNotes) return "Shared manual auth and session guidance recorded";
  if (hasManualAuth) return "Shared manual auth guidance recorded";
  if (hasCookieNotes) return "Shared session guidance recorded";
  return accountSummary;
}

export function readinessSummary(data) {
  const targetCount = flattenTargetValues(data.targets).length;
  const accountCount = countMeaningfulAccessContexts(data.access || {});
  const moduleCount = enabledModules(data.modules).length;
  return `${targetCount} scoped target${targetCount === 1 ? "" : "s"} · ${accountCount} access context${accountCount === 1 ? "" : "s"} · ${moduleCount} enabled module${moduleCount === 1 ? "" : "s"}`;
}

export function requiresCredentials(config) {
  const profile = config.test_profile || "";
  const assessmentType = config.assessment_type || "";
  const authStrategy = String(config.intake_preferences?.auth_strategy || "").trim();
  if (authStrategy === "unauthenticated" && profile !== "Authenticated Only") {
    return false;
  }
  if (["Authenticated Only"].includes(profile) || ["Authenticated App"].includes(assessmentType)) {
    return true;
  }
  if (["credentialed", "api-access", "session-access", "advanced-details"].includes(authStrategy)) {
    return true;
  }
  if (Boolean(config.modules?.auth_flows) && authStrategy && authStrategy !== "unauthenticated") {
    return true;
  }
  return false;
}

export function countScopeTargets(scope) {
  if (!scope) return 0;
  return Object.values(scope.allowlist_json || {}).reduce((count, values) => count + (Array.isArray(values) ? values.length : 0), 0);
}

export function executionPlanForProfile(profileName, runProfiles = []) {
  const profile =
    runProfiles.find((item) => item && item.name === profileName) ||
    RUN_PROFILE_PLAN_FALLBACKS[profileName] ||
    null;
  const limits = profile?.limits_json || {};
  const tools = Array.isArray(limits.tools)
    ? limits.tools.filter((tool) => typeof tool === "string" && tool.trim()).map((tool) => tool.trim())
    : [];
  const requiredApprovals = Number.isFinite(Number(limits.required_approvals))
    ? Number(limits.required_approvals)
    : 0;
  return {
    profileName: profileName || "unknown-profile",
    runClass: String(profile?.run_class || "unknown"),
    description: String(limits.description || "Execution lane details are not available."),
    tools,
    toolsLabel: tools.length ? tools.join(", ") : "No explicit tools recorded",
    requiredApprovals,
  };
}

export function humanizeCheckMode(value) {
  const mapping = {
    "passive-only": "Passive Only",
    guarded: "Guarded Active",
    active: "Active Validation",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

export function humanizeDepthLabel(value) {
  const mapping = {
    light: "Light",
    standard: "Standard",
    deep: "Deep",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

export function isSeedOnlyInventory(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.source_tools_json) || !snapshot.source_tools_json.length) {
    return false;
  }
  return snapshot.source_tools_json.every((tool) => tool === "wizard-input");
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

export function renderBadgeList(items, className = "") {
  const filtered = (items || []).filter(Boolean);
  if (!filtered.length) return "";
  return `
    <div class="pill-grid ${escapeHtml(className)}">
      ${filtered.map((item) => `<span class="badge">${escapeHtml(item)}</span>`).join("")}
    </div>
  `;
}

export function renderDisclosure({
  title,
  summary = "",
  body = "",
  open = false,
  className = "",
  testId = "",
} = {}) {
  return `
    <details class="disclosure-card ${escapeHtml(className)}" ${open ? "open" : ""} ${
      testId ? `data-testid="${escapeHtml(testId)}"` : ""
    }>
      <summary class="disclosure-summary">
        <span class="disclosure-copy">
          <strong>${escapeHtml(title || "Details")}</strong>
          ${summary ? `<small>${escapeHtml(summary)}</small>` : ""}
        </span>
        <span class="disclosure-caret" aria-hidden="true">Expand</span>
      </summary>
      <div class="disclosure-body">
        ${body}
      </div>
    </details>
  `;
}

export function helpBadge(text, label = "Why?") {
  return `
    <span
      class="help-badge"
      tabindex="0"
      role="note"
      aria-label="${escapeHtml(text)}"
      data-tooltip="${escapeHtml(text)}"
    >${escapeHtml(label)}</span>
  `;
}

export function fieldLabel(label, helpText = "", helpLabel = "Why?") {
  return `
    <span class="field-label">
      <span>${escapeHtml(label)}</span>
      ${helpText ? helpBadge(helpText, helpLabel) : ""}
    </span>
  `;
}

export function fieldHelp(text = "") {
  return text ? `<small class="field-help">${escapeHtml(text)}</small>` : "";
}

export function textareaField(
  id,
  label,
  values,
  placeholder,
  helpText = "",
  tooltipText = "",
) {
  return `
    <label class="field">
      ${fieldLabel(label, tooltipText || helpText)}
      <textarea id="${id}" rows="6" placeholder="${escapeHtml(placeholder)}">${escapeHtml((values || []).join("\n"))}</textarea>
      ${fieldHelp(helpText)}
    </label>
  `;
}

export function emptyState(message, action = null) {
  const config =
    action && typeof action === "object"
      ? {
          label: String(action.label || "").trim(),
          screen: String(action.screen || "").trim(),
          href: String(action.href || "").trim(),
          className: String(action.className || "ghost").trim() || "ghost",
          testId: String(action.testId || "").trim(),
        }
      : null;
  const actionMarkup = config?.label
    ? config.href
      ? `
        <a
          class="action ${escapeHtml(config.className)} empty-state-action"
          href="${escapeHtml(config.href)}"
          ${config.testId ? `data-testid="${escapeHtml(config.testId)}"` : ""}
        >${escapeHtml(config.label)}</a>
      `
      : `
        <button
          class="action ${escapeHtml(config.className)} empty-state-action"
          type="button"
          ${config.screen ? `data-nav-screen="${escapeHtml(config.screen)}"` : ""}
          ${config.testId ? `data-testid="${escapeHtml(config.testId)}"` : ""}
        >${escapeHtml(config.label)}</button>
      `
    : "";
  return `
    <div class="empty-state">
      <div class="empty-state-copy">
        <span class="empty-icon" aria-hidden="true"></span>
        <span>${escapeHtml(message)}</span>
      </div>
      ${actionMarkup}
    </div>
  `;
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

export function followUpStrategyLabel(strategy) {
  const mapping = {
    "service-enumeration": "Service Identification",
    "web-baseline": "Web Profiling",
    "approved-range-discovery": "Additional Range Discovery",
  };
  return mapping[String(strategy || "").toLowerCase()] || String(strategy || "Inventory Follow-Up");
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
