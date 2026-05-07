import { runtime, state, subscribe } from "./runtime.js";
import { escapeHtml, formatDurationLabel, formatExposureScore, parseBackendTimestamp, summarizeTaskStatuses } from "./shared.js?v=20260428-cinema-elapsed-1";

const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
  none: 6,
};
const STATUS_RANK = {
  running: 0,
  queued: 1,
  failed: 2,
  blocked: 2,
  cancelled: 3,
  completed: 4,
  unknown: 5,
};
const TOOL_COLORS = ["#5ecfff", "#10b981", "#fbbf24", "#8b5cf6", "#f97316", "#ef4444"];

let cinemaUnsubscribe = null;
let cinemaRefreshTimer = null;
let cinemaPreviousFocus = null;
let cinemaNarrationCycle = 0;
let cinemaNarrationLast = "";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "summary",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, String(value)));
  return el;
}

function normalizeStatus(value) {
  const status = String(value || "unknown").trim().toLowerCase();
  if (["in_progress", "started", "active"].includes(status)) return "running";
  if (["pending", "pending_review"].includes(status)) return "queued";
  if (["completed_with_errors", "complete", "succeeded", "success"].includes(status)) return "completed";
  if (["error"].includes(status)) return "failed";
  return status || "unknown";
}

function normalizeSeverity(value) {
  const severity = String(value || "none").trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity) ? severity : "unknown";
}

function highestSeverity(findings) {
  return (Array.isArray(findings) ? findings : []).reduce((highest, finding) => {
    const severity = normalizeSeverity(finding?.severity);
    return SEVERITY_RANK[severity] < SEVERITY_RANK[highest] ? severity : highest;
  }, "none");
}

function severityColor(severity) {
  const colors = {
    critical: "#ef4444",
    high: "#f59e0b",
    medium: "#fbbf24",
    low: "#5ecfff",
    info: "#10b981",
    unknown: "#8b5cf6",
    none: "#5ecfff",
  };
  return colors[normalizeSeverity(severity)] || colors.none;
}

function statusColor(status, severity = "none") {
  const normalized = normalizeStatus(status);
  if (["failed", "blocked", "cancelled"].includes(normalized)) return "#ef4444";
  if (normalized === "running") return "#5ecfff";
  if (normalized === "queued") return "#fbbf24";
  if (normalizeSeverity(severity) !== "none") return severityColor(severity);
  if (normalized === "completed") return "#10b981";
  return "#8b5cf6";
}

function formatToolLabel(value) {
  const normalized = String(value || "source").trim();
  const labels = {
    "aws-inventory": "AWS",
    "easm-discover": "EASM",
    "external-infra": "External Infra",
    "ldap-enum": "LDAP",
    llm_probe: "LLM",
    nuclei: "nuclei",
    nmap: "nmap",
    httpx: "httpx",
    semgrep: "semgrep",
    zap: "zap",
  };
  return labels[normalized.toLowerCase()] || normalized.replaceAll("_", " ");
}

function shortToolLabel(value) {
  return formatToolLabel(value).replace(/\s+/g, "").slice(0, 7).toLowerCase() || "tool";
}

function normalizeTarget(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    return `${url.hostname}${url.pathname && url.pathname !== "/" ? url.pathname : ""}`.toLowerCase();
  } catch {
    return raw.replace(/^https?:\/\//i, "").toLowerCase();
  }
}

function compactTargetLabel(value) {
  const raw = String(value || "target").trim() || "target";
  let label = raw;
  try {
    const url = new URL(raw);
    label = `${url.hostname}${url.pathname && url.pathname !== "/" ? url.pathname : ""}`;
  } catch {
    label = raw.replace(/^https?:\/\//i, "");
  }
  return label.length > 28 ? `${label.slice(0, 25)}...` : label;
}

function selectedRunFindings() {
  return runtime.actions.selectedRunFindings?.() ||
    (state.selectedRunId ? state.mission.findingsByRun[state.selectedRunId] || [] : []);
}

function selectedInventorySnapshot() {
  return runtime.actions.selectedRunInventorySnapshot?.() || null;
}

function inventoryHosts(snapshot) {
  const normalized = snapshot?.normalized_inventory_json || {};
  return Array.isArray(normalized.hosts)
    ? normalized.hosts.map((host) => host?.host || host?.address || "").filter(Boolean)
    : [];
}

function flattenTargets(targets) {
  return Object.values(targets || {}).flatMap((items) => (Array.isArray(items) ? items.filter(Boolean) : []));
}

function countPendingAiProposals() {
  const proposals = Array.isArray(state.selectedAiInsights?.proposals) ? state.selectedAiInsights.proposals : [];
  return proposals.filter((proposal) => String(proposal?.status || "").toLowerCase() === "pending_review").length;
}

function authoritativeElapsedLabel(run) {
  if (!run) return "0m";
  const start = parseBackendTimestamp(run.started_at || run.created_at);
  if (!Number.isFinite(start)) return "0m";
  const status = normalizeStatus(run.status);
  const terminal = ["completed", "failed", "cancelled", "rejected"].includes(status) ||
    String(run.status || "").toLowerCase() === "completed_with_errors";
  const end = terminal
    ? parseBackendTimestamp(run.completed_at || run.updated_at || run.started_at || run.created_at)
    : Date.now();
  const minutes = Math.max(0, Math.round(((Number.isFinite(end) ? end : Date.now()) - start) / 60000));
  return formatDurationLabel(minutes);
}

function latestTaskStdout(tasks) {
  const running = tasks.filter((t) => normalizeStatus(t.status) === "running");
  const recent = running.length ? running : tasks.filter((t) => normalizeStatus(t.status) === "completed").slice(-2);
  for (const task of recent) {
    const execs = Array.isArray(task.executions) ? task.executions : [];
    const last = execs[execs.length - 1];
    const out = String(last?.stdout_text || "").trim();
    if (out) {
      const lines = out.split("\n").map((l) => l.trim()).filter(Boolean);
      const tail = lines.slice(-2).join(" · ");
      return tail.length > 120 ? tail.slice(-120) : tail;
    }
  }
  return null;
}

function buildNarrationCandidates({ run, findings, inventory, pendingAiProposals, counts, tasks }) {
  const candidates = [];
  const guidance = run?.ai_mission_guidance || null;
  const reasoning = Array.isArray(state.selectedAiInsights?.reasoning_records)
    ? state.selectedAiInsights.reasoning_records : [];

  if (!run) {
    return ["Cinema Mode ready — no scan active. Select a run to begin visualization."];
  }

  const stdout = latestTaskStdout(tasks);
  if (stdout) candidates.push(`Live output: ${stdout}`);

  if (pendingAiProposals) {
    candidates.push(`${pendingAiProposals} AI proposal${pendingAiProposals === 1 ? "" : "s"} awaiting operator review — no action executes without approval.`);
  }

  const failedReasoning = reasoning.find((r) => ["failed", "error", "blocked"].includes(String(r?.status || "").toLowerCase()));
  if (failedReasoning) candidates.push("AI reasoning flagged for review — diagnostic available in Mission Control.");

  if (guidance?.available && guidance.summary) {
    candidates.push(`AI Signal: ${guidance.summary}`);
  }

  const runningTasks = tasks.filter((t) => normalizeStatus(t.status) === "running");
  if (runningTasks.length) {
    const toolNames = [...new Set(runningTasks.map((t) => t.tool || "unknown"))].join(", ");
    candidates.push(`Active: ${toolNames} — scanning approved targets within engagement scope.`);
    candidates.push(`${runningTasks.length} runner${runningTasks.length === 1 ? "" : "s"} active. Evidence captured after each completed step.`);
  }

  if (findings.length) {
    const severity = highestSeverity(findings);
    candidates.push(`${findings.length} finding${findings.length === 1 ? "" : "s"} recorded — highest severity: ${severity}. Review in Findings Theater.`);
    const crit = findings.filter((f) => normalizeSeverity(f?.severity) === "critical").length;
    if (crit) candidates.push(`${crit} critical finding${crit === 1 ? "" : "s"} require immediate attention. Kill switch available at any time.`);
  }

  if (inventory) {
    const hostCount = Number(inventory.summary_json?.host_count || inventoryHosts(inventory).length || 0);
    if (hostCount) candidates.push(`${hostCount} host${hostCount === 1 ? "" : "s"} in inventory snapshot. Scope boundaries enforced for every task.`);
  }

  const queued = Number(counts.queued || 0);
  const completed = Number(counts.completed || 0);
  const total = tasks.length;
  if (total > 0 && completed > 0) {
    candidates.push(`${completed} of ${total} task${total === 1 ? "" : "s"} complete. Evidence stored with SHA-256 integrity hash.`);
  }
  if (queued > 0) candidates.push(`${queued} task${queued === 1 ? "" : "s"} queued — approval gates enforced before intrusive steps.`);

  if (!candidates.length) {
    candidates.push("Scan in progress — results appear as evidence is stored from each completed step.");
    candidates.push("Cinema Mode shows real data from the selected run. All evidence is evidence-backed and auditable.");
  }
  return candidates;
}

function buildNarration({ run, findings, inventory, pendingAiProposals, counts, tasks }) {
  const candidates = buildNarrationCandidates({ run, findings, inventory, pendingAiProposals, counts, tasks });
  const idx = cinemaNarrationCycle % candidates.length;
  return candidates[idx] || candidates[0];
}

function deriveTaskTarget(task) {
  return String(task?.target_id || task?.params_json?.target || task?.params_json?.url || "").trim();
}

function ensureTool(tools, key, label = null) {
  const normalized = String(key || "source").trim().toLowerCase() || "source";
  if (!tools.has(normalized)) {
    tools.set(normalized, {
      key: normalized,
      label: label || formatToolLabel(normalized),
      color: TOOL_COLORS[tools.size % TOOL_COLORS.length],
    });
  }
  return tools.get(normalized);
}

function ensureTarget(targets, value, origin = "task") {
  const normalized = normalizeTarget(value);
  if (!normalized) return null;
  if (!targets.has(normalized)) {
    targets.set(normalized, {
      key: normalized,
      label: String(value),
      origin,
      tasks: [],
      findings: [],
      inventory: false,
      scope: false,
    });
  }
  return targets.get(normalized);
}

function targetStatus(target) {
  const statuses = target.tasks.map((task) => normalizeStatus(task.status));
  if (statuses.includes("running")) return "running";
  if (statuses.includes("queued")) return "queued";
  if (statuses.some((status) => ["failed", "blocked", "cancelled"].includes(status))) return "failed";
  if (statuses.includes("completed")) return "completed";
  if (target.inventory) return "completed";
  if (target.scope) return "queued";
  return "unknown";
}

function buildGraphModel({ run, tasks, findings, inventory }) {
  const tools = new Map();
  const targets = new Map();

  tasks.forEach((task) => {
    const tool = ensureTool(tools, task.tool || "task");
    const target = ensureTarget(targets, deriveTaskTarget(task) || task.tool || "task target", "task");
    if (target) {
      target.tasks.push({ ...task, cinemaToolKey: tool.key });
    }
  });

  findings.forEach((finding) => {
    const target = ensureTarget(targets, finding.target_id || finding.title || "finding target", "finding");
    if (target) target.findings.push(finding);
  });

  inventoryHosts(inventory).forEach((host) => {
    const target = ensureTarget(targets, host, "inventory");
    if (target) target.inventory = true;
  });

  flattenTargets(run?.configuration_json?.targets).forEach((targetValue) => {
    const target = ensureTarget(targets, targetValue, "scope");
    if (target) target.scope = true;
  });

  const inventorySource = Array.isArray(inventory?.source_tools_json) && inventory.source_tools_json.length
    ? inventory.source_tools_json[0]
    : "inventory";
  const needsInventorySource = [...targets.values()].some((target) => target.inventory && !target.tasks.length);
  if (needsInventorySource) {
    ensureTool(tools, inventorySource, formatToolLabel(inventorySource));
  }
  const needsScopeSource = [...targets.values()].some((target) => target.scope && !target.tasks.length && !target.inventory);
  if (needsScopeSource) {
    ensureTool(tools, "approved-scope", "Scope");
  }

  const targetList = [...targets.values()]
    .map((target) => ({
      ...target,
      severity: highestSeverity(target.findings),
      status: targetStatus(target),
    }))
    .sort((left, right) => {
      const severityOrder = SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
      if (severityOrder !== 0) return severityOrder;
      const statusOrder = (STATUS_RANK[left.status] ?? 9) - (STATUS_RANK[right.status] ?? 9);
      if (statusOrder !== 0) return statusOrder;
      return left.label.localeCompare(right.label);
    });

  return {
    tools: [...tools.values()],
    targets: targetList,
    hiddenTargetCount: Math.max(0, targetList.length - 16),
    visibleTargets: targetList.slice(0, 16),
  };
}

function uniqueCompletedTargets(tasks, inventory, runStatus) {
  const completedTargets = new Set();
  tasks.forEach((task) => {
    const status = normalizeStatus(task.status);
    const target = normalizeTarget(deriveTaskTarget(task));
    if (target && ["completed", "failed", "cancelled"].includes(status)) {
      completedTargets.add(target);
    }
  });
  const discoveredHosts = Number(inventory?.summary_json?.host_count || inventoryHosts(inventory).length || 0);
  if (!completedTargets.size && discoveredHosts && ["completed", "completed_with_errors"].includes(String(runStatus || "").toLowerCase())) {
    return discoveredHosts;
  }
  return completedTargets.size;
}

function buildCinemaModel() {
  const run = state.selectedRun || null;
  const tasks = Array.isArray(run?.tasks) ? run.tasks : [];
  const findings = selectedRunFindings();
  const inventory = selectedInventorySnapshot();
  const counts = summarizeTaskStatuses(tasks);
  const criticalCount = findings.filter((finding) => normalizeSeverity(finding?.severity) === "critical").length;
  const highCount = findings.filter((finding) => normalizeSeverity(finding?.severity) === "high").length;
  const inventoryHostCount = Number(inventory?.summary_json?.host_count || inventoryHosts(inventory).length || 0);
  const uniqueTaskTargets = new Set(tasks.map(deriveTaskTarget).map(normalizeTarget).filter(Boolean)).size;
  const discoveredHosts = Math.max(inventoryHostCount, uniqueTaskTargets);
  const scannedHosts = uniqueCompletedTargets(tasks, inventory, run?.status);
  const pendingAiProposals = countPendingAiProposals();
  const exposureCurrent = state.exposureScore?.current || null;
  const exposureScore = exposureCurrent && Number.isFinite(Number(exposureCurrent.score))
    ? Math.max(0, Math.min(100, Number(exposureCurrent.score)))
    : null;
  const graph = buildGraphModel({ run, tasks, findings, inventory });
  const terminal = ["completed", "completed_with_errors", "failed", "cancelled", "rejected"].includes(
    String(run?.status || "").toLowerCase()
  );
  const liveAttached = state.runStream?.runId && String(state.runStream.runId) === String(run?.id || "") && state.runStream.status === "connected";
  const runningOrQueued = Number(counts.running || 0) + Number(counts.queued || 0);
  const activePhase = !run
    ? "No run selected"
    : liveAttached
      ? `${run.status || "run"} · live stream`
      : runningOrQueued
        ? `${run.status || "run"} · polling snapshot`
        : terminal
          ? `${run.status || "run"} · stored snapshot`
          : `${run.status || "run"} · standing by`;
  const profileName = run?.profile?.name || run?.configuration_json?.execution_profile || run?.configuration_json?.test_profile || "Mission";

  return {
    run,
    tasks,
    findings,
    inventory,
    counts,
    criticalCount,
    highCount,
    discoveredHosts,
    scannedHosts,
    pendingAiProposals,
    exposureScore,
    exposureCurrent,
    graph,
    activePhase,
    profileName,
    elapsed: authoritativeElapsedLabel(run),
    narration: buildNarration({ run, findings, inventory, pendingAiProposals, counts, tasks }),
  };
}

function distributeY(index, total, height) {
  if (total <= 1) return Math.round(height / 2);
  const top = 86;
  const bottom = height - 82;
  return Math.round(top + ((bottom - top) * index) / Math.max(1, total - 1));
}

function threadPath(tool, target, laneIndex) {
  const startX = tool.x + 38;
  const endX = target.x - 42;
  const offset = ((laneIndex % 3) - 1) * 16;
  return `M ${startX} ${tool.y} C ${startX + 210} ${tool.y + offset}, ${endX - 210} ${target.y - offset}, ${endX} ${target.y}`;
}

function renderCinemaSvg(model) {
  const width = 1100;
  const height = 620;
  const svg = svgEl("svg", {
    class: "cinema-svg",
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": "Live scan visualization derived from selected run state",
  });

  const defs = svgEl("defs");
  defs.append(svgEl("radialGradient", { id: "cinema-node-core", cx: "50%", cy: "50%", r: "60%" }));
  defs.querySelector("#cinema-node-core")?.append(
    svgEl("stop", { offset: "0%", "stop-color": "#e4eeff", "stop-opacity": "0.82" }),
    svgEl("stop", { offset: "100%", "stop-color": "#5ecfff", "stop-opacity": "0.08" })
  );
  svg.append(defs);

  const grid = svgEl("g", { class: "cinema-grid" });
  for (let x = 100; x < width; x += 160) {
    grid.append(svgEl("line", { x1: x, y1: 54, x2: x, y2: height - 54 }));
  }
  for (let y = 100; y < height; y += 120) {
    grid.append(svgEl("line", { x1: 48, y1: y, x2: width - 48, y2: y }));
  }
  svg.append(grid);

  if (!model.graph.tools.length || !model.graph.visibleTargets.length) {
    const emptyGroup = svgEl("g", { class: "cinema-empty-state", transform: `translate(${width / 2} ${height / 2})` });
    emptyGroup.append(svgEl("circle", { r: "76", class: "cinema-empty-ring" }));
    const title = svgEl("text", { y: "-6", "text-anchor": "middle", class: "cinema-empty-title" });
    title.textContent = model.run ? "No task or inventory map yet" : "No selected run";
    const detail = svgEl("text", { y: "24", "text-anchor": "middle", class: "cinema-empty-copy" });
    detail.textContent = model.run
      ? "Cinema Mode will animate stored tasks, findings, and inventory as soon as they exist."
      : "Select or launch a mission to populate this visualization.";
    emptyGroup.append(title, detail);
    svg.append(emptyGroup);
    return svg;
  }

  const toolCount = model.graph.tools.length;
  const targetCount = model.graph.visibleTargets.length;
  const tools = model.graph.tools.map((tool, index) => ({
    ...tool,
    x: 92,
    y: distributeY(index, toolCount, height),
  }));
  const toolByKey = new Map(tools.map((tool) => [tool.key, tool]));
  const targets = model.graph.visibleTargets.map((target, index) => ({
    ...target,
    x: width - 118,
    y: distributeY(index, targetCount, height),
  }));

  const threads = svgEl("g", { class: "cinema-threads" });
  let threadIndex = 0;
  targets.forEach((target) => {
    const taskThreads = target.tasks.length
      ? target.tasks.map((task) => ({ task, toolKey: task.cinemaToolKey }))
      : target.inventory
        ? [{ task: { status: "completed", tool: "inventory" }, toolKey: model.graph.tools[0]?.key || "inventory" }]
        : [{ task: { status: "queued", tool: "approved-scope" }, toolKey: "approved-scope" }];
    taskThreads.forEach(({ task, toolKey }) => {
      const tool = toolByKey.get(toolKey) || tools[0];
      if (!tool) return;
      const status = normalizeStatus(task.status);
      const path = threadPath(tool, target, threadIndex);
      const thread = svgEl("path", {
        d: path,
        class: `cinema-thread thread-draw state-${status} severity-${target.severity}`,
        stroke: statusColor(status, target.severity),
        style: `--thread-delay:${threadIndex * 80}ms`,
      });
      threads.append(thread);
      if (["running", "queued"].includes(status)) {
        const dotCount = status === "running" ? 3 : 1;
        const baseDur = status === "running" ? 1.7 : 3.2;
        for (let d = 0; d < dotCount; d++) {
          const pulse = svgEl("circle", {
            r: d === 0 ? (status === "running" ? "5" : "3.5") : "3",
            class: `cinema-thread-pulse severity-${target.severity}`,
            fill: statusColor(status, target.severity),
            "fill-opacity": d === 0 ? "1" : "0.55",
            style: `--thread-delay:${threadIndex * 90 + d * 40}ms`,
          });
          const motion = svgEl("animateMotion", {
            dur: `${baseDur + d * 0.55}s`,
            begin: `${d * (baseDur / dotCount)}s`,
            repeatCount: "indefinite",
            path,
          });
          pulse.append(motion);
          threads.append(pulse);
        }
      }
      threadIndex += 1;
    });
  });
  svg.append(threads);

  const runningToolKeys = new Set(
    model.tasks.filter((t) => normalizeStatus(t.status) === "running").map((t) => t.cinemaToolKey || t.tool || "")
  );
  const toolGroup = svgEl("g", { class: "cinema-tools" });
  tools.forEach((tool) => {
    const isActive = runningToolKeys.has(tool.key);
    const group = svgEl("g", {
      class: `cinema-tool-node${isActive ? " tool-active" : ""}`,
      transform: `translate(${tool.x} ${tool.y})`
    });
    if (isActive) {
      const pulse1 = svgEl("circle", { r: "36", fill: "none", stroke: tool.color, "stroke-opacity": "0.3", "stroke-width": "1.5" });
      const pulseAnim = svgEl("animate", { attributeName: "r", values: "28;44;28", dur: "2.4s", repeatCount: "indefinite" });
      const pulseAlpha = svgEl("animate", { attributeName: "stroke-opacity", values: "0.4;0;0.4", dur: "2.4s", repeatCount: "indefinite" });
      pulse1.append(pulseAnim, pulseAlpha);
      group.append(pulse1);
    }
    group.append(svgEl("circle", { r: "28", fill: tool.color, "fill-opacity": isActive ? "0.18" : "0.12", stroke: tool.color, "stroke-width": isActive ? "1.5" : "1" }));
    const short = svgEl("text", { y: "4", "text-anchor": "middle", fill: tool.color, "font-size": "11", "font-weight": "700" });
    short.textContent = shortToolLabel(tool.label);
    const label = svgEl("text", { y: "42", "text-anchor": "middle", fill: "rgba(228,238,255,0.62)", "font-size": "11" });
    label.textContent = formatToolLabel(tool.label);
    if (isActive) {
      const statusDot = svgEl("circle", { cx: "20", cy: "-20", r: "5", fill: "#10b981" });
      const dotBlink = svgEl("animate", { attributeName: "opacity", values: "1;0.3;1", dur: "1.2s", repeatCount: "indefinite" });
      statusDot.append(dotBlink);
      group.append(statusDot);
    }
    group.append(short, label);
    toolGroup.append(group);
  });
  svg.append(toolGroup);

  const targetGroup = svgEl("g", { class: "cinema-targets" });
  targets.forEach((target) => {
    const color = statusColor(target.status, target.severity);
    const stateName = target.severity === "critical"
      ? "critical"
      : target.findings.length
        ? "finding"
        : normalizeStatus(target.status);
    const group = svgEl("g", {
      class: `cinema-target-node state-${stateName} severity-${target.severity}`,
      transform: `translate(${target.x} ${target.y})`,
      "data-testid": "cinema-host-node",
    });
    group.append(svgEl("circle", { r: "38", fill: color, "fill-opacity": "0.04", stroke: color, "stroke-opacity": "0.16" }));
    group.append(svgEl("circle", { r: "24", fill: "none", stroke: color, class: "node-ring" }));
    group.append(svgEl("circle", { r: "16", fill: color, "fill-opacity": "0.18", stroke: color, "stroke-width": "2", class: target.severity === "critical" ? "node-critical" : "" }));
    if (target.findings.length) {
      group.append(svgEl("circle", { r: "26", fill: "none", stroke: color, class: "ripple" }));
      const badge = svgEl("g", { class: `cinema-finding-badge severity-${target.severity}`, transform: "translate(28 -24)" });
      badge.append(svgEl("circle", { r: "14", fill: color, "fill-opacity": "0.92" }));
      const count = svgEl("text", { y: "4", "text-anchor": "middle", fill: "#04080f", "font-size": "11", "font-weight": "800" });
      count.textContent = String(target.findings.length);
      badge.append(count);
      group.append(badge);
    }
    const label = svgEl("text", { x: "-48", y: "-34", fill: "rgba(228,238,255,0.78)", "font-size": "11", "text-anchor": "end" });
    label.textContent = compactTargetLabel(target.label);
    const stateLabel = svgEl("text", { x: "-48", y: "-18", fill: color, "font-size": "10", "text-anchor": "end", "font-weight": "700" });
    stateLabel.textContent = target.findings.length
      ? `${target.findings.length} finding${target.findings.length === 1 ? "" : "s"}`
      : normalizeStatus(target.status);
    group.append(label, stateLabel);
    targetGroup.append(group);
  });
  svg.append(targetGroup);

  if (model.graph.hiddenTargetCount) {
    const hidden = svgEl("text", { x: width - 120, y: height - 28, "text-anchor": "end", class: "cinema-hidden-summary" });
    hidden.textContent = `+${model.graph.hiddenTargetCount} additional mapped target${model.graph.hiddenTargetCount === 1 ? "" : "s"}`;
    svg.append(hidden);
  }

  return svg;
}

function counterSnapshot(model) {
  return {
    exposure: model.exposureScore === null ? "n/a" : formatExposureScore(model.exposureScore),
    critical: String(model.criticalCount),
    high: String(model.highCount),
    hosts: String(model.scannedHosts),
    proposals: String(model.pendingAiProposals),
  };
}

function changedClass(previous, current, key) {
  if (!previous || previous[key] === current[key]) return "";
  return " bump";
}

function graphSignature(model) {
  return JSON.stringify({
    tools: model.graph.tools.map((tool) => tool.key),
    hiddenTargetCount: model.graph.hiddenTargetCount,
    targets: model.graph.visibleTargets.map((target) => ({
      key: target.key,
      findingCount: target.findings.length,
      taskTools: target.tasks.map((task) => task.cinemaToolKey || task.tool || ""),
    })),
  });
}

function setText(root, selector, value) {
  const element = root.querySelector(selector);
  if (!element) return;
  const nextValue = String(value ?? "");
  if (element.textContent !== nextValue) {
    element.textContent = nextValue;
  }
}

function setClassName(root, selector, value) {
  const element = root.querySelector(selector);
  if (!element || element.className === value) return;
  element.className = value;
}

function renderCinemaShell(overlay, liveLabel) {
  overlay.innerHTML = `
    <div id="c1" data-testid="cinema-overlay" data-cinema-state="${escapeHtml(liveLabel)}">
      <div class="c1-topbar">
        <div class="c1-logo"><div class="c1-logo-mark">A</div>AegisPT</div>
        <div class="c1-status">
          <div class="c1-pulse"></div>
          <span data-testid="cinema-phase"></span>
        </div>
        <div class="cinema-label">CINEMA MODE</div>
        <div class="c1-right">
          <div class="c1-stat"><span>Mission</span><strong data-cinema-field="mission"></strong></div>
          <div class="c1-stat"><span>Elapsed</span><strong data-cinema-field="elapsed"></strong></div>
          <div class="c1-stat"><span>Tasks</span><strong data-cinema-field="tasks"></strong></div>
          <button class="cinema-close" type="button" data-testid="cinema-mode-close">✕ Exit Cinema</button>
        </div>
      </div>
      <div class="c1-canvas" data-testid="cinema-visualization"></div>
      <div class="critical-flash" aria-hidden="true"></div>
      <div class="c1-narrator">
        <div class="narrator-dot"></div>
        <div class="narrator-text typing" data-testid="cinema-narrator"></div>
      </div>
      <div class="c1-bottom">
        <div class="c1-metric" data-testid="cinema-counter-exposure">
          <span class="cm-label">Exposure Score</span>
          <span class="cm-value muted" data-cinema-field="exposure"></span>
          <span class="cm-sub" data-cinema-field="exposure-sub"></span>
        </div>
        <div class="c1-metric" data-testid="cinema-counter-critical">
          <span class="cm-label">Critical</span>
          <span class="cm-value red" data-cinema-field="critical"></span>
          <span class="cm-delta up" data-cinema-field="critical-sub"></span>
        </div>
        <div class="c1-metric" data-testid="cinema-counter-high">
          <span class="cm-label">High</span>
          <span class="cm-value amber" data-cinema-field="high"></span>
          <span class="cm-delta up" data-cinema-field="high-sub"></span>
        </div>
        <div class="c1-metric" data-testid="cinema-counter-hosts">
          <span class="cm-label">Hosts Scanned</span>
          <span class="cm-value cyan" data-cinema-field="hosts"></span>
          <span class="cm-sub" data-cinema-field="hosts-sub"></span>
        </div>
        <div class="c1-metric" data-testid="cinema-counter-ai-proposals">
          <span class="cm-label">AI Proposals</span>
          <span class="cm-value muted" data-cinema-field="proposals"></span>
          <span class="cm-sub" data-cinema-field="proposals-sub"></span>
        </div>
      </div>
    </div>
  `;
  overlay.querySelector("[data-testid='cinema-mode-close']")?.addEventListener("click", closeCinemaMode);
}

function renderCinemaOverlay(overlay) {
  if (!overlay?.isConnected) return;
  const model = buildCinemaModel();
  const previous = overlay.__cinemaCounters || null;
  const counters = counterSnapshot(model);
  const completed = Number(model.counts.completed || 0) + Number(model.counts.failed || 0) + Number(model.counts.cancelled || 0);
  const total = model.tasks.length;
  const liveLabel = model.run ? (state.runStream?.status === "connected" ? "live stream" : "stored state") : "idle";
  const shouldFlash = model.criticalCount > 0 && (!previous || Number(counters.critical) > Number(previous.critical || 0));
  const narratorChars = Math.max(1, model.narration.length);
  const narratorDuration = Math.min(5200, Math.max(1600, narratorChars * 34));
  const narratorWidth = Math.min(760, Math.max(220, narratorChars * 7.2));
  const hostsSub = model.discoveredHosts
    ? `of ${model.discoveredHosts} discovered`
    : model.run
      ? "no discovered hosts"
      : "select a run";
  const exposureSub = model.exposureScore === null
    ? "not computed"
    : model.exposureCurrent?.trend
      ? `trend ${model.exposureCurrent.trend}`
      : "stored score";

  if (!overlay.querySelector("#c1")) {
    renderCinemaShell(overlay, liveLabel);
  }

  const shell = overlay.querySelector("#c1");
  if (!shell) return;
  shell.dataset.cinemaState = liveLabel;
  setText(shell, "[data-testid='cinema-phase']", model.activePhase);
  setText(shell, "[data-cinema-field='mission']", model.profileName);
  setText(shell, "[data-cinema-field='elapsed']", model.elapsed);
  setText(shell, "[data-cinema-field='tasks']", total ? `${completed}/${total}` : "0/0");

  const flash = shell.querySelector(".critical-flash");
  flash?.classList.toggle("active", shouldFlash);

  const narrator = shell.querySelector("[data-testid='cinema-narrator']");
  if (narrator && (narrator.textContent !== model.narration || cinemaNarrationLast !== model.narration)) {
    cinemaNarrationLast = model.narration;
    narrator.textContent = model.narration;
    narrator.style.setProperty("--narrator-chars", String(narratorChars));
    narrator.style.setProperty("--narrator-duration", `${narratorDuration}ms`);
    narrator.style.setProperty("--narrator-width", `${narratorWidth}px`);
    narrator.classList.remove("typing");
    void narrator.offsetWidth;
    narrator.classList.add("typing");
  }

  setText(shell, "[data-cinema-field='exposure']", counters.exposure);
  setText(shell, "[data-cinema-field='exposure-sub']", exposureSub);
  setClassName(
    shell,
    "[data-cinema-field='exposure']",
    `cm-value ${model.exposureScore === null ? "muted" : "red"}${changedClass(previous, counters, "exposure")}`
  );
  setText(shell, "[data-cinema-field='critical']", counters.critical);
  setText(shell, "[data-cinema-field='critical-sub']", model.criticalCount ? "stored finding signal" : "none stored");
  setClassName(shell, "[data-cinema-field='critical']", `cm-value red${changedClass(previous, counters, "critical")}`);
  setText(shell, "[data-cinema-field='high']", counters.high);
  setText(shell, "[data-cinema-field='high-sub']", model.highCount ? "stored finding signal" : "none stored");
  setClassName(shell, "[data-cinema-field='high']", `cm-value amber${changedClass(previous, counters, "high")}`);
  setText(shell, "[data-cinema-field='hosts']", counters.hosts);
  setText(shell, "[data-cinema-field='hosts-sub']", hostsSub);
  setClassName(shell, "[data-cinema-field='hosts']", `cm-value cyan${changedClass(previous, counters, "hosts")}`);
  setText(shell, "[data-cinema-field='proposals']", counters.proposals);
  setText(shell, "[data-cinema-field='proposals-sub']", model.pendingAiProposals ? "waiting review" : "none pending");
  setClassName(shell, "[data-cinema-field='proposals']", `cm-value muted${changedClass(previous, counters, "proposals")}`);

  const nextGraphSignature = graphSignature(model);
  if (overlay.__cinemaGraphSignature !== nextGraphSignature) {
    const canvas = shell.querySelector(".c1-canvas");
    if (canvas) {
      canvas.replaceChildren(renderCinemaSvg(model));
    }
    overlay.__cinemaGraphSignature = nextGraphSignature;
  }
  overlay.__cinemaCounters = counters;
}

export function closeCinemaMode() {
  document.removeEventListener("keydown", handleCinemaKeydown);
  document.body.classList.remove("cinema-open");
  if (cinemaUnsubscribe) {
    cinemaUnsubscribe();
    cinemaUnsubscribe = null;
  }
  if (cinemaRefreshTimer) {
    window.clearInterval(cinemaRefreshTimer);
    cinemaRefreshTimer = null;
  }
  document.getElementById("cinema-overlay")?.remove();
  if (cinemaPreviousFocus?.isConnected) {
    cinemaPreviousFocus.focus();
  }
  cinemaPreviousFocus = null;
}

function handleCinemaKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeCinemaMode();
    return;
  }
  if (event.key !== "Tab") return;
  const overlay = document.getElementById("cinema-overlay");
  const focusable = focusableElements(overlay);
  if (!focusable.length) {
    event.preventDefault();
    overlay?.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function focusableElements(root) {
  if (!root) return [];
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter((element) => {
    if (!(element instanceof HTMLElement)) return false;
    if (element.getAttribute("aria-hidden") === "true") return false;
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

export function openCinemaMode() {
  closeCinemaMode();
  cinemaPreviousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const overlay = document.createElement("div");
  overlay.id = "cinema-overlay";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Cinema Mode");
  overlay.setAttribute("tabindex", "-1");
  document.body.append(overlay);
  document.body.classList.add("cinema-open");
  renderCinemaOverlay(overlay);
  cinemaNarrationCycle = 0;
  cinemaNarrationLast = "";
  cinemaUnsubscribe = subscribe(() => renderCinemaOverlay(overlay));
  cinemaRefreshTimer = window.setInterval(() => {
    cinemaNarrationCycle += 1;
    renderCinemaOverlay(overlay);
  }, 6000);
  document.addEventListener("keydown", handleCinemaKeydown);
  window.requestAnimationFrame(() => {
    const closeButton = overlay.querySelector("[data-testid='cinema-mode-close']");
    if (closeButton instanceof HTMLElement) {
      closeButton.focus();
    } else {
      overlay.focus();
    }
  });
}
