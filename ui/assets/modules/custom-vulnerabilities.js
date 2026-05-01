import { api } from "./api.js";
import { dom, patchState, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  formatDateTime,
  renderBadgeList,
  severityPill,
  statusPill,
  stringValue,
} from "./shared.js";

const SEVERITIES = ["all", "critical", "high", "medium", "low"];
const STATUSES = ["all", "draft", "active", "deprecated"];
const IMPORT_FORMATS = [
  ["plain_text", "Plain text"],
  ["nvd_json", "NVD JSON"],
  ["csaf", "CSAF"],
  ["aegispt_export", "AegisPT JSON"],
];

export function createCustomVulnerabilitiesModule() {
  let eventsBound = false;

  function bindEvents() {
    if (eventsBound) return;
    eventsBound = true;

    document.body.addEventListener("input", (event) => {
      const target = event.target.closest("[data-custom-vuln-filter]");
      if (!target) return;
      const key = target.dataset.customVulnFilter;
      patchState(
        {
          customVulnFilters: {
            ...state.customVulnFilters,
            [key]: target.value,
          },
        },
        "customVulnerabilities.filter.input"
      );
      window.clearTimeout(bindEvents.filterTimer);
      bindEvents.filterTimer = window.setTimeout(() => {
        loadCustomVulnerabilities().catch(runtime.actions.handleError);
      }, 180);
    });

    document.body.addEventListener("change", (event) => {
      const target = event.target.closest("[data-custom-vuln-filter]");
      if (!target) return;
      const key = target.dataset.customVulnFilter;
      patchState(
        {
          customVulnFilters: {
            ...state.customVulnFilters,
            [key]: target.value,
          },
        },
        "customVulnerabilities.filter.change"
      );
      loadCustomVulnerabilities().catch(runtime.actions.handleError);
    });

    document.body.addEventListener("click", (event) => {
      const row = event.target.closest("[data-custom-vuln-select]");
      if (!row) return;
      patchState({ customVulnSelectedId: row.dataset.customVulnSelect || null }, "customVulnerabilities.select");
      renderCustomVulnerabilityLibrary();
    });

    document.body.addEventListener("submit", (event) => {
      const form = event.target.closest("[data-custom-vuln-create-form]");
      if (!form) return;
      event.preventDefault();
      createCustomVulnerability(new FormData(form)).catch(runtime.actions.handleError);
    });

    document.body.addEventListener("submit", (event) => {
      const form = event.target.closest("[data-custom-vuln-import-form]");
      if (!form) return;
      event.preventDefault();
      importCustomVulnerabilities(new FormData(form)).catch(runtime.actions.handleError);
    });

    document.body.addEventListener("click", (event) => {
      const target = event.target.closest("[data-custom-vuln-export]");
      if (!target) return;
      event.preventDefault();
      exportCustomVulnerabilities().catch(runtime.actions.handleError);
    });

    document.body.addEventListener("click", (event) => {
      const target = event.target.closest("[data-custom-vuln-toggle]");
      if (!target) return;
      event.preventDefault();
      toggleCustomVulnerability(target.dataset.customVulnToggle, target.dataset.enabled !== "true").catch(
        runtime.actions.handleError
      );
    });
  }

  bindEvents.filterTimer = null;

  async function loadCustomVulnerabilities() {
    patchState({ customVulnLoading: true, customVulnError: null }, "customVulnerabilities.load.start");
    renderCustomVulnerabilityLibrary();
    try {
      const filters = state.customVulnFilters || {};
      const params = new URLSearchParams();
      if (stringValue(filters.q)) params.set("q", filters.q);
      if (stringValue(filters.product)) params.set("product", filters.product);
      if (filters.severity && filters.severity !== "all") params.set("severity", filters.severity);
      if (filters.status && filters.status !== "all") params.set("status", filters.status);
      if (state.selectedEngagementId) params.set("engagement_id", state.selectedEngagementId);
      const library = await api(`/api/v1/custom-vulnerabilities?${params.toString()}`);
      let scanOptions = [];
      if (state.selectedEngagementId) {
        scanOptions = await api(
          `/api/v1/engagements/${encodeURIComponent(state.selectedEngagementId)}/custom-vulnerabilities/scan-options`
        );
      }
      patchState(
        {
          customVulnerabilities: Array.isArray(library.items) ? library.items : [],
          customVulnerabilityScanOptions: Array.isArray(scanOptions) ? scanOptions : [],
          customVulnLoading: false,
          customVulnError: null,
          customVulnSelectedId:
            state.customVulnSelectedId &&
            (library.items || []).some((item) => String(item.id) === String(state.customVulnSelectedId))
              ? state.customVulnSelectedId
              : (library.items || [])[0]?.id || null,
        },
        "customVulnerabilities.load.complete"
      );
    } catch (error) {
      patchState(
        {
          customVulnLoading: false,
          customVulnError: String(error?.message || error),
        },
        "customVulnerabilities.load.error"
      );
    }
    renderCustomVulnerabilityLibrary();
  }

  async function createCustomVulnerability(formData) {
    patchState({ customVulnSaving: true, customVulnError: null }, "customVulnerabilities.create.start");
    renderCustomVulnerabilityLibrary();
    const payload = {
      custom_id: valueOrNull(formData.get("custom_id")),
      title: stringValue(formData.get("title")),
      description: stringValue(formData.get("description")),
      severity: stringValue(formData.get("severity")) || "medium",
      status: stringValue(formData.get("status")) || "draft",
      cvss_score: valueOrNull(formData.get("cvss_score")) ? Number(formData.get("cvss_score")) : null,
      affected_products: splitList(formData.get("affected_products")),
      cwe_ids: splitList(formData.get("cwe_ids")),
      linked_nuclei_template_ref: valueOrNull(formData.get("linked_nuclei_template_ref")),
      metadata: { source: "operator-ui" },
    };
    try {
      const created = await api("/api/v1/custom-vulnerabilities", {
        method: "POST",
        body: payload,
      });
      patchState(
        { customVulnSaving: false, customVulnSelectedId: created.id, customVulnImportResult: null },
        "customVulnerabilities.create.complete"
      );
      runtime.actions.pushStatus?.("Custom CVE definition saved.", "success");
      await loadCustomVulnerabilities();
    } catch (error) {
      patchState({ customVulnSaving: false, customVulnError: String(error?.message || error) }, "customVulnerabilities.create.error");
      renderCustomVulnerabilityLibrary();
    }
  }

  async function importCustomVulnerabilities(formData) {
    patchState({ customVulnSaving: true, customVulnError: null }, "customVulnerabilities.import.start");
    renderCustomVulnerabilityLibrary();
    const format = stringValue(formData.get("format")) || "plain_text";
    const rawPayload = stringValue(formData.get("payload"));
    let payload = rawPayload;
    if (format !== "plain_text") {
      try {
        payload = JSON.parse(rawPayload || "{}");
      } catch {
        patchState(
          { customVulnSaving: false, customVulnError: "Import payload must be valid JSON for this format." },
          "customVulnerabilities.import.invalidJson"
        );
        renderCustomVulnerabilityLibrary();
        return;
      }
    }
    try {
      const imported = await api("/api/v1/custom-vulnerabilities/import", {
        method: "POST",
        body: {
          format,
          payload,
          use_ai: Boolean(formData.get("use_ai")),
          engagement_id: state.selectedEngagementId || null,
          default_status: stringValue(formData.get("default_status")) || "draft",
        },
      });
      patchState(
        {
          customVulnSaving: false,
          customVulnImportResult: imported,
          customVulnSelectedId: imported.items?.[0]?.id || state.customVulnSelectedId,
        },
        "customVulnerabilities.import.complete"
      );
      runtime.actions.pushStatus?.("Custom vulnerability import completed.", "success");
      await loadCustomVulnerabilities();
    } catch (error) {
      patchState({ customVulnSaving: false, customVulnError: String(error?.message || error) }, "customVulnerabilities.import.error");
      renderCustomVulnerabilityLibrary();
    }
  }

  async function exportCustomVulnerabilities() {
    const exported = await api("/api/v1/custom-vulnerabilities/export");
    patchState({ customVulnExport: JSON.stringify(exported, null, 2) }, "customVulnerabilities.export");
    renderCustomVulnerabilityLibrary();
    runtime.actions.pushStatus?.("Custom CVE library export prepared.", "info");
  }

  async function toggleCustomVulnerability(id, enabled) {
    if (!state.selectedEngagementId || !id) return;
    patchState({ customVulnSaving: true, customVulnError: null }, "customVulnerabilities.toggle.start");
    await api(
      `/api/v1/engagements/${encodeURIComponent(state.selectedEngagementId)}/custom-vulnerabilities/${encodeURIComponent(id)}/toggle`,
      {
        method: "POST",
        body: { enabled },
      }
    );
    patchState({ customVulnSaving: false }, "customVulnerabilities.toggle.complete");
    await loadCustomVulnerabilities();
  }

  function renderCustomVulnerabilityLibrary() {
    if (!dom.customVulnerabilitiesContent) return;
    const items = Array.isArray(state.customVulnerabilities) ? state.customVulnerabilities : [];
    const selected = items.find((item) => String(item.id) === String(state.customVulnSelectedId)) || items[0] || null;
    const activeCount = items.filter((item) => item.status === "active").length;
    const linkedCount = items.filter((item) => item.linked_nuclei_template_ref).length;
    const readyCount = (state.customVulnerabilityScanOptions || []).filter((item) => item.profile_option?.ready_to_run).length;
    dom.customVulnerabilitiesContent.innerHTML = `
      <section class="custom-vuln-command-strip">
        <div>
          <p class="eyebrow">Library</p>
          <h3>Custom CVE and Signature Library</h3>
          <p>Track internal advisories, proprietary product flaws, and pack-backed Nuclei checks without bypassing validation or runtime binding.</p>
        </div>
        <div class="agents-metrics">
          <span class="metric-pill">${escapeHtml(`${items.length} definitions`)}</span>
          <span class="metric-pill">${escapeHtml(`${activeCount} active`)}</span>
          <span class="metric-pill">${escapeHtml(`${linkedCount} linked templates`)}</span>
          <span class="metric-pill">${escapeHtml(`${readyCount} scan-ready`)}</span>
        </div>
      </section>
      ${state.customVulnError ? `<div class="inline-errors">${escapeHtml(state.customVulnError)}</div>` : ""}
      <div class="toolbar custom-vuln-toolbar">
        <label class="field compact">
          <span class="field-label">Search</span>
          <input data-custom-vuln-filter="q" value="${escapeHtml(state.customVulnFilters.q)}" placeholder="ID, title, text, CWE" />
        </label>
        <label class="field compact">
          <span class="field-label">Product</span>
          <input data-custom-vuln-filter="product" value="${escapeHtml(state.customVulnFilters.product)}" placeholder="Product or component" />
        </label>
        <label class="field compact">
          <span class="field-label">Severity</span>
          <select data-custom-vuln-filter="severity">${renderOptions(SEVERITIES, state.customVulnFilters.severity)}</select>
        </label>
        <label class="field compact">
          <span class="field-label">Status</span>
          <select data-custom-vuln-filter="status">${renderOptions(STATUSES, state.customVulnFilters.status)}</select>
        </label>
      </div>
      <div class="custom-vuln-grid">
        <article class="panel custom-vuln-list-panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Definitions</p>
              <h3>Library Items</h3>
            </div>
            ${state.customVulnLoading ? statusPill("loading") : statusPill(`${items.length} shown`)}
          </div>
          <div class="stack-zone custom-vuln-list">
            ${items.length ? items.map((item) => renderCustomVulnerabilityRow(item, selected)).join("") : emptyState("No custom vulnerability definitions match the current filters.")}
          </div>
        </article>
        <article class="panel custom-vuln-detail-panel">
          ${selected ? renderCustomVulnerabilityDetail(selected) : emptyState("Select or create a custom definition to review pack coverage.")}
        </article>
        <article class="panel custom-vuln-editor-panel">
          ${renderCreateForm()}
        </article>
        <article class="panel custom-vuln-import-panel">
          ${renderImportExportPanel()}
        </article>
      </div>
    `;
  }

  bindEvents();

  return {
    loadCustomVulnerabilities,
    renderCustomVulnerabilityLibrary,
  };
}

function renderCustomVulnerabilityRow(item, selected) {
  const active = selected && String(selected.id) === String(item.id);
  const coverage = item.test_coverage || {};
  return `
    <button
      class="list-card custom-vuln-row ${active ? "selected" : ""}"
      type="button"
      data-custom-vuln-select="${escapeHtml(item.id)}"
      data-testid="custom-vulnerability-row"
    >
      <span class="severity-dot severity-${escapeHtml(item.severity)}"></span>
      <span class="custom-vuln-row-main">
        <strong>${escapeHtml(item.title)}</strong>
        <small>${escapeHtml(item.custom_id)} · ${(item.affected_products_json || []).map(escapeHtml).join(", ") || "No product tags"}</small>
      </span>
      <span class="custom-vuln-row-status">
        ${severityPill(item.severity)}
        ${statusPill(item.status)}
        ${coverage.deployed ? statusPill("deployed") : statusPill(coverage.status || "no template")}
      </span>
    </button>
  `;
}

function renderCustomVulnerabilityDetail(item) {
  const coverage = item.test_coverage || {};
  const stateLabel = item.engagement_state?.enabled ? "enabled" : "disabled";
  const option = (state.customVulnerabilityScanOptions || []).find((candidate) => String(candidate.id) === String(item.id));
  return `
    <div class="panel-head">
      <div>
        <p class="eyebrow">Selected Definition</p>
        <h3>${escapeHtml(item.title)}</h3>
      </div>
      <div class="pill-grid">
        ${severityPill(item.severity)}
        ${statusPill(item.status)}
      </div>
    </div>
    <div class="custom-vuln-detail">
      <p>${escapeHtml(item.description)}</p>
      ${renderBadgeList([item.custom_id, ...(item.cwe_ids_json || []), ...(item.affected_products_json || [])], "compact-badge-list")}
      <div class="custom-vuln-readout">
        <div><span>CVSS</span><strong>${escapeHtml(item.cvss_score ?? "not set")}</strong></div>
        <div><span>Reporter</span><strong>${escapeHtml(item.reporter || "operator")}</strong></div>
        <div><span>Discovery</span><strong>${escapeHtml(formatDateTime(item.discovery_date))}</strong></div>
        <div><span>Coverage</span><strong>${escapeHtml(coverage.status || "unknown")}</strong></div>
      </div>
      <div class="detail-surface split-top">
        <p class="eyebrow">Pack Lifecycle Link</p>
        <p>${escapeHtml(coverage.message || "No template coverage recorded yet.")}</p>
        <code>${escapeHtml(item.linked_nuclei_template_ref || "No linked Nuclei template reference")}</code>
      </div>
      ${
        state.selectedEngagementId && option
          ? `
            <div class="custom-vuln-toggle-row split-top">
              <div>
                <p class="eyebrow">Selected Engagement</p>
                <strong>${escapeHtml(stateLabel)}</strong>
                <p>${escapeHtml(option.profile_option?.ready_to_run ? "Ready for the passive Nuclei profile." : "Needs enabled state and deployed pack coverage before runtime selection.")}</p>
              </div>
              <button
                class="action ${option.enabled ? "ghost" : "primary"}"
                type="button"
                data-custom-vuln-toggle="${escapeHtml(item.id)}"
                data-enabled="${option.enabled ? "true" : "false"}"
                ${state.customVulnSaving ? "disabled" : ""}
              >${escapeHtml(option.enabled ? "Disable for Engagement" : "Enable for Engagement")}</button>
            </div>
          `
          : ""
      }
    </div>
  `;
}

function renderCreateForm() {
  return `
    <div class="panel-head">
      <div>
        <p class="eyebrow">Create</p>
        <h3>New Definition</h3>
      </div>
    </div>
    <form class="stack-form custom-vuln-form" data-custom-vuln-create-form data-testid="custom-vulnerability-create-form">
      <div class="field-grid two">
        <label class="field"><span class="field-label">Custom ID</span><input name="custom_id" placeholder="ORG-2026-001" /></label>
        <label class="field"><span class="field-label">Title</span><input name="title" required placeholder="Internal product flaw" /></label>
      </div>
      <label class="field"><span class="field-label">Description</span><textarea name="description" required rows="4" placeholder="Evidence-first vulnerability description"></textarea></label>
      <div class="field-grid two">
        <label class="field"><span class="field-label">Severity</span><select name="severity">${renderOptions(SEVERITIES.filter((item) => item !== "all"), "medium")}</select></label>
        <label class="field"><span class="field-label">Status</span><select name="status">${renderOptions(STATUSES.filter((item) => item !== "all"), "draft")}</select></label>
        <label class="field"><span class="field-label">CVSS</span><input name="cvss_score" type="number" min="0" max="10" step="0.1" placeholder="7.4" /></label>
        <label class="field"><span class="field-label">CWE IDs</span><input name="cwe_ids" placeholder="CWE-79, CWE-287" /></label>
      </div>
      <label class="field"><span class="field-label">Affected Products</span><input name="affected_products" placeholder="Product, component, version" /></label>
      <label class="field"><span class="field-label">Linked Nuclei Template Ref</span><input name="linked_nuclei_template_ref" placeholder="pack-artifact://uuid" /></label>
      <button class="action primary" type="submit" ${state.customVulnSaving ? "disabled" : ""}>Save Definition</button>
    </form>
  `;
}

function renderImportExportPanel() {
  const result = state.customVulnImportResult;
  return `
    <div class="panel-head">
      <div>
        <p class="eyebrow">Import / Export</p>
        <h3>Structured Intake</h3>
      </div>
      <button class="action ghost" type="button" data-custom-vuln-export ${state.customVulnSaving ? "disabled" : ""}>Export JSON</button>
    </div>
    <form class="stack-form custom-vuln-form" data-custom-vuln-import-form data-testid="custom-vulnerability-import-form">
      <div class="field-grid two">
        <label class="field"><span class="field-label">Format</span><select name="format">${IMPORT_FORMATS.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("")}</select></label>
        <label class="field"><span class="field-label">Default Status</span><select name="default_status">${renderOptions(STATUSES.filter((item) => item !== "all"), "draft")}</select></label>
      </div>
      <label class="field"><span class="field-label">Payload</span><textarea name="payload" rows="8" placeholder="Paste NVD JSON, CSAF, export JSON, or plain text"></textarea></label>
      <label class="settings-checkline">
        <input type="checkbox" name="use_ai" ${state.selectedEngagementId ? "" : "disabled"} />
        <span>Use connected ChatGPT OAuth to structure plain text metadata</span>
      </label>
      <button class="action secondary" type="submit" ${state.customVulnSaving ? "disabled" : ""}>Import Definitions</button>
    </form>
    ${
      result
        ? `<div class="detail-surface split-top"><p class="eyebrow">Last Import</p><p>${escapeHtml(`${result.imported_count} imported · ${result.updated_count} updated · ${result.skipped_count} skipped`)}</p><p>${escapeHtml(result.ai_assistance?.status || "AI not requested")}</p></div>`
        : ""
    }
    ${
      state.customVulnExport
        ? `<pre class="report-preview split-top custom-vuln-export" data-testid="custom-vulnerability-export">${escapeHtml(state.customVulnExport)}</pre>`
        : ""
    }
  `;
}

function renderOptions(options, selected) {
  return options
    .map((option) => `<option value="${escapeHtml(option)}" ${option === selected ? "selected" : ""}>${escapeHtml(labelFor(option))}</option>`)
    .join("");
}

function splitList(value) {
  return String(value || "")
    .split(/[,;\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function valueOrNull(value) {
  const normalized = stringValue(value);
  return normalized ? normalized : null;
}

function labelFor(value) {
  return value === "all" ? "All" : String(value || "").replaceAll("_", " ");
}
