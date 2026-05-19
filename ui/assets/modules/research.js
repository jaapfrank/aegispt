import { api } from "./api.js";
import { dom, patchState, runtime, state } from "./runtime.js";
import { emptyState, escapeHtml, formatDateTime, statusPill } from "./shared.js";

const RESULT_STATUS_TONES = {
  generated: "warning",
  already_exists: "warning",
  blocked: "danger",
  unavailable: "danger",
};

export function createResearchModule() {
  let eventsBound = false;

  function bindEvents() {
    if (eventsBound) return;
    eventsBound = true;

    document.body.addEventListener("click", (event) => {
      const target = event.target.closest("[data-research-generate-cve]");
      if (!target) return;
      event.preventDefault();
      generateCveTemplate(target.dataset.researchGenerateCve).catch(runtime.actions.handleError);
    });

    document.body.addEventListener("click", (event) => {
      const target = event.target.closest("[data-research-open-pack]");
      if (!target) return;
      event.preventDefault();
      patchState({ selectedPackId: target.dataset.researchOpenPack || null }, "research.openPack");
      Promise.resolve(runtime.actions.loadSelectedPack?.())
        .catch(runtime.actions.handleError || (() => {}))
        .finally(() => runtime.actions.navigateToScreen?.("pack-forge"));
    });

    document.body.addEventListener("submit", (event) => {
      const form = event.target.closest("[data-research-idea-form]");
      if (!form) return;
      event.preventDefault();
      generateCustomIdea(new FormData(form)).catch(runtime.actions.handleError);
    });
  }

  async function fetchResearchLab() {
    if (!state.selectedEngagementId) return null;
    const params = new URLSearchParams({ engagement_id: state.selectedEngagementId });
    return api(`/api/v1/ai/research?${params.toString()}`);
  }

  async function loadResearchLab() {
    if (!state.selectedEngagementId) {
      patchState(
        { researchLab: null, researchLoading: false, researchError: null },
        "research.load.noEngagement"
      );
      renderResearchLab();
      return null;
    }
    patchState({ researchLoading: true, researchError: null }, "research.load.start");
    renderResearchLab();
    try {
      const lab = await fetchResearchLab();
      patchState({ researchLab: lab, researchLoading: false, researchError: null }, "research.load.complete");
      renderResearchLab();
      return lab;
    } catch (error) {
      patchState(
        { researchLoading: false, researchError: String(error?.message || error) },
        "research.load.error"
      );
      renderResearchLab();
      throw error;
    }
  }

  async function generateCveTemplate(recordId) {
    if (!recordId || !state.selectedEngagementId) return;
    patchState(
      {
        researchCveGeneratingId: recordId,
        researchGenerationResult: null,
        researchError: null,
      },
      "research.cve.generate.start"
    );
    renderResearchLab();
    try {
      const result = await api(`/api/v1/threat-intel/${encodeURIComponent(recordId)}/generate-template`, {
        method: "POST",
        body: { engagement_id: state.selectedEngagementId },
      });
      const lab = await fetchResearchLab();
      patchState(
        {
          researchCveGeneratingId: null,
          researchGenerationResult: result,
          researchLab: lab,
        },
        "research.cve.generate.complete"
      );
      runtime.actions.pushStatus?.(
        result.status === "generated"
          ? "Generated CVE template staged in Pack Forge."
          : result.message || "CVE template generation did not stage a pack.",
        result.status === "generated" ? "info" : "warning"
      );
    } catch (error) {
      patchState(
        {
          researchCveGeneratingId: null,
          researchError: String(error?.message || error),
        },
        "research.cve.generate.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderResearchLab();
  }

  async function generateCustomIdea(formData) {
    if (!state.selectedEngagementId) return;
    const description = stringValue(formData.get("description"));
    const outputKind = stringValue(formData.get("output_kind")) || "nuclei_yaml";
    if (!description) {
      patchState({ researchError: "Describe the detection idea before generation." }, "research.idea.empty");
      renderResearchLab();
      return;
    }
    patchState(
      { researchIdeaGenerating: true, researchGenerationResult: null, researchError: null },
      "research.idea.generate.start"
    );
    renderResearchLab();
    try {
      const result = await api("/api/v1/ai/research/generate-script", {
        method: "POST",
        body: {
          engagement_id: state.selectedEngagementId,
          description,
          output_kind: outputKind,
        },
      });
      const lab = await fetchResearchLab();
      patchState(
        {
          researchIdeaGenerating: false,
          researchGenerationResult: result,
          researchLab: lab,
        },
        "research.idea.generate.complete"
      );
      runtime.actions.pushStatus?.(
        result.status === "generated"
          ? "Generated research template staged in Pack Forge."
          : result.message || "Research idea returned a safe blocked state.",
        result.status === "generated" ? "info" : "warning"
      );
    } catch (error) {
      patchState(
        { researchIdeaGenerating: false, researchError: String(error?.message || error) },
        "research.idea.generate.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderResearchLab();
  }

  function renderResearchLab() {
    if (!dom.researchContent) return;
    bindEvents();
    if (!state.selectedEngagementId) {
      dom.researchContent.innerHTML = `
        <article class="panel" data-testid="research-empty-state">
          ${emptyState("Select an engagement before staging AI-generated research templates.", {
            label: "Open Intake",
            screen: "wizard",
          })}
        </article>
      `;
      return;
    }
    if (state.researchLoading && !state.researchLab) {
      dom.researchContent.innerHTML = `
        <article class="panel" data-testid="research-loading">
          <p class="eyebrow">Research</p>
          <h3>Loading research workspace...</h3>
        </article>
      `;
      return;
    }
    const lab = state.researchLab || {};
    const cveRecords = Array.isArray(lab.cve_records) ? lab.cve_records : [];
    const proposals = Array.isArray(lab.research_proposals) ? lab.research_proposals : [];
    dom.researchContent.innerHTML = `
      <section class="research-command-strip" data-testid="research-command-strip">
        <div>
          <p class="eyebrow">Build Lane</p>
          <h3>AI Research Lab</h3>
          <p>Stage detection-only templates from local CVE intelligence and operator research ideas through Pack Forge review.</p>
        </div>
        <div class="agents-metrics">
          <span class="metric-pill">${escapeHtml(`${cveRecords.length} CVE records`)}</span>
          <span class="metric-pill">${escapeHtml(`${proposals.length} proposals`)}</span>
          <span class="metric-pill">approval gated</span>
        </div>
      </section>
      ${state.researchError ? `<article class="settings-result-card danger" data-testid="research-error">${escapeHtml(state.researchError)}</article>` : ""}
      <div class="research-grid">
        <article class="panel research-cve-panel" data-testid="research-cve-generator">
          <div class="panel-head">
            <div>
              <p class="eyebrow">CVE -> Template</p>
              <h3>CVE Template Generator</h3>
            </div>
          </div>
          ${renderCveRecords(cveRecords)}
        </article>
        <article class="panel research-idea-panel" data-testid="research-custom-ideas">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Custom Ideas</p>
              <h3>Detection Script Ideas</h3>
            </div>
          </div>
          ${renderCustomIdeaForm()}
        </article>
        <article class="panel research-proposals-panel" data-testid="research-proposals-log">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Review Queue</p>
              <h3>Research Proposals</h3>
            </div>
          </div>
          ${renderProposalLog(proposals)}
        </article>
      </div>
      ${state.researchGenerationResult ? renderGenerationResult(state.researchGenerationResult) : ""}
    `;
  }

  function renderCveRecords(records) {
    if (!records.length) {
      return `<div class="cicd-history-empty">No local CVE records are available yet. Sync or ingest threat intelligence before generating templates.</div>`;
    }
    return `
      <div class="research-list">
        ${records.slice(0, 10).map((record) => renderCveRecord(record)).join("")}
      </div>
    `;
  }

  function renderCveRecord(record) {
    const generated = generatedTemplateForRecord(record);
    const isGenerating = state.researchCveGeneratingId === record.id;
    const canGenerate = state.selectedEngagementId && !generated?.pack_id && !isGenerating;
    return `
      <article class="research-row" data-testid="research-cve-row">
        <span class="status-dot status-${escapeHtml(generated?.status || "suggested")}"></span>
        <div class="research-row-main">
          <strong>${escapeHtml(record.advisory_id || "CVE record")}</strong>
          <p>${escapeHtml(record.title || "No title recorded.")}</p>
          <div class="chip-row compact">
            <span class="status-chip neutral">${escapeHtml(record.severity || "severity n/a")}</span>
            <span class="status-chip neutral">${escapeHtml((record.affected_products_json || []).slice(0, 2).join(", ") || "product n/a")}</span>
            <span class="status-chip ${generated?.pack_id ? "warning" : "neutral"}">${escapeHtml(generated?.status || "not generated")}</span>
          </div>
        </div>
        <div class="research-row-actions">
          ${
            generated?.pack_id
              ? `<button class="action secondary compact-action" type="button" data-research-open-pack="${escapeHtml(generated.pack_id)}">Review</button>`
              : `<button class="action primary compact-action" type="button" data-research-generate-cve="${escapeHtml(record.id)}" ${canGenerate ? "" : "disabled"}>${escapeHtml(isGenerating ? "Generating..." : "Generate")}</button>`
          }
        </div>
      </article>
    `;
  }

  function renderCustomIdeaForm() {
    return `
      <form class="stack-form research-idea-form" data-research-idea-form>
        <label>
          <span>Detection idea</span>
          <textarea name="description" rows="7" data-testid="research-idea-description" placeholder="Check if MQTT broker allows anonymous subscribe on port 1883"></textarea>
        </label>
        <label>
          <span>Output</span>
          <select name="output_kind" data-testid="research-output-kind">
            <option value="nuclei_yaml">Nuclei YAML</option>
            <option value="python_detection">Python detection script</option>
          </select>
        </label>
        <button class="action primary" type="submit" data-testid="research-generate-idea" ${state.researchIdeaGenerating ? "disabled" : ""}>
          ${escapeHtml(state.researchIdeaGenerating ? "Generating..." : "Generate Research Idea")}
        </button>
      </form>
    `;
  }

  function renderProposalLog(proposals) {
    if (!proposals.length) {
      return `<div class="cicd-history-empty">No generated research proposals are staged for this engagement yet.</div>`;
    }
    return `
      <div class="research-list">
        ${proposals.map((proposal) => renderProposal(proposal)).join("")}
      </div>
    `;
  }

  function renderProposal(proposal) {
    return `
      <article class="research-proposal-row" data-testid="research-proposal-row">
        <div class="research-proposal-head">
          <div>
            <strong>${escapeHtml(proposal.title || "Research proposal")}</strong>
            <p>${escapeHtml(proposal.description || proposal.detection_strategy || "Generated detection output requires review.")}</p>
          </div>
          ${statusPill(proposal.status || proposal.pack_status || "staged")}
        </div>
        <div class="chip-row compact">
          <span class="status-chip neutral">${escapeHtml(proposal.source || "research")}</span>
          <span class="status-chip neutral">${escapeHtml(proposal.output_kind || "nuclei_yaml")}</span>
          <span class="status-chip neutral">${escapeHtml(proposal.model || "model n/a")}</span>
        </div>
        ${proposal.reasoning ? `<p>${escapeHtml(proposal.reasoning)}</p>` : ""}
        ${proposal.safety_notes?.length ? `<p class="micro-copy">${escapeHtml(proposal.safety_notes.join(" | "))}</p>` : ""}
        <div class="panel-actions">
          <button class="action secondary compact-action" type="button" data-research-open-pack="${escapeHtml(proposal.pack_id)}">Review in Pack Forge</button>
          <span class="micro-copy">${escapeHtml(formatDateTime(proposal.updated_at || proposal.created_at))}</span>
        </div>
      </article>
    `;
  }

  function renderGenerationResult(result) {
    const tone = RESULT_STATUS_TONES[result.status] || "neutral";
    const generated = result.generated_template || {};
    return `
      <article class="panel research-result" data-testid="research-generation-result">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Generated Output</p>
            <h3>${escapeHtml(result.status === "generated" ? "Template staged for review" : "Generation status")}</h3>
          </div>
          <span class="status-chip ${escapeHtml(tone)}">${escapeHtml(result.status || "unknown")}</span>
        </div>
        <p>${escapeHtml(result.message || result.lifecycle_note || "Review required before runtime use.")}</p>
        ${renderSafetySummary(result.validation || {})}
        <div class="panel-actions">
          ${
            result.pack_id || generated.pack_id
              ? `<button class="action secondary compact-action" type="button" data-research-open-pack="${escapeHtml(result.pack_id || generated.pack_id)}">Review in Pack Forge</button>`
              : ""
          }
        </div>
        ${
          result.yaml_diff
            ? `<pre class="research-yaml-diff">${escapeHtml(result.yaml_diff).slice(0, 3600)}</pre>`
            : result.template_yaml
              ? `<pre class="research-yaml-diff">${escapeHtml(result.template_yaml).slice(0, 3600)}</pre>`
              : ""
        }
      </article>
    `;
  }

  function renderSafetySummary(validation) {
    if (!validation || !Object.keys(validation).length) return "";
    const items = [
      validation.schema,
      validation.detection_only === true ? "detection only" : null,
      validation.auto_deploy === false ? "no auto deploy" : null,
      validation.operator_review_required === true ? "operator review" : null,
      validation.matcher_count !== undefined ? `${validation.matcher_count} matchers` : null,
      Array.isArray(validation.allowed_methods) ? `methods ${validation.allowed_methods.join("/")}` : null,
      validation.blocked ? "blocked" : null,
    ].filter(Boolean);
    return `<div class="chip-row compact" data-testid="research-safety-summary">${items.map((item) => `<span class="status-chip neutral">${escapeHtml(item)}</span>`).join("")}</div>`;
  }

  bindEvents();
  return { loadResearchLab, renderResearchLab, generateCveTemplate, generateCustomIdea };
}

function generatedTemplateForRecord(record) {
  const generated = record?.metadata_json?.generated_nuclei_template;
  return generated && typeof generated === "object" ? generated : null;
}

function stringValue(value) {
  return String(value || "").trim();
}
