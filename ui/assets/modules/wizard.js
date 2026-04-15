import {
  ASSESSMENT_TYPES,
  DEFAULT_MODULE_STATE,
  DEFAULT_SAFETY,
  MODULES,
  TEST_PROFILES,
  WIZARD_STEPS,
} from "./constants.js";
import { api } from "./api.js";
import { buildEmptyAccount, buildEmptyWizardState, dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  enabledModules,
  escapeHtml,
  flattenTargetValues,
  hasMeaningfulAccount,
  isLikelyCidr,
  isLikelyDomain,
  isLikelyIp,
  isLikelyUrl,
  numberValue,
  readinessSummary,
  renderAccountSummary,
  renderTargetSummary,
  requiresCredentials,
  splitComma,
  splitLines,
  stringValue,
  textareaField,
  valueOrNull,
} from "./shared.js";

export function createWizardModule() {
  function renderWizard() {
    const wizard = state.wizard;
    const estimate = estimateMission(wizard.data);
    dom.wizardStepper.innerHTML = WIZARD_STEPS.map((label, index) => `
        <div class="wizard-step ${index === wizard.step ? "active" : ""} ${index < wizard.step ? "complete" : ""}" data-testid="wizard-step-${index + 1}">
          <small>Step ${index + 1}</small>
          <strong>${escapeHtml(label)}</strong>
        </div>
      `).join("");

    const lead = wizardStepLead(wizard.step);
    dom.wizardPanel.innerHTML = `
      <div class="section-note">
        <strong>${escapeHtml(lead.title)}</strong>
        <p>${escapeHtml(lead.body)}</p>
      </div>
      ${wizardStepContent(wizard.step, wizard.data, wizard.useExistingEngagement)}
    `;
    dom.wizardErrors.innerHTML = wizard.errors.length
      ? wizard.errors.map((error) => `<div>${escapeHtml(error)}</div>`).join("")
      : "";
    dom.wizardSummary.innerHTML = renderWizardSummary(wizard, estimate);
    dom.wizardBackBtn.disabled = wizard.step === 0 || wizard.submitting;
    dom.wizardNextBtn.classList.toggle("hidden", wizard.step === WIZARD_STEPS.length - 1);
    dom.wizardConfirmBtn.classList.toggle("hidden", wizard.step !== WIZARD_STEPS.length - 1);
    dom.wizardConfirmBtn.disabled = wizard.submitting;
    dom.wizardNextBtn.disabled = wizard.submitting;
    dom.wizardBackBtn.disabled = wizard.step === 0 || wizard.submitting;
    dom.wizardBackBtn.textContent = wizard.submitting ? "Locked" : "Back";
    dom.wizardNextBtn.textContent = wizard.submitting ? "Saving..." : "Next";
    dom.wizardConfirmBtn.textContent = wizard.submitting ? "Creating Mission..." : "Confirm Mission";

    attachWizardHandlers();
  }

  function wizardStepContent(step, data, useExistingEngagement) {
    if (step === 0) {
      const selectedEngagement = runtime.actions.selectedEngagement?.();
      return `
        <div class="wizard-panel-grid">
          <div class="stack-form">
            <label class="field">
              <span>Mission Mode</span>
              <div class="option-card">
                <input id="wizard-use-existing" data-testid="wizard-use-existing" type="checkbox" ${useExistingEngagement ? "checked" : ""} ${state.engagements.length ? "" : "disabled"} />
                <div>
                  <strong>Use the selected engagement dossier</strong>
                  <p class="micro-copy">Reuse the engagement selected in the rail and create a new run under it.</p>
                </div>
              </div>
            </label>
            ${useExistingEngagement ? `
              <div class="detail-surface">
                <h4>Selected Engagement</h4>
                <p>${escapeHtml(selectedEngagement?.name || "No engagement selected")}</p>
                <p class="micro-copy">${escapeHtml(selectedEngagement?.client || "Client not set")}</p>
              </div>
            ` : `
              <label class="field">
                <span>Engagement Name</span>
                <input id="wizard-engagement-name" data-testid="wizard-engagement-name" type="text" value="${escapeHtml(data.engagement_name)}" placeholder="Acme External Validation" />
              </label>
              <label class="field">
                <span>Customer</span>
                <input id="wizard-client" data-testid="wizard-client" type="text" value="${escapeHtml(data.client)}" placeholder="Acme Corp" />
              </label>
              <label class="field">
                <span>ROE Reference</span>
                <input id="wizard-roe-ref" data-testid="wizard-roe-ref" type="text" value="${escapeHtml(data.roe_ref)}" placeholder="ROE-2026-200" />
              </label>
            `}
          </div>
          <div class="stack-form">
            <span class="inline-label">Assessment Type</span>
            <div class="toggle-grid">
              ${ASSESSMENT_TYPES.map((type) => `
                <label class="option-card">
                  <input type="radio" name="wizard-assessment-type" value="${escapeHtml(type)}" ${data.assessment_type === type ? "checked" : ""} />
                  <div>
                    <strong>${escapeHtml(type)}</strong>
                    <p class="micro-copy">${escapeHtml(assessmentTypeCopy(type))}</p>
                  </div>
                </label>
              `).join("")}
            </div>
          </div>
        </div>
      `;
    }

    if (step === 1) {
      const visibleGroups = visibleTargetGroups(data.assessment_type);
      return `
        <div class="wizard-panel-grid">
          ${visibleGroups.includes("domains") ? textareaField("wizard-target-domains", "Domains", data.targets.domains, "example.com\nshop.example.com") : ""}
          ${visibleGroups.includes("subdomains") ? textareaField("wizard-target-subdomains", "Subdomains", data.targets.subdomains, "api.example.com\nadmin.example.com") : ""}
          ${visibleGroups.includes("urls") ? textareaField("wizard-target-urls", "URLs", data.targets.urls, "https://example.com\nhttps://example.com/login") : ""}
          ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-target-ip-addresses", "IP Addresses", data.targets.ip_addresses, "203.0.113.5\n203.0.113.8") : ""}
          ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-target-cidrs", "CIDR Ranges", data.targets.cidr_ranges, "10.10.0.0/24") : ""}
          ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-target-api", "API Base URLs", data.targets.api_base_urls, "https://api.example.com/v1") : ""}
        </div>
      `;
    }

    if (step === 2) {
      return `
        <div class="stack-zone">
          ${data.access.accounts.map((account, index) => `
            <div class="account-card" data-account-card="${index}">
              <div class="panel-head">
                <div>
                  <p class="eyebrow">Account ${index + 1}</p>
                  <h4>${escapeHtml(account.label || `Account ${index + 1}`)}</h4>
                </div>
                <button class="action ghost wizard-remove-account-btn" type="button" data-account-remove="${index}" ${data.access.accounts.length === 1 ? "disabled" : ""}>Remove</button>
              </div>
              <div class="wizard-panel-grid">
                <label class="field">
                  <span>Label</span>
                  <input data-account-field="label" data-account-index="${index}" type="text" value="${escapeHtml(account.label)}" placeholder="Primary User" />
                </label>
                <label class="field">
                  <span>Username</span>
                  <input data-account-field="username" data-account-index="${index}" type="text" value="${escapeHtml(account.username)}" placeholder="tester@example.com" />
                </label>
                <label class="field">
                  <span>Role</span>
                  <input data-account-field="role" data-account-index="${index}" type="text" value="${escapeHtml(account.role)}" placeholder="Admin" />
                </label>
                <label class="field">
                  <span>Password / Secret Reference</span>
                  <input data-account-field="secret_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.secret_ref)}" placeholder="vault://prod/app/admin or direct secret" />
                </label>
                <label class="field">
                  <span>API Key Reference or Value</span>
                  <input data-account-field="api_key_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.api_key_ref)}" placeholder="vault://prod/api/key or direct key" />
                </label>
                <label class="field">
                  <span>Bearer Token Reference or Value</span>
                  <input data-account-field="bearer_token_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.bearer_token_ref)}" placeholder="vault://prod/api/bearer or direct token" />
                </label>
                <label class="field">
                  <span>Cookie / Session Reference or Material</span>
                  <input data-account-field="session_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.session_ref)}" placeholder="session-bundle-A or direct cookie material" />
                </label>
                <label class="field">
                  <span>MFA Notes / Manual Auth Steps</span>
                  <textarea data-account-field="mfa_notes" data-account-index="${index}" rows="3" placeholder="Manual OTP or SSO handoff notes">${escapeHtml(account.mfa_notes)}</textarea>
                </label>
              </div>
            </div>
          `).join("")}
          <div class="action-row">
            <button id="wizard-add-account-btn" class="action ghost" type="button">Add Account / Role</button>
          </div>
          <label class="field">
            <span>Shared Manual Auth Steps</span>
            <textarea id="wizard-manual-auth-steps" rows="3" placeholder="Manual login, device trust, or MFA sequencing">${escapeHtml(data.access.manual_auth_steps)}</textarea>
          </label>
          <label class="field">
            <span>Cookie / Session Notes</span>
            <textarea id="wizard-cookie-notes" rows="3" placeholder="Session capture notes or cookie replay guidance">${escapeHtml(data.access.cookie_notes)}</textarea>
          </label>
        </div>
      `;
    }

    if (step === 3) {
      return `
        <div class="toggle-grid">
          ${TEST_PROFILES.map((profile) => `
            <label class="option-card">
              <input type="radio" name="wizard-test-profile" value="${escapeHtml(profile)}" ${data.test_profile === profile ? "checked" : ""} />
              <div>
                <strong>${escapeHtml(profile)}</strong>
                <p class="micro-copy">${escapeHtml(testProfileCopy(profile))}</p>
              </div>
            </label>
          `).join("")}
        </div>
      `;
    }

    if (step === 4) {
      return `
        <div class="toggle-grid">
          ${MODULES.map(([key, label]) => `
            <label class="toggle-card">
              <input type="checkbox" data-module-key="${key}" ${data.modules[key] ? "checked" : ""} />
              <div>
                <strong>${escapeHtml(label)}</strong>
                <p class="micro-copy">${escapeHtml(moduleCopy(key))}</p>
              </div>
            </label>
          `).join("")}
        </div>
      `;
    }

    if (step === 5) {
      return `
        <div class="wizard-panel-grid">
          <label class="field">
            <span>Rate Limit (requests / second)</span>
            <input id="wizard-rate-limit" type="number" min="1" max="20" value="${escapeHtml(String(data.safety.rate_limit_rps))}" />
          </label>
          <label class="field">
            <span>Concurrency</span>
            <input id="wizard-concurrency" type="number" min="1" max="10" value="${escapeHtml(String(data.safety.concurrency))}" />
          </label>
          <label class="field">
            <span>Time Budget (minutes)</span>
            <input id="wizard-time-budget" type="number" min="15" max="1440" value="${escapeHtml(String(data.safety.time_budget_minutes))}" />
          </label>
          <label class="field">
            <span>Active Checks</span>
            <select id="wizard-active-checks">
              ${["passive-only", "guarded", "active"].map((mode) => `<option value="${mode}" ${data.safety.active_checks === mode ? "selected" : ""}>${escapeHtml(mode)}</option>`).join("")}
            </select>
          </label>
          <label class="field">
            <span>Adaptive Generation</span>
            <select id="wizard-adaptive-generation">
              <option value="true" ${data.safety.adaptive_generation ? "selected" : ""}>Enabled</option>
              <option value="false" ${!data.safety.adaptive_generation ? "selected" : ""}>Disabled</option>
            </select>
          </label>
          <label class="field">
            <span>Maximum Validation Depth</span>
            <select id="wizard-max-depth">
              ${["light", "standard", "deep"].map((value) => `<option value="${value}" ${data.safety.max_validation_depth === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
            </select>
          </label>
        </div>
      `;
    }

    const estimate = estimateMission(data);
    return `
      <div class="stack-zone" data-testid="wizard-review">
        <div class="detail-surface">
          <h4>Mission Review</h4>
          <p>${escapeHtml(data.assessment_type)} with the ${escapeHtml(data.test_profile)} operator profile will use the ${escapeHtml(estimate.execution_profile)} execution lane.</p>
          <p>${escapeHtml(estimate.summary)}</p>
        </div>
        <div class="wizard-panel-grid">
          <div class="detail-surface">
            <h4>Targets</h4>
            <p>${renderTargetSummary(data.targets)}</p>
          </div>
          <div class="detail-surface">
            <h4>Access</h4>
            <p>${escapeHtml(renderAccountSummary(data.access.accounts))}</p>
          </div>
          <div class="detail-surface">
            <h4>Modules</h4>
            <p>${escapeHtml(enabledModules(data.modules).join(", ") || "None")}</p>
          </div>
          <div class="detail-surface">
            <h4>Safety</h4>
            <p>${escapeHtml(`RPS ${data.safety.rate_limit_rps}, concurrency ${data.safety.concurrency}, budget ${data.safety.time_budget_minutes}m, checks ${data.safety.active_checks}`)}</p>
          </div>
        </div>
        <div class="detail-surface">
          <h4>Confirmation</h4>
          <p>Confirming creates or reuses the engagement, stores the wizard configuration on the run record, seeds the inventory model from the reviewed scope, and opens Mission Control.</p>
        </div>
      </div>
    `;
  }

  function renderWizardSummary(wizard, estimate) {
    return `
      ${wizard.lastCreated ? `
        <div class="list-card">
          <h4>Last Mission Created</h4>
          <p>${escapeHtml(wizard.lastCreated.engagementName)}</p>
          <p class="micro-copy">Run ${escapeHtml(wizard.lastCreated.runId)}</p>
        </div>
      ` : ""}
      <div class="list-card">
        <h4>Assessment</h4>
        <p>${escapeHtml(wizard.data.assessment_type)}</p>
        <p class="micro-copy">${escapeHtml(estimate.execution_profile)} execution lane</p>
      </div>
      <div class="list-card">
        <h4>Readiness</h4>
        <p>${escapeHtml(readinessSummary(wizard.data))}</p>
        <p class="micro-copy">${escapeHtml(wizard.step === WIZARD_STEPS.length - 1 ? "Review this summary before the mission record is created." : "Each step updates the future mission record in place.")}</p>
      </div>
      <div class="list-card">
        <h4>Targets</h4>
        <p>${renderTargetSummary(wizard.data.targets)}</p>
      </div>
      <div class="list-card">
        <h4>Access</h4>
        <p>${escapeHtml(renderAccountSummary(wizard.data.access.accounts))}</p>
      </div>
      <div class="list-card">
        <h4>Modules</h4>
        <p>${escapeHtml(enabledModules(wizard.data.modules).join(", ") || "No modules enabled")}</p>
      </div>
      <div class="list-card">
        <h4>Safety</h4>
        <p>${escapeHtml(`RPS ${wizard.data.safety.rate_limit_rps}, concurrency ${wizard.data.safety.concurrency}, budget ${wizard.data.safety.time_budget_minutes}m`)}</p>
        <p class="micro-copy">${escapeHtml(`${wizard.data.safety.active_checks} checks · depth ${wizard.data.safety.max_validation_depth}`)}</p>
      </div>
      <div class="list-card">
        <h4>ETA Model</h4>
        <p>${escapeHtml(`${estimate.estimated_total_minutes} minutes estimated`)}</p>
        <p class="micro-copy">${escapeHtml(`${estimate.estimated_impact} impact · ${estimate.confidence} confidence`)}</p>
      </div>
    `;
  }

  function attachWizardHandlers() {
    dom.wizardPanel.querySelectorAll("input, textarea, select").forEach((element) => {
      element.addEventListener("input", onWizardInput);
      element.addEventListener("change", onWizardInput);
    });

    const addAccountButton = document.getElementById("wizard-add-account-btn");
    if (addAccountButton) {
      addAccountButton.addEventListener("click", () => {
        syncWizardStepFromDom();
        state.wizard.data.access.accounts.push(buildEmptyAccount());
        renderWizard();
      });
    }

    dom.wizardPanel.querySelectorAll(".wizard-remove-account-btn").forEach((button) => {
      button.addEventListener("click", () => {
        syncWizardStepFromDom();
        const index = Number(button.dataset.accountRemove);
        state.wizard.data.access.accounts.splice(index, 1);
        renderWizard();
      });
    });
  }

  function onWizardInput(event) {
    if (state.wizard.step === 3 && event.target.name === "wizard-test-profile") {
      syncWizardStepFromDom();
      applyProfilePreset(state.wizard.data.test_profile);
      renderWizard();
      return;
    }
    syncWizardStepFromDom();
    if (
      (state.wizard.step === 0 && (event.target.id === "wizard-use-existing" || event.target.name === "wizard-assessment-type")) ||
      (state.wizard.step === 2 && event.target.dataset.accountField === "label")
    ) {
      renderWizard();
    } else {
      dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data));
    }
  }

  function syncWizardStepFromDom() {
    const wizard = state.wizard;
    const data = wizard.data;
    if (wizard.step === 0) {
      const useExisting = document.getElementById("wizard-use-existing");
      wizard.useExistingEngagement = Boolean(useExisting?.checked);
      data.engagement_name = stringValue(document.getElementById("wizard-engagement-name")?.value);
      data.client = stringValue(document.getElementById("wizard-client")?.value);
      data.roe_ref = stringValue(document.getElementById("wizard-roe-ref")?.value);
      data.assessment_type =
        document.querySelector('input[name="wizard-assessment-type"]:checked')?.value || data.assessment_type;
      return;
    }
    if (wizard.step === 1) {
      data.targets = {
        domains: splitLines(document.getElementById("wizard-target-domains")?.value),
        subdomains: splitLines(document.getElementById("wizard-target-subdomains")?.value),
        urls: splitLines(document.getElementById("wizard-target-urls")?.value),
        ip_addresses: splitLines(document.getElementById("wizard-target-ip-addresses")?.value),
        cidr_ranges: splitLines(document.getElementById("wizard-target-cidrs")?.value),
        api_base_urls: splitLines(document.getElementById("wizard-target-api")?.value),
      };
      return;
    }
    if (wizard.step === 2) {
      const accounts = Array.from(dom.wizardPanel.querySelectorAll("[data-account-card]")).map((card) => {
        const index = Number(card.dataset.accountCard);
        return {
          label: stringValue(card.querySelector('[data-account-field="label"]')?.value),
          username: stringValue(card.querySelector('[data-account-field="username"]')?.value),
          role: stringValue(card.querySelector('[data-account-field="role"]')?.value),
          secret_ref: stringValue(card.querySelector('[data-account-field="secret_ref"]')?.value),
          api_key_ref: stringValue(card.querySelector('[data-account-field="api_key_ref"]')?.value),
          bearer_token_ref: stringValue(card.querySelector('[data-account-field="bearer_token_ref"]')?.value),
          session_ref: stringValue(card.querySelector('[data-account-field="session_ref"]')?.value),
          mfa_notes: stringValue(card.querySelector('[data-account-field="mfa_notes"]')?.value),
          _index: index,
        };
      }).sort((left, right) => left._index - right._index).map(({ _index, ...account }) => account);
      data.access.accounts = accounts.length ? accounts : [buildEmptyAccount()];
      data.access.manual_auth_steps = stringValue(document.getElementById("wizard-manual-auth-steps")?.value);
      data.access.cookie_notes = stringValue(document.getElementById("wizard-cookie-notes")?.value);
      return;
    }
    if (wizard.step === 3) {
      data.test_profile = document.querySelector('input[name="wizard-test-profile"]:checked')?.value || data.test_profile;
      return;
    }
    if (wizard.step === 4) {
      MODULES.forEach(([key]) => {
        data.modules[key] = Boolean(dom.wizardPanel.querySelector(`[data-module-key="${key}"]`)?.checked);
      });
      return;
    }
    if (wizard.step === 5) {
      data.safety.rate_limit_rps = numberValue(document.getElementById("wizard-rate-limit")?.value, DEFAULT_SAFETY.rate_limit_rps);
      data.safety.concurrency = numberValue(document.getElementById("wizard-concurrency")?.value, DEFAULT_SAFETY.concurrency);
      data.safety.time_budget_minutes = numberValue(document.getElementById("wizard-time-budget")?.value, DEFAULT_SAFETY.time_budget_minutes);
      data.safety.active_checks = document.getElementById("wizard-active-checks")?.value || DEFAULT_SAFETY.active_checks;
      data.safety.adaptive_generation = (document.getElementById("wizard-adaptive-generation")?.value || "true") === "true";
      data.safety.max_validation_depth = document.getElementById("wizard-max-depth")?.value || DEFAULT_SAFETY.max_validation_depth;
    }
  }

  function validateWizardStep(step) {
    const data = state.wizard.data;
    if (step === 0) {
      const errors = [];
      if (state.wizard.useExistingEngagement && !state.selectedEngagementId) {
        errors.push("Select an existing engagement or create a new one.");
      }
      if (!state.wizard.useExistingEngagement && !data.engagement_name.trim()) {
        errors.push("Enter an engagement name.");
      }
      if (!data.assessment_type) {
        errors.push("Choose an assessment type.");
      }
      return errors;
    }
    if (step === 1) {
      const targets = flattenTargetValues(data.targets);
      const errors = [];
      if (!targets.length) {
        errors.push("Add at least one target in scope.");
      }
      splitLines(document.getElementById("wizard-target-urls")?.value).forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid URL: ${value}`);
      });
      splitLines(document.getElementById("wizard-target-api")?.value).forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid API base URL: ${value}`);
      });
      splitLines(document.getElementById("wizard-target-ip-addresses")?.value).forEach((value) => {
        if (!isLikelyIp(value)) errors.push(`Invalid IP address: ${value}`);
      });
      splitLines(document.getElementById("wizard-target-cidrs")?.value).forEach((value) => {
        if (!isLikelyCidr(value)) errors.push(`Invalid CIDR range: ${value}`);
      });
      splitLines(document.getElementById("wizard-target-domains")?.value).forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid domain: ${value}`);
      });
      return [...new Set(errors)];
    }
    if (step === 2) {
      if (requiresCredentials(data) && !hasMeaningfulAccount(data.access.accounts)) {
        return ["This assessment profile needs at least one account, token reference, or session label."];
      }
      return [];
    }
    if (step === 3) {
      return data.test_profile ? [] : ["Choose a test profile."];
    }
    if (step === 4) {
      return enabledModules(data.modules).length ? [] : ["Enable at least one test module."];
    }
    if (step === 5) {
      const errors = [];
      if (data.safety.rate_limit_rps < 1) errors.push("Rate limit must be at least 1 request per second.");
      if (data.safety.concurrency < 1) errors.push("Concurrency must be at least 1.");
      if (data.safety.time_budget_minutes < 15) errors.push("Time budget must be at least 15 minutes.");
      return errors;
    }
    return validateEntireWizard();
  }

  function validateEntireWizard() {
    const allErrors = [];
    for (let step = 0; step < WIZARD_STEPS.length - 1; step += 1) {
      allErrors.push(...validateWizardStep(step));
    }
    return [...new Set(allErrors)];
  }

  async function submitWizard() {
    syncWizardStepFromDom();
    const errors = validateEntireWizard();
    if (errors.length) {
      state.wizard.errors = errors;
      renderWizard();
      return;
    }

    state.wizard.submitting = true;
    state.wizard.errors = [];
    runtime.actions.pushStatus?.("Creating mission dossier and run configuration.", "info");
    renderWizard();

    try {
      const estimate = estimateMission(state.wizard.data);
      const configuration = buildRunConfiguration(state.wizard.data, estimate);
      const engagement = state.wizard.useExistingEngagement
        ? runtime.actions.selectedEngagement?.()
        : await api("/api/v1/engagements", {
            method: "POST",
            body: {
              name: state.wizard.data.engagement_name,
              client: valueOrNull(state.wizard.data.client),
              roe_ref: valueOrNull(state.wizard.data.roe_ref),
            },
          });

      const scopePayload = {
        allowlist_json: buildAllowlistFromWizard(state.wizard.data.targets),
        denylist_json: {},
      };
      await api(`/api/v1/engagements/${engagement.id}/scope`, {
        method: "POST",
        body: scopePayload,
      });

      const inventorySnapshot = await api("/api/v1/inventory/runs", {
        method: "POST",
        body: buildInventorySeedPayload(engagement.id, state.wizard.data),
      });

      const run = await api(`/api/v1/engagements/${engagement.id}/runs`, {
        method: "POST",
        body: {
          profile_name: estimate.execution_profile,
          source_inventory_snapshot_id: inventorySnapshot.id,
          configuration_json: configuration,
        },
      });

      runtime.actions.pushStatus?.(
        `Mission ${engagement.name} created and bound to run ${run.id}.`,
        "success"
      );
      state.selectedEngagementId = engagement.id;
      state.selectedRunId = run.id;
      state.wizard = buildEmptyWizardState();
      state.wizard.lastCreated = {
        engagementName: engagement.name,
        runId: run.id,
      };
      state.activeScreen = "mission-control";
      await runtime.actions.refreshShell?.();
    } catch (error) {
      state.wizard.submitting = false;
      state.wizard.errors = [error.message || "Wizard submission failed."];
      renderWizard();
      throw error;
    }
  }

  return {
    renderWizard,
    syncWizardStepFromDom,
    validateWizardStep,
    submitWizard,
  };
}

export function buildRunConfiguration(data, estimate) {
  return {
    assessment_type: data.assessment_type,
    test_profile: data.test_profile,
    execution_profile: estimate.execution_profile,
    targets: data.targets,
    access: {
      accounts: data.access.accounts
        .filter((account) => hasMeaningfulAccount([account]))
        .map((account) => ({
          label: account.label,
          username: account.username,
          role: account.role,
          secret_ref: account.secret_ref || null,
          api_key_ref: account.api_key_ref || null,
          bearer_token_ref: account.bearer_token_ref || null,
          session_ref: account.session_ref || null,
          mfa_notes: account.mfa_notes || null,
        })),
      manual_auth_steps: valueOrNull(data.access.manual_auth_steps),
      cookie_notes: valueOrNull(data.access.cookie_notes),
    },
    modules: data.modules,
    safety: data.safety,
    eta: estimate,
  };
}

function buildAllowlistFromWizard(targets) {
  return {
    domains: [...targets.domains, ...targets.subdomains].filter(Boolean),
    urls: [...targets.urls, ...targets.api_base_urls].filter(Boolean),
    hosts: [...targets.ip_addresses].filter(Boolean),
    cidrs: [...targets.cidr_ranges].filter(Boolean),
  };
}

function buildInventorySeedPayload(engagementId, data) {
  const hosts = [...data.targets.domains, ...data.targets.subdomains, ...data.targets.ip_addresses];
  const urls = [...data.targets.urls, ...data.targets.api_base_urls];
  return {
    engagement_id: engagementId,
    source_tools: ["wizard-input"],
    observations: [
      {
        tool: "wizard-input",
        kind: "inventory-seed",
        data: {
          hosts,
          urls,
          endpoints: urls.map((url) => ({ url, methods: ["GET"], status_code: 200 })),
          auth_mechanisms: data.access.accounts.filter((account) => hasMeaningfulAccount([account])).map((account) => ({
            type: account.session_ref ? "session-context" : "credential-reference",
            location: account.role || null,
            confidence: 0.7,
          })),
          api_types: data.targets.api_base_urls.map((url) => ({ type: "rest", base_url: url, confidence: 0.7 })),
          tls: data.assessment_type === "SSL/TLS Only"
            ? { protocols: ["tls"], issues: [], confidence: 0.8 }
            : undefined,
          confidence: 0.72,
        },
      },
    ],
    environment_notes: [
      `Wizard seeded assessment type: ${data.assessment_type}`,
      `Wizard profile: ${data.test_profile}`,
    ],
    assumptions: [
      "Seed inventory was created from operator-reviewed wizard input before active discovery.",
      data.access.manual_auth_steps ? `Manual auth note: ${data.access.manual_auth_steps}` : "No shared manual auth note provided.",
    ],
  };
}

export function estimateMission(data) {
  const targetsCount = flattenTargetValues(data.targets).length;
  const moduleCount = enabledModules(data.modules).length;
  const accountCount = data.access.accounts.filter((account) => hasMeaningfulAccount([account])).length;
  const profileMultipliers = {
    "Light": 0.7,
    "Standard": 1,
    "Deep": 1.5,
    "External Surface Only": 0.85,
    "Authenticated Only": 1.15,
    "SSL/TLS Only": 0.65,
    "Internal Validation": 1.85,
    "Adaptive Customer-Specific Mode": 1.55,
  };
  const base = 24 + targetsCount * 9 + moduleCount * 4 + accountCount * 10 + (data.safety.adaptive_generation ? 14 : 0);
  const estimated_total_minutes = Math.round(base * (profileMultipliers[data.test_profile] || 1));
  const execution_profile = resolveExecutionProfile(data);
  const estimated_impact = data.safety.active_checks === "active" || data.test_profile === "Internal Validation"
    ? "high"
    : data.test_profile === "Deep" || data.test_profile === "Authenticated Only"
      ? "medium"
      : "low";
  const confidence = targetsCount >= 2 ? "medium" : "low";
  return {
    estimated_total_minutes,
    estimated_impact,
    confidence,
    execution_profile,
    summary: `Estimated duration ${estimated_total_minutes} minutes with ${estimated_impact} expected impact under ${execution_profile}.`,
  };
}

function resolveExecutionProfile(data) {
  if (data.test_profile === "Internal Validation") return "intrusive-validation";
  if (data.test_profile === "SSL/TLS Only") return "passive-web-baseline";
  if (data.test_profile === "Light" || data.test_profile === "External Surface Only") return "passive-web-baseline";
  if (data.test_profile === "Standard" && data.modules.nuclei_checks) return "passive-web-nuclei-audit";
  if (data.safety.active_checks === "active" && data.modules.zap_active_checks) return "active-web-zap-active";
  if (data.test_profile === "Deep" || data.test_profile === "Authenticated Only" || data.test_profile === "Adaptive Customer-Specific Mode") return "active-web-safe";
  return "passive-web-baseline";
}

function applyProfilePreset(profile) {
  const modules = state.wizard.data.modules;
  if (profile === "SSL/TLS Only") {
    Object.keys(modules).forEach((key) => { modules[key] = false; });
    modules.ssl_tls_analysis = true;
    state.wizard.data.safety.active_checks = "passive-only";
    state.wizard.data.safety.adaptive_generation = false;
    return;
  }
  if (profile === "External Surface Only") {
    Object.keys(modules).forEach((key) => { modules[key] = false; });
    modules.discovery = true;
    modules.web_crawling = true;
    modules.content_discovery = true;
    modules.nuclei_checks = true;
    modules.ssl_tls_analysis = true;
    return;
  }
  if (profile === "Authenticated Only") {
    modules.auth_flows = true;
    modules.business_logic_testing = true;
    modules.web_crawling = true;
    state.wizard.data.safety.active_checks = "guarded";
    return;
  }
  if (profile === "Internal Validation") {
    modules.internal_validation_modules = true;
    modules.auth_flows = true;
    modules.nuclei_checks = true;
    modules.zap_active_checks = true;
    state.wizard.data.safety.active_checks = "active";
    state.wizard.data.safety.adaptive_generation = false;
    return;
  }
  if (profile === "Adaptive Customer-Specific Mode") {
    modules.adaptive_ai_generated_tests = true;
    modules.nuclei_checks = true;
    modules.web_crawling = true;
    modules.auth_flows = true;
    state.wizard.data.safety.adaptive_generation = true;
    return;
  }
  Object.assign(state.wizard.data.modules, { ...DEFAULT_MODULE_STATE });
  Object.assign(state.wizard.data.safety, { ...DEFAULT_SAFETY });
}

function wizardStepLead(step) {
  const leads = [
    {
      title: "Choose the mission shape",
      body: "Set whether you are launching a new mission dossier or adding a new mission to an existing engagement, then choose the assessment type that best matches the target surface.",
    },
    {
      title: "Define exactly what is in scope",
      body: "Add only the targets that should enter inventory and validation. The wizard validates core formats before anything becomes part of the mission record.",
    },
    {
      title: "Record access context safely",
      body: "Store operator-facing references or direct secrets. Sensitive values are moved behind protected secret bindings when the run is created.",
    },
    {
      title: "Pick the right depth",
      body: "The test profile shapes execution safety, likely ETA, and how much adaptive testing or active validation the mission is allowed to perform.",
    },
    {
      title: "Enable only the modules that matter",
      body: "Turn on the validation lanes you actually want. The module set directly feeds run configuration, mission progress, ETA, and reporting coverage.",
    },
    {
      title: "Set guardrails before launch",
      body: "Tune rate, concurrency, validation depth, and active-check posture so the mission stays controlled and aligned with the rules of engagement.",
    },
    {
      title: "Confirm what will happen next",
      body: "Review the full mission configuration before confirmation. AegisPT will create or reuse the engagement, seed inventory, create the mission record, and open Mission Control.",
    },
  ];
  return leads[step] || leads[0];
}

function assessmentTypeCopy(type) {
  const mapping = {
    "Website / Web App": "Crawlable browser-facing surface with standard page and workflow discovery.",
    "Domain / Domains": "Domain-scoped recon and service discovery across named targets.",
    "External IP / WAN": "Perimeter validation against explicit WAN IP targets.",
    "Internal Range / LAN": "Internal network range validation with scope-controlled depth.",
    "API": "API-first assessment with base URLs, auth context, and protocol-aware testing.",
    "SSL/TLS Only": "Certificate, protocol, and crypto posture validation only.",
    "Authenticated App": "Application validation where session or credentialed access is central.",
    "Mixed Assessment": "Combined web, API, network, auth, and adaptive workflows.",
  };
  return mapping[type] || "Assessment type";
}

function testProfileCopy(profile) {
  const mapping = {
    "Light": "Faster low-impact coverage with emphasis on passive discovery and fingerprinting.",
    "Standard": "Balanced baseline suited for most scoped engagements.",
    "Deep": "Broader active depth with more validation time and review overhead.",
    "External Surface Only": "Focus on exposed surface and perimeter posture without deeper auth flows.",
    "Authenticated Only": "Prioritize account-context workflows, auth paths, and role behavior.",
    "SSL/TLS Only": "Only certificate and transport protection analysis.",
    "Internal Validation": "Approval-heavy validation for controlled internal adversary simulation.",
    "Adaptive Customer-Specific Mode": "Inventory-informed plus adaptive pack generation before deeper validation.",
  };
  return mapping[profile] || "Profile";
}

function moduleCopy(key) {
  const mapping = {
    discovery: "Resolve targets, fingerprints, and accessible surface safely.",
    web_crawling: "Build page and route coverage for browser-facing applications.",
    auth_flows: "Exercise login, session, and role-aware access paths.",
    content_discovery: "Enumerate discoverable content and hidden application routes.",
    nuclei_checks: "Run templated security probes through the managed validation lane.",
    zap_active_checks: "Use approval-aware ZAP active checks where safety allows.",
    ssl_tls_analysis: "Inspect certificate and transport security posture.",
    business_logic_testing: "Investigate workflow abuse and privilege or process edge cases.",
    adaptive_ai_generated_tests: "Enable customer-specific adaptive checks from Pack Forge.",
    internal_validation_modules: "Prepare internal validation modules and scenarios.",
  };
  return mapping[key] || key;
}

function visibleTargetGroups(assessmentType) {
  const base = ["domains", "urls"];
  if (assessmentType === "API") return ["api_base_urls", "urls", "domains"];
  if (assessmentType === "SSL/TLS Only") return ["domains", "urls", "ip_addresses"];
  if (assessmentType === "External IP / WAN") return ["ip_addresses", "cidr_ranges"];
  if (assessmentType === "Internal Range / LAN") return ["cidr_ranges", "ip_addresses"];
  if (assessmentType === "Domain / Domains") return ["domains", "subdomains", "urls"];
  if (assessmentType === "Authenticated App") return ["urls", "domains", "api_base_urls"];
  if (assessmentType === "Mixed Assessment") return ["domains", "subdomains", "urls", "ip_addresses", "cidr_ranges", "api_base_urls"];
  return [...base, "subdomains"];
}
