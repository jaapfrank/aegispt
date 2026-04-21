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
  countMeaningfulAccessContexts,
  emptyState,
  executionPlanForProfile,
  enabledModules,
  escapeHtml,
  fieldHelp,
  fieldLabel,
  flattenTargetValues,
  hasMeaningfulAccount,
  hasMeaningfulAccessContext,
  humanizeCheckMode,
  humanizeDepthLabel,
  inferAuthStrategyFromAccess,
  isLikelyCidr,
  isLikelyDomain,
  isLikelyIp,
  isLikelyUrl,
  numberValue,
  readinessSummary,
  renderAccessContextSummary,
  renderBadgeList,
  renderDisclosure,
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
    ensureConversationDefaults();
    const wizard = state.wizard;
    const context = buildConversationContext();
    dom.wizardStepper.innerHTML = renderConversationStepper(context);
    dom.wizardPanel.innerHTML = renderConversationPanel(context);
    dom.wizardErrors.innerHTML = wizard.errors.length
      ? wizard.errors.map((error) => `<div>${escapeHtml(error)}</div>`).join("")
      : "";
    dom.wizardSummary.innerHTML = renderWizardSummary(wizard, context.estimate, context);
    if (dom.wizardAdvancedDrawer) {
      dom.wizardAdvancedDrawer.innerHTML = renderAdvancedDrawer(context);
      dom.wizardAdvancedDrawer.classList.toggle("hidden", !wizard.intake.advancedOpen);
    }

    dom.wizardBackBtn.disabled = wizard.submitting || !hasConversationHistory();
    dom.wizardNextBtn.classList.toggle("hidden", context.confirmationReady);
    dom.wizardConfirmBtn.classList.toggle("hidden", !context.confirmationReady);
    dom.wizardConfirmBtn.disabled = wizard.submitting;
    dom.wizardNextBtn.disabled = wizard.submitting || !context.question.allowSubmission;
    dom.wizardBackBtn.textContent = wizard.submitting ? "Locked" : "Previous Topic";
    dom.wizardNextBtn.textContent = wizard.submitting
      ? "Saving..."
      : context.isReviewingEarlierTopic
        ? "Apply Answer & Return"
        : "Apply Answer";
    dom.wizardConfirmBtn.textContent = wizard.submitting
      ? "Creating Mission..."
      : "Create Mission & Open Mission Control";

    attachConversationHandlers(context);
    attachAdvancedHandlers();

    const answerInput = document.getElementById("wizard-answer-input");
    const shouldAutofocusAnswer =
      typeof window.matchMedia !== "function" ||
      !window.matchMedia("(max-width: 900px)").matches;
    const currentQuestionKey = `${context.question.id}:${context.confirmationReady ? "confirm" : "question"}`;
    const questionChanged = wizard.intake.lastRenderedQuestionKey !== currentQuestionKey;
    wizard.intake.lastRenderedQuestionKey = currentQuestionKey;
    if (answerInput && shouldAutofocusAnswer) {
      answerInput.focus();
      if (typeof answerInput.value === "string" && typeof answerInput.setSelectionRange === "function") {
        answerInput.setSelectionRange(answerInput.value.length, answerInput.value.length);
      }
    } else if (!shouldAutofocusAnswer && questionChanged) {
      const mobileTargetSelector = context.confirmationReady
        ? '[data-testid="conversation-thread"]'
        : '[data-testid="conversation-question"]';
      const scrollToMobileTarget = () => {
        document.querySelector(mobileTargetSelector)?.scrollIntoView({
          block: "start",
          behavior: "auto",
        });
      };
      if (typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(() => window.requestAnimationFrame(scrollToMobileTarget));
      } else {
        scrollToMobileTarget();
      }
    }
  }

  function ensureConversationDefaults() {
    const wizard = state.wizard;
    const intake = wizard.intake;
    const preferences = wizard.data.intake_preferences;
    const previousNameContext = snapshotEngagementNameContext(wizard.data);
    let compatibilityChanged = false;

    if (!wizard.data.engagement_name) {
      wizard.data.engagement_name = suggestedEngagementName(wizard.data);
    }

    compatibilityChanged = reconcileGoalCompatibility("inferred").changed || compatibilityChanged;

    if (!preferences.output_style) {
      if (/per[- ]?item|clear information|detailed|every found item/i.test(preferences.mission_intent || "")) {
        preferences.output_style = "detailed-per-item";
        intake.sources.output = "confirmed";
      } else if (preferences.primary_goal === "inventory-first") {
        preferences.output_style = "detailed-per-item";
        if (intake.sources.output === "still-needed") intake.sources.output = "inferred";
      } else if (["deep-assessment", "authenticated-review", "adaptive-coverage", "internal-validation"].includes(preferences.primary_goal)) {
        preferences.output_style = "technical-detail";
        if (intake.sources.output === "still-needed") intake.sources.output = "inferred";
      } else if (intake.sources.output === "still-needed") {
        preferences.output_style = "balanced-technical";
        intake.sources.output = "inferred";
      }
    } else if (intake.sources.output === "still-needed") {
      intake.sources.output = "inferred";
    }

    if (
      shouldAskAuthQuestion(wizard.data) &&
      intake.sources.auth === "inferred" &&
      preferences.auth_strategy === "unauthenticated" &&
      !hasMeaningfulAccessContext(wizard.data.access)
    ) {
      preferences.auth_strategy = "";
      intake.sources.auth = "still-needed";
    }

    if (
      !preferences.auth_strategy &&
      intake.sources.intent !== "still-needed" &&
      !shouldAskAuthQuestion(wizard.data)
    ) {
      preferences.auth_strategy = "unauthenticated";
      if (intake.sources.auth === "still-needed") intake.sources.auth = "inferred";
    }

    if (preferences.auth_strategy === "unauthenticated") {
      if (
        hasMeaningfulAccount(wizard.data.access.accounts) ||
        stringValue(wizard.data.access.manual_auth_steps) ||
        stringValue(wizard.data.access.cookie_notes)
      ) {
        clearAccessContext();
      }
      alignPlanForUnauthenticatedAccess();
    }

    if (!preferences.safety_posture) {
      const canInferInventorySafety =
        wizard.data.assessment_type !== "Internal Range / LAN" &&
        wizard.data.assessment_type !== "SSL/TLS Only";
      if (
        ["inventory-first", "quick-overview"].includes(preferences.primary_goal) && canInferInventorySafety
      ) {
        preferences.safety_posture = "conservative";
        if (intake.sources.safety === "still-needed") intake.sources.safety = "inferred";
      }
    }

    if (!preferences.boundary_handling) {
      const hasExclusions = flattenTargetValues(wizard.data.exclusions).length > 0 || wizard.data.exclusions.notes;
      const shouldPromptBoundaries = requiresExplicitBoundaryConfirmation(wizard.data);
      if (!hasExclusions && preferences.lateral_discovery !== "requested" && !shouldPromptBoundaries) {
        preferences.boundary_handling = "standard-scope-only";
        if (intake.sources.boundaries === "still-needed") intake.sources.boundaries = "inferred";
      }
    }

    if (compatibilityChanged) {
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, wizard.data);
    }

    const recommended = recommendedQuestionId(wizard);
    if (wizard.intake.activeQuestionId === "confirm" && recommended !== "confirm") {
      wizard.intake.activeQuestionId = recommended;
    }
    if (!wizard.intake.activeQuestionId) {
      wizard.intake.activeQuestionId = recommended;
    }
  }

  function buildConversationContext() {
    const wizard = state.wizard;
    const estimate = estimateMission(wizard.data);
    const recommendedQuestion = recommendedQuestionId(wizard);
    const activeQuestionId =
      wizard.intake.activeQuestionId && wizard.intake.activeQuestionId !== "confirm"
        ? wizard.intake.activeQuestionId
        : recommendedQuestion;
    const question = buildQuestion(activeQuestionId === "confirm" ? "confirm" : activeQuestionId, estimate);
    const summary = buildSummaryBuckets(wizard, estimate);
    const reviewMode = determineReviewMode(activeQuestionId, recommendedQuestion);
    return {
      estimate,
      question,
      recommendedQuestionId: recommendedQuestion,
      confirmationReady: question.id === "confirm" && validateEntireWizard().length === 0,
      progress: buildConversationProgress(wizard),
      summary,
      reviewMode,
      isReviewingEarlierTopic:
        reviewMode === "earlier",
      isReviewingOtherTopic:
        Boolean(wizard.intake.reviewQuestionId) &&
        wizard.intake.reviewQuestionId === activeQuestionId &&
        activeQuestionId !== "confirm" &&
        activeQuestionId !== recommendedQuestion,
    };
  }

  function determineReviewMode(activeQuestionId, recommendedQuestionId) {
    if (
      !state.wizard.intake.reviewQuestionId ||
      state.wizard.intake.reviewQuestionId !== activeQuestionId ||
      !activeQuestionId ||
      activeQuestionId === "confirm" ||
      activeQuestionId === recommendedQuestionId
    ) {
      return null;
    }

    const order = ["intent", "goal", "output", "scope", "auth", "auth-details", "safety", "boundaries", "confirm"];
    const activeIndex = order.indexOf(activeQuestionId);
    const recommendedIndex = order.indexOf(recommendedQuestionId);
    if (activeIndex === -1 || recommendedIndex === -1) return "other";
    if (activeIndex < recommendedIndex) return "earlier";
    if (activeIndex > recommendedIndex) return "later";
    return "other";
  }

  function questionStillNeedsInput(wizard, questionId) {
    const data = wizard.data;
    if (questionId === "intent") {
      return wizard.intake.sources.intent === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "goal") {
      return wizard.intake.sources.goal === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "scope") {
      return (
        !flattenTargetValues(data.targets).length ||
        wizard.intake.sources.scope === "still-needed" ||
        questionHasBlockingErrors(wizard, questionId)
      );
    }
    if (questionId === "auth") {
      return shouldAskAuthQuestion(data) && wizard.intake.sources.auth === "still-needed";
    }
    if (questionId === "auth-details") return needsAuthDetails(data) || questionHasBlockingErrors(wizard, questionId);
    if (questionId === "safety") {
      return wizard.intake.sources.safety === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "boundaries") {
      const boundaryConfirmationRequired = requiresExplicitBoundaryConfirmation(data);
      if (boundaryConfirmationRequired) {
        return !["confirmed", "override"].includes(String(wizard.intake.sources.boundaries || ""));
      }
      return wizard.intake.sources.boundaries === "still-needed";
    }
    return false;
  }

  function validationErrorsForQuestion(wizard, questionId) {
    if (questionId === "intent") return validateWizardStep(0);
    if (questionId === "scope") return validateWizardStep(1);
    if (questionId === "auth-details") return validateWizardStep(2);
    if (questionId === "goal") {
      return [...new Set([...validateWizardStep(3), ...validateWizardStep(4)])];
    }
    if (questionId === "safety") return validateWizardStep(5);
    return [];
  }

  function transitionValidationErrorsForQuestion(wizard, questionId) {
    const errors = validationErrorsForQuestion(wizard, questionId);
    if (
      questionId === "scope" &&
      errors.length === 1 &&
      errors[0] === "Add at least one target in scope." &&
      !flattenTargetValues(wizard.data.targets).length &&
      wizard.intake.sources.scope === "still-needed"
    ) {
      return [];
    }
    return errors;
  }

  function questionHasBlockingErrors(wizard, questionId) {
    return validationErrorsForQuestion(wizard, questionId).length > 0;
  }

  function realignConversationAfterAdvancedChange() {
    const wizard = state.wizard;
    const activeQuestionId = wizard.intake.activeQuestionId;
    const recommendedQuestionIdValue = recommendedQuestionId(wizard);
    if (
      !activeQuestionId ||
      activeQuestionId === recommendedQuestionIdValue
    ) {
      return;
    }
    if (
      wizard.intake.reviewQuestionId === activeQuestionId &&
      questionStillNeedsInput(wizard, activeQuestionId)
    ) {
      return;
    }
    wizard.intake.activeQuestionId = recommendedQuestionIdValue;
    if (wizard.intake.reviewQuestionId === activeQuestionId) {
      wizard.intake.reviewQuestionId = null;
    }
  }

  function buildConversationProgress(wizard) {
    const mapping = [
      ["Intent & Type", ["intent", "target_type"]],
      ["Scope", ["scope"]],
      ["Access", ["auth"]],
      ["Safety", ["goal", "safety", "boundaries"]],
      ["Confirm", []],
    ];
    const sourceForProgressKey = (key) => {
      if (key === "auth") {
        return questionStillNeedsInput(wizard, "auth") || questionStillNeedsInput(wizard, "auth-details")
          ? "still-needed"
          : wizard.intake.sources.auth;
      }
      if (["intent", "goal", "scope", "safety", "boundaries"].includes(key)) {
        return questionStillNeedsInput(wizard, key) ? "still-needed" : wizard.intake.sources[key];
      }
      return wizard.intake.sources[key];
    };
    return mapping.map(([label, keys]) => {
      const states = keys.map((key) => sourceForProgressKey(key));
      const unresolved = states.filter((stateValue) => stateValue === "still-needed").length;
      const refined = states.filter((stateValue) => stateValue === "override").length;
      const inferred = states.filter((stateValue) => stateValue === "inferred").length;
      let stateValue = "complete";
      if (!keys.length) {
        stateValue = recommendedQuestionId(wizard) === "confirm" ? "active" : "pending";
      } else if (unresolved) {
        stateValue = "active";
      } else if (refined) {
        stateValue = "complete";
      } else if (inferred) {
        stateValue = "complete";
      }
      return {
        label,
        state: stateValue,
        meta: !keys.length
          ? (recommendedQuestionId(wizard) === "confirm" ? "Ready for confirmation" : "Waiting for intake")
          : unresolved
            ? `${unresolved} item${unresolved === 1 ? "" : "s"} still needed`
            : refined
              ? "Advanced override active"
              : inferred
              ? "Resolved with safe inference"
              : "Confirmed",
        questionId:
          keys[0] === "auth"
            ? resolveConversationTopicQuestionId("auth")
            : keys[0] || "confirm",
      };
    });
  }

  function renderConversationStepper(context) {
    return context.progress.map((item, index) => `
      <button class="wizard-step ${item.state}" type="button" data-edit-question="${escapeHtml(item.questionId)}" data-testid="wizard-stage-${index + 1}">
        <small>${escapeHtml(item.meta)}</small>
        <strong>${escapeHtml(item.label)}</strong>
      </button>
    `).join("");
  }

  function renderConversationPanel(context) {
    const wizard = state.wizard;
    const question = context.question;
    const recentHistory = wizard.intake.history.slice(-2);
    const earlierHistory = wizard.intake.history.slice(0, Math.max(0, wizard.intake.history.length - recentHistory.length));
    return `
      <div class="conversation-ribbon">
        <strong>AI intake</strong>
        <span>Plain-language intake mapped into the deterministic run model.</span>
      </div>
      ${
        earlierHistory.length
          ? renderDisclosure({
              title: "Earlier Intake Context",
              summary: `${wizard.intake.history.length} captured turns`,
              open: false,
              testId: "conversation-history-disclosure",
              body: `<div class="conversation-thread compact">${earlierHistory.map(renderConversationTurn).join("")}</div>`,
            })
          : ""
      }
      <div class="conversation-thread ${recentHistory.length <= 1 ? "compact" : ""}" data-testid="conversation-thread">
        ${recentHistory.map(renderConversationTurn).join("")}
      </div>
      <div class="conversation-question-card" data-testid="conversation-question">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Current Question</p>
            <h3>${escapeHtml(question.title)}</h3>
          </div>
          <span class="badge">${escapeHtml(question.badge)}</span>
        </div>
        ${renderConversationPathNote(context)}
        ${
          question.id === "confirm"
            ? `<p class="micro-copy">Review the planned mission below, revise any topic if needed, or open Advanced Configuration before you create the mission.</p>`
            : `<p>${escapeHtml(question.prompt)}</p>`
        }
        ${question.guidance && question.id !== "confirm" ? `<p class="micro-copy split-top">${escapeHtml(question.guidance)}</p>` : ""}
        ${question.recommendation ? `
          <div class="section-note split-top">
            <strong>Recommendation</strong>
            <p>${escapeHtml(question.recommendation)}</p>
          </div>
        ` : ""}
        ${question.quickReplies.length ? `
          <div class="chip-row split-top" data-testid="conversation-quick-replies">
            ${question.quickReplies.map((reply) => `
              <button class="action ghost quick-reply-chip" type="button" data-quick-reply="${escapeHtml(reply)}">${escapeHtml(reply)}</button>
            `).join("")}
          </div>
        ` : ""}
        ${question.quickReplies.length && question.id !== "confirm" ? `
          <p class="micro-copy split-top">Use one of the suggested replies for the common path, or type your own wording below if your mission needs more detail.</p>
        ` : ""}
        ${question.id === "confirm" ? `
          <div class="detail-surface emphasis-surface split-top" data-testid="wizard-confirmation-summary">
            <h4>Planned Mission</h4>
            <p>${escapeHtml(buildNaturalConfirmationSummary(context.estimate))}</p>
            ${renderConfirmationAuthorizationContext()}
            ${renderConfirmationScopeGuardrails()}
            <p class="micro-copy split-top">${escapeHtml(buildConfirmationSafetyLine(wizard.data, context.estimate.execution_profile))}</p>
          </div>
        ` : `
          <form id="conversation-answer-form" class="conversation-answer-form split-top">
            ${question.multiline ? `
              <textarea id="wizard-answer-input" rows="4" placeholder="${escapeHtml(question.placeholder)}" data-testid="conversation-answer-input">${escapeHtml(wizard.intake.draftAnswer || "")}</textarea>
            ` : `
              <input id="wizard-answer-input" type="text" placeholder="${escapeHtml(question.placeholder)}" value="${escapeHtml(wizard.intake.draftAnswer || "")}" data-testid="conversation-answer-input" />
            `}
          </form>
        `}
      </div>
      ${renderConversationEditActions(context)}
    `;
  }

  function renderConversationPathNote(context) {
    if (context.question.id === "confirm") {
      return `
        <div class="intake-progress-note ready split-top" data-testid="conversation-path-note">
          <strong>Confirmation Ready</strong>
          <p>All required intake topics are resolved. Review the mission summary, revise any topic if needed, then create the mission.</p>
        </div>
      `;
    }

    if (context.reviewMode === "earlier") {
      return `
        <div class="intake-progress-note review split-top" data-testid="conversation-path-note">
          <strong>Revising Earlier Topic</strong>
          <p>You are updating an earlier answer. After you apply it, AegisPT recalculates the next required question from the updated mission state.</p>
          <p class="micro-copy split-top">The live summary and deterministic run dossier update immediately when this answer is applied.</p>
        </div>
      `;
    }

    if (context.reviewMode === "later" || context.reviewMode === "other") {
      return `
        <div class="intake-progress-note review split-top" data-testid="conversation-path-note">
          <strong>Reviewing Another Topic</strong>
          <p>You are checking a different mission topic before the main intake reaches it. After you apply this answer, AegisPT returns to the next required topic from the updated mission state.</p>
          <p class="micro-copy split-top">Use this when you want to jump ahead without losing the deterministic intake path.</p>
        </div>
      `;
    }

    const remainingStillNeededLabels = filterStillNeededLabelsForActiveQuestion(
      context.summary,
      context.question.id,
    );
    const remainingLine =
      remainingStillNeededLabels.length === 0
        ? "Answer this to continue. AegisPT will either move straight to confirmation or ask for the next required topic immediately after."
        : `Still to confirm in this mission: ${remainingStillNeededLabels.join(", ")}.`;

    return `
      <div class="intake-progress-note split-top" data-testid="conversation-path-note">
        <strong>Mission Progress</strong>
        <p>${escapeHtml(remainingLine)}</p>
        <p class="micro-copy split-top">Apply this answer to keep the intake moving toward a deterministic run dossier and confirmation-ready mission.</p>
      </div>
    `;
  }

  function activeQuestionFamilyIds(questionId) {
    if (questionId === "auth") {
      return new Set(["auth", "auth-details"]);
    }
    if (
      questionId === "auth-details" &&
      state.wizard.data.intake_preferences.auth_strategy === "advanced-details" &&
      !hasMeaningfulAccessContext(state.wizard.data.access)
    ) {
      return new Set();
    }
    if (questionId === "auth-details") {
      return new Set(["auth", "auth-details"]);
    }
    return new Set([questionId]);
  }

  function labelsResolvedByActiveQuestion(summary, questionId) {
    const activeQuestionIds = activeQuestionFamilyIds(questionId);
    return new Set(
      (summary?.stillNeededDetails || [])
        .filter((item) => item.questionId && activeQuestionIds.has(item.questionId))
        .map((item) => item.label),
    );
  }

  function filterStillNeededLabelsForActiveQuestion(summary, questionId) {
    const suppressedLabels = labelsResolvedByActiveQuestion(summary, questionId);
    return (summary?.stillNeeded || []).filter((label) => !suppressedLabels.has(label));
  }

  function revisableConversationActions(context) {
    const wizard = state.wizard;
    const activeQuestionIds = activeQuestionFamilyIds(context.question.id);
    const confirmedOrOverride = (value) => ["confirmed", "override"].includes(String(value || ""));
    return [
      {
        questionId: "goal",
        label: "Change Goal",
        ready: confirmedOrOverride(wizard.intake.sources.goal) && !questionStillNeedsInput(wizard, "goal"),
      },
      {
        questionId: "output",
        label: "Change Output",
        ready: confirmedOrOverride(wizard.intake.sources.output),
      },
      {
        questionId: "scope",
        label: "Change Scope",
        ready: confirmedOrOverride(wizard.intake.sources.scope) && !questionStillNeedsInput(wizard, "scope"),
      },
      {
        questionId: resolveConversationTopicQuestionId("auth"),
        label: "Change Access",
        ready:
          confirmedOrOverride(wizard.intake.sources.auth) &&
          !questionStillNeedsInput(wizard, "auth") &&
          !questionStillNeedsInput(wizard, "auth-details"),
      },
      {
        questionId: "safety",
        label: "Change Safety",
        ready: confirmedOrOverride(wizard.intake.sources.safety) && !questionStillNeedsInput(wizard, "safety"),
      },
      {
        questionId: "boundaries",
        label: "Change Boundaries",
        ready: confirmedOrOverride(wizard.intake.sources.boundaries) && !questionStillNeedsInput(wizard, "boundaries"),
      },
    ].filter((item) => item.ready && !activeQuestionIds.has(item.questionId));
  }

  function renderConversationTurn(turn) {
    return `
      <article class="conversation-turn ${escapeHtml(turn.role)} ${escapeHtml(turn.tone || "neutral")}" data-testid="conversation-turn">
        <p class="eyebrow">${escapeHtml(turn.role === "assistant" ? "AegisPT" : "Operator")}</p>
        <p>${escapeHtml(turn.text)}</p>
        ${turn.questionId && turn.role === "user" ? `<button class="action ghost tiny" type="button" data-edit-question="${escapeHtml(turn.questionId)}">Change</button>` : ""}
      </article>
    `;
  }

  function renderConversationEditActions(context) {
    if (!hasConversationHistory()) return "";
    const actions = revisableConversationActions(context);
    if (!actions.length) return "";
    return renderDisclosure({
      title: "Revise Captured Topic",
      summary: `${actions.length} captured topic${actions.length === 1 ? "" : "s"} can be updated`,
      open: false,
      testId: "conversation-edit-row",
      body: `
        <div class="conversation-edit-row">
          ${actions
            .map(
              ({ questionId, label }) => `
                <button class="action ghost tiny" type="button" data-edit-question="${escapeHtml(questionId)}">${escapeHtml(label)}</button>
              `
            )
            .join("")}
        </div>
        <p class="micro-copy split-top">Only topics already captured in the run dossier are shown here, so later unanswered steps do not add extra noise.</p>
      `,
    });
  }

  function renderAdvancedDrawer(context) {
    const wizard = state.wizard;
    const steps = WIZARD_STEPS.slice(0, 6);
    return `
      <div class="advanced-drawer-shell">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Advanced Configuration</p>
            <h4>Deterministic Run Controls</h4>
          </div>
          <button class="action ghost tiny" type="button" data-advanced-close="true">Hide</button>
        </div>
        <p class="micro-copy">These controls write into the same run configuration that the conversational intake is building.</p>
        <div class="advanced-nav split-top">
          ${steps.map((label, index) => `
            <button class="action ${wizard.advancedStep === index ? "secondary" : "ghost"} tiny" type="button" data-advanced-step="${index}">${escapeHtml(label)}</button>
          `).join("")}
        </div>
        <div id="wizard-advanced-content" class="advanced-content split-top" data-testid="wizard-advanced-content">
          ${wizardStepContent(wizard.advancedStep, wizard.data, wizard.useExistingEngagement)}
        </div>
      </div>
    `;
  }

  function attachConversationHandlers(context) {
    document.getElementById("conversation-answer-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      submitConversationAnswer().catch(runtime.actions.handleError || (() => {}));
    });

    document.getElementById("wizard-answer-input")?.addEventListener("input", (event) => {
      state.wizard.intake.draftAnswer = event.target.value;
      dom.wizardNextBtn.disabled = !stringValue(event.target.value);
    });

    document.querySelectorAll("[data-quick-reply]").forEach((button) => {
      button.addEventListener("click", () => {
        submitConversationAnswer(button.dataset.quickReply).catch(runtime.actions.handleError || (() => {}));
      });
    });

    document.querySelectorAll("[data-edit-question]").forEach((button) => {
      button.addEventListener("click", () => {
        focusQuestion(button.dataset.editQuestion);
      });
    });

    document.querySelectorAll("[data-intake-advanced]").forEach((button) => {
      button.addEventListener("click", () => {
        state.wizard.intake.advancedOpen = true;
        const requestedStep = Number(button.dataset.intakeAdvancedStep);
        if (!Number.isNaN(requestedStep)) {
          state.wizard.advancedStep = requestedStep;
        }
        renderWizard();
      });
    });

    const advancedToggle = document.getElementById("wizard-advanced-toggle");
    if (advancedToggle) {
      advancedToggle.onclick = () => {
        state.wizard.intake.advancedOpen = !state.wizard.intake.advancedOpen;
        renderWizard();
      };
    }

    const restartButton = document.getElementById("wizard-restart-btn");
    if (restartButton) {
      restartButton.onclick = () => {
        restartConversation();
      };
    }
  }

  function attachAdvancedHandlers() {
    document.querySelectorAll("[data-advanced-step]").forEach((button) => {
      button.addEventListener("click", () => {
        state.wizard.advancedStep = Number(button.dataset.advancedStep || 0);
        renderWizard();
      });
    });

    document.querySelector('[data-advanced-close="true"]')?.addEventListener("click", () => {
      state.wizard.intake.advancedOpen = false;
      renderWizard();
    });

    const advancedRoot = document.getElementById("wizard-advanced-content");
    if (!advancedRoot) return;

    advancedRoot.querySelectorAll("input, textarea, select").forEach((element) => {
      element.addEventListener("input", onAdvancedInput);
      element.addEventListener("change", onAdvancedInput);
    });

    advancedRoot.querySelector("#wizard-add-account-btn")?.addEventListener("click", () => {
      syncWizardStepFromDom();
      state.wizard.data.access.accounts.push(buildEmptyAccount());
      markAdvancedOverrideForStep(state.wizard.advancedStep);
      renderWizard();
    });

    advancedRoot.querySelectorAll(".wizard-remove-account-btn").forEach((button) => {
      button.addEventListener("click", () => {
        syncWizardStepFromDom();
        const index = Number(button.dataset.accountRemove);
        state.wizard.data.access.accounts.splice(index, 1);
        if (!state.wizard.data.access.accounts.length) {
          state.wizard.data.access.accounts.push(buildEmptyAccount());
        }
        markAdvancedOverrideForStep(state.wizard.advancedStep);
        renderWizard();
      });
    });
  }

  function submitConversationAnswer(answerOverride) {
    syncWizardStepFromDom();
    const wizard = state.wizard;
    const context = buildConversationContext();
    const question = context.question;
    const answer = stringValue(answerOverride ?? wizard.intake.draftAnswer ?? document.getElementById("wizard-answer-input")?.value);

    if (question.id === "confirm") {
      return Promise.resolve();
    }

    if (!answer) {
      wizard.errors = ["Enter an answer or use a quick reply."];
      renderWizard();
      return Promise.resolve();
    }

    if (handleConversationCommand(answer)) {
      return Promise.resolve();
    }

    wizard.errors = [];
    const result = applyConversationAnswer(question.id, answer);
    wizard.intake.history.push({
      role: "user",
      questionId: question.id,
      text: answer,
    });
    wizard.intake.draftAnswer = "";

    if (!result.ok) {
      wizard.errors = [result.error];
      wizard.intake.history.push({
        role: "assistant",
        questionId: question.id,
        tone: "warning",
        text: result.error,
      });
      renderWizard();
      return Promise.resolve();
    }

    wizard.intake.history.push({
      role: "assistant",
      questionId: question.id,
      text: result.message,
    });
    wizard.intake.reviewQuestionId = null;
    syncConversationMetadataFromData();
    ensureConversationDefaults();
    wizard.intake.activeQuestionId = recommendedQuestionId(wizard);
    wizard.errors = transitionValidationErrorsForQuestion(wizard, wizard.intake.activeQuestionId);
    renderWizard();
    return Promise.resolve();
  }

  function goBackConversation() {
    const previousUserTurn = [...state.wizard.intake.history]
      .reverse()
      .find((turn) => turn.role === "user" && turn.questionId);
    if (!previousUserTurn) return;
    focusQuestion(resolveConversationTopicQuestionId(previousUserTurn.questionId));
  }

  function focusQuestion(questionId) {
    if (!questionId) return;
    state.wizard.intake.activeQuestionId = questionId;
    state.wizard.intake.reviewQuestionId = questionId;
    state.wizard.intake.draftAnswer = draftAnswerForQuestion(questionId);
    state.wizard.errors = validationErrorsForQuestion(state.wizard, questionId);
    renderWizard();
  }

  function restartConversation() {
    state.wizard = buildEmptyWizardState();
    renderWizard();
  }

  function hasConversationHistory() {
    return state.wizard.intake.history.some((turn) => turn.role === "user");
  }

  function resolveConversationTopicQuestionId(questionId) {
    if (questionId !== "auth") return questionId;
    const preferredQuestionId = preferredAuthRevisionQuestionId(state.wizard.data);
    const accessTurn = [...state.wizard.intake.history]
      .reverse()
      .find((turn) => turn.role === "user" && ["auth", "auth-details"].includes(turn.questionId));
    if (accessTurn?.questionId && accessTurn.questionId !== preferredQuestionId) {
      return preferredQuestionId;
    }
    if (accessTurn?.questionId) {
      return accessTurn.questionId;
    }
    return preferredQuestionId;
  }

  function buildQuestion(questionId, estimate) {
    const wizard = state.wizard;
    const assessmentType = wizard.data.assessment_type;
    const goal = wizard.data.intake_preferences.primary_goal;
    const questionMap = {
      intent: {
        id: "intent",
        badge: "Intent",
        title: "Hello. What would you like to pentest today?",
        prompt: "Describe the target in plain language. You can say things like “my LAN network”, “our customer portal”, “our API”, or “our external domain”.",
        placeholder: "Example: My LAN network, our customer portal, our public API, our external domain",
        quickReplies: ["My LAN network", "Our web application", "Our API", "An external domain", "A mixed environment"],
        multiline: false,
        allowSubmission: true,
      },
      goal: {
        id: "goal",
        badge: "Goal",
        title: "What is your main goal for this assessment?",
        prompt: "I only need the next decision that materially changes the run shape.",
        placeholder: "Example: Inventory first, a standard assessment, deep validation, authenticated review, or adaptive customer-specific testing",
        quickReplies: goalQuickRepliesForAssessment(assessmentType),
        multiline: false,
        allowSubmission: true,
      },
      output: {
        id: "output",
        badge: "Output",
        title: "What reporting style should I use?",
        prompt: "This changes only the mission handoff and reporting preference. It does not change scope, safety, or execution lane.",
        placeholder: "Example: Detailed per item, balanced technical, technical detail, or executive summary",
        quickReplies: ["Detailed per item", "Balanced technical", "Technical detail", "Executive summary"],
        multiline: false,
        allowSubmission: true,
      },
      scope: {
        id: "scope",
        badge: "Scope",
        title: scopeQuestionTitle(assessmentType),
        prompt: scopeQuestionPrompt(assessmentType),
        guidance: "Only include explicitly authorized targets. I will not broaden scope from vague phrases like “look around” or “scan anything public”.",
        placeholder: scopePlaceholder(assessmentType),
        quickReplies: [],
        multiline: true,
        allowSubmission: true,
      },
      auth: {
        id: "auth",
        badge: "Access",
        title: "Should this stay unauthenticated, or do you have access I should use?",
        prompt: "If you already know this should stay unauthenticated, say so. If you have accounts, tokens, or sessions, I can prepare for them now and you can add the details in Advanced Configuration.",
        placeholder: "Example: Keep it unauthenticated, I have a portal account, I have API keys, or I will add credentials in advanced settings",
        quickReplies: ["Keep it unauthenticated", "I have portal/app accounts", "I have API tokens or keys", "I will add access in advanced settings"],
        multiline: false,
        allowSubmission: true,
      },
      "auth-details": {
        id: "auth-details",
        badge: "Access Detail",
        title: "What access context should I record?",
        prompt: "You can paste a username, role, token reference, or session reference. Keep it concise if you want to finish quickly, use Advanced Configuration for full detail, or say that access should be withdrawn if you want to remove authenticated context.",
        placeholder: "Example: analyst@example.com role Analyst secret vault://prod/app/user or api-key vault://prod/api/key",
        quickReplies: ["I will add the full details in advanced settings"],
        multiline: true,
        allowSubmission: true,
      },
      safety: {
        id: "safety",
        badge: "Safety",
        title: "Should I keep this conservative or more thorough?",
        prompt: "I will explain any change that makes the run more invasive before I enable it.",
        recommendation: goal === "inventory-first"
          ? "I recommend a conservative posture because you asked for visibility first."
          : (goal === "deep-assessment" ? "I recommend a balanced but guarded posture unless you explicitly want active validation." : ""),
        placeholder: "Example: Conservative, balanced, thorough, passive only, or aggressive with approval",
        quickReplies: ["Conservative", "Balanced", "Thorough", "Passive only", "Aggressive with approval"],
        multiline: false,
        allowSubmission: true,
      },
      boundaries: boundaryQuestionConfig(assessmentType),
      confirm: {
        id: "confirm",
        badge: "Confirm",
        title: "I have enough to prepare the mission.",
        prompt: buildNaturalConfirmationSummary(estimate),
        guidance: "Confirm to create the engagement and run, revise any topic, or open Advanced Configuration for the full deterministic controls.",
        quickReplies: [],
        multiline: false,
        allowSubmission: false,
      },
    };
    return questionMap[questionId] || questionMap.intent;
  }

function isInternalRangeAssessment(assessmentType) {
  return String(assessmentType || "").trim() === "Internal Range / LAN";
}

function boundaryQuestionConfig(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return {
      id: "boundaries",
      badge: "Boundaries",
      title: "Are there systems, behaviors, or internal edges I must avoid or handle carefully?",
      prompt: "This is where you can name exclusions, maintenance-sensitive targets, or how to treat adjacent internal ranges if they become visible.",
      guidance: "For internal expansion I stay inside your configured scope. I can report adjacent reachable ranges, but I do not scan newly discovered ranges without explicit authorization.",
      placeholder: "Example: Avoid 10.0.20.10, report adjacent internal ranges only, do not touch production payment hosts",
      quickReplies: ["No extra exclusions", "Report adjacent internal ranges only", "I need custom exclusions"],
      multiline: true,
      allowSubmission: true,
    };
  }

  return {
    id: "boundaries",
    badge: "Boundaries",
    title: "Are there systems, behaviors, or boundaries I must avoid or handle carefully?",
    prompt: "This is where you can name exclusions, maintenance-sensitive targets, sensitive user journeys, or any scope assumptions that should stay explicit.",
    guidance: "I stay inside the exact approved scope. I do not broaden coverage, change target classes, or expand into related systems without explicit authorization.",
    placeholder: "Example: Avoid billing flows, do not touch production payment hosts, no after-hours testing",
    quickReplies: ["No extra exclusions", "I need custom exclusions"],
    multiline: true,
    allowSubmission: true,
  };
}

function boundaryNotesIntro(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return "Use these fields when the engagement has explicit denylist targets or when internal range handling needs notes that should stay visible in the run configuration and report scope snapshot.";
  }
  return "Use these fields when the engagement has explicit denylist targets or when scope assumptions and sensitive flows need notes that should stay visible in the run configuration and report scope snapshot.";
}

function boundaryNotesPlaceholder(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return "Report adjacent internal ranges only, avoid production payment hosts, no after-hours testing";
  }
  return "Avoid billing flows, do not touch production payment hosts, no after-hours testing";
}

function goalQuickRepliesForAssessment(assessmentType) {
  if (assessmentType === "Internal Range / LAN") {
    return ["Inventory first", "Visibility with clear per-item detail", "Standard internal assessment", "Deep internal validation"];
  }
  if (assessmentType === "External IP / WAN") {
    return [
      "Quick perimeter overview",
      "Inventory first",
      "Perimeter review",
      "Deep follow-up after discovery",
      "Adaptive follow-up after discovery",
    ];
  }
  if (assessmentType === "Authenticated App") {
    return ["Authenticated review", "Standard assessment", "Deep assessment", "Inventory first"];
  }
    if (assessmentType === "API") {
      return ["Inventory first", "Authenticated API review", "Deep API assessment", "Adaptive customer-specific testing"];
    }
    if (assessmentType === "SSL/TLS Only") {
      return ["Quick overview", "Standard assessment"];
    }
    return ["Quick overview", "Inventory first", "Standard assessment", "Deep assessment", "Adaptive customer-specific testing"];
  }

  function scopeQuestionTitle(assessmentType) {
    if (assessmentType === "Internal Range / LAN") return "What exact CIDR range or internal hosts may I use?";
    if (assessmentType === "External IP / WAN") return "What exact IPs or CIDR ranges are authorized?";
    if (assessmentType === "API") return "What API base URLs or application URLs may I use?";
    if (assessmentType === "SSL/TLS Only") return "What hostnames, URLs, or IPs should I validate for TLS only?";
    return "What exact targets are authorized for this assessment?";
  }

  function scopeQuestionPrompt(assessmentType) {
    if (assessmentType === "Internal Range / LAN") {
      return "Enter one or more approved internal CIDRs or hosts. I will keep discovery inside that scope and only report adjacent ranges unless you later authorize more.";
    }
    if (assessmentType === "API") {
      return "Enter the approved API base URLs or related application URLs. I will classify them into API and application scope automatically where possible.";
    }
    return "Enter the exact authorized domains, URLs, IPs, or CIDRs that belong in scope.";
  }

  function scopePlaceholder(assessmentType) {
    if (assessmentType === "Internal Range / LAN") return "Example: 10.0.20.0/24";
    if (assessmentType === "API") return "Example: https://api.example.com/v1";
    if (assessmentType === "External IP / WAN") return "Example: 203.0.113.10 or 203.0.113.0/28";
    return "Example: https://portal.example.com or app.example.com";
  }

  function recommendedQuestionId(wizard) {
    const orderedQuestions = ["intent", "goal", "scope", "auth", "auth-details", "safety", "boundaries"];
    for (const questionId of orderedQuestions) {
      if (questionStillNeedsInput(wizard, questionId)) return questionId;
    }
    return "confirm";
  }

  function buildSummaryBuckets(wizard, estimate) {
    const data = wizard.data;
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const engagementRoute = currentEngagementRouteContext(data);
    const deferAccessUntilRelevant =
      wizard.intake.sources.intent === "still-needed" &&
      wizard.intake.sources.auth === "still-needed" &&
      !shouldAskAuthQuestion(data) &&
      !String(data.intake_preferences.auth_strategy || "").trim() &&
      !hasMeaningfulAccessContext(data.access) &&
      !wizard.intake.overrides.access;
    const deferOutputUntilGoalContext =
      questionStillNeedsInput(wizard, "goal") &&
      wizard.intake.sources.output === "inferred" &&
      !wizard.intake.overrides.profile &&
      !wizard.intake.overrides.modules &&
      !wizard.intake.overrides.safety;
    const effectiveGoalSource = questionStillNeedsInput(wizard, "goal") ? "still-needed" : wizard.intake.sources.goal;
    const effectiveScopeSource = questionStillNeedsInput(wizard, "scope") ? "still-needed" : wizard.intake.sources.scope;
    const effectiveAccessSource =
      deferAccessUntilRelevant
        ? "deferred"
        : questionStillNeedsInput(wizard, "auth") || questionStillNeedsInput(wizard, "auth-details")
        ? "still-needed"
        : wizard.intake.sources.auth;
    const effectiveSafetySource = questionStillNeedsInput(wizard, "safety")
      ? "still-needed"
      : wizard.intake.sources.safety;
    const effectiveBoundarySource = questionStillNeedsInput(wizard, "boundaries")
      ? "still-needed"
      : wizard.intake.sources.boundaries;
    const effectiveOutputSource = deferOutputUntilGoalContext
      ? "deferred"
      : wizard.intake.sources.output;
    const confirmed = [];
    const inferred = [];
    const stillNeeded = [];
    const stillNeededDetails = [];
    const addToBucket = (source, label, value, stillNeededDetail = null) => {
      if (!value) return;
      if (source === "deferred") return;
      if (source === "confirmed" || source === "override") {
        confirmed.push(`${label}: ${value}${source === "override" ? " (advanced override)" : ""}`);
      } else if (source === "inferred") {
        inferred.push(`${label}: ${value}`);
      } else {
        stillNeeded.push(label);
        if (stillNeededDetail) stillNeededDetails.push(stillNeededDetail);
      }
    };

    if (engagementRoute.mode === "reuse-selected-engagement") {
      confirmed.push(`Engagement Route: ${engagementRoute.summaryLabel}`);
    }
    addToBucket(wizard.intake.sources.target_type, "Target Type", data.assessment_type, {
      key: "target-type",
      label: "Target Type",
      questionId: "intent",
    });
    addToBucket(effectiveGoalSource, "Goal", humanizeGoal(data.intake_preferences.primary_goal), {
      key: "goal",
      label: "Goal",
      questionId: "goal",
    });
    addToBucket(effectiveScopeSource, "Scope", renderTargetSummary(data.targets), {
      key: "scope",
      label: "Scope",
      questionId: "scope",
    });
    const accessStillNeededDetail =
      data.intake_preferences.auth_strategy === "advanced-details" &&
      !hasMeaningfulAccessContext(data.access)
        ? {
            key: "access",
            label: "Access",
            action: "advanced",
            advancedStep: 2,
          }
        : {
            key: "access",
            label: "Access",
            questionId: "auth",
          };
    addToBucket(effectiveAccessSource, "Access", summarizeAuthStrategy(data), accessStillNeededDetail);
    addToBucket(
      effectiveSafetySource,
      "Safety",
      `${humanizeSafetyPosture(data.intake_preferences.safety_posture)} · ${humanizeCheckMode(data.safety.active_checks)}`,
      {
        key: "safety",
        label: "Safety",
        questionId: "safety",
      }
    );
    addToBucket(effectiveBoundarySource, "Boundaries", summarizeBoundaries(data), {
      key: "boundaries",
      label: "Boundaries",
      questionId: "boundaries",
    });
    addToBucket(effectiveOutputSource, "Output", humanizeOutputStyle(data.intake_preferences.output_style), {
      key: "output",
      label: "Output",
      questionId: "output",
    });

    if (!data.engagement_name) {
      stillNeeded.push("Mission record name");
      stillNeededDetails.push({
        key: "mission-record-name",
        label: "Mission record name",
        action: "advanced",
        advancedStep: 0,
      });
    }

    return {
      confirmed,
      inferred,
      stillNeeded,
      stillNeededDetails,
      plan,
    };
  }

  function applyConversationAnswer(questionId, answer) {
    const normalized = String(answer || "").trim();
    if (questionId === "intent") return applyIntentAnswer(normalized);
    if (questionId === "goal") return applyGoalAnswer(normalized);
    if (questionId === "output") return applyOutputAnswer(normalized);
    if (questionId === "scope") return applyScopeAnswer(normalized);
    if (questionId === "auth") return applyAuthAnswer(normalized);
    if (questionId === "auth-details") return applyAuthDetailsAnswer(normalized);
    if (questionId === "safety") return applySafetyAnswer(normalized);
    if (questionId === "boundaries") return applyBoundariesAnswer(normalized);
    return { ok: true, message: "Understood." };
  }

  function applyIntentAnswer(answer) {
    const wizard = state.wizard;
    const previousNameContext = snapshotEngagementNameContext(wizard.data);
    wizard.data.intake_preferences.mission_intent = answer;
    wizard.intake.sources.intent = "confirmed";

    const inferredType = inferAssessmentType(answer);
    if (inferredType) {
      wizard.data.assessment_type = inferredType;
      if (!wizard.intake.overrides.profile && !wizard.intake.overrides.modules && !wizard.intake.overrides.safety) {
        applyAssessmentTypePreset(inferredType);
      }
      wizard.intake.sources.target_type = "confirmed";
    }

    const inferredGoal = inferPrimaryGoal(answer);
    if (inferredGoal) {
      setGoalRecommendation(inferredGoal, "confirmed");
    }

    const outputStyle = inferOutputStyle(answer);
    if (outputStyle) {
      wizard.data.intake_preferences.output_style = outputStyle;
      wizard.intake.sources.output = "confirmed";
    }

    const authStrategy = inferAuthStrategy(answer);
    if (authStrategy) {
      wizard.data.intake_preferences.auth_strategy = authStrategy;
      wizard.intake.sources.auth = "confirmed";
    }

    const lateral = inferLateralDiscovery(answer);
    if (lateral) {
      wizard.data.intake_preferences.lateral_discovery = lateral;
      wizard.data.intake_preferences.boundary_handling = "";
      wizard.intake.sources.boundaries = "still-needed";
    }

    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, wizard.data);
    return {
      ok: true,
      message: `Understood. I am preparing a ${wizard.data.assessment_type.toLowerCase()} intake${inferredGoal ? ` with a ${humanizeGoal(inferredGoal).toLowerCase()} goal` : ""}.`,
    };
  }

  function applyGoalAnswer(answer) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const goal = inferPrimaryGoal(answer);
    if (!goal) {
      return {
        ok: false,
        error: "Tell me whether you want an overview, inventory-first run, standard assessment, deep assessment, authenticated review, or adaptive testing.",
      };
    }
    const compatibility = setGoalRecommendation(goal, "confirmed");
    const outputStyle = inferOutputStyle(answer);
    if (outputStyle) {
      state.wizard.data.intake_preferences.output_style = outputStyle;
      state.wizard.intake.sources.output = "confirmed";
    }
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? compatibility.reason
        : `I will shape this as a ${humanizeGoal(goal).toLowerCase()} and keep the execution lane aligned with that intent.`,
    };
  }

  function applyOutputAnswer(answer) {
    const outputStyle = inferOutputStyle(answer);
    if (!outputStyle) {
      return {
        ok: false,
        error: "Tell me whether you want detailed per-item, balanced technical, technical detail, or executive-summary output.",
      };
    }
    state.wizard.data.intake_preferences.output_style = outputStyle;
    state.wizard.intake.sources.output = "confirmed";
    return {
      ok: true,
      message: `I will use ${humanizeOutputStyle(outputStyle).toLowerCase()} reporting for this mission.`,
    };
  }

  function applyScopeAnswer(answer) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const previousAssessmentType = state.wizard.data.assessment_type;
    const previousBoundaryRequirement = requiresExplicitBoundaryConfirmation(state.wizard.data);
    const previousBoundaryHandling = effectiveBoundaryHandling(state.wizard.data);
    const previousLateralDiscovery = state.wizard.data.intake_preferences.lateral_discovery;
    const previousHasExplicitBoundaryScope =
      countExplicitExclusions(state.wizard.data.exclusions || {}) > 0 ||
      hasBoundaryNotes(state.wizard.data.exclusions || {});
    if (containsUnauthorizedExpansion(answer)) {
      return {
        ok: false,
        error: "I need exact authorized targets. I will not expand to arbitrary public scope or “anything reachable” without explicit approved targets.",
      };
    }

    const parsed = parseTargetsFromText(answer);
    if (!flattenTargetValues(parsed).length) {
      return {
        ok: false,
        error: "I could not find a valid URL, domain, IP, CIDR, or API base URL in that answer. Please enter the exact approved targets.",
      };
    }

    state.wizard.data.targets = parsed;
    const inferredType = inferAssessmentTypeFromTargets(parsed);
    if (inferredType) {
      const changedType = inferredType !== state.wizard.data.assessment_type;
      if (changedType && !shouldPreserveAssessmentType(state.wizard.data.assessment_type, inferredType)) {
        state.wizard.data.assessment_type = inferredType;
        if (!state.wizard.intake.overrides.profile && !state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
          applyAssessmentTypePreset(inferredType);
        }
      }
      state.wizard.intake.sources.target_type = state.wizard.intake.sources.target_type === "still-needed" ? "inferred" : state.wizard.intake.sources.target_type;
    }
    const compatibility = reconcileGoalCompatibility("inferred");
    if (
      inferredType &&
      !state.wizard.intake.overrides.profile &&
      !state.wizard.intake.overrides.modules &&
      !state.wizard.intake.overrides.safety
    ) {
      applyGoalDrivenPlanDefaults();
    }
    resetBoundaryConfirmationAfterScopeChange({
      previousAssessmentType,
      previousBoundaryRequirement,
      previousBoundaryHandling,
      previousLateralDiscovery,
      previousHasExplicitBoundaryScope,
    });
    state.wizard.intake.sources.scope = "confirmed";
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `Scope recorded as ${renderTargetSummary(state.wizard.data.targets)}. ${compatibility.reason}`
        : `Scope recorded as ${renderTargetSummary(state.wizard.data.targets)}.`,
    };
  }

  function applyAuthAnswer(answer) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const strategy = inferAuthStrategy(answer);
    if (!strategy) {
      return {
        ok: false,
        error: "Tell me whether this should stay unauthenticated, whether you have accounts, whether you have API keys/tokens, or whether you will add access in advanced settings.",
      };
    }
    state.wizard.data.intake_preferences.auth_strategy = strategy;
    state.wizard.intake.sources.auth = "confirmed";
    if (strategy === "unauthenticated") {
      clearAccessContext();
      const downgraded = alignPlanForUnauthenticatedAccess();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      return {
        ok: true,
        message: downgraded
          ? "I will keep the assessment unauthenticated, clear the prior access context, and downgrade the mission to a compatible unauthenticated plan unless you add access later."
          : "I will keep the assessment unauthenticated unless you change that later.",
      };
    }
    if (strategy === "advanced-details") {
      const compatibility = reconcileGoalCompatibility("inferred");
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `${compatibility.reason} Add the account, token, or session details in Advanced Configuration and I will keep the conversational summary synchronized.`
          : "Understood. Add the account, token, or session details in Advanced Configuration and I will keep the conversational summary synchronized.",
      };
    }
    const compatibility = reconcileGoalCompatibility("inferred");
    state.wizard.intake.activeQuestionId = "auth-details";
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `${compatibility.reason} I will capture the access context next so the run and replay lane know what to use.`
        : "Understood. I will capture the access context next so the run and replay lane know what to use.",
    };
  }

  function applyAuthDetailsAnswer(answer) {
    const strategy = inferAuthStrategy(answer);
    // At the detail step, only a true withdrawal back to unauthenticated should
    // bypass detail parsing. Token/session keywords may legitimately appear
    // inside the secret reference itself (for example `vault://.../updated-token`).
    if (strategy === "unauthenticated") {
      return applyAuthAnswer(answer);
    }

    if (/advanced settings/i.test(answer)) {
      state.wizard.data.intake_preferences.auth_strategy = "advanced-details";
      state.wizard.intake.advancedOpen = true;
      state.wizard.advancedStep = 2;
      return {
        ok: true,
        message: "Understood. I opened Advanced Configuration on Access so you can add the required detail before confirmation.",
      };
    }

    const existingAccess = state.wizard.data.access || {};
    const meaningfulAccounts = (existingAccess.accounts || []).filter((account) =>
      hasMeaningfulAccount([account]),
    );
    const sharedManualOnlyRoute =
      !meaningfulAccounts.length &&
      String(state.wizard.data.intake_preferences.auth_strategy || "").trim() === "credentialed" &&
      stringValue(existingAccess.manual_auth_steps);
    const sharedSessionOnlyRoute =
      !meaningfulAccounts.length &&
      String(state.wizard.data.intake_preferences.auth_strategy || "").trim() === "session-access" &&
      stringValue(existingAccess.cookie_notes);
    const noteOnlyRevisionAnswer = !looksLikeStructuredAccessDetail(answer);
    if (sharedManualOnlyRoute && noteOnlyRevisionAnswer) {
      state.wizard.data.access.accounts = [];
      state.wizard.data.access.manual_auth_steps = stringValue(answer);
      state.wizard.data.access.cookie_notes = "";
      state.wizard.intake.sources.auth = "confirmed";
      const compatibility = reconcileGoalCompatibility("inferred");
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `Shared manual auth guidance updated. ${compatibility.reason}`
          : "Shared manual auth guidance updated.",
      };
    }
    if (sharedSessionOnlyRoute && noteOnlyRevisionAnswer) {
      state.wizard.data.access.accounts = [];
      state.wizard.data.access.manual_auth_steps = "";
      state.wizard.data.access.cookie_notes = stringValue(answer);
      state.wizard.intake.sources.auth = "confirmed";
      const compatibility = reconcileGoalCompatibility("inferred");
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `Shared session guidance updated. ${compatibility.reason}`
          : "Shared session guidance updated.",
      };
    }
    const account = buildAccountFromFreeText(answer);
    if (!hasMeaningfulAccount([account])) {
      return {
        ok: false,
        error: "I still need at least a username, token reference, session reference, or password reference for an authenticated run.",
      };
    }
    state.wizard.data.access.accounts = [account];
    state.wizard.data.intake_preferences.auth_strategy =
      account.api_key_ref || account.bearer_token_ref
        ? "api-access"
        : account.session_ref
          ? "session-access"
          : "credentialed";
    state.wizard.intake.sources.auth = "confirmed";
    const compatibility = reconcileGoalCompatibility("inferred");
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `Access context recorded for ${account.label || account.username || "the provided account"}. ${compatibility.reason}`
        : `Access context recorded for ${account.label || account.username || "the provided account"}.`,
    };
  }

function applySafetyAnswer(answer) {
  const repeatedAuthStrategy = inferAuthStrategy(answer);
  if (repeatedAuthStrategy) {
    const currentAuthStrategy = String(state.wizard.data.intake_preferences.auth_strategy || "").trim();
    const currentAccessSummary =
      currentAuthStrategy === "unauthenticated"
        ? "unauthenticated"
        : summarizeAuthStrategy(state.wizard.data).toLowerCase();
    return {
      ok: false,
      error:
        repeatedAuthStrategy === currentAuthStrategy
          ? `Access is already set to ${currentAccessSummary}. Next I need a safety choice such as Conservative, Balanced, Thorough, Passive only, or Aggressive with approval.`
          : "That answer changes access, but the current question is about safety. Use Change Access if you want to revise access, or answer Conservative, Balanced, Thorough, Passive only, or Aggressive with approval.",
    };
  }
  const posture = inferSafetyPosture(answer);
  if (!posture) {
    return {
      ok: false,
        error: "Tell me whether this should stay conservative, balanced, thorough, passive only, or aggressive with approval.",
      };
    }
    state.wizard.data.intake_preferences.safety_posture = posture;
    applySafetyPreference(posture);
    enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
    state.wizard.intake.sources.safety = "confirmed";
    const stagedDiscoveryPlan = stagedDiscoveryCompatibility(state.wizard.data);
    return {
      ok: true,
      message: posture === "aggressive"
        ? "I will mark this as an approval-aware aggressive posture. Active checks still remain bounded by the configured lane and authorized scope."
        : stagedDiscoveryPlan?.profile === "External Surface Only"
          ? `I will keep the perimeter discovery run ${humanizeSafetyPosture(posture).toLowerCase()} while the first run remains passive discovery only.`
        : `I will keep the run ${humanizeSafetyPosture(posture).toLowerCase()}.`,
    };
  }

  function applyBoundariesAnswer(answer) {
    const repeatedAuthStrategy = inferAuthStrategy(answer);
    if (repeatedAuthStrategy) {
      const currentAuthStrategy = String(state.wizard.data.intake_preferences.auth_strategy || "").trim();
      const currentAccessSummary =
        currentAuthStrategy === "unauthenticated"
          ? "unauthenticated"
          : summarizeAuthStrategy(state.wizard.data).toLowerCase();
      const boundaryGuidance = summarizeBoundaryReplyOptions(state.wizard.data.assessment_type);
      return {
        ok: false,
        error:
          repeatedAuthStrategy === currentAuthStrategy
            ? `Access is already set to ${currentAccessSummary}. Next I need boundary guidance such as ${boundaryGuidance}.`
            : `That answer changes access, but the current question is about boundaries. Use Change Access if you want to revise access, or answer ${boundaryGuidance}.`,
      };
    }

    const repeatedSafety = inferStandaloneSafetyAnswer(answer);
    if (repeatedSafety) {
      const currentSafety = String(state.wizard.data.intake_preferences.safety_posture || "").trim();
      const boundaryGuidance = summarizeBoundaryReplyOptions(state.wizard.data.assessment_type);
      return {
        ok: false,
        error:
          repeatedSafety === currentSafety
            ? `Safety is already set to ${humanizeSafetyPosture(repeatedSafety).toLowerCase()}. Next I need boundary guidance such as ${boundaryGuidance}.`
            : `That answer changes safety, but the current question is about boundaries. Use Change Safety if you want to revise safety, or answer ${boundaryGuidance}.`,
      };
    }

    if (/no extra exclusions|no exclusions|nothing extra/i.test(answer)) {
      state.wizard.data.exclusions = buildEmptyExclusions();
      state.wizard.data.intake_preferences.boundary_handling = "standard-scope-only";
      state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
      state.wizard.intake.sources.boundaries = "confirmed";
      return {
        ok: true,
        message: "Understood. I will keep the mission inside the exact approved scope with no extra exclusions.",
      };
    }

    if (/adjacent internal|report adjacent|reachable internal ranges|lateral/i.test(answer)) {
      state.wizard.data.exclusions = buildEmptyExclusions();
      state.wizard.data.intake_preferences.boundary_handling = "report-adjacent-ranges-only";
      state.wizard.data.intake_preferences.lateral_discovery = "report-only";
      state.wizard.intake.sources.boundaries = "confirmed";
      return {
        ok: true,
        message: "Understood. I will keep discovery inside the approved scope and only report adjacent reachable internal ranges for explicit follow-up approval.",
      };
    }

    const exclusions = parseTargetsFromText(answer);
    const hasStructuredExclusions = flattenTargetValues(exclusions).length > 0;
    state.wizard.data.exclusions = {
      ...buildEmptyExclusions(),
      ...exclusions,
      notes: answer,
    };
    state.wizard.data.intake_preferences.boundary_handling = hasStructuredExclusions ? "custom-exclusions" : "notes-only-boundaries";
    state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
    state.wizard.intake.sources.boundaries = "confirmed";
    return {
      ok: true,
      message: hasStructuredExclusions
        ? "Understood. I recorded structured exclusions and boundary notes."
        : "Understood. I recorded those boundary notes for confirmation and reporting context.",
    };
  }

  function parseConversationCommand(answer) {
    const normalized = String(answer || "").trim().toLowerCase().replace(/\s+/g, " ");
    const cleaned = normalized.replace(/[.!?]+$/g, "").trim();
    const politeTrimmed = cleaned
      .replace(/^please\s+/, "")
      .replace(/\s+please$/, "")
      .trim();

    if (["go back", "undo", "previous", "change that"].includes(politeTrimmed)) {
      return { type: "back" };
    }

    const revisionMatch = politeTrimmed.match(/^(change|edit|revise)\s+([a-z -]+)$/);
    if (!revisionMatch) return null;

    const target = revisionMatch[2].trim();
    const targetGroups = [
      ["scope", ["scope", "target", "targets"]],
      ["goal", ["goal", "depth", "profile"]],
      ["output", ["output", "output style", "reporting", "reporting style", "report", "report style", "format"]],
      ["auth", ["access", "auth", "credential", "credentials", "token", "tokens", "session", "sessions"]],
      ["safety", ["safety", "careful", "conservative", "aggressive", "thorough"]],
      ["boundaries", ["exclude", "excludes", "exclusion", "exclusions", "boundary", "boundaries", "avoid", "lateral"]],
    ];
    const matchedGroup = targetGroups.find(([, aliases]) => aliases.includes(target));
    if (!matchedGroup) return null;

    return { type: "focus", questionId: matchedGroup[0] };
  }

  function handleConversationCommand(answer) {
    const command = parseConversationCommand(answer);
    if (!command) return false;
    if (command.type === "back") {
      goBackConversation();
      return true;
    }
    if (command.type === "focus") {
      focusQuestion(resolveConversationTopicQuestionId(command.questionId));
      return true;
    }
    return false;
  }

  function markAdvancedOverrideForStep(step) {
    const overrides = state.wizard.intake.overrides;
    if (step === 0) {
      overrides.mission = true;
      state.wizard.intake.sources.intent = "override";
      state.wizard.intake.sources.target_type = "override";
    } else if (step === 1) {
      overrides.scope = true;
      overrides.boundaries = true;
      state.wizard.intake.sources.scope = "override";
      state.wizard.intake.sources.boundaries = "override";
    } else if (step === 2) {
      overrides.access = true;
      state.wizard.intake.sources.auth = "override";
    } else if (step === 3) {
      overrides.profile = true;
      state.wizard.intake.sources.goal = "override";
    } else if (step === 4) {
      overrides.modules = true;
      state.wizard.intake.sources.goal = "override";
    } else if (step === 5) {
      overrides.safety = true;
      state.wizard.intake.sources.safety = "override";
    }
  }

  function markMissionContextOverrideOnly() {
    state.wizard.intake.overrides.mission = true;
  }

  function onAdvancedInput(event) {
    if (state.wizard.advancedStep === 0 && event.target.name === "wizard-assessment-type") {
      const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
      syncWizardStepFromDom();
      if (!state.wizard.intake.overrides.profile && !state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
        applyAssessmentTypePreset(state.wizard.data.assessment_type);
      }
      markAdvancedOverrideForStep(0);
      syncConversationMetadataFromData();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      realignConversationAfterAdvancedChange();
      state.wizard.errors = validationErrorsForQuestion(
        state.wizard,
        state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
      );
      renderWizard();
      return;
    }
    if (
      state.wizard.advancedStep === 0 &&
      (event.target.id === "wizard-use-existing" ||
        ["wizard-engagement-name", "wizard-client", "wizard-roe-ref"].includes(event.target.id))
    ) {
      syncWizardStepFromDom();
      markMissionContextOverrideOnly();
      syncConversationMetadataFromData();
      dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data), buildConversationContext());
      return;
    }
    if (state.wizard.advancedStep === 3 && event.target.name === "wizard-test-profile") {
      const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
      syncWizardStepFromDom();
      if (!state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
        applyProfilePreset(state.wizard.data.test_profile);
      }
      markAdvancedOverrideForStep(3);
      syncConversationMetadataFromData();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      realignConversationAfterAdvancedChange();
      state.wizard.errors = validationErrorsForQuestion(
        state.wizard,
        state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
      );
      renderWizard();
      return;
    }
    const previousNameContext = state.wizard.advancedStep === 1
      ? snapshotEngagementNameContext(state.wizard.data)
      : null;
    syncWizardStepFromDom();
    markAdvancedOverrideForStep(state.wizard.advancedStep);
    syncConversationMetadataFromData();
    if (previousNameContext) {
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    }
    realignConversationAfterAdvancedChange();
    state.wizard.errors = validationErrorsForQuestion(
      state.wizard,
      state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
    );
    dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data), buildConversationContext());
  }

  function draftAnswerForQuestion(questionId) {
    const data = state.wizard.data;
    if (questionId === "intent") return data.intake_preferences.mission_intent || "";
    if (questionId === "goal") return humanizeGoal(data.intake_preferences.primary_goal);
    if (questionId === "output") return humanizeOutputStyle(data.intake_preferences.output_style);
    if (questionId === "scope") return flattenTargetValues(data.targets).join("\n");
    if (questionId === "auth") return draftAuthStrategyText(data);
    if (questionId === "auth-details") return draftAuthDetailsText(data.access);
    if (questionId === "safety") return humanizeSafetyPosture(data.intake_preferences.safety_posture);
    if (questionId === "boundaries") return draftBoundariesText(data);
    return "";
  }

  function wizardStepContent(step, data, useExistingEngagement) {
    if (step === 0) {
      const selectedEngagement = runtime.actions.selectedEngagement?.();
      return `
        <div class="wizard-panel-grid">
          <div class="stack-form">
            <label class="field">
              ${fieldLabel(
                "Mission Mode",
                "Choose whether this wizard should create a brand-new engagement dossier or add a new run under the engagement already selected in the left rail."
              )}
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
                ${fieldLabel(
                  "Engagement Name",
                  "Use a name a human can immediately recognize later in Explorer, Reports, and History. Example: customer plus scope or objective."
                )}
                <input id="wizard-engagement-name" data-testid="wizard-engagement-name" type="text" value="${escapeHtml(data.engagement_name)}" placeholder="Acme External Validation" />
                ${fieldHelp("Give the mission a recognizable dossier name, for example customer plus scope or objective.")}
              </label>
              <label class="field">
                ${fieldLabel(
                  "Customer",
                  "This appears in dossiers and report headers so operators and recipients can see which customer the run belongs to."
                )}
                <input id="wizard-client" data-testid="wizard-client" type="text" value="${escapeHtml(data.client)}" placeholder="Acme Corp" />
                ${fieldHelp("Used in the customer dossier and in generated report headers.")}
              </label>
              <label class="field">
                ${fieldLabel(
                  "ROE Reference",
                  "Link this run back to the Rules of Engagement, ticket, or approval reference so later reviews can see under which authorization the work happened."
                )}
                <input id="wizard-roe-ref" data-testid="wizard-roe-ref" type="text" value="${escapeHtml(data.roe_ref)}" placeholder="ROE-2026-200" />
                ${fieldHelp("Point to the Rules of Engagement, approval ticket, or engagement reference for auditability.")}
              </label>
            `}
          </div>
          <div class="stack-form">
            ${fieldLabel(
              "Assessment Type",
              "This controls which scope inputs are shown next and which execution lane is likely to be selected later.",
              "What changes?"
            )}
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
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Scope and Boundaries</h4>
            <p>These fields stay synchronized with the conversational intake. Use the top section for approved scope, and the lower section for exclusions or internal boundary notes.</p>
          </div>
          <div class="wizard-panel-grid">
          ${visibleGroups.includes("domains") ? textareaField("wizard-target-domains", "Domains", data.targets.domains, "example.com\nshop.example.com", "Enter bare hostnames without protocol. Use this for DNS and domain-scoped discovery.", "Bare domain names only, without https:// or paths.") : ""}
          ${visibleGroups.includes("subdomains") ? textareaField("wizard-target-subdomains", "Subdomains", data.targets.subdomains, "api.example.com\nadmin.example.com", "List known subdomains you already want in scope so discovery starts from explicit assets.", "Known child hostnames such as api.example.com or admin.example.com.") : ""}
          ${visibleGroups.includes("urls") ? textareaField("wizard-target-urls", "URLs", data.targets.urls, "https://example.com\nhttps://example.com/login", "Use full URLs including protocol when you want page or route level web validation.", "Full application or page URLs, including https:// and optional path.") : ""}
          ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-target-ip-addresses", "IP Addresses", data.targets.ip_addresses, "203.0.113.5\n203.0.113.8", "Use individual hosts when the scope is defined as explicit IPs rather than a whole range.", "One host per line. Use this for explicit WAN or LAN hosts.") : ""}
          ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-target-cidrs", "CIDR Ranges", data.targets.cidr_ranges, "10.10.0.0/24", "Use only approved network blocks here. CIDR ranges drive network discovery breadth and can increase runtime quickly.", "Only enter ranges that are explicitly allowed in scope, for example 10.10.0.0/24.") : ""}
          ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-target-api", "API Base URLs", data.targets.api_base_urls, "https://api.example.com/v1", "Use the base URL that API crawling and validation should start from, not every individual endpoint.", "Start point for API coverage, for example https://api.example.com/v1.") : ""}
          </div>
          <div class="detail-surface split-top">
            <h4>Exclusions and boundary handling</h4>
            <p class="micro-copy">${escapeHtml(boundaryNotesIntro(data.assessment_type))}</p>
          </div>
          <div class="wizard-panel-grid">
            ${visibleGroups.includes("domains") ? textareaField("wizard-exclude-domains", "Excluded Domains", data.exclusions.domains, "legacy.example.com", "Explicit domains that must stay out of scope even if operators mention them conversationally.", "Denied domains remain visible in the scope snapshot and confirmation summary.") : ""}
            ${visibleGroups.includes("urls") ? textareaField("wizard-exclude-urls", "Excluded URLs", data.exclusions.urls, "https://example.com/admin", "Specific URLs or app paths that should not be touched during this run.", "Useful for maintenance pages, admin consoles, or sensitive user journeys.") : ""}
            ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-exclude-ip-addresses", "Excluded IP Addresses", data.exclusions.ip_addresses, "10.0.20.10", "Individual hosts that must be avoided even when they sit inside an approved network block.", "Denied IPs are carried into the denylist scope snapshot.") : ""}
            ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-exclude-cidrs", "Excluded CIDR Ranges", data.exclusions.cidr_ranges, "10.0.21.0/24", "Internal ranges that must not be scanned or expanded into.", "Use this for known restricted network segments.") : ""}
            ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-exclude-api", "Excluded API Base URLs", data.exclusions.api_base_urls, "https://api.example.com/internal", "API roots or prefixes that are explicitly out of scope.", "These stay visible to operators and report consumers as deliberate exclusions.") : ""}
            <label class="field">
              ${fieldLabel("Boundary Notes", "Use notes for maintenance-sensitive systems, approved internal-expansion handling where applicable, or scope assumptions that should remain human-readable.")}
              <textarea id="wizard-boundary-notes" rows="4" placeholder="${escapeHtml(boundaryNotesPlaceholder(data.assessment_type))}">${escapeHtml(data.exclusions.notes || "")}</textarea>
              ${fieldHelp("These notes appear in the conversational confirmation summary and can be carried into the run configuration and reports.")}
            </label>
          </div>
        </div>
      `;
    }

    if (step === 2) {
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>What to provide here</h4>
            <p>Only add the identities, tokens, sessions, or manual auth notes the run really needs. Leave fields empty if they do not apply.</p>
            <p class="micro-copy">Direct secrets are allowed for operator practicality, but they are converted into protected secret bindings when the run is created.</p>
          </div>
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
                  ${fieldLabel("Label", "Human-friendly name for this identity inside the UI and report context, for example Analyst, Admin, or Read Only API User.")}
                  <input data-account-field="label" data-account-index="${index}" type="text" value="${escapeHtml(account.label)}" placeholder="Primary User" />
                  ${fieldHelp("Give the identity a short human label such as Analyst, Admin, or API User.")}
                </label>
                <label class="field">
                  ${fieldLabel("Username", "Optional if you only have a token or session. Fill it in when the operator should know which account is being used.")}
                  <input data-account-field="username" data-account-index="${index}" type="text" value="${escapeHtml(account.username)}" placeholder="tester@example.com" />
                  ${fieldHelp("Optional if you are authenticating with a token or session instead of a username/password.")}
                </label>
                <label class="field">
                  ${fieldLabel("Role", "Describe the privilege level this identity represents so findings and replay are easier to interpret later.")}
                  <input data-account-field="role" data-account-index="${index}" type="text" value="${escapeHtml(account.role)}" placeholder="Admin" />
                  ${fieldHelp("Examples: User, Analyst, Admin, Billing, Read Only API.")}
                </label>
                <label class="field">
                  ${fieldLabel("Password / Secret Reference", "Use a direct password only when necessary. Prefer an external pointer such as vault:// or env:// when your workflow already has one.")}
                  <input data-account-field="secret_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.secret_ref)}" placeholder="vault://prod/app/admin or direct secret" />
                  ${fieldHelp("Direct secrets are protected after creation. External references are preserved as references.")}
                </label>
                <label class="field">
                  ${fieldLabel("API Key Reference or Value", "Use this when the application or API authenticates with a static key instead of a user login.")}
                  <input data-account-field="api_key_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.api_key_ref)}" placeholder="vault://prod/api/key or direct key" />
                  ${fieldHelp("Fill only if the target uses API key authentication.")}
                </label>
                <label class="field">
                  ${fieldLabel("Bearer Token Reference or Value", "Use this for JWTs or bearer tokens that should seed authenticated API or application checks.")}
                  <input data-account-field="bearer_token_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.bearer_token_ref)}" placeholder="vault://prod/api/bearer or direct token" />
                  ${fieldHelp("Use this when you already have a bearer token and do not want the run to log in first.")}
                </label>
                <label class="field">
                  ${fieldLabel("Cookie / Session Reference or Material", "Use this when access depends on a captured session rather than a fresh login flow.")}
                  <input data-account-field="session_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.session_ref)}" placeholder="session-bundle-A or direct cookie material" />
                  ${fieldHelp("Helpful for SSO, handoff logins, or test accounts that rely on an existing browser session.")}
                </label>
                <label class="field">
                  ${fieldLabel("MFA Notes / Manual Auth Steps", "Document anything a human operator may need to complete before replay or authenticated validation works.")}
                  <textarea data-account-field="mfa_notes" data-account-index="${index}" rows="3" placeholder="Manual OTP or SSO handoff notes">${escapeHtml(account.mfa_notes)}</textarea>
                  ${fieldHelp("Examples: approve push notification, complete SSO handoff, or copy OTP from secure channel.")}
                </label>
              </div>
            </div>
          `).join("")}
          <div class="action-row">
            <button id="wizard-add-account-btn" class="action ghost" type="button">Add Account / Role</button>
          </div>
          <label class="field">
            ${fieldLabel("Shared Manual Auth Steps", "Use this for login choreography that applies to the whole run rather than to one specific account.")}
            <textarea id="wizard-manual-auth-steps" rows="3" placeholder="Manual login, device trust, or MFA sequencing">${escapeHtml(data.access.manual_auth_steps)}</textarea>
            ${fieldHelp("Examples: first visit must trust a device, or analyst must complete SSO before the session can be reused.")}
          </label>
          <label class="field">
            ${fieldLabel("Cookie / Session Notes", "Capture any notes about how the session was obtained, how long it stays valid, or when it must be refreshed.")}
            <textarea id="wizard-cookie-notes" rows="3" placeholder="Session capture notes or cookie replay guidance">${escapeHtml(data.access.cookie_notes)}</textarea>
            ${fieldHelp("Useful when the run depends on an imported cookie jar or a short-lived session.")}
          </label>
        </div>
      `;
    }

    if (step === 3) {
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Profile Presets</h4>
            <p>Changing the operator profile resets the module and safety defaults for that profile. You can fine-tune both in the next two steps.</p>
          </div>
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
        </div>
      `;
    }

    if (step === 4) {
      const estimate = estimateMission(data);
      const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Coverage Intent vs Runtime Lane</h4>
            <p>These toggles capture the coverage you want reflected in the mission record, UI summaries, and reports.</p>
            <p class="micro-copy">The enforced runtime lane for this mission is currently <strong>${escapeHtml(plan.profileName)}</strong> using ${escapeHtml(plan.toolsLabel)}.</p>
          </div>
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
        </div>
      `;
    }

    if (step === 5) {
      return `
        <div class="wizard-panel-grid">
          <label class="field">
            ${fieldLabel("Rate Limit (requests / second)", "The maximum pace the run should maintain against the target. Lower values are safer for fragile or shared environments.")}
            <input id="wizard-rate-limit" type="number" min="1" max="20" value="${escapeHtml(String(data.safety.rate_limit_rps))}" />
            ${fieldHelp("Set this lower when the environment is sensitive or the customer expects a cautious pace.")}
          </label>
          <label class="field">
            ${fieldLabel("Concurrency", "How many validations AegisPT may work on at once. Higher concurrency finishes faster but increases target load and log volume.")}
            <input id="wizard-concurrency" type="number" min="1" max="10" value="${escapeHtml(String(data.safety.concurrency))}" />
            ${fieldHelp("Use low concurrency for fragile apps, narrow maintenance windows, or sensitive internal segments.")}
          </label>
          <label class="field">
            ${fieldLabel("Time Budget (minutes)", "The expected operator-approved time envelope for this run before you review progress or stop it.")}
            <input id="wizard-time-budget" type="number" min="15" max="1440" value="${escapeHtml(String(data.safety.time_budget_minutes))}" />
            ${fieldHelp("This helps keep the run aligned with the engagement window and the ETA model.")}
          </label>
          <label class="field">
            ${fieldLabel("Active Checks", "Choose how invasive the run is allowed to become. Passive only observes. Guarded permits safer validation. Active allows deeper probing where approved.")}
            <select id="wizard-active-checks">
              ${[
                ["passive-only", "Passive Only"],
                ["guarded", "Guarded Active"],
                ["active", "Active Validation"],
              ].map(([value, label]) => `<option value="${value}" ${data.safety.active_checks === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
            </select>
            ${fieldHelp("Use Passive Only for reconnaissance and low-risk review, Guarded Active for common web validation, and Active Validation only when the ROE allows it.")}
          </label>
          <label class="field">
            ${fieldLabel("Adaptive Generation", "Allow AegisPT to prepare customer-specific pack proposals after inventory and relevance analysis, before deeper validation starts.")}
            <select id="wizard-adaptive-generation">
              <option value="true" ${data.safety.adaptive_generation ? "selected" : ""}>Enabled</option>
              <option value="false" ${!data.safety.adaptive_generation ? "selected" : ""}>Disabled</option>
            </select>
            ${fieldHelp("Enable this when you want inventory-driven pack planning. Disable it for fixed, baseline-only runs.")}
          </label>
          <label class="field">
            ${fieldLabel("Maximum Validation Depth", "Sets how far the run may go when the profile and safety posture still allow more coverage.")}
            <select id="wizard-max-depth">
              ${[
                ["light", "Light"],
                ["standard", "Standard"],
                ["deep", "Deep"],
              ].map(([value, label]) => `<option value="${value}" ${data.safety.max_validation_depth === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
            </select>
            ${fieldHelp("Light keeps validation short and cautious. Standard fits most work. Deep allows broader follow-up within the approved profile.")}
          </label>
        </div>
      `;
    }

    const estimate = estimateMission(data);
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const moduleLabels = enabledModules(data.modules);
    const accessSummary = renderAccessContextSummary(data.access);
    const accessContextCount = countMeaningfulAccessContexts(data.access);
    return `
      <div class="stack-zone" data-testid="wizard-review">
        <div class="detail-surface">
          <h4>Mission Review</h4>
          <p>${escapeHtml(data.assessment_type)} with the ${escapeHtml(data.test_profile)} operator profile will use the ${escapeHtml(plan.profileName)} execution lane.</p>
          <p>${escapeHtml(estimate.summary)}</p>
          ${renderBadgeList([
            renderTargetSummary(data.targets),
            `${accessContextCount} access context${accessContextCount === 1 ? "" : "s"}`,
            `${moduleLabels.length} enabled module${moduleLabels.length === 1 ? "" : "s"}`,
            `RPS ${data.safety.rate_limit_rps}`,
            `${humanizeCheckMode(data.safety.active_checks)}`,
            `${estimate.confidence} ETA confidence`,
          ], "compact-badge-list split-top")}
        </div>
        <div class="disclosure-grid">
          ${renderDisclosure({
            title: "Targets & Access",
            summary: `${renderTargetSummary(data.targets)} · ${accessSummary}`,
            open: true,
            body: `
              <div class="compact-definition-grid">
                <div><span>Targets</span><strong>${escapeHtml(renderTargetSummary(data.targets))}</strong></div>
                <div><span>Access</span><strong>${escapeHtml(accessSummary)}</strong></div>
                <div><span>Manual Auth</span><strong>${escapeHtml(data.access.manual_auth_steps || "Not provided")}</strong></div>
                <div><span>Session Notes</span><strong>${escapeHtml(data.access.cookie_notes || "Not provided")}</strong></div>
              </div>
            `,
          })}
          ${renderDisclosure({
            title: "Execution Lane & Coverage",
            summary: `${plan.profileName} · ${plan.toolsLabel} · ${moduleLabels.length} modules`,
            open: true,
            testId: "wizard-execution-lane",
            body: `
              <div class="compact-definition-grid">
                <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
                <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
                <div><span>Approvals</span><strong>${escapeHtml(String(plan.requiredApprovals))}</strong></div>
                <div><span>Coverage Intent</span><strong>${escapeHtml(moduleLabels.join(", ") || "None")}</strong></div>
              </div>
              <p class="micro-copy split-top">${escapeHtml(plan.description)}</p>
            `,
          })}
          ${renderDisclosure({
            title: "Safety & Launch Handoff",
            summary: `Budget ${data.safety.time_budget_minutes}m · depth ${humanizeDepthLabel(data.safety.max_validation_depth)} · adaptive ${data.safety.adaptive_generation ? "enabled" : "disabled"}`,
            open: true,
            body: `
              <div class="compact-definition-grid">
                <div><span>Rate Limit</span><strong>${escapeHtml(`${data.safety.rate_limit_rps} RPS`)}</strong></div>
                <div><span>Concurrency</span><strong>${escapeHtml(String(data.safety.concurrency))}</strong></div>
                <div><span>Time Budget</span><strong>${escapeHtml(`${data.safety.time_budget_minutes} minutes`)}</strong></div>
                <div><span>Check Mode</span><strong>${escapeHtml(humanizeCheckMode(data.safety.active_checks))}</strong></div>
                <div><span>Maximum Depth</span><strong>${escapeHtml(humanizeDepthLabel(data.safety.max_validation_depth))}</strong></div>
                <div><span>Adaptive Generation</span><strong>${escapeHtml(data.safety.adaptive_generation ? "Enabled" : "Disabled")}</strong></div>
              </div>
              <p class="micro-copy split-top">Confirming creates or reuses the engagement, stores this wizard configuration on the run record, seeds the inventory model from the reviewed scope, and opens Mission Control.</p>
              <p class="micro-copy">After Mission Control opens, press <strong>Start Validation</strong> to launch the queued checks with the scope and safety settings you chose here.</p>
            `,
          })}
        </div>
      </div>
    `;
  }

  function renderWizardSummary(wizard, estimate, context = buildConversationContext()) {
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const targetSummary = renderTargetSummary(wizard.data.targets);
    const targetDetails = flattenTargetValues(wizard.data.targets).join(", ") || "No targets recorded";
    const accessSummary = renderAccessContextSummary(wizard.data.access);
    const moduleLabels = enabledModules(wizard.data.modules);
    const accessContextCount = countMeaningfulAccessContexts(wizard.data.access);
    const summary = context.summary || buildSummaryBuckets(wizard, estimate);
    const confirmedItems = summary.confirmed.length ? summary.confirmed.slice(0, 6) : [];
    const stillNeededItems = summary.stillNeeded.length
      ? summary.stillNeeded
      : [context.confirmationReady ? "Nothing blocking confirmation" : "Continue the intake to confirm remaining assumptions"];
    const stillNeededActions = summary.stillNeededDetails || [];
    const currentQuestionIds = activeQuestionFamilyIds(context.question.id);
    const visibleStillNeededActions = stillNeededActions.filter((item) =>
      item.action === "advanced" || !currentQuestionIds.has(item.questionId)
    );
    const currentQuestionStillNeededLabels = labelsResolvedByActiveQuestion(summary, context.question.id);
    const visibleStillNeededActionLabels = new Set(visibleStillNeededActions.map((item) => item.label));
    const remainingStillNeededBadges = stillNeededItems
      .slice(1)
      .filter((item) => !visibleStillNeededActionLabels.has(item) && !currentQuestionStillNeededLabels.has(item));
    const advancedMissionOpen = wizard.intake.advancedOpen && wizard.advancedStep === 0;
    const advancedPlanningOpen = wizard.intake.advancedOpen && [0, 3, 4, 5].includes(wizard.advancedStep);
    const advancedLaneOpen = wizard.intake.advancedOpen && [3, 4, 5].includes(wizard.advancedStep);
    const targetTypeMeaningful =
      wizard.intake.sources.target_type !== "still-needed" ||
      wizard.intake.overrides.mission ||
      advancedMissionOpen;
    const profileMeaningful =
      wizard.intake.sources.goal !== "still-needed" ||
      advancedPlanningOpen ||
      wizard.intake.overrides.mission ||
      wizard.intake.overrides.profile ||
      wizard.intake.overrides.modules ||
      wizard.intake.overrides.safety;
    const safetyMeaningful =
      wizard.intake.sources.safety !== "still-needed" ||
      advancedMissionOpen ||
      advancedLaneOpen ||
      wizard.intake.overrides.mission ||
      wizard.intake.overrides.profile ||
      wizard.intake.overrides.modules ||
      wizard.intake.overrides.safety;
    const essentialsBadges = [];
    if (targetTypeMeaningful) essentialsBadges.push(wizard.data.assessment_type);
    if (profileMeaningful) {
      essentialsBadges.push(`${wizard.data.test_profile} profile`);
      essentialsBadges.push(plan.profileName);
    }
    if (targetTypeMeaningful && profileMeaningful && safetyMeaningful) {
      essentialsBadges.push(
        `${estimate.estimated_total_minutes}m ETA`,
        `${estimate.estimated_impact} impact`,
        `${estimate.confidence} confidence`,
      );
    }
    const essentialsMicrocopy = context.confirmationReady
      ? "Everything required for deterministic run creation is present."
      : essentialsBadges.length
        ? "The intake is updating the real run model in place while advanced overrides stay available."
        : "Mission type, profile, execution lane, and ETA appear here once the intake has enough confirmed or safely inferred context.";
    const coverageDetailsReady = profileMeaningful;
    const laneDetailsReady = targetTypeMeaningful && profileMeaningful;
    const coverageSummary = coverageDetailsReady
      ? `${wizard.data.test_profile === "Deep" ? "Deep Assessment" : `${wizard.data.test_profile} profile`} · ${humanizeCheckMode(wizard.data.safety.active_checks)} · Modules ${moduleLabels.length}`
      : "Waiting for mission shape";
    const coverageBody = coverageDetailsReady
      ? `
          <div class="compact-definition-grid">
            <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
            <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
            <div><span>Modules</span><strong>${escapeHtml(moduleLabels.join(", ") || "No modules enabled")}</strong></div>
            <div><span>Access Contexts</span><strong>${escapeHtml(String(accessContextCount))}</strong></div>
            <div><span>Rate / Concurrency</span><strong>${escapeHtml(`${wizard.data.safety.rate_limit_rps} RPS · ${wizard.data.safety.concurrency}`)}</strong></div>
            <div><span>Budget</span><strong>${escapeHtml(`${wizard.data.safety.time_budget_minutes} minutes`)}</strong></div>
            <div><span>Check Mode</span><strong>${escapeHtml(humanizeCheckMode(wizard.data.safety.active_checks))}</strong></div>
            <div><span>Adaptive</span><strong>${escapeHtml(wizard.data.safety.adaptive_generation ? "Enabled" : "Disabled")}</strong></div>
            <div><span>Goal</span><strong>${escapeHtml(humanizeGoal(wizard.data.intake_preferences.primary_goal))}</strong></div>
            <div><span>Output</span><strong>${escapeHtml(humanizeOutputStyle(wizard.data.intake_preferences.output_style))}</strong></div>
          </div>
        `
      : "<p class='micro-copy'>Coverage posture, execution lane, and ETA stay hidden here until the intake has enough confirmed or safely inferred mission context.</p>";
    const laneSummary = laneDetailsReady && safetyMeaningful
      ? `${plan.profileName} · approvals ${plan.requiredApprovals} · ${estimate.estimated_total_minutes}m`
      : "Waiting for mission shape";
    const laneBody = laneDetailsReady && safetyMeaningful
      ? `
          <div class="compact-definition-grid">
            <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
            <div><span>Approvals</span><strong>${escapeHtml(String(plan.requiredApprovals))}</strong></div>
            <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
            <div><span>ETA</span><strong>${escapeHtml(`${estimate.estimated_total_minutes} minutes`)}</strong></div>
            <div><span>Impact</span><strong>${escapeHtml(estimate.estimated_impact)}</strong></div>
            <div><span>Confidence</span><strong>${escapeHtml(estimate.confidence)}</strong></div>
          </div>
          <p class="micro-copy split-top">${escapeHtml(plan.description)}</p>
        `
      : "<p class='micro-copy'>AegisPT only surfaces the execution lane, approvals, ETA, impact, and confidence here once the intake has enough confirmed or safely inferred mission context.</p>";
    return `
      <div class="list-card" data-testid="wizard-summary-current">
        <h4>Current Essentials</h4>
        <p>${escapeHtml(readinessSummary(wizard.data))}</p>
        <p class="micro-copy">${escapeHtml(essentialsMicrocopy)}</p>
        ${renderBadgeList(essentialsBadges, "compact-badge-list split-top")}
      </div>
      <div class="detail-surface emphasis-surface wizard-summary-focus" data-testid="wizard-summary-needed">
        <h4>${escapeHtml(context.confirmationReady ? "Ready to Create" : "What Still Needs Confirmation")}</h4>
        <p>${escapeHtml(stillNeededItems[0])}</p>
        ${
          visibleStillNeededActions.length
            ? `<div class="chip-row split-top" data-testid="wizard-needed-actions">${visibleStillNeededActions.map((item) => item.action === "advanced"
                ? `<button class="action ghost quick-reply-chip" type="button" data-intake-advanced="true" ${item.advancedStep !== undefined ? `data-intake-advanced-step="${escapeHtml(String(item.advancedStep))}"` : ""} data-testid="wizard-needed-action-${escapeHtml(item.key)}">${escapeHtml(item.label)}</button>`
                : `<button class="action ghost quick-reply-chip" type="button" data-edit-question="${escapeHtml(item.questionId)}" data-testid="wizard-needed-action-${escapeHtml(item.key)}">${escapeHtml(item.label)}</button>`
              ).join("")}</div>`
            : ""
        }
        ${
          remainingStillNeededBadges.length
            ? `${renderBadgeList(remainingStillNeededBadges, "compact-badge-list split-top")}<p class="micro-copy split-top">The remaining items still need confirmation before the mission can be created cleanly.</p>`
            : visibleStillNeededActions.length
              ? `<p class="micro-copy split-top">Use the remaining quick actions to revise the other missing mission topics without losing the current intake path.</p>`
            : `<p class="micro-copy split-top">${escapeHtml(context.confirmationReady ? "Nothing blocking confirmation. You can confirm now or revise any topic first." : "This topic still needs confirmation before the mission can be created cleanly.")}</p>`
        }
      </div>
      <div class="detail-surface" data-testid="wizard-summary-confirmed">
        <h4>Mission Brief</h4>
        <p>${escapeHtml(summary.confirmed.length ? `${summary.confirmed.length} items are already locked into the deterministic run dossier.` : "Nothing confirmed yet.")}</p>
        ${
          confirmedItems.length
            ? `<div class="compact-definition-grid split-top">${confirmedItems.map((item, index) => `<div><span>Locked ${index + 1}</span><strong>${escapeHtml(item)}</strong></div>`).join("")}</div>`
            : "<p class='micro-copy split-top'>Confirmed intake items appear here as soon as the conversation or advanced configuration resolves them.</p>"
        }
        ${
          summary.confirmed.length > confirmedItems.length
            ? `<p class="micro-copy split-top">${escapeHtml(`${summary.confirmed.length - confirmedItems.length} additional confirmed item${summary.confirmed.length - confirmedItems.length === 1 ? "" : "s"} remain available in the detailed disclosures below.`)}</p>`
            : ""
        }
      </div>
      ${renderDisclosure({
        title: "Inferred",
        summary: summary.inferred.length ? `${summary.inferred.length} safe defaults proposed` : "No safe inferences active",
        open: false,
        testId: "wizard-summary-inferred",
        body: summary.inferred.length
          ? `<div class="compact-definition-grid">${summary.inferred.map((item, index) => `<div><span>Inference ${index + 1}</span><strong>${escapeHtml(item)}</strong></div>`).join("")}</div>`
          : "<p class='micro-copy'>When the intake can safely infer a profile, safety posture, or output style, it will show up here until you confirm or override it.</p>",
      })}
      ${wizard.lastCreated ? renderDisclosure({
        title: "Last Mission Created",
        summary: `${wizard.lastCreated.engagementName} · ${wizard.lastCreated.runId}`,
        open: false,
        body: `
          <div class="compact-definition-grid">
            <div><span>Engagement</span><strong>${escapeHtml(wizard.lastCreated.engagementName)}</strong></div>
            <div><span>Run</span><strong>${escapeHtml(wizard.lastCreated.runId)}</strong></div>
          </div>
        `,
      }) : ""}
      ${renderDisclosure({
        title: "Targets & Access",
        summary: `${targetSummary} · ${accessSummary}`,
        open: false,
        testId: "wizard-summary-targets",
        body: `
          <div class="compact-definition-grid">
            <div><span>Targets</span><strong>${escapeHtml(targetSummary)}</strong></div>
            <div><span>Target Detail</span><strong>${escapeHtml(targetDetails)}</strong></div>
            <div><span>Access Context</span><strong>${escapeHtml(accessSummary)}</strong></div>
            <div><span>Boundary Notes</span><strong>${escapeHtml(wizard.data.exclusions.notes || "Not provided")}</strong></div>
            <div><span>Denylist</span><strong>${escapeHtml(renderExclusionSummary(wizard.data.exclusions))}</strong></div>
            <div><span>Shared Auth Notes</span><strong>${escapeHtml(wizard.data.access.manual_auth_steps || "Not provided")}</strong></div>
            <div><span>Session Notes</span><strong>${escapeHtml(wizard.data.access.cookie_notes || "Not provided")}</strong></div>
          </div>
        `,
      })}
      ${renderDisclosure({
        title: "Coverage & Safety",
        summary: coverageSummary,
        open: false,
        testId: "wizard-summary-coverage",
        body: coverageBody,
      })}
      ${renderDisclosure({
        title: "Execution Lane & ETA",
        summary: laneSummary,
        open: false,
        testId: "wizard-summary-lane",
        body: laneBody,
      })}
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
    if (state.wizard.step === 0 && event.target.name === "wizard-assessment-type") {
      syncWizardStepFromDom();
      applyAssessmentTypePreset(state.wizard.data.assessment_type);
      renderWizard();
      return;
    }
    if (state.wizard.step === 3 && event.target.name === "wizard-test-profile") {
      syncWizardStepFromDom();
      applyProfilePreset(state.wizard.data.test_profile);
      renderWizard();
      return;
    }
    syncWizardStepFromDom();
    if (
      (state.wizard.step === 0 && event.target.id === "wizard-use-existing") ||
      (state.wizard.step === 2 && event.target.dataset.accountField === "label")
    ) {
      renderWizard();
    } else {
      dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data));
    }
  }

  function syncWizardStepFromDom(stepOverride = null) {
    const wizard = state.wizard;
    const data = wizard.data;
    const currentStep = stepOverride ?? currentWizardFormStep();
    const formRoot = document.getElementById("wizard-advanced-content") || dom.wizardPanel || document;

    if (currentStep === 0) {
      const useExisting = document.getElementById("wizard-use-existing");
      wizard.useExistingEngagement = Boolean(useExisting?.checked);
      data.engagement_name = stringValue(document.getElementById("wizard-engagement-name")?.value);
      data.client = stringValue(document.getElementById("wizard-client")?.value);
      data.roe_ref = stringValue(document.getElementById("wizard-roe-ref")?.value);
      data.assessment_type =
        document.querySelector('input[name="wizard-assessment-type"]:checked')?.value || data.assessment_type;
      return;
    }
    if (currentStep === 1) {
      data.targets = {
        domains: splitLines(document.getElementById("wizard-target-domains")?.value),
        subdomains: splitLines(document.getElementById("wizard-target-subdomains")?.value),
        urls: splitLines(document.getElementById("wizard-target-urls")?.value),
        ip_addresses: splitLines(document.getElementById("wizard-target-ip-addresses")?.value),
        cidr_ranges: splitLines(document.getElementById("wizard-target-cidrs")?.value),
        api_base_urls: splitLines(document.getElementById("wizard-target-api")?.value),
      };
      data.exclusions = {
        domains: splitLines(document.getElementById("wizard-exclude-domains")?.value),
        urls: splitLines(document.getElementById("wizard-exclude-urls")?.value),
        ip_addresses: splitLines(document.getElementById("wizard-exclude-ip-addresses")?.value),
        cidr_ranges: splitLines(document.getElementById("wizard-exclude-cidrs")?.value),
        api_base_urls: splitLines(document.getElementById("wizard-exclude-api")?.value),
        notes: stringValue(document.getElementById("wizard-boundary-notes")?.value),
      };
      const exclusionCount = countExplicitExclusions(data.exclusions);
      if (exclusionCount) {
        data.intake_preferences.boundary_handling = "custom-exclusions";
      } else if (hasBoundaryNotes(data.exclusions)) {
        data.intake_preferences.boundary_handling = "notes-only-boundaries";
      } else if (["custom-exclusions", "notes-only-boundaries"].includes(String(data.intake_preferences.boundary_handling || "").trim())) {
        data.intake_preferences.boundary_handling = "standard-scope-only";
      }
      return;
    }
    if (currentStep === 2) {
      const accounts = Array.from(formRoot.querySelectorAll("[data-account-card]")).map((card) => {
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
    if (currentStep === 3) {
      data.test_profile = document.querySelector('input[name="wizard-test-profile"]:checked')?.value || data.test_profile;
      return;
    }
    if (currentStep === 4) {
      MODULES.forEach(([key]) => {
        data.modules[key] = Boolean(formRoot.querySelector(`[data-module-key="${key}"]`)?.checked);
      });
      return;
    }
    if (currentStep === 5) {
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
      data.targets.urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid URL: ${value}`);
      });
      data.targets.api_base_urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid API base URL: ${value}`);
      });
      data.targets.ip_addresses.forEach((value) => {
        if (!isLikelyIp(value)) errors.push(`Invalid IP address: ${value}`);
      });
      data.targets.cidr_ranges.forEach((value) => {
        if (!isLikelyCidr(value)) errors.push(`Invalid CIDR range: ${value}`);
      });
      data.targets.domains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid domain: ${value}`);
      });
      data.targets.subdomains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid subdomain: ${value}`);
      });
      data.exclusions.urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid excluded URL: ${value}`);
      });
      data.exclusions.api_base_urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid excluded API base URL: ${value}`);
      });
      data.exclusions.ip_addresses.forEach((value) => {
        if (!isLikelyIp(value)) errors.push(`Invalid excluded IP address: ${value}`);
      });
      data.exclusions.cidr_ranges.forEach((value) => {
        if (!isLikelyCidr(value)) errors.push(`Invalid excluded CIDR range: ${value}`);
      });
      data.exclusions.domains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid excluded domain: ${value}`);
      });
      return [...new Set(errors)];
    }
    if (step === 2) {
      if (requiresCredentials(data) && !hasMeaningfulAccessContext(data.access)) {
        return ["This assessment profile needs at least one access context, shared manual-auth note, or session note."];
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
      if (configuration.intake?.engagement_context) {
        configuration.intake.engagement_context = {
          ...configuration.intake.engagement_context,
          engagement_id: engagement.id,
          engagement_name: engagement.name,
          client: engagement.client || configuration.intake.engagement_context.client || null,
          roe_ref: engagement.roe_ref || configuration.intake.engagement_context.roe_ref || null,
        };
      }

      const scopePayload = {
        allowlist_json: buildAllowlistFromWizard(state.wizard.data.targets),
        denylist_json: buildDenylistFromWizard(state.wizard.data.exclusions),
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
        `Mission ${engagement.name} created. Open Mission Control and press Start Validation to dispatch the queued run.`,
        "success"
      );
      if (!state.wizard.useExistingEngagement) {
        state.engagements = [
          engagement,
          ...state.engagements.filter((item) => String(item.id) !== String(engagement.id)),
        ];
      }
      state.selectedEngagementId = engagement.id;
      state.selectedRunId = run.id;
      state.selectedRun = {
        ...run,
        profile: run.profile || { name: estimate.execution_profile },
        tasks: Array.isArray(run.tasks) ? run.tasks : [],
        configuration_json: configuration,
      };
      state.selectedTaskId = state.selectedRun.tasks[0]?.id || null;
      state.selectedTask = state.selectedRun.tasks[0] || null;
      state.selectedFindingId = null;
      state.selectedFindingTheater = null;
      state.selectedFindingEvidence = null;
      state.reportCatalog = [];
      state.selectedPackBundle = null;
      state.selectedCodexContext = null;
      state.selectedCodexResult = null;
      state.mission = {
        scope: {
          allowlist_json: buildAllowlistFromWizard(state.wizard.data.targets),
          denylist_json: buildDenylistFromWizard(state.wizard.data.exclusions),
        },
        inventory: inventorySnapshot ? [inventorySnapshot] : [],
        relevance: [],
        packs:
          state.wizard.useExistingEngagement && String(runtime.actions.selectedEngagement?.()?.id || "") === String(engagement.id)
            ? state.mission.packs
            : [],
        runs: [state.selectedRun],
        internalValidations:
          state.wizard.useExistingEngagement && String(runtime.actions.selectedEngagement?.()?.id || "") === String(engagement.id)
            ? state.mission.internalValidations
            : [],
        findingsByRun: {
          [run.id]: [],
        },
      };
      state.wizard = buildEmptyWizardState();
      state.wizard.lastCreated = {
        engagementName: engagement.name,
        runId: run.id,
      };
      state.activeScreen = "mission-control";
      state.activePhase = "execution";
      runtime.actions.renderAll?.();
      await runtime.actions.refreshShell?.();
    } catch (error) {
      state.wizard.submitting = false;
      state.wizard.errors = [error.message || "Wizard submission failed."];
      renderWizard();
      throw error;
    }
  }

  return {
    goBackConversation,
    renderWizard,
    submitConversationAnswer,
    syncWizardStepFromDom,
    validateWizardStep,
    submitWizard,
  };
}

export function buildRunConfiguration(data, estimate) {
  const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
  const engagementRoute = currentEngagementRouteContext(data);
  return {
    assessment_type: data.assessment_type,
    test_profile: data.test_profile,
    execution_profile: estimate.execution_profile,
    execution_plan: {
      profile_name: plan.profileName,
      run_class: plan.runClass,
      planned_tools: plan.tools,
      required_approvals: plan.requiredApprovals,
      description: plan.description,
    },
    targets: data.targets,
    exclusions: data.exclusions,
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
    intake: {
      mode: "conversational-ai-guided",
      engagement_route: engagementRoute.mode,
      engagement_context: engagementRoute.configContext,
      preferences: data.intake_preferences,
      sources: state.wizard?.intake?.sources || {},
      advanced_overrides: state.wizard?.intake?.overrides || {},
      confirmation_summary: buildNaturalConfirmationSummary(estimate, data),
    },
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

function buildDenylistFromWizard(exclusions) {
  return {
    domains: [...(exclusions?.domains || [])].filter(Boolean),
    urls: [...(exclusions?.urls || []), ...(exclusions?.api_base_urls || [])].filter(Boolean),
    hosts: [...(exclusions?.ip_addresses || [])].filter(Boolean),
    cidrs: [...(exclusions?.cidr_ranges || [])].filter(Boolean),
    notes: exclusions?.notes ? [exclusions.notes] : [],
  };
}

function currentEngagementRouteContext(data = state.wizard?.data || {}) {
  const selectedEngagement = state.wizard?.useExistingEngagement
    ? runtime.actions.selectedEngagement?.()
    : null;
  if (state.wizard?.useExistingEngagement) {
    const engagementName = selectedEngagement?.name || data.engagement_name || "Selected engagement";
    return {
      mode: "reuse-selected-engagement",
      summaryLabel: `Reuse existing dossier · ${engagementName}`,
      configContext: {
        source: "selected-engagement",
        engagement_id: selectedEngagement?.id || null,
        engagement_name: engagementName,
        client: selectedEngagement?.client || null,
        roe_ref: selectedEngagement?.roe_ref || null,
      },
    };
  }
  const engagementName = data.engagement_name || suggestedEngagementName(data);
  return {
    mode: "create-new-engagement",
    summaryLabel: `Create new dossier · ${engagementName}`,
    configContext: {
      source: "wizard-created-engagement",
      engagement_id: null,
      engagement_name: engagementName,
      client: valueOrNull(data.client),
      roe_ref: valueOrNull(data.roe_ref),
    },
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
          endpoints: urls.map((url) => ({
            url,
            methods: [],
            status_code: null,
            title: "Wizard-seeded target",
          })),
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
      `Conversation goal: ${humanizeGoal(data.intake_preferences.primary_goal)}`,
      `Safety posture: ${humanizeSafetyPosture(data.intake_preferences.safety_posture)}`,
      `Output style: ${humanizeOutputStyle(data.intake_preferences.output_style)}`,
      data.exclusions.notes ? `Boundary notes: ${data.exclusions.notes}` : "No boundary notes provided.",
    ],
    assumptions: [
      "Seed inventory was created from operator-reviewed wizard input before active discovery.",
      data.intake_preferences.boundary_handling
        ? `Boundary handling: ${data.intake_preferences.boundary_handling}`
        : "Boundary handling not explicitly set.",
      data.intake_preferences.lateral_discovery
        ? `Lateral discovery posture: ${data.intake_preferences.lateral_discovery}`
        : "Lateral discovery not requested.",
      data.access.manual_auth_steps ? `Manual auth note: ${data.access.manual_auth_steps}` : "No shared manual auth note provided.",
    ],
  };
}

export function estimateMission(data) {
  const targetsCount = flattenTargetValues(data.targets).length;
  const moduleCount = enabledModules(data.modules).length;
  const accessContextCount = countMeaningfulAccessContexts(data.access);
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
  const base = 24 + targetsCount * 9 + moduleCount * 4 + accessContextCount * 10 + (data.safety.adaptive_generation ? 14 : 0);
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
  if (data.assessment_type === "Internal Range / LAN" || data.assessment_type === "External IP / WAN") {
    if (data.test_profile === "Internal Validation") return "passive-network-discovery";
    return "passive-network-discovery";
  }
  if (data.test_profile === "Internal Validation") return "intrusive-validation";
  if (data.safety.active_checks === "active" && data.modules.zap_active_checks) return "active-web-zap-active";
  if (
    data.safety.active_checks !== "passive-only" &&
    (
      data.test_profile === "Deep" ||
      data.test_profile === "Authenticated Only" ||
      data.test_profile === "Adaptive Customer-Specific Mode" ||
      data.assessment_type === "Authenticated App" ||
      data.modules.zap_active_checks
    )
  ) {
    return "active-web-safe";
  }
  if (data.test_profile === "SSL/TLS Only") return "passive-web-baseline";
  if (data.test_profile === "Standard" && data.modules.nuclei_checks) return "passive-web-nuclei-audit";
  if (data.test_profile === "Light" || data.test_profile === "External Surface Only") return "passive-web-baseline";
  return "passive-web-baseline";
}

function moduleState(enabledKeys = []) {
  const modules = Object.fromEntries(
    Object.keys(DEFAULT_MODULE_STATE).map((key) => [key, false])
  );
  enabledKeys.forEach((key) => {
    if (Object.hasOwn(modules, key)) {
      modules[key] = true;
    }
  });
  return modules;
}

function profileModulePreset(profile) {
  const presets = {
    "Light": moduleState(["discovery", "web_crawling", "nuclei_checks", "ssl_tls_analysis"]),
    "Standard": { ...DEFAULT_MODULE_STATE },
    "Deep": moduleState([
      "discovery",
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "zap_active_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
      "adaptive_ai_generated_tests",
    ]),
    "External Surface Only": moduleState([
      "discovery",
      "web_crawling",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
    ]),
    "Authenticated Only": moduleState([
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
    ]),
    "SSL/TLS Only": moduleState(["ssl_tls_analysis"]),
    "Internal Validation": moduleState([
      "discovery",
      "auth_flows",
      "nuclei_checks",
      "zap_active_checks",
      "business_logic_testing",
      "internal_validation_modules",
    ]),
    "Adaptive Customer-Specific Mode": moduleState([
      "discovery",
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
      "adaptive_ai_generated_tests",
    ]),
  };
  return { ...(presets[profile] || DEFAULT_MODULE_STATE) };
}

function profileSafetyPreset(profile) {
  const presets = {
    "Light": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Deep": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: true,
      max_validation_depth: "deep",
    },
    "External Surface Only": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Authenticated Only": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: false,
      max_validation_depth: "standard",
    },
    "SSL/TLS Only": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Internal Validation": {
      ...DEFAULT_SAFETY,
      active_checks: "active",
      adaptive_generation: false,
      max_validation_depth: "deep",
    },
    "Adaptive Customer-Specific Mode": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: true,
      max_validation_depth: "deep",
    },
  };
  return { ...(presets[profile] || DEFAULT_SAFETY) };
}

function assessmentTypeProfileRecommendation(assessmentType) {
  const mapping = {
    "Website / Web App": "Standard",
    "Domain / Domains": "External Surface Only",
    "External IP / WAN": "External Surface Only",
    "Internal Range / LAN": "Standard",
    "API": "Standard",
    "SSL/TLS Only": "SSL/TLS Only",
    "Authenticated App": "Authenticated Only",
    "Mixed Assessment": "Adaptive Customer-Specific Mode",
  };
  return mapping[assessmentType] || "Standard";
}

function applyProfilePreset(profile) {
  const modules = profileModulePreset(profile);
  const safety = profileSafetyPreset(profile);
  Object.assign(state.wizard.data.modules, modules);
  Object.assign(state.wizard.data.safety, safety);
}

function applyAssessmentTypePreset(assessmentType) {
  const recommendation = assessmentTypeProfileRecommendation(assessmentType);
  state.wizard.data.test_profile = recommendation;
  applyProfilePreset(recommendation);

  if (assessmentType === "External IP / WAN") {
    Object.assign(state.wizard.data.modules, moduleState(["discovery", "ssl_tls_analysis"]));
    Object.assign(state.wizard.data.safety, {
      ...state.wizard.data.safety,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    });
    return;
  }

  if (assessmentType === "Internal Range / LAN") {
    Object.assign(state.wizard.data.modules, moduleState(["discovery"]));
    Object.assign(state.wizard.data.safety, {
      ...state.wizard.data.safety,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    });
    return;
  }

  if (assessmentType === "API") {
    Object.assign(
      state.wizard.data.modules,
      moduleState([
        "discovery",
        "nuclei_checks",
        "ssl_tls_analysis",
        "adaptive_ai_generated_tests",
      ])
    );
    return;
  }

  if (assessmentType === "Mixed Assessment") {
    Object.assign(
      state.wizard.data.modules,
      moduleState([
        "discovery",
        "web_crawling",
        "content_discovery",
        "nuclei_checks",
        "ssl_tls_analysis",
        "adaptive_ai_generated_tests",
      ])
    );
  }
}

function wizardStepLead(step) {
  const leads = [
    {
      title: "Choose the mission shape",
      body: "Set whether you are launching a new mission dossier or adding a new mission to an existing engagement, then choose the assessment type that best matches the target surface.",
      ask: "Name the engagement and choose the assessment type that best matches the surface you want to validate.",
      why: "This decides what scope fields appear next, how the run is classified, and which execution lane is most likely to be used.",
    },
    {
      title: "Define exactly what is in scope",
      body: "Add only the targets that should enter inventory and validation. The wizard validates core formats before anything becomes part of the mission record.",
      ask: "Provide the domains, URLs, IPs, CIDRs, or API base URLs that are explicitly allowed in scope.",
      why: "These values seed inventory, target selection, and later evidence and reporting. Over-scoping here creates noisy or risky validation later.",
    },
    {
      title: "Record access context safely",
      body: "Store operator-facing references or direct secrets. Sensitive values are moved behind protected secret bindings when the run is created.",
      ask: "Add only the credentials, sessions, or manual auth notes needed for the selected assessment profile.",
      why: "Authenticated context changes what the run can see, which findings are reachable, and how replay works later.",
    },
    {
      title: "Pick the right depth",
      body: "The test profile shapes execution safety, likely ETA, and how much adaptive testing or active validation the mission is allowed to perform.",
      ask: "Choose how deep or specialized the run should be: light, standard, deep, authenticated, TLS-only, or adaptive.",
      why: "This is the fastest way to align coverage depth with customer appetite, target sensitivity, and the expected run duration.",
    },
    {
      title: "Enable only the modules that matter",
      body: "Turn on the validation lanes you actually want. The module set directly feeds run configuration, mission progress, ETA, and reporting coverage.",
      ask: "Keep the modules that matter for this engagement and disable anything that is out of scope or not worth the runtime cost.",
      why: "Cleaner module selection produces clearer progress, less noise, and more explainable reports for the operator and customer.",
    },
    {
      title: "Set guardrails before launch",
      body: "Tune rate, concurrency, validation depth, and active-check posture so the mission stays controlled and aligned with the rules of engagement.",
      ask: "Set the pace, allowed aggressiveness, adaptive behavior, and maximum depth the run may use.",
      why: "These controls make the run safer, easier to explain, and easier to stop before it exceeds the engagement intent.",
    },
    {
      title: "Confirm what will happen next",
      body: "Review the full mission configuration before confirmation. AegisPT will create or reuse the engagement, seed inventory, create the mission record, and open Mission Control.",
      ask: "Check that the targets, access, modules, and safety settings match what you actually want to run.",
      why: "This is the last point where a human can spot a wrong target, too much depth, or the wrong access context before work is queued.",
    },
  ];
  return leads[step] || leads[0];
}

function renderWizardGuidance(lead) {
  if (!lead.ask && !lead.why) return "";
  return `
    <div class="wizard-guidance">
      <div class="guidance-card">
        <h4>What This Step Asks For</h4>
        <p>${escapeHtml(lead.ask || "Review the visible fields and provide only what this mission needs.")}</p>
      </div>
      <div class="guidance-card">
        <h4>Why It Matters</h4>
        <p>${escapeHtml(lead.why || "This input affects later execution, reporting, and evidence handling.")}</p>
      </div>
    </div>
  `;
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

function currentWizardFormStep() {
  const advancedStep = Number(state.wizard?.advancedStep);
  if (Number.isInteger(advancedStep) && advancedStep >= 0) return advancedStep;
  const step = Number(state.wizard?.step);
  return Number.isInteger(step) && step >= 0 ? step : 0;
}

function snapshotEngagementNameContext(data) {
  return {
    engagement_name: stringValue(data.engagement_name),
    assessment_type: data.assessment_type,
    targets: {
      domains: [...(data.targets?.domains || [])],
      subdomains: [...(data.targets?.subdomains || [])],
      urls: [...(data.targets?.urls || [])],
      ip_addresses: [...(data.targets?.ip_addresses || [])],
      cidr_ranges: [...(data.targets?.cidr_ranges || [])],
      api_base_urls: [...(data.targets?.api_base_urls || [])],
    },
    intake_preferences: {
      primary_goal: data.intake_preferences?.primary_goal || "",
    },
    test_profile: data.test_profile,
  };
}

function refreshSuggestedEngagementNameIfAutomatic(previousContext, data = state.wizard?.data) {
  const previousName = stringValue(previousContext?.engagement_name);
  const previousSuggestedName = suggestedEngagementName(previousContext || data);
  if (!previousName || previousName === previousSuggestedName) {
    data.engagement_name = suggestedEngagementName(data);
  }
}

function suggestedEngagementName(data) {
  const firstTarget = flattenTargetValues(data.targets)[0];
  const base = firstTarget
    ? String(firstTarget).replace(/^https?:\/\//i, "").replace(/[^a-z0-9./:-]+/gi, " ").trim()
    : humanizeAssessmentTypeShort(data.assessment_type);
  const goal = humanizeGoal(data.intake_preferences.primary_goal || goalForProfile(data.test_profile)).replace(/\s+/g, " ");
  return `${base || "Mission"} ${goal}`.trim();
}

function humanizeAssessmentTypeShort(value) {
  const mapping = {
    "Website / Web App": "Web App",
    "Domain / Domains": "Domain",
    "External IP / WAN": "External Surface",
    "Internal Range / LAN": "Internal Range",
    "API": "API",
    "SSL/TLS Only": "TLS",
    "Authenticated App": "Authenticated App",
    "Mixed Assessment": "Mixed Surface",
  };
  return mapping[value] || String(value || "Mission");
}

function humanizeGoal(value) {
  const mapping = {
    "quick-overview": "Quick Overview",
    "inventory-first": "Inventory First",
    "standard-assessment": "Standard Assessment",
    "deep-assessment": "Deep Assessment",
    "authenticated-review": "Authenticated Review",
    "adaptive-coverage": "Adaptive Customer-Specific Testing",
    "internal-validation": "Internal Validation",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeOutputStyle(value) {
  const mapping = {
    "detailed-per-item": "Detailed Per Item",
    "balanced-technical": "Balanced Technical",
    "technical-detail": "Technical Detail",
    "executive-summary": "Executive Summary",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeBoundaryHandling(value) {
  const mapping = {
    "standard-scope-only": "Standard Scope Only",
    "report-adjacent-ranges-only": "Report Adjacent Ranges Only",
    "approved-lateral-discovery": "Approved Lateral Discovery",
    "custom-exclusions": "Custom Exclusions Recorded",
    "notes-only-boundaries": "Boundary Notes Recorded",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeSafetyPosture(value) {
  const mapping = {
    conservative: "Conservative",
    balanced: "Balanced",
    thorough: "Thorough",
    "passive-only": "Passive Only",
    aggressive: "Aggressive with Approval",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function summarizeAuthStrategy(data) {
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const accessSummary = renderAccessContextSummary(data.access);
  const mapping = {
    unauthenticated: "Unauthenticated",
    credentialed: accessSummary !== "No account context recorded" ? accessSummary : "Credentialed access planned",
    "api-access": accessSummary !== "No account context recorded" ? accessSummary : "API token or key access planned",
    "session-access": accessSummary !== "No account context recorded" ? accessSummary : "Session-based access planned",
    "advanced-details": "Access details to be finalized in Advanced Configuration",
  };
  return mapping[strategy] || accessSummary;
}

function summarizeBoundaries(data) {
  const exclusionSummary = renderExclusionSummary(data.exclusions);
  const notes = stringValue(data.exclusions.notes);
  const lateral = data.intake_preferences.lateral_discovery;
  const lateralSummary = lateral === "requested"
    ? "Lateral discovery requested within approved internal limits"
    : lateral === "report-only"
      ? "Adjacent internal ranges reported only"
      : "No lateral expansion";
  if (notes && exclusionSummary !== "No denylist recorded") {
    return `${exclusionSummary} · ${notes}`;
  }
  if (notes) return `${lateralSummary} · ${notes}`;
  if (exclusionSummary !== "No denylist recorded") return `${lateralSummary} · ${exclusionSummary}`;
  return lateralSummary;
}

function renderExclusionSummary(exclusions) {
  const count = countExplicitExclusions(exclusions);
  if (!count && !hasBoundaryNotes(exclusions)) return "No denylist recorded";
  if (!count) return "Boundary notes only";
  return `${count} explicit exclusion${count === 1 ? "" : "s"}`;
}

function countExplicitExclusions(exclusions) {
  return flattenTargetValues({
    domains: exclusions?.domains || [],
    urls: exclusions?.urls || [],
    ip_addresses: exclusions?.ip_addresses || [],
    cidr_ranges: exclusions?.cidr_ranges || [],
    api_base_urls: exclusions?.api_base_urls || [],
  }).length;
}

function hasBoundaryNotes(exclusions) {
  return Boolean(stringValue(exclusions?.notes));
}

function clearAccessContext() {
  state.wizard.data.access = {
    accounts: [buildEmptyAccount()],
    manual_auth_steps: "",
    cookie_notes: "",
  };
}

function unauthenticatedProfileRecommendation(assessmentType) {
  const mapping = {
    "Website / Web App": "Standard",
    "Domain / Domains": "External Surface Only",
    "External IP / WAN": "External Surface Only",
    "Internal Range / LAN": "Standard",
    "API": "Standard",
    "SSL/TLS Only": "SSL/TLS Only",
    "Authenticated App": "Standard",
    "Mixed Assessment": "Standard",
  };
  return mapping[assessmentType] || "Standard";
}

function alignPlanForUnauthenticatedAccess() {
  const data = state.wizard.data;
  const intake = state.wizard.intake;
  let changed = false;

  if (data.intake_preferences.primary_goal === "authenticated-review") {
    data.intake_preferences.primary_goal = "standard-assessment";
    if (intake.sources.goal !== "still-needed") {
      intake.sources.goal = "inferred";
    }
    changed = true;
  }

  if (data.test_profile === "Authenticated Only") {
    const fallbackProfile = unauthenticatedProfileRecommendation(data.assessment_type);
    if (fallbackProfile !== data.test_profile) {
      data.test_profile = fallbackProfile;
      intake.overrides.profile = false;
      changed = true;
      if (!intake.overrides.modules && !intake.overrides.safety) {
        applyProfilePreset(fallbackProfile);
      } else {
        if (!intake.overrides.modules) {
          Object.assign(data.modules, profileModulePreset(fallbackProfile));
        }
        if (!intake.overrides.safety) {
          Object.assign(data.safety, profileSafetyPreset(fallbackProfile));
        }
      }
    }
  }

  data.modules.auth_flows = false;
  return changed;
}

function buildEmptyExclusions() {
  return {
    domains: [],
    urls: [],
    ip_addresses: [],
    cidr_ranges: [],
    api_base_urls: [],
    notes: "",
  };
}

function effectiveBoundaryHandling(data = state.wizard.data) {
  const explicit = String(data?.intake_preferences?.boundary_handling || "").trim();
  if (explicit) return explicit;
  const exclusions = data?.exclusions || {};
  if (countExplicitExclusions(exclusions)) return "custom-exclusions";
  if (hasBoundaryNotes(exclusions)) return "notes-only-boundaries";
  return "standard-scope-only";
}

function requiresExplicitBoundaryConfirmation(data = state.wizard.data) {
  const assessmentType = String(data?.assessment_type || "").trim();
  const goal = String(data?.intake_preferences?.primary_goal || "").trim();
  const authStrategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  const supportedAssessmentTypes = new Set([
    "Website / Web App",
    "Domain / Domains",
    "External IP / WAN",
    "Internal Range / LAN",
    "API",
    "SSL/TLS Only",
    "Authenticated App",
    "Mixed Assessment",
  ]);

  if (supportedAssessmentTypes.has(assessmentType)) return true;
  if (assessmentType === "Internal Range / LAN" || goal === "internal-validation") return true;
  if (assessmentType === "SSL/TLS Only") return true;
  if (assessmentType === "Mixed Assessment") return true;
  if (goal === "adaptive-coverage") return true;
  if (["credentialed", "api-access", "session-access", "advanced-details"].includes(authStrategy)) return true;
  return false;
}

function resetBoundaryConfirmationAfterScopeChange({
  previousAssessmentType,
  previousBoundaryRequirement,
  previousBoundaryHandling,
  previousLateralDiscovery,
  previousHasExplicitBoundaryScope,
}) {
  const assessmentChanged = previousAssessmentType !== state.wizard.data.assessment_type;
  const currentBoundaryRequirement = requiresExplicitBoundaryConfirmation(state.wizard.data);
  const boundaryRequirementChanged = previousBoundaryRequirement !== currentBoundaryRequirement;
  const currentAssessmentType = String(state.wizard.data.assessment_type || "").trim();
  const shouldClearInternalLateralScope =
    currentAssessmentType !== "Internal Range / LAN" &&
    !previousHasExplicitBoundaryScope &&
    (
      previousBoundaryHandling === "report-adjacent-ranges-only" ||
      ["requested", "report-only", "authorized-allowlist-only"].includes(String(previousLateralDiscovery || "").trim())
    );

  if (shouldClearInternalLateralScope) {
    state.wizard.data.intake_preferences.boundary_handling = "";
    state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
    state.wizard.intake.sources.boundaries = currentBoundaryRequirement ? "still-needed" : "inferred";
    return;
  }

  if (!assessmentChanged && !boundaryRequirementChanged) return;
  if (previousHasExplicitBoundaryScope) return;
  if (previousBoundaryHandling !== "standard-scope-only") return;

  state.wizard.data.intake_preferences.boundary_handling = "";
  state.wizard.intake.sources.boundaries = currentBoundaryRequirement ? "still-needed" : "inferred";
}

function shouldAskAuthQuestion(data) {
  if (["Authenticated App", "API", "Mixed Assessment"].includes(data.assessment_type)) return true;
  if (["authenticated-review", "internal-validation"].includes(data.intake_preferences.primary_goal)) return true;
  if (data.test_profile === "Authenticated Only") return true;
  if (
    data.modules.auth_flows &&
    ["Internal Range / LAN"].includes(String(data.assessment_type || "").trim())
  ) {
    return true;
  }
  return false;
}

function needsAuthDetails(data) {
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  if (!strategy || ["unauthenticated", "advanced-details"].includes(strategy)) return false;
  return !hasMeaningfulAccessContext(data.access);
}

function inferAssessmentType(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(mixed|hybrid|both web and api|web and api)\b/.test(normalized)) return "Mixed Assessment";
  if (/\b(api|graphql|swagger|openapi)\b/.test(normalized)) return "API";
  if (/\b(wan|public ip|external ip|perimeter|internet-facing ip)\b/.test(normalized)) return "External IP / WAN";
  if (/\b(lan|internal|subnet|cidr|network|range)\b/.test(normalized)) return "Internal Range / LAN";
  if (/\b(tls|ssl|certificate|cipher)\b/.test(normalized)) return "SSL/TLS Only";
  if (/\b(authenticated app|portal with login|logged[- ]in portal)\b/.test(normalized)) return "Authenticated App";
  if (/\b(customer|client|member|partner|admin)\s+portal\b/.test(normalized)) return "Authenticated App";
  if (/\bportal\b.*\b(login|sign[- ]?in|account|accounts|dashboard)\b/.test(normalized)) return "Authenticated App";
  if (/\b(domain|domains|dns)\b/.test(normalized)) return "Domain / Domains";
  if (/\b(app|portal|website|site|web application|web app)\b/.test(normalized)) return "Website / Web App";
  return null;
}

function shouldPreserveAssessmentType(currentType, inferredType) {
  const preserveMap = {
    "SSL/TLS Only": ["Domain / Domains", "Website / Web App"],
    "Authenticated App": ["Website / Web App", "Domain / Domains"],
  };
  return (preserveMap[currentType] || []).includes(inferredType);
}

function inferAssessmentTypeFromTargets(parsed) {
  const hasDomains = parsed.domains.length || parsed.subdomains.length;
  const hasUrls = parsed.urls.length;
  const hasApi = parsed.api_base_urls.length;
  const hasIps = parsed.ip_addresses.length;
  const hasCidrs = parsed.cidr_ranges.length;

  if ((hasCidrs || hasIps) && !(hasDomains || hasUrls || hasApi)) {
    const privateOnly = [...parsed.ip_addresses, ...parsed.cidr_ranges.map((item) => item.split("/")[0])]
      .every((value) => isPrivateIp(value));
    return privateOnly ? "Internal Range / LAN" : "External IP / WAN";
  }
  if (hasApi && (hasDomains || hasUrls || hasIps || hasCidrs)) return "Mixed Assessment";
  if (hasApi) return "API";
  if (hasUrls) return "Website / Web App";
  if (hasDomains) return "Domain / Domains";
  return null;
}

function inferPrimaryGoal(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(quick perimeter overview|perimeter overview)\b/.test(normalized)) return "quick-overview";
  if (/\b(quick|overview|high level|light)\b/.test(normalized)) return "quick-overview";
  if (/\b(perimeter review)\b/.test(normalized)) return "standard-assessment";
  if (/\b(inventory|visibility|enumeration|per[- ]item|asset list)\b/.test(normalized)) return "inventory-first";
  if (/\b(authenticated|portal account|logged[- ]in|role[- ]based)\b/.test(normalized)) return "authenticated-review";
  if (/\b(adaptive follow[- ]up after discovery|adaptive follow[- ]up)\b/.test(normalized)) return "adaptive-coverage";
  if (/\b(adaptive|customer-specific|custom pack|codex|ai-generated)\b/.test(normalized)) return "adaptive-coverage";
  if (/\b(internal validation|adversary|lateral|privilege escalation)\b/.test(normalized)) return "internal-validation";
  if (/\b(deep follow[- ]up after discovery|deep follow[- ]up)\b/.test(normalized)) return "deep-assessment";
  if (/\b(deep|thorough|full test|full pentest|in-depth)\b/.test(normalized)) return "deep-assessment";
  if (/\b(standard|normal|balanced)\b/.test(normalized)) return "standard-assessment";
  return null;
}

function inferOutputStyle(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(per item|each item|clear information per found item|detailed visibility)\b/.test(normalized)) return "detailed-per-item";
  if (/\b(technical|deep detail|full detail)\b/.test(normalized)) return "technical-detail";
  if (/\b(executive|leadership|summary)\b/.test(normalized)) return "executive-summary";
  if (/\b(balanced|normal)\b/.test(normalized)) return "balanced-technical";
  return null;
}

function inferAuthStrategy(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(unauthenticated|unauth|no auth|without auth|guest only|keep it unauthenticated|no credentials)\b/.test(normalized)) return "unauthenticated";
  if (/\b(advanced settings|advanced config|i will add.*advanced)\b/.test(normalized)) return "advanced-details";
  if (/\b(token|tokens|api key|api keys|apikey|apikeys|bearer)\b/.test(normalized)) return "api-access";
  if (/\b(cookie|cookies|session|sessions)\b/.test(normalized)) return "session-access";
  if (/\b(account|accounts|username|password|portal account|portal accounts|credentials|login)\b/.test(normalized)) return "credentialed";
  return null;
}

function inferLateralDiscovery(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(report adjacent|report reachable|report only)\b/.test(normalized)) return "report-only";
  if (/\b(reach other internal|discover other internal|lateral|adjacent internal)\b/.test(normalized)) return "requested";
  return null;
}

function inferSafetyPosture(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(passive only|passive)\b/.test(normalized)) return "passive-only";
  if (/\b(conservative|careful|cautious|safe)\b/.test(normalized)) return "conservative";
  if (/\b(aggressive|intrusive|exploit)\b/.test(normalized)) return "aggressive";
  if (/\b(thorough|deep)\b/.test(normalized)) return "thorough";
  if (/\b(balanced|standard|normal|guarded)\b/.test(normalized)) return "balanced";
  return null;
}

function inferStandaloneSafetyAnswer(answer) {
  const normalized = String(answer || "").trim().toLowerCase();
  if (/^(passive only|passive)(?:[.!])?$/.test(normalized)) return "passive-only";
  if (/^(conservative|careful|cautious|safe)(?:[.!])?$/.test(normalized)) return "conservative";
  if (/^(aggressive|intrusive|exploit|aggressive with approval)(?:[.!])?$/.test(normalized)) return "aggressive";
  if (/^(thorough|deep)(?:[.!])?$/.test(normalized)) return "thorough";
  if (/^(balanced|standard|normal|guarded)(?:[.!])?$/.test(normalized)) return "balanced";
  return null;
}

function summarizeBoundaryReplyOptions(assessmentType) {
  const quickReplies = assessmentType === "Internal Range / LAN"
    ? ["No extra exclusions", "Report adjacent internal ranges only"]
    : ["No extra exclusions"];
  const customOption = "custom exclusions / boundary notes";
  if (!quickReplies.length) return customOption;
  if (quickReplies.length === 1) return `${quickReplies[0]} or ${customOption}`;
  return `${quickReplies.join(", ")}, or ${customOption}`;
}

function containsUnauthorizedExpansion(answer) {
  const normalized = String(answer || "").toLowerCase();
  const riskyBroadPhrases = [
    "scan the internet",
    "anything reachable",
    "anything public",
    "whatever you can find",
    "all public websites",
    "look around everywhere",
    "scan random public targets",
  ];
  return riskyBroadPhrases.some((phrase) => normalized.includes(phrase));
}

function parseTargetsFromText(answer) {
  const text = String(answer || "");
  const isScopeRevision = state.wizard.intake.reviewQuestionId === "scope";
  const urls = [...text.matchAll(/https?:\/\/[^\s,;]+/gi)].map((match) => match[0].replace(/[.)]+$/, ""));
  const cidrs = [...text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/g)].map((match) => match[0]);
  const ips = [...text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)]
    .map((match) => match[0])
    .filter((value) => !cidrs.some((cidr) => cidr.startsWith(`${value}/`)));
  const domains = [...text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi)]
    .map((match) => match[0].toLowerCase())
    .filter((value) => !urls.some((url) => {
      try {
        return new URL(url).hostname.toLowerCase() === value;
      } catch {
        return false;
      }
    }));

  const parsed = {
    domains: [],
    subdomains: [],
    urls: [],
    ip_addresses: [],
    cidr_ranges: [],
    api_base_urls: [],
  };
  const seen = {
    domains: new Set(),
    subdomains: new Set(),
    urls: new Set(),
    ip_addresses: new Set(),
    cidr_ranges: new Set(),
    api_base_urls: new Set(),
  };

  cidrs.forEach((value) => addUniqueTarget(parsed, seen, "cidr_ranges", value));
  ips.forEach((value) => addUniqueTarget(parsed, seen, "ip_addresses", value));
  urls.forEach((value) => {
    const preserveApiUrlBias =
      state.wizard.data.assessment_type === "API" &&
      !isScopeRevision;
    if (looksLikeApiUrl(value) || preserveApiUrlBias) {
      addUniqueTarget(parsed, seen, "api_base_urls", value);
      return;
    }
    addUniqueTarget(parsed, seen, "urls", value);
  });
  domains.forEach((value) => {
    const key = value.split(".").length > 2 ? "subdomains" : "domains";
    addUniqueTarget(parsed, seen, key, value);
  });
  return parsed;
}

function addUniqueTarget(parsed, seen, key, value) {
  const normalized = String(value || "").trim();
  if (!normalized || seen[key].has(normalized)) return;
  seen[key].add(normalized);
  parsed[key].push(normalized);
}

function looksLikeApiUrl(value) {
  try {
    const url = new URL(value);
    return /^api\./i.test(url.hostname) || /\/(api|graphql|v\d+)(\/|$)/i.test(url.pathname);
  } catch {
    return false;
  }
}

function buildAccountFromFreeText(answer) {
  const account = buildEmptyAccount();
  const usernameMatch = answer.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i) || answer.match(/\buser(name)?[:=]?\s*([^\s,;]+)/i);
  const labelMatch = !usernameMatch
    ? answer.match(/^\s*([^,\n]+?)\s+role[:=]?\s+/i)
    : null;
  const roleMatch = answer.match(
    /\brole[:=]?\s+([a-z0-9 _-]+?)(?=\s+(secret|password|api[- ]?key|key|bearer|session|cookie)\b|\s+(vault:\/\/|env:\/\/|secret:\/\/)|$)/i
  );
  const secretMatch = answer.match(/\b(secret|password)[:=]?\s+([^\s,;]+)/i);
  const apiKeyMatch = answer.match(/\b(api[- ]?key|key)[:=]?\s+([^\s,;]+)/i);
  const bearerMatch = answer.match(/\bbearer[:=]?\s+([^\s,;]+)/i);
  const sessionMatch = answer.match(/\b(session|cookie)[:=]?\s+(?!role\b)([^\s,;]+)/i);

  account.username = usernameMatch ? (usernameMatch[2] || usernameMatch[0]) : "";
  account.role = roleMatch ? roleMatch[1].trim() : account.role;
  account.secret_ref = secretMatch ? secretMatch[2].trim() : "";
  account.api_key_ref = apiKeyMatch ? apiKeyMatch[2].trim() : "";
  account.bearer_token_ref = bearerMatch ? bearerMatch[1].trim() : "";
  account.session_ref = sessionMatch ? sessionMatch[2].trim() : "";
  account.label = labelMatch?.[1]?.trim() || account.role || account.username || "Primary Account";

  if (!account.secret_ref && !account.api_key_ref && !account.bearer_token_ref && !account.session_ref) {
    const vaultLike = answer.match(/\b(vault:\/\/[^\s,;]+|env:\/\/[^\s,;]+|secret:\/\/[^\s,;]+)\b/i);
    if (vaultLike) {
      account.secret_ref = vaultLike[1];
    }
  }
  return account;
}

function looksLikeStructuredAccessDetail(answer) {
  const text = String(answer || "");
  if (!text.trim()) return false;
  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text)) return true;
  if (/\buser(name)?[:=]?\s*[^\s,;]+/i.test(text)) return true;
  if (/\brole[:=]?\s+[a-z0-9 _-]+/i.test(text)) return true;
  if (/\b(secret|password|api[- ]?key|key|bearer)[:=]?\s+[^\s,;]+/i.test(text)) return true;
  if (/\b(vault:\/\/[^\s,;]+|env:\/\/[^\s,;]+|secret:\/\/[^\s,;]+)\b/i.test(text)) return true;
  if (/\b(session|cookie)[:=]\s*[^\s,;]+/i.test(text)) return true;
  if (/\b(session|cookie)\s+[^\s,;=]+=[^\s,;]+/i.test(text)) return true;
  return false;
}

function draftAuthDetailsText(access) {
  const meaningfulAccounts = (access?.accounts || []).filter((account) => hasMeaningfulAccount([account]));
  const lines = meaningfulAccounts.map((account) => {
    const parts = [];
    const labelOnly =
      !account.username &&
      stringValue(account.label) &&
      account.label !== account.role &&
      account.label !== "Primary Account";
    if (account.username) parts.push(account.username);
    else if (labelOnly) parts.push(account.label);
    if (account.role) parts.push(`role ${account.role}`);
    if (account.secret_ref) parts.push(`secret ${account.secret_ref}`);
    if (account.api_key_ref) parts.push(`api-key ${account.api_key_ref}`);
    if (account.bearer_token_ref) parts.push(`bearer ${account.bearer_token_ref}`);
    if (account.session_ref) parts.push(`session ${account.session_ref}`);
    return parts.join(" ").trim();
  }).filter(Boolean);

  if (lines.length) return lines.join("\n");
  if (stringValue(access?.manual_auth_steps)) return access.manual_auth_steps.trim();
  if (stringValue(access?.cookie_notes)) return access.cookie_notes.trim();
  return "";
}

function preferredAuthRevisionQuestionId(data) {
  const strategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  const hasCapturedAccessDetail = hasMeaningfulAccessContext(data?.access || {});
  if (
    ["credentialed", "api-access", "session-access"].includes(strategy) &&
    (hasCapturedAccessDetail || needsAuthDetails(data))
  ) {
    return "auth-details";
  }
  return "auth";
}

function draftAuthStrategyText(data) {
  const strategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  if (strategy === "unauthenticated") return "Keep it unauthenticated";
  if (strategy === "advanced-details") return "I will add access in advanced settings";
  if (strategy === "api-access") return "I have API tokens or keys";
  if (strategy === "session-access") return "I have a session reference";
  if (strategy === "credentialed") return "I have portal/app accounts";
  return summarizeAuthStrategy(data);
}

function draftBoundariesText(data) {
  const notes = stringValue(data?.exclusions?.notes);
  const explicitExclusions = flattenTargetValues(data?.exclusions || {});
  const boundaryHandling = String(data?.intake_preferences?.boundary_handling || "").trim();
  const lateral = String(data?.intake_preferences?.lateral_discovery || "").trim();

  if (
    boundaryHandling === "report-adjacent-ranges-only" ||
    ["requested", "report-only", "authorized-allowlist-only"].includes(lateral)
  ) {
    return "Report adjacent internal ranges only";
  }
  if (!notes && !explicitExclusions.length) {
    return "No extra exclusions";
  }
  if (notes) return notes;
  return explicitExclusions.join("\n");
}

function normalizeGoalForAssessmentType(goal, assessmentType) {
  if (goal === "internal-validation" && assessmentType !== "Internal Range / LAN") {
    return {
      goal: "deep-assessment",
      changed: true,
      reason: `Internal validation stays reserved for approved internal ranges. With the current ${assessmentType.toLowerCase()} scope I will shape this as a deep assessment unless you switch the mission back to an internal CIDR.`,
    };
  }
  if (assessmentType === "SSL/TLS Only") {
    if (goal === "inventory-first") {
      return {
        goal: "quick-overview",
        changed: true,
        reason: "TLS-only missions stay limited to certificate, protocol, and crypto posture. I will shape this as a quick overview unless you switch to a broader web, API, or network assessment.",
      };
    }
    if (["deep-assessment", "adaptive-coverage", "authenticated-review", "internal-validation"].includes(goal)) {
      return {
        goal: "standard-assessment",
        changed: true,
        reason: "TLS-only missions stay limited to certificate, protocol, and crypto posture. I will shape this as a standard TLS-only assessment unless you switch to a broader application or network mission.",
      };
    }
  }
  return { goal, changed: false, reason: "" };
}

function internalDiscoveryFirstCompatibility(data) {
  if (data.assessment_type !== "Internal Range / LAN") return null;

  const goal = String(data.intake_preferences.primary_goal || "").trim();
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const hasAccessPlan = Boolean(strategy && strategy !== "unauthenticated");

  if (goal === "authenticated-review" && hasAccessPlan) {
    return {
      profile: "Standard",
      reason:
        "Authenticated review against an internal range starts with staged discovery. I will keep the planned access context attached to this mission and begin with a discovery-first internal run until reachable services are confirmed.",
      confirmationLine:
        "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface credential-aware follow-up options once reachable services are confirmed.",
    };
  }

  if (goal === "deep-assessment") {
    return {
      profile: "Standard",
      reason: hasAccessPlan
        ? "Deep assessment against an internal range starts with staged discovery. I will keep the planned access context attached to this mission, begin with a discovery-first internal run, and surface deeper follow-up validation once reachable hosts and services are confirmed."
        : "Deep assessment against an internal range starts with staged discovery. I will begin with a discovery-first internal run and surface deeper follow-up validation once reachable hosts and services are confirmed.",
      confirmationLine: hasAccessPlan
        ? "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface deeper follow-up validation once reachable hosts and services are confirmed."
        : "I will begin with live network discovery under the Standard profile and surface deeper follow-up validation once reachable hosts and services are confirmed.",
    };
  }

  if (goal === "adaptive-coverage") {
    return {
      profile: "Standard",
      reason: hasAccessPlan
        ? "Adaptive customer-specific testing against an internal range starts with staged discovery. I will keep the planned access context attached to this mission, begin with a discovery-first internal run, and surface adaptive follow-up coverage once the reachable inventory is confirmed."
        : "Adaptive customer-specific testing against an internal range starts with staged discovery. I will begin with a discovery-first internal run and surface adaptive follow-up coverage once the reachable inventory is confirmed.",
      confirmationLine: hasAccessPlan
        ? "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed."
        : "I will begin with live network discovery under the Standard profile and surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed.",
    };
  }

  return null;
}

function externalPerimeterDiscoveryCompatibility(data) {
  if (data.assessment_type !== "External IP / WAN") return null;

  const goal = String(data.intake_preferences.primary_goal || "").trim();
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const hasAccessPlan = Boolean(strategy && strategy !== "unauthenticated");

  if (goal === "authenticated-review" && hasAccessPlan) {
    return {
      profile: "External Surface Only",
      reason:
        "Authenticated review against explicit WAN IP scope starts with staged perimeter discovery. I will keep the planned access context attached to this mission, begin with a passive perimeter discovery run, and surface access-aware follow-up options once reachable services and protected application surfaces are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile, keep the planned access context attached to this mission, and surface access-aware follow-up options once reachable services and protected application surfaces are confirmed.",
    };
  }

  if (goal === "deep-assessment") {
    return {
      profile: "External Surface Only",
      reason:
        "Deep assessment against explicit WAN IP scope starts with staged perimeter discovery. I will begin with a passive perimeter discovery run and surface deeper service-aware follow-up validation once reachable hosts and services are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile and surface deeper service-aware follow-up validation once reachable hosts and services are confirmed.",
    };
  }

  if (goal === "adaptive-coverage") {
    return {
      profile: "External Surface Only",
      reason:
        "Adaptive customer-specific testing against explicit WAN IP scope starts with staged perimeter discovery. I will begin with a passive perimeter discovery run and surface adaptive customer-specific follow-up coverage once reachable hosts and services are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile and surface adaptive customer-specific follow-up coverage once reachable hosts and services are confirmed.",
    };
  }

  return null;
}

function stagedDiscoveryCompatibility(data) {
  return internalDiscoveryFirstCompatibility(data) || externalPerimeterDiscoveryCompatibility(data);
}

function reconcileGoalCompatibility(sourceWhenNormalized = "inferred") {
  const data = state.wizard.data;
  const intake = state.wizard.intake;
  const normalized = normalizeGoalForAssessmentType(
    data.intake_preferences.primary_goal,
    data.assessment_type,
  );
  let changed = normalized.changed;
  let reason = normalized.reason;

  if (normalized.changed) {
    data.intake_preferences.primary_goal = normalized.goal;
    if (intake.sources.goal !== "still-needed") {
      intake.sources.goal = sourceWhenNormalized;
    }
  }

  if (!intake.overrides.profile) {
    const stagedDiscoveryPlan = stagedDiscoveryCompatibility(data);
    const compatibleProfile = stagedDiscoveryPlan?.profile || recommendedProfileForGoal(
      data.intake_preferences.primary_goal,
      data.assessment_type,
    );
    if (!reason && stagedDiscoveryPlan?.reason) {
      reason = stagedDiscoveryPlan.reason;
    }
    if (compatibleProfile && compatibleProfile !== data.test_profile) {
      data.test_profile = compatibleProfile;
      changed = true;
      if (!intake.overrides.modules && !intake.overrides.safety) {
        applyProfilePreset(compatibleProfile);
      } else {
        if (!intake.overrides.modules) {
          Object.assign(data.modules, profileModulePreset(compatibleProfile));
        }
        if (!intake.overrides.safety) {
          Object.assign(data.safety, profileSafetyPreset(compatibleProfile));
        }
      }
    }
  }

  return {
    goal: data.intake_preferences.primary_goal,
    changed,
    reason,
  };
}

function setGoalRecommendation(goal, source = "confirmed") {
  state.wizard.data.intake_preferences.primary_goal = goal;
  state.wizard.intake.sources.goal = source;
  const compatibility = reconcileGoalCompatibility(source === "confirmed" ? "inferred" : source);

  if (state.wizard.intake.overrides.profile || state.wizard.intake.overrides.modules || state.wizard.intake.overrides.safety) {
    return compatibility;
  }

  applyGoalDrivenPlanDefaults();
  return compatibility;
}

function applyGoalDrivenPlanDefaults() {
  const stagedDiscoveryPlan = stagedDiscoveryCompatibility(state.wizard.data);
  const profile = stagedDiscoveryPlan?.profile || recommendedProfileForGoal(
    state.wizard.data.intake_preferences.primary_goal,
    state.wizard.data.assessment_type,
  );
  state.wizard.data.test_profile = profile;
  applyProfilePreset(profile);

  if (state.wizard.data.intake_preferences.primary_goal === "inventory-first" || state.wizard.data.intake_preferences.primary_goal === "quick-overview") {
    applyInventoryGoalTuning(state.wizard.data.intake_preferences.primary_goal);
  }
  if (state.wizard.data.intake_preferences.primary_goal === "authenticated-review" && !state.wizard.data.modules.auth_flows) {
    state.wizard.data.modules.auth_flows = true;
  }
  if (state.wizard.data.intake_preferences.safety_posture) {
    applySafetyPreference(state.wizard.data.intake_preferences.safety_posture);
  }
  enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
}

function recommendedProfileForGoal(goal, assessmentType) {
  if (goal === "quick-overview") return assessmentType === "External IP / WAN" ? "External Surface Only" : "Light";
  if (goal === "inventory-first") {
    if (assessmentType === "Internal Range / LAN") return "Standard";
    if (assessmentType === "External IP / WAN") return "External Surface Only";
    if (assessmentType === "SSL/TLS Only") return "SSL/TLS Only";
    return "Light";
  }
  if (goal === "deep-assessment") return "Deep";
  if (goal === "authenticated-review") return "Authenticated Only";
  if (goal === "adaptive-coverage") return "Adaptive Customer-Specific Mode";
  if (goal === "internal-validation") return "Internal Validation";
  return assessmentTypeProfileRecommendation(assessmentType);
}

function goalForProfile(profile) {
  const mapping = {
    "Light": "quick-overview",
    "Standard": "standard-assessment",
    "Deep": "deep-assessment",
    "External Surface Only": "inventory-first",
    "Authenticated Only": "authenticated-review",
    "SSL/TLS Only": "inventory-first",
    "Internal Validation": "internal-validation",
    "Adaptive Customer-Specific Mode": "adaptive-coverage",
  };
  return mapping[profile] || "standard-assessment";
}

function applyInventoryGoalTuning(goal) {
  const networkAssessment = ["Internal Range / LAN", "External IP / WAN"].includes(state.wizard.data.assessment_type);
  if (networkAssessment) {
    Object.assign(state.wizard.data.modules, moduleState(["discovery"]));
  } else {
    Object.assign(state.wizard.data.modules, moduleState(["discovery", "web_crawling", "ssl_tls_analysis", "nuclei_checks"]));
  }
  state.wizard.data.safety.active_checks = "passive-only";
  state.wizard.data.safety.adaptive_generation = goal === "inventory-first" ? false : state.wizard.data.safety.adaptive_generation;
  state.wizard.data.safety.max_validation_depth = "light";
}

function enforceDiscoveryFirstSafetyGuardrails(data) {
  if (!externalPerimeterDiscoveryCompatibility(data)) return;
  Object.assign(data.safety, {
    active_checks: "passive-only",
    max_validation_depth: "light",
  });
}

function applySafetyPreference(posture) {
  const safety = state.wizard.data.safety;
  if (posture === "passive-only") {
    Object.assign(safety, {
      rate_limit_rps: Math.min(safety.rate_limit_rps, 2),
      concurrency: 1,
      active_checks: "passive-only",
      max_validation_depth: "light",
    });
    return;
  }
  if (posture === "conservative") {
    Object.assign(safety, {
      rate_limit_rps: Math.min(safety.rate_limit_rps, 2),
      concurrency: Math.min(safety.concurrency, 2),
      active_checks: "passive-only",
      max_validation_depth: "light",
    });
    return;
  }
  if (posture === "balanced") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(2, safety.rate_limit_rps),
      concurrency: Math.max(2, safety.concurrency),
      active_checks: "guarded",
      max_validation_depth: "standard",
    });
    return;
  }
  if (posture === "thorough") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(3, safety.rate_limit_rps),
      concurrency: Math.max(2, safety.concurrency),
      active_checks: "guarded",
      max_validation_depth: "deep",
    });
    return;
  }
  if (posture === "aggressive") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(4, safety.rate_limit_rps),
      concurrency: Math.max(3, safety.concurrency),
      active_checks: "active",
      max_validation_depth: "deep",
    });
  }
}

function deriveSafetyPostureFromConfig(data) {
  if (data.safety.active_checks === "active") return "aggressive";
  if (data.safety.active_checks === "passive-only") {
    return data.safety.max_validation_depth === "light" ? "conservative" : "passive-only";
  }
  if (data.safety.max_validation_depth === "deep") return "thorough";
  return "balanced";
}

function syncConversationMetadataFromData() {
  const { data, intake } = state.wizard;
  if ((!data.intake_preferences.primary_goal && intake.overrides.profile) || intake.sources.goal === "override") {
    data.intake_preferences.primary_goal = goalForProfile(data.test_profile);
  }
  if ((!data.intake_preferences.safety_posture && intake.overrides.safety) || intake.sources.safety === "override") {
    data.intake_preferences.safety_posture = deriveSafetyPostureFromConfig(data);
  }
  const inferredAuthStrategy = inferAuthStrategyFromAccess(data.access);
  if (
    inferredAuthStrategy &&
    (
      !data.intake_preferences.auth_strategy ||
      data.intake_preferences.auth_strategy === "advanced-details" ||
      intake.overrides.access
    )
  ) {
    data.intake_preferences.auth_strategy = inferredAuthStrategy;
  }
  if (flattenTargetValues(data.targets).length && intake.sources.scope === "still-needed") {
    intake.sources.scope = "inferred";
  }
  if (data.assessment_type && intake.sources.target_type === "still-needed") {
    intake.sources.target_type = "inferred";
  }
  if (data.intake_preferences.primary_goal && intake.sources.goal === "still-needed") {
    intake.sources.goal = "inferred";
  }
  if (data.intake_preferences.auth_strategy && intake.sources.auth === "still-needed") {
    intake.sources.auth = "inferred";
  }
  if (renderExclusionSummary(data.exclusions) !== "No denylist recorded" && intake.sources.boundaries === "still-needed") {
    intake.sources.boundaries = "inferred";
  }
  syncAdvancedSharedAccessHistoryFromData();
}

function syncAdvancedSharedAccessHistoryFromData() {
  const wizard = state.wizard;
  const preservedHistory = wizard.intake.history.filter((turn) => !isSyntheticSharedAccessTurn(turn));
  const hasAuthenticAuthDetailsTurn = preservedHistory.some(
    (turn) => turn.role === "user" && turn.questionId === "auth-details"
  );

  if (hasAuthenticAuthDetailsTurn) {
    wizard.intake.history = preservedHistory;
    return;
  }

  const sharedAccessHistory = buildAdvancedSharedAccessHistoryEntry(wizard.data.access);
  if (!sharedAccessHistory) {
    wizard.intake.history = preservedHistory;
    return;
  }

  wizard.intake.history = [
    ...preservedHistory,
    {
      role: "user",
      questionId: "auth-details",
      text: sharedAccessHistory.userText,
      syncKey: "advanced-shared-access-user",
    },
    {
      role: "assistant",
      questionId: "auth-details",
      text: sharedAccessHistory.assistantText,
      syncKey: "advanced-shared-access-assistant",
    },
  ];
}

function isSyntheticSharedAccessTurn(turn) {
  return [
    "advanced-shared-access-user",
    "advanced-shared-access-assistant",
  ].includes(String(turn?.syncKey || ""));
}

function buildAdvancedSharedAccessHistoryEntry(access) {
  if (hasMeaningfulAccount(access?.accounts || [])) return null;

  const manualAuthSteps = stringValue(access?.manual_auth_steps);
  const cookieNotes = stringValue(access?.cookie_notes);

  if (manualAuthSteps && !cookieNotes) {
    return {
      userText: manualAuthSteps,
      assistantText: "Advanced shared manual-auth guidance recorded in the mission configuration.",
    };
  }

  if (cookieNotes && !manualAuthSteps) {
    return {
      userText: cookieNotes,
      assistantText: "Advanced shared session guidance recorded in the mission configuration.",
    };
  }

  return null;
}

function buildNaturalConfirmationSummary(estimate, data = state.wizard.data) {
  const engagementRoute = currentEngagementRouteContext(data);
  const assessmentLead =
    data.assessment_type === "Mixed Assessment"
      ? "a mixed assessment"
      : `${data.assessment_type === "Internal Range / LAN"
          ? "an"
          : /^[AEIOU]/i.test(data.assessment_type) ? "an" : "a"} ${data.assessment_type.toLowerCase()} assessment`;
  const scopePieces = flattenTargetValues(data.targets);
  const scopeText = scopePieces.length > 3
    ? `${scopePieces.slice(0, 3).join(", ")}, plus ${scopePieces.length - 3} more approved target${scopePieces.length - 3 === 1 ? "" : "s"}`
    : (scopePieces.join(", ") || "the approved scope");
  const stagedInternalValidation = data.assessment_type === "Internal Range / LAN" && data.test_profile === "Internal Validation";
  const stagedDiscoveryPlan = stagedDiscoveryCompatibility(data);
  const outputLine = data.intake_preferences.output_style === "detailed-per-item"
    ? "I will keep the output detailed per discovered item."
    : data.intake_preferences.output_style
      ? `I will bias reporting toward ${humanizeOutputStyle(data.intake_preferences.output_style).toLowerCase()}.`
      : "";
  const lateralLine = data.intake_preferences.lateral_discovery === "requested"
    ? "I will only consider lateral discovery inside your authorized internal environment and configured limits."
    : data.intake_preferences.lateral_discovery === "report-only"
      ? "I will report adjacent reachable internal ranges but will not expand into them without explicit follow-up approval."
      : "";
  const engagementRouteLine = engagementRoute.mode === "reuse-selected-engagement"
    ? `I will attach this run to the existing engagement dossier "${engagementRoute.configContext.engagement_name}" instead of creating a new customer dossier.`
    : `I will create a new engagement dossier named "${engagementRoute.configContext.engagement_name}" before this run begins.`;
  const authorizationLine = buildAuthorizationContextLine(engagementRoute.configContext);
  const scopeGuardrailLine = buildScopeGuardrailLine(data);
  return [
    `I am going to run ${assessmentLead} against ${scopeText}.`,
    stagedInternalValidation
      ? `I will begin with live network discovery under the ${data.test_profile} profile, then surface controlled follow-up validation options once hosts and services are confirmed.`
      : stagedDiscoveryPlan?.confirmationLine
      ? stagedDiscoveryPlan.confirmationLine
      : `I will prioritize ${humanizeGoal(data.intake_preferences.primary_goal).toLowerCase()} with the ${data.test_profile} profile and the ${estimate.execution_profile} execution lane.`,
    engagementRouteLine,
    authorizationLine,
    scopeGuardrailLine,
    outputLine,
    lateralLine,
    `Estimated duration: ${estimate.estimated_total_minutes} minutes with ${estimate.confidence} ETA confidence.`,
  ].filter(Boolean).join(" ");
}

function buildAuthorizationContextLine(engagementContext = {}) {
  const client = stringValue(engagementContext.client);
  const roeRef = stringValue(engagementContext.roe_ref);
  if (!client && !roeRef) return "";
  if (client && roeRef) return `Authorization context: ${client} under ${roeRef}.`;
  if (client) return `Authorization context: ${client}.`;
  return `Authorization context: ${roeRef}.`;
}

function renderConfirmationAuthorizationContext(data = state.wizard.data) {
  const engagementContext = currentEngagementRouteContext(data).configContext || {};
  const client = stringValue(engagementContext.client);
  const roeRef = stringValue(engagementContext.roe_ref);
  if (!client && !roeRef) return "";
  return `
    <div class="compact-definition-grid split-top" data-testid="wizard-authorization-context">
      <div><span>Customer</span><strong>${escapeHtml(client || "Not recorded")}</strong></div>
      <div><span>ROE Reference</span><strong>${escapeHtml(roeRef || "Not recorded")}</strong></div>
    </div>
  `;
}

function buildScopeGuardrailLine(data = state.wizard.data) {
  const exclusions = data.exclusions || {};
  const exclusionSummary = renderExclusionSummary(exclusions);
  const boundaryHandling = humanizeBoundaryHandling(effectiveBoundaryHandling(data));
  const exclusionCount = countExplicitExclusions(exclusions);
  if (!exclusionCount && hasBoundaryNotes(exclusions)) {
    return `Scope guardrails: ${boundaryHandling}. The recorded boundary note stays in force unless you revise the approved scope.`;
  }
  if (exclusionSummary === "No denylist recorded") {
    if (boundaryHandling === "Standard Scope Only") return "";
    return `Scope guardrails: ${boundaryHandling}.`;
  }
  const exclusionVerb = exclusionCount === 1 ? "remains" : "remain";
  return `Scope guardrails: ${boundaryHandling}. ${exclusionSummary} ${exclusionVerb} outside this mission unless you revise the approved scope.`;
}

function renderConfirmationScopeGuardrails(data = state.wizard.data) {
  const exclusionSummary = renderExclusionSummary(data.exclusions);
  const boundaryHandling = humanizeBoundaryHandling(effectiveBoundaryHandling(data));
  const outputStyle = humanizeOutputStyle(data.intake_preferences.output_style);
  const boundaryNotes = stringValue(data.exclusions.notes) || "Not recorded";
  return `
    <div class="compact-definition-grid split-top" data-testid="wizard-scope-guardrails">
      <div><span>Output Style</span><strong>${escapeHtml(outputStyle)}</strong></div>
      <div><span>Boundary Handling</span><strong>${escapeHtml(boundaryHandling)}</strong></div>
      <div><span>Exclusions</span><strong>${escapeHtml(exclusionSummary)}</strong></div>
      <div><span>Boundary Notes</span><strong>${escapeHtml(boundaryNotes)}</strong></div>
    </div>
  `;
}

function buildConfirmationSafetyLine(data = state.wizard.data, executionProfile = estimateMission(data).execution_profile) {
  const stagedInternalValidation = data.assessment_type === "Internal Range / LAN" && data.test_profile === "Internal Validation";
  if (stagedInternalValidation) {
    const boundaryLine = data.exclusions.notes
      ? `Boundary note: ${data.exclusions.notes}`
      : "No extra boundary note is currently recorded.";
    return `This mission starts with passive discovery across the approved range. Deeper internal validation stays gated behind the follow-up lane, your configured safety posture, and explicit operator action. ${boundaryLine}`;
  }
  const executionPlan = executionPlanForProfile(executionProfile, state.runProfiles);
  const activeLine = executionPlan.runClass === "passive"
    ? `This mission stays in the ${executionPlan.profileName} execution lane, so active exploitation-style checks are not enabled in this run.`
    : data.safety.active_checks === "active"
      ? "Active exploitation-style checks are enabled only within the approved scope and current safety limits."
      : data.safety.active_checks === "guarded"
        ? "Guarded active validation is enabled, but the run remains bounded by the configured rate, concurrency, and approval lane."
        : "Active exploitation-style checks are not enabled.";
  const boundaryLine = data.exclusions.notes
    ? `Boundary note: ${data.exclusions.notes}`
    : "No extra boundary note is currently recorded.";
  return `${activeLine} ${boundaryLine}`;
}

function isPrivateIp(value) {
  const normalized = String(value || "").trim();
  if (!isLikelyIp(normalized)) return false;
  const octets = normalized.split(".").map(Number);
  return octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}
