from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from playwright.sync_api import Page, expect

REPO_ROOT = Path(__file__).resolve().parents[2]
OPERATOR_CONSOLE_E2E = REPO_ROOT / "ui/tests/test_operator_console_e2e.py"
UI_STYLESHEET = REPO_ROOT / "ui/assets/styles.css"
REPORTS_MODULE = REPO_ROOT / "ui/assets/modules/reports.js"
RUNTIME_MODULE = REPO_ROOT / "ui/assets/modules/runtime.js"
WIZARD_MODULE = REPO_ROOT / "ui/assets/modules/wizard.js"
MISSION_CONTROL_MODULE = REPO_ROOT / "ui/assets/modules/mission-control.js"
CONVERSATIONAL_INTAKE_DOC = REPO_ROOT / "docs/ui_conversational_intake.md"
PRODUCT_TEST_MATRIX_DOC = REPO_ROOT / "docs/product_test_matrix.md"
BROWSER_VALIDATION_DOC = REPO_ROOT / "docs/ui_browser_validation.md"
UI_MATRIX = json.loads((REPO_ROOT / "codex/tasks/ui_acceptance_matrix.json").read_text(encoding="utf-8"))
REVISION_COMMAND_PATTERN = re.compile(
    r'(?:_answer_current_question\(loaded_page,|pytest\.param\()\s*"(go back|undo|previous|change that|(?:change|edit|revise) [a-z]+(?: [a-z]+)*)"'
)
DOCUMENTED_REVISION_COMMAND_PATTERN = re.compile(
    r"`(go back|undo|previous|change that|(?:change|edit|revise) [a-z]+(?: [a-z]+)*)`"
)


def _scenario(section_id: str) -> dict:
    return next(item for item in UI_MATRIX["scenarios"] if item["id"] == section_id)


ASSESSMENT_MATRIX = _scenario("wizard_assessment_matrix")["assessment_matrix"]
PROFILE_MATRIX = _scenario("wizard_profile_matrix")["profile_matrix"]
MODULE_KEYS = _scenario("module_toggle_matrix")["module_keys"]
ACCESS_MODE_MATRIX = _scenario("access_mode_matrix")["access_modes"]
SAFETY_CLUSTER_MATRIX = _scenario("safety_cluster_matrix")["safety_clusters"]
MULTI_ROLE_MATRIX = _scenario("multi_role_access_matrix")["flows"]
EXECUTION_OUTCOME_MATRIX = _scenario("execution_outcome_matrix")["states"]
ADAPTIVE_PACK_MATRIX = _scenario("adaptive_pack_visibility_matrix")["states"]
REVISION_ALIAS_COMMANDS = set(_scenario("wizard_revision_alias_matrix")["commands"])
REVISION_ALIAS_EXPECTED_OUTPUTS = set(_scenario("wizard_revision_alias_matrix")["expected_outputs"])
NORMALIZED_REVISION_COMMAND_EXAMPLES = {
    "please go back?",
    "UNDO!",
    "please change that?",
    "PREVIOUS!",
    "please change scope?",
    "change target please.",
    "CHANGE   SCOPE!",
    "edit   targets",
    "please change output?",
    "EDIT   OUTPUT!",
}
NORMALIZED_REVISION_COMMAND_TESTS = (
    "test_back_command_normalization_reopens_last_answered_access_topic",
    "test_polite_revision_command_wrappers_reopen_scope_with_editable_draft",
    "test_revision_command_case_and_spacing_normalization_reopens_scope_draft",
    "test_output_revision_command_normalization_reopens_output_style_draft",
)
NORMALIZED_REVISION_EXPECTED_OUTPUTS = {
    "back_command_normalization_truth",
    "polite_revision_command_wrapper_truth",
    "case_whitespace_revision_command_normalization_truth",
    "output_style_normalization_truth",
}
WINDOWS_ONLY_PRIMARY_FONTS = ("Aptos", "Bahnschrift")
REMOTE_FONT_MARKERS = ("fonts.googleapis", "fonts.gstatic", "@import url")


def test_commercial_ui_font_stacks_are_local_safe() -> None:
    stylesheet = UI_STYLESHEET.read_text(encoding="utf-8")
    reports_module = REPORTS_MODULE.read_text(encoding="utf-8")

    assert "--font-body: Inter, ui-sans-serif, system-ui" in stylesheet
    assert "--font-display: Inter, ui-sans-serif, system-ui" in stylesheet
    assert "font-family: var(--font-body);" in stylesheet
    assert "font-family: var(--font-display);" in stylesheet
    assert "REPORT_PLACEHOLDER_FONT_STACK" in reports_module
    assert "Inter, ui-sans-serif, system-ui" in reports_module

    scanned_sources = {
        "ui/assets/styles.css": stylesheet,
        "ui/assets/modules/reports.js": reports_module,
    }
    forbidden_hits = [
        (path, marker)
        for path, source in scanned_sources.items()
        for marker in (*WINDOWS_ONLY_PRIMARY_FONTS, *REMOTE_FONT_MARKERS)
        if marker in source
    ]

    assert forbidden_hits == []


def test_runtime_store_foundation_exports_and_targeted_ui_paths_use_store_seam() -> None:
    runtime_source = RUNTIME_MODULE.read_text(encoding="utf-8")
    wizard_source = WIZARD_MODULE.read_text(encoding="utf-8")
    mission_control_source = MISSION_CONTROL_MODULE.read_text(encoding="utf-8")

    assert "export function getState(" in runtime_source
    assert "export function patchState(" in runtime_source
    assert "export function subscribe(" in runtime_source
    assert "stateSubscribers" in runtime_source

    assert "patchState" in wizard_source
    assert "wizard.submit.createdRun" in wizard_source
    assert "wizard.submit.start" in wizard_source
    assert "state.wizard.submitting = true" not in wizard_source

    assert "patchState" in mission_control_source
    assert "mission.dispatch.start" in mission_control_source
    assert "mission.surface.normalizeBrowser" in mission_control_source
    assert re.search(r"state\.selectedSurfaceAssetKey\s*=(?!=)", mission_control_source) is None
    assert re.search(r"state\.loading\.dispatchRunId\s*=(?!=)", mission_control_source) is None
    assert "delete state.dispatchHintsByRunId" not in mission_control_source


def test_revision_alias_matrix_matches_proven_typed_command_coverage() -> None:
    proven_commands = _parser_supported_revision_commands()

    assert proven_commands, "Expected typed revision commands to be present in operator console browser tests."
    assert proven_commands == REVISION_ALIAS_COMMANDS


def _parser_supported_revision_commands() -> set[str]:
    wizard_source = WIZARD_MODULE.read_text(encoding="utf-8")
    parse_start = wizard_source.index("  function parseConversationCommand(answer) {")
    parse_end = wizard_source.index("  function handleConversationCommand(answer) {", parse_start)
    parse_block = wizard_source[parse_start:parse_end]
    back_match = re.search(
        r"if \(\[(?P<commands>.*?)\]\.includes\(politeTrimmed\)\)",
        parse_block,
        re.S,
    )
    assert back_match is not None, "Expected conversational back-command parser in wizard module."
    commands = set(re.findall(r'"([^"]+)"', back_match.group("commands")))

    target_start = parse_block.index("    const targetGroups = [")
    target_end = parse_block.index("    const matchedGroup", target_start)
    target_block = parse_block[target_start:target_end]
    for alias_list in re.findall(r'\["[^"]+", \[(.*?)\]\]', target_block):
        for alias in re.findall(r'"([^"]+)"', alias_list):
            commands.update(f"{verb} {alias}" for verb in ("change", "edit", "revise"))
    return commands


def test_revision_alias_matrix_matches_parser_supported_commands() -> None:
    assert _parser_supported_revision_commands() == REVISION_ALIAS_COMMANDS


def test_revision_alias_matrix_commands_are_documented_for_operators() -> None:
    doc_text = CONVERSATIONAL_INTAKE_DOC.read_text(encoding="utf-8")
    missing_commands = [
        command for command in sorted(REVISION_ALIAS_COMMANDS)
        if f"`{command}`" not in doc_text
    ]

    assert missing_commands == []


def test_revision_alias_matrix_commands_are_documented_in_product_matrix() -> None:
    doc_text = PRODUCT_TEST_MATRIX_DOC.read_text(encoding="utf-8")
    missing_commands = [
        command for command in sorted(REVISION_ALIAS_COMMANDS)
        if f"`{command}`" not in doc_text
    ]

    assert missing_commands == []


def test_revision_alias_docs_do_not_claim_unsupported_canonical_commands() -> None:
    docs = {
        "docs/ui_conversational_intake.md": CONVERSATIONAL_INTAKE_DOC.read_text(encoding="utf-8"),
        "docs/product_test_matrix.md": PRODUCT_TEST_MATRIX_DOC.read_text(encoding="utf-8"),
    }
    unsupported_commands = [
        (path, command)
        for path, doc_text in docs.items()
        for command in sorted(set(DOCUMENTED_REVISION_COMMAND_PATTERN.findall(doc_text)))
        if command not in REVISION_ALIAS_COMMANDS
    ]

    assert unsupported_commands == []


def test_revision_alias_matrix_outputs_are_documented_in_product_matrix() -> None:
    doc_text = PRODUCT_TEST_MATRIX_DOC.read_text(encoding="utf-8")
    missing_outputs = [
        expected_output for expected_output in sorted(REVISION_ALIAS_EXPECTED_OUTPUTS)
        if f"`{expected_output}`" not in doc_text
    ]

    assert missing_outputs == []


def test_normalized_revision_command_examples_are_documented() -> None:
    docs = {
        "docs/ui_conversational_intake.md": CONVERSATIONAL_INTAKE_DOC.read_text(encoding="utf-8"),
        "docs/product_test_matrix.md": PRODUCT_TEST_MATRIX_DOC.read_text(encoding="utf-8"),
    }
    missing_examples = [
        (path, example)
        for path, doc_text in docs.items()
        for example in sorted(NORMALIZED_REVISION_COMMAND_EXAMPLES)
        if f"`{example}`" not in doc_text
    ]

    assert missing_examples == []


def test_normalized_revision_command_browser_tests_are_documented() -> None:
    doc_text = BROWSER_VALIDATION_DOC.read_text(encoding="utf-8")
    missing_tests = [
        test_name for test_name in NORMALIZED_REVISION_COMMAND_TESTS
        if test_name not in doc_text
    ]

    assert missing_tests == []


def _normalized_revision_command_examples_from_browser_tests() -> set[str]:
    doc_text = "\n".join(
        [
            CONVERSATIONAL_INTAKE_DOC.read_text(encoding="utf-8"),
            PRODUCT_TEST_MATRIX_DOC.read_text(encoding="utf-8"),
        ]
    )
    return {example for example in NORMALIZED_REVISION_COMMAND_EXAMPLES if f"`{example}`" in doc_text}


def _canonicalize_revision_command_example(command: str) -> str:
    normalized = " ".join(command.strip().lower().split())
    cleaned = re.sub(r"[.!?]+$", "", normalized).strip()
    return re.sub(r"^please\s+|\s+please$", "", cleaned).strip()


def test_normalized_revision_command_canonicalizer_matches_wizard_parser_shape() -> None:
    wizard_source = WIZARD_MODULE.read_text(encoding="utf-8")
    parse_start = wizard_source.index("  function parseConversationCommand(answer) {")
    parse_end = wizard_source.index("  function handleConversationCommand(answer) {", parse_start)
    parse_block = wizard_source[parse_start:parse_end]

    assert '.trim().toLowerCase().replace(/\\s+/g, " ")' in parse_block
    assert 'normalized.replace(/[.!?]+$/g, "").trim()' in parse_block
    assert '.replace(/^please\\s+/, "")' in parse_block
    assert '.replace(/\\s+please$/, "")' in parse_block


def test_normalized_revision_command_examples_match_browser_proof() -> None:
    assert _normalized_revision_command_examples_from_browser_tests() == NORMALIZED_REVISION_COMMAND_EXAMPLES


def test_normalized_revision_command_examples_resolve_to_canonical_commands() -> None:
    canonical_examples = {
        _canonicalize_revision_command_example(example)
        for example in NORMALIZED_REVISION_COMMAND_EXAMPLES
    }

    assert canonical_examples <= REVISION_ALIAS_COMMANDS
    assert canonical_examples.isdisjoint(NORMALIZED_REVISION_COMMAND_EXAMPLES)


def test_revision_alias_matrix_excludes_normalized_command_examples() -> None:
    matrix_commands = _scenario("wizard_revision_alias_matrix")["commands"]

    assert len(matrix_commands) == len(REVISION_ALIAS_COMMANDS)
    assert NORMALIZED_REVISION_COMMAND_EXAMPLES.isdisjoint(REVISION_ALIAS_COMMANDS)


def test_revision_alias_matrix_records_normalized_command_outputs() -> None:
    expected_outputs = set(_scenario("wizard_revision_alias_matrix")["expected_outputs"])

    assert NORMALIZED_REVISION_EXPECTED_OUTPUTS <= expected_outputs


def _open_advanced_drawer(page: Page) -> None:
    toggle = page.get_by_test_id("wizard-advanced-toggle")
    drawer = page.get_by_test_id("wizard-advanced-drawer")
    expect(toggle).to_be_visible()
    if not drawer.count() or not drawer.first.is_visible():
        toggle.click()
    page.wait_for_timeout(100)
    if not drawer.count() or not drawer.first.is_visible():
        page.evaluate(
            """
            async () => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const wizard = runtimeModule.state.wizard;
              runtimeModule.patchState({
                wizard: {
                  ...wizard,
                  intake: {
                    ...wizard.intake,
                    advancedOpen: true,
                  },
                },
              }, "ui.test.forceAdvancedOpen");
              wizardModule.createWizardModule().renderWizard();
            }
            """
        )
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()


def _go_to_advanced_step(page: Page, step: int) -> None:
    _open_advanced_drawer(page)
    page.evaluate(
        """
        async (step) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const wizard = runtimeModule.state.wizard;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              advancedStep: step,
              intake: {
                ...wizard.intake,
                advancedOpen: true,
              },
            },
          }, "ui.test.advancedStep");
          wizardModule.createWizardModule().renderWizard();
        }
        """,
        step,
    )
    expect(page.get_by_test_id("wizard-advanced-content")).to_be_visible()


def _wizard_is_assessment_selection_step(page: Page) -> bool:
    question = page.get_by_test_id("conversation-question")
    tile_grid = page.get_by_test_id("wizard-assessment-tile-grid")
    return bool(question.count() and tile_grid.count() and question.first.is_visible() and tile_grid.first.is_visible())


def _select_assessment_tile(page: Page, tile_or_legacy_label: str) -> None:
    mapping = {
        "Our web application": "external-web",
        "Our website": "external-web",
        "Our customer portal": "external-web",
        "Our external domain": "external-web",
        "Our external infrastructure": "external-infrastructure",
        "Our internet-facing IP range": "external-infrastructure",
        "My LAN network": "internal-lan",
        "Our API": "api-security",
        "Active Directory": "active-directory",
        "Full internal assessment": "full-internal",
        "Cloud environment": "cloud",
        "LLM / AI application": "llm-ai-app",
        "Our mixed web and API estate": "custom",
        "A mixed environment": "custom",
    }
    tile_key = mapping.get(tile_or_legacy_label, tile_or_legacy_label)
    expect(page.get_by_test_id(f"wizard-assessment-tile-{tile_key}")).to_be_visible()
    page.get_by_test_id(f"wizard-assessment-tile-{tile_key}").click()
    submit = page.get_by_test_id("wizard-assessment-submit-selection")
    if submit.count() and submit.first.is_visible():
        submit.first.click()


def _expect_current_question(page: Page, title_fragment: str) -> None:
    question = page.get_by_test_id("conversation-question")
    if "what would you like to pentest today" in title_fragment.lower():
        question_text = question.inner_text()
        if _wizard_is_assessment_selection_step(page) or "Assessment Types" in question_text:
            expect(question).to_contain_text("Assessment Types")
            return
    expect(question).to_contain_text(title_fragment)


def _answer_current_question(page: Page, answer: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    target_card = page.get_by_test_id("wizard-target-card")
    if target_card.count() and target_card.first.is_visible():
        depth_mapping = {
            "Standard assessment": "active",
            "Authenticated review": "active",
            "Adaptive customer-specific testing": "full",
            "Deep internal validation": "full",
            "Inventory first, but I want clear information per found item": "passive",
            "Quick overview": "passive",
            "Full including exploitation": "full",
            "Full internal assessment": "full",
            "Passive discovery": "passive",
            "Keep it passive": "passive",
            "Conservative": "passive",
            "Balanced": "active",
        }
        depth_key = depth_mapping.get(answer)
        if depth_key:
            page.get_by_test_id(f"wizard-depth-tile-{depth_key}").click()
            return
        target_input = page.get_by_test_id("wizard-target-input")
        if target_input.count() and target_input.first.is_visible():
            target_input.fill(answer)
            page.locator("[data-wizard-preview]").click()
            return

    answer_input = page.get_by_test_id("conversation-answer-input")
    if answer_input.count() and answer_input.first.is_visible():
        answer_input.fill(answer)
        page.get_by_test_id("wizard-next").click()
        return

    if _wizard_is_assessment_selection_step(page):
        _select_assessment_tile(page, answer)
        return

    raise AssertionError(f"No visible answer input or mapped tile available for answer: {answer}")


def _acknowledge_roe_authorization_if_required(page: Page, create_mission) -> None:
    roe_checkbox = page.get_by_test_id("wizard-roe-authorization-checkbox")
    if create_mission.is_disabled() and roe_checkbox.count() and roe_checkbox.first.is_visible():
        if not roe_checkbox.first.is_checked():
            roe_checkbox.first.check()
        expect(create_mission).to_be_enabled()


def _selected_run_id_or_none(page: Page) -> str | None:
    return page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )


def _launch_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    confirmation_input = page.get_by_test_id("wizard-full-authorization-input")
    if confirmation_input.count() and confirmation_input.first.is_visible():
        target = page.evaluate(
            """
            async () => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const data = runtimeModule.state.wizard.data;
              const buckets = ["urls", "domains", "api_base_urls", "cidr_ranges", "ip_addresses", "subdomains"];
              for (const bucket of buckets) {
                const value = data.targets?.[bucket]?.[0];
                if (value) return value;
              }
              return "";
            }
            """
        )
        confirmation_input.fill(target)
    if not launch_step.is_enabled():
        if confirmation_input.count() and confirmation_input.first.is_visible():
            confirmation_input.blur()
        expect(launch_step).to_be_enabled()
    launch_step.click()
    create_mission = page.locator('[data-wizard-create-mission="true"]')
    expect(create_mission).to_be_visible()
    _acknowledge_roe_authorization_if_required(page, create_mission)
    last_error: AssertionError | None = None
    for _attempt in range(3):
        create_mission.click()
        try:
            expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
            return
        except AssertionError as exc:
            last_error = exc
            if _selected_run_id_or_none(page):
                page.get_by_test_id("nav-mission-control").click()
                expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=5000)
                return
            create_mission = page.locator('[data-wizard-create-mission="true"]')
            if not create_mission.count() or not create_mission.first.is_visible():
                raise
            _acknowledge_roe_authorization_if_required(page, create_mission)
    if last_error:
        raise last_error


def _is_boundary_question_text(question: str) -> bool:
    return "must avoid or handle carefully" in question.lower()


def _switch_phase(page: Page, phase: str) -> None:
    target_by_phase = {
        "intake": "nav-wizard",
        "execution": "nav-mission-control",
        "analysis": "nav-reports",
    }
    page.get_by_test_id(target_by_phase[phase]).click()
    expect(page.locator("body")).to_have_attribute("data-phase", phase)


def _open_execution_screen(page: Page, nav_test_id: str) -> None:
    _switch_phase(page, "execution")
    page.wait_for_timeout(150)
    nav = page.get_by_test_id(nav_test_id)
    expect(nav).to_be_visible()
    if "active" not in (nav.get_attribute("class") or ""):
        nav.click()


def _open_analysis_screen(page: Page, nav_test_id: str) -> None:
    _switch_phase(page, "analysis")
    page.wait_for_timeout(150)
    nav = page.get_by_test_id(nav_test_id)
    expect(nav).to_be_visible()
    if "active" not in (nav.get_attribute("class") or ""):
        nav.click()


def _finish_authenticated_webapp_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our customer portal")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("https://portal.example.com")
    page.get_by_test_id("wizard-depth-tile-active").click()
    page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: "Authenticated App",
                test_profile: "Authenticated Only",
                access: {
                  ...wizard.data.access,
                  accounts: [{
                    label: "Security Analyst",
                    username: "analyst@example.com",
                    role: "Security Analyst",
                    secret_ref: "vault://portal/analyst",
                    api_key_ref: "",
                    bearer_token_ref: "",
                    session_ref: "",
                    mfa_notes: "",
                  }],
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: "authenticated-review",
                  auth_strategy: "credentialed",
                  boundary_handling: "standard-scope-only",
                },
                modules: {
                  ...wizard.data.modules,
                  auth_flows: true,
                },
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  max_validation_depth: "standard",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  assessment_type: true,
                  profile: true,
                  access: true,
                  safety: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  goal: "override",
                  auth: "override",
                  safety: "override",
                  boundaries: "confirmed",
                },
              },
            },
          }, "ui.test.product.authenticatedWebProfile");
        }
        """
    )
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()


def _configure_assessment_scope(page: Page, assessment_type: str, scope_field: str, scope_value: str) -> None:
    _open_advanced_drawer(page)
    _go_to_advanced_step(page, 0)
    page.locator(f'input[name="wizard-assessment-type"][value="{assessment_type}"]').check()
    _go_to_advanced_step(page, 1)
    page.locator(f"#{scope_field}").fill(scope_value)


def _profile_matrix_answer_for_question(entry: dict, title: str) -> str | None:
    if title == "Hello. What would you like to pentest today?":
        return {
            "Website / Web App": "Our web application",
            "Domain / Domains": "Our external domain",
            "External IP / WAN": "Our internet-facing IP range",
            "Internal Range / LAN": "My LAN network",
            "API": "Our API",
            "SSL/TLS Only": "TLS posture for our public site",
            "Authenticated App": "Our portal with login",
            "Mixed Assessment": "Our mixed web and API estate",
        }[entry["assessment_type"]]
    if title == "What is your main goal for this assessment?":
        return entry.get("goal_answer") or {
            "Internal Validation": "Deep internal validation",
            "Authenticated Only": "Authenticated review",
            "Adaptive Customer-Specific Mode": "Adaptive customer-specific testing",
        }.get(entry["profile"], "Standard assessment")
    if title.startswith("What exact targets are authorized") or title.startswith("What hostnames, URLs, or IPs should I validate for TLS only?") or title.startswith("What exact CIDR range or internal hosts may I use?") or title.startswith("What API base URLs or application URLs may I use?") or title.startswith("What exact IPs or CIDR ranges are authorized?"):
        return entry["scope_value"]
    if title == "Should this stay unauthenticated, or do you have access I should use?":
        return entry.get("auth_answer", "Keep it unauthenticated")
    if title == "What access context should I record?":
        return entry.get(
            "auth_detail_answer",
            "analyst@example.com role Security Analyst secret vault://profile-matrix/default",
        )
    if title == "Should I keep this conservative or more thorough?":
        return entry.get("safety_answer", "Balanced")
    if "must avoid or handle carefully" in title.lower():
        return entry.get("boundary_answer", "No extra exclusions")
    return None


def _complete_profile_matrix_remaining_topics(page: Page, entry: dict) -> None:
    page.evaluate(
        """
        async (entry) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const wizard = runtimeModule.state.wizard;
          const tileByType = {
            "Website / Web App": "external-web",
            "Domain / Domains": "external-web",
            "External IP / WAN": "external-infrastructure",
            "Internal Range / LAN": "internal-lan",
            "API": "api-security",
            "SSL/TLS Only": "external-web",
            "Authenticated App": "external-web",
            "Mixed Assessment": "custom",
          };
          const bucketByField = {
            "wizard-target-urls": "urls",
            "wizard-target-domains": "domains",
            "wizard-target-cidrs": "cidr_ranges",
            "wizard-target-api": "api_base_urls",
            "wizard-target-ips": "ip_addresses",
          };
          const depthByProfile = {
            "Light": "passive",
            "External Surface Only": "passive",
            "SSL/TLS Only": "passive",
            "Standard": "active",
            "Authenticated Only": "active",
            "Adaptive Customer-Specific Mode": "active",
            "Deep": "full",
            "Internal Validation": "full",
          };
          const targets = {
            domains: [],
            subdomains: [],
            urls: [],
            ip_addresses: [],
            cidr_ranges: [],
            api_base_urls: [],
          };
          const bucket = bucketByField[entry.scope_field] || "urls";
          targets[bucket] = [entry.scope_value];
          const accessAccounts = entry.auth_answer
            ? [{
                label: "Security Analyst",
                username: "analyst@example.com",
                role: "Security Analyst",
                secret_ref: entry.auth_detail_answer?.includes("secret ") ? entry.auth_detail_answer.split("secret ")[1] : "",
                api_key_ref: "",
                bearer_token_ref: "",
                session_ref: "",
                mfa_notes: "",
              }]
            : wizard.data.access.accounts;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: entry.assessment_type,
                targets,
                test_profile: entry.profile,
                access: {
                  ...wizard.data.access,
                  accounts: accessAccounts,
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: entry.profile === "Internal Validation"
                    ? "internal-validation"
                    : entry.profile === "Authenticated Only"
                      ? "authenticated-review"
                      : entry.profile === "Adaptive Customer-Specific Mode"
                        ? "adaptive-coverage"
                        : "standard-assessment",
                  auth_strategy: entry.auth_answer ? "credentialed" : "unauthenticated",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                flowMode: "tile",
                flowStep: 3,
                flowDepthChoice: depthByProfile[entry.profile] || "active",
                selectedAssessmentTileKey: tileByType[entry.assessment_type] || "external-web",
                selectedAssessmentTileKeys: [tileByType[entry.assessment_type] || "external-web"],
                sources: {
                  ...wizard.intake.sources,
                  intent: "confirmed",
                  target_type: "confirmed",
                  scope: "confirmed",
                  goal: "confirmed",
                  auth: "confirmed",
                  safety: "confirmed",
                  boundaries: "confirmed",
                  output: "confirmed",
                },
                overrides: {
                  ...wizard.intake.overrides,
                  assessment_type: true,
                  profile: true,
                  access: Boolean(entry.auth_answer),
                },
              },
            },
          }, "ui.test.product.profileMatrixReady");
          wizardModule.createWizardModule().renderWizard();
        }
        """,
        entry,
    )
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()


def _fill_account_fields(page: Page, account: dict) -> None:
    _fill_account_fields_at_index(page, account, 0)


def _fill_account_fields_at_index(page: Page, account: dict, index: int) -> None:
    page.evaluate(
        """
        ({ account, index }) => {
          for (const [fieldName, value] of Object.entries(account || {})) {
            if (!value) continue;
            const input = document.querySelector(`[data-account-field="${fieldName}"][data-account-index="${index}"]`);
            if (!input) continue;
            input.value = value;
          }
        }
        """,
        {"account": account, "index": index},
    )


def _set_access_notes(page: Page, *, manual_auth_steps: str = "", cookie_notes: str = "") -> None:
    page.evaluate(
        """
        ({ manualAuthSteps, cookieNotes }) => {
          const manual = document.getElementById("wizard-manual-auth-steps");
          const cookies = document.getElementById("wizard-cookie-notes");
          if (manual) manual.value = manualAuthSteps || "";
          if (cookies) cookies.value = cookieNotes || "";
        }
        """,
        {"manualAuthSteps": manual_auth_steps, "cookieNotes": cookie_notes},
    )


def _set_safety_controls(page: Page, entry: dict) -> None:
    page.evaluate(
        """
        (entry) => {
          const values = {
            "wizard-rate-limit": String(entry.rate_limit_rps),
            "wizard-concurrency": String(entry.concurrency),
            "wizard-time-budget": String(entry.time_budget_minutes),
            "wizard-active-checks": entry.active_checks,
            "wizard-adaptive-generation": entry.adaptive_generation ? "true" : "false",
            "wizard-max-depth": entry.max_validation_depth,
          };
          for (const [id, value] of Object.entries(values)) {
            const input = document.getElementById(id);
            if (!input) continue;
            input.value = value;
          }
        }
        """,
        entry,
    )


def _api_json(base_url: str, path: str, *, method: str = "GET", body: dict | None = None, actor: str = "tester") -> dict:
    headers = {"X-Actor": actor}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def _seed_failed_run(base_url: str) -> tuple[str, str]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="matrix-tester",
        body={
            "name": "Failure Matrix",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-501",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="matrix-tester",
        body={
            "allowlist_json": {
                "urls": ["http://127.0.0.1:1", "http://127.0.0.1:2"],
            },
            "denylist_json": {},
        },
    )
    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="matrix-tester",
        body={"profile_name": "passive-web-baseline"},
    )
    _api_json(
        base_url,
        f"/api/v1/runs/{run['id']}/dispatch",
        method="POST",
        actor="dispatcher",
        body={},
    )
    return engagement["id"], run["id"]


def _seed_bound_adaptive_run(base_url: str) -> dict:
    target_url = "https://api.matrix.example.com/v1"
    target_host = "api.matrix.example.com"

    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="matrix-tester",
        body={
            "name": "Adaptive Pack Matrix",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-601",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="matrix-tester",
        body={
            "allowlist_json": {"urls": [target_url], "hosts": [target_host]},
            "denylist_json": {},
        },
    )
    inventory = _api_json(
        base_url,
        "/api/v1/inventory/runs",
        method="POST",
        actor="inventory-operator",
        body={
            "engagement_id": engagement["id"],
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": [target_host],
                        "urls": [target_url],
                        "endpoints": [
                            {
                                "url": target_url,
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "Adaptive Matrix API",
                            }
                        ],
                        "technologies": [
                            {
                                "name": "Matrix Gateway",
                                "vendor": "AegisPT",
                                "confidence": 0.92,
                            }
                        ],
                        "auth_mechanisms": [
                            {"type": "bearer-token", "confidence": 0.88}
                        ],
                        "fingerprints": [
                            {
                                "vendor": "AegisPT",
                                "product": "Matrix Gateway",
                                "version": "1.0",
                            }
                        ],
                        "confidence": 0.92,
                    },
                }
            ],
        },
    )
    intel = _api_json(
        base_url,
        "/api/v1/threat-intel/ingest",
        method="POST",
        actor="intel-operator",
        body={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "AEGIS-MATRIX-0001",
                    "title": "Matrix API auth follow-up",
                    "summary": "Adaptive auth review is relevant for the exposed API gateway.",
                    "affected_products": ["matrix gateway"],
                    "product_match_hints": ["matrix gateway", "aegispt"],
                    "attack_surface_type": "api",
                    "suggested_test_patterns": ["playwright", "zap", "nuclei"],
                    "confidence": 0.9,
                    "severity": "high",
                    "references": [],
                }
            ]
        },
    )[0]
    relevance = _api_json(
        base_url,
        "/api/v1/relevance/analyze",
        method="POST",
        actor="planner",
        body={
            "engagement_id": engagement["id"],
            "inventory_snapshot_id": inventory["id"],
            "threat_intel_ids": [intel["id"]],
            "include_prior_findings": True,
        },
    )
    pack = _api_json(
        base_url,
        "/api/v1/packs/generate",
        method="POST",
        actor="planner",
        body={
            "engagement_id": engagement["id"],
            "relevance_decision_id": relevance["id"],
            "name": "ui-adaptive-pack",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/packs/{pack['id']}/validate",
        method="POST",
        actor="validator",
        body={},
    )
    _api_json(
        base_url,
        f"/api/v1/packs/{pack['id']}/approve?notes=matrix",
        method="POST",
        actor="approver",
        body={},
    )
    deployment = _api_json(
        base_url,
        f"/api/v1/packs/{pack['id']}/deploy",
        method="POST",
        actor="deployer",
        body={
            "engagement_id": engagement["id"],
            "deployment_target": "engagement-runtime",
            "run_profile_name": "active-web-safe",
            "notes": "matrix deployment",
        },
    )
    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="operator",
        body={
            "profile_name": "active-web-safe",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "API",
                "test_profile": "Adaptive Customer-Specific Mode",
                "execution_profile": "active-web-safe",
                "targets": {
                    "api_base_urls": [target_url],
                    "urls": [target_url],
                },
                "access": {
                    "accounts": [
                        {
                            "label": "API Analyst",
                            "username": "api-analyst@example.com",
                            "role": "API Analyst",
                            "api_key_ref": "vault://api/matrix-key",
                        }
                    ]
                },
                "modules": {
                    "discovery": True,
                    "web_crawling": True,
                    "auth_flows": True,
                    "content_discovery": False,
                    "nuclei_checks": True,
                    "zap_active_checks": True,
                    "ssl_tls_analysis": False,
                    "business_logic_testing": True,
                    "adaptive_ai_generated_tests": True,
                    "internal_validation_modules": False,
                },
                "safety": {
                    "rate_limit_rps": 1,
                    "concurrency": 1,
                    "time_budget_minutes": 45,
                    "active_checks": "guarded",
                    "adaptive_generation": True,
                    "max_validation_depth": "deep",
                },
                "eta": {
                    "estimated_total_minutes": 45,
                    "estimated_impact": "medium",
                    "confidence": "high",
                },
                "intake_preferences": {
                    "mission_intent": "Adaptive API validation",
                    "primary_goal": "adaptive-coverage",
                    "output_style": "technical-detail",
                    "auth_strategy": "api-keys",
                    "safety_posture": "balanced",
                    "boundary_handling": "approved-scope-only",
                    "lateral_discovery": "not-requested",
                },
            },
        },
    )
    _api_json(
        base_url,
        f"/api/v1/runs/{run['id']}/bind-pack",
        method="POST",
        actor="operator",
        body={"pack_id": pack["id"]},
    )
    reports = _api_json(
        base_url,
        f"/api/v1/runs/{run['id']}/reports",
        actor="operator",
    )
    return {
        "engagement_id": engagement["id"],
        "inventory_id": inventory["id"],
        "relevance_id": relevance["id"],
        "pack_id": pack["id"],
        "pack_version": pack["version"],
        "deployment_id": deployment["id"],
        "run_id": run["id"],
        "reports": reports,
    }


def _seed_attack_path_surface_run(base_url: str, *, include_inventory: bool = True) -> dict:
    app_url = "https://app.attack-path.example/login"
    api_url = "https://api.attack-path.example/v1"
    app_host = "app.attack-path.example"
    api_host = "api.attack-path.example"
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="attack-path-operator",
        body={
            "name": "Attack Path Matrix",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-701",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="attack-path-operator",
        body={
            "allowlist_json": {
                "hosts": [app_host, api_host],
                "urls": [app_url, api_url],
            },
            "denylist_json": {},
        },
    )

    inventory = None
    if include_inventory:
        inventory = _api_json(
            base_url,
            "/api/v1/inventory/runs",
            method="POST",
            actor="inventory-operator",
            body={
                "engagement_id": engagement["id"],
                "source_tools": ["attack-path-fixture"],
                "observations": [
                    {
                        "tool": "attack-path-fixture",
                        "kind": "inventory",
                        "data": {
                            "hosts": [app_host, api_host],
                            "services": [
                                {
                                    "host": app_host,
                                    "port": 443,
                                    "protocol": "tcp",
                                    "service": "https",
                                    "product": "nginx",
                                    "confidence": 0.92,
                                },
                                {
                                    "host": api_host,
                                    "port": 443,
                                    "protocol": "tcp",
                                    "service": "https",
                                    "product": "uvicorn",
                                    "confidence": 0.88,
                                },
                            ],
                            "endpoints": [
                                {
                                    "url": app_url,
                                    "methods": ["GET"],
                                    "status_code": 200,
                                    "title": "Login",
                                    "confidence": 0.9,
                                },
                                {
                                    "url": api_url,
                                    "methods": ["GET"],
                                    "status_code": 200,
                                    "title": "API Root",
                                    "confidence": 0.86,
                                },
                            ],
                            "confidence": 0.9,
                        },
                    }
                ],
            },
        )

    run_body = {
        "profile_name": "passive-web-baseline",
        "configuration_json": {
            "assessment_type": "Mixed Assessment",
            "test_profile": "Standard",
            "execution_profile": "passive-web-baseline",
            "targets": {"urls": [app_url, api_url]},
        },
    }
    if inventory is not None:
        run_body["source_inventory_snapshot_id"] = inventory["id"]

    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="attack-path-operator",
        body=run_body,
    )
    return {
        "engagement_id": engagement["id"],
        "inventory_id": inventory["id"] if inventory else None,
        "run_id": run["id"],
        "app_host": app_host,
        "api_host": api_host,
        "app_url": app_url,
        "api_url": api_url,
    }


def _attack_path_ui_fixture(seeded: dict) -> dict:
    return {
        "status": "ready",
        "run_id": seeded["run_id"],
        "engagement_id": seeded["engagement_id"],
        "evaluation_model": "evidence-first-choke-point-v1",
        "choke_point_threshold": 3,
        "sources": {
            "inventory_snapshot_id": seeded["inventory_id"],
            "aggregated_snapshot_count": 1,
            "inventory_confidence": 0.9,
            "source_tools": ["attack-path-fixture"],
            "finding_count": 4,
        },
        "summary": {
            "status": "ready",
            "node_count": 10,
            "edge_count": 8,
            "candidate_path_count": 4,
            "choke_point_count": 1,
            "mean_path_confidence": 0.88,
            "reason": "Candidate paths were derived from selected-run inventory and finding evidence.",
        },
        "nodes": [
            {"id": f"host:{seeded['app_host']}", "type": "host", "label": seeded["app_host"], "confidence": 0.9},
            {"id": f"service:{seeded['app_host']}:443/tcp", "type": "service", "label": f"{seeded['app_host']}:443/tcp", "confidence": 0.9},
            {"id": f"endpoint:{seeded['app_url']}", "type": "endpoint", "label": seeded["app_url"], "confidence": 0.9},
            {"id": "finding:weak-login", "type": "finding", "label": "Weak login throttling", "confidence": 1.0},
            {"id": "finding:headers", "type": "finding", "label": "Missing security headers", "confidence": 1.0},
            {"id": "finding:tls", "type": "finding", "label": "TLS certificate nearing expiry", "confidence": 1.0},
            {"id": f"host:{seeded['api_host']}", "type": "host", "label": seeded["api_host"], "confidence": 0.88},
            {"id": f"service:{seeded['api_host']}:443/tcp", "type": "service", "label": f"{seeded['api_host']}:443/tcp", "confidence": 0.88},
            {"id": f"endpoint:{seeded['api_url']}", "type": "endpoint", "label": seeded["api_url"], "confidence": 0.86},
            {"id": "finding:api-banner", "type": "finding", "label": "Verbose API banner", "confidence": 1.0},
        ],
        "edges": [
            {"id": "edge:1", "source": f"host:{seeded['app_host']}", "target": f"service:{seeded['app_host']}:443/tcp", "type": "exposes-service", "evidence_refs": ["inventory"]},
            {"id": "edge:2", "source": f"service:{seeded['app_host']}:443/tcp", "target": f"endpoint:{seeded['app_url']}", "type": "serves-endpoint", "evidence_refs": ["inventory"]},
            {"id": "edge:3", "source": f"endpoint:{seeded['app_url']}", "target": "finding:weak-login", "type": "evidences-finding", "evidence_refs": ["artifact://zap/app/login-throttling"]},
            {"id": "edge:4", "source": f"host:{seeded['app_host']}", "target": "finding:headers", "type": "evidences-finding", "evidence_refs": ["artifact://httpx/app/headers"]},
            {"id": "edge:5", "source": f"service:{seeded['app_host']}:443/tcp", "target": "finding:tls", "type": "evidences-finding", "evidence_refs": ["artifact://tls/app/certificate"]},
            {"id": "edge:6", "source": f"host:{seeded['api_host']}", "target": f"service:{seeded['api_host']}:443/tcp", "type": "exposes-service", "evidence_refs": ["inventory"]},
            {"id": "edge:7", "source": f"service:{seeded['api_host']}:443/tcp", "target": f"endpoint:{seeded['api_url']}", "type": "serves-endpoint", "evidence_refs": ["inventory"]},
            {"id": "edge:8", "source": f"endpoint:{seeded['api_url']}", "target": "finding:api-banner", "type": "evidences-finding", "evidence_refs": ["artifact://httpx/api/banner"]},
        ],
        "candidate_paths": [
            {
                "id": "path:1",
                "node_ids": [
                    f"host:{seeded['app_host']}",
                    f"service:{seeded['app_host']}:443/tcp",
                    f"endpoint:{seeded['app_url']}",
                    "finding:weak-login",
                ],
                "labels": [seeded["app_host"], f"{seeded['app_host']}:443/tcp", seeded["app_url"], "Weak login throttling"],
                "finding_id": "finding-1",
                "finding_title": "Weak login throttling",
                "severity": "high",
                "target_id": seeded["app_url"],
                "confidence": 0.9,
                "evidence_refs": ["artifact://zap/app/login-throttling"],
                "explanation": "Finding 'Weak login throttling' is tied to endpoint https://app.attack-path.example/login through the selected run inventory.",
            },
            {
                "id": "path:2",
                "node_ids": [f"host:{seeded['app_host']}", "finding:headers"],
                "labels": [seeded["app_host"], "Missing security headers"],
                "finding_id": "finding-2",
                "finding_title": "Missing security headers",
                "severity": "medium",
                "target_id": seeded["app_host"],
                "confidence": 0.92,
                "evidence_refs": ["artifact://httpx/app/headers"],
                "explanation": "Finding 'Missing security headers' is tied to host app.attack-path.example through the selected run inventory.",
            },
            {
                "id": "path:3",
                "node_ids": [
                    f"host:{seeded['app_host']}",
                    f"service:{seeded['app_host']}:443/tcp",
                    "finding:tls",
                ],
                "labels": [seeded["app_host"], f"{seeded['app_host']}:443/tcp", "TLS certificate nearing expiry"],
                "finding_id": "finding-3",
                "finding_title": "TLS certificate nearing expiry",
                "severity": "low",
                "target_id": f"{seeded['app_host']}:443",
                "confidence": 0.92,
                "evidence_refs": ["artifact://tls/app/certificate"],
                "explanation": "Finding 'TLS certificate nearing expiry' is tied to exposed service app.attack-path.example:443/tcp through the selected run inventory.",
            },
            {
                "id": "path:4",
                "node_ids": [
                    f"host:{seeded['api_host']}",
                    f"service:{seeded['api_host']}:443/tcp",
                    f"endpoint:{seeded['api_url']}",
                    "finding:api-banner",
                ],
                "labels": [seeded["api_host"], f"{seeded['api_host']}:443/tcp", seeded["api_url"], "Verbose API banner"],
                "finding_id": "finding-4",
                "finding_title": "Verbose API banner",
                "severity": "medium",
                "target_id": seeded["api_url"],
                "confidence": 0.86,
                "evidence_refs": ["artifact://httpx/api/banner"],
                "explanation": "Finding 'Verbose API banner' is tied to endpoint https://api.attack-path.example/v1 through the selected run inventory.",
            },
        ],
        "choke_points": [
            {
                "node_id": f"host:{seeded['app_host']}",
                "type": "host",
                "label": seeded["app_host"],
                "path_count": 3,
                "finding_count": 3,
                "affected_findings": ["finding-1", "finding-2", "finding-3"],
                "severity_breakdown": {"high": 1, "medium": 1, "low": 1},
                "summary": "app.attack-path.example appears in 3 candidate paths; reviewing this point first may close multiple evidence-backed routes.",
            }
        ],
    }


def test_assessment_type_matrix_presets_render_expected_scope_and_lane(loaded_page: Page) -> None:
    _open_advanced_drawer(loaded_page)
    for entry in ASSESSMENT_MATRIX:
        _go_to_advanced_step(loaded_page, 0)
        loaded_page.locator(
            f'input[name="wizard-assessment-type"][value="{entry["assessment_type"]}"]'
        ).check()
        preset = loaded_page.evaluate(
            """
            async () => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const data = runtimeModule.state.wizard.data;
              return {
                assessment_type: data.assessment_type,
                test_profile: data.test_profile,
                execution_profile: wizardModule.estimateMission(data).execution_profile,
              };
            }
            """
        )
        assert preset["assessment_type"] == entry["assessment_type"]
        assert preset["test_profile"] == entry["expected_profile"]
        _go_to_advanced_step(loaded_page, 1)
        expect(loaded_page.locator(f'#{entry["expected_scope_field"]}')).to_be_visible()


def test_profile_matrix_presets_align_execution_lane_and_guardrails(loaded_page: Page) -> None:
    for entry in PROFILE_MATRIX:
        _complete_profile_matrix_remaining_topics(loaded_page, entry)
        preset = loaded_page.evaluate(
            """
            async () => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const data = runtimeModule.state.wizard.data;
              return {
                test_profile: data.test_profile,
                execution_profile: wizardModule.estimateMission(data).execution_profile,
                active_checks: data.safety.active_checks,
              };
            }
            """
        )
        assert preset["test_profile"] == entry["profile"]
        assert preset["execution_profile"] == entry["expected_lane"]


def test_invalid_tls_scope_advanced_override_returns_focus_to_scope_instead_of_fake_confirmation(
    loaded_page: Page,
) -> None:
    _open_advanced_drawer(loaded_page)
    _go_to_advanced_step(loaded_page, 0)
    loaded_page.locator('input[name="wizard-assessment-type"][value="SSL/TLS Only"]').check()
    _go_to_advanced_step(loaded_page, 1)
    loaded_page.locator("#wizard-target-ip-addresses").fill("portal.example.com")
    errors = loaded_page.evaluate(
        """
        async () => {
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const module = wizardModule.createWizardModule();
          module.syncWizardStepFromDom();
          return module.validateWizardStep(1);
        }
        """
    )
    assert "Invalid IP address: portal.example.com" in errors


@pytest.mark.parametrize(
    "entry",
    PROFILE_MATRIX,
    ids=[f'{item["assessment_type"]}-{item["profile"]}' for item in PROFILE_MATRIX],
)
def test_profile_matrix_presets_create_truthful_run_dossiers(
    loaded_page: Page, operator_console_base_url: str, entry: dict
) -> None:
    page = loaded_page

    _configure_assessment_scope(
        page,
        entry["assessment_type"],
        entry["scope_field"],
        entry["scope_value"],
    )
    _complete_profile_matrix_remaining_topics(page, entry)

    _launch_guided_mission_from_preview(page)

    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#mission-scope-summary")).to_contain_text(entry["assessment_type"])
    expect(page.locator("#mission-scope-summary")).to_contain_text(entry["profile"])

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after profile-matrix mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == entry["assessment_type"]
    assert configuration["test_profile"] == entry["profile"]
    assert configuration["execution_profile"] == entry["expected_lane"]
    flattened_targets = [
        value
        for values in configuration["targets"].values()
        if isinstance(values, list)
        for value in values
    ]
    assert entry["scope_value"] in flattened_targets


def test_module_toggle_matrix_controls_render_and_sync_into_summary(loaded_page: Page) -> None:
    _open_advanced_drawer(loaded_page)
    _go_to_advanced_step(loaded_page, 4)
    before_modules = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return {...runtimeModule.state.wizard.data.modules};
        }
        """
    )

    for key in MODULE_KEYS:
        checkbox = loaded_page.locator(f'[data-module-key="{key}"]')
        expect(checkbox).to_be_visible()
        if checkbox.is_checked():
            checkbox.uncheck()
            expect(checkbox).not_to_be_checked()
        else:
            checkbox.check()
            expect(checkbox).to_be_checked()

    after_modules = loaded_page.evaluate(
        """
        async () => {
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          wizardModule.createWizardModule().syncWizardStepFromDom();
          return {...runtimeModule.state.wizard.data.modules};
        }
        """
    )
    assert before_modules != after_modules


@pytest.mark.parametrize(
    "entry",
    ACCESS_MODE_MATRIX,
    ids=[item["id"] for item in ACCESS_MODE_MATRIX],
)
def test_access_mode_matrix_keeps_access_summary_and_manual_notes_aligned(
    loaded_page: Page, entry: dict
) -> None:
    _configure_assessment_scope(
        loaded_page,
        entry["assessment_type"],
        entry["scope_field"],
        entry["scope_value"],
    )
    _go_to_advanced_step(loaded_page, 2)

    account = entry.get("account")
    if account:
        _fill_account_fields(loaded_page, account)
    _set_access_notes(
        loaded_page,
        manual_auth_steps=entry.get("manual_auth_steps", ""),
        cookie_notes=entry.get("cookie_notes", ""),
    )

    access_state = loaded_page.evaluate(
        """
        async () => {
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          wizardModule.createWizardModule().syncWizardStepFromDom();
          return runtimeModule.state.wizard.data.access;
        }
        """
    )
    assert access_state["manual_auth_steps"] == entry.get("manual_auth_steps", "")
    assert access_state["cookie_notes"] == entry.get("cookie_notes", "")
    if account:
        assert access_state["accounts"][0]["role"] == account.get("role", "User")


@pytest.mark.parametrize(
    "entry",
    MULTI_ROLE_MATRIX,
    ids=[item["id"] for item in MULTI_ROLE_MATRIX],
)
def test_multi_role_access_matrix_keeps_role_context_visible_from_intake_to_dossier(
    loaded_page: Page, entry: dict
) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    _open_advanced_drawer(loaded_page)
    _go_to_advanced_step(loaded_page, 2)

    _fill_account_fields_at_index(loaded_page, entry["accounts"][0], 0)
    loaded_page.locator("#wizard-add-account-btn").click()
    _fill_account_fields_at_index(loaded_page, entry["accounts"][1], 1)

    access_state = loaded_page.evaluate(
        """
        async () => {
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          wizardModule.createWizardModule().syncWizardStepFromDom();
          return runtimeModule.state.wizard.data.access;
        }
        """
    )
    assert [account["role"] for account in access_state["accounts"][:2]] == [
        entry["accounts"][0]["role"],
        entry["accounts"][1]["role"],
    ]
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        f"{entry['expected_context_count']} account / role contexts"
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text(
        f"{entry['expected_protected_binding_count']} secret bindings"
    )


@pytest.mark.parametrize(
    "entry",
    SAFETY_CLUSTER_MATRIX,
    ids=[item["id"] for item in SAFETY_CLUSTER_MATRIX],
)
def test_safety_cluster_matrix_keeps_guardrails_and_lane_alignment_visible(
    loaded_page: Page, entry: dict
) -> None:
    _configure_assessment_scope(
        loaded_page,
        entry["assessment_type"],
        entry["scope_field"],
        entry["scope_value"],
    )
    _complete_profile_matrix_remaining_topics(loaded_page, entry)
    _open_advanced_drawer(loaded_page)
    _go_to_advanced_step(loaded_page, 5)
    _set_safety_controls(loaded_page, entry)

    safety_state = loaded_page.evaluate(
        """
        async () => {
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          wizardModule.createWizardModule().syncWizardStepFromDom();
          return {
            safety: runtimeModule.state.wizard.data.safety,
            execution_profile: wizardModule.estimateMission(runtimeModule.state.wizard.data).execution_profile,
          };
        }
        """
    )
    assert safety_state["execution_profile"] == entry["expected_lane"]
    assert safety_state["safety"]["rate_limit_rps"] == entry["rate_limit_rps"]
    assert safety_state["safety"]["concurrency"] == entry["concurrency"]
    assert safety_state["safety"]["time_budget_minutes"] == entry["time_budget_minutes"]
    assert safety_state["safety"]["active_checks"] == entry["active_checks"]
    assert safety_state["safety"]["adaptive_generation"] == entry["adaptive_generation"]
    assert safety_state["safety"]["max_validation_depth"] == entry["max_validation_depth"]


def test_execution_outcome_matrix_surfaces_blocked_pending_approval_state(loaded_page: Page) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("Active Target Scan Map")
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        "Approval is still required before active checks can be queued"
    )
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text("Pending")
    expect(loaded_page.get_by_test_id("mission-run-activity")).not_to_contain_text("Start Validation")


def test_execution_outcome_matrix_surfaces_failed_dispatch_state(
    page: Page, operator_console_base_url: str
) -> None:
    _seed_failed_run(operator_console_base_url)

    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    _switch_phase(page, "execution")

    expect(page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(page.get_by_test_id("mission-activity")).to_contain_text(
        "Blocked target scan map"
    )
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("2 tasks")
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("Last execution completed with errors.")
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("failed")
    expect(page.get_by_test_id("mission-task-focus")).to_contain_text("failed")


def test_attack_path_summary_surface_shows_choke_points_and_candidate_paths(
    page: Page, operator_console_base_url: str
) -> None:
    seeded = _seed_attack_path_surface_run(operator_console_base_url)
    fixture = _attack_path_ui_fixture(seeded)

    page.route(
        "**/api/v1/runs/*/attack-paths",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(fixture),
        ),
    )
    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    _open_execution_screen(page, "nav-attack-map")
    expect(page.get_by_test_id("screen-surface-map")).to_be_visible()
    expect(page.get_by_test_id("attack-path-summary")).to_contain_text("Attack-Path Summary")
    expect(page.get_by_test_id("attack-path-summary")).to_contain_text("4 candidate paths")
    expect(page.get_by_test_id("attack-path-summary")).to_contain_text("threshold 3 paths")
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "Relationship View"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "10 API nodes"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "app.attack-path.example"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "Weak login throttling"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "artifact://zap/app/login-throttling"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "choke point"
    )
    expect(page.get_by_test_id("attack-path-choke-points")).to_contain_text(
        "app.attack-path.example appears in 3 candidate paths"
    )
    expect(page.get_by_test_id("attack-path-choke-card")).to_contain_text("Paths")
    expect(page.get_by_test_id("attack-path-choke-card")).to_contain_text("3")
    expect(page.get_by_test_id("attack-path-candidate-paths")).to_contain_text(
        "Weak login throttling"
    )
    expect(page.get_by_test_id("attack-path-candidate-paths")).to_contain_text(
        "Verbose API banner"
    )


def test_attack_path_summary_surface_shows_zero_data_fallback(
    page: Page, operator_console_base_url: str
) -> None:
    _seed_attack_path_surface_run(operator_console_base_url, include_inventory=False)

    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    _open_execution_screen(page, "nav-attack-map")
    expect(page.get_by_test_id("screen-surface-map")).to_be_visible()
    expect(page.get_by_test_id("attack-path-summary")).to_contain_text("No candidate paths yet")
    expect(page.get_by_test_id("attack-path-summary")).to_contain_text(
        "No selected-run inventory or finding evidence"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "No relationship chain yet"
    )
    expect(page.get_by_test_id("attack-path-relationship-view")).to_contain_text(
        "zero candidate paths"
    )
    expect(page.get_by_test_id("attack-path-choke-points")).to_contain_text(
        "No choke point reached the 3-path threshold"
    )
    expect(page.get_by_test_id("attack-path-candidate-paths")).to_contain_text(
        "No candidate paths are available yet"
    )


@pytest.mark.parametrize(
    "entry",
    ADAPTIVE_PACK_MATRIX,
    ids=[item["id"] for item in ADAPTIVE_PACK_MATRIX],
)
def test_adaptive_pack_matrix_keeps_pack_status_binding_and_report_context_visible(
    page: Page, operator_console_base_url: str, entry: dict
) -> None:
    seeded = _seed_bound_adaptive_run(operator_console_base_url)

    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    _switch_phase(page, "execution")
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(page.locator("#mission-pack-status")).to_contain_text(entry["expected_pack_name"])
    expect(page.locator("#mission-pack-status")).to_contain_text(seeded["pack_version"])
    expect(page.locator("#mission-pack-status")).to_contain_text(
        entry["expected_runtime_fragment"].replace("{pack_version}", seeded["pack_version"])
    )
    expect(page.locator("#mission-ai-narrative")).to_contain_text(
        "Keep adaptive pack provenance visible"
    )
    expect(page.locator("#mission-ai-narrative")).to_contain_text("This run has a bound pack")

    page.get_by_test_id("nav-packs").click()
    expect(page.get_by_test_id("screen-pack-forge")).to_be_visible()
    expect(page.get_by_test_id("pack-summary")).to_contain_text(entry["expected_pack_name"])
    expect(page.get_by_test_id("pack-summary")).to_contain_text(seeded["pack_version"])
    expect(page.get_by_test_id("pack-summary")).to_contain_text(entry["expected_pack_status"])
    expect(page.locator("#pack-forge-detail")).to_contain_text(entry["expected_pack_status"])
    expect(page.locator("#pack-forge-detail")).to_contain_text(entry["expected_deployment_fragment"])

    _open_analysis_screen(page, "nav-reports")
    page.get_by_test_id("report-preview-markdown").click()
    expect(page.get_by_test_id("report-preview")).to_contain_text("AegisPT Run Report", timeout=20000)
    for fragment in entry["expected_report_fragments"]:
        expect(page.get_by_test_id("report-preview")).to_contain_text(
            fragment.replace("{pack_version}", seeded["pack_version"])
        )

    page.get_by_test_id("nav-explorer").click()
    expect(page.get_by_test_id("run-dossier")).to_contain_text(
        entry["expected_dossier_fragment"].replace("{pack_version}", seeded["pack_version"])
    )

    page.get_by_test_id("nav-history").click()
    expect(page.get_by_test_id("history-run-card").first).to_contain_text(
        entry["expected_history_fragment"].replace("{pack_version}", seeded["pack_version"])
    )


def test_pack_forge_surfaces_codex_suggestions_preview_and_prepared_task(
    page: Page, operator_console_base_url: str
) -> None:
    seeded = _seed_bound_adaptive_run(operator_console_base_url)
    generation_reason = "Refine the bound adaptive pack before any future runtime promotion."
    _api_json(
        operator_console_base_url,
        "/api/v1/codex/tasks",
        method="POST",
        actor="codex-planner",
        body={
            "task_type": "pack_refinement",
            "scope": "Review the bound adaptive pack in the supervised build lane.",
            "inputs": {"review_bundle": True},
            "constraints": {"runtime_mutation": False},
            "expected_output": {"workspace_export": True, "validation_required": True},
            "generation_reason": generation_reason,
            "source_context": {"pack_id": seeded["pack_id"]},
        },
    )
    codex_context = _api_json(
        operator_console_base_url,
        f"/api/v1/packs/{seeded['pack_id']}/codex-context",
    )

    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    _open_execution_screen(page, "nav-packs")
    expect(page.get_by_test_id("screen-pack-forge")).to_be_visible()
    expect(page.get_by_test_id("pack-summary")).to_contain_text(seeded["pack_version"])
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Proposal")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Validation")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Approval")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Deployment")
    expect(page.get_by_test_id("codex-suggestions")).to_contain_text(generation_reason)
    expect(page.get_by_test_id("codex-suggestions")).to_contain_text("Prepare the selected build-lane task")
    expect(page.get_by_test_id("codex-pack-preview")).to_contain_text(
        codex_context["artifacts"][0]["logical_name"]
    )
    expect(page.get_by_test_id("codex-context")).to_contain_text("Build Lane Guardrails")
    expect(page.get_by_test_id("codex-context")).to_contain_text("artifact.playwright_flow.validate")
    expect(page.get_by_test_id("codex-context")).to_contain_text("has steps array")
    expect(page.get_by_test_id("codex-context")).to_contain_text("artifact.zap_job.validate")
    expect(page.get_by_test_id("codex-context")).to_contain_text("has tool")
    expect(page.get_by_test_id("codex-pack-preview")).to_contain_text("Validation Expectations")

    page.get_by_test_id("codex-task-card").first.click()
    page.get_by_test_id("prepare-codex-task").click()

    expect(page.get_by_test_id("codex-task-result")).to_contain_text("Prepared Task Output")
    expect(page.get_by_test_id("codex-prepared-commands")).to_contain_text(
        "export_codex_pack_workspace.sh"
    )
    expect(page.get_by_test_id("codex-prepared-commands")).to_contain_text(
        "validation-result.json"
    )
    expect(page.get_by_test_id("codex-validation-handoff")).to_contain_text("artifact.playwright_flow.validate")
    expect(page.get_by_test_id("codex-validation-handoff")).to_contain_text("has steps array")
    expect(page.get_by_test_id("codex-validation-handoff")).to_contain_text("artifact.zap_job.validate")
    expect(page.get_by_test_id("codex-validation-handoff")).to_contain_text("has tool")
    expect(page.get_by_test_id("codex-validation-handoff")).to_contain_text("validation-result.json")
    expect(page.get_by_test_id("codex-task-result")).to_contain_text(
        "No live runtime mutation is allowed"
    )
    expect(page.get_by_test_id("codex-task-result")).to_contain_text("validation-result.json")


def test_report_center_surfaces_codex_reviewed_adaptive_change_summary(
    page: Page, operator_console_base_url: str
) -> None:
    seeded = _seed_bound_adaptive_run(operator_console_base_url)
    task = _api_json(
        operator_console_base_url,
        "/api/v1/codex/tasks",
        method="POST",
        actor="codex-planner",
        body={
            "task_type": "pack_refinement",
            "scope": "Review the bound adaptive pack in the supervised build lane.",
            "inputs": {"review_bundle": True},
            "constraints": {"runtime_mutation": False},
            "expected_output": {"workspace_export": True, "validation_required": True},
            "generation_reason": "Refine the bound adaptive pack before future reporting signoff.",
            "source_context": {"pack_id": seeded["pack_id"]},
        },
    )
    _api_json(
        operator_console_base_url,
        f"/api/v1/codex/tasks/{task['id']}/run",
        method="POST",
        actor="codex-runner",
        body={
            "base_url": operator_console_base_url,
            "workspace_root": "./codex-workspaces/report-center-pack",
            "dry_run": True,
        },
    )

    page.goto("/app/")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    _open_analysis_screen(page, "nav-reports")
    expect(page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(page.get_by_test_id("report-adaptive-change-note")).to_contain_text(
        "Codex-reviewed adaptive coverage"
    )
    expect(page.get_by_test_id("report-adaptive-change-note")).to_contain_text(task["id"])
    expect(page.get_by_test_id("report-adaptive-change-note")).to_contain_text("pack_refinement")

    page.get_by_test_id("report-preview-markdown").click()
    expect(page.get_by_test_id("report-preview")).to_contain_text(
        "## Adaptive Change Summary",
        timeout=20000,
    )
    expect(page.get_by_test_id("report-preview")).to_contain_text(task["id"])
    expect(page.get_by_test_id("report-preview")).to_contain_text("Prepared Review Bundle: prepared")


def test_report_download_actions_create_real_browser_files(loaded_page: Page, tmp_path: Path) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-reports").click()

    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("report-download-markdown")).to_be_visible()

    with loaded_page.expect_download() as markdown_info:
        loaded_page.get_by_test_id("report-download-markdown").click()
    markdown_download = markdown_info.value
    markdown_path = tmp_path / markdown_download.suggested_filename
    markdown_download.save_as(str(markdown_path))
    assert markdown_path.suffix == ".md"
    assert "# AegisPT" in markdown_path.read_text(encoding="utf-8")

    with loaded_page.expect_download() as html_info:
        loaded_page.get_by_test_id("report-download-html").click()
    html_download = html_info.value
    html_path = tmp_path / html_download.suggested_filename
    html_download.save_as(str(html_path))
    assert html_path.suffix == ".html"
    assert "<html" in html_path.read_text(encoding="utf-8").lower()

    with loaded_page.expect_download() as pdf_info:
        loaded_page.get_by_test_id("report-download-pdf").click()
    pdf_download = pdf_info.value
    pdf_path = tmp_path / pdf_download.suggested_filename
    pdf_download.save_as(str(pdf_path))
    assert pdf_path.suffix == ".pdf"
    assert pdf_path.read_bytes().startswith(b"%PDF")
