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
WIZARD_MODULE = REPO_ROOT / "ui/assets/modules/wizard.js"
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


def test_revision_alias_matrix_matches_proven_typed_command_coverage() -> None:
    proven_commands = set(REVISION_COMMAND_PATTERN.findall(OPERATOR_CONSOLE_E2E.read_text(encoding="utf-8")))

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
    browser_source = OPERATOR_CONSOLE_E2E.read_text(encoding="utf-8")
    examples = set()
    for test_name in NORMALIZED_REVISION_COMMAND_TESTS:
        function_start = browser_source.index(f"def {test_name}(")
        decorator_start = browser_source.rfind("@pytest.mark.parametrize", 0, function_start)
        function_end = browser_source.find("\n\ndef test_", function_start + 1)
        block = browser_source[decorator_start:function_end]
        values = re.findall(r'pytest\.param\(\s*"([^"]+)"', block)
        assert values, f"Expected normalized revision examples in {test_name}."
        examples.update(value.strip() for value in values)
    return examples


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
    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()


def _go_to_advanced_step(page: Page, step: int) -> None:
    page.locator(f'[data-advanced-step="{step}"]').click()
    expect(page.get_by_test_id("wizard-advanced-content")).to_be_visible()


def _answer_current_question(page: Page, answer: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    page.get_by_test_id("conversation-answer-input").fill(answer)
    page.get_by_test_id("wizard-next").click()


def _is_boundary_question_text(question: str) -> bool:
    return "must avoid or handle carefully" in question.lower()


def _switch_phase(page: Page, phase: str) -> None:
    page.get_by_test_id(f"phase-nav-{phase}").click()
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
    _answer_current_question(page, "Our customer portal")
    _answer_current_question(page, "Authenticated review")
    _answer_current_question(page, "https://portal.example.com")
    _answer_current_question(page, "I have portal/app accounts")
    _answer_current_question(
        page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    question = page.get_by_test_id("conversation-question").inner_text().lower()
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = page.get_by_test_id("conversation-question").inner_text().lower()
    if _is_boundary_question_text(question):
        _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


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
    for _ in range(8):
        if page.get_by_test_id("wizard-confirm").is_visible():
            return
        title = page.get_by_test_id("conversation-question").locator("h3").inner_text()
        answer = _profile_matrix_answer_for_question(entry, title)
        if answer is None:
            raise AssertionError(f"Unexpected wizard question during profile matrix completion: {title}")
        _answer_current_question(page, answer)
    raise AssertionError("Profile matrix flow did not reach confirmation within the expected number of turns.")


def _fill_account_fields(page: Page, account: dict) -> None:
    for field_name, value in account.items():
        if value:
            page.locator(f'[data-account-field="{field_name}"][data-account-index="0"]').fill(value)


def _fill_account_fields_at_index(page: Page, account: dict, index: int) -> None:
    for field_name, value in account.items():
        if value:
            page.locator(f'[data-account-field="{field_name}"][data-account-index="{index}"]').fill(value)


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


def test_assessment_type_matrix_presets_render_expected_scope_and_lane(loaded_page: Page) -> None:
    _open_advanced_drawer(loaded_page)
    for entry in ASSESSMENT_MATRIX:
        _go_to_advanced_step(loaded_page, 0)
        loaded_page.locator(
            f'input[name="wizard-assessment-type"][value="{entry["assessment_type"]}"]'
        ).check()
        expect(loaded_page.locator("#wizard-summary")).to_contain_text(
            f'{entry["expected_profile"]} profile'
        )
        expect(loaded_page.get_by_test_id("wizard-summary-lane")).to_contain_text(
            entry["expected_lane"]
        )
        _go_to_advanced_step(loaded_page, 1)
        expect(loaded_page.locator(f'#{entry["expected_scope_field"]}')).to_be_visible()


def test_profile_matrix_presets_align_execution_lane_and_guardrails(loaded_page: Page) -> None:
    _open_advanced_drawer(loaded_page)
    for entry in PROFILE_MATRIX:
        _go_to_advanced_step(loaded_page, 0)
        loaded_page.locator(
            f'input[name="wizard-assessment-type"][value="{entry["assessment_type"]}"]'
        ).check()
        _go_to_advanced_step(loaded_page, 3)
        loaded_page.locator(
            f'input[name="wizard-test-profile"][value="{entry["profile"]}"]'
        ).check()
        expect(loaded_page.locator("#wizard-summary")).to_contain_text(
            f'{entry["profile"]} profile'
        )
        expect(loaded_page.get_by_test_id("wizard-summary-lane")).to_contain_text(
            entry["expected_lane"]
        )
        expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
            entry["expected_check_mode"]
        )


def test_invalid_tls_scope_advanced_override_returns_focus_to_scope_instead_of_fake_confirmation(
    loaded_page: Page,
) -> None:
    _open_advanced_drawer(loaded_page)
    _go_to_advanced_step(loaded_page, 0)
    loaded_page.locator('input[name="wizard-assessment-type"][value="SSL/TLS Only"]').check()
    _go_to_advanced_step(loaded_page, 1)
    loaded_page.locator("#wizard-target-ip-addresses").fill("portal.example.com")
    _go_to_advanced_step(loaded_page, 3)
    loaded_page.locator('input[name="wizard-test-profile"][value="SSL/TLS Only"]').check()

    _answer_current_question(loaded_page, "Standard assessment")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What hostnames, URLs, or IPs should I validate for TLS only?"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text("Mission Progress")
    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "Invalid IP address: portal.example.com"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()
    expect(loaded_page.get_by_test_id("wizard-confirm")).to_be_hidden()
    expect(loaded_page.get_by_test_id("wizard-next")).to_be_visible()


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
    _go_to_advanced_step(page, 3)
    page.locator(
        f'input[name="wizard-test-profile"][value="{entry["profile"]}"]'
    ).check()

    _complete_profile_matrix_remaining_topics(page, entry)

    expect(page.get_by_test_id("wizard-confirm")).to_be_visible()
    page.get_by_test_id("wizard-confirm").click()

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
    before_summary = loaded_page.get_by_test_id("wizard-summary-coverage").inner_text()

    for key in MODULE_KEYS:
        checkbox = loaded_page.locator(f'[data-module-key="{key}"]')
        expect(checkbox).to_be_visible()
        if checkbox.is_checked():
            checkbox.uncheck()
            expect(checkbox).not_to_be_checked()
        else:
            checkbox.check()
            expect(checkbox).to_be_checked()

    after_summary = loaded_page.get_by_test_id("wizard-summary-coverage").inner_text()
    assert before_summary != after_summary
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        "Modules"
    )


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
    loaded_page.locator("#wizard-manual-auth-steps").fill(entry.get("manual_auth_steps", ""))
    loaded_page.locator("#wizard-cookie-notes").fill(entry.get("cookie_notes", ""))

    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        entry["expected_summary"]
    )
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        entry["expected_manual_note"]
    )


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

    for fragment in entry["expected_summary_fragments"]:
        expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(fragment)
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text("Access:")
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        entry["expected_summary_fragments"][0]
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        entry["expected_summary_fragments"][1]
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

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
    _go_to_advanced_step(loaded_page, 3)
    loaded_page.locator(
        f'input[name="wizard-test-profile"][value="{entry["profile"]}"]'
    ).check()
    _go_to_advanced_step(loaded_page, 5)
    loaded_page.locator("#wizard-rate-limit").fill(str(entry["rate_limit_rps"]))
    loaded_page.locator("#wizard-concurrency").fill(str(entry["concurrency"]))
    loaded_page.locator("#wizard-time-budget").fill(str(entry["time_budget_minutes"]))
    loaded_page.locator("#wizard-active-checks").select_option(entry["active_checks"])
    loaded_page.locator("#wizard-adaptive-generation").select_option(
        "true" if entry["adaptive_generation"] else "false"
    )
    loaded_page.locator("#wizard-max-depth").select_option(entry["max_validation_depth"])

    expect(loaded_page.get_by_test_id("wizard-summary-lane")).to_contain_text(
        entry["expected_lane"]
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        entry["expected_check_mode"]
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        f'{entry["rate_limit_rps"]} RPS'
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        str(entry["time_budget_minutes"])
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        "Enabled" if entry["adaptive_generation"] else "Disabled"
    )


def test_execution_outcome_matrix_surfaces_blocked_pending_approval_state(loaded_page: Page) -> None:
    expected = next(item for item in EXECUTION_OUTCOME_MATRIX if item["id"] == "pending_approval_blocked")

    _finish_authenticated_webapp_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        expected["expected_activity_title"]
    )
    expect(loaded_page.get_by_test_id("mission-snapshot-panel")).to_contain_text(
        expected["expected_signal"]
    )
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        expected["expected_run_activity_signal"]
    )
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text("Approval Status")
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text("Pending")
    expect(loaded_page.get_by_test_id("mission-run-activity")).not_to_contain_text("Start Validation")


def test_execution_outcome_matrix_surfaces_failed_dispatch_state(
    page: Page, operator_console_base_url: str
) -> None:
    expected = next(item for item in EXECUTION_OUTCOME_MATRIX if item["id"] == "completed_with_errors_failed_tasks")
    _seed_failed_run(operator_console_base_url)

    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()
    _switch_phase(page, "execution")

    expect(page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(page.get_by_test_id("mission-activity")).to_contain_text(
        expected["expected_activity_title"]
    )
    expect(page.get_by_test_id("mission-snapshot-panel")).to_contain_text(
        expected["expected_signal"]
    )
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("2 planned checks")
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("The last execution completed with errors.")
    expect(page.get_by_test_id("mission-run-activity")).to_contain_text("Failed")
    expect(page.get_by_test_id("mission-task-focus")).to_contain_text("failed")


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
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()
    expect(page.get_by_test_id("persistent-context")).to_contain_text("Adaptive Pack Matrix")

    _switch_phase(page, "execution")
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(page.locator("#mission-pack-status")).to_contain_text(entry["expected_pack_name"])
    expect(page.locator("#mission-pack-status")).to_contain_text(seeded["pack_version"])
    expect(page.locator("#mission-pack-status")).to_contain_text(
        entry["expected_runtime_fragment"].replace("{pack_version}", seeded["pack_version"])
    )
    expect(page.locator("#mission-ai-narrative")).to_contain_text(
        entry["expected_narrative_fragment"].replace("{pack_version}", seeded["pack_version"])
    )

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
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

    _open_execution_screen(page, "nav-packs")
    expect(page.get_by_test_id("screen-pack-forge")).to_be_visible()
    expect(page.get_by_test_id("pack-summary")).to_contain_text(seeded["pack_version"])
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Proposal")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Validation")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Approval")
    expect(page.get_by_test_id("codex-lifecycle")).to_contain_text("Deployment")
    expect(page.get_by_test_id("codex-suggestions")).to_contain_text(generation_reason)
    expect(page.get_by_test_id("codex-suggestions")).to_contain_text("Prepare the selected Codex task")
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
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

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
    loaded_page.get_by_test_id("wizard-confirm").click()
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
