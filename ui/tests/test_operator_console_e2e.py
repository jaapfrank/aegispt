from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from playwright.sync_api import Page, expect

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_MATRIX = json.loads((REPO_ROOT / "codex/tasks/ui_acceptance_matrix.json").read_text(encoding="utf-8"))
CONVERSATIONAL_MATRIX = next(
    item for item in UI_MATRIX["scenarios"] if item["id"] == "wizard_conversational_completion_matrix"
)["flows"]
QUICK_REPLY_MATRIX = next(
    item for item in UI_MATRIX["scenarios"] if item["id"] == "wizard_quick_reply_completion_matrix"
)["flows"]


def _answer_current_question(page: Page, answer: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    page.get_by_test_id("conversation-answer-input").fill(answer)
    page.get_by_test_id("wizard-next").click()


def _click_quick_reply(page: Page, label: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    page.locator(f'[data-quick-reply="{label}"]').click()


def _expect_current_question(page: Page, title_fragment: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_contain_text(title_fragment)


def _current_question_text(page: Page) -> str:
    return page.get_by_test_id("conversation-question").inner_text().lower()


def _is_boundary_question(question: str) -> bool:
    return "must avoid or handle carefully" in question.lower()


def _api_json(base_url: str, path: str, *, method: str = "GET", body: dict | None = None, actor: str = "tester") -> dict | list:
    headers = {"X-Actor": actor}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _target_values_text(configuration: dict) -> str:
    targets = configuration.get("targets", {})
    return json.dumps(targets, sort_keys=True)


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


def _finish_internal_inventory_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "My LAN network")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Inventory first, but I want clear information per found item")
    _expect_current_question(page, "CIDR range")
    _answer_current_question(page, "10.0.20.0/24")
    question = _current_question_text(page)
    if "conservative" in question:
        _answer_current_question(page, "Conservative")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "Report adjacent internal ranges only")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _finish_authenticated_webapp_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our customer portal")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Authenticated review")
    _expect_current_question(page, "exact targets")
    _answer_current_question(page, "https://portal.example.com")
    _expect_current_question(page, "stay unauthenticated")
    _answer_current_question(page, "I have portal/app accounts")
    _expect_current_question(page, "access context")
    _answer_current_question(
        page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    question = _current_question_text(page)
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _finish_api_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our API")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Adaptive customer-specific testing")
    _expect_current_question(page, "API base URLs")
    _answer_current_question(page, "https://api.example.com/v1")
    _expect_current_question(page, "stay unauthenticated")
    _answer_current_question(page, "I have API tokens or keys")
    _expect_current_question(page, "access context")
    _answer_current_question(page, "role API Analyst api-key vault://api/key")
    question = _current_question_text(page)
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _complete_shared_no_account_auth_alias_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    command: str,
    access_mode: str,
    initial_text: str,
    updated_text: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    if access_mode == "manual":
        loaded_page.locator("#wizard-manual-auth-steps").fill(initial_text)
    else:
        loaded_page.locator("#wizard-cookie-notes").fill(initial_text)
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        initial_text
    )

    _answer_current_question(loaded_page, updated_text)
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the shared no-account auth-alias run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["access"]["accounts"] == []

    if access_mode == "manual":
        assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
        assert run["configuration_json"]["access"]["manual_auth_steps"] == updated_text
        assert run["configuration_json"]["access"]["cookie_notes"] is None
    else:
        assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
        assert run["configuration_json"]["access"]["manual_auth_steps"] is None
        assert run["configuration_json"]["access"]["cookie_notes"] == updated_text

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        updated_text
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        initial_text
    )


def _complete_advanced_access_detail_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    command: str,
    access_mode: str,
    initial_detail: str,
    updated_detail: str,
) -> None:
    if access_mode == "api":
        _answer_current_question(loaded_page, "Our API")
        _answer_current_question(loaded_page, "Adaptive customer-specific testing")
        _answer_current_question(loaded_page, "https://api.example.com/v1")
    else:
        _answer_current_question(loaded_page, "Our customer portal")
        _answer_current_question(loaded_page, "Authenticated review")
        _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    if access_mode == "credential":
        loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
            "analyst@example.com"
        )
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "Security Analyst"
        )
        loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
            "vault://portal/analyst"
        )
    elif access_mode == "session":
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "Security Analyst"
        )
        loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
            "session-cookie=abc123"
        )
    else:
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "API Analyst"
        )
        loaded_page.locator('[data-account-field="api_key_ref"][data-account-index="0"]').fill(
            "vault://api/original-token"
        )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        initial_detail
    )

    _answer_current_question(loaded_page, updated_detail)
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-access revision run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]

    if access_mode == "credential":
        assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
        assert account["role"] == "Security Lead"
        assert "password" in account["secret_bindings"]
    elif access_mode == "session":
        assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
        assert account["role"] == "Security Lead"
        assert "session" in account["secret_bindings"]
    else:
        assert configuration["intake"]["preferences"]["auth_strategy"] == "api-access"
        assert account["role"] == "API Lead"
        assert "api_key" in account["secret_bindings"]
        assert configuration["access"]["secret_storage"]["binding_count"] >= 1


def _complete_previous_topic_advanced_access_detail_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    access_mode: str,
    initial_detail: str,
    updated_detail: str,
    expected_role: str,
) -> None:
    if access_mode == "api":
        _answer_current_question(loaded_page, "Our API")
        _answer_current_question(loaded_page, "Adaptive customer-specific testing")
        _answer_current_question(loaded_page, "https://api.example.com/v1")
    else:
        _answer_current_question(loaded_page, "Our customer portal")
        _answer_current_question(loaded_page, "Authenticated review")
        _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    if access_mode == "credential":
        loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
            "analyst@example.com"
        )
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "Security Analyst"
        )
        loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
            "vault://portal/analyst"
        )
    elif access_mode == "session":
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "Security Analyst"
        )
        loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
            "session-cookie=abc123"
        )
    else:
        loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
            "API Analyst"
        )
        loaded_page.locator('[data-account-field="api_key_ref"][data-account-index="0"]').fill(
            "vault://api/original-token"
        )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    loaded_page.get_by_test_id("wizard-back").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        initial_detail
    )

    _answer_current_question(loaded_page, updated_detail)
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        expected_role
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the previous-topic-revised advanced-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]

    if access_mode == "credential":
        assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
        assert account["role"] == expected_role
        assert "password" in account["secret_bindings"]
    elif access_mode == "session":
        assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
        assert account["role"] == expected_role
        assert "session" in account["secret_bindings"]
    else:
        assert configuration["intake"]["preferences"]["auth_strategy"] == "api-access"
        assert account["role"] == expected_role
        assert "api_key" in account["secret_bindings"]

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        expected_role
    )


def _finish_standard_web_intake(page: Page, target_url: str) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our website")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Standard assessment")
    _expect_current_question(page, "exact targets")
    _answer_current_question(page, target_url)
    question = _current_question_text(page)
    if "stay unauthenticated" in question:
        _answer_current_question(page, "Keep it unauthenticated")
        question = _current_question_text(page)
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _finish_internal_validation_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "My LAN network")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Deep internal validation")
    _expect_current_question(page, "CIDR range")
    _answer_current_question(page, "10.0.20.0/24")
    _expect_current_question(page, "stay unauthenticated")
    _answer_current_question(page, "Unauthenticated")
    _expect_current_question(page, "conservative or more thorough")
    _answer_current_question(page, "Thorough")
    question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _finish_quick_reply_matrix_flow(page: Page, flow: dict) -> None:
    for step in flow["steps"]:
        if step["type"] == "chip":
            _click_quick_reply(page, step["value"])
        else:
            _answer_current_question(page, step["value"])
    if not page.get_by_test_id("wizard-confirmation-summary").is_visible():
        question = _current_question_text(page)
        if _is_boundary_question(question):
            _answer_current_question(page, flow.get("boundary_answer", "No extra exclusions"))
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def _finish_conversational_matrix_flow(page: Page, flow: dict) -> None:
    for _ in range(8):
        if page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(page)
        if "what would you like to pentest today" in question:
            _answer_current_question(page, flow["intent_answer"])
            continue
        if "main goal" in question:
            _answer_current_question(page, flow["goal_answer"])
            continue
        if any(
            fragment in question
            for fragment in (
                "exact cidr range",
                "exact ips or cidr ranges",
                "api base urls",
                "hostnames, urls, or ips",
                "exact targets",
            )
        ):
            _answer_current_question(page, flow["scope_answer"])
            continue
        if "stay unauthenticated" in question:
            assert flow.get("auth_answer"), f"Missing auth_answer for flow {flow['assessment_type']}"
            _answer_current_question(page, flow["auth_answer"])
            continue
        if "access context" in question:
            assert flow.get("auth_detail_answer"), (
                f"Missing auth_detail_answer for flow {flow['assessment_type']}"
            )
            _answer_current_question(page, flow["auth_detail_answer"])
            continue
        if "conservative or more thorough" in question:
            _answer_current_question(page, flow.get("safety_answer", "Balanced"))
            continue
        if _is_boundary_question(question):
            _answer_current_question(page, flow.get("boundary_answer", "No extra exclusions"))
            continue
        raise AssertionError(f"Unhandled question for {flow['assessment_type']}: {question}")

    expect(page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def test_operator_console_empty_states_render(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("conversation-thread")).to_contain_text(
        "Hello. What would you like to pentest today?"
    )
    expect(loaded_page.get_by_test_id("engagement-select")).to_have_value("")
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Conversational Intake")
    expect(loaded_page.get_by_test_id("persistent-context")).to_contain_text("Mission Context")
    expect(loaded_page.get_by_test_id("persistent-context")).to_contain_text("Start your first mission")
    expect(loaded_page.get_by_test_id("persistent-context")).to_contain_text(
        "Start in Conversational Intake by answering the first question"
    )
    expect(loaded_page.locator("#next-actions")).to_contain_text("Start Mission Intake")
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Nothing confirmed yet"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Target Type")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Goal")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Safety")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).not_to_contain_text("Access")

    _switch_phase(loaded_page, "execution")
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "Start in Conversational Intake"
    )
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "No engagement exists yet"
    )
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Mission Control")
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_visible()

    loaded_page.get_by_test_id("nav-surface-map").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible()
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text(
        "No inventory snapshot is available yet"
    )
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text(
        "Create a mission in Conversational Intake first"
    )
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text(
        "asset browser needs inventory"
    )

    _open_analysis_screen(loaded_page, "nav-reports")
    expect(loaded_page.get_by_test_id("report-catalog")).to_contain_text(
        "Report variants become available once a run dossier exists."
    )
    expect(loaded_page.locator("#report-metadata")).to_contain_text(
        "Create a mission in Conversational Intake first"
    )

    loaded_page.get_by_test_id("nav-evidence").click()
    expect(loaded_page.get_by_test_id("evidence-overview")).to_contain_text(
        "Create a mission first"
    )

    loaded_page.get_by_test_id("nav-findings").click()
    expect(loaded_page.get_by_test_id("findings-group-list")).to_contain_text(
        "Create a mission in Conversational Intake first"
    )
    expect(loaded_page.get_by_test_id("finding-theater-detail")).to_contain_text(
        "Start with Intake"
    )


def test_intake_focus_shell_keeps_secondary_context_in_disclosure(loaded_page: Page) -> None:
    expect(loaded_page.locator("body")).to_have_attribute("data-phase-layout", "focus")
    expect(loaded_page.get_by_test_id("persistent-context")).to_contain_text(
        "Only the essentials stay expanded during intake"
    )
    expect(loaded_page.get_by_test_id("persistent-context-secondary")).to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission"
    )


def test_initial_intake_defers_access_and_output_until_they_are_relevant(
    loaded_page: Page,
) -> None:
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Target Type")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Goal")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Safety")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).not_to_contain_text("Access")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).not_to_contain_text("Output")
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Goal, Scope, Safety, Boundaries."
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Output")


def test_initial_current_essentials_do_not_overclaim_default_lane_before_intake_context(
    loaded_page: Page,
) -> None:
    current_essentials = loaded_page.get_by_test_id("wizard-summary-current")
    expect(current_essentials).to_contain_text(
        "Mission type, profile, execution lane, and ETA appear here once the intake has enough confirmed or safely inferred context."
    )
    expect(current_essentials).not_to_contain_text("Website / Web App")
    expect(current_essentials).not_to_contain_text("Standard profile")
    expect(current_essentials).not_to_contain_text("passive-web-nuclei-audit")
    expect(current_essentials).not_to_contain_text("62m ETA")

    loaded_page.get_by_test_id("wizard-summary-coverage").click()
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        "Waiting for mission shape"
    )

    loaded_page.get_by_test_id("wizard-summary-lane").click()
    expect(loaded_page.get_by_test_id("wizard-summary-lane")).to_contain_text(
        "Waiting for mission shape"
    )


def test_still_needed_actions_can_jump_ahead_without_losing_main_path(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("wizard-needed-action-safety")).to_be_visible()
    loaded_page.get_by_test_id("wizard-needed-action-safety").click()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Reviewing Another Topic"
    )

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )


def test_advanced_override_realigns_the_current_question_to_the_next_required_topic(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "https://app.example.com")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="3"]').click()
    loaded_page.locator('input[name="wizard-test-profile"][value="Deep"]').check()
    loaded_page.locator('[data-advanced-step="5"]').click()
    loaded_page.locator("#wizard-active-checks").select_option("active")
    loaded_page.locator("#wizard-max-depth").select_option("deep")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Deep Assessment (advanced override)"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Aggressive with Approval · Active Validation (advanced override)"
    )
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()


def test_internal_inventory_conversation_creates_a_real_run(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Internal Range / LAN"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Inventory First"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "10.0.20.0/24"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "internal range / lan assessment"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("10.0.20.0/24")


def test_partial_intake_moves_older_context_and_revision_controls_into_quieter_disclosures(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_have_count(0)
    _answer_current_question(loaded_page, "My LAN network")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_have_count(0)
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_be_visible()
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_contain_text("Change Goal")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).not_to_contain_text("Change Scope")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).not_to_contain_text("Change Access")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-history-disclosure")).to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_be_visible()
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_contain_text("Change Goal")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).to_contain_text("Change Scope")
    expect(loaded_page.get_by_test_id("conversation-edit-row")).not_to_contain_text("Change Access")
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Internal Range / LAN"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text(
        "Safety"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text(
        "Boundaries"
    )


def test_inventory_only_run_explains_empty_findings_and_history_actions(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-findings")
    expect(loaded_page.get_by_test_id("finding-empty-discovery")).to_contain_text(
        "discovery-only runs do not create findings by themselves"
    )
    expect(loaded_page.get_by_test_id("finding-detail-discovery")).to_contain_text(
        "Review Discovered Assets"
    )

    loaded_page.get_by_test_id("nav-history").click()
    expect(loaded_page.get_by_test_id("history-run-card").first).to_contain_text("Open Surface")
    loaded_page.get_by_test_id("history-open-surface").first.click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible()


def test_findings_theater_surfaces_remediation_and_retest_truth(loaded_page: Page) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js');
          const { state, runtime } = runtimeModule;
          const sourceRunId = '11111111-1111-4111-8111-111111111111';
          const retestRunId = '22222222-2222-4222-8222-222222222222';
          const finding = {
            id: '33333333-3333-4333-8333-333333333333',
            run_id: sourceRunId,
            title: 'Missing X-Frame-Options Header',
            severity: 'low',
            target_id: 'https://portal.example.test',
            evidence_ref: 'artifact://headers/x-frame-options',
            status: 'open',
            summary: 'The target did not return X-Frame-Options.',
            finding_origin: 'standard',
            methodology_tags: [],
          };

          state.activePhase = 'analysis';
          state.activeScreen = 'findings-theater';
          state.selectedRunId = sourceRunId;
          state.selectedRun = {
            id: sourceRunId,
            status: 'completed',
            profile: { name: 'passive-web-baseline' },
            configuration_json: {},
            tasks: [],
          };
          state.mission.runs = [
            state.selectedRun,
            {
              id: retestRunId,
              status: 'completed',
              profile: { name: 'passive-web-baseline' },
              configuration_json: {
                retest: {
                  mode: 'single_finding',
                  source_finding_id: finding.id,
                  source_run_id: sourceRunId,
                },
              },
              tasks: [],
            },
          ];
          state.mission.findingsByRun = { [sourceRunId]: [finding] };
          state.selectedFindingId = finding.id;
          state.selectedFindingTheater = {
            finding,
            severity_rank: 3,
            confidence_label: 'medium',
            exploitability: 'limited',
            business_impact: 'Limited direct impact, but worth addressing to reduce exposure.',
            technical_details: 'Target evidence is linked through stored artifact references.',
            evidence_summary: 'Evidence is linked through stored artifact references.',
            provenance: {
              origin: 'standard',
              source_pack_version: null,
              source_inventory_snapshot_id: null,
              source_relevance_decision_id: null,
            },
            methodology: {
              ptes_label: 'Analysis / Validation',
              nist_label: 'Discovery',
              wstg_reference: 'WSTG-CONF-07',
              control_family: 'Security Headers',
            },
            remediation: {
              priority: 'Routine',
              summary: 'Fix the affected control and retain evidence.',
              detail: 'Apply the remediation in the approved environment before retest.',
              record: {
                state: 'ready_for_retest',
                notes: 'Patch deployed to the approved test environment.',
                owner: 'app-team',
                updated_by: 'retest-coordinator',
                updated_at: '2026-04-21T10:00:00+00:00',
              },
              linked_retests: [
                {
                  run_id: retestRunId,
                  source_run_id: sourceRunId,
                  status: 'completed',
                  verification_state: 'requested',
                  remediation_state: 'ready_for_retest',
                  operator_notes: 'Retest only the original affected endpoint.',
                  verification_timestamp: '2026-04-21T10:10:00+00:00',
                  queued_task_count: 0,
                  completed_task_count: 1,
                  failed_task_count: 0,
                },
              ],
              linked_retest_count: 1,
              latest_retest_status: 'completed',
              proof_of_resolution_ready: true,
            },
            verification_status: 'evidence-linked and ready for replay',
            next_steps: ['Review proof-of-resolution report before closing.'],
            risk_snapshot: {},
          };
          state.selectedFindingEvidence = null;
          runtime.actions.engagementFindings = () =>
            Object.entries(state.mission.findingsByRun).flatMap(([runId, findings]) =>
              findings.map((item) => ({ ...item, _runId: runId }))
            );

          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-card")).to_contain_text(
        "Missing X-Frame-Options Header"
    )
    expect(loaded_page.get_by_test_id("finding-remediation-record")).to_contain_text(
        "ready for retest"
    )
    expect(loaded_page.get_by_test_id("finding-remediation-record")).to_contain_text(
        "Patch deployed to the approved test environment."
    )
    expect(loaded_page.get_by_test_id("finding-retest-linkage")).to_contain_text(
        "1 linked retest run"
    )
    expect(loaded_page.get_by_test_id("finding-retest-linkage")).to_contain_text(
        "Proof-of-resolution output is ready"
    )
    expect(loaded_page.get_by_test_id("finding-linked-retest")).to_contain_text(
        "Retest only the original affected endpoint."
    )
    proof_link = loaded_page.get_by_test_id("finding-linked-retest").locator("a")
    expect(proof_link).to_have_attribute("href", re.compile(r"variant=retest"))


def test_authenticated_webapp_flow_supports_reports_and_secret_binding(loaded_page: Page) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    confirmation_summary = loaded_page.get_by_test_id("wizard-confirmation-summary").locator("p").first.inner_text()
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Authenticated Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    _open_analysis_screen(loaded_page, "nav-reports")
    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    loaded_page.get_by_test_id("report-preview-markdown").click()
    expect(loaded_page.get_by_test_id("report-preview")).to_contain_text(
        "AegisPT Run Report", timeout=20000
    )
    loaded_page.get_by_test_id("report-preview-html").click()
    expect(loaded_page.get_by_test_id("report-frame")).to_be_visible(timeout=20000)
    pdf_href = loaded_page.get_by_test_id("report-download-pdf").get_attribute("href")
    assert pdf_href is not None
    assert "format=pdf" in pdf_href

    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text("Protected Access")
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text("1 secret binding")
    expect(loaded_page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        confirmation_summary.split(". ")[0]
    )
    expect(loaded_page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        "Estimated duration"
    )


def test_customer_portal_intent_enters_authenticated_app_path(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Authenticated App"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is your main goal for this assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Authenticated review"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Quick overview"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Scope, Access, Safety, Boundaries."
    )

    _click_quick_reply(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/customer",
    )
    _answer_current_question(loaded_page, "Balanced")
    if not loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
        _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "authenticated app assessment"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after customer-portal mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Authenticated App"
    assert configuration["test_profile"] == "Authenticated Only"
    assert configuration["execution_profile"] == "active-web-safe"
    assert "https://portal.example.com" in _target_values_text(configuration)


def test_external_ip_intent_keeps_public_scope_language_and_type_truthful(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: External IP / WAN"
    )

    _answer_current_question(loaded_page, "Standard assessment")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What exact IPs or CIDR ranges are authorized?"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "internal hosts"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Safety, Boundaries"
    )

    _answer_current_question(loaded_page, "203.0.113.10")
    _answer_current_question(loaded_page, "Conservative")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "external ip / wan assessment"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after external-surface mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert "203.0.113.10" in _target_values_text(configuration)


def test_external_ip_authenticated_review_stages_perimeter_discovery_first_with_access_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "203.0.113.0/28")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )

    _answer_current_question(loaded_page, "I have portal/app accounts")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )

    _answer_current_question(
        loaded_page,
        "user perimeter@example.com role Analyst secret vault://wan/user",
    )
    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Authenticated Review"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with passive perimeter discovery under the External Surface Only profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "keep the planned access context attached to this mission"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface access-aware follow-up options once reachable services and protected application surfaces are confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Authenticated Only profile and the passive-network-discovery execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External Surface Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after WAN authenticated-review mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "authenticated-review"
    assert configuration["access"]["accounts"]
    assert configuration["safety"]["active_checks"] == "passive-only"
    assert configuration["safety"]["max_validation_depth"] == "light"


def test_external_ip_goal_choices_flag_discovery_first_follow_up_language(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: External IP / WAN"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Quick perimeter overview"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Perimeter review"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Deep follow-up after discovery"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Adaptive follow-up after discovery"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Deep assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Adaptive customer-specific testing"
    )


def test_external_ip_deep_assessment_stages_perimeter_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")
    _answer_current_question(loaded_page, "Deep assessment")
    _answer_current_question(loaded_page, "203.0.113.0/28")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Deep Assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with passive perimeter discovery under the External Surface Only profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface deeper service-aware follow-up validation once reachable hosts and services are confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Deep profile and the passive-network-discovery execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External Surface Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after deep WAN mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["auth_flows"] is False
    assert configuration["safety"]["active_checks"] == "passive-only"
    assert configuration["safety"]["max_validation_depth"] == "light"


def test_external_ip_adaptive_testing_stages_perimeter_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "203.0.113.0/28")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Adaptive Customer-Specific Testing"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with passive perimeter discovery under the External Surface Only profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface adaptive customer-specific follow-up coverage once reachable hosts and services are confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Adaptive Customer-Specific Mode profile and the passive-network-discovery execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External Surface Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after adaptive WAN mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "adaptive-coverage"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["auth_flows"] is False
    assert configuration["safety"]["active_checks"] == "passive-only"
    assert configuration["safety"]["max_validation_depth"] == "light"


def test_domain_deep_assessment_stays_unauthenticated_by_default(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our external domain")
    _answer_current_question(loaded_page, "Deep assessment")
    _answer_current_question(loaded_page, "example.com")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize deep assessment with the Deep profile and the active-web-safe execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Do you have access"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Boundary Handling"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Domain / Domains")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after deep domain mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Domain / Domains"
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["modules"]["auth_flows"] is False


def test_web_deep_assessment_stays_unauthenticated_by_default(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Deep assessment")
    _answer_current_question(loaded_page, "https://app.example.com")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize deep assessment with the Deep profile and the active-web-safe execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Boundary Handling"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after deep web mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["modules"]["auth_flows"] is False


def test_web_adaptive_assessment_stays_unauthenticated_by_default(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://app.example.com")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")

    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize adaptive customer-specific testing with the Adaptive Customer-Specific Mode profile and the active-web-safe execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        "Adaptive Customer-Specific Mode"
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after adaptive web mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Adaptive Customer-Specific Mode"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "adaptive-coverage"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["modules"]["auth_flows"] is False


def test_tls_only_intent_limits_goal_choices_to_tls_safe_options(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "TLS posture for our public site")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: SSL/TLS Only"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Quick overview"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Standard assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Deep assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Adaptive customer-specific testing"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).not_to_contain_text(
        "Inventory first"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Scope, Safety, Boundaries."
    )


def test_tls_only_standard_route_requires_safety_and_boundaries_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "TLS posture for our public site")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "portal.example.com")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough?"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Boundaries."
    )

    _answer_current_question(loaded_page, "Passive only")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()

    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "ssl/tls only assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "passive-web-baseline execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "No extra boundary note is currently recorded."
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after TLS-only mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "SSL/TLS Only"
    assert configuration["test_profile"] == "SSL/TLS Only"
    assert configuration["execution_profile"] == "passive-web-baseline"
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["intake"]["preferences"]["safety_posture"] == "passive-only"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert "portal.example.com" in _target_values_text(configuration)


@pytest.mark.parametrize(
    (
        "intent_answer",
        "goal_answer",
        "scope_answer",
        "auth_answer",
        "safety_answer",
        "expected_assessment_type",
        "expected_profile",
        "expected_lane",
        "expected_scope_fragment",
    ),
    [
        (
            "Our web application",
            "Standard assessment",
            "https://app.example.com",
            None,
            "Balanced",
            "Website / Web App",
            "Standard",
            "passive-web-nuclei-audit",
            "https://app.example.com",
        ),
        (
            "Our external domain",
            "Standard assessment",
            "example.com",
            None,
            "Balanced",
            "Domain / Domains",
            "External Surface Only",
            "passive-web-baseline",
            "example.com",
        ),
        (
            "Our internet-facing IP range",
            "Standard assessment",
            "203.0.113.10",
            None,
            "Conservative",
            "External IP / WAN",
            "External Surface Only",
            "passive-network-discovery",
            "203.0.113.10",
        ),
        (
            "Our API",
            "Standard assessment",
            "https://api.example.com/v1",
            "Keep it unauthenticated",
            "Balanced",
            "API",
            "Standard",
            "passive-web-nuclei-audit",
            "https://api.example.com/v1",
        ),
        (
            "Our customer portal",
            "Standard assessment",
            "https://portal.example.com",
            "Keep it unauthenticated",
            "Balanced",
            "Authenticated App",
            "Standard",
            "active-web-safe",
            "https://portal.example.com",
        ),
    ],
)
def test_standard_supported_routes_require_boundaries_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
    intent_answer: str,
    goal_answer: str,
    scope_answer: str,
    auth_answer: str | None,
    safety_answer: str,
    expected_assessment_type: str,
    expected_profile: str,
    expected_lane: str,
    expected_scope_fragment: str,
) -> None:
    _answer_current_question(loaded_page, intent_answer)
    _answer_current_question(loaded_page, goal_answer)
    _answer_current_question(loaded_page, scope_answer)

    if auth_answer is not None:
        expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
            "Should this stay unauthenticated"
        )
        _answer_current_question(loaded_page, auth_answer)

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough?"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()

    _answer_current_question(loaded_page, safety_answer)

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Answer this to continue."
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Boundary Handling"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Standard Scope Only"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after standard mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == expected_assessment_type
    assert configuration["test_profile"] == expected_profile
    assert configuration["execution_profile"] == expected_lane
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert expected_scope_fragment in _target_values_text(configuration)


def test_tls_only_deep_goal_normalizes_to_standard_tls_assessment(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "TLS posture for our public site")
    _answer_current_question(loaded_page, "Deep assessment")

    expect(loaded_page.get_by_test_id("conversation-thread")).to_contain_text(
        "standard TLS-only assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )

    _answer_current_question(loaded_page, "portal.example.com")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough?"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()

    _answer_current_question(loaded_page, "Passive only")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )

    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "ssl/tls only assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "standard assessment with the SSL/TLS Only profile"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after TLS-only mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "SSL/TLS Only"
    assert configuration["test_profile"] == "SSL/TLS Only"
    assert configuration["execution_profile"] == "passive-web-baseline"
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["intake"]["preferences"]["safety_posture"] == "passive-only"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert "portal.example.com" in _target_values_text(configuration)


def test_passive_execution_lanes_do_not_claim_guarded_active_validation_in_confirmation_copy(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our website")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "passive-web-nuclei-audit execution lane"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "active exploitation-style checks are not enabled in this run"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "Guarded active validation is enabled"
    )


def test_mixed_assessment_confirmation_copy_avoids_duplicate_assessment_wording(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our mixed web and API estate")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://portal.example.com https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://mixed/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "I am going to run a mixed assessment against"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "mixed assessment assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Boundary Handling"
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Standard Scope Only"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after mixed-surface mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Mixed Assessment"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert "https://api.example.com/v1" in _target_values_text(configuration)


def test_authenticated_app_credentialed_route_requires_boundary_confirmation_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )

    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Boundary Handling"
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Standard Scope Only"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created authenticated-app run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Authenticated App"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"


def test_api_token_route_requires_boundary_confirmation_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(loaded_page, "role API Analyst api-key vault://api/key")
    _answer_current_question(loaded_page, "Balanced")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )

    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Boundary Handling"
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Standard Scope Only"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created API run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "API"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "api-access"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"


def test_existing_engagement_route_reuses_selected_dossier_without_creating_new_engagement(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagement = _api_json(
        operator_console_base_url,
        "/api/v1/engagements",
        method="POST",
        actor="wizard-tester",
        body={
            "name": "Existing Dossier Reuse",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-310",
        },
    )
    _api_json(
        operator_console_base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="wizard-tester",
        body={
            "allowlist_json": {"urls": ["https://api.example.com/v1"]},
            "denylist_json": {},
        },
    )
    engagements_before = _api_json(operator_console_base_url, "/api/v1/engagements")
    runs_before = _api_json(operator_console_base_url, f"/api/v1/engagements/{engagement['id']}/runs")

    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])
    selected_label = page.locator("#engagement-select option:checked").inner_text()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator('input[name="wizard-assessment-type"][value="API"]').check()
    page.get_by_test_id("wizard-use-existing").check()
    page.get_by_test_id("wizard-advanced-toggle").click()

    expect(page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Engagement Route: Reuse existing dossier"
    )
    expect(page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(engagement["name"])

    expect(page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    _answer_current_question(page, "Adaptive customer-specific testing")
    _expect_current_question(page, "API base URLs")
    _answer_current_question(page, "https://api.example.com/v1")
    _expect_current_question(page, "stay unauthenticated")
    _answer_current_question(page, "I have API tokens or keys")
    _expect_current_question(page, "access context")
    _answer_current_question(page, "role API Analyst api-key vault://api/key")
    _expect_current_question(page, "conservative or more thorough")
    _answer_current_question(page, "Balanced")
    expect(page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(page, "No extra exclusions")
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "existing engagement dossier"
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(engagement["name"])
    expect(page.get_by_test_id("wizard-authorization-context")).to_contain_text("Acme Corp")
    expect(page.get_by_test_id("wizard-authorization-context")).to_contain_text("ROE-2026-310")

    page.get_by_test_id("wizard-confirm").click()
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])
    expect(page.locator("#engagement-select option:checked")).to_contain_text(selected_label)

    engagements_after = _api_json(operator_console_base_url, "/api/v1/engagements")
    runs_after = _api_json(operator_console_base_url, f"/api/v1/engagements/{engagement['id']}/runs")
    assert len(engagements_after) == len(engagements_before)
    assert len(runs_after) == len(runs_before) + 1

    _open_analysis_screen(page, "nav-explorer")
    expect(page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        "existing engagement dossier"
    )
    expect(page.get_by_test_id("dossier-mission-handoff")).to_contain_text(engagement["name"])
    expect(page.get_by_test_id("dossier-engagement-route")).to_contain_text(
        "Reuse existing dossier"
    )
    expect(page.get_by_test_id("dossier-engagement-route")).to_contain_text(engagement["name"])
    expect(page.get_by_test_id("dossier-authorization-context")).to_contain_text("Acme Corp")
    expect(page.get_by_test_id("dossier-authorization-context")).to_contain_text("ROE-2026-310")


def test_new_engagement_route_creates_one_dossier_and_keeps_creation_route_visible(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagements_before = _api_json(operator_console_base_url, "/api/v1/engagements")

    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator("#wizard-engagement-name").fill("Portal Assessment 2026")
    page.locator("#wizard-client").fill("Acme Corp")
    page.locator("#wizard-roe-ref").fill("ROE-2026-021")
    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("conversation-question")).to_contain_text(
        "What would you like to pentest today"
    )

    _finish_authenticated_webapp_intake(page)
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        'create a new engagement dossier named "Portal Assessment 2026"'
    )
    expect(page.get_by_test_id("wizard-authorization-context")).to_contain_text("Acme Corp")
    expect(page.get_by_test_id("wizard-authorization-context")).to_contain_text("ROE-2026-021")

    page.get_by_test_id("wizard-confirm").click()
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    engagements_after = _api_json(operator_console_base_url, "/api/v1/engagements")
    assert len(engagements_after) == len(engagements_before) + 1
    created_engagement = next(
        engagement
        for engagement in engagements_after
        if all(str(engagement["id"]) != str(before["id"]) for before in engagements_before)
    )
    assert created_engagement["name"] == "Portal Assessment 2026"

    expect(page.locator("#engagement-select option:checked")).to_contain_text(
        "Portal Assessment 2026"
    )

    _open_analysis_screen(page, "nav-explorer")
    expect(page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        'create a new engagement dossier named "Portal Assessment 2026"'
    )
    expect(page.get_by_test_id("dossier-engagement-route")).to_contain_text(
        "Create new dossier"
    )
    expect(page.get_by_test_id("dossier-engagement-route")).to_contain_text(
        "Portal Assessment 2026"
    )
    expect(page.get_by_test_id("dossier-authorization-context")).to_contain_text("Acme Corp")
    expect(page.get_by_test_id("dossier-authorization-context")).to_contain_text("ROE-2026-021")


def test_automatic_new_dossier_name_tracks_advanced_scope_and_profile_overrides(
    page: Page,
    operator_console_base_url: str,
) -> None:
    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    expect(page.locator("#wizard-engagement-name")).to_have_value("Web App Standard Assessment")

    page.locator('[data-advanced-step="1"]').click()
    page.locator("#wizard-target-urls").fill("https://portal.example.com")
    page.locator('[data-advanced-step="0"]').click()
    expect(page.locator("#wizard-engagement-name")).to_have_value(
        "portal.example.com Standard Assessment"
    )

    page.locator('[data-advanced-step="3"]').click()
    page.locator('input[name="wizard-test-profile"][value="Light"]').check()
    page.locator('[data-advanced-step="0"]').click()
    expect(page.locator("#wizard-engagement-name")).to_have_value(
        "portal.example.com Quick Overview"
    )

    page.locator('[data-advanced-step="3"]').click()
    page.locator('input[name="wizard-test-profile"][value="Deep"]').check()
    page.locator('[data-advanced-step="0"]').click()
    expect(page.locator("#wizard-engagement-name")).to_have_value(
        "portal.example.com Deep Assessment"
    )

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("conversation-question")).to_contain_text(
        "What would you like to pentest today"
    )

    _answer_current_question(page, "Our web application")
    question = _current_question_text(page)
    if "main goal" in question:
        _answer_current_question(page, "Deep assessment")
        question = _current_question_text(page)
    if any(
        fragment in question
        for fragment in (
            "exact targets",
            "hostnames, urls, or ips",
            "api base urls",
            "exact ips or cidr ranges",
        )
    ):
        _answer_current_question(page, "https://portal.example.com")
        question = _current_question_text(page)
    if "stay unauthenticated" in question:
        _answer_current_question(page, "Keep it unauthenticated")
        question = _current_question_text(page)
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")

    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        'create a new engagement dossier named "portal.example.com Deep Assessment"'
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        '"Web App Standard Assessment"'
    )

    page.get_by_test_id("wizard-confirm").click()
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select option:checked")).to_contain_text(
        "portal.example.com Deep Assessment"
    )

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["engagement_context"]["engagement_name"] == (
        "portal.example.com Deep Assessment"
    )
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"


def test_manual_dossier_name_survives_advanced_scope_and_profile_overrides(
    page: Page,
    operator_console_base_url: str,
) -> None:
    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator("#wizard-engagement-name").fill("Manual Deep Portal Review")

    page.locator('[data-advanced-step="1"]').click()
    page.locator("#wizard-target-urls").fill("https://portal.example.com")
    page.locator('[data-advanced-step="3"]').click()
    page.locator('input[name="wizard-test-profile"][value="Deep"]').check()
    page.locator('[data-advanced-step="0"]').click()
    expect(page.locator("#wizard-engagement-name")).to_have_value(
        "Manual Deep Portal Review"
    )

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("conversation-question")).to_contain_text(
        "What would you like to pentest today"
    )

    _answer_current_question(page, "Our web application")
    _answer_current_question(page, "Keep it unauthenticated")
    question = _current_question_text(page)
    if "conservative or more thorough" in question:
        _answer_current_question(page, "Balanced")
        question = _current_question_text(page)
    if _is_boundary_question(question):
        _answer_current_question(page, "No extra exclusions")

    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        'create a new engagement dossier named "Manual Deep Portal Review"'
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "portal.example.com Deep Assessment"
    )

    page.get_by_test_id("wizard-confirm").click()
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select option:checked")).to_contain_text(
        "Manual Deep Portal Review"
    )

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["engagement_context"]["engagement_name"] == (
        "Manual Deep Portal Review"
    )
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"


def test_scope_guardrails_remain_visible_from_confirmation_into_explorer_dossier(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-exclude-urls").fill("https://portal.example.com/admin")
    loaded_page.locator("#wizard-boundary-notes").fill("Avoid billing and admin flows.")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "Avoid billing and admin flows.")
            continue
        raise AssertionError(f"Unhandled question while preparing scope-guardrail flow: {question}")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text("Scope guardrails")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "1 explicit exclusion remains outside this mission unless you revise the approved scope."
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Avoid billing and admin flows.")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Balanced Technical")

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Avoid billing and admin flows.")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Balanced Technical")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Custom Exclusions Recorded")


def test_scope_guardrail_confirmation_summary_handles_plural_exclusions_cleanly(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-exclude-urls").fill(
        "https://portal.example.com/admin\nhttps://portal.example.com/billing"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(page=loaded_page, answer="No extra exclusions")
            continue
        raise AssertionError(f"Unhandled question while preparing plural scope-guardrail flow: {question}")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "2 explicit exclusions remain outside this mission unless you revise the approved scope."
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("2 explicit exclusions")


def test_revising_boundaries_to_no_extra_exclusions_clears_previous_boundary_state(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-exclude-urls").fill("https://portal.example.com/admin")
    loaded_page.locator("#wizard-boundary-notes").fill("Avoid billing and admin flows.")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "Avoid billing and admin flows.")
            continue
        raise AssertionError(f"Unhandled question while preparing boundary revision flow: {question}")

    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("1 explicit exclusion")
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Boundaries").click()
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text("Scope guardrails")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text("Avoid billing and admin flows.")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Standard Scope Only")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("No denylist recorded")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Not recorded")

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Standard Scope Only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("No denylist recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Not recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).not_to_contain_text("Avoid billing and admin flows.")


def test_revising_boundaries_to_notes_only_replaces_previous_explicit_exclusions(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-exclude-urls").fill("https://portal.example.com/admin")
    loaded_page.locator("#wizard-boundary-notes").fill("Avoid billing and admin flows.")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "Avoid billing and admin flows.")
            continue
        raise AssertionError(f"Unhandled question while preparing boundary note replacement flow: {question}")

    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("1 explicit exclusion")
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Boundaries").click()
    _answer_current_question(loaded_page, "Avoid the billing journey, but no explicit denylist entries.")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Scope guardrails: Boundary Notes Recorded. The recorded boundary note stays in force unless you revise the approved scope."
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).not_to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text(
        "Avoid the billing journey, but no explicit denylist entries."
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).not_to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text(
        "Avoid the billing journey, but no explicit denylist entries."
    )


def test_notes_only_boundary_guardrails_remain_truthful_from_confirmation_into_explorer_dossier(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-boundary-notes").fill("Avoid login and billing flows.")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "Avoid login and billing flows.")
            continue
        raise AssertionError(f"Unhandled question while preparing notes-only boundary flow: {question}")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Scope guardrails: Boundary Notes Recorded. The recorded boundary note stays in force unless you revise the approved scope."
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Avoid login and billing flows.")

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Avoid login and billing flows.")


def test_notes_only_boundary_fallback_without_explicit_metadata_stays_truthful(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Standard assessment")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-boundary-notes").fill("Avoid login and billing flows.")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "Avoid login and billing flows.")
            continue
        raise AssertionError(f"Unhandled question while preparing notes-only fallback flow: {question}")

    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizardModule = await import('/app/assets/modules/wizard.js');
          runtimeModule.state.wizard.data.intake_preferences.boundary_handling = '';
          runtimeModule.state.wizard.intake.activeQuestionId = 'confirm';
          wizardModule.createWizardModule().renderWizard();
        }
        """
    )

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Scope guardrails: Boundary Notes Recorded. The recorded boundary note stays in force unless you revise the approved scope."
    )
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("wizard-scope-guardrails")).to_contain_text("Boundary notes only")

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          runtimeModule.state.selectedRun.configuration_json.intake.preferences.boundary_handling = '';
          runtimeModule.runtime.actions.renderAll?.();
        }
        """
    )

    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Avoid login and billing flows.")


def test_session_reference_in_advanced_drawer_reaches_run_dossier(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _expect_current_question(loaded_page, "main goal")
    _answer_current_question(loaded_page, "Authenticated review")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _expect_current_question(loaded_page, "stay unauthenticated")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _expect_current_question(loaded_page, "access context")
    _answer_current_question(loaded_page, "I will add the session in advanced settings")

    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="2"]').click()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill("Analyst Session")
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill("Security Analyst")
    loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
        "session-cookie=abc123"
    )
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Complete SSO once before reusing the imported cookie jar."
    )
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Session stays valid for roughly 30 minutes."
    )

    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("Analyst Session")
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "Complete SSO once before reusing the imported cookie jar."
    )
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "Session stays valid for roughly 30 minutes."
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Access: Analyst Session (Security Analyst)"
    )

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(loaded_page)
        if "conservative or more thorough" in question:
            _answer_current_question(loaded_page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(loaded_page, "No extra exclusions")
            continue
        if "access context" in question:
            _answer_current_question(loaded_page, "Advanced settings will hold the session details")
            continue
        raise AssertionError(f"Unhandled question after session override: {question}")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Authenticated Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("1 account / role context")

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text("Protected Access")
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text("1 secret binding")
    expect(loaded_page.get_by_test_id("run-dossier")).to_contain_text("encrypted_local")


def test_revising_authenticated_access_to_unauthenticated_clears_access_context_and_downgrades_plan(
    page: Page,
    operator_console_base_url: str,
) -> None:
    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()

    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our customer portal")
    _expect_current_question(page, "main goal")
    _answer_current_question(page, "Authenticated review")
    _expect_current_question(page, "exact targets")
    _answer_current_question(page, "https://portal.example.com")
    _expect_current_question(page, "stay unauthenticated")
    _answer_current_question(page, "I have portal/app accounts")
    _expect_current_question(page, "access context")
    _answer_current_question(page, "I will add the session in advanced settings")

    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator('[data-advanced-step="2"]').click()
    page.locator('[data-account-field="label"][data-account-index="0"]').fill("Analyst Session")
    page.locator('[data-account-field="role"][data-account-index="0"]').fill("Security Analyst")
    page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
        "session-cookie=abc123"
    )
    page.locator("#wizard-manual-auth-steps").fill(
        "Complete SSO once before reusing the imported cookie jar."
    )
    page.locator("#wizard-cookie-notes").fill(
        "Session stays valid for roughly 30 minutes."
    )
    page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(5):
        if page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(page)
        if "conservative or more thorough" in question:
            _answer_current_question(page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(page, "No extra exclusions")
            continue
        if "access context" in question:
            _answer_current_question(page, "Advanced settings will hold the session details")
            continue
        raise AssertionError(f"Unhandled question before auth revision downgrade test: {question}")

    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize authenticated review with the Authenticated Only profile"
    )

    page.get_by_test_id("conversation-edit-row").locator("summary").click()
    page.get_by_role("button", name="Change Access").click()
    _answer_current_question(page, "Keep it unauthenticated")

    for _ in range(5):
        if page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        question = _current_question_text(page)
        if "main goal" in question:
            _answer_current_question(page, "Standard assessment")
            continue
        if "conservative or more thorough" in question:
            _answer_current_question(page, "Balanced")
            continue
        if _is_boundary_question(question):
            _answer_current_question(page, "No extra exclusions")
            continue
        raise AssertionError(f"Unhandled question after auth revision downgrade: {question}")

    expect(page.get_by_test_id("wizard-summary-confirmed")).not_to_contain_text(
        "Goal: Authenticated Review"
    )
    expect(page.get_by_test_id("wizard-summary-targets")).not_to_contain_text(
        "Analyst Session"
    )
    expect(page.get_by_test_id("wizard-summary-targets")).not_to_contain_text(
        "Complete SSO once before reusing the imported cookie jar."
    )
    expect(page.get_by_test_id("wizard-summary-targets")).not_to_contain_text(
        "Session stays valid for roughly 30 minutes."
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize standard assessment with the Standard profile and the active-web-safe execution lane"
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "authenticated review"
    )
    expect(page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Authenticated Only"
    )

    page.get_by_test_id("wizard-confirm").click()
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(page.locator("#mission-scope-summary")).not_to_contain_text("1 account / role context")

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["test_profile"] == "Standard"
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []
    assert configuration["access"]["manual_auth_steps"] is None
    assert configuration["access"]["cookie_notes"] is None

    _open_analysis_screen(page, "nav-explorer")
    expect(page.get_by_test_id("run-dossier")).to_contain_text("0 secret bindings")
    expect(page.get_by_test_id("run-dossier")).not_to_contain_text(
        "Complete SSO once before reusing the imported cookie jar."
    )
    expect(page.get_by_test_id("run-dossier")).not_to_contain_text(
        "Session stays valid for roughly 30 minutes."
    )
    expect(page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        "prioritize standard assessment with the Standard profile"
    )
    expect(page.get_by_test_id("dossier-mission-handoff")).not_to_contain_text(
        "authenticated review"
    )


def test_api_conversation_maps_to_adaptive_profile_and_pack_context(loaded_page: Page) -> None:
    _finish_api_intake(loaded_page)
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Adaptive Customer-Specific Testing"
    )
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("API")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        "Adaptive Customer-Specific Mode"
    )

    _open_execution_screen(loaded_page, "nav-packs")
    expect(loaded_page.get_by_test_id("screen-pack-forge")).to_be_visible()
    expect(loaded_page.get_by_test_id("pack-summary")).to_contain_text(
        "Generate or select a capability pack"
    )


@pytest.mark.parametrize(
    "flow",
    CONVERSATIONAL_MATRIX,
    ids=[entry["assessment_type"].lower().replace(" / ", "-").replace(" ", "-") for entry in CONVERSATIONAL_MATRIX],
)
def test_conversational_completion_matrix_covers_every_assessment_type(
    loaded_page: Page,
    operator_console_base_url: str,
    flow: dict,
) -> None:
    _finish_conversational_matrix_flow(loaded_page, flow)

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        f"Target Type: {flow['assessment_type']}"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        flow["expected_scope_fragment"]
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["assessment_type"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected_profile"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(flow["expected_lane"])

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, f"Expected the created {flow['assessment_type']} run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == flow["assessment_type"]
    assert configuration["test_profile"] == flow["expected_profile"]
    assert configuration["execution_profile"] == flow["expected_lane"]
    assert flow["expected_scope_fragment"] in _target_values_text(configuration)


@pytest.mark.parametrize(
    "flow",
    QUICK_REPLY_MATRIX,
    ids=[entry["id"] for entry in QUICK_REPLY_MATRIX],
)
def test_quick_reply_driven_intake_flows_create_truthful_runs(
    loaded_page: Page,
    operator_console_base_url: str,
    flow: dict,
) -> None:
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What would you like to pentest today"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Use one of the suggested replies for the common path"
    )

    _finish_quick_reply_matrix_flow(loaded_page, flow)

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        f"Target Type: {flow['expected']['assessment_type']}"
    )
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected"]["assessment_type"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected"]["test_profile"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected"]["execution_profile"]
    )

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after chip-driven mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == flow["expected"]["assessment_type"]
    assert configuration["test_profile"] == flow["expected"]["test_profile"]
    assert configuration["execution_profile"] == flow["expected"]["execution_profile"]
    assert flow["expected"]["scope_fragment"] in _target_values_text(configuration)


def test_still_needed_summary_hides_current_topic_from_jump_actions(loaded_page: Page) -> None:
    _click_quick_reply(loaded_page, "Our web application")
    _click_quick_reply(loaded_page, "Standard assessment")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What exact targets are authorized for this assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).not_to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Safety")
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text(
        "Use the remaining quick actions to revise the other missing mission topics"
    )


def test_still_needed_summary_deduplicates_goal_linked_actions(loaded_page: Page) -> None:
    _click_quick_reply(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is your main goal for this assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).not_to_contain_text("Goal")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).not_to_contain_text("Output")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Scope")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Safety")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Boundaries")
    assert (
        loaded_page.locator('[data-testid="wizard-summary-needed"] .compact-badge-list .badge').count()
        == 0
    )


def test_path_note_deduplicates_goal_linked_topics(loaded_page: Page) -> None:
    _click_quick_reply(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is your main goal for this assessment"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Scope, Safety, Boundaries."
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Goal")
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Output")


def test_auth_details_question_does_not_repeat_access_in_summary_or_path_note(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What access context should I record"
    )
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).not_to_contain_text("Access")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Safety")
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")


def test_advanced_access_placeholder_opens_drawer_and_realigns_to_safety(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What access context should I record"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Access, Safety, Boundaries."
    )
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Access")
    expect(loaded_page.get_by_test_id("wizard-needed-actions")).to_contain_text("Safety")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    expect(loaded_page.locator('[data-advanced-step="2"]')).to_have_class(
        re.compile(r"secondary")
    )

    loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
        "analyst@example.com"
    )
    loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
        "vault://portal/analyst"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Boundaries."
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text("Boundaries")


def test_change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
        "analyst@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
        "vault://portal/analyst"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-access revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert account["role"] == "Security Lead"
    assert "password" in account["secret_bindings"]


def test_edit_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit access",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_previous_topic_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
        expected_role="Security Lead",
    )


def test_previous_topic_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_previous_topic_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
        expected_role="Security Lead",
    )


def test_previous_topic_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_previous_topic_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        access_mode="api",
        initial_detail="role API Analyst api-key vault://api/original-token",
        updated_detail="role API Lead api-key vault://api/updated-token",
        expected_role="API Lead",
    )


def test_multi_role_advanced_access_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill(
        "Analyst User"
    )
    loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
        "analyst@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
        "vault://portal/analyst"
    )
    loaded_page.locator("#wizard-add-account-btn").click()
    loaded_page.locator('[data-account-field="label"][data-account-index="1"]').fill(
        "Admin User"
    )
    loaded_page.locator('[data-account-field="username"][data-account-index="1"]').fill(
        "admin@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="1"]').fill(
        "Application Admin"
    )
    loaded_page.locator('[data-account-field="secret_ref"][data-account-index="1"]').fill(
        "vault://portal/admin"
    )
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Use SSO handoff before privileged replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Analyst User (Security Analyst), Admin User (Application Admin)"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "Avoid billing flows")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the multi-role advanced-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    accounts = run["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert accounts[0]["label"] == "Analyst User"
    assert accounts[1]["label"] == "Admin User"
    assert run["configuration_json"]["access"]["secret_storage"]["binding_count"] == 2
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Use SSO handoff before privileged replay."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "2 access contexts recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Analyst User (Security Analyst), Admin User (Application Admin)"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Credentialed Login"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Use SSO handoff before privileged replay."
    )
    loaded_page.get_by_test_id("dossier-access-detail").locator("summary").click()
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Protected Binding Types"
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text("password")
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Application Admin"
    )


def test_multi_role_api_access_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill(
        "API Analyst"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Read Only API"
    )
    loaded_page.locator('[data-account-field="api_key_ref"][data-account-index="0"]').fill(
        "vault://api/analyst-key"
    )
    loaded_page.locator("#wizard-add-account-btn").click()
    loaded_page.locator('[data-account-field="label"][data-account-index="1"]').fill(
        "API Admin"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="1"]').fill(
        "API Admin"
    )
    loaded_page.locator(
        '[data-account-field="bearer_token_ref"][data-account-index="1"]'
    ).fill("vault://api/admin-bearer")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "API Analyst (Read Only API), API Admin (API Admin)"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the multi-role API access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    accounts = run["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"
    assert "api_key" in accounts[0]["secret_bindings"]
    assert "bearer_token" in accounts[1]["secret_bindings"]
    assert run["configuration_json"]["access"]["secret_storage"]["binding_count"] == 2

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "2 access contexts recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "API Token / Key"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "API Analyst (Read Only API), API Admin (API Admin)"
    )
    loaded_page.get_by_test_id("dossier-access-detail").locator("summary").click()
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text("api_key")
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "bearer_token"
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Not recorded"
    )


def test_multi_role_session_access_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill(
        "Analyst Session"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
        "session-cookie=abc123"
    )
    loaded_page.locator("#wizard-add-account-btn").click()
    loaded_page.locator('[data-account-field="label"][data-account-index="1"]').fill(
        "Admin Session"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="1"]').fill(
        "Application Admin"
    )
    loaded_page.locator('[data-account-field="session_ref"][data-account-index="1"]').fill(
        "session-cookie=xyz789"
    )
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Rotate imported cookie bundles every 30 minutes."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Analyst Session (Security Analyst), Admin Session (Application Admin)"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the multi-role session access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    accounts = run["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert "session" in accounts[0]["secret_bindings"]
    assert "session" in accounts[1]["secret_bindings"]
    assert run["configuration_json"]["access"]["secret_storage"]["binding_count"] == 2
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Rotate imported cookie bundles every 30 minutes."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "2 access contexts recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Session / Cookie"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Rotate imported cookie bundles every 30 minutes."
    )
    loaded_page.get_by_test_id("dossier-access-detail").locator("summary").click()
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text("session")
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Application Admin"
    )


def test_multi_role_manual_auth_access_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill(
        "Analyst SSO"
    )
    loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
        "analyst@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="mfa_notes"][data-account-index="0"]').fill(
        "Approve push notification on analyst device."
    )
    loaded_page.locator("#wizard-add-account-btn").click()
    loaded_page.locator('[data-account-field="label"][data-account-index="1"]').fill(
        "Admin SSO"
    )
    loaded_page.locator('[data-account-field="username"][data-account-index="1"]').fill(
        "admin@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="1"]').fill(
        "Application Admin"
    )
    loaded_page.locator('[data-account-field="mfa_notes"][data-account-index="1"]').fill(
        "Complete IdP handoff before privileged validation."
    )
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Analyst SSO (Security Analyst), Admin SSO (Application Admin)"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the manual-auth multi-role run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    accounts = run["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert accounts[0]["label"] == "Analyst SSO"
    assert accounts[0]["username"] == "analyst@example.com"
    assert accounts[0]["mfa_notes"] == "Approve push notification on analyst device."
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["username"] == "admin@example.com"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before privileged validation."
    assert "secret_bindings" not in accounts[0]
    assert "secret_bindings" not in accounts[1]
    assert "secret_storage" not in run["configuration_json"]["access"]
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete shared SSO handoff before replay."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "2 access contexts recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Credentialed Login"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("dossier-access-detail").locator("summary").click()
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "No protected binding recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Approve push notification on analyst device."
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Complete IdP handoff before privileged validation."
    )


def test_manual_note_only_roles_persist_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="label"][data-account-index="0"]').fill(
        "Analyst MFA"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="mfa_notes"][data-account-index="0"]').fill(
        "Approve analyst push notification."
    )
    loaded_page.locator("#wizard-add-account-btn").click()
    loaded_page.locator('[data-account-field="label"][data-account-index="1"]').fill(
        "Admin SSO"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="1"]').fill(
        "Application Admin"
    )
    loaded_page.locator('[data-account-field="mfa_notes"][data-account-index="1"]').fill(
        "Complete IdP handoff before privileged validation."
    )
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Shared SSO handoff is required before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Analyst MFA (Security Analyst), Admin SSO (Application Admin)"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the manual-note-only run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    accounts = run["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert accounts[0]["label"] == "Analyst MFA"
    assert accounts[0]["role"] == "Security Analyst"
    assert accounts[0]["mfa_notes"] == "Approve analyst push notification."
    assert "secret_bindings" not in accounts[0]
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["role"] == "Application Admin"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before privileged validation."
    assert "secret_bindings" not in accounts[1]
    assert "secret_storage" not in run["configuration_json"]["access"]
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Shared SSO handoff is required before replay."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "2 access contexts recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "0 secret bindings"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Shared SSO handoff is required before replay."
    )
    loaded_page.get_by_test_id("dossier-access-detail").locator("summary").click()
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "No protected binding recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Approve analyst push notification."
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Complete IdP handoff before privileged validation."
    )
    expect(loaded_page.get_by_test_id("dossier-access-detail")).to_contain_text(
        "Not recorded"
    )


def test_shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Shared manual auth guidance recorded"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None
    assert "secret_storage" not in run["configuration_json"]["access"]

    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("1 access context")
    expect(loaded_page.locator("#mission-scope-summary")).not_to_contain_text(
        "0 access context"
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "1 access context recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Credentialed Login"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Shared manual auth guidance recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "No access context recorded"
    )


def test_shared_session_note_without_accounts_persists_into_run_and_dossier_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Shared session guidance recorded"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay imported cookie bundle after operator login."
    )
    assert "secret_storage" not in run["configuration_json"]["access"]

    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("1 access context")
    expect(loaded_page.locator("#mission-scope-summary")).not_to_contain_text(
        "0 access context"
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "1 access context recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Session / Cookie"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Shared session guidance recorded"
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay imported cookie bundle after operator login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "No access context recorded"
    )


def test_change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Shared manual auth guidance recorded"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "Operator must complete the updated shared SSO handoff before replay."
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the edit-path-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edit-access shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the edit-path-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the edit-path-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the revise-access-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revise-access shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the revise-access-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the revise-access-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Access").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the confirmation-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the confirmation-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the confirmation-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the confirmation-updated shared SSO handoff before replay."
    )


def test_inline_change_from_history_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("conversation-history-disclosure").locator("summary").click()
    target_turn = loaded_page.get_by_test_id("conversation-turn").filter(
        has_text="Operator must complete shared SSO handoff before replay."
    )
    expect(target_turn).to_have_count(1)
    target_turn.get_by_role("button", name="Change").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the inline-history-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the inline-history-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the inline-history-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the inline-history-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_previous_topic_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    loaded_page.get_by_test_id("wizard-back").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the back-button-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the previous-topic-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the back-button-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the back-button-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_change_that_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change that")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the change-that-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the change-that-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the change-that-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the change-that-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_undo_alias_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "undo")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the revision-proof-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the undo-alias-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the revision-proof-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the revision-proof-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-manual-auth-steps").fill(
        "Operator must complete shared SSO handoff before replay."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-stage-3").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Operator must complete shared SSO handoff before replay."
    )

    _answer_current_question(
        loaded_page,
        "Operator must complete the stage-button-updated shared SSO handoff before replay.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the stepper-revised shared-manual-auth run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete the stage-button-updated shared SSO handoff before replay."
    )
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Operator must complete the stage-button-updated shared SSO handoff before replay."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def test_revise_access_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="revise access",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Revise access sequencing after the shared SSO handoff before replay.",
    )


def test_change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Operator must complete the change-auth shared SSO handoff before replay.",
    )


def test_edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Operator must complete the edit-auth shared SSO handoff before replay.",
    )


def test_revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="revise auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Operator must complete the revise-auth shared SSO handoff before replay.",
    )


def test_change_auth_after_shared_manual_auth_note_without_accounts_accepts_longer_note_text_containing_change_auth_phrase(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Operator must change auth sequencing after the shared SSO handoff before replay.",
    )


def test_revise_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="revise auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Revise auth sequencing after the shared SSO handoff before replay.",
    )


def test_edit_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="manual",
        initial_text="Operator must complete shared SSO handoff before replay.",
        updated_text="Edit auth sequencing after the shared SSO handoff before replay.",
    )


def test_change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the refreshed cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Shared session guidance recorded"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "Replay the refreshed cookie bundle after the operator completes login."
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the refreshed cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the refreshed cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the revise-path-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revise-session shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the revise-path-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the revise-path-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the edit-session-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edit-session shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the edit-session-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the edit-session-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_edit_session_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit session",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Edit session cookie scope after the operator completes login if needed.",
    )


def test_change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Replay the change-auth cookie bundle after the operator completes login.",
    )


def test_edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Replay the edit-auth cookie bundle after the operator completes login.",
    )


def test_revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="revise auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Replay the revise-auth cookie bundle after the operator completes login.",
    )


def test_edit_auth_after_shared_session_note_without_accounts_accepts_longer_note_text_containing_edit_auth_phrase(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Replay the imported cookie bundle after the operator completes login and edit auth cookie scope if needed.",
    )


def test_change_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Change auth cookie scope after the operator completes login if needed.",
    )


def test_edit_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text="Edit auth cookie scope after the operator completes login if needed.",
    )


def test_change_access_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Access").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the confirmation-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the confirmation-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the confirmation-updated cookie bundle after the operator completes login."
    )


def test_inline_change_from_history_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("conversation-history-disclosure").locator("summary").click()
    target_turn = loaded_page.get_by_test_id("conversation-turn").filter(
        has_text="Replay imported cookie bundle after operator login."
    )
    expect(target_turn).to_have_count(1)
    target_turn.get_by_role("button", name="Change").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the inline-history-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the inline-history-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the inline-history-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the inline-history-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_previous_topic_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    loaded_page.get_by_test_id("wizard-back").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the back-button-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the previous-topic-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the back-button-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the back-button-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_previous_alias_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "previous")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the back-alias-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the previous-alias-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the back-alias-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the back-alias-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_go_back_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "go back")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the return-path-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the go-back-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the return-path-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the return-path-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator("#wizard-cookie-notes").fill(
        "Replay imported cookie bundle after operator login."
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-stage-3").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Replay imported cookie bundle after operator login."
    )

    _answer_current_question(
        loaded_page,
        "Replay the stage-button-updated cookie bundle after the operator completes login.",
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the stepper-revised shared-session-note run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] is None
    assert run["configuration_json"]["access"]["cookie_notes"] == (
        "Replay the stage-button-updated cookie bundle after the operator completes login."
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        "Replay the stage-button-updated cookie bundle after the operator completes login."
    )
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Replay imported cookie bundle after operator login."
    )


def test_change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="username"][data-account-index="0"]').fill(
        "analyst@example.com"
    )
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill(
        "vault://portal/analyst"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change credential")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-credential revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert account["role"] == "Security Lead"
    assert "password" in account["secret_bindings"]


def test_change_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_edit_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_revise_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="revise auth",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_edit_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit credential",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_revise_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="revise credential",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


def test_auth_details_advanced_settings_reply_opens_access_drawer(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(loaded_page, "I will add the full details in advanced settings")

    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    expect(loaded_page.locator('[data-advanced-step="2"]')).to_have_class(
        re.compile(r"secondary")
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Access, Safety, Boundaries."
    )


def test_auth_details_question_can_switch_back_to_unauthenticated_without_dead_end(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What access context should I record"
    )
    _answer_current_question(loaded_page, "Keep it unauthenticated")

    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "What access context should I record"
    )
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Access: Unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).not_to_contain_text("Access")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


def test_change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
        "session-cookie=abc123"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change auth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "role Security Lead session session-cookie=xyz789",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-session revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_revise_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="revise auth",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


def test_edit_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit auth",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


def test_change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I will add access in advanced settings")

    loaded_page.get_by_test_id("wizard-needed-action-access").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-account-field="role"][data-account-index="0"]').fill(
        "Security Analyst"
    )
    loaded_page.locator('[data-account-field="session_ref"][data-account-index="0"]').fill(
        "session-cookie=abc123"
    )
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should I keep this conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "role Security Lead session session-cookie=xyz789",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-session alias-revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_edit_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit session",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


def test_revise_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="revise session",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


def test_change_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change token",
        access_mode="api",
        initial_detail="role API Analyst api-key vault://api/original-token",
        updated_detail="role API Lead api-key vault://api/updated-token",
    )


def test_revise_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="revise token",
        access_mode="api",
        initial_detail="role API Analyst api-key vault://api/original-token",
        updated_detail="role API Lead api-key vault://api/updated-token",
    )


def test_edit_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="edit token",
        access_mode="api",
        initial_detail="role API Analyst api-key vault://api/original-token",
        updated_detail="role API Lead api-key vault://api/updated-token",
    )


def test_advanced_drawer_overrides_stay_synchronized(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "https://app.example.com")

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()

    loaded_page.locator('[data-advanced-step="3"]').click()
    loaded_page.locator('input[name="wizard-test-profile"][value="Deep"]').check()
    loaded_page.locator('[data-advanced-step="5"]').click()
    loaded_page.locator("#wizard-active-checks").select_option("active")
    loaded_page.locator("#wizard-max-depth").select_option("deep")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "advanced override"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        "Deep Assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_contain_text(
        "Active Validation"
    )


def test_clearing_advanced_scope_from_confirmation_returns_to_scope_with_visible_validation_feedback(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_standard_web_intake(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="1"]').click()
    loaded_page.locator("#wizard-target-urls").fill("")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What exact targets are authorized for this assessment"
    )
    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "Add at least one target in scope."
    )

    _answer_current_question(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the recovered advanced-scope run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert "https://app.example.com" in _target_values_text(run["configuration_json"])


def test_authenticated_only_advanced_profile_from_confirmation_reopens_access_before_confirm(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_standard_web_intake(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="3"]').click()
    loaded_page.locator('input[name="wizard-test-profile"][value="Authenticated Only"]').check()
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_hidden()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Should this stay unauthenticated"
    )

    _answer_current_question(loaded_page, "I have portal/app accounts")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What access context should I record"
    )
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the advanced-profile-adjusted run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["test_profile"] == "Authenticated Only"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert configuration["access"]["accounts"][0]["role"] == "Security Lead"


def test_ambiguous_public_scope_is_rejected_safely(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our website")
    _answer_current_question(loaded_page, "Quick overview")
    _expect_current_question(loaded_page, "exact targets")
    _answer_current_question(loaded_page, "scan anything public you can find")

    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "I need exact authorized targets"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact targets"
    )


def test_dispatch_and_status_history_work_after_conversational_intake(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()

    run_activity = loaded_page.get_by_test_id("mission-run-activity")
    expect(run_activity).to_contain_text("Queued")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(
        "Selected Check Focus"
    )
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("10.0.20.0/24")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(
        "Waiting for explicit operator dispatch"
    )

    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.locator("#status-feed")).to_contain_text(
        "Discovery completed in inline mode",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.locator("#surface-insights")).to_contain_text("3 hosts or network objects")
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text("10.0.20.1")
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("10.0.20.3")
    expect(loaded_page.get_by_test_id("discovery-complete-summary")).to_contain_text(
        "3 hosts and 0 services were mapped"
    )
    expect(loaded_page.get_by_test_id("status-feed-history")).to_be_visible()
    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("Inventory is complete")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("Nmap version test-build")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("1 artifact")


def test_ready_to_start_and_thin_output_states_keep_one_dispatch_action_and_truthful_completion(
    loaded_page: Page, probe_server: str
) -> None:
    _finish_standard_web_intake(loaded_page, probe_server)
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("Run is ready to start")
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        "Queued checks are ready. Press Start Validation to launch them."
    )
    expect(loaded_page.locator('[data-run-dispatch="selected"]')).to_have_count(1)
    expect(loaded_page.locator("#next-actions")).not_to_contain_text("Start Validation")
    expect(
        loaded_page.get_by_test_id("mission-run-activity").locator('[data-run-dispatch="selected"]')
    ).to_have_count(0)

    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "Execution finished with limited analyst output",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        "The queued work finished, but there are no findings and no discovery-confirmed inventory yet."
    )
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("Selected Check Focus")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(probe_server)
    expect(loaded_page.locator('[data-run-dispatch="selected"]')).to_have_count(0)


def test_manual_dispatch_mode_explains_why_start_validation_does_not_launch_work(
    manual_loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(manual_loaded_page)
    manual_loaded_page.get_by_test_id("wizard-confirm").click()

    expect(manual_loaded_page.get_by_test_id("mission-dispatch")).to_be_visible(timeout=15000)
    manual_loaded_page.get_by_test_id("mission-dispatch").click()

    expect(manual_loaded_page.locator("#status-feed")).to_contain_text(
        "manual mode",
        timeout=15000,
    )
    expect(manual_loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "Dispatch is waiting on a worker"
    )
    expect(manual_loaded_page.get_by_test_id("manual-dispatch-warning")).to_contain_text(
        "no inline runner or background worker is attached"
    )
    expect(manual_loaded_page.get_by_test_id("manual-dispatch-warning")).to_contain_text(
        "TASK_DISPATCH_MODE=inline"
    )
    expect(manual_loaded_page.locator('[data-testid="mission-dispatch"]')).to_have_count(0)


def test_phase_navigation_keeps_only_current_workflow_visible(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Conversational Intake")
    expect(loaded_page.get_by_test_id("phase-subnav")).not_to_contain_text("Findings")

    _switch_phase(loaded_page, "execution")
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(loaded_page.get_by_test_id("screen-wizard")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Mission Control")
    expect(loaded_page.get_by_test_id("phase-subnav")).not_to_contain_text("Conversational Intake")
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_visible()
    expect(loaded_page.get_by_test_id("persistent-context")).to_contain_text("Run")

    _switch_phase(loaded_page, "analysis")
    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("screen-mission-control")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Reports")
    expect(loaded_page.get_by_test_id("phase-subnav")).not_to_contain_text("Mission Control")
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()


def test_mission_control_groups_secondary_context_into_calmer_snapshot_panels(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.get_by_test_id("mission-snapshot-panel")).to_contain_text(
        "Operational Snapshot"
    )
    expect(loaded_page.get_by_test_id("mission-snapshot-panel")).to_contain_text(
        "Status Board"
    )
    expect(loaded_page.get_by_test_id("mission-support-panel")).to_contain_text(
        "Supporting Context"
    )
    expect(loaded_page.get_by_test_id("mission-support-panel")).to_contain_text(
        "Active Scope & Profile"
    )


def test_internal_validation_conversation_stays_operational_without_credentials(loaded_page: Page) -> None:
    _finish_internal_validation_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Internal Validation"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text(
        "Nothing blocking confirmation"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Validation")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")
    expect(loaded_page.get_by_test_id("mission-dispatch")).to_be_visible()

    loaded_page.get_by_test_id("mission-dispatch").click()
    expect(loaded_page.locator("#status-feed")).to_contain_text(
        "Discovery completed in inline mode",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("discovery-complete-summary")).to_contain_text(
        "ready for the next controlled follow-up run"
    )
    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("follow-up-service-enumeration-mission")).to_be_visible()


def test_internal_validation_accepts_keep_it_unauthenticated_and_advances_cleanly(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission"
    )
    _expect_current_question(loaded_page, "stay unauthenticated")
    _answer_current_question(loaded_page, "Keep it unauthenticated")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Boundaries."
    )


def test_goal_to_scope_transition_does_not_show_scope_error_before_scope_input(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range or internal hosts"
    )
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Access, Safety, Boundaries."
    )


def test_repeating_access_answer_at_safety_gives_contextual_guidance(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Keep it unauthenticated")

    _expect_current_question(loaded_page, "conservative or more thorough")
    _answer_current_question(loaded_page, "Unauthenticated")

    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "Access is already set to unauthenticated. Next I need a safety choice"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Boundaries."
    )


def test_repeating_safety_answer_at_boundaries_gives_contextual_guidance(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Keep it unauthenticated")
    _answer_current_question(loaded_page, "Balanced")

    _expect_current_question(loaded_page, "internal edges I must avoid")
    _answer_current_question(loaded_page, "Balanced")

    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "Safety is already set to balanced. Next I need boundary guidance such as No extra exclusions, Report adjacent internal ranges only, or custom exclusions / boundary notes."
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).not_to_contain_text(
        "LOCKED 6"
    )
    expect(loaded_page.get_by_test_id("wizard-confirm")).to_be_hidden()


def test_authenticated_app_can_stay_unauthenticated_without_access_dead_end(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "Keep it unauthenticated")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "What access context should I record"
    )

    _answer_current_question(loaded_page, "Balanced")
    if not loaded_page.get_by_test_id("wizard-confirmation-summary").is_visible():
        _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize standard assessment with the Standard profile and the active-web-safe execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "authenticated review"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).not_to_contain_text("1 account / role context")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created unauthenticated authenticated-app run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Authenticated App"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []


def test_internal_range_authenticated_review_stages_discovery_first_with_access_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(loaded_page, "user alice role Analyst secret vault://lan/alice")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Authenticated Review"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Standard profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "credential-aware follow-up options"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Authenticated Only profile and the passive-network-discovery execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "\"10.0.20.0/24 Authenticated Review\""
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "authenticated-review"
    assert configuration["access"]["accounts"]


def test_internal_range_deep_assessment_stages_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep assessment")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Keep it unauthenticated")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Deep Assessment"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Standard profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface deeper follow-up validation once reachable hosts and services are confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Deep profile and the passive-network-discovery execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["web_crawling"] is True
    assert configuration["modules"]["content_discovery"] is True
    assert configuration["modules"]["nuclei_checks"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["adaptive_ai_generated_tests"] is True
    assert configuration["safety"]["active_checks"] == "guarded"
    assert configuration["safety"]["max_validation_depth"] == "standard"


def test_internal_range_adaptive_testing_stages_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Keep it unauthenticated")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Adaptive Customer-Specific Testing"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Standard profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Adaptive Customer-Specific Mode profile and the passive-network-discovery execution lane"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "adaptive-coverage"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["web_crawling"] is True
    assert configuration["modules"]["content_discovery"] is True
    assert configuration["modules"]["nuclei_checks"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["adaptive_ai_generated_tests"] is True
    assert configuration["safety"]["active_checks"] == "guarded"
    assert configuration["safety"]["max_validation_depth"] == "standard"


def test_web_internal_validation_intent_normalizes_to_deep_assessment(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "https://app.example.com")

    question = _current_question_text(loaded_page)
    if "stay unauthenticated" in question:
        _answer_current_question(loaded_page, "Keep it unauthenticated")
        question = _current_question_text(loaded_page)
    if "conservative or more thorough" in question:
        _answer_current_question(loaded_page, "Balanced")
        question = _current_question_text(loaded_page)
    if _is_boundary_question(question):
        _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize deep assessment with the Deep profile and the active-web-safe execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "internal validation"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "\"app.example.com Deep Assessment\""
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"


def test_scope_revision_from_authenticated_web_to_internal_range_realigns_to_discovery_first_internal_plan(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_authenticated_webapp_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize authenticated review with the Authenticated Only profile and the active-web-safe execution lane"
    )

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Scope").click()
    _answer_current_question(loaded_page, "10.0.20.0/24")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Standard profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "credential-aware follow-up options"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Authenticated Only profile and the passive-network-discovery execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Internal Range / LAN"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Authenticated Review"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "authenticated-review"
    assert configuration["access"]["accounts"]


def test_scope_revision_from_adaptive_web_to_internal_range_realigns_to_discovery_first_internal_plan(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our web application")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://app.example.com")
    _answer_current_question(loaded_page, "Keep it unauthenticated")
    question = _current_question_text(loaded_page)
    if "conservative or more thorough" in question:
        _answer_current_question(loaded_page, "Balanced")
        question = _current_question_text(loaded_page)
    if _is_boundary_question(question):
        _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize adaptive customer-specific testing with the Adaptive Customer-Specific Mode profile and the active-web-safe execution lane"
    )

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Scope").click()
    _answer_current_question(loaded_page, "10.0.20.0/24")
    question = _current_question_text(loaded_page)
    if _is_boundary_question(question):
        _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Standard profile"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Adaptive Customer-Specific Mode profile and the passive-network-discovery execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Internal Range / LAN"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Goal: Adaptive Customer-Specific Testing"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["intake"]["preferences"]["primary_goal"] == "adaptive-coverage"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["web_crawling"] is True
    assert configuration["modules"]["content_discovery"] is True
    assert configuration["modules"]["nuclei_checks"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["adaptive_ai_generated_tests"] is True
    assert configuration["safety"]["active_checks"] == "guarded"
    assert configuration["safety"]["max_validation_depth"] == "standard"


def test_scope_revision_from_api_to_plain_web_url_reclassifies_scope_truthfully(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Standard assessment")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(loaded_page, "role API Analyst api-key vault://api/key")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "I am going to run an api assessment against https://api.example.com/v1."
    )

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Scope").click()
    _answer_current_question(loaded_page, "https://app.example.com")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "adjacent internal ranges"
    )
    expect(loaded_page.locator('[data-quick-reply="Report adjacent internal ranges only"]')).to_have_count(0)
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "I am going to run a website / web app assessment against https://app.example.com."
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "I am going to run an api assessment against https://app.example.com."
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Website / Web App"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Scope: 1 urls"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).not_to_contain_text(
        "Scope: 1 api base urls"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-web-nuclei-audit")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised API-to-web run to stay selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-web-nuclei-audit"
    assert configuration["targets"]["urls"] == ["https://app.example.com"]
    assert configuration["targets"]["api_base_urls"] == []
    assert configuration["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_scope_revision_from_internal_report_only_boundaries_to_web_clears_stale_lateral_copy(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    question = _current_question_text(loaded_page)
    if "stay unauthenticated" in question:
        _answer_current_question(loaded_page, "Keep it unauthenticated")
        question = _current_question_text(loaded_page)
    if "conservative or more thorough" in question:
        _answer_current_question(loaded_page, "Balanced")
        question = _current_question_text(loaded_page)

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "adjacent internal ranges"
    )
    _answer_current_question(loaded_page, "Report adjacent internal ranges only")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "Scope guardrails: Report Adjacent Ranges Only."
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "I will report adjacent reachable internal ranges but will not expand into them without explicit follow-up approval."
    )

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Scope").click()
    _answer_current_question(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Report Adjacent Ranges Only"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "adjacent reachable internal ranges"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Website / Web App"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-needed")).to_contain_text(
        "Nothing blocking confirmation"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-inferred")).to_contain_text(
        "1 safe defaults proposed"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Light")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-web-baseline")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised run to stay selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Light"
    assert configuration["execution_profile"] == "passive-web-baseline"
    assert configuration["intake"]["preferences"]["primary_goal"] == "inventory-first"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert configuration["intake"]["preferences"]["lateral_discovery"] == "not-requested"


def test_scope_revision_from_internal_validation_lan_realigns_to_deep_web_plan(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_internal_validation_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "begin with live network discovery under the Internal Validation profile"
    )

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Scope").click()
    _answer_current_question(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "Are there systems, behaviors, or boundaries I must avoid or handle carefully?"
    )
    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "prioritize deep assessment with the Deep profile and the active-web-safe execution lane"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "Internal Validation"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).not_to_contain_text(
        "passive-web-nuclei-audit"
    )
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_contain_text(
        "\"app.example.com Deep Assessment\""
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Target Type: Website / Web App"
    )

    loaded_page.get_by_test_id("wizard-confirm").click()

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to be selected after mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"


def test_revising_an_earlier_topic_shows_return_to_main_intake_flow(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Goal").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )

    _answer_current_question(loaded_page, "Deep internal validation")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )


def test_change_goal_command_reopens_goal_question_and_realigns_to_auth(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change goal")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_edit_goal_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit goal")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_revise_goal_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise goal")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_change_profile_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change profile")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )


def test_edit_profile_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit profile")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_revise_profile_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise profile")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_change_depth_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change depth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )


def test_edit_depth_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit depth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_revise_depth_alias_reopens_goal_question_with_editable_goal_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise depth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "main goal"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Inventory First"
    )

    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "stay unauthenticated"
    )
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Still to confirm in this mission: Safety, Boundaries."
    )


def test_change_output_command_reopens_output_question_and_updates_style(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change output")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, "Executive summary")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Output: Executive Summary"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


def test_edit_output_alias_reopens_output_question_with_editable_style_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit output")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, "Technical detail")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Output: Technical Detail"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


def test_revise_output_alias_reopens_output_question_with_editable_style_draft(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise output")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, "Normal")

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Output: Balanced Technical"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


@pytest.mark.parametrize(
    ("command", "style_answer", "expected_summary"),
    [
        pytest.param(
            "change report",
            "Executive summary",
            "Output: Executive Summary",
            id="change-report",
        ),
        pytest.param(
            "edit report",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-report",
        ),
        pytest.param(
            "revise report",
            "Normal",
            "Output: Balanced Technical",
            id="revise-report",
        ),
        pytest.param(
            "change output style",
            "Executive summary",
            "Output: Executive Summary",
            id="change-output-style",
        ),
        pytest.param(
            "edit output style",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-output-style",
        ),
        pytest.param(
            "revise output style",
            "Normal",
            "Output: Balanced Technical",
            id="revise-output-style",
        ),
        pytest.param(
            "change reporting style",
            "Executive summary",
            "Output: Executive Summary",
            id="change-reporting-style",
        ),
        pytest.param(
            "edit reporting style",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-reporting-style",
        ),
        pytest.param(
            "revise reporting style",
            "Normal",
            "Output: Balanced Technical",
            id="revise-reporting-style",
        ),
        pytest.param(
            "change report style",
            "Executive summary",
            "Output: Executive Summary",
            id="change-report-style",
        ),
        pytest.param(
            "edit report style",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-report-style",
        ),
        pytest.param(
            "revise report style",
            "Normal",
            "Output: Balanced Technical",
            id="revise-report-style",
        ),
        pytest.param(
            "change format",
            "Executive summary",
            "Output: Executive Summary",
            id="change-format",
        ),
        pytest.param(
            "edit format",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-format",
        ),
        pytest.param(
            "revise format",
            "Normal",
            "Output: Balanced Technical",
            id="revise-format",
        ),
        pytest.param(
            "change reporting",
            "Executive summary",
            "Output: Executive Summary",
            id="change-reporting",
        ),
        pytest.param(
            "edit reporting",
            "Technical detail",
            "Output: Technical Detail",
            id="edit-reporting",
        ),
        pytest.param(
            "revise reporting",
            "Normal",
            "Output: Balanced Technical",
            id="revise-reporting",
        ),
    ],
)
def test_reporting_aliases_reopen_output_question_with_editable_style_draft(
    loaded_page: Page,
    command: str,
    style_answer: str,
    expected_summary: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, style_answer)

    confirmed_summary = loaded_page.get_by_test_id("wizard-summary-confirmed")
    expect(confirmed_summary).to_contain_text("Target Type: Internal Range / LAN")
    expect(confirmed_summary).to_contain_text("Goal: Inventory First")
    expect(confirmed_summary).to_contain_text("Scope: 1 cidr ranges")
    expect(confirmed_summary).to_contain_text(expected_summary)
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "10.0.20.0/24"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


def test_output_style_revision_after_safety_preserves_safety_and_lane_context(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Balanced")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )

    _answer_current_question(loaded_page, "change output style")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )

    _answer_current_question(loaded_page, "Executive summary")

    confirmed_summary = loaded_page.get_by_test_id("wizard-summary-confirmed")
    expect(confirmed_summary).to_contain_text("Safety: Balanced")
    expect(confirmed_summary).to_contain_text("Guarded Active")
    expect(confirmed_summary).to_contain_text("Output: Executive Summary")

    coverage_summary = loaded_page.get_by_test_id("wizard-summary-coverage")
    coverage_summary.locator("summary").click()
    expect(coverage_summary).to_contain_text("Standard profile")
    expect(coverage_summary).to_contain_text("Guarded Active")
    expect(coverage_summary).to_contain_text("Executive Summary")

    lane_summary = loaded_page.get_by_test_id("wizard-summary-lane")
    lane_summary.locator("summary").click()
    expect(lane_summary).to_contain_text("passive-network-discovery")
    expect(lane_summary).to_contain_text("Approvals")
    expect(lane_summary).to_contain_text("nmap")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )


def test_change_output_button_from_confirmation_preserves_boundary_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    boundary_note = "Avoid production payment hosts during business hours"

    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, boundary_note)

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    edit_row = loaded_page.get_by_test_id("conversation-edit-row")
    edit_row.locator("summary").click()
    expect(edit_row).to_contain_text("Change Output")
    edit_row.get_by_role("button", name="Change Output").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, "Executive summary")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    confirmed_summary = loaded_page.get_by_test_id("wizard-summary-confirmed")
    expect(confirmed_summary).to_contain_text("Safety: Balanced")
    expect(confirmed_summary).to_contain_text("Output: Executive Summary")

    scope_guardrails = loaded_page.get_by_test_id("wizard-scope-guardrails")
    expect(scope_guardrails).to_contain_text("Executive Summary")
    expect(scope_guardrails).to_contain_text(boundary_note)

    targets_summary = loaded_page.get_by_test_id("wizard-summary-targets")
    targets_summary.locator("summary").click()
    expect(targets_summary).to_contain_text("10.0.20.0/24")
    expect(targets_summary).to_contain_text(boundary_note)

    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the output-revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["preferences"]["output_style"] == "executive-summary"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "notes-only-boundaries"
    assert configuration["exclusions"]["notes"] == boundary_note
    assert configuration["targets"]["cidr_ranges"] == ["10.0.20.0/24"]


def test_change_output_button_mid_intake_returns_to_safety_without_scope_drift(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    edit_row = loaded_page.get_by_test_id("conversation-edit-row")
    edit_row.locator("summary").click()
    expect(edit_row).to_contain_text("Change Output")
    edit_row.get_by_role("button", name="Change Output").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, "Technical detail")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    confirmed_summary = loaded_page.get_by_test_id("wizard-summary-confirmed")
    expect(confirmed_summary).to_contain_text("Target Type: Internal Range / LAN")
    expect(confirmed_summary).to_contain_text("Goal: Inventory First")
    expect(confirmed_summary).to_contain_text("Scope: 1 cidr ranges")
    expect(confirmed_summary).to_contain_text("Output: Technical Detail")
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "10.0.20.0/24"
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the mid-intake output-revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["preferences"]["output_style"] == "technical-detail"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert configuration["targets"]["cidr_ranges"] == ["10.0.20.0/24"]


@pytest.mark.parametrize(
    ("command", "style_answer", "expected_summary"),
    [
        pytest.param(
            "please change output?",
            "Executive summary",
            "Output: Executive Summary",
            id="leading-please-trailing-punctuation",
        ),
        pytest.param(
            "EDIT   OUTPUT!",
            "Technical detail",
            "Output: Technical Detail",
            id="case-whitespace-punctuation",
        ),
    ],
)
def test_output_revision_command_normalization_reopens_output_style_draft(
    loaded_page: Page,
    command: str,
    style_answer: str,
    expected_summary: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "reporting style"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Detailed Per Item"
    )

    _answer_current_question(loaded_page, style_answer)

    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        expected_summary
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )


def test_change_that_reopens_last_answered_topic_and_returns_to_main_path(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change that")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.30.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "10.0.30.0/24"
    )


def test_go_back_reopens_last_answered_access_topic_and_returns_to_safety(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "go back")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Security Lead"
    )


def test_undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "undo")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.40.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(
        "10.0.40.0/24"
    )


def test_previous_alias_reopens_last_answered_access_topic_and_returns_to_safety(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "previous")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Security Lead"
    )


@pytest.mark.parametrize(
    ("revision_command", "updated_role", "updated_secret"),
    [
        pytest.param("please go back?", "Security Lead", "vault://portal/lead", id="polite-go-back"),
        pytest.param("  UNDO!  ", "Security Owner", "vault://portal/owner", id="uppercase-undo"),
        pytest.param(
            "please change that?",
            "Security Reviewer",
            "vault://portal/reviewer",
            id="polite-change-that",
        ),
        pytest.param("  PREVIOUS!  ", "Security Partner", "vault://portal/partner", id="uppercase-previous"),
    ],
)
def test_back_command_normalization_reopens_last_answered_access_topic(
    loaded_page: Page,
    revision_command: str,
    updated_role: str,
    updated_secret: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, revision_command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text(
        "Apply Answer & Return"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        f"analyst@example.com role {updated_role} secret {updated_secret}",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        updated_role
    )


def test_change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    _answer_current_question(loaded_page, "change scope")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.30.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("10.0.30.0/24")


@pytest.mark.parametrize(
    ("revision_command", "updated_scope"),
    [
        pytest.param("please change scope?", "10.0.31.0/24", id="prefix-please-question"),
        pytest.param("change target please.", "10.0.32.0/24", id="suffix-please-period"),
    ],
)
def test_polite_revision_command_wrappers_reopen_scope_with_editable_draft(
    loaded_page: Page,
    revision_command: str,
    updated_scope: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    _answer_current_question(loaded_page, revision_command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, updated_scope)

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(updated_scope)


@pytest.mark.parametrize(
    ("revision_command", "updated_scope"),
    [
        pytest.param("  CHANGE   SCOPE!  ", "10.0.33.0/24", id="uppercase-spaced-scope"),
        pytest.param("edit   targets", "10.0.34.0/24", id="collapsed-space-targets"),
    ],
)
def test_revision_command_case_and_spacing_normalization_reopens_scope_draft(
    loaded_page: Page,
    revision_command: str,
    updated_scope: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    _answer_current_question(loaded_page, revision_command)

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, updated_scope)

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text(updated_scope)


def test_change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    _answer_current_question(loaded_page, "change target")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.50.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("10.0.50.0/24")


def test_revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise target")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.60.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("10.0.60.0/24")


def test_edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit scope")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.70.0/24")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "Conservative")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-scope run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert "10.0.70.0/24" in _target_values_text(run["configuration_json"])


def test_revise_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise scope")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.90.0/24")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "Conservative")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-scope run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert "10.0.90.0/24" in _target_values_text(run["configuration_json"])


def test_edit_target_alias_reopens_scope_with_editable_draft_and_persists_updated_scope(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit target")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.80.0/24")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "Conservative")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-target run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert "10.0.80.0/24" in _target_values_text(run["configuration_json"])


def test_change_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    _answer_current_question(loaded_page, "change targets")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.55.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("10.0.55.0/24")


def test_edit_targets_alias_reopens_scope_with_editable_draft_and_persists_updated_scope(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit targets")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.85.0/24")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "Conservative")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-targets run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert "10.0.85.0/24" in _target_values_text(run["configuration_json"])


def test_revise_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Inventory first, but I want clear information per found item")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise targets")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "exact CIDR range"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("10.0.20.0/24")

    _answer_current_question(loaded_page, "10.0.65.0/24")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    loaded_page.get_by_test_id("wizard-summary-targets").locator("summary").click()
    expect(loaded_page.get_by_test_id("wizard-summary-targets")).to_contain_text("10.0.65.0/24")


def test_change_access_command_reopens_editable_access_details_and_returns_to_safety(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Security Lead"
    )


def test_revise_access_alias_reopens_editable_access_details_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert account["role"] == "Security Lead"
    assert "password" in account["secret_bindings"]


def test_edit_access_alias_reopens_editable_access_details_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit access")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert account["role"] == "Security Lead"
    assert "password" in account["secret_bindings"]


def test_change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change auth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(loaded_page, "Keep it unauthenticated")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Access: Unauthenticated"
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised unauthenticated run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []


def test_revise_auth_alias_can_withdraw_access_and_persist_unauthenticated_run(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise auth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(loaded_page, "Keep it unauthenticated")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Access: Unauthenticated"
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-auth unauthenticated run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []


def test_edit_auth_alias_can_withdraw_access_and_persist_unauthenticated_run(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit auth")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(loaded_page, "Keep it unauthenticated")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Access: Unauthenticated"
    )

    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised unauthenticated run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []


def test_change_credential_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change credential")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the credential-revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_edit_credential_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit credential")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-credential run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_revise_credential_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise credential")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-credential run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_change_credentials_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change credentials")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the credentials-revised run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_edit_credentials_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit credentials")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-credentials run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_revise_credentials_alias_reopens_credential_detail_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise credentials")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "analyst@example.com role Security Analyst secret vault://portal/analyst"
    )

    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Lead secret vault://portal/lead",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-credentials run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    account = run["configuration_json"]["access"]["accounts"][0]
    assert account["role"] == "Security Lead"
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"


def test_change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change token")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/updated-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit token")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/edited-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-token API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise token")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/revised-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_edit_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "edit tokens")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/edited-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-tokens API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_change_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "change tokens")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/changed-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the changed-tokens API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_revise_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our API")
    _answer_current_question(loaded_page, "Adaptive customer-specific testing")
    _answer_current_question(loaded_page, "https://api.example.com/v1")
    _answer_current_question(loaded_page, "I have API tokens or keys")
    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/original-token",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )

    _answer_current_question(loaded_page, "revise tokens")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "role API Analyst api-key vault://api/original-token"
    )

    _answer_current_question(
        loaded_page,
        "role API Analyst api-key vault://api/revised-token",
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-tokens API mission to create a selected run."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    access = run["configuration_json"]["access"]
    account = access["accounts"][0]
    assert "api_key_ref" not in account
    assert account["role"] == "API Analyst"
    assert "api_key" in account["secret_bindings"]
    assert access["secret_storage"]["binding_count"] >= 1
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "api-access"


def test_direct_session_reference_route_and_change_session_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "change session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_direct_session_reference_route_and_change_sessions_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "change sessions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the changed-sessions session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_direct_session_reference_route_and_revise_session_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "revise session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_direct_session_reference_route_and_revise_sessions_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "revise sessions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the revised-sessions session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_direct_session_reference_route_and_edit_sessions_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "edit sessions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited-sessions session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_direct_session_reference_route_and_edit_session_alias_keep_session_access_truth(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have a session reference")
    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Analyst session session-cookie=abc123",
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "edit session")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "access context"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Analyst Session role Security Analyst session session-cookie=abc123"
    )

    _answer_current_question(
        loaded_page,
        "Analyst Session role Security Lead session session-cookie=xyz789",
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    _answer_current_question(loaded_page, "Balanced")
    _answer_current_question(loaded_page, "No extra exclusions")
    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    loaded_page.get_by_test_id("wizard-confirm").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the edited session-access run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    account = configuration["access"]["accounts"][0]
    assert configuration["intake"]["preferences"]["auth_strategy"] == "session-access"
    assert account["role"] == "Security Lead"
    assert "session" in account["secret_bindings"]


def test_change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "change safety")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "edit safety")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "revise safety")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_change_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "change careful")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_edit_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "edit careful")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_revise_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "revise careful")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_edit_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "edit conservative")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_change_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "change conservative")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_revise_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "revise conservative")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_revise_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "revise aggressive")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_change_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "change aggressive")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_edit_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "edit aggressive")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_edit_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "edit thorough")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_change_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "change thorough")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_revise_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "Our customer portal")
    _answer_current_question(loaded_page, "Authenticated review")
    _answer_current_question(loaded_page, "https://portal.example.com")
    _answer_current_question(loaded_page, "I have portal/app accounts")
    _answer_current_question(
        loaded_page,
        "analyst@example.com role Security Analyst secret vault://portal/analyst",
    )
    _answer_current_question(loaded_page, "Balanced")

    _answer_current_question(loaded_page, "revise thorough")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value("Balanced")

    _answer_current_question(loaded_page, "Conservative")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Safety: Conservative"
    )


def test_change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Boundaries").click()

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit boundary")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change boundary")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise boundary")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit boundaries")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change boundaries")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise boundaries")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change exclusions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit exclusions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise exclusions")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change excludes")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit excludes")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise excludes")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change exclude")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit exclude")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise exclude")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change exclusion")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit exclusion")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise exclusion")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change lateral")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit lateral")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise lateral")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_change_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "change avoid")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_edit_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "edit avoid")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_revise_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)

    loaded_page.get_by_test_id("conversation-edit-row").locator("summary").click()
    loaded_page.get_by_role("button", name="Change Safety").click()

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "conservative or more thorough"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Conservative"
    )

    _answer_current_question(loaded_page, "revise avoid")

    expect(loaded_page.get_by_test_id("conversation-path-note")).to_contain_text(
        "Revising Earlier Topic"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "internal edges I must avoid or handle carefully"
    )
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_value(
        "Report adjacent internal ranges only"
    )

    _answer_current_question(loaded_page, "No extra exclusions")

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-summary-confirmed")).to_contain_text(
        "Boundaries: No lateral expansion"
    )


def test_inventory_follow_up_can_launch_service_identification(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("10.0.20.1")

    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("follow-up-service-enumeration-mission")).to_be_visible(timeout=20000)
    loaded_page.get_by_test_id("follow-up-service-enumeration-mission").click()

    expect(loaded_page.locator("#status-feed")).to_contain_text(
        "Run Service Identification started",
        timeout=20000,
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        "passive-network-service-enumeration",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "Service Identification is complete",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("follow-up-complete-summary")).to_contain_text(
        "services were identified",
        timeout=20000,
    )

    loaded_page.get_by_test_id("nav-surface-map").click()
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("10.0.20.1:80/tcp")
    loaded_page.get_by_test_id("surface-asset-card").filter(has_text="10.0.20.1:80/tcp").first.click()
    expect(loaded_page.get_by_test_id("surface-asset-detail-card")).to_contain_text("nginx")

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("follow-up-lineage-card")).to_contain_text(
        "Service Identification from passive-network-discovery"
    )
    expect(loaded_page.get_by_test_id("follow-up-load-source-run")).to_be_visible()

    loaded_page.get_by_test_id("nav-reports").click()
    expect(loaded_page.get_by_test_id("report-follow-up-note")).to_contain_text(
        "Service Identification lineage is attached"
    )
    expect(loaded_page.get_by_test_id("report-follow-up-note")).to_contain_text(
        "passive-network-discovery"
    )

    loaded_page.get_by_test_id("nav-evidence").click()
    expect(loaded_page.get_by_test_id("evidence-run-summary")).to_contain_text(
        "Service Identification evidence posture"
    )
    expect(loaded_page.get_by_test_id("evidence-run-lineage")).to_contain_text(
        "Follow-Up Lineage"
    )
    expect(loaded_page.get_by_test_id("evidence-run-lineage")).to_contain_text(
        "passive-network-discovery"
    )

    loaded_page.get_by_test_id("nav-history").click()
    expect(loaded_page.get_by_test_id("history-run-card").first).to_contain_text(
        "Service Identification from passive-network-discovery"
    )
    expect(loaded_page.get_by_test_id("history-trace-origin").first).to_be_visible()


def test_discovery_report_center_shows_inventory_even_without_findings(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.get_by_test_id("discovery-complete-summary")).to_contain_text(
        "3 hosts and 0 services were mapped"
    )

    _open_analysis_screen(loaded_page, "nav-reports")
    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("report-discovery-note")).to_contain_text(
        "discovered 3 assets",
        timeout=20000,
    )
    expect(loaded_page.locator("#report-metadata")).to_contain_text("Assets 3")
    expect(loaded_page.get_by_test_id("report-actions")).to_contain_text("Generate Markdown Preview")
    loaded_page.locator('[data-report-preview="markdown"]').evaluate("(element) => element.click()")
    expect(loaded_page.get_by_test_id("report-preview")).to_contain_text("## Discovery Summary")
    expect(loaded_page.get_by_test_id("report-preview")).to_contain_text("Hosts Observed: 3")


def test_discovery_evidence_replay_shows_run_level_context_without_findings(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)

    _open_analysis_screen(loaded_page, "nav-evidence")
    expect(loaded_page.get_by_test_id("evidence-run-summary")).to_contain_text(
        "Run evidence posture"
    )
    expect(loaded_page.get_by_test_id("evidence-run-summary")).to_contain_text(
        "3 hosts"
    )
    expect(loaded_page.get_by_test_id("evidence-run-task")).to_contain_text("nmap")
    expect(loaded_page.get_by_test_id("evidence-run-lineage")).to_contain_text(
        "Run Lineage"
    )
    expect(loaded_page.get_by_test_id("evidence-run-lineage")).to_contain_text(
        "Standard Coverage"
    )


def test_surface_map_search_filters_large_inventory_without_losing_detail(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.get_by_test_id("surface-browser-summary")).to_contain_text(
        "3 total asset records"
    )
    host_cards = loaded_page.locator('[data-testid="surface-asset-card"][data-surface-kind="host"]')
    expect(host_cards).to_have_count(3)
    first_host_card = host_cards.first
    expect(first_host_card).to_contain_text("Host Card")
    expect(first_host_card).to_contain_text("Source")
    expect(first_host_card).to_contain_text("Services")
    expect(first_host_card).to_contain_text("Endpoints")
    expect(first_host_card).to_contain_text("10.0.20.")

    loaded_page.get_by_test_id("surface-asset-search").fill("10.0.20.3")
    expect(loaded_page.get_by_test_id("surface-browser-summary")).to_contain_text(
        'for "10.0.20.3"'
    )
    expect(loaded_page.locator('[data-testid="surface-asset-card"]')).to_have_count(1)
    expect(loaded_page.locator('[data-testid="surface-asset-card"][data-surface-kind="host"]')).to_have_count(1)
    expect(loaded_page.get_by_test_id("surface-asset-detail-card")).to_contain_text("10.0.20.3")


def test_explorer_dossier_summary_makes_follow_up_review_actionable(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.get_by_test_id("follow-up-service-enumeration-surface")).to_be_visible(
        timeout=20000
    )
    loaded_page.get_by_test_id("follow-up-service-enumeration-surface").click()
    expect(loaded_page.get_by_test_id("follow-up-complete-summary")).to_contain_text(
        "services were identified",
        timeout=20000,
    )

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text("Dossier Summary")
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text("3 hosts")
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        re.compile(r"\d+ services")
    )
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        "Inspect enriched estate context"
    )
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        "Open Surface Map"
    )


def test_history_comparison_includes_inventory_delta_and_search(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    loaded_page.get_by_test_id("wizard-confirm").click()
    loaded_page.get_by_test_id("mission-dispatch").click()

    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.get_by_test_id("follow-up-service-enumeration-surface")).to_be_visible(
        timeout=20000
    )
    loaded_page.get_by_test_id("follow-up-service-enumeration-surface").click()
    expect(loaded_page.get_by_test_id("follow-up-complete-summary")).to_contain_text(
        "services were identified",
        timeout=20000,
    )

    _open_analysis_screen(loaded_page, "nav-history")
    expect(loaded_page.get_by_test_id("comparison-inventory-delta")).to_contain_text(
        re.compile(r"\+\d+ services")
    )
    expect(loaded_page.get_by_test_id("comparison-summary")).to_contain_text("Inspect Surface")

    loaded_page.get_by_test_id("history-search").fill("service identification")
    expect(loaded_page.get_by_test_id("history-toolbar-summary")).to_contain_text("runs visible")
    expect(loaded_page.locator('[data-testid="history-run-card"]')).to_have_count(1)
    expect(loaded_page.get_by_test_id("history-run-card").first).to_contain_text(
        "Service Identification from passive-network-discovery"
    )


def test_mobile_conversational_wizard_keeps_core_controls_visible(loaded_page: Page) -> None:
    loaded_page.set_viewport_size({"width": 360, "height": 900})
    loaded_page.reload(wait_until="networkidle")

    layout = loaded_page.evaluate(
        """
        () => {
          const workspace = document.querySelector('.workspace');
          const rail = document.querySelector('.rail');
          const wizard = document.querySelector('[data-testid="conversation-question"]');
          const workspaceColumns = getComputedStyle(workspace).gridTemplateColumns.trim();
          return {
            viewportWidth: window.innerWidth,
            workspaceColumns,
            wizardWidth: wizard?.getBoundingClientRect().width || 0,
            railOrder: getComputedStyle(rail).order,
          };
        }
        """
    )

    expect(loaded_page.get_by_test_id("wizard-next")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-next")).to_contain_text("Apply Answer")
    expect(loaded_page.get_by_test_id("conversation-question")).to_be_visible()
    expect(loaded_page.locator("body")).to_have_attribute("data-phase-layout", "focus")
    expect(loaded_page.get_by_test_id("persistent-context-secondary")).to_be_visible()
    assert " " not in layout["workspaceColumns"]
    assert layout["wizardWidth"] >= layout["viewportWidth"] * 0.7
    assert layout["railOrder"] == "2"


def test_mobile_confirmation_state_keeps_summary_readable_and_confirm_visible(loaded_page: Page) -> None:
    loaded_page.set_viewport_size({"width": 360, "height": 900})
    loaded_page.reload(wait_until="networkidle")

    _finish_internal_inventory_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-confirmation-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-confirm")).to_be_visible()
    loaded_page.wait_for_function(
        """
        () => {
          const summary = document.querySelector('[data-testid="wizard-confirmation-summary"]');
          const confirm = document.querySelector('[data-testid="wizard-confirm"]');
          const question = document.querySelector('[data-testid="conversation-question"]');
          const thread = document.querySelector('[data-testid="conversation-thread"]');
          if (!summary || !confirm || !question || !thread) return false;
          const summaryRect = summary.getBoundingClientRect();
          const confirmRect = confirm.getBoundingClientRect();
          const questionRect = question.getBoundingClientRect();
          const threadRect = thread.getBoundingClientRect();
          return (
            threadRect.top >= 0 &&
            threadRect.top < window.innerHeight * 0.2 &&
            questionRect.top < window.innerHeight * 0.65 &&
            summaryRect.top >= 0 &&
            summaryRect.top < window.innerHeight &&
            summaryRect.height <= window.innerHeight * 0.55 &&
            confirmRect.top >= 0 &&
            confirmRect.bottom <= window.innerHeight
          );
        }
        """,
        timeout=2000,
    )

    geometry = loaded_page.evaluate(
        """
        () => {
          const summary = document.querySelector('[data-testid="wizard-confirmation-summary"]');
          const confirm = document.querySelector('[data-testid="wizard-confirm"]');
          const question = document.querySelector('[data-testid="conversation-question"]');
          const thread = document.querySelector('[data-testid="conversation-thread"]');
          const summaryRect = summary.getBoundingClientRect();
          const confirmRect = confirm.getBoundingClientRect();
          const questionRect = question.getBoundingClientRect();
          const threadRect = thread.getBoundingClientRect();
          return {
            viewportWidth: window.innerWidth,
            viewportHeight: window.innerHeight,
            scrollY: window.scrollY,
            summaryTop: summaryRect.top,
            summaryHeight: summaryRect.height,
            confirmTop: confirmRect.top,
            confirmBottom: confirmRect.bottom,
            questionTop: questionRect.top,
            questionWidth: questionRect.width,
            threadTop: threadRect.top,
            threadBottom: threadRect.bottom,
          };
        }
        """
    )

    assert geometry["questionWidth"] >= geometry["viewportWidth"] * 0.7
    assert 0 <= geometry["threadTop"] < geometry["viewportHeight"] * 0.2
    assert geometry["questionTop"] < geometry["viewportHeight"] * 0.65
    assert 0 <= geometry["summaryTop"] < geometry["viewportHeight"]
    assert geometry["summaryHeight"] <= geometry["viewportHeight"] * 0.55
    assert geometry["confirmTop"] >= 0
    assert geometry["confirmBottom"] <= geometry["viewportHeight"]
