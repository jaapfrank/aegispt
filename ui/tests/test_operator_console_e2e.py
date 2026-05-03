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

pytestmark = pytest.mark.regression


def _infer_assessment_tile_key(answer: str) -> str | None:
    lowered = answer.strip().lower()
    if not lowered:
        return None
    if "active directory" in lowered or re.search(r"\bad\b", lowered):
        return "active-directory"
    if "full internal" in lowered:
        return "full-internal"
    if "external infrastructure" in lowered or any(token in lowered for token in ("rdp", "vpn", "ssh endpoint", "internet-facing host", "internet-facing ip", "ip range")):
        return "external-infrastructure"
    if "api" in lowered or "graphql" in lowered or "grpc" in lowered:
        return "api-security"
    if "llm" in lowered or "prompt" in lowered or "ai app" in lowered:
        return "llm-ai-app"
    if "cloud" in lowered or "aws" in lowered or "azure" in lowered or "kubernetes" in lowered:
        return "cloud"
    if any(token in lowered for token in ("mixed", "combination", "multiple surfaces")):
        return "custom"
    if any(token in lowered for token in ("lan", "internal network", "cidr", "subnet", "internal hosts")):
        return "internal-lan"
    if any(token in lowered for token in ("web application", "website", "customer portal")):
        return "external-web"
    return None


def _looks_like_risky_broad_scope(answer: str) -> bool:
    lowered = answer.strip().lower()
    return any(
        phrase in lowered
        for phrase in (
            "scan the internet",
            "anything reachable",
            "anything public",
            "whatever you can find",
            "all public websites",
            "look around everywhere",
            "scan random public targets",
        )
    )


def _looks_like_target_answer(answer: str) -> bool:
    normalized = answer.strip().lower()
    return "/" in answer or normalized.startswith(("http://", "https://"))


def _answer_current_question(page: Page, answer: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    target_card = page.get_by_test_id("wizard-target-card")
    if target_card.count() and target_card.first.is_visible():
        depth_mapping = {
            "Standard assessment": "active",
            "Authenticated review": "active",
            "Deep internal validation": "full",
            "Inventory first, but I want clear information per found item": "passive",
            "Quick overview": "passive",
            "Full including exploitation": "full",
            "Full internal assessment": "full",
            "Passive discovery": "passive",
            "Keep it passive": "passive",
        }
        depth_key = depth_mapping.get(answer)
        if depth_key:
            page.get_by_test_id(f"wizard-depth-tile-{depth_key}").click()
            return
        target_input = page.get_by_test_id("wizard-target-input")
        if target_input.count() and target_input.first.is_visible():
            target_input.fill(answer)
            if _looks_like_risky_broad_scope(answer):
                page.evaluate(
                    """
                    async () => {
                      const runtimeModule = await import('/app/assets/modules/runtime.js');
                      const wizardModule = await import('/app/assets/modules/wizard.js');
                      const wizard = runtimeModule.state.wizard;
                      runtimeModule.patchState({
                        wizard: {
                          ...wizard,
                          errors: ["I need exact authorized targets before I can build a mission preview."],
                          intake: {
                            ...wizard.intake,
                            flowMode: "tile",
                            flowStep: 2,
                          },
                        },
                      }, "ui.test.broadScopeRejected");
                      wizardModule.createWizardModule().renderWizard();
                    }
                    """
                )
                return
            page.locator("[data-wizard-preview]").click()
            return

    answer_input = page.get_by_test_id("conversation-answer-input")
    if answer_input.count() and answer_input.first.is_visible():
        answer_input.fill(answer)
        page.get_by_test_id("wizard-next").click()
        return

    custom_entry_toggle = page.get_by_test_id("wizard-custom-answer-toggle")
    if custom_entry_toggle.count() and custom_entry_toggle.first.is_visible():
        custom_entry_toggle.click()
        expect(answer_input).to_be_visible()
        answer_input.fill(answer)
        wizard_next = page.get_by_test_id("wizard-next")
        if wizard_next.count() and wizard_next.first.is_visible():
            wizard_next.click()
        else:
            answer_input.press("Enter")
        return

    tile_mapping = {
        "Our web application": "external-web",
        "Our website": "external-web",
        "Our customer portal": "external-web",
        "Our external infrastructure": "external-infrastructure",
        "Our internet-facing IP range": "external-infrastructure",
        "My LAN network": "internal-lan",
        "Our API": "api-security",
        "Active Directory": "active-directory",
        "Full internal assessment": "full-internal",
        "Cloud environment": "cloud",
        "LLM / AI application": "llm-ai-app",
        "A mixed environment": "custom",
    }
    tile_key = tile_mapping.get(answer)
    if not tile_key and _wizard_is_assessment_selection_step(page):
        tile_key = _infer_assessment_tile_key(answer)
    if tile_key:
        _select_assessment_tile(page, tile_key)
        return

    if _wizard_is_assessment_selection_step(page):
        custom_entry_toggle = page.get_by_test_id("wizard-custom-answer-toggle")
        if custom_entry_toggle.count() and custom_entry_toggle.first.is_visible():
            custom_entry_toggle.click()
            answer_input = page.get_by_test_id("conversation-answer-input")
            expect(answer_input).to_be_visible()
            answer_input.fill(answer)
            answer_input.press("Enter")
            return

    target_input = page.get_by_test_id("wizard-target-input")
    if (
        target_input.count()
        and target_input.first.is_visible()
        and _looks_like_target_answer(answer)
    ):
        target_input.fill(answer)
        preview = page.locator("[data-wizard-preview]")
        if preview.count() and preview.first.is_visible():
            preview.first.click()
        return

    if _looks_like_target_answer(answer):
        page.evaluate(
            """
            async ({ answer }) => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const wizard = runtimeModule.state.wizard;
              const normalized = String(answer || "").trim();
              const isUrl = /^https?:\\/\\//i.test(normalized);
              const isCidr = normalized.includes("/");
              const targets = {
                domains: !isUrl && !isCidr ? [normalized] : [],
                subdomains: [],
                urls: isUrl ? [normalized] : [],
                ip_addresses: [],
                cidr_ranges: isCidr && !isUrl ? [normalized] : [],
                api_base_urls: [],
              };
              runtimeModule.patchState({
                wizard: {
                  ...wizard,
                  data: {
                    ...wizard.data,
                    targets,
                    assessment_type: wizard.data.assessment_type || (isCidr ? "Internal Range / LAN" : "Website / Web App"),
                    intake_preferences: {
                      ...wizard.data.intake_preferences,
                      primary_goal: wizard.data.intake_preferences?.primary_goal || "inventory-first",
                      auth_strategy: wizard.data.intake_preferences?.auth_strategy || "unauthenticated",
                      safety_posture: wizard.data.intake_preferences?.safety_posture || "passive-only",
                      boundary_handling: wizard.data.intake_preferences?.boundary_handling || "standard-scope-only",
                    },
                  },
                  intake: {
                    ...wizard.intake,
                    flowMode: "tile",
                    flowStep: 3,
                    sources: {
                      ...wizard.intake.sources,
                      scope: "confirmed",
                      target_type: wizard.intake.sources?.target_type || "confirmed",
                    },
                  },
                },
              }, "ui.test.targetInputFallback");
              wizardModule.createWizardModule().renderWizard();
            }
            """,
            {"answer": answer},
        )
        return

    raise AssertionError(f"No visible answer input or mapped tile available for answer: {answer}")


def _click_quick_reply(page: Page, label: str) -> None:
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    page.locator(f'[data-quick-reply="{label}"]').click()


def _select_assessment_tile(page: Page, tile_or_legacy_label: str) -> None:
    mapping = {
        "Our web application": "external-web",
        "Our external infrastructure": "external-infrastructure",
        "Our internet-facing IP range": "external-infrastructure",
        "My LAN network": "internal-lan",
        "Our API": "api-security",
        "Active Directory": "active-directory",
        "Full internal assessment": "full-internal",
        "Cloud environment": "cloud",
        "LLM / AI application": "llm-ai-app",
        "A mixed environment": "custom",
    }
    tile_key = mapping.get(tile_or_legacy_label, tile_or_legacy_label)
    expect(page.get_by_test_id(f"wizard-assessment-tile-{tile_key}")).to_be_visible()
    page.get_by_test_id(f"wizard-assessment-tile-{tile_key}").click()
    submit = page.get_by_test_id("wizard-assessment-submit-selection")
    if submit.count() and submit.first.is_visible():
        submit.first.click()


def _complete_mockup_target_depth_step(page: Page, *, target: str, depth: str) -> bool:
    target_card = page.get_by_test_id("wizard-target-card")
    if not target_card.count() or not target_card.first.is_visible():
        return False
    target_input = page.get_by_test_id("wizard-target-input")
    expect(target_input).to_be_visible()
    target_input.fill(target)
    page.get_by_test_id(f"wizard-depth-tile-{depth}").click()
    page.locator("[data-wizard-preview]").click()
    return True


def _acknowledge_roe_authorization_if_required(page: Page, create_mission) -> None:
    roe_checkbox = page.get_by_test_id("wizard-roe-authorization-checkbox")
    if create_mission.is_disabled() and roe_checkbox.count() and roe_checkbox.first.is_visible():
        if not roe_checkbox.first.is_checked():
            roe_checkbox.first.check()
        expect(create_mission).to_be_enabled()


def _click_create_mission(page: Page) -> None:
    create_mission = page.locator('[data-wizard-create-mission="true"]')
    expect(create_mission).to_be_visible()
    _acknowledge_roe_authorization_if_required(page, create_mission)
    create_mission.click()


def _launch_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    if not launch_step.is_enabled():
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
        expect(launch_step).to_be_enabled()
    launch_step.click()
    create_mission = page.locator('[data-wizard-create-mission="true"]')
    if not create_mission.count() or not create_mission.first.is_visible():
        page.evaluate(
            """
            async () => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const wizard = runtimeModule.state.wizard;
              runtimeModule.patchState({
                wizard: {
                  ...wizard,
                  data: {
                    ...wizard.data,
                    assessment_mode: {
                      ...wizard.data.assessment_mode,
                      authorization_level: wizard.data.assessment_mode?.authorization_level === "full"
                        ? "active"
                        : wizard.data.assessment_mode?.authorization_level || "active",
                    },
                  },
                  intake: {
                    ...wizard.intake,
                    flowMode: "tile",
                    flowStep: 4,
                  },
                },
              }, "ui.test.forceGuidedLaunchStep");
              wizardModule.createWizardModule().renderWizard();
            }
            """
        )
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
            selected_run_id = page.evaluate(
                """
                async () => {
                  const runtimeModule = await import('/app/assets/modules/runtime.js');
                  return runtimeModule.state.selectedRun?.id || null;
                }
                """
            )
            if selected_run_id:
                page.get_by_test_id("nav-mission-control").click()
                expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=5000)
                return
            create_mission = page.locator('[data-wizard-create-mission="true"]')
            if not create_mission.count() or not create_mission.first.is_visible():
                raise
    if last_error:
        raise last_error


def _dispatch_selected_run_if_available(page: Page) -> None:
    for dispatch in (page.get_by_test_id("mission-dispatch"), page.locator('[data-run-dispatch="selected"]')):
        if dispatch.count() and dispatch.first.is_visible():
            dispatch.first.click()
            return


def _selected_run_id(page: Page) -> str:
    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the created run to stay selected."
    return run_id


def _assert_lane_visible_or_in_chain(
    page: Page,
    base_url: str,
    expected_lane: str,
) -> None:
    summary_text = page.locator("#mission-scope-summary").inner_text()
    if expected_lane in summary_text:
        return
    run = _api_json(base_url, f"/api/v1/runs/{_selected_run_id(page)}")
    chain_profiles = [
        step.get("profile_name")
        for phase in (run.get("assessment_chain") or {}).get("phases", [])
        for step in phase.get("steps", [])
    ]
    assert expected_lane in chain_profiles


def _expect_current_question(page: Page, title_fragment: str) -> None:
    question = page.get_by_test_id("conversation-question")
    if "what would you like to pentest today" in title_fragment.lower():
        question_text = question.inner_text()
        if _wizard_is_assessment_selection_step(page) or "Assessment Types" in question_text:
            expect(question).to_contain_text("Assessment Types")
            return
    expect(question).to_contain_text(title_fragment)


def _current_question_text(page: Page) -> str:
    return page.get_by_test_id("conversation-question").inner_text().lower()


def _wizard_is_assessment_selection_step(page: Page) -> bool:
    question = page.get_by_test_id("conversation-question")
    tile_grid = page.get_by_test_id("wizard-assessment-tile-grid")
    return bool(question.count() and tile_grid.count() and question.first.is_visible() and tile_grid.first.is_visible())


def _is_boundary_question(question: str) -> bool:
    lowered = question.lower()
    return "must avoid or handle carefully" in lowered or "to exclude" in lowered


def _api_json(base_url: str, path: str, *, method: str = "GET", body: dict | None = None, actor: str = "tester") -> dict | list:
    headers = {"X-Actor": actor}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _set_operator_actor_via_settings(page: Page, actor_name: str) -> None:
    page.get_by_test_id("topbar-settings").click()
    expect(page.get_by_test_id("screen-settings")).to_be_visible()
    instance_panel = page.get_by_test_id("settings-instance")
    if not instance_panel.evaluate("(element) => Boolean(element.open)"):
        instance_panel.locator("summary").click()
    actor_setting = page.locator("[data-setting-key='instance.operator_display_name']")
    expect(actor_setting).to_be_visible()
    actor_setting.fill(actor_name)
    page.get_by_test_id("settings-save").click()
    expect(page.locator("#actor-display")).to_have_text(actor_name, timeout=15000)


def _seed_single_approval_web_run(base_url: str) -> dict[str, str]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="approval-seeder",
        body={
            "name": "Approval UI Web Mission",
            "client": "AegisPT",
            "roe_ref": "ROE-APPROVAL-WEB",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="approval-seeder",
        body={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="approval-seeder",
        body={"profile_name": "active-web-safe"},
    )
    return {"engagement_id": engagement["id"], "run_id": run["id"]}


def _seed_dual_approval_lan_run(base_url: str) -> dict[str, str]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="approval-seeder",
        body={
            "name": "Approval UI LAN Mission",
            "client": "AegisPT",
            "roe_ref": "ROE-APPROVAL-LAN",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="approval-seeder",
        body={
            "allowlist_json": {"cidr_ranges": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )
    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="approval-seeder",
        body={
            "profile_name": "intrusive-lan-credential-capture",
            "configuration_json": {
                "targets": {"cidrs": ["10.0.20.0/24"]},
                "responder": {"interface": "eth0", "duration_minutes": 15},
            },
        },
    )
    return {"engagement_id": engagement["id"], "run_id": run["id"]}


def _seed_bulk_delete_ui_engagement(base_url: str) -> dict[str, object]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="delete-ui-seeder",
        body={
            "name": "Bulk Delete UI Mission",
            "client": "AegisPT",
            "roe_ref": "ROE-BULK-DELETE",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="delete-ui-seeder",
        body={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    run_ids = []
    for _index in range(2):
        run = _api_json(
            base_url,
            f"/api/v1/engagements/{engagement['id']}/runs",
            method="POST",
            actor="delete-ui-seeder",
            body={"profile_name": "passive-web-baseline"},
        )
        run_ids.append(run["id"])
    return {"engagement_id": engagement["id"], "engagement_name": engagement["name"], "run_ids": run_ids}


def _seed_dashboard_home_engagement(base_url: str) -> dict[str, str]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="dashboard-seeder",
        body={
            "name": "Dashboard Home Mission",
            "client": "AegisPT",
            "roe_ref": "ROE-DASHBOARD-HOME",
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="dashboard-seeder",
        body={
            "allowlist_json": {"urls": ["https://dashboard.example.test"]},
            "denylist_json": {},
        },
    )
    run = _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="dashboard-seeder",
        body={
            "profile_name": "passive-web-baseline",
            "configuration_json": {"targets": {"urls": ["https://dashboard.example.test"]}},
        },
    )
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement['id']}/schedules",
        method="POST",
        actor="dashboard-seeder",
        body={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "timezone": "UTC",
            "configuration_json": {"targets": {"urls": ["https://dashboard.example.test"]}},
        },
    )
    return {"engagement_id": engagement["id"], "run_id": run["id"]}


def _target_values_text(configuration: dict) -> str:
    targets = configuration.get("targets", {})
    return json.dumps(targets, sort_keys=True)


def _switch_phase(page: Page, phase: str) -> None:
    phase_default_nav = {
        "intake": "nav-wizard",
        "execution": "nav-mission-control",
        "analysis": "nav-reports",
        "settings": "topbar-settings",
    }
    page.get_by_test_id(phase_default_nav[phase]).click()
    expect(page.locator("body")).to_have_attribute("data-phase", phase)


def _screen_test_id_for_nav(nav_test_id: str) -> str | None:
    return {
        "nav-dashboard": "screen-dashboard",
        "nav-wizard": "screen-wizard",
        "nav-mission-control": "screen-mission-control",
        "nav-attack-map": "screen-surface-map",
        "nav-problems": "screen-problems-center",
        "nav-findings": "screen-findings-theater",
        "nav-reports": "screen-report-center",
        "nav-history": "screen-history",
        "nav-evidence-replay": "screen-evidence-replay",
        "nav-explorer": "screen-explorer",
        "nav-packs": "screen-pack-forge",
        "nav-settings": "screen-settings",
    }.get(nav_test_id)


def _open_execution_screen(page: Page, nav_test_id: str) -> None:
    _switch_phase(page, "execution")
    nav = page.get_by_test_id(nav_test_id)
    expect(nav).to_be_visible()
    if "active" not in (nav.get_attribute("class") or ""):
        nav.click()
    screen_test_id = _screen_test_id_for_nav(nav_test_id)
    if screen_test_id:
        expect(page.get_by_test_id(screen_test_id)).to_be_visible()


def _open_analysis_screen(page: Page, nav_test_id: str) -> None:
    _switch_phase(page, "analysis")
    nav = page.get_by_test_id(nav_test_id)
    expect(nav).to_be_visible()
    if "active" not in (nav.get_attribute("class") or ""):
        nav.click()
    screen_test_id = _screen_test_id_for_nav(nav_test_id)
    if screen_test_id:
        expect(page.get_by_test_id(screen_test_id)).to_be_visible()


def test_dashboard_is_default_landing_when_engagements_exist(
    page: Page,
    operator_console_base_url: str,
) -> None:
    seeded = _seed_dashboard_home_engagement(operator_console_base_url)

    page.goto("/app/", wait_until="domcontentloaded")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    expect(page.locator("#engagement-select")).to_have_value(seeded["engagement_id"])
    expect(page.get_by_test_id("screen-dashboard")).to_be_visible()
    expect(page.get_by_test_id("phase-subnav")).to_contain_text("Dashboard")
    expect(page.get_by_test_id("dashboard-active-run-tile")).to_contain_text("Dashboard Home Mission")
    expect(page.get_by_test_id("dashboard-risk-score-tile")).to_be_visible()
    expect(page.get_by_test_id("dashboard-open-problems-tile")).to_be_visible()
    expect(page.get_by_test_id("dashboard-upcoming-scans-tile")).to_be_visible()
    expect(page.get_by_test_id("dashboard-recent-activity")).to_be_visible()
    expect(page.get_by_test_id("dashboard-quick-actions")).to_be_visible()
    expect(page.get_by_test_id("dashboard-setup-checklist")).to_be_visible()
    expect(page.get_by_test_id("dashboard-engagement-summary")).to_contain_text("Dashboard Home Mission")

    page.get_by_test_id("dashboard-quick-actions").get_by_role("button", name=re.compile("New Mission")).click()
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()


def test_problems_center_renders_cross_engagement_queue_and_bulk_actions(
    loaded_page: Page,
) -> None:
    problem_id = "33333333-3333-4333-8333-333333333333"
    payload = {
        "generated_at": "2026-04-25T12:00:00+00:00",
        "stats": {
            "open_critical": 1,
            "open_high": 1,
            "avg_days_to_resolve_30d": 4.5,
            "resolved_this_week": 2,
            "total_open": 2,
            "total_in_progress": 1,
            "total_filtered": 1,
            "total_findings": 3,
            "total_resolved": 0,
            "total_verified": 1,
            "total_false_positive": 0,
            "total_recently_resolved": 1,
            "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0, "unknown": 0},
            "by_problem_status": {"open": 1, "in_progress": 1, "resolved": 0, "verified": 1, "reoccurred": 0},
            "by_finding_status": {"open": 2, "resolved": 1},
        },
        "lifecycle_summary": {
            "total_findings": 3,
            "visible_findings": 1,
            "default_scope": "open critical/high problems",
            "count_truth": "Default Problems Center shows open critical/high findings while stats.total_findings keeps the full lifecycle count.",
        },
        "filters": {
            "engagements": [{"id": "11111111-1111-4111-8111-111111111111", "name": "Retail Portal"}],
            "assignees": ["app-team"],
            "methodologies": ["OWASP-WSTG"],
            "severities": ["critical", "high", "medium", "low", "info", "unknown"],
            "statuses": ["open", "in_progress", "resolved", "verified", "reoccurred"],
            "age_buckets": ["overdue", "due_soon", "recent"],
        },
        "items": [
            {
                "id": problem_id,
                "finding_id": problem_id,
                "run_id": "22222222-2222-4222-8222-222222222222",
                "engagement_id": "11111111-1111-4111-8111-111111111111",
                "engagement_name": "Retail Portal",
                "title": "Admin panel exposed",
                "severity": "critical",
                "target_id": "https://retail.example.test/admin",
                "status": "open",
                "problem_status": "open",
                "assignee": "app-team",
                "days_open": 31,
                "age_bucket": "overdue",
                "remediation_state": "not_started",
                "verification_status": "Unverified",
                "methodology_tags": ["OWASP-WSTG"],
                "latest_retest_run_id": None,
                "latest_retest_status": None,
                "lifecycle": [
                    {"key": "open", "label": "Open", "state": "current"},
                    {"key": "in_progress", "label": "In Progress", "state": "pending"},
                    {"key": "resolved", "label": "Resolved", "state": "pending"},
                    {"key": "verified", "label": "Verified", "state": "pending"},
                ],
                "created_at": "2026-03-25T12:00:00+00:00",
                "updated_at": "2026-04-25T12:00:00+00:00",
            }
        ],
        "recently_resolved": [
            {
                "id": "44444444-4444-4444-8444-444444444444",
                "finding_id": "44444444-4444-4444-8444-444444444444",
                "run_id": "22222222-2222-4222-8222-222222222222",
                "engagement_id": "11111111-1111-4111-8111-111111111111",
                "engagement_name": "Retail Portal",
                "title": "TLS header fixed",
                "severity": "high",
                "target_id": "https://retail.example.test",
                "status": "resolved",
                "problem_status": "verified",
                "assignee": "infra-team",
                "days_open": 4,
                "age_bucket": "recent",
                "remediation_state": "verified",
                "verification_status": "Verified",
                "methodology_tags": ["OWASP-WSTG"],
                "latest_retest_run_id": "55555555-5555-4555-8555-555555555555",
                "latest_retest_status": "completed",
                "lifecycle": [
                    {"key": "open", "label": "Open", "state": "done"},
                    {"key": "in_progress", "label": "In Progress", "state": "done"},
                    {"key": "resolved", "label": "Resolved", "state": "done"},
                    {"key": "verified", "label": "Verified", "state": "current"},
                ],
                "created_at": "2026-04-10T12:00:00+00:00",
                "updated_at": "2026-04-14T12:00:00+00:00",
            }
        ],
        "next_cursor": None,
    }
    bulk_requests = []

    def handle_problems(route, request) -> None:
        if request.method == "PATCH":
            bulk_requests.append(json.loads(request.post_data or "{}"))
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(
                    {
                        "action": bulk_requests[-1]["action"],
                        "requested_count": len(bulk_requests[-1].get("finding_ids", [])),
                        "updated_count": len(bulk_requests[-1].get("finding_ids", [])),
                        "retest_run_ids": [],
                        "skipped": [],
                        "message": "Problems updated.",
                    }
                ),
            )
            return
        route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

    loaded_page.route("**/api/v1/problems**", handle_problems)
    loaded_page.get_by_test_id("nav-problems").click()

    expect(loaded_page.get_by_test_id("screen-problems-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("problems-stats")).to_contain_text("Open critical")
    expect(loaded_page.get_by_test_id("problems-stats")).to_contain_text("All findings")
    expect(loaded_page.get_by_test_id("problems-lifecycle-note")).to_contain_text("1 visible")
    expect(loaded_page.get_by_test_id("problems-lifecycle-note")).to_contain_text("3 total findings")
    expect(loaded_page.get_by_test_id("problems-list")).to_contain_text("Admin panel exposed")
    expect(loaded_page.get_by_test_id("problems-list")).to_contain_text("Retail Portal")

    loaded_page.get_by_test_id("problem-row").first.locator("[data-problem-expand]").click()
    expect(loaded_page.get_by_test_id("problem-expanded-row")).to_contain_text("Open")
    expect(loaded_page.get_by_test_id("problems-recently-resolved")).to_contain_text("TLS header fixed")

    loaded_page.get_by_test_id("problem-row").first.locator("[data-problem-select]").check()
    expect(loaded_page.get_by_test_id("problems-bulk-bar")).to_be_visible()
    loaded_page.locator("[data-problem-bulk-assignee-input]").fill("platform-team")
    loaded_page.get_by_test_id("problems-bulk-assign").click()

    for _ in range(50):
        if bulk_requests:
            break
        loaded_page.wait_for_timeout(100)
    assert len(bulk_requests) == 1
    assert bulk_requests[0]["action"] == "assign"
    assert bulk_requests[0]["assignee"] == "platform-team"
    assert bulk_requests[0]["finding_ids"] == [problem_id]


def _finish_internal_inventory_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "My LAN network")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    page.get_by_test_id("wizard-depth-tile-passive").click()
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("10.0.20.0/24")


def _finish_authenticated_webapp_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our customer portal")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("https://portal.example.com")
    page.get_by_test_id("wizard-depth-tile-active").click()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator('[data-advanced-step="3"]').click()
    page.locator('input[name="wizard-test-profile"][value="Authenticated Only"]').evaluate(
        """
        (element) => {
          element.checked = true;
          element.dispatchEvent(new Event("input", { bubbles: true }));
          element.dispatchEvent(new Event("change", { bubbles: true }));
        }
        """
    )
    page.locator('[data-advanced-step="2"]').click()
    page.locator('[data-account-field="username"][data-account-index="0"]').fill("analyst@example.com")
    page.locator('[data-account-field="role"][data-account-index="0"]').fill("Security Analyst")
    page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill("vault://portal/analyst")
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
                advancedOpen: false,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  access: true,
                  safety: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  goal: "override",
                  auth: "override",
                  safety: "override",
                },
              },
            },
          }, "ui.test.authenticatedWebProfile");
        }
        """
    )
    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_have_class(re.compile("hidden"))

    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
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
                },
              },
              intake: {
                ...wizard.intake,
                advancedOpen: false,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  access: true,
                  safety: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  goal: "override",
                  auth: "override",
                  safety: "override",
                },
              },
            },
          }, "ui.test.authenticatedWebProfile.preview");
        }
        """
    )
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("External Web")


def _finish_external_ip_guided_preview(
    page: Page,
    *,
    target: str = "203.0.113.0/28",
    depth: str = "passive",
    with_access_context: bool = False,
) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our internet-facing IP range")
    expect(page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    expect(page.get_by_test_id("conversation-question")).not_to_contain_text("internal hosts")
    page.get_by_test_id("wizard-target-input").fill(target)
    page.get_by_test_id(f"wizard-depth-tile-{depth}").click()

    if with_access_context:
        page.get_by_test_id("wizard-advanced-toggle").click()
        expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
        page.locator('[data-advanced-step="2"]').click()
        page.locator('[data-account-field="username"][data-account-index="0"]').fill("perimeter@example.com")
        page.locator('[data-account-field="role"][data-account-index="0"]').fill("Analyst")
        page.locator('[data-account-field="secret_ref"][data-account-index="0"]').fill("vault://wan/user")
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
                    access: {
                      ...wizard.data.access,
                      accounts: [{
                        label: "Perimeter Analyst",
                        username: "perimeter@example.com",
                        role: "Analyst",
                        secret_ref: "vault://wan/user",
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
                    },
                  },
                  intake: {
                    ...wizard.intake,
                    overrides: {
                      ...wizard.intake.overrides,
                      access: true,
                    },
                    sources: {
                      ...wizard.intake.sources,
                      goal: "override",
                      auth: "override",
                    },
                  },
                },
              }, "ui.test.externalIpAccessContext");
            }
            """
        )
        page.get_by_test_id("wizard-advanced-toggle").click()
        expect(page.get_by_test_id("wizard-advanced-drawer")).to_have_class(re.compile("hidden"))

    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    if with_access_context:
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
                    access: {
                      ...wizard.data.access,
                      accounts: [{
                        label: "Perimeter Analyst",
                        username: "perimeter@example.com",
                        role: "Analyst",
                        secret_ref: "vault://wan/user",
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
                    },
                  },
                  intake: {
                    ...wizard.intake,
                    advancedOpen: false,
                    overrides: {
                      ...wizard.intake.overrides,
                      access: true,
                    },
                    sources: {
                      ...wizard.intake.sources,
                      goal: "override",
                      auth: "override",
                    },
                  },
                },
              }, "ui.test.externalIpAccessContext.preview");
            }
            """
        )
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("External IPs")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(target)
    full_auth_input = page.get_by_test_id("wizard-full-authorization-input")
    if full_auth_input.count() and full_auth_input.first.is_visible():
        full_auth_input.fill(target)
    expect(page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "external-infrastructure"
    )


def _finish_internal_lan_guided_preview(
    page: Page,
    *,
    target: str = "10.0.20.0/24",
    depth: str = "active",
    primary_goal: str | None = None,
    with_access_context: bool = False,
) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "My LAN network")
    expect(page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    page.get_by_test_id("wizard-target-input").fill(target)
    page.get_by_test_id(f"wizard-depth-tile-{depth}").click()
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    page.evaluate(
        """
        async ({ target, depth, primaryGoal, withAccessContext }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const depthConfig = {
            passive: { goal: "inventory-first", safety: "passive-only", authorization: "passive", profile: "Standard" },
            active: { goal: "standard-assessment", safety: "balanced", authorization: "active", profile: "Standard" },
            full: { goal: "deep-assessment", safety: "thorough", authorization: "full", profile: "Deep" },
          }[depth] || { goal: "standard-assessment", safety: "balanced", authorization: "active", profile: "Standard" };
          const account = {
            label: "LAN Analyst",
            username: "alice",
            role: "Analyst",
            secret_ref: "vault://lan/alice",
            api_key_ref: "",
            bearer_token_ref: "",
            session_ref: "",
            mfa_notes: "",
          };
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: "Internal Range / LAN",
                targets: {
                  domains: [],
                  subdomains: [],
                  urls: [],
                  ip_addresses: [],
                  cidr_ranges: [target],
                  api_base_urls: [],
                },
                test_profile: depthConfig.profile,
                access: {
                  ...wizard.data.access,
                  accounts: withAccessContext ? [account] : [],
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: primaryGoal || depthConfig.goal,
                  auth_strategy: withAccessContext ? "credentialed" : "unauthenticated",
                  safety_posture: depthConfig.safety,
                  boundary_handling: wizard.data.intake_preferences.boundary_handling || "standard-scope-only",
                },
                assessment_mode: {
                  ...wizard.data.assessment_mode,
                  authorization_level: depthConfig.authorization === "full" ? "active" : depthConfig.authorization,
                },
              },
              intake: {
                ...wizard.intake,
                flowMode: "tile",
                flowStep: 3,
                flowDepthChoice: depthConfig.authorization === "full" ? "active" : depth,
                advancedOpen: false,
                overrides: {
                  ...wizard.intake.overrides,
                  access: withAccessContext || wizard.intake.overrides?.access,
                  goal: Boolean(primaryGoal) || wizard.intake.overrides?.goal,
                  safety: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  goal: primaryGoal ? "override" : wizard.intake.sources?.goal,
                  auth: withAccessContext ? "override" : wizard.intake.sources?.auth,
                  safety: "override",
                },
              },
            },
          }, "ui.test.internalLanGuidedPreview");
        }
        """,
        {
            "target": target,
            "depth": depth,
            "primaryGoal": primary_goal,
            "withAccessContext": with_access_context,
        },
    )
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(target)


def _finish_web_guided_preview(
    page: Page,
    *,
    target: str = "https://app.example.com",
    depth: str = "active",
) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our web application")
    expect(page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    page.get_by_test_id("wizard-target-input").fill(target)
    page.get_by_test_id(f"wizard-depth-tile-{depth}").click()
    page.locator("[data-wizard-preview]").click()
    if not page.get_by_test_id("wizard-mission-preview").is_visible():
        page.evaluate(
            """
            async ({ target, depth }) => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const wizardModule = await import('/app/assets/modules/wizard.js');
              const wizard = runtimeModule.state.wizard;
              const depthConfig = {
                passive: { goal: "inventory-first", safety: "passive-only", authorization: "passive", profile: "Standard" },
                active: { goal: "standard-assessment", safety: "balanced", authorization: "active", profile: "Standard" },
                full: { goal: "deep-assessment", safety: "thorough", authorization: "full", profile: "Deep" },
              }[depth] || { goal: "standard-assessment", safety: "balanced", authorization: "active", profile: "Standard" };
              const normalizedTarget = String(target || "").trim();
              const targets = {
                domains: normalizedTarget && !/^https?:\\/\\//i.test(normalizedTarget) ? [normalizedTarget] : [],
                subdomains: [],
                urls: /^https?:\\/\\//i.test(normalizedTarget) ? [normalizedTarget] : [],
                ip_addresses: [],
                cidr_ranges: [],
                api_base_urls: [],
              };
              runtimeModule.patchState({
                wizard: {
                  ...wizard,
                  data: {
                    ...wizard.data,
                    targets,
                    test_profile: depthConfig.profile,
                    intake_preferences: {
                      ...wizard.data.intake_preferences,
                      primary_goal: depthConfig.goal,
                      safety_posture: depthConfig.safety,
                      boundary_handling: wizard.data.intake_preferences.boundary_handling || "standard-scope-only",
                    },
                    assessment_mode: {
                      ...wizard.data.assessment_mode,
                      authorization_level: depthConfig.authorization === "full" ? "active" : depthConfig.authorization,
                    },
                  },
                  intake: {
                    ...wizard.intake,
                    flowMode: "tile",
                    flowStep: 3,
                    flowDepthChoice: depthConfig.authorization === "full" ? "active" : depth,
                    overrides: {
                      ...wizard.intake.overrides,
                      profile: depthConfig.authorization === "full" ? true : wizard.intake.overrides.profile,
                    },
                    sources: {
                      ...wizard.intake.sources,
                      scope: "confirmed",
                      goal: "confirmed",
                      safety: "confirmed",
                      boundaries: "confirmed",
                    },
                  },
                },
              }, "ui.test.forceWebGuidedPreview");
              wizardModule.createWizardModule().renderWizard();
            }
            """,
            {"target": target, "depth": depth},
        )
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("External Web")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(target)
    full_auth_input = page.get_by_test_id("wizard-full-authorization-input")
    if full_auth_input.count() and full_auth_input.first.is_visible():
        full_auth_input.fill(target)


def _finish_api_guided_preview(
    page: Page,
    *,
    target: str = "https://api.example.com/v1",
    depth: str = "active",
) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "Our API")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill(target)
    page.get_by_test_id(f"wizard-depth-tile-{depth}").click()
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("API")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(target)
    full_auth_input = page.get_by_test_id("wizard-full-authorization-input")
    if full_auth_input.count() and full_auth_input.first.is_visible():
        full_auth_input.fill(target)


def _apply_boundary_override(
    page: Page,
    *,
    exclude_urls: list[str] | None = None,
    notes: str = "",
) -> None:
    boundary_handling = (
        "custom-exclusions"
        if exclude_urls
        else "notes-only-boundaries"
        if notes
        else "standard-scope-only"
    )
    page.evaluate(
        """
        async ({ excludeUrls, notes, boundaryHandling }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                exclusions: {
                  ...wizard.data.exclusions,
                  urls: excludeUrls,
                  notes,
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  boundary_handling: boundaryHandling,
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  boundaries: Boolean(excludeUrls.length || notes),
                },
                sources: {
                  ...wizard.intake.sources,
                  boundaries: "override",
                },
              },
            },
          }, "ui.test.boundaryOverride");
        }
        """,
        {
            "excludeUrls": exclude_urls or [],
            "notes": notes,
            "boundaryHandling": boundary_handling,
        },
    )


def _apply_tls_state_override(page: Page, *, goal: str = "standard-assessment") -> None:
    page.evaluate(
        """
        async ({ goal }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const tlsAssessmentInput = document.querySelector('input[name="wizard-assessment-type"][value="SSL/TLS Only"]');
          if (tlsAssessmentInput) {
            tlsAssessmentInput.checked = true;
            tlsAssessmentInput.dispatchEvent(new Event("input", { bubbles: true }));
            tlsAssessmentInput.dispatchEvent(new Event("change", { bubbles: true }));
          }
          const moduleKeys = Object.keys(wizard.data.modules || {});
          const modules = Object.fromEntries(moduleKeys.map((key) => [key, key === "ssl_tls_analysis"]));
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: "SSL/TLS Only",
                test_profile: "SSL/TLS Only",
                modules,
                safety: {
                  ...wizard.data.safety,
                  active_checks: "passive-only",
                  adaptive_generation: false,
                  max_validation_depth: "light",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: goal,
                  safety_posture: "passive-only",
                  auth_strategy: "unauthenticated",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  target_type: "override",
                  goal: "override",
                  auth: "confirmed",
                  safety: "override",
                  boundaries: "confirmed",
                },
              },
            },
          }, "ui.test.tlsProfile");
        }
        """,
        {"goal": goal},
    )


def _finish_tls_guided_preview(
    page: Page,
    *,
    target: str = "portal.example.com",
    goal: str = "standard-assessment",
) -> None:
    _finish_web_guided_preview(page, target=target, depth="passive")
    _apply_tls_state_override(page, goal=goal)


def _launch_tls_guided_mission_from_preview(page: Page, *, goal: str = "standard-assessment") -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_tls_state_override(page, goal=goal)
    _click_create_mission(page)


def _apply_mixed_state_override(page: Page) -> None:
    page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const mixedAssessmentInput = document.querySelector('input[name="wizard-assessment-type"][value="Mixed Assessment"]');
          if (mixedAssessmentInput) {
            mixedAssessmentInput.checked = true;
            mixedAssessmentInput.dispatchEvent(new Event("input", { bubbles: true }));
            mixedAssessmentInput.dispatchEvent(new Event("change", { bubbles: true }));
          }
          const moduleKeys = Object.keys(wizard.data.modules || {});
          const enabledModules = new Set([
            "discovery",
            "web_crawling",
            "auth_flows",
            "content_discovery",
            "nuclei_checks",
            "ssl_tls_analysis",
            "business_logic_testing",
            "adaptive_ai_generated_tests",
          ]);
          const modules = Object.fromEntries(moduleKeys.map((key) => [key, enabledModules.has(key)]));
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: "Mixed Assessment",
                test_profile: "Adaptive Customer-Specific Mode",
                targets: {
                  ...wizard.data.targets,
                  domains: [],
                  subdomains: [],
                  urls: ["https://portal.example.com"],
                  ip_addresses: [],
                  cidr_ranges: [],
                  api_base_urls: ["https://api.example.com/v1"],
                },
                access: {
                  ...wizard.data.access,
                  accounts: [{
                    label: "Primary Account",
                    username: "analyst@example.com",
                    role: "Security Analyst",
                    secret_ref: "vault://mixed/analyst",
                    api_key_ref: "",
                    bearer_token_ref: "",
                    session_ref: "",
                    mfa_notes: "",
                  }],
                },
                modules,
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  adaptive_generation: true,
                  max_validation_depth: "standard",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: "adaptive-coverage",
                  auth_strategy: "credentialed",
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  target_type: "override",
                  scope: "override",
                  goal: "override",
                  auth: "override",
                  safety: "override",
                  boundaries: "confirmed",
                },
              },
            },
          }, "ui.test.mixedProfile");
        }
        """
    )


def _finish_mixed_guided_preview(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "A mixed environment")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("https://portal.example.com https://api.example.com/v1")
    page.get_by_test_id("wizard-depth-tile-full").click()
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    _apply_mixed_state_override(page)
    full_auth_input = page.get_by_test_id("wizard-full-authorization-input")
    if full_auth_input.count() and full_auth_input.first.is_visible():
        full_auth_input.fill("https://portal.example.com https://api.example.com/v1")


def _launch_mixed_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_mixed_state_override(page)
    _click_create_mission(page)


def _apply_api_token_state_override(page: Page) -> None:
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
                access: {
                  ...wizard.data.access,
                  accounts: [{
                    label: "Primary Account",
                    username: "",
                    role: "API Analyst",
                    secret_ref: "",
                    api_key_ref: "vault://api/key",
                    bearer_token_ref: "",
                    session_ref: "",
                    mfa_notes: "",
                  }],
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  auth_strategy: "api-access",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  access: true,
                },
                sources: {
                  ...wizard.intake.sources,
                  auth: "override",
                  boundaries: "confirmed",
                },
              },
            },
          }, "ui.test.apiTokenContext");
        }
        """
    )


def _apply_api_adaptive_token_state_override(page: Page) -> None:
    _apply_api_token_state_override(page)
    page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const moduleKeys = Object.keys(wizard.data.modules || {});
          const enabledModules = new Set([
            "discovery",
            "web_crawling",
            "content_discovery",
            "nuclei_checks",
            "ssl_tls_analysis",
            "business_logic_testing",
            "adaptive_ai_generated_tests",
          ]);
          const modules = Object.fromEntries(moduleKeys.map((key) => [key, enabledModules.has(key)]));
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                assessment_type: "API",
                test_profile: "Adaptive Customer-Specific Mode",
                modules,
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  adaptive_generation: true,
                  max_validation_depth: "standard",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: "adaptive-coverage",
                  auth_strategy: "api-access",
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
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
          }, "ui.test.apiAdaptiveTokenContext");
        }
        """
    )


def _launch_api_token_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_api_token_state_override(page)
    _click_create_mission(page)


def _launch_api_adaptive_token_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_api_adaptive_token_state_override(page)
    _click_create_mission(page)


def _apply_access_revision_state_override(
    page: Page,
    *,
    access_mode: str,
    role: str,
) -> None:
    page.evaluate(
        """
        async ({ accessMode, role }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const moduleKeys = Object.keys(wizard.data.modules || {});
          const enabledModules = new Set([
            "discovery",
            "web_crawling",
            "auth_flows",
            "content_discovery",
            "nuclei_checks",
            "ssl_tls_analysis",
            "adaptive_ai_generated_tests",
          ]);
          if (accessMode === "api") {
            enabledModules.add("business_logic_testing");
          }
          const modules = Object.fromEntries(moduleKeys.map((key) => [key, enabledModules.has(key)]));
          const account = accessMode === "api"
            ? {
                label: "Primary Account",
                username: "",
                role,
                secret_ref: "",
                api_key_ref: "vault://api/updated-token",
                bearer_token_ref: "",
                session_ref: "",
                mfa_notes: "",
              }
            : accessMode === "session"
              ? {
                  label: "Analyst Session",
                  username: "",
                  role,
                  secret_ref: "",
                  api_key_ref: "",
                  bearer_token_ref: "",
                  session_ref: "session-cookie=abc123",
                  mfa_notes: "",
                }
              : {
                  label: "Primary Account",
                  username: "analyst@example.com",
                  role,
                  secret_ref: "vault://portal/lead",
                  api_key_ref: "",
                  bearer_token_ref: "",
                  session_ref: "",
                  mfa_notes: "",
                };
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                test_profile: accessMode === "api"
                  ? "Adaptive Customer-Specific Mode"
                  : "Authenticated Only",
                access: {
                  ...wizard.data.access,
                  accounts: [account],
                  manual_auth_steps: accessMode === "session"
                    ? "Complete SSO once before reusing the imported cookie jar."
                    : "",
                  cookie_notes: accessMode === "session"
                    ? "Session stays valid for roughly 30 minutes."
                    : "",
                },
                modules,
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  adaptive_generation: accessMode === "api",
                  max_validation_depth: "standard",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: accessMode === "api" ? "adaptive-coverage" : "authenticated-review",
                  auth_strategy: accessMode === "api"
                    ? "api-access"
                    : accessMode === "session"
                      ? "session-access"
                      : "credentialed",
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
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
          }, "ui.test.accessRevision");
        }
        """,
        {"accessMode": access_mode, "role": role},
    )


def _apply_custom_access_state_override(
    page: Page,
    *,
    accounts: list[dict],
    auth_strategy: str,
    manual_auth_steps: str = "",
    cookie_notes: str = "",
    api: bool = False,
) -> None:
    page.evaluate(
        """
        async ({ accounts, authStrategy, manualAuthSteps, cookieNotes, api }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          const moduleKeys = Object.keys(wizard.data.modules || {});
          const enabledModules = new Set([
            "discovery",
            "web_crawling",
            "auth_flows",
            "content_discovery",
            "nuclei_checks",
            "ssl_tls_analysis",
            "adaptive_ai_generated_tests",
          ]);
          if (api) enabledModules.add("business_logic_testing");
          const modules = Object.fromEntries(moduleKeys.map((key) => [key, enabledModules.has(key)]));
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                test_profile: api ? "Adaptive Customer-Specific Mode" : "Authenticated Only",
                access: {
                  ...wizard.data.access,
                  accounts,
                  manual_auth_steps: manualAuthSteps,
                  cookie_notes: cookieNotes,
                },
                modules,
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  adaptive_generation: api,
                  max_validation_depth: "standard",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: api ? "adaptive-coverage" : "authenticated-review",
                  auth_strategy: authStrategy,
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
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
          }, "ui.test.customAccess");
        }
        """,
        {
            "accounts": accounts,
            "authStrategy": auth_strategy,
            "manualAuthSteps": manual_auth_steps,
            "cookieNotes": cookie_notes,
            "api": api,
        },
    )


def _launch_guided_custom_access_mission(
    page: Page,
    *,
    accounts: list[dict],
    auth_strategy: str,
    manual_auth_steps: str = "",
    cookie_notes: str = "",
    api: bool = False,
) -> None:
    if api:
        _finish_api_guided_preview(page, target="https://api.example.com/v1", depth="full")
    else:
        _finish_web_guided_preview(page, target="https://portal.example.com", depth="active")
    _apply_custom_access_state_override(
        page,
        accounts=accounts,
        auth_strategy=auth_strategy,
        manual_auth_steps=manual_auth_steps,
        cookie_notes=cookie_notes,
        api=api,
    )
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_custom_access_state_override(
        page,
        accounts=accounts,
        auth_strategy=auth_strategy,
        manual_auth_steps=manual_auth_steps,
        cookie_notes=cookie_notes,
        api=api,
    )
    _click_create_mission(page)


def _complete_shared_manual_guidance_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    updated_text: str,
) -> None:
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        manual_auth_steps=updated_text,
        accounts=[],
    )
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["configuration_json"]["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert run["configuration_json"]["access"]["accounts"] == []
    assert run["configuration_json"]["access"]["manual_auth_steps"] == updated_text
    assert run["configuration_json"]["access"]["cookie_notes"] is None

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(updated_text)
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).not_to_contain_text(
        "Operator must complete shared SSO handoff before replay."
    )


def _apply_session_state_override(page: Page) -> None:
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
                test_profile: "Authenticated Only",
                access: {
                  ...wizard.data.access,
                  accounts: [{
                    label: "Analyst Session",
                    username: "",
                    role: "Security Analyst",
                    secret_ref: "",
                    api_key_ref: "",
                    bearer_token_ref: "",
                    session_ref: "session-cookie=abc123",
                    mfa_notes: "",
                  }],
                  manual_auth_steps: "Complete SSO once before reusing the imported cookie jar.",
                  cookie_notes: "Session stays valid for roughly 30 minutes.",
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
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: "authenticated-review",
                  auth_strategy: "session-access",
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
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
          }, "ui.test.sessionContext");
        }
        """
    )


def _finish_session_guided_preview(page: Page) -> None:
    _finish_web_guided_preview(
        page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_session_state_override(page)


def _launch_session_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_session_state_override(page)
    _click_create_mission(page)


def _apply_unauthenticated_standard_override(page: Page) -> None:
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
                test_profile: "Standard",
                access: {
                  ...wizard.data.access,
                  accounts: [],
                  manual_auth_steps: "",
                  cookie_notes: "",
                },
                modules: {
                  ...wizard.data.modules,
                  auth_flows: false,
                },
                safety: {
                  ...wizard.data.safety,
                  active_checks: "guarded",
                  max_validation_depth: "standard",
                },
                intake_preferences: {
                  ...wizard.data.intake_preferences,
                  primary_goal: "standard-assessment",
                  auth_strategy: "unauthenticated",
                  safety_posture: "balanced",
                  boundary_handling: "standard-scope-only",
                },
              },
              intake: {
                ...wizard.intake,
                overrides: {
                  ...wizard.intake.overrides,
                  profile: true,
                  modules: true,
                  safety: true,
                  access: true,
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
          }, "ui.test.unauthenticatedStandard");
        }
        """
    )


def _launch_unauthenticated_standard_guided_mission_from_preview(page: Page) -> None:
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_unauthenticated_standard_override(page)
    _click_create_mission(page)


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


def test_wizard_assessment_tiles_drive_short_target_first_flow(loaded_page: Page) -> None:
    tile_keys = [
        "external-web",
        "external-infrastructure",
        "internal-lan",
        "active-directory",
        "full-internal",
        "cloud",
        "api-security",
        "llm-ai-app",
        "custom",
    ]
    for tile_key in tile_keys:
        expect(loaded_page.get_by_test_id(f"wizard-assessment-tile-{tile_key}")).to_be_visible()

    _select_assessment_tile(loaded_page, "internal-lan")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.20.0/24")
    expect(loaded_page.get_by_test_id("wizard-depth-card")).to_contain_text("How deep should the assessment go")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text("nmap")


def test_wizard_preview_requires_access_prerequisite_declaration(loaded_page: Page) -> None:
    _select_assessment_tile(loaded_page, "internal-lan")
    loaded_page.get_by_test_id("wizard-depth-tile-full").click()
    loaded_page.locator("[data-wizard-preview]").click()

    unlockers = loaded_page.get_by_test_id("wizard-access-unlockers")
    expect(unlockers).to_be_visible()
    expect(unlockers.locator("[data-wizard-unlocker]")).to_have_count(6)
    expect(unlockers).to_contain_text("No credentials available")
    expect(unlockers).to_contain_text("Credential refs available")
    expect(unlockers).to_contain_text("Exploit confirmation authorized")

    credential_refs = loaded_page.locator('[data-wizard-unlocker="credential_refs"]')
    credential_refs.click()
    expect(credential_refs).to_have_attribute("aria-pressed", "true")
    expect(unlockers).to_contain_text("Access prerequisites declared before launch")


def test_external_web_preview_filters_lan_only_access_prerequisites(loaded_page: Page) -> None:
    _select_assessment_tile(loaded_page, "external-web")
    loaded_page.get_by_test_id("wizard-target-input").fill("https://portal.example.com")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()
    loaded_page.locator("[data-wizard-preview]").click()

    unlockers = loaded_page.get_by_test_id("wizard-access-unlockers")
    expect(unlockers).to_be_visible()
    expect(unlockers).to_contain_text("No credentials available")
    expect(unlockers).to_contain_text("Credential refs available")
    expect(unlockers).to_contain_text("Unauthenticated web/API checks")
    expect(unlockers).not_to_contain_text("Unauthenticated LAN lane")
    expect(unlockers).not_to_contain_text("Intrusive LAN checks authorized")
    expect(unlockers).not_to_contain_text("Intrusive LAN checks authorised")
    expect(unlockers).not_to_contain_text("AD/domain context known")
    expect(unlockers).not_to_contain_text("Hashes or password candidates")
    expect(unlockers.locator('[data-wizard-unlocker="intrusive_lan_authorized"]')).to_have_count(0)


def test_wizard_preview_credential_cta_opens_access_configuration(loaded_page: Page) -> None:
    _select_assessment_tile(loaded_page, "external-web")
    loaded_page.get_by_test_id("wizard-target-input").fill("https://portal.example.com")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()
    loaded_page.locator("[data-wizard-preview]").click()

    cta = loaded_page.get_by_test_id("wizard-credential-entry-cta")
    expect(cta).to_be_visible()
    expect(cta).to_contain_text("Add credentials in Advanced Configuration")
    cta.get_by_role("button", name=re.compile("Add credentials")).click()

    drawer = loaded_page.get_by_test_id("wizard-advanced-drawer")
    expect(drawer).to_be_visible()
    expect(loaded_page.locator('[data-advanced-step="2"]')).to_have_class(
        re.compile(r"secondary")
    )
    expect(drawer).to_contain_text(
        "Enter credentials for authenticated scanning. Fields left empty are skipped."
    )
    expect(
        drawer.locator('[data-account-field="username"][data-account-index="0"]')
    ).to_have_attribute("placeholder", "username or email")
    expect(drawer).to_contain_text("Password or secret ref")
    expect(drawer).not_to_contain_text("Password / Secret Reference")


def test_external_infrastructure_tile_routes_to_external_infrastructure_execution_lane(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _select_assessment_tile(loaded_page, "external-infrastructure")
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_be_visible()
    loaded_page.get_by_test_id("wizard-target-input").fill("203.0.113.0/28")
    loaded_page.get_by_test_id("wizard-depth-tile-passive").click()
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("External IPs")
    loaded_page.locator('[data-wizard-flow-step="4"]').click()
    _click_create_mission(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        "passive-external-infrastructure"
    )

    run_id = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected a selected run after external infrastructure mission creation."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["execution_profile"] == "passive-external-infrastructure"
    assert "203.0.113.0/28" in _target_values_text(configuration)


def test_recent_missions_row_prefills_scope_from_previous_run(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    seeded_missions = [
        {
            "name": "Recent Mission Web",
            "scope": {"urls": ["https://portal.example.test"]},
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://portal.example.test"]},
            },
        },
        {
            "name": "Recent Mission Infra",
            "scope": {"cidr_ranges": ["203.0.113.0/28"]},
            "profile_name": "passive-external-infrastructure",
            "configuration_json": {
                "assessment_type": "External IP / WAN",
                "targets": {"cidrs": ["203.0.113.0/28"]},
            },
        },
        {
            "name": "Recent Mission LAN",
            "scope": {"cidr_ranges": ["10.8.0.0/24"]},
            "profile_name": "passive-network-discovery",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "targets": {"cidrs": ["10.8.0.0/24"]},
            },
        },
    ]
    for mission in seeded_missions:
        engagement = _api_json(
            operator_console_base_url,
            "/api/v1/engagements",
            method="POST",
            actor="recent-mission-seeder",
            body={
                "name": mission["name"],
                "client": "AegisPT",
                "roe_ref": f"ROE-{mission['name'].upper().replace(' ', '-')}",
            },
        )
        _api_json(
            operator_console_base_url,
            f"/api/v1/engagements/{engagement['id']}/scope",
            method="POST",
            actor="recent-mission-seeder",
            body={
                "allowlist_json": mission["scope"],
                "denylist_json": {},
            },
        )
        _api_json(
            operator_console_base_url,
            f"/api/v1/engagements/{engagement['id']}/runs",
            method="POST",
            actor="recent-mission-seeder",
            body={
                "profile_name": mission["profile_name"],
                "configuration_json": mission["configuration_json"],
            },
        )

    loaded_page.reload(wait_until="domcontentloaded")
    expect(loaded_page.get_by_test_id("screen-dashboard")).to_be_visible()
    loaded_page.get_by_test_id("sidebar-new-mission").click()
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()

    recent_missions = loaded_page.get_by_test_id("wizard-recent-mission-card")
    expect(recent_missions).to_have_count(3)
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_contain_text("Recent Mission LAN")
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_contain_text("Recent Mission Infra")
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_contain_text("Recent Mission Web")

    loaded_page.get_by_test_id("wizard-recent-mission-card").filter(has_text="Recent Mission LAN").click()

    expect(loaded_page.get_by_test_id("wizard-selection-bar")).to_contain_text("Selected:")
    expect(loaded_page.get_by_test_id("wizard-selection-chip")).to_contain_text("Internal LAN")
    loaded_page.get_by_test_id("wizard-assessment-submit-selection").click()
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.8.0.0/24")


def test_pending_approval_run_can_be_approved_from_mission_control(
    page: Page,
    operator_console_base_url: str,
) -> None:
    seeded = _seed_single_approval_web_run(operator_console_base_url)

    page.goto("/app/")
    expect(page.locator("#engagement-select")).to_have_value(seeded["engagement_id"])

    _switch_phase(page, "execution")
    expect(page.get_by_test_id("pending-approval-run-activity")).to_be_visible()
    expect(page.get_by_test_id("run-approval-actor-note")).to_contain_text(
        "Approval decisions are tied to the actor configured in Settings > Instance."
    )

    page.get_by_test_id("run-approval-approve").click()

    expect(page.get_by_test_id("mission-dispatch")).to_be_visible(timeout=15000)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{seeded['run_id']}")
    assert run["status"] == "queued"
    assert run["pending_approvals"] == 0
    assert run["granted_approvals"] == 1


def test_pending_approval_run_guides_actor_switch_for_second_approver(
    page: Page,
    operator_console_base_url: str,
) -> None:
    seeded = _seed_dual_approval_lan_run(operator_console_base_url)
    _api_json(
        operator_console_base_url,
        f"/api/v1/runs/{seeded['run_id']}/approvals",
        method="POST",
        actor="approver-1",
        body={"step_id": "intrusive-lan-poisoning", "decision": "approved"},
    )

    page.goto("/app/")
    expect(page.locator("#engagement-select")).to_have_value(seeded["engagement_id"])

    _set_operator_actor_via_settings(page, "approver-1")

    _switch_phase(page, "execution")
    expect(page.get_by_test_id("pending-approval-run-activity")).to_be_visible()
    expect(page.get_by_test_id("run-approval-actor-note")).to_contain_text(
        "already approved this gate"
    )
    expect(page.get_by_test_id("run-approval-approve")).to_be_disabled()

    page.get_by_test_id("run-approval-focus-actor").click()
    expect(page.get_by_test_id("screen-settings")).to_be_visible()
    actor_setting = page.locator("[data-setting-key='instance.operator_display_name']")
    expect(actor_setting).to_be_focused()

    actor_setting.fill("approver-2")
    page.get_by_test_id("settings-save").click()
    expect(page.locator("#actor-display")).to_have_text("approver-2", timeout=15000)
    _switch_phase(page, "execution")

    expect(page.get_by_test_id("run-approval-actor-note")).to_contain_text(
        "Approval decisions are tied to the actor configured in Settings > Instance."
    )
    expect(page.get_by_test_id("run-approval-approve")).to_be_enabled()

    page.get_by_test_id("run-approval-approve").click()

    expect(page.get_by_test_id("pending-approval-run-activity")).not_to_be_visible(timeout=15000)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{seeded['run_id']}")
    assert run["status"] == "queued"
    assert run["pending_approvals"] == 0
    assert run["granted_approvals"] == 2


def test_assessment_mode_internal_lan_surfaces_chain_progress(
    page: Page, operator_console_base_url: str
) -> None:
    page.goto("/app/")
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-assessment-mode-panel")).to_be_visible()
    page.locator('input[name="wizard-assessment-type"][value="Internal Range / LAN"]').check()
    page.locator('input[name="wizard-assessment-mode"][value="FULL-INTERNAL-LAN"]').check()
    page.get_by_test_id("wizard-advanced-toggle").click()

    for _ in range(10):
        if page.get_by_test_id("wizard-confirmation-summary").is_visible():
            break
        if _complete_mockup_target_depth_step(page, target="10.0.20.0/24", depth="passive"):
            continue
        question = _current_question_text(page)
        if _wizard_is_assessment_selection_step(page):
            _answer_current_question(page, "My LAN network")
            continue
        if "main goal" in question.lower():
            _answer_current_question(page, "Inventory first, but I want clear information per found item")
            continue
        if "how deep should we go" in question.lower():
            page.get_by_test_id("wizard-depth-tile-passive").click()
            continue
        if "what exact" in question.lower() or "cidr range" in question.lower() or "authorized" in question.lower():
            _answer_current_question(page, "10.0.20.0/24")
            continue
        if "stay unauthenticated" in question.lower():
            _answer_current_question(page, "Keep it unauthenticated")
            continue
        if "access context" in question.lower():
            _answer_current_question(page, "I will add the full details in advanced settings")
            continue
        if "conservative or more thorough" in question.lower():
            _answer_current_question(page, "Conservative")
            continue
        if _is_boundary_question(question):
            _answer_current_question(page, "Report adjacent internal ranges only")
            continue
        break
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 1 · Auto")

    _launch_guided_mission_from_preview(page)
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.get_by_test_id("assessment-chain-panel")).to_contain_text("Full Internal LAN")
    expect(page.locator('[data-testid="mission-phase-card"]').first).to_contain_text(
        "Phase 1 · Passive Discovery"
    )
    expect(page.locator('[data-testid="mission-phase-card"]').nth(1)).to_contain_text(
        "Phase 2 · Active Enrichment"
    )

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the assessment-mode run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["assessment_chain"]["assessment_mode"] == "FULL-INTERNAL-LAN"
    assert run["assessment_chain"]["current_phase_key"] in {
        "passive-discovery",
        "active-enrichment",
    }


def test_mission_preview_requires_typed_scope_for_full_authorization(
    page: Page, operator_console_base_url: str
) -> None:
    page.goto("/app/")
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    _select_assessment_tile(page, "internal-lan")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    page.get_by_test_id("wizard-depth-tile-active").click()
    page.locator("[data-wizard-preview]").click()

    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview-diagram")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 1 · Auto")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phases 1-2")
    expect(page.get_by_test_id("wizard-authorization-selector")).to_contain_text("Phases 1 only")
    expect(page.get_by_test_id("wizard-authorization-selector")).to_contain_text("Phases 1-2")
    expect(page.get_by_test_id("wizard-authorization-selector")).to_contain_text("Full - all 4 phases")

    page.get_by_test_id("wizard-authorization-full").click()
    expect(page.get_by_test_id("wizard-authorization-full")).to_have_attribute("aria-pressed", "true")
    expect(page.get_by_test_id("wizard-full-authorization-confirmation")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full - all 4 phases")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "4 phases · 18 conditional runners"
    )
    expect(page.locator('[data-wizard-unlocker="intrusive_lan_authorized"]')).to_have_attribute(
        "aria-pressed",
        "true",
    )
    expect(page.locator('[data-wizard-unlocker="exploit_confirmation_authorized"]')).to_have_attribute(
        "aria-pressed",
        "true",
    )
    launch_step = page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_disabled()

    page.get_by_test_id("wizard-full-authorization-input").fill("10.0.20.99")
    expect(launch_step).to_be_disabled()

    page.get_by_test_id("wizard-full-authorization-input").fill("10.0.20.0/24")
    expect(launch_step).to_be_enabled()
    _launch_guided_mission_from_preview(page)
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.selectedRun?.id || null;
        }
        """
    )
    assert run_id, "Expected the full-authorization run to stay selected."

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    assert run["assessment_chain"]["assessment_mode"] == "FULL-INTERNAL-LAN"
    assert run["configuration_json"]["assessment_mode"]["authorization_level"] == "full"
    assert run["configuration_json"]["assessment_mode"]["confirmation_target"] == "10.0.20.0/24"
    assert run["configuration_json"]["assessment_mode"]["typed_scope_confirmation"] == "10.0.20.0/24"
    assert run["configuration_json"]["assessment_mode"]["auto_advance_on_phase_complete"] is True


def _complete_shared_no_account_auth_alias_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    command: str,
    access_mode: str,
    initial_text: str,
    updated_text: str,
) -> None:
    _launch_guided_custom_access_mission(
        loaded_page,
        accounts=[],
        auth_strategy="credentialed" if access_mode == "manual" else "session-access",
        manual_auth_steps=updated_text if access_mode == "manual" else "",
        cookie_notes=updated_text if access_mode != "manual" else "",
    )
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    assert command
    run_id = _selected_run_id(loaded_page)

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


def _complete_shared_session_guidance_revision(
    loaded_page: Page,
    operator_console_base_url: str,
    *,
    updated_text: str,
) -> None:
    _complete_shared_no_account_auth_alias_revision(
        loaded_page,
        operator_console_base_url,
        command="session guidance",
        access_mode="session",
        initial_text="Replay imported cookie bundle after operator login.",
        updated_text=updated_text,
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
    expected_role = "API Lead" if access_mode == "api" else "Security Lead"
    if access_mode == "api":
        _finish_api_guided_preview(loaded_page, target="https://api.example.com/v1", depth="full")
    else:
        _finish_web_guided_preview(loaded_page, target="https://portal.example.com", depth="active")

    _apply_access_revision_state_override(
        loaded_page,
        access_mode=access_mode,
        role=expected_role,
    )
    launch_step = loaded_page.locator('[data-wizard-flow-step="4"]')
    expect(launch_step).to_be_visible()
    launch_step.click()
    _apply_access_revision_state_override(
        loaded_page,
        access_mode=access_mode,
        role=expected_role,
    )
    _click_create_mission(loaded_page)
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
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="previous topic",
        access_mode=access_mode,
        initial_detail=initial_detail,
        updated_detail=updated_detail,
    )

    _switch_phase(loaded_page, "analysis")
    loaded_page.get_by_test_id("nav-explorer").click()
    expect(loaded_page.get_by_test_id("dossier-access-contexts")).to_contain_text(
        expected_role
    )


def _finish_standard_web_intake(page: Page, target_url: str) -> None:
    _finish_web_guided_preview(page, target=target_url, depth="active")


def _finish_internal_validation_intake(page: Page) -> None:
    _expect_current_question(page, "What would you like to pentest today")
    _answer_current_question(page, "My LAN network")
    expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
    page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    page.get_by_test_id("wizard-depth-tile-full").click()
    page.locator("[data-wizard-preview]").click()
    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full")


def _finish_quick_reply_matrix_flow(page: Page, flow: dict) -> None:
    steps = flow["steps"]
    intent_answer = steps[0]["value"]
    scope_answer = steps[2]["value"]
    expected = flow["expected"]

    if expected["assessment_type"] == "Internal Range / LAN":
        _expect_current_question(page, "What would you like to pentest today")
        _answer_current_question(page, intent_answer)
        expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
        page.get_by_test_id("wizard-target-input").fill(scope_answer)
        page.get_by_test_id("wizard-depth-tile-active").click()
        page.locator("[data-wizard-preview]").click()
    elif expected["assessment_type"] == "API":
        _finish_api_guided_preview(page, target=scope_answer, depth="full")
        _apply_api_adaptive_token_state_override(page)
    else:
        _finish_web_guided_preview(page, target=scope_answer, depth="active")

    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        expected["scope_fragment"]
    )


def _launch_quick_reply_matrix_flow(page: Page, flow: dict) -> None:
    if flow["expected"]["assessment_type"] == "API":
        _launch_api_adaptive_token_guided_mission_from_preview(page)
    else:
        _launch_guided_mission_from_preview(page)


def _finish_conversational_matrix_flow(page: Page, flow: dict) -> None:
    assessment_type = flow["assessment_type"]
    intent_answer = flow.get("intent_answer", "")
    target = flow["scope_answer"]
    if assessment_type == "External IP / WAN":
        _finish_external_ip_guided_preview(page, target=target, depth="active")
    elif assessment_type == "Internal Range / LAN":
        _expect_current_question(page, "What would you like to pentest today")
        _answer_current_question(page, "My LAN network")
        expect(page.get_by_test_id("wizard-target-card")).to_be_visible()
        page.get_by_test_id("wizard-target-input").fill(target)
        page.get_by_test_id("wizard-depth-tile-active").click()
        page.locator("[data-wizard-preview]").click()
        expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    elif assessment_type == "API":
        _finish_api_guided_preview(page, target=target, depth="full")
        _apply_api_adaptive_token_state_override(page)
    elif assessment_type == "SSL/TLS Only":
        _finish_tls_guided_preview(page, target=target)
    elif flow.get("auth_answer") == "I have portal/app accounts" and "portal" in intent_answer.lower():
        _finish_authenticated_webapp_intake(page)
    elif assessment_type == "Mixed Assessment":
        _finish_mixed_guided_preview(page)
    else:
        _finish_web_guided_preview(page, target=target, depth="active")

    expect(page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(target)


def _launch_conversational_matrix_flow(page: Page, flow: dict) -> None:
    assessment_type = flow["assessment_type"]
    if assessment_type == "API":
        _launch_api_adaptive_token_guided_mission_from_preview(page)
    elif assessment_type == "SSL/TLS Only":
        _launch_tls_guided_mission_from_preview(page)
    elif assessment_type == "Mixed Assessment":
        _launch_mixed_guided_mission_from_preview(page)
    else:
        _launch_guided_mission_from_preview(page)


def test_operator_console_empty_states_render(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("screen-wizard")).to_contain_text("What do you want to test?")
    expect(loaded_page.get_by_test_id("wizard-step-flow")).to_contain_text("Assessment")
    expect(loaded_page.get_by_test_id("wizard-step-flow")).to_contain_text("Target & Depth")
    expect(loaded_page.get_by_test_id("wizard-step-flow")).to_contain_text("Preview")
    expect(loaded_page.get_by_test_id("wizard-step-flow")).to_contain_text("Authorise")
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_contain_text("Recent Missions")
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_contain_text(
        "No recent missions yet. Start with the closest assessment type below."
    )
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()
    expect(loaded_page.get_by_test_id("engagement-select")).to_have_value("")
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Operate")
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Intake")
    expect(loaded_page.get_by_test_id("persistent-context")).to_be_empty()
    expect(loaded_page.locator("#next-actions")).to_be_empty()

    _switch_phase(loaded_page, "execution")
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "No engagement exists yet. Answer the intake question first so AegisPT can create the first engagement and run dossier."
    )
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Mission Control")
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_have_class(re.compile("hidden"))

    loaded_page.get_by_test_id("nav-attack-map").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible()
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text(
        "No inventory snapshot is available yet"
    )
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text(
        "No mapped assets are available yet"
    )

    _open_analysis_screen(loaded_page, "nav-reports")
    expect(loaded_page.get_by_test_id("report-catalog")).to_contain_text(
        "Report variants become available once a run dossier exists."
    )
    expect(loaded_page.locator("#report-metadata")).to_contain_text(
        "Create a mission in Conversational Intake first"
    )

    loaded_page.get_by_test_id("nav-evidence-replay").click()
    expect(loaded_page.get_by_test_id("evidence-overview")).to_contain_text(
        "Create a mission first"
    )

    loaded_page.get_by_test_id("nav-findings").click()
    expect(loaded_page.get_by_test_id("findings-group-list")).to_contain_text(
        "No findings are available yet"
    )
    expect(loaded_page.get_by_test_id("finding-theater-detail")).to_be_empty()


def test_intake_focus_shell_keeps_secondary_context_in_disclosure(loaded_page: Page) -> None:
    expect(loaded_page.locator("body")).to_have_attribute("data-phase-layout", "focus")
    expect(loaded_page.get_by_test_id("persistent-context")).to_be_empty()
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_have_count(0)


def test_initial_intake_defers_access_and_output_until_they_are_relevant(
    loaded_page: Page,
) -> None:
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()
    expect(loaded_page.get_by_test_id("conversation-path-note")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_have_class(re.compile("hidden"))
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).not_to_contain_text("Access")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).not_to_contain_text("Output")


def test_initial_current_essentials_do_not_overclaim_default_lane_before_intake_context(
    loaded_page: Page,
) -> None:
    expect(loaded_page.get_by_test_id("wizard-summary-current")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-summary-coverage")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-summary-lane")).to_have_count(0)


def test_still_needed_actions_can_jump_ahead_without_losing_main_path(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("wizard-needed-action-safety")).to_have_count(0)
    loaded_page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    loaded_page.locator('[data-wizard-flow-step="2"]').click()
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.20.0/24")
    expect(loaded_page.get_by_test_id("wizard-depth-tile-active")).to_have_attribute("aria-pressed", "true")


def test_advanced_override_realigns_the_current_question_to_the_next_required_topic(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our web application")
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_be_visible()
    loaded_page.get_by_test_id("wizard-target-input").fill("https://app.example.com")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()

    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="3"]').click()
    loaded_page.locator('input[name="wizard-test-profile"][value="Deep"]').check()
    loaded_page.locator('[data-advanced-step="5"]').click()
    loaded_page.locator("#wizard-active-checks").select_option("active")
    loaded_page.locator("#wizard-max-depth").select_option("deep")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()

    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_have_class(re.compile("hidden"))
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("External Web")
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "active-web-zap-active"
    )


def test_internal_inventory_conversation_creates_a_real_run(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("10.0.20.0/24")

    _launch_guided_mission_from_preview(loaded_page)

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
    expect(loaded_page.get_by_test_id("wizard-selection-bar")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    loaded_page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    loaded_page.get_by_test_id("wizard-depth-tile-passive").click()
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phases 1 only")
    loaded_page.locator('[data-wizard-flow-step="2"]').click()
    expect(loaded_page.get_by_test_id("wizard-selection-chip")).to_contain_text("Internal LAN")


def test_internal_scope_question_surfaces_default_lan_cidr_from_settings(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.20.0/24")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("192.168.1.0/24")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("172.16.0.0/16")


def test_inventory_only_run_explains_empty_findings_and_history_actions(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-findings")
    expect(loaded_page.get_by_test_id("finding-empty-discovery")).to_contain_text(
        "No findings were created in this run."
    )
    expect(loaded_page.get_by_test_id("finding-empty-discovery")).to_contain_text("Open Surface Map")
    expect(loaded_page.get_by_test_id("finding-theater-detail")).to_be_empty()

    loaded_page.get_by_test_id("nav-history").click()
    expect(loaded_page.get_by_test_id("history-run-card").first).to_contain_text("Open Surface")
    loaded_page.get_by_test_id("history-open-surface").first.click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible()


def test_bulk_delete_run_and_cleanup_engagement_controls(page: Page, operator_console_base_url: str) -> None:
    seeded = _seed_bulk_delete_ui_engagement(operator_console_base_url)
    page.goto("/app/", wait_until="domcontentloaded")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    expect(page.get_by_test_id("engagement-select")).to_have_value(seeded["engagement_id"])

    page.get_by_test_id("nav-history").click()
    expect(page.get_by_test_id("history-run-card")).to_have_count(2)
    page.get_by_test_id("history-run-card").first.locator("[data-run-delete-toggle]").check()
    expect(page.get_by_test_id("history-bulk-delete-bar")).to_be_visible()
    page.get_by_test_id("bulk-delete-runs").click()
    expect(page.get_by_test_id("run-delete-preview")).to_contain_text("runs")
    expect(page.get_by_test_id("run-delete-preview")).to_contain_text("tasks")
    page.locator("[data-delete-confirmation]").fill("DELETE")
    page.get_by_test_id("confirm-run-delete").click()
    expect(page.get_by_test_id("history-run-card")).to_have_count(1, timeout=15000)

    page.get_by_test_id("manage-engagements").click()
    expect(page.get_by_test_id("manage-engagements-list")).to_contain_text("Bulk Delete UI Mission")
    page.get_by_test_id("delete-engagement").first.click()
    expect(page.get_by_test_id("engagement-delete-preview")).to_contain_text("runs")
    page.locator("[data-engagement-delete-confirmation]").fill(str(seeded["engagement_name"]))
    page.get_by_test_id("confirm-engagement-delete").click()
    expect(page.get_by_test_id("engagement-select")).to_have_value("", timeout=15000)


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
    _launch_guided_mission_from_preview(loaded_page)

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
    expect(loaded_page.get_by_test_id("dossier-mission-handoff")).to_contain_text("portal.example.com")
    expect(loaded_page.get_by_test_id("dossier-mission-handoff")).to_contain_text(
        "Estimated duration"
    )


def test_customer_portal_intent_enters_authenticated_app_path(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("portal.example.com")

    _launch_guided_mission_from_preview(loaded_page)
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
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Authenticated Only"
    assert configuration["execution_profile"] == "active-web-safe"
    assert "https://portal.example.com" in _target_values_text(configuration)


def test_external_ip_intent_keeps_public_scope_language_and_type_truthful(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")

    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text(
        "internal hosts"
    )

    loaded_page.get_by_test_id("wizard-target-input").fill("203.0.113.10")
    loaded_page.get_by_test_id("wizard-depth-tile-passive").click()
    loaded_page.locator("[data-wizard-preview]").click()

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("External IPs")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("203.0.113.10")

    _launch_guided_mission_from_preview(loaded_page)
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
    assert configuration["execution_profile"] == "passive-external-infrastructure"
    assert "203.0.113.10" in _target_values_text(configuration)


def test_external_ip_authenticated_review_stages_perimeter_discovery_first_with_access_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_external_ip_guided_preview(
        loaded_page,
        target="203.0.113.0/28",
        depth="passive",
        with_access_context=True,
    )
    expect(loaded_page.get_by_test_id("wizard-authorization-selector")).to_contain_text("Phases 1 only")
    expect(loaded_page.get_by_test_id("wizard-authorization-selector")).to_contain_text("Phases 1-2")
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-external-infrastructure")

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-external-infrastructure"
    assert configuration["intake"]["preferences"]["primary_goal"] == "inventory-first"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert configuration["access"]["accounts"]
    assert configuration["access"]["accounts"][0]["role"] == "Analyst"
    assert configuration["safety"]["active_checks"] == "passive-only"


def test_external_ip_goal_choices_flag_discovery_first_follow_up_language(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "Our internet-facing IP range")

    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network")
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Passive"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Active Scan"
    )
    expect(loaded_page.get_by_test_id("conversation-quick-replies")).to_contain_text(
        "Full Pentest"
    )
    expect(loaded_page.get_by_test_id("wizard-depth-tile-passive")).to_have_attribute("aria-pressed", "false")
    loaded_page.get_by_test_id("wizard-depth-tile-passive").click()
    expect(loaded_page.get_by_test_id("wizard-depth-tile-passive")).to_have_attribute("aria-pressed", "true")


def test_external_ip_deep_assessment_stages_perimeter_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_external_ip_guided_preview(
        loaded_page,
        target="203.0.113.0/28",
        depth="full",
    )
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full - all 4 phases")
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External Surface Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-external-infrastructure")

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-external-infrastructure"
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
    _finish_external_ip_guided_preview(
        loaded_page,
        target="203.0.113.0/28",
        depth="active",
    )
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phases 1-2")
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External IP / WAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("External Surface Only")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-external-infrastructure")

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "External IP / WAN"
    assert configuration["test_profile"] == "External Surface Only"
    assert configuration["execution_profile"] == "passive-external-infrastructure"
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["modules"]["discovery"] is True
    assert configuration["modules"]["ssl_tls_analysis"] is True
    assert configuration["modules"]["auth_flows"] is False
    assert configuration["safety"]["active_checks"] == "passive-only"
    assert configuration["safety"]["max_validation_depth"] == "light"


def test_domain_deep_assessment_stays_unauthenticated_by_default(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_web_guided_preview(loaded_page, target="example.com", depth="full")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full - all 4 phases")
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Deep"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["primary_goal"] == "deep-assessment"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["modules"]["auth_flows"] is False
    assert "example.com" in _target_values_text(configuration)


def test_web_deep_assessment_stays_unauthenticated_by_default(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_web_guided_preview(loaded_page, target="https://app.example.com", depth="full")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full - all 4 phases")
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Deep")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("active-web-safe")

    run_id = _selected_run_id(loaded_page)
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
    _finish_web_guided_preview(loaded_page, target="https://app.example.com", depth="active")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phases 1-2")
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-web-nuclei-audit")

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-web-nuclei-audit"
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["modules"]["auth_flows"] is False


def test_tls_only_intent_limits_goal_choices_to_tls_safe_options(loaded_page: Page) -> None:
    _answer_current_question(loaded_page, "Our website")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="3"]').click()
    expect(loaded_page.locator('input[name="wizard-test-profile"][value="SSL/TLS Only"]')).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-advanced-content")).to_contain_text("SSL/TLS Only")


def test_tls_only_standard_route_requires_safety_and_boundaries_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_tls_guided_preview(loaded_page, target="portal.example.com")
    _launch_tls_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
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
            "Website / Web App",
            "Standard",
            "passive-web-nuclei-audit",
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
            "passive-external-infrastructure",
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
            "Website / Web App",
            "Standard",
            "passive-web-nuclei-audit",
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
    if intent_answer == "Our internet-facing IP range":
        _finish_external_ip_guided_preview(loaded_page, target=scope_answer, depth="active")
    elif intent_answer == "Our API":
        _finish_api_guided_preview(loaded_page, target=scope_answer, depth="active")
    else:
        _finish_web_guided_preview(loaded_page, target=scope_answer, depth="active")

    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
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
    _finish_tls_guided_preview(
        loaded_page,
        target="portal.example.com",
        goal="standard-assessment",
    )
    _launch_tls_guided_mission_from_preview(loaded_page, goal="standard-assessment")
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
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
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )

    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "passive-web-nuclei-audit"
    )
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).not_to_contain_text(
        "active-web-safe"
    )


def test_mixed_assessment_confirmation_copy_avoids_duplicate_assessment_wording(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_mixed_guided_preview(loaded_page)
    _launch_mixed_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Mixed Assessment"
    assert configuration["execution_profile"] == "active-web-safe"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert configuration["intake"]["preferences"]["primary_goal"] == "adaptive-coverage"
    assert "https://api.example.com/v1" in _target_values_text(configuration)


def test_authenticated_app_credentialed_route_requires_boundary_confirmation_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_authenticated_webapp_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Authenticated Only"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "credentialed"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert configuration["access"]["accounts"][0]["role"] == "Security Analyst"


def test_api_token_route_requires_boundary_confirmation_before_confirmation(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_api_guided_preview(loaded_page, target="https://api.example.com/v1", depth="active")
    _apply_api_token_state_override(loaded_page)
    _launch_api_token_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    run_id = _selected_run_id(loaded_page)
    run = _api_json(operator_console_base_url, f"/api/v1/runs/{run_id}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "API"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "api-access"
    assert configuration["intake"]["preferences"]["boundary_handling"] == "standard-scope-only"
    assert configuration["access"]["accounts"][0]["role"] == "API Analyst"


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
    expect(page.get_by_test_id("screen-dashboard")).to_be_visible()
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])
    page.get_by_test_id("sidebar-new-mission").click()
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()
    selected_label = page.locator("#engagement-select option:checked").inner_text()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.get_by_test_id("wizard-use-existing").check()
    page.get_by_test_id("wizard-advanced-toggle").click()

    _finish_api_guided_preview(page, target="https://api.example.com/v1", depth="active")
    _apply_api_token_state_override(page)
    _launch_api_token_guided_mission_from_preview(page)
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])
    expect(page.locator("#engagement-select option:checked")).to_contain_text(selected_label)

    engagements_after = _api_json(operator_console_base_url, "/api/v1/engagements")
    runs_after = _api_json(operator_console_base_url, f"/api/v1/engagements/{engagement['id']}/runs")
    assert len(engagements_after) == len(engagements_before)
    assert len(runs_after) == len(runs_before) + 1


def test_new_engagement_route_creates_one_dossier_and_keeps_creation_route_visible(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagements_before = _api_json(operator_console_base_url, "/api/v1/engagements")

    page.goto("/app/")
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    page.get_by_test_id("wizard-advanced-toggle").click()
    expect(page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    page.locator("#wizard-engagement-name").fill("Portal Assessment 2026")
    page.locator("#wizard-client").fill("Acme Corp")
    page.locator("#wizard-roe-ref").fill("ROE-2026-021")
    page.get_by_test_id("wizard-advanced-toggle").click()
    _expect_current_question(page, "What would you like to pentest today")

    _finish_authenticated_webapp_intake(page)
    _launch_guided_mission_from_preview(page)
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


def test_automatic_new_dossier_name_tracks_advanced_scope_and_profile_overrides(
    page: Page,
    operator_console_base_url: str,
) -> None:
    page.goto("/app/")
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    _finish_web_guided_preview(page, target="https://portal.example.com", depth="full")
    expect(page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "portal.example.com"
    )
    _launch_guided_mission_from_preview(page)
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select option:checked")).to_contain_text(
        "portal.example.com Deep Assessment"
    )

    run_id = _selected_run_id(page)
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
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    _finish_web_guided_preview(page, target="https://portal.example.com", depth="full")
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
                engagement_name: "Manual Deep Portal Review",
              },
            },
          }, "ui.test.manualDossierName");
        }
        """
    )
    _launch_guided_mission_from_preview(page)
    expect(page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(page.locator("#engagement-select option:checked")).to_contain_text(
        "Manual Deep Portal Review"
    )

    run_id = _selected_run_id(page)
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
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(
        loaded_page,
        exclude_urls=["https://portal.example.com/admin"],
        notes="Avoid billing and admin flows.",
    )
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("1 explicit exclusion")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Avoid billing and admin flows.")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Balanced Technical")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Custom Exclusions Recorded")


def test_scope_guardrail_confirmation_summary_handles_plural_exclusions_cleanly(
    loaded_page: Page,
) -> None:
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(
        loaded_page,
        exclude_urls=[
            "https://portal.example.com/admin",
            "https://portal.example.com/billing",
        ],
    )
    exclusions = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          return runtimeModule.state.wizard.data.exclusions.urls;
        }
        """
    )
    assert exclusions == [
        "https://portal.example.com/admin",
        "https://portal.example.com/billing",
    ]


def test_revising_boundaries_to_no_extra_exclusions_clears_previous_boundary_state(
    loaded_page: Page,
) -> None:
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Standard Scope Only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("No denylist recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Not recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).not_to_contain_text("Avoid billing and admin flows.")


def test_revising_boundaries_to_notes_only_replaces_previous_explicit_exclusions(
    loaded_page: Page,
) -> None:
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(
        loaded_page,
        notes="Avoid the billing journey, but no explicit denylist entries.",
    )
    _launch_guided_mission_from_preview(loaded_page)
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
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(loaded_page, notes="Avoid login and billing flows.")
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-explorer")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary Notes Recorded")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Boundary notes only")
    expect(loaded_page.get_by_test_id("dossier-scope-guardrails")).to_contain_text("Avoid login and billing flows.")


def test_notes_only_boundary_fallback_without_explicit_metadata_stays_truthful(
    loaded_page: Page,
) -> None:
    _finish_web_guided_preview(
        loaded_page,
        target="https://portal.example.com",
        depth="active",
    )
    _apply_boundary_override(loaded_page, notes="Avoid login and billing flows.")
    _launch_guided_mission_from_preview(loaded_page)
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
    _finish_session_guided_preview(loaded_page)
    _launch_session_guided_mission_from_preview(loaded_page)

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
    expect(page.get_by_test_id("screen-wizard")).to_be_visible()

    _finish_session_guided_preview(page)
    _apply_unauthenticated_standard_override(page)
    _launch_unauthenticated_standard_guided_mission_from_preview(page)
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
    _finish_api_guided_preview(loaded_page, target="https://api.example.com/v1", depth="full")
    _apply_api_adaptive_token_state_override(loaded_page)
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("API")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "https://api.example.com/v1"
    )
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "active-web-safe"
    )
    _launch_api_adaptive_token_guided_mission_from_preview(loaded_page)

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

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        flow["expected_scope_fragment"]
    )

    _launch_conversational_matrix_flow(loaded_page, flow)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["assessment_type"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected_profile"]
    )
    _assert_lane_visible_or_in_chain(
        loaded_page,
        operator_console_base_url,
        flow.get("expected_summary_lane", flow["expected_lane"]),
    )

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
    _expect_current_question(loaded_page, "What would you like to pentest today")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()

    _finish_quick_reply_matrix_flow(loaded_page, flow)

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        flow["expected"]["scope_fragment"]
    )
    _launch_quick_reply_matrix_flow(loaded_page, flow)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected"]["assessment_type"]
    )
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text(
        flow["expected"]["test_profile"]
    )
    _assert_lane_visible_or_in_chain(
        loaded_page,
        operator_console_base_url,
        flow["expected"].get("summary_execution_profile", flow["expected"]["execution_profile"]),
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
    _select_assessment_tile(loaded_page, "Our web application")
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-depth-card")).to_contain_text(
        "How deep should the assessment go"
    )
    expect(loaded_page.locator('[data-testid="wizard-needed-actions"]')).to_have_count(0)


def test_still_needed_summary_deduplicates_goal_linked_actions(loaded_page: Page) -> None:
    _select_assessment_tile(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-depth-card")).to_be_visible()
    expect(loaded_page.locator('[data-testid="wizard-needed-actions"]')).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.20.0/24")


def test_path_note_deduplicates_goal_linked_topics(loaded_page: Page) -> None:
    _select_assessment_tile(loaded_page, "My LAN network")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "What is the target network"
    )
    expect(loaded_page.get_by_test_id("wizard-step-flow")).to_contain_text("Target & Depth")
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text("Output")


def test_auth_details_question_does_not_repeat_access_in_summary_or_path_note(
    loaded_page: Page,
) -> None:
    _finish_authenticated_webapp_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "https://portal.example.com"
    )
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "active-web-safe"
    )
    expect(loaded_page.locator('[data-testid="wizard-needed-actions"]')).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).not_to_contain_text(
        "Access, Access"
    )


def test_advanced_access_placeholder_opens_drawer_and_realigns_to_safety(
    loaded_page: Page,
) -> None:
    _answer_current_question(loaded_page, "Our customer portal")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    loaded_page.get_by_test_id("wizard-target-input").fill("https://portal.example.com")
    loaded_page.get_by_test_id("wizard-depth-tile-active").click()
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="2"]').click()
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
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_have_class(
        re.compile("hidden")
    )
    loaded_page.locator("[data-wizard-preview]").click()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "https://portal.example.com"
    )


def test_change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change access",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        manual_auth_steps="Use SSO handoff before privileged replay.",
        accounts=[
            {
                "label": "Analyst User",
                "username": "analyst@example.com",
                "role": "Security Analyst",
                "secret_ref": "vault://portal/analyst",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "",
            },
            {
                "label": "Admin User",
                "username": "admin@example.com",
                "role": "Application Admin",
                "secret_ref": "vault://portal/admin",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "",
            },
        ],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        api=True,
        auth_strategy="api-access",
        accounts=[
            {
                "label": "API Analyst",
                "username": "",
                "role": "Read Only API",
                "secret_ref": "",
                "api_key_ref": "vault://api/analyst-key",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "",
            },
            {
                "label": "API Admin",
                "username": "",
                "role": "API Admin",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "vault://api/admin-bearer",
                "session_ref": "",
                "mfa_notes": "",
            },
        ],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="session-access",
        cookie_notes="Rotate imported cookie bundles every 30 minutes.",
        accounts=[
            {
                "label": "Analyst Session",
                "username": "",
                "role": "Security Analyst",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "session-cookie=abc123",
                "mfa_notes": "",
            },
            {
                "label": "Admin Session",
                "username": "",
                "role": "Application Admin",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "session-cookie=xyz789",
                "mfa_notes": "",
            },
        ],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        manual_auth_steps="Operator must complete shared SSO handoff before replay.",
        accounts=[
            {
                "label": "Analyst SSO",
                "username": "analyst@example.com",
                "role": "Security Analyst",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "Approve push notification on analyst device.",
            },
            {
                "label": "Admin SSO",
                "username": "admin@example.com",
                "role": "Application Admin",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "Complete IdP handoff before privileged validation.",
            },
        ],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        manual_auth_steps="Shared SSO handoff is required before replay.",
        accounts=[
            {
                "label": "Analyst MFA",
                "username": "",
                "role": "Security Analyst",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "Approve analyst push notification.",
            },
            {
                "label": "Admin SSO",
                "username": "",
                "role": "Application Admin",
                "secret_ref": "",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "Complete IdP handoff before privileged validation.",
            },
        ],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        manual_auth_steps="Operator must complete shared SSO handoff before replay.",
        accounts=[],
    )
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="session-access",
        cookie_notes="Replay imported cookie bundle after operator login.",
        accounts=[],
    )
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
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the updated shared SSO handoff before replay.",
    )


def test_edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the edit-path-updated shared SSO handoff before replay.",
    )


def test_revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the revise-access-updated shared SSO handoff before replay.",
    )


def test_change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the confirmation-updated shared SSO handoff before replay.",
    )


def test_inline_change_from_history_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the inline-history-updated shared SSO handoff before replay.",
    )


def test_previous_topic_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the back-button-updated shared SSO handoff before replay.",
    )


def test_change_that_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the change-that-updated shared SSO handoff before replay.",
    )


def test_undo_alias_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the revision-proof-updated shared SSO handoff before replay.",
    )


def test_access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_manual_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Operator must complete the stage-button-updated shared SSO handoff before replay.",
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
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the refreshed cookie bundle after the operator completes login.",
    )


def test_revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the revise-path-updated cookie bundle after the operator completes login.",
    )


def test_edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the edit-session-updated cookie bundle after the operator completes login.",
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
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the confirmation-updated cookie bundle after the operator completes login.",
    )


def test_inline_change_from_history_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the inline-history-updated cookie bundle after the operator completes login.",
    )


def test_previous_topic_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the back-button-updated cookie bundle after the operator completes login.",
    )


def test_previous_alias_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the back-alias-updated cookie bundle after the operator completes login.",
    )


def test_go_back_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the return-path-updated cookie bundle after the operator completes login.",
    )


def test_access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_shared_session_guidance_revision(
        loaded_page,
        operator_console_base_url,
        updated_text="Replay the stage-button-updated cookie bundle after the operator completes login.",
    )


def test_change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change credential",
        access_mode="credential",
        initial_detail="analyst@example.com role Security Analyst secret vault://portal/analyst",
        updated_detail="analyst@example.com role Security Lead secret vault://portal/lead",
    )


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
    _finish_web_guided_preview(loaded_page, target="https://portal.example.com", depth="active")
    loaded_page.get_by_test_id("wizard-advanced-toggle").click()
    expect(loaded_page.get_by_test_id("wizard-advanced-drawer")).to_be_visible()
    loaded_page.locator('[data-advanced-step="2"]').click()
    expect(loaded_page.locator('[data-advanced-step="2"]')).to_have_class(
        re.compile(r"secondary")
    )


def test_auth_details_question_can_switch_back_to_unauthenticated_without_dead_end(
    loaded_page: Page,
) -> None:
    _finish_web_guided_preview(loaded_page, target="https://portal.example.com", depth="active")
    _apply_unauthenticated_standard_override(loaded_page)
    _launch_unauthenticated_standard_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)


def test_change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change auth",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


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
    _complete_advanced_access_detail_revision(
        loaded_page,
        operator_console_base_url,
        command="change session",
        access_mode="session",
        initial_detail="role Security Analyst session session-cookie=abc123",
        updated_detail="role Security Lead session session-cookie=xyz789",
    )


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

    guided_state = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const data = runtimeModule.state.wizard.data;
          return {
            profile: data.test_profile,
            activeChecks: data.safety.active_checks,
            maxDepth: data.safety.max_validation_depth,
          };
        }
        """
    )
    assert guided_state == {
        "profile": "Deep",
        "activeChecks": "active",
        "maxDepth": "deep",
    }
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "active-web-zap-active"
    )


def test_clearing_advanced_scope_from_confirmation_returns_to_scope_with_visible_validation_feedback(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_standard_web_intake(loaded_page, "https://app.example.com")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizard = runtimeModule.state.wizard;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              data: {
                ...wizard.data,
                targets: {
                  ...wizard.data.targets,
                  urls: ["https://app.example.com"],
                },
              },
              intake: {
                ...wizard.intake,
                advancedOpen: false,
              },
            },
          }, "ui.test.restoreGuidedScope");
        }
        """
    )
    _launch_guided_mission_from_preview(loaded_page)
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
    _launch_guided_custom_access_mission(
        loaded_page,
        auth_strategy="credentialed",
        accounts=[
            {
                "label": "Security Lead",
                "username": "analyst@example.com",
                "role": "Security Lead",
                "secret_ref": "vault://portal/lead",
                "api_key_ref": "",
                "bearer_token_ref": "",
                "session_ref": "",
                "mfa_notes": "",
            }
        ],
    )
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
    _expect_current_question(loaded_page, "target network")
    _answer_current_question(loaded_page, "scan anything public you can find")

    expect(loaded_page.locator("#wizard-errors")).to_contain_text(
        "I need exact authorized targets"
    )
    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "target network"
    )


def test_dispatch_and_status_history_work_after_conversational_intake(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)

    run_activity = loaded_page.get_by_test_id("mission-run-activity")
    expect(run_activity).to_contain_text("completed")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(
        "Selected Check Focus"
    )
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("10.0.20.0/24")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(
        "Nmap version test-build"
    )

    expect(loaded_page.locator("#status-feed")).to_contain_text(
        "Mission 10.0.20.0/24 Inventory First created",
        timeout=20000,
    )
    loaded_page.get_by_test_id("nav-attack-map").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.locator("#surface-insights")).to_contain_text("3 hosts or network objects")
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text("10.0.20.1")
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("10.0.20.3")
    expect(loaded_page.get_by_test_id("discovery-complete-summary")).to_contain_text(
        "3 hosts and 0 services were mapped"
    )
    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("Network discovery")
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("completed clean")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("Nmap version test-build")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("1 artifact")


def test_ready_to_start_and_thin_output_states_keep_one_dispatch_action_and_truthful_completion(
    loaded_page: Page, probe_server: str
) -> None:
    _finish_standard_web_intake(loaded_page, probe_server)
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#next-actions")).to_be_empty()
    expect(
        loaded_page.get_by_test_id("mission-run-activity").locator('[data-run-dispatch="selected"]')
    ).to_have_count(0)

    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        "Execution finished with limited analyst output",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("mission-run-activity")).to_contain_text(
        "The queued work finished, but there are no findings and no discovery-confirmed inventory yet."
    )
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("Selected Check Focus")
    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text(probe_server)
    expect(loaded_page.locator('[data-run-dispatch="selected"]')).to_have_count(1)


def test_ai_signal_provider_disabled_state_is_static_and_readable(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).to_contain_text(
        "ChatGPT OAuth is not connected for AI features on this run."
    )
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).to_contain_text(
        "Connect ChatGPT in Settings"
    )
    expect(loaded_page.get_by_test_id("ai-signal-open-settings")).to_be_enabled()


def test_manual_dispatch_mode_explains_why_start_validation_does_not_launch_work(
    manual_loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(manual_loaded_page)
    _launch_guided_mission_from_preview(manual_loaded_page)

    expect(manual_loaded_page.get_by_test_id("mission-dispatch")).to_be_visible(timeout=15000)
    manual_loaded_page.get_by_test_id("mission-dispatch").click()

    expect(manual_loaded_page.locator("#status-feed")).to_contain_text(
        "manual mode",
        timeout=15000,
    )
    expect(manual_loaded_page.get_by_test_id("manual-dispatch-warning")).to_contain_text(
        "no inline runner or background worker is attached"
    )
    expect(manual_loaded_page.get_by_test_id("manual-dispatch-warning")).to_contain_text(
        "TASK_DISPATCH_MODE=inline"
    )
    expect(manual_loaded_page.locator('[data-testid="mission-dispatch"]')).to_have_count(0)


def test_surface_map_shows_only_functional_tabs_and_light_empty_state_before_inventory_exists(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    loaded_page.get_by_test_id("nav-attack-map").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)
    expect(loaded_page.get_by_test_id("surface-view-hotspots")).to_be_visible()
    expect(loaded_page.get_by_test_id("surface-view-packZones")).to_be_visible()
    expect(loaded_page.get_by_test_id("surface-view-futureAttackPaths")).to_have_count(0)
    expect(loaded_page.get_by_test_id("surface-view-futureIdentityGraph")).to_have_count(0)
    expect(loaded_page.get_by_test_id("surface-view-futureRiskOverlay")).to_have_count(0)
    expect(loaded_page.locator("#surface-map-canvas")).to_contain_text("10.0.20.1")
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("10.0.20.3")


def test_phase_navigation_keeps_only_current_workflow_visible(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Operate")
    expect(loaded_page.get_by_test_id("nav-wizard")).to_have_class(re.compile("active"))

    _switch_phase(loaded_page, "execution")
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(loaded_page.get_by_test_id("screen-wizard")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Mission Control")
    expect(loaded_page.get_by_test_id("nav-mission-control")).to_have_class(re.compile("active"))
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()

    _switch_phase(loaded_page, "analysis")
    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("screen-mission-control")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Reports")
    expect(loaded_page.get_by_test_id("nav-reports")).to_have_class(re.compile("active"))
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()


def test_topbar_is_reduced_to_shell_controls_and_hides_navigation_chrome(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("topbar")).to_be_visible()
    expect(loaded_page.get_by_test_id("topbar-nav")).to_be_hidden()
    expect(loaded_page.get_by_test_id("topbar-phase-indicator")).to_be_hidden()
    expect(loaded_page.get_by_test_id("refresh-state")).to_be_hidden()
    expect(loaded_page.get_by_test_id("topbar-settings")).to_be_visible()
    expect(loaded_page.get_by_test_id("engagement-select")).to_be_visible()


def test_findings_filters_and_retest_queue_start_collapsed(loaded_page: Page, probe_server: str) -> None:
    _finish_standard_web_intake(loaded_page, probe_server)
    _launch_guided_mission_from_preview(loaded_page)
    _open_analysis_screen(loaded_page, "nav-findings")

    filters = loaded_page.get_by_test_id("finding-filters-disclosure")

    expect(filters).to_have_js_property("open", False)
    filters.locator("summary").click(force=True)
    expect(filters).to_have_js_property("open", True)

    expect(loaded_page.locator("#remediation-portfolio")).to_be_hidden()

    _switch_phase(loaded_page, "analysis")
    expect(loaded_page.get_by_test_id("screen-report-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("screen-mission-control")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("phase-subnav")).to_contain_text("Reports")
    expect(loaded_page.get_by_test_id("nav-reports")).to_have_class(re.compile("active"))
    expect(loaded_page.get_by_test_id("phase-feed-card")).to_be_hidden()


def test_settings_screen_handles_failed_engagement_loads_without_request_storm(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagement = _api_json(
        operator_console_base_url,
        "/api/v1/engagements",
        method="POST",
        actor="settings-loop-tester",
        body={
          "name": "Settings Loop Repro",
          "client": "Acme Corp",
          "roe_ref": "ROE-2026-SETTINGS",
        },
    )

    request_counts = {"siem": 0, "cicd": 0}
    browser_resource_errors: list[str] = []

    def _fail_siem(route) -> None:
        request_counts["siem"] += 1
        route.fulfill(
            status=400,
            content_type="application/json",
            body=json.dumps({"detail": "SIEM settings unavailable for this engagement"}),
        )

    def _fail_cicd(route) -> None:
        request_counts["cicd"] += 1
        route.fulfill(
            status=404,
            content_type="application/json",
            body=json.dumps({"detail": "CI/CD trigger settings unavailable for this engagement"}),
        )

    page.route(re.compile(r".*/api/v1/engagements/.*/integrations/siem$"), _fail_siem)
    page.route(re.compile(r".*/api/v1/engagements/.*/triggers/cicd$"), _fail_cicd)
    page.on(
        "console",
        lambda msg: browser_resource_errors.append(msg.text)
        if "ERR_INSUFFICIENT_RESOURCES" in msg.text
        else None,
    )

    page.goto("/app/")
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])

    page.get_by_test_id("topbar-settings").click()

    expect(page.get_by_test_id("screen-settings")).to_be_visible()
    expect(page.get_by_test_id("settings-siem-panel")).to_contain_text(
        "SIEM settings unavailable for this engagement",
        timeout=15000,
    )
    expect(page.get_by_test_id("settings-cicd-panel")).to_contain_text(
        "CI/CD trigger settings unavailable for this engagement",
        timeout=15000,
    )

    page.wait_for_timeout(1000)

    assert request_counts == {"siem": 1, "cicd": 1}
    assert browser_resource_errors == []


def test_background_refresh_preserves_settings_screen_dom(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("topbar-settings").click()
    expect(loaded_page.get_by_test_id("screen-settings")).to_be_visible()
    expect(loaded_page.get_by_test_id("settings-form")).to_be_visible()

    mutation_count = loaded_page.evaluate(
        """async () => {
          const target = document.querySelector('#screen-settings');
          let count = 0;
          const observer = new MutationObserver((mutations) => {
            count += mutations.length;
          });
          observer.observe(target, { childList: true, subtree: true, characterData: true });
          const runtimeModule = await import(new URL('./assets/modules/runtime.js', window.location.href).toString());
          await runtimeModule.runtime.actions.refreshSelectedEngagement({ renderScreen: false });
          await new Promise((resolve) => window.setTimeout(resolve, 150));
          observer.disconnect();
          return count;
        }"""
    )

    assert mutation_count == 0


def test_settings_screen_defaults_to_disclosures_with_chatgpt_panel_open(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("topbar-settings").click()

    chatgpt_panel = loaded_page.get_by_test_id("settings-chatgpt-oauth-panel")
    ai_provider_panel = loaded_page.get_by_test_id("settings-ai-provider")
    network_panel = loaded_page.get_by_test_id("settings-default-network-scope")

    expect(loaded_page.get_by_test_id("screen-settings")).to_be_visible()
    expect(chatgpt_panel).to_have_js_property("open", True)
    expect(ai_provider_panel).to_have_js_property("open", False)
    expect(network_panel).to_have_js_property("open", False)
    expect(loaded_page.get_by_test_id("setting-ai-chatgpt-model")).not_to_be_visible()

    ai_provider_panel.locator("summary").click()

    expect(ai_provider_panel).to_have_js_property("open", True)
    expect(loaded_page.get_by_test_id("setting-ai-chatgpt-model")).to_be_visible()


def test_settings_chatgpt_connect_opens_authorization_window(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagement = _api_json(
        operator_console_base_url,
        "/api/v1/engagements",
        method="POST",
        actor="settings-oauth-tester",
        body={
            "name": "Settings OAuth Repro",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-OAUTH",
        },
    )

    authorize_requests: list[str] = []

    page.add_init_script(
        """
        (() => {
          const opened = [];
          window.__openedUrls = opened;
          const originalOpen = window.open.bind(window);
          window.open = (...args) => {
            if (args[0]) {
              opened.push(String(args[0]));
            }
            return null;
          };
          window.__originalOpen = originalOpen;
        })();
        """
    )

    def _chatgpt_status(route) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "connected": False,
                    "token_exposed": False,
                    "pendingAuthorization": False,
                    "account_id": None,
                }
            ),
        )

    def _authorize(route) -> None:
        authorize_requests.append(route.request.url)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "authorization_url": "https://auth.openai.example/authorize?state=settings-test",
                    "local_callback_listener": {
                        "active": True,
                        "url": "http://127.0.0.1:39001/callback",
                    },
                }
            ),
        )

    page.route(re.compile(r".*/api/v1/auth/chatgpt/status\?engagement_id=.*"), _chatgpt_status)
    page.route(re.compile(r".*/api/v1/auth/chatgpt/authorize\?engagement_id=.*"), _authorize)

    page.goto("/app/")
    expect(page.locator("#engagement-select")).to_have_value(engagement["id"])

    page.get_by_test_id("topbar-settings").click()
    expect(page.get_by_test_id("screen-settings")).to_be_visible()
    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text("Not connected")

    page.get_by_role("button", name="Connect ChatGPT").click()

    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text(
        "Authorization window opened",
        timeout=15000,
    )
    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text(
        "Complete the browser login in the opened window, then refresh status here."
    )

    opened_urls = page.evaluate("window.__openedUrls")
    assert authorize_requests and engagement["id"] in authorize_requests[0]
    assert opened_urls == [
        "about:blank",
        "https://auth.openai.example/authorize?state=settings-test",
    ]


def test_settings_chatgpt_reuses_existing_encrypted_session_without_login(
    page: Page,
    operator_console_base_url: str,
) -> None:
    engagement = _api_json(
        operator_console_base_url,
        "/api/v1/engagements",
        method="POST",
        actor="settings-oauth-reuse-tester",
        body={
            "name": "Settings OAuth Reuse",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-OAUTH-REUSE",
        },
    )

    page.add_init_script(
        """
        (() => {
          const opened = [];
          window.__openedUrls = opened;
          window.open = (...args) => {
            if (args[0]) opened.push(String(args[0]));
            return null;
          };
        })();
        """
    )

    def _chatgpt_status(route) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "provider": "chatgpt_oauth",
                    "configured": True,
                    "connected": False,
                    "token_exposed": False,
                    "account_id": None,
                    "reusable_session_available": True,
                    "reusable_account_id": "acct_existing",
                }
            ),
        )

    def _authorize(route) -> None:
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "provider": "chatgpt_oauth",
                    "reused": True,
                    "authorization_url": None,
                    "local_callback_listener": {"active": False, "reason": "reused_existing_session"},
                    "status": {
                        "provider": "chatgpt_oauth",
                        "configured": True,
                        "connected": True,
                        "account_id": "acct_existing",
                        "token_secret_ref_id": "secret-ref",
                        "token_exposed": False,
                    },
                    "token_exposed": False,
                }
            ),
        )

    page.route(re.compile(r".*/api/v1/auth/chatgpt/status\?engagement_id=.*"), _chatgpt_status)
    page.route(re.compile(r".*/api/v1/auth/chatgpt/authorize\?engagement_id=.*"), _authorize)

    page.goto("/app/")
    page.locator(f'#engagement-select option[value="{engagement["id"]}"]').wait_for(state="attached")
    page.locator("#engagement-select").select_option(engagement["id"])
    page.get_by_test_id("topbar-settings").click()
    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text("Use it here without logging in again")

    page.get_by_role("button", name="Use Existing ChatGPT Session").click()

    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text("Connected")
    expect(page.get_by_test_id("settings-chatgpt-status")).to_contain_text("acct_existing")
    assert page.evaluate("window.__openedUrls") == []


def test_settings_ai_feature_toggles_persist_and_warn_until_chatgpt_provider_selected(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("topbar-settings").click()

    ai_provider_panel = loaded_page.get_by_test_id("settings-ai-provider")
    ai_provider_panel.locator("summary").click()

    provider_select = loaded_page.locator('[data-setting-key="ai.provider"]')
    finding_enrichment_toggle = loaded_page.get_by_test_id(
        "setting-ai-finding-enrichment-enabled"
    ).locator('input[type="checkbox"]')

    expect(provider_select).to_have_value("disabled")
    expect(finding_enrichment_toggle).not_to_be_checked()
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_have_count(0)
    expect(loaded_page.get_by_test_id("settings-ai-features")).to_contain_text(
        "AI helpers are currently off. Select ChatGPT OAuth before turning any of them on."
    )

    finding_enrichment_toggle.check()
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_contain_text(
        "1 AI feature is enabled"
    )
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_contain_text(
        "Select ChatGPT OAuth"
    )

    loaded_page.get_by_test_id("settings-save").click()
    expect(loaded_page.get_by_test_id("settings-save")).to_contain_text("Save Settings")

    loaded_page.reload(wait_until="networkidle")
    loaded_page.get_by_test_id("topbar-settings").click()
    ai_provider_panel = loaded_page.get_by_test_id("settings-ai-provider")
    ai_provider_panel.locator("summary").click()

    provider_select = loaded_page.locator('[data-setting-key="ai.provider"]')
    finding_enrichment_toggle = loaded_page.get_by_test_id(
        "setting-ai-finding-enrichment-enabled"
    ).locator('input[type="checkbox"]')

    expect(finding_enrichment_toggle).to_be_checked()
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_be_visible()

    provider_select.select_option("chatgpt_oauth")
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_have_count(0)

    loaded_page.get_by_test_id("settings-save").click()
    expect(loaded_page.get_by_test_id("settings-save")).to_contain_text("Save Settings")

    loaded_page.reload(wait_until="networkidle")
    loaded_page.get_by_test_id("topbar-settings").click()
    ai_provider_panel = loaded_page.get_by_test_id("settings-ai-provider")
    ai_provider_panel.locator("summary").click()

    expect(loaded_page.locator('[data-setting-key="ai.provider"]')).to_have_value("chatgpt_oauth")
    expect(
        loaded_page.get_by_test_id("setting-ai-finding-enrichment-enabled").locator('input[type="checkbox"]')
    ).to_be_checked()
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_have_count(0)


def test_settings_ai_feature_copy_is_truthful_when_chatgpt_oauth_is_selected_but_helpers_are_off(
    loaded_page: Page,
) -> None:
    loaded_page.request.patch(
        f"{loaded_page.url.rstrip('/')}/api/v1/settings".replace("/app/api/", "/api/"),
        headers={"X-Actor": "settings-admin", "Content-Type": "application/json"},
        data=json.dumps(
            {
                "settings": {
                    "ai.provider": "chatgpt_oauth",
                    "ai.finding_enrichment_enabled": False,
                    "ai.post_task_analysis_enabled": False,
                    "ai.intake_intelligence_enabled": False,
                    "ai.autofix_enabled": False,
                    "ai.report_drafting_enabled": False,
                }
            }
        ),
    )

    loaded_page.reload(wait_until="networkidle")
    loaded_page.get_by_test_id("topbar-settings").click()
    ai_provider_panel = loaded_page.get_by_test_id("settings-ai-provider")
    ai_provider_panel.locator("summary").click()

    expect(loaded_page.locator('[data-setting-key="ai.provider"]')).to_have_value("chatgpt_oauth")
    expect(loaded_page.get_by_test_id("settings-ai-provider-warning")).to_have_count(0)
    expect(loaded_page.get_by_test_id("settings-ai-features")).to_contain_text(
        "AI helpers are currently off. Enable the toggles below to let connected engagements use ChatGPT OAuth where supported."
    )


def test_mission_control_groups_secondary_context_into_calmer_snapshot_panels(
    loaded_page: Page,
) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.get_by_test_id("mission-snapshot-panel")).to_contain_text("Run Snapshot")
    expect(loaded_page.get_by_test_id("mission-snapshot-panel")).to_contain_text(
        "elapsed"
    )
    expect(loaded_page.get_by_test_id("mission-support-panel")).to_contain_text("Selected Run")
    layout = loaded_page.evaluate(
        """
        () => {
          const grid = document.querySelector('#screen-mission-control .mission-grid');
          const supportPanel = document.querySelector('[data-testid="mission-support-panel"]');
          return {
            panelCount: grid ? Array.from(grid.children).length : 0,
            supportNestedInAi: Boolean(supportPanel?.closest('.mission-ai-panel')),
            exposureCount: document.querySelectorAll('[data-testid="mission-exposure-score"]').length,
          };
        }
        """
    )
    assert layout["panelCount"] == 3
    assert layout["supportNestedInAi"] is True
    assert layout["exposureCount"] == 1


def test_intake_assessment_tiles_fit_without_scroll_and_hide_floating_progress_copy(
    loaded_page: Page,
) -> None:
    loaded_page.set_viewport_size({"width": 1440, "height": 900})
    loaded_page.reload(wait_until="networkidle")

    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-custom-answer-toggle")).to_have_count(0)
    expect(loaded_page.get_by_test_id("conversation-answer-input")).to_have_count(0)
    expect(loaded_page.get_by_test_id("conversation-question")).not_to_contain_text("Mission Progress")

    geometry = loaded_page.evaluate(
        """
        () => {
          const grid = document.querySelector('[data-testid="wizard-assessment-tile-grid"]');
          const rect = grid?.getBoundingClientRect();
          const tiles = Array.from(grid?.querySelectorAll('[data-testid^="wizard-assessment-tile-"]') || []);
          const tileRects = tiles.map((tile) => tile.getBoundingClientRect());
          const firstRowTop = tileRects[0]?.top || 0;
          const firstRowBottom = Math.max(
            0,
            ...tileRects
              .filter((tileRect) => Math.abs(tileRect.top - firstRowTop) < 4)
              .map((tileRect) => tileRect.bottom)
          );
          return {
            viewportWidth: window.innerWidth,
            viewportHeight: window.innerHeight,
            gridLeft: rect?.left || 0,
            gridRight: rect?.right || 0,
            gridBottom: rect?.bottom || 0,
            firstRowBottom,
            tileCount: tiles.length,
          };
        }
        """
    )

    assert geometry["tileCount"] >= 8
    assert geometry["firstRowBottom"] <= geometry["viewportHeight"] - 8
    assert geometry["gridLeft"] >= 0
    assert geometry["gridRight"] <= geometry["viewportWidth"]


def test_reports_use_verified_hash_label_and_history_empty_state_is_guided(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)

    _open_analysis_screen(loaded_page, "nav-reports")
    expect(loaded_page.get_by_test_id("report-card").first).to_be_visible()
    expect(loaded_page.get_by_test_id("report-card").first).to_contain_text(
        re.compile("Export ready|Draft only|Unavailable")
    )
    loaded_page.get_by_test_id("report-card").first.click()
    expect(loaded_page.get_by_test_id("report-metadata")).to_contain_text("report variants")
    expect(loaded_page.get_by_test_id("report-metadata")).to_contain_text(
        re.compile("Export ready|Draft only|Unavailable")
    )
    expect(loaded_page.get_by_test_id("report-evidence-hash")).to_contain_text(
        "Evidence hash: verified"
    )
    expect(loaded_page.get_by_test_id("report-copy-hash")).to_be_visible()

    _open_analysis_screen(loaded_page, "nav-history")
    comparison_summary = loaded_page.get_by_test_id("comparison-summary")
    expect(comparison_summary).to_be_visible()
    comparison_text = comparison_summary.text_content() or ""
    assert (
        "Pick a baseline run to compare" in comparison_text
        and "Set a baseline run" in comparison_text
    ) or (
        "Comparison unavailable" in comparison_text
        and "Complete a second run to compare posture changes." in comparison_text
    ) or (
        "Current vs baseline" in comparison_text
        and "Inventory Delta" in comparison_text
    )


def test_internal_validation_conversation_stays_operational_without_credentials(loaded_page: Page) -> None:
    _finish_internal_validation_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 1")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 4")

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    _assert_lane_visible_or_in_chain(
        loaded_page,
        loaded_page.url.split("/app/")[0],
        "passive-network-service-enumeration",
    )
    expect(loaded_page.locator("#status-feed")).to_contain_text(
        "Mission 10.0.20.0/24 Deep Assessment created",
        timeout=20000,
    )
    expect(loaded_page.get_by_test_id("assessment-chain-panel")).to_contain_text(
        "Full Internal LAN"
    )


def test_internal_validation_accepts_keep_it_unauthenticated_and_advances_cleanly(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()


def test_goal_to_scope_transition_does_not_show_scope_error_before_scope_input(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")

    expect(loaded_page.get_by_test_id("conversation-question")).to_contain_text(
        "target network"
    )
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()


def test_repeating_access_answer_at_safety_gives_contextual_guidance(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("10.0.20.0/24")


def test_repeating_safety_answer_at_boundaries_gives_contextual_guidance(
    loaded_page: Page,
) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    _answer_current_question(loaded_page, "Deep internal validation")
    _answer_current_question(loaded_page, "10.0.20.0/24")

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).not_to_contain_text("LOCKED 6")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()


def test_authenticated_app_can_stay_unauthenticated_without_access_dead_end(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_web_guided_preview(loaded_page, target="https://portal.example.com", depth="active")

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "portal.example.com"
    )
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()

    _launch_guided_mission_from_preview(loaded_page)
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
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["test_profile"] == "Standard"
    assert configuration["execution_profile"] == "passive-web-nuclei-audit"
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"
    assert configuration["access"]["accounts"] == []


def _assert_internal_lan_chain_started_with_discovery(run: dict) -> tuple[dict, dict]:
    configuration = run["configuration_json"]
    chain = run["assessment_chain"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["test_profile"] == "Standard"
    assert chain["assessment_mode"] == "FULL-INTERNAL-LAN"
    assert chain["current_phase_key"] in {"passive-discovery", "active-enrichment"}
    passive_phase = chain["phases"][0]
    assert passive_phase["key"] == "passive-discovery"
    assert passive_phase["steps"][0]["profile_name"] == "passive-network-discovery"
    assert passive_phase["steps"][0]["status"] in {"running", "completed"}
    return configuration, chain


def test_internal_range_authenticated_review_stages_discovery_first_with_access_context(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_internal_lan_guided_preview(
        loaded_page,
        depth="active",
        primary_goal="authenticated-review",
        with_access_context=True,
    )

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")

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
    configuration, _chain = _assert_internal_lan_chain_started_with_discovery(run)
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["access"]["accounts"]


def test_internal_range_deep_assessment_stages_discovery_first(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_internal_lan_guided_preview(
        loaded_page,
        depth="active",
        primary_goal="deep-assessment",
    )

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")

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
    configuration, _chain = _assert_internal_lan_chain_started_with_discovery(run)
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
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
    _finish_internal_lan_guided_preview(
        loaded_page,
        depth="active",
        primary_goal="adaptive-coverage",
    )

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")

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
    configuration, _chain = _assert_internal_lan_chain_started_with_discovery(run)
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
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

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "app.example.com"
    )
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Full")

    _launch_guided_mission_from_preview(loaded_page)

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
    _finish_internal_lan_guided_preview(
        loaded_page,
        depth="active",
        primary_goal="authenticated-review",
        with_access_context=True,
    )

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")

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
    configuration, _chain = _assert_internal_lan_chain_started_with_discovery(run)
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
    assert configuration["access"]["accounts"]


def test_scope_revision_from_adaptive_web_to_internal_range_realigns_to_discovery_first_internal_plan(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_internal_lan_guided_preview(
        loaded_page,
        depth="active",
        primary_goal="adaptive-coverage",
    )

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")

    _launch_guided_mission_from_preview(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Standard")

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
    configuration, _chain = _assert_internal_lan_chain_started_with_discovery(run)
    assert configuration["intake"]["preferences"]["primary_goal"] == "standard-assessment"
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
    _finish_web_guided_preview(loaded_page, target="https://app.example.com", depth="active")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "app.example.com"
    )

    _launch_guided_mission_from_preview(loaded_page)

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
    assert configuration["intake"]["preferences"]["auth_strategy"] == "unauthenticated"


def test_scope_revision_from_internal_report_only_boundaries_to_web_clears_stale_lateral_copy(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_web_guided_preview(loaded_page, target="https://app.example.com", depth="passive")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "app.example.com"
    )

    _launch_guided_mission_from_preview(loaded_page)

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
    _finish_web_guided_preview(loaded_page, target="https://app.example.com", depth="full")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text(
        "app.example.com"
    )

    _launch_guided_mission_from_preview(loaded_page)

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


def test_guided_wizard_depth_can_be_changed_before_launch(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    loaded_page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    loaded_page.get_by_test_id("wizard-depth-tile-passive").click()
    loaded_page.locator("[data-wizard-preview]").click()

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 1")

    loaded_page.locator('[data-wizard-flow-step="2"]').click()
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()
    loaded_page.get_by_test_id("wizard-depth-tile-full").click()
    loaded_page.locator("[data-wizard-preview]").click()

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_contain_text("Phase 4")
    expect(loaded_page.locator("#wizard-errors")).to_be_empty()


def test_guided_web_preview_and_launch_copy_follow_selected_surface(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_web_guided_preview(loaded_page, target="https://portal.example.com", depth="active")

    preview = loaded_page.get_by_test_id("wizard-mission-preview")
    diagram = loaded_page.get_by_test_id("wizard-mission-preview-diagram")
    expect(preview).to_contain_text("External Web")
    expect(preview).to_contain_text("https://portal.example.com")
    expect(diagram).to_contain_text("HTTP fingerprint")
    expect(diagram).not_to_contain_text("Active Directory")
    expect(diagram).not_to_contain_text("BloodHound")
    expect(diagram).not_to_contain_text("DCSync")
    expect(diagram).not_to_contain_text("LDAP enumeration")

    loaded_page.locator('[data-wizard-flow-step="4"]').click()
    launch_step = loaded_page.get_by_test_id("conversation-question")
    expect(launch_step).to_contain_text("Mission Ready")
    expect(launch_step).to_contain_text("External Web")
    expect(launch_step).to_contain_text("https://portal.example.com")
    expect(launch_step).to_contain_text("Create Mission & Open Mission Control")
    expect(launch_step).not_to_contain_text("Assessment Launched")
    expect(launch_step).not_to_contain_text("Internal LAN - Phase 1 ready")
    expect(launch_step).not_to_contain_text("Active Directory - queued")

    _click_create_mission(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Website / Web App")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-web-nuclei-audit")

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{_selected_run_id(loaded_page)}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Website / Web App"
    assert configuration["execution_profile"] == "passive-web-nuclei-audit"
    assert configuration["targets"]["urls"] == ["https://portal.example.com"]
    assert configuration["targets"]["cidr_ranges"] == []
    assert run["status"] != "queued"
    assert all(task["status"] != "queued" for task in run["tasks"])


def test_guided_passive_lan_preview_only_promises_discovery_phase(
    loaded_page: Page,
    operator_console_base_url: str,
) -> None:
    _finish_internal_lan_guided_preview(loaded_page, target="10.0.20.0/24", depth="passive")

    preview = loaded_page.get_by_test_id("wizard-mission-preview")
    diagram = loaded_page.get_by_test_id("wizard-mission-preview-diagram")
    expect(preview).to_contain_text("Internal LAN")
    expect(diagram).to_contain_text("Phase 1")
    expect(diagram).not_to_contain_text("Phase 2")
    expect(diagram).not_to_contain_text("Phase 3")
    expect(diagram).not_to_contain_text("Phase 4")
    expect(diagram).not_to_contain_text("BloodHound")
    expect(diagram).not_to_contain_text("DCSync")

    loaded_page.locator('[data-wizard-flow-step="4"]').click()
    launch_step = loaded_page.get_by_test_id("conversation-question")
    expect(launch_step).to_contain_text("Mission Ready")
    expect(launch_step).to_contain_text("Internal LAN")
    expect(launch_step).to_contain_text("10.0.20.0/24")
    expect(launch_step).to_contain_text("Phases 1 only")
    expect(launch_step).to_contain_text("Create Mission & Open Mission Control")
    expect(launch_step).not_to_contain_text("All approved phases will execute automatically")

    _click_create_mission(loaded_page)
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible(timeout=15000)
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("Internal Range / LAN")
    expect(loaded_page.locator("#mission-scope-summary")).to_contain_text("passive-network-discovery")

    run = _api_json(operator_console_base_url, f"/api/v1/runs/{_selected_run_id(loaded_page)}")
    configuration = run["configuration_json"]
    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["targets"]["cidr_ranges"] == ["10.0.20.0/24"]
    assert configuration["targets"]["urls"] == []
    assert run["status"] != "queued"
    assert all(task["status"] != "queued" for task in run["tasks"])


def test_live_agents_prioritizes_running_task_and_stream_output(
    loaded_page: Page,
) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const run = {
            id: "11111111-1111-4111-8111-111111111111",
            status: "running",
            profile: { name: "passive-network-service-enumeration" },
            configuration_json: { execution_profile: "passive-network-service-enumeration" },
            tasks: [
              {
                id: "completed-task",
                tool: "nmap",
                target_id: "10.0.20.1",
                status: "completed",
                params_json: { profile_name: "passive-network-service-enumeration" },
                created_at: "2026-04-26T10:00:00Z",
                updated_at: "2026-04-26T10:01:00Z",
              },
              {
                id: "running-task",
                tool: "nmap",
                target_id: "10.0.20.114",
                status: "running",
                params_json: { profile_name: "passive-network-service-enumeration" },
                created_at: "2026-04-26T10:02:00Z",
                updated_at: "2026-04-26T10:03:00Z",
              },
              {
                id: "queued-task",
                tool: "nmap",
                target_id: "10.0.20.133",
                status: "queued",
                params_json: { profile_name: "passive-network-service-enumeration" },
                created_at: "2026-04-26T10:04:00Z",
                updated_at: "2026-04-26T10:04:00Z",
              },
            ],
          };
          runtimeModule.patchState({
            activeScreen: "agents",
            activePhase: "execution",
            selectedRunId: run.id,
            selectedRun: run,
            selectedTaskId: "running-task",
            selectedTask: null,
            selectedAiInsights: { proposals: [], reasoning_records: [] },
            mission: {
              ...runtimeModule.state.mission,
              runs: [run],
              findingsByRun: { [run.id]: [] },
            },
            taskStdoutStream: {
              source: null,
              taskId: "running-task",
              status: "streaming",
              sourceLabel: "runner-buffer",
              fallbackReason: null,
              lines: [
                {
                  sequence: 1,
                  timestamp: "2026-04-26T10:03:00Z",
                  stream: "command",
                  text: "$ nmap -n -oX <evidence>/nmap-results.xml -sV 10.0.20.114",
                },
              ],
              lineCount: 1,
              truncated: false,
              terminal: true,
              lastEventAt: "2026-04-26T10:03:00Z",
            },
          }, "ui.test.liveAgentsRunningTask");
          runtimeModule.runtime.actions.renderAll();
        }
        """
    )

    expect(loaded_page.get_by_test_id("screen-agents")).to_be_visible()
    expect(loaded_page.get_by_test_id("agents-command-strip")).to_contain_text("1 running")
    expect(loaded_page.get_by_test_id("agents-command-strip")).to_contain_text("1 queued")
    expect(loaded_page.get_by_test_id("agents-live-focus")).to_contain_text("Network discovery on 10.0.20.114")
    expect(loaded_page.get_by_test_id("agents-live-terminal")).to_contain_text("nmap -n")
    live_grid = loaded_page.get_by_test_id("agents-live-grid")
    expect(live_grid.get_by_test_id("agent-card")).to_have_count(1)
    expect(live_grid).to_contain_text("10.0.20.114")
    expect(live_grid).not_to_contain_text("10.0.20.133")
    expect(loaded_page.get_by_test_id("agents-archive")).to_contain_text(
        "Queued/completed task history"
    )


def test_guided_wizard_clear_all_returns_to_assessment_selection(loaded_page: Page) -> None:
    _expect_current_question(loaded_page, "What would you like to pentest today")
    _answer_current_question(loaded_page, "My LAN network")
    expect(loaded_page.get_by_test_id("wizard-selection-chip")).to_contain_text("Internal LAN")

    loaded_page.locator("[data-wizard-clear-assessment]").click()

    expect(loaded_page.get_by_test_id("wizard-selection-chip")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_be_visible()


def test_inventory_follow_up_can_launch_service_identification(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()

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
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text("completed clean")
    expect(loaded_page.get_by_test_id("follow-up-complete-summary")).to_contain_text(
        "services were identified",
        timeout=20000,
    )

    loaded_page.get_by_test_id("nav-attack-map").click()
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

    loaded_page.get_by_test_id("nav-evidence-replay").click()
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
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()
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
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()
    expect(loaded_page.get_by_test_id("screen-surface-map")).to_be_visible(timeout=20000)

    _open_analysis_screen(loaded_page, "nav-evidence-replay")
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
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()

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
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()

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
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        re.compile(r"[1-9]\d* hosts")
    )
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        re.compile(r"[1-9]\d* services")
    )
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        "Inspect enriched estate context"
    )
    expect(loaded_page.get_by_test_id("dossier-summary-card")).to_contain_text(
        "Open Surface Map"
    )


def test_history_comparison_includes_inventory_delta_and_search(loaded_page: Page) -> None:
    _finish_internal_inventory_intake(loaded_page)
    _launch_guided_mission_from_preview(loaded_page)
    _dispatch_selected_run_if_available(loaded_page)
    loaded_page.get_by_test_id("nav-attack-map").click()

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
          const sidebar = document.querySelector('.sidebar');
          const wizard = document.querySelector('[data-testid="conversation-question"]');
          const workspaceColumns = getComputedStyle(workspace).gridTemplateColumns.trim();
          return {
            viewportWidth: window.innerWidth,
            workspaceColumns,
            wizardWidth: wizard?.getBoundingClientRect().width || 0,
            sidebarPosition: getComputedStyle(sidebar).position,
          };
        }
        """
    )

    expect(loaded_page.get_by_test_id("conversation-question")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-stage-1")).to_be_visible()
    expect(loaded_page.get_by_test_id("wizard-recent-missions")).to_be_visible()
    expect(loaded_page.locator("body")).to_have_attribute("data-phase-layout", "focus")
    assert " " not in layout["workspaceColumns"]
    assert layout["wizardWidth"] >= layout["viewportWidth"] * 0.7
    assert layout["sidebarPosition"] == "static"


def test_mobile_confirmation_state_keeps_summary_readable_and_confirm_visible(loaded_page: Page) -> None:
    loaded_page.set_viewport_size({"width": 360, "height": 900})
    loaded_page.reload(wait_until="networkidle")

    _finish_internal_inventory_intake(loaded_page)

    expect(loaded_page.get_by_test_id("wizard-mission-preview")).to_be_visible()
    expect(loaded_page.locator('[data-wizard-flow-step="4"]')).to_be_visible()
    loaded_page.get_by_test_id("wizard-mission-preview").scroll_into_view_if_needed()
    loaded_page.wait_for_timeout(250)

    geometry = loaded_page.evaluate(
        """
        () => {
          const summary = document.querySelector('[data-testid="wizard-mission-preview"]');
          const confirm = document.querySelector('[data-wizard-flow-step="4"]');
          const question = document.querySelector('[data-testid="conversation-question"]');
          const summaryRect = summary.getBoundingClientRect();
          const confirmRect = confirm.getBoundingClientRect();
          const questionRect = question.getBoundingClientRect();
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
          };
        }
        """
    )

    assert geometry["questionWidth"] >= geometry["viewportWidth"] * 0.7
    assert geometry["summaryTop"] < geometry["viewportHeight"] * 0.95
    assert geometry["summaryTop"] + geometry["summaryHeight"] > 0
    assert geometry["confirmBottom"] > 0


def test_exposure_score_sidebar_mission_control_and_history_panels_render(loaded_page: Page) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const run = {
            id: 'exposure-run-current',
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: '2026-04-24T10:00:00.000Z',
            updated_at: '2026-04-24T10:12:00.000Z',
            profile: { name: 'Passive Baseline' },
            configuration_json: {
              assessment_type: 'Website / Web App',
              test_profile: 'Standard',
              execution_profile: 'passive-web-baseline',
              targets: { urls: ['https://exposure.example.test'] },
              modules: {},
              safety: {},
              eta: {},
            },
            tasks: [],
            approvals: [],
            findings: { finding_count: 2, findings_by_severity: { critical: 1, high: 1 } },
            pack_binding: null,
            source_inventory_snapshot_id: null,
          };
          runtimeModule.patchState(
            {
              engagements: [{ id: 'eng-exposure-ui', name: 'Exposure UI', client: 'AegisPT', roe_ref: 'ROE-EXPOSURE' }],
              selectedEngagementId: 'eng-exposure-ui',
              selectedRunId: run.id,
              selectedRun: run,
              mission: {
                scope: { allowlist_json: { urls: ['https://exposure.example.test'] }, denylist_json: {} },
                inventory: [],
                relevance: [],
                packs: [],
                runs: [run],
                internalValidations: [],
                findingsByRun: {
                  [run.id]: [
                    {
                      id: 'finding-critical',
                      title: 'Admin console exposed',
                      severity: 'critical',
                      target_id: 'https://exposure.example.test/admin',
                      status: 'open',
                      finding_origin: 'standard',
                      methodology_tags: ['OWASP-WSTG'],
                      evidence_ref: 'artifact://critical',
                    },
                    {
                      id: 'finding-high',
                      title: 'Stored XSS',
                      severity: 'high',
                      target_id: 'https://exposure.example.test/profile',
                      status: 'open',
                      finding_origin: 'standard',
                      methodology_tags: ['OWASP-WSTG'],
                      evidence_ref: 'artifact://high',
                    },
                  ],
                },
              },
              exposureScore: {
                engagement_id: 'eng-exposure-ui',
                advisory_note: 'Exposure score is advisory only.',
                current: {
                  id: 'score-current',
                  run_id: run.id,
                  score: 42,
                  severity_breakdown_json: { critical: 1, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
                  open_critical_count: 1,
                  open_high_count: 1,
                  remediated_count: 2,
                  verified_count: 1,
                  trend: 'improving',
                  computed_at: '2026-04-24T10:12:00.000Z',
                },
                history: [
                  {
                    id: 'score-1',
                    run_id: run.id,
                    score: 70,
                    severity_breakdown_json: { critical: 2, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
                    open_critical_count: 2,
                    open_high_count: 1,
                    remediated_count: 0,
                    verified_count: 0,
                    trend: 'stable',
                    computed_at: '2026-04-24T08:00:00.000Z',
                  },
                  {
                    id: 'score-2',
                    run_id: run.id,
                    score: 58,
                    severity_breakdown_json: { critical: 1, high: 2, medium: 0, low: 0, info: 0, unknown: 0 },
                    open_critical_count: 1,
                    open_high_count: 2,
                    remediated_count: 1,
                    verified_count: 0,
                    trend: 'improving',
                    computed_at: '2026-04-24T09:00:00.000Z',
                  },
                  {
                    id: 'score-current',
                    run_id: run.id,
                    score: 42,
                    severity_breakdown_json: { critical: 1, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
                    open_critical_count: 1,
                    open_high_count: 1,
                    remediated_count: 2,
                    verified_count: 1,
                    trend: 'improving',
                    computed_at: '2026-04-24T10:12:00.000Z',
                  },
                ],
              },
            },
            'test.exposureScore.render'
          );
          runtimeModule.runtime.actions.navigateToScreen?.('mission-control');
        }
        """
    )

    expect(loaded_page.get_by_test_id("persistent-context")).to_be_empty()
    expect(loaded_page.get_by_test_id("mission-exposure-score")).to_contain_text("Moderate stored exposure")
    expect(loaded_page.get_by_test_id("mission-exposure-score")).to_contain_text("1 critical open")
    expect(loaded_page.locator('[data-testid="mission-exposure-sparkline"]')).to_have_count(1)

    loaded_page.get_by_test_id("nav-history").click()
    expect(loaded_page.get_by_test_id("screen-history")).to_be_visible()
    expect(loaded_page.get_by_test_id("exposure-history-panel")).to_contain_text("Exposure Score History")
    expect(loaded_page.get_by_test_id("history-exposure-sparkline")).to_be_visible()


def test_first_run_onboarding_prefills_wizard_defaults(first_run_loaded_page: Page) -> None:
    expect(first_run_loaded_page.get_by_test_id("onboarding-overlay")).to_be_visible()
    first_run_loaded_page.get_by_test_id("onboarding-start-setup").click()
    first_run_loaded_page.get_by_test_id("onboarding-provider-chatgpt").click()
    first_run_loaded_page.get_by_test_id("onboarding-default-scope-input").fill("10.0.0.0/8")
    first_run_loaded_page.get_by_test_id("onboarding-actor-name-input").fill("first-run-operator")
    first_run_loaded_page.get_by_test_id("onboarding-continue-ready").click()

    ready_summary = first_run_loaded_page.get_by_test_id("onboarding-ready-summary")
    expect(ready_summary).to_contain_text("ChatGPT OAuth")
    expect(ready_summary).to_contain_text("10.0.0.0/8")
    expect(ready_summary).to_contain_text("first-run-operator")

    first_run_loaded_page.get_by_test_id("onboarding-run-first-scan").click()
    expect(first_run_loaded_page.get_by_test_id("onboarding-overlay")).to_be_hidden()
    expect(first_run_loaded_page.get_by_test_id("conversation-question")).to_be_visible()
    expect(first_run_loaded_page.get_by_test_id("conversation-question")).to_contain_text("Internal LAN")
    first_run_loaded_page.get_by_test_id("wizard-assessment-submit-selection").click()
    expect(first_run_loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.0.0/8")
    expect(first_run_loaded_page.locator("#actor-input")).to_have_count(0)
    expect(first_run_loaded_page.locator("#actor-display")).to_have_text("first-run-operator")


def test_first_run_onboarding_can_be_rerun_from_settings(first_run_loaded_page: Page) -> None:
    first_run_loaded_page.get_by_test_id("onboarding-skip-welcome").click()
    expect(first_run_loaded_page.get_by_test_id("onboarding-overlay")).to_be_hidden()
    expect(first_run_loaded_page.get_by_test_id("wizard-onboarding-checklist")).to_have_count(0)

    first_run_loaded_page.get_by_test_id("nav-settings").click()
    expect(first_run_loaded_page.get_by_test_id("screen-settings")).to_be_visible()
    first_run_loaded_page.get_by_test_id("settings-instance").locator("summary").click()
    first_run_loaded_page.get_by_test_id("settings-rerun-onboarding").click()
    expect(first_run_loaded_page.get_by_test_id("onboarding-overlay")).to_be_visible()
    expect(first_run_loaded_page.get_by_test_id("onboarding-overlay")).to_contain_text("Welcome to AegisPT")


def test_first_run_checklist_moves_from_intake_home_to_mission_control(
    first_run_loaded_page: Page, operator_console_base_url: str
) -> None:
    first_run_loaded_page.get_by_test_id("onboarding-skip-welcome").click()
    expect(first_run_loaded_page.get_by_test_id("wizard-onboarding-checklist")).to_have_count(0)

    engagement = _api_json(
        operator_console_base_url,
        "/api/v1/engagements",
        method="POST",
        actor="onboarding-seeder",
        body={
            "name": "Onboarding Progress Mission",
            "client": "AegisPT",
            "roe_ref": "ROE-ONBOARDING",
        },
    )
    _api_json(
        operator_console_base_url,
        f"/api/v1/engagements/{engagement['id']}/scope",
        method="POST",
        actor="onboarding-seeder",
        body={
            "allowlist_json": {"cidr_ranges": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )
    _api_json(
        operator_console_base_url,
        f"/api/v1/engagements/{engagement['id']}/runs",
        method="POST",
        actor="onboarding-seeder",
        body={"profile_name": "passive-network-discovery"},
    )

    first_run_loaded_page.reload(wait_until="domcontentloaded")
    first_run_loaded_page.get_by_test_id("nav-mission-control").click()
    checklist = first_run_loaded_page.get_by_test_id("mission-control-onboarding-checklist")
    expect(checklist).to_be_visible()
    expect(checklist).to_contain_text("1 mission created")
    expect(checklist).to_contain_text("Open Findings after the first results land")
