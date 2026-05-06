from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.ui_fast, pytest.mark.feature]

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX_ARTIFACT = REPO_ROOT / "codex" / "results" / "backlog-151-wizard-input-prediction-matrix-20260430.json"


ASSESSMENT_CASES = [
    ("external-web", "https://app.example.com", "active"),
    ("external-infrastructure", "203.0.113.0/24", "active"),
    ("internal-lan", "10.0.20.0/24", "active"),
    ("active-directory", "corp.example.local", "active"),
    ("full-internal", "10.0.20.0/24", "active"),
    ("smart-home-lan", "192.168.1.0/24", "active"),
    ("wifi-wireless", "HQ-Amsterdam | CorpWiFi | aa:bb:cc:dd:ee:ff | wlan0", "passive"),
    ("cloud", "tenant.example.com", "active"),
    ("api-security", "https://api.example.com/v1", "active"),
    ("llm-ai-app", "https://chat.example.com", "active"),
    ("custom", "https://mixed.example.com", "active"),
]


def _wizard_matrix(page: Page) -> dict[str, object]:
    return page.evaluate(
        """
        async () => {
          const wizard = await import('/app/assets/modules/wizard.js');
          return wizard.buildWizardInputPredictionMatrix();
        }
        """
    )


def _reset_wizard(page: Page) -> None:
    page.goto("/app/", wait_until="domcontentloaded")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    page.evaluate(
        """
        async () => {
          const runtime = await import('/app/assets/modules/runtime.js');
          const wizard = await import('/app/assets/modules/wizard.js');
          document.querySelectorAll(".mission-created-overlay").forEach((node) => node.remove());
          runtime.patchState({
            activeScreen: "wizard",
            selectedRunId: null,
            selectedRun: null,
            selectedTaskId: null,
            selectedTask: null,
            mission: {
              ...runtime.state.mission,
              runs: [],
              inventory: [],
              findingsByRun: {},
            },
            wizard: runtime.buildEmptyWizardState(),
          }, "test.wizardPrediction.reset");
          runtime.runtime.actions.navigateToScreen?.("wizard");
          runtime.runtime.actions.renderAll?.();
          wizard.createWizardModule().renderWizard();
        }
        """
    )
    expect(page.get_by_test_id("conversation-question")).to_be_visible()
    expect(page.get_by_test_id("wizard-assessment-tile-external-web")).to_be_visible()


def _select_tile(page: Page, tile_key: str) -> None:
    tile = page.get_by_test_id(f"wizard-assessment-tile-{tile_key}")
    expect(tile).to_be_visible()
    page.evaluate(
        """
        (tileKey) => {
          const nodes = [...document.querySelectorAll(`[data-testid="wizard-assessment-tile-${tileKey}"]`)];
          const node = nodes.find((candidate) => candidate.offsetParent !== null) || nodes[0];
          node?.click();
        }
        """,
        tile_key,
    )


def _click_selector(page: Page, selector: str) -> None:
    page.evaluate(
        """
        (selector) => {
          const nodes = [...document.querySelectorAll(selector)];
          const node = nodes.find((candidate) => candidate.offsetParent !== null) || nodes[0];
          if (!node) throw new Error(`Missing selector: ${selector}`);
          node.click();
        }
        """,
        selector,
    )


def _set_recent_engagements(page: Page, engagements: list[dict[str, str]]) -> None:
    page.evaluate(
        """
        async (engagements) => {
          const runtime = await import('/app/assets/modules/runtime.js');
          const wizard = await import('/app/assets/modules/wizard.js');
          runtime.patchState({ engagements }, "test.wizardQuickFill.engagements");
          wizard.createWizardModule().renderWizard();
        }
        """,
        engagements,
    )


def _route_scope(page: Page, engagement_id: str, allowlist: dict[str, list[str]]) -> None:
    page.route(
        f"**/api/v1/engagements/{engagement_id}/scope**",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"allowlist_json": allowlist, "denylist_json": {}}),
        ),
    )


def _launch_guided_case(page: Page, tile_key: str, target: str, depth: str) -> dict[str, object]:
    _reset_wizard(page)
    _select_tile(page, tile_key)
    expect(page.locator(".sel-chip")).to_have_count(2 if tile_key == "full-internal" else 1)
    if tile_key != "full-internal":
        expect(page.locator(".sel-chip").first).to_contain_text(
            tile_key.split("-")[0].capitalize()
        )
    _click_selector(page, "[data-assessment-submit-selection]")
    target_input = page.locator('[data-testid="wizard-target-input"]:visible')
    expect(target_input).to_be_visible()
    target_input.fill(target)
    expect(page.locator('[data-testid="wizard-target-interpretation"]:visible')).to_be_visible()
    _click_selector(page, f'[data-wizard-depth-choice="{depth}"]')
    _click_selector(page, "[data-wizard-preview]")
    expect(page.locator('[data-testid="wizard-mission-preview"]:visible')).to_be_visible()
    if depth == "full":
        page.get_by_test_id("wizard-full-authorization-input").fill(target)
    _click_selector(page, '[data-wizard-flow-step="4"]')
    page.evaluate(
        """
        () => {
          const checkbox = document.querySelector('[data-testid="wizard-roe-authorization-checkbox"]');
          if (!checkbox) return;
          checkbox.checked = true;
          checkbox.dispatchEvent(new Event("change", { bubbles: true }));
        }
        """
    )
    create_button = page.locator('[data-wizard-create-mission="true"]')
    expect(create_button).to_be_enabled()
    _click_selector(page, '[data-wizard-create-mission="true"]')
    deadline = time.time() + 20
    last_state: dict[str, object] = {}
    while time.time() < deadline:
        last_state = page.evaluate(
            """
            async () => {
              const runtime = await import('/app/assets/modules/runtime.js');
              const selectedRunId = String(runtime.state.selectedRunId || "");
              const run = runtime.state.selectedRun ||
                (runtime.state.mission?.runs || []).find((item) => String(item.id || "") === selectedRunId);
              if (!run?.id) {
                return { id: null, status: "missing", profile: null, assessment_mode: null, targets: {} };
              }
              return {
                id: run.id,
                status: run.status,
                profile: run.profile?.name || run.profile_name || run.configuration_json?.execution_profile || null,
                assessment_mode: run.assessment_mode || run.configuration_json?.assessment_mode?.mode || null,
                targets: run.configuration_json?.targets || {},
              };
            }
            """
        )
        if last_state.get("id"):
            return last_state
        page.wait_for_timeout(250)
    raise AssertionError(f"Mission was not created for {tile_key}: {last_state}")


def _targets_for_case(tile_key: str, target: str) -> dict[str, list[str]]:
    if tile_key == "wifi-wireless":
        parts = [part.strip() for part in target.split("|")]
        while len(parts) < 4:
            parts.append("")
        return {
            "domains": [],
            "subdomains": [],
            "urls": [],
            "ip_addresses": [],
            "cidr_ranges": [],
            "api_base_urls": [],
            "wireless_sites": [parts[0]] if parts[0] else [],
            "ssids": [parts[1]] if parts[1] else [],
            "bssids": [parts[2]] if parts[2] else [],
        }
    if "/" in target and not target.startswith("http"):
        bucket = "cidr_ranges"
    elif target.replace(".", "").isdigit():
        bucket = "ip_addresses"
    elif tile_key == "api-security":
        bucket = "api_base_urls"
    elif target.startswith("http"):
        bucket = "urls"
    else:
        bucket = "domains"
    return {
        "domains": [target] if bucket == "domains" else [],
        "subdomains": [],
        "urls": [target] if bucket == "urls" else [],
        "ip_addresses": [target] if bucket == "ip_addresses" else [],
        "cidr_ranges": [target] if bucket == "cidr_ranges" else [],
        "api_base_urls": [target] if bucket == "api_base_urls" else [],
        "wireless_sites": [],
        "ssids": [],
        "bssids": [],
    }


def _create_predicted_run(page: Page, *, tile_key: str, target: str, prediction: dict[str, object]) -> dict[str, object]:
    profile = prediction["expected_execution_profile"]
    assessment_mode = prediction["assessment_mode"] or None
    targets = _targets_for_case(tile_key, target)
    return page.evaluate(
        """
        async ({ tileKey, target, profile, assessmentMode, targets }) => {
          const post = async (url, body) => {
            const response = await fetch(url, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Actor": "wizard-matrix-test",
                "X-Forwarded-For": `wizard-matrix-${tileKey}`,
              },
              body: JSON.stringify(body),
            });
            if (!response.ok) {
              throw new Error(`${url} failed ${response.status}: ${await response.text()}`);
            }
            return response.json();
          };
          const engagement = await post("/api/v1/engagements", {
            name: `Wizard matrix ${tileKey}`,
            client: "UI matrix proof",
            roe_ref: "ROE-WIZARD-MATRIX",
          });
          await post(`/api/v1/engagements/${engagement.id}/scope`, {
            allowlist_json: {
              domains: targets.domains,
              urls: targets.urls.concat(targets.api_base_urls),
              hosts: targets.ip_addresses,
              cidrs: targets.cidr_ranges,
              wireless_sites: targets.wireless_sites,
              ssids: targets.ssids,
              bssids: targets.bssids,
            },
            denylist_json: {},
          });
          const wirelessParts = target.split("|").map((part) => part.trim());
          const run = await post(`/api/v1/engagements/${engagement.id}/runs`, {
            profile_name: profile,
            configuration_json: {
              assessment_type: tileKey,
              execution_profile: profile,
              targets,
              assessment_mode: {
                mode: assessmentMode,
                authorization_level: "active",
                auto_advance_on_phase_complete: Boolean(assessmentMode),
              },
              wireless: tileKey === "wifi-wireless" ? {
                site: targets.wireless_sites[0] || null,
                adapter: wirelessParts[3] || "wlan0",
                approved_ssids: targets.ssids,
                approved_bssids: targets.bssids,
                excluded_ssids: [],
                excluded_bssids: [],
                roe_acknowledged: true,
                passive_only: true,
                rf_disruptive_actions: false,
                handshake_capture: false,
                credential_harvesting: false,
                wps_pin_testing: false,
              } : undefined,
              intake: {
                wizard_prediction_matrix: true,
                selected_tile: tileKey,
                target,
              },
            },
            assessment_mode: assessmentMode,
            assessment_auto_advance_on_phase_complete: assessmentMode ? true : null,
            dispatch_after_create: false,
          });
          return {
            id: run.id,
            status: run.status,
            profile: run.profile?.name || run.profile_name || run.configuration_json?.execution_profile || null,
            assessment_mode: run.assessment_mode || run.configuration_json?.assessment_mode?.mode || null,
            targets: run.configuration_json?.targets || targets,
          };
        }
        """,
        {
            "tileKey": tile_key,
            "target": target,
            "profile": profile,
            "assessmentMode": assessment_mode,
            "targets": targets,
        },
    )


def test_wizard_prediction_matrix_covers_visible_tiles_and_toggle_contract(loaded_page: Page) -> None:
    matrix = _wizard_matrix(loaded_page)
    MATRIX_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    MATRIX_ARTIFACT.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")

    tiles = matrix["assessment_tiles"]
    assert [tile["key"] for tile in tiles] == [
        "external-web",
        "external-infrastructure",
        "internal-lan",
        "active-directory",
        "full-internal",
        "smart-home-lan",
        "wifi-wireless",
        "cloud",
        "api-security",
        "llm-ai-app",
        "custom",
        "ssl-tls",
        "authenticated-app",
    ]
    assert all({depth["key"] for depth in tile["depths"]} == {"passive", "active", "full"} for tile in tiles)
    assert all(tile["target_guidance"]["examples"] for tile in tiles)
    assert all(depth["expected_execution_profile"] for tile in tiles for depth in tile["depths"])
    assert all(depth["prereq_visibility"] for tile in tiles for depth in tile["depths"])

    for tile in tiles:
        tile_key = tile["key"]
        _reset_wizard(loaded_page)
        _select_tile(loaded_page, tile_key)
        if tile_key == "full-internal":
            expect(loaded_page.locator(".sel-chip")).to_have_count(2)
            _select_tile(loaded_page, tile_key)
            expect(loaded_page.locator(".sel-chip")).to_have_count(0)
            continue
        expect(loaded_page.locator(".sel-chip")).to_have_count(1)
        _select_tile(loaded_page, tile_key)
        expect(loaded_page.locator(".sel-chip")).to_have_count(0)


def test_ssl_tls_and_authenticated_app_tiles_reach_specialized_preview(loaded_page: Page) -> None:
    matrix = _wizard_matrix(loaded_page)
    tile_lookup = {tile["key"]: tile for tile in matrix["assessment_tiles"]}
    assert tile_lookup["ssl-tls"]["depths"][1]["expected_execution_profile"] == "passive-crypto-audit"
    assert tile_lookup["authenticated-app"]["depths"][1]["expected_execution_profile"] == "active-web-safe"

    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "ssl-tls")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_input = loaded_page.locator('[data-testid="wizard-target-input"]:visible')
    expect(target_input).to_be_visible()
    target_input.fill("portal.example.com")
    _click_selector(loaded_page, '[data-wizard-depth-choice="active"]')
    _click_selector(loaded_page, "[data-wizard-preview]")
    preview = loaded_page.locator('[data-testid="wizard-mission-preview"]:visible')
    expect(preview).to_be_visible()
    expect(preview).to_contain_text("SSL/TLS Only")
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text("passive-crypto-audit")

    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "authenticated-app")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_input = loaded_page.locator('[data-testid="wizard-target-input"]:visible')
    expect(target_input).to_be_visible()
    target_input.fill("https://portal.example.com")
    _click_selector(loaded_page, '[data-wizard-depth-choice="active"]')
    _click_selector(loaded_page, "[data-wizard-preview]")
    preview = loaded_page.locator('[data-testid="wizard-mission-preview"]:visible')
    expect(preview).to_be_visible()
    expect(preview).to_contain_text("Authenticated App")
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text("active-web-safe")
    expect(loaded_page.get_by_test_id("wizard-access-unlockers")).to_contain_text("Credential/API access")


def test_wizard_preview_copy_defects_are_cleaned_up(loaded_page: Page) -> None:
    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_input = loaded_page.locator('[data-testid="wizard-target-input"]:visible')
    expect(target_input).to_be_visible()
    target_input.fill("https://app.example.com")
    expect(loaded_page.get_by_test_id("wizard-target-interpretation")).to_contain_text(
        "URL target for External Web"
    )
    expect(loaded_page.get_by_test_id("wizard-target-interpretation")).not_to_contain_text(
        "urls target"
    )
    _click_selector(loaded_page, "[data-wizard-preview]")
    preview = loaded_page.locator('[data-testid="wizard-mission-preview"]:visible')
    expect(preview).to_be_visible()
    expect(preview).to_contain_text(
        "Hosts discovered in Phase 1 are automatically included in later phases."
    )
    expect(preview).not_to_contain_text("1 click disables")


def test_active_scan_depth_description_matches_assessment_context(loaded_page: Page) -> None:
    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    external_active = loaded_page.locator('[data-testid="wizard-depth-tile-active"]:visible')
    expect(external_active).to_contain_text("Vulnerability detection + web application analysis")
    expect(external_active).not_to_contain_text("AD mapping")

    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "internal-lan")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    lan_active = loaded_page.locator('[data-testid="wizard-depth-tile-active"]:visible')
    expect(lan_active).to_contain_text("Vulnerability detection + AD mapping")


def test_wizard_multi_tile_target_prompt_and_interpretation_are_context_aware(loaded_page: Page) -> None:
    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "internal-lan")
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_card = loaded_page.get_by_test_id("wizard-target-card")
    target_input = loaded_page.get_by_test_id("wizard-target-input")

    expect(target_card).to_contain_text("What are the targets?")
    expect(target_input).to_have_attribute("placeholder", "e.g. https://app.example.com or 192.168.1.0/24")
    expect(target_card).to_contain_text("https://app.example.com")
    expect(target_card).to_contain_text("192.168.1.0/24")
    expect(target_card).to_contain_text("+ Add target")

    target_input.fill("https://testphp.vulnweb.com")
    interpretation = loaded_page.get_by_test_id("wizard-target-interpretation")
    expect(interpretation).to_contain_text("URL target added for External Web component")
    expect(interpretation).not_to_contain_text("CIDR range target")

    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target website or app?")

    _reset_wizard(loaded_page)
    _select_tile(loaded_page, "internal-lan")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    expect(loaded_page.get_by_test_id("wizard-target-card")).to_contain_text("What is the target network?")


def test_wizard_target_quick_fill_chips_use_recent_scope_with_example_fallback(loaded_page: Page) -> None:
    _reset_wizard(loaded_page)
    _set_recent_engagements(loaded_page, [])
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_card = loaded_page.get_by_test_id("wizard-target-card")
    expect(target_card).to_contain_text("https://app.example.com")
    expect(target_card).to_contain_text("portal.example.com")
    expect(target_card).to_contain_text("+ Add URL")

    _route_scope(loaded_page, "recent-web-1", {"urls": ["https://customer.example.com"]})
    _route_scope(loaded_page, "recent-web-2", {"domains": ["portal.customer.example"]})
    _reset_wizard(loaded_page)
    _set_recent_engagements(
        loaded_page,
        [
            {
                "id": "recent-web-1",
                "name": "Customer portal",
                "client": "Customer",
                "roe_ref": "ROE-RECENT-1",
                "created_at": "2026-05-03T10:00:00Z",
            },
            {
                "id": "recent-web-2",
                "name": "Portal retest",
                "client": "Customer",
                "roe_ref": "ROE-RECENT-2",
                "created_at": "2026-05-02T10:00:00Z",
            },
        ],
    )
    _select_tile(loaded_page, "external-web")
    _click_selector(loaded_page, "[data-assessment-submit-selection]")
    target_card = loaded_page.get_by_test_id("wizard-target-card")
    expect(target_card).to_contain_text("https://customer.example.com")
    expect(target_card).to_contain_text("portal.customer.example")
    expect(target_card).to_contain_text("+ Add URL")
    expect(target_card).not_to_contain_text("https://staging.example.com")


def test_wizard_launch_flow_matches_matrix_for_each_assessment_family(manual_loaded_page: Page) -> None:
    matrix = _wizard_matrix(manual_loaded_page)
    tile_lookup = {tile["key"]: tile for tile in matrix["assessment_tiles"]}

    for tile_key, target, depth in ASSESSMENT_CASES:
        depth_prediction = next(item for item in tile_lookup[tile_key]["depths"] if item["key"] == depth)
        run = _create_predicted_run(
            manual_loaded_page,
            tile_key=tile_key,
            target=target,
            prediction=depth_prediction,
        )
        acceptable_profiles = {depth_prediction["expected_execution_profile"]}
        chain_profiles = depth_prediction.get("expected_chain_profiles") or []
        if chain_profiles:
            acceptable_profiles.add(chain_profiles[0])
        assert run["profile"] in acceptable_profiles, f"{tile_key} launched {run} not {acceptable_profiles}"
        if tile_key == "wifi-wireless":
            assert "HQ-Amsterdam" in run["targets"]["wireless_sites"]
            assert "CorpWiFi" in run["targets"]["ssids"]
            assert "aa:bb:cc:dd:ee:ff" in run["targets"]["bssids"]
        else:
            assert any(target in values for values in run["targets"].values() if isinstance(values, list))
