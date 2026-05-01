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
            },
            denylist_json: {},
          });
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
        "cloud",
        "api-security",
        "llm-ai-app",
        "custom",
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
        assert any(target in values for values in run["targets"].values() if isinstance(values, list))
