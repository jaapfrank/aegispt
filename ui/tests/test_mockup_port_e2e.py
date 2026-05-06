from __future__ import annotations

import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.ui_fast, pytest.mark.feature]


def test_exact_mockup_port_tiles_sidebar_stepper_and_cinema(loaded_page: Page) -> None:
    for nav_id, label in {
        "nav-wizard": "Intake",
        "nav-mission-control": "Mission Control",
        "nav-attack-map": "Attack Map",
        "nav-findings": "Findings",
        "nav-reports": "Reports",
        "nav-history": "History",
        "nav-packs": "Packs",
        "nav-settings": "Settings",
    }.items():
        expect(loaded_page.get_by_test_id(nav_id)).to_contain_text(label)

    expect(loaded_page.locator(".steps")).to_be_visible()
    expect(loaded_page.locator(".step-dot.active")).to_be_visible()
    expect(loaded_page.get_by_test_id("bottom-screen-nav")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-grid")).to_have_class("tile-grid")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-external-web")).to_contain_text("🌐")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-external-web")).to_contain_text("Popular")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-external-web")).to_contain_text("passive")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-internal-lan")).to_contain_text("🏠")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-active-directory")).to_contain_text("🛡️")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-full-internal")).to_contain_text("🎯")
    expect(loaded_page.get_by_test_id("wizard-assessment-tile-api-security")).to_contain_text("{ }")

    loaded_page.get_by_test_id("wizard-assessment-tile-internal-lan").click()
    loaded_page.get_by_test_id("wizard-assessment-tile-active-directory").click()
    expect(loaded_page.get_by_test_id("wizard-selection-bar")).to_contain_text("🏠 Internal LAN")
    expect(loaded_page.get_by_test_id("wizard-selection-bar")).to_contain_text("🛡️ Active Directory")
    expect(loaded_page.get_by_test_id("wizard-selection-count")).to_contain_text("2 types selected")
    expect(loaded_page.get_by_test_id("wizard-combo-hint")).to_contain_text("Internal LAN + Active Directory")
    expect(loaded_page.locator(".wizard-step-bar")).to_contain_text("1 · Choose")
    expect(loaded_page.locator(".wizard-step-bar")).to_contain_text("4 · Launch")
    expect(loaded_page.locator(".sel-chip")).to_have_count(2)

    loaded_page.locator("[data-assessment-submit-selection]").click()
    expect(loaded_page.get_by_test_id("conversation-question")).to_be_visible()
    expect(loaded_page.locator(".wizard-step-bar .demo-tab.on")).to_contain_text("2 · Target")

    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("mission-view-agents")).to_be_visible()
    loaded_page.get_by_test_id("mission-view-agents").click()
    expect(loaded_page.get_by_test_id("screen-agents")).to_be_visible()
    expect(loaded_page.get_by_test_id("agents-content")).to_be_visible()
    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("cinema-mode-open")).to_be_visible()
    loaded_page.keyboard.press("f")
    expect(loaded_page.get_by_test_id("cinema-overlay")).to_be_visible()
    expect(loaded_page.locator("#cinema-overlay")).to_contain_text("CINEMA MODE")
    expect(loaded_page.get_by_test_id("cinema-visualization")).to_be_visible()
    expect(loaded_page.get_by_test_id("cinema-counter-exposure")).to_contain_text("n/a")
    expect(loaded_page.get_by_test_id("cinema-narrator")).to_contain_text("No selected run")
    expect(loaded_page.locator("#cinema-overlay")).not_to_contain_text("10.0.20.5")
    loaded_page.keyboard.press("Escape")
    expect(loaded_page.locator("#cinema-overlay")).to_have_count(0)

    loaded_page.get_by_test_id("cinema-mode-open").click()
    expect(loaded_page.get_by_test_id("cinema-counter-critical")).to_contain_text("0")
    expect(loaded_page.get_by_test_id("cinema-counter-ai-proposals")).to_contain_text("0")
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import(new URL("./assets/modules/runtime.js", window.location.href).href);
          runtimeModule.patchState({
            selectedRunId: "cinema-stability-run",
            selectedRun: {
              id: "cinema-stability-run",
              status: "running",
              created_at: new Date().toISOString(),
              profile: { name: "passive-network-service-enumeration" },
              configuration_json: { targets: { hosts: ["10.0.20.1"] } },
              tasks: [
                {
                  id: "cinema-task-1",
                  tool: "nmap",
                  target_id: "10.0.20.1",
                  status: "running",
                  params_json: {},
                },
              ],
            },
            selectedAiInsights: { proposals: [], reasoning_records: [] },
            exposureScore: { current: { score: 0, trend: "stable" } },
            runStream: { runId: "cinema-stability-run", status: "connected" },
          }, "test.cinema.populate");
          window.__cinemaSvgNode = document.querySelector("[data-testid='cinema-visualization'] svg");
          window.__cinemaNarratorNode = document.querySelector("[data-testid='cinema-narrator']");
          runtimeModule.patchState({
            selectedRun: {
              id: "cinema-stability-run",
              status: "running",
              created_at: new Date().toISOString(),
              profile: { name: "passive-network-service-enumeration" },
              configuration_json: { targets: { hosts: ["10.0.20.1"] } },
              tasks: [
                {
                  id: "cinema-task-1",
                  tool: "nmap",
                  target_id: "10.0.20.1",
                  status: "running",
                  params_json: {},
                },
              ],
            },
          }, "test.cinema.sameSnapshot");
        }
        """
    )
    assert loaded_page.evaluate(
        """
        () => window.__cinemaSvgNode === document.querySelector("[data-testid='cinema-visualization'] svg")
          && window.__cinemaNarratorNode === document.querySelector("[data-testid='cinema-narrator']")
        """
    )
    loaded_page.get_by_test_id("cinema-mode-close").click()
    expect(loaded_page.locator("#cinema-overlay")).to_have_count(0)


def test_lan_wizard_routes_private_cidr_to_discovery_lane(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("wizard-assessment-tile-internal-lan").click()
    loaded_page.locator("[data-assessment-submit-selection]").click()
    expect(loaded_page.get_by_test_id("wizard-target-input")).to_have_value("10.0.20.0/24")

    loaded_page.locator("[data-wizard-preview]").click()

    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "passive-network-discovery"
    )
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text("nmap")
    expect(loaded_page.get_by_test_id("lan-discovery-routing-warning")).to_have_count(0)


def test_private_cidr_web_path_warns_and_one_click_corrects_to_lan_discovery(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("wizard-assessment-tile-external-web").click()
    loaded_page.locator("[data-assessment-submit-selection]").click()
    loaded_page.get_by_test_id("wizard-target-input").fill("10.0.20.0/24")
    loaded_page.locator("[data-wizard-preview]").click()

    expect(loaded_page.get_by_test_id("lan-discovery-routing-warning")).to_be_visible()
    expect(loaded_page.get_by_test_id("lan-discovery-routing-warning")).to_contain_text(
        "passive-network-discovery"
    )

    loaded_page.get_by_test_id("lan-profile-fix").click()

    expect(loaded_page.get_by_test_id("lan-discovery-routing-warning")).to_have_count(0)
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text(
        "passive-network-discovery"
    )
    expect(loaded_page.get_by_test_id("wizard-preview-execution-lane")).to_contain_text("nmap")


def _finding_record(finding_id: str, title: str, severity: str, target: str) -> dict[str, object]:
    return {
        "id": finding_id,
        "run_id": "molecule-run",
        "source_pack_id": None,
        "source_pack_artifact_id": None,
        "source_inventory_snapshot_id": None,
        "source_relevance_decision_id": None,
        "source_pack_version": None,
        "finding_origin": "standard",
        "title": title,
        "severity": severity,
        "target_id": target,
        "evidence_ref": f"artifact://{finding_id}",
        "status": "open",
        "validation_status": "unvalidated",
        "summary": "Synthetic browser-state finding for Molecule View validation.",
        "methodology_tags": ["OWASP-WSTG"],
        "ptes_phase": "exploitation",
        "nist_phase": "analysis",
        "wstg_id": "WSTG-INPV",
        "wstg_version": "4.2",
        "asvs_reference": None,
        "control_family": "Web Application Security",
        "created_at": "2026-04-26T10:00:00.000Z",
    }


def _finding_theater_payload(finding: dict[str, object]) -> dict[str, object]:
    return {
        "finding": finding,
        "business_impact": "The finding may expose sensitive application data.",
        "technical_details": "Stored evidence supports operator review.",
        "evidence_summary": "One evidence reference is linked.",
        "verification_status": "Pending operator verification.",
        "exploitability": "review",
        "severity_rank": 0,
        "confidence_label": "medium",
        "methodology": {
            "methodology_tags": finding["methodology_tags"],
            "control_family": "Web Application Security",
            "ptes_label": "Exploitation",
            "nist_label": "Analysis",
            "wstg_reference": "WSTG-INPV",
            "asvs_reference": None,
        },
        "provenance": {
            "origin": "standard",
            "source_pack_version": None,
            "source_inventory_snapshot_id": None,
            "source_relevance_decision_id": None,
        },
        "validation": {"status": "unvalidated", "label": "Pending review", "tone": "neutral", "note": "No re-probe yet."},
        "threat_intel_badges": {"badges": [], "no_badge_reason": "No local feed match.", "boundary": {}},
        "vulnerability_chains": {
            "chains": [
                {
                    "id": "chain-1",
                    "pattern_id": "test-chain",
                    "title": "SQLi to stored session impact",
                    "status": "review",
                    "component_finding_ids": ["finding-critical", "finding-high"],
                    "component_findings": [
                        finding,
                        _finding_record("finding-high", "Stored XSS", "high", "portal.example.test/profile"),
                    ],
                    "confidence_score": 0.8,
                    "combined_impact": "Two findings are linked by stored chain context.",
                    "evidence_refs": ["artifact://finding-critical"],
                    "metadata": {"operator_note": "Review-only chain context."},
                }
            ],
            "boundary": {
                "auto_escalates_severity": False,
                "mutates_component_findings": False,
                "executes_exploits": False,
                "message": "Chain context is additive and review-only.",
            },
        },
        "autofix": None,
        "repository_context": None,
        "ai_enrichment": None,
        "threat_context": None,
        "detection_engineering": None,
        "remediation": {
            "priority": "Review and remediate based on evidence.",
            "summary": "Fix the exposed control path.",
            "detail": "Retest after remediation.",
            "record": None,
            "linked_retests": [],
            "integrations": {},
            "proof_of_resolution_ready": False,
        },
        "next_steps": ["Open the linked evidence and confirm remediation ownership."],
    }


def _finding_evidence_payload(finding: dict[str, object]) -> dict[str, object]:
    return {
        "finding": finding,
        "evidence_ref": finding["evidence_ref"],
        "related_executions": [],
        "methodology_references": {"ptes": "Exploitation", "wstg": "WSTG-INPV"},
        "inventory_source": {"snapshot_id": None},
        "pack_provenance": {"name": None, "version": None},
        "relevance_source": {"decision_id": None},
        "validation_history": [],
    }


def test_risk_molecule_view_is_optional_and_opens_existing_detail_drawer(loaded_page: Page) -> None:
    critical = _finding_record("finding-critical", "SQL Injection", "critical", "portal.example.test/graphql")
    high = _finding_record("finding-high", "Stored XSS", "high", "portal.example.test/profile")
    medium = _finding_record("finding-medium", "Missing Security Header", "medium", "portal.example.test")

    findings_by_id = {
        "finding-critical": critical,
        "finding-high": high,
        "finding-medium": medium,
    }

    def handle_finding_detail(route) -> None:
        url = route.request.url
        finding = next((item for finding_id, item in findings_by_id.items() if finding_id in url), critical)
        payload = _finding_evidence_payload(finding) if url.endswith("/evidence") else _finding_theater_payload(finding)
        route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

    loaded_page.route("**/api/v1/findings/**", handle_finding_detail)

    loaded_page.evaluate(
        """
        async ({ critical, high, medium }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const run = {
            id: 'molecule-run',
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: '2026-04-26T10:00:00.000Z',
            updated_at: '2026-04-26T10:15:00.000Z',
            profile: { name: 'Molecule Validation' },
            configuration_json: {
              assessment_type: 'Website / Web App',
              test_profile: 'Standard',
              targets: { urls: ['https://portal.example.test'] },
              modules: {},
              safety: {},
            },
            tasks: [],
            approvals: [],
            findings: { finding_count: 3, findings_by_severity: { critical: 1, high: 1, medium: 1 } },
            pack_binding: null,
            source_inventory_snapshot_id: null,
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            engagements: [{ id: 'molecule-engagement', name: 'Molecule UI', client: 'AegisPT', roe_ref: 'ROE-MOL' }],
            selectedEngagementId: 'molecule-engagement',
            selectedRunId: run.id,
            selectedRun: run,
            findingsUi: { filtersOpen: false, remediationOpen: false, view: 'list' },
            mission: {
              scope: { allowlist_json: { urls: ['https://portal.example.test'] }, denylist_json: {} },
              inventory: [],
              relevance: [],
              packs: [],
              runs: [run],
              internalValidations: [],
              findingsByRun: {
                [run.id]: [
                  { ...critical, chains: ['finding-high'] },
                  high,
                  medium,
                ],
              },
            },
          }, 'test.riskMolecule');
          runtimeModule.runtime.actions.renderAll();
        }
        """,
        {"critical": critical, "high": high, "medium": medium},
    )

    expect(loaded_page.get_by_test_id("screen-findings-theater")).to_be_visible()
    expect(loaded_page.get_by_test_id("findings-view-list")).to_have_class("active")
    expect(loaded_page.get_by_test_id("finding-card")).to_have_count(3)
    expect(loaded_page.get_by_test_id("risk-molecule-view")).to_have_count(0)

    loaded_page.get_by_test_id("findings-view-molecule").click()
    expect(loaded_page.get_by_test_id("risk-molecule-view")).to_be_visible()
    expect(loaded_page.get_by_test_id("risk-molecule-node")).to_have_count(3)
    expect(loaded_page.get_by_test_id("risk-molecule-link")).to_have_count(1)
    expect(loaded_page.get_by_test_id("risk-molecule-legend")).to_contain_text("Critical (1)")
    expect(loaded_page.get_by_test_id("risk-molecule-detail")).to_contain_text("1 stored chain link")

    critical_node = loaded_page.locator('[data-testid="risk-molecule-node"][data-finding-pick="finding-critical"]')
    critical_node.hover()
    expect(loaded_page.get_by_test_id("risk-molecule-tooltip")).to_be_visible()
    expect(loaded_page.get_by_test_id("risk-molecule-tooltip")).to_contain_text("SQL Injection")

    critical_node.click()
    expect(loaded_page.get_by_test_id("finding-theater-detail")).to_be_visible()
    expect(loaded_page.get_by_test_id("finding-theater-detail")).to_contain_text("SQL Injection")
