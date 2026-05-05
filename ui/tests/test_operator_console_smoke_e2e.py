from __future__ import annotations

import json
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.ui_fast, pytest.mark.smoke]


def test_operator_console_fast_navigation_smoke(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("topbar")).to_contain_text("AegisPT")

    screens = {
        "nav-dashboard": "screen-dashboard",
        "nav-wizard": "screen-wizard",
        "nav-mission-control": "screen-mission-control",
        "nav-attack-map": "screen-surface-map",
        "nav-problems": "screen-problems-center",
        "nav-custom-vulnerabilities": "screen-custom-vulnerabilities",
        "nav-findings": "screen-findings-theater",
        "nav-reports": "screen-report-center",
        "nav-history": "screen-history",
        "nav-packs": "screen-pack-forge",
        "nav-settings": "screen-settings",
    }

    for nav_test_id, screen_test_id in screens.items():
        nav = loaded_page.get_by_test_id(nav_test_id)
        expect(nav).to_be_visible()
        nav.click()
        expect(loaded_page.get_by_test_id(screen_test_id)).to_be_visible()

    loaded_page.get_by_test_id("nav-wizard").click()
    expect(loaded_page.get_by_test_id("wizard-bottom-stepper")).to_be_visible()
    loaded_page.get_by_test_id("nav-mission-control").click()

    bottom_screens = {
        "bottom-nav-mission-control": "screen-mission-control",
        "bottom-nav-agents": "screen-agents",
        "bottom-nav-findings-theater": "screen-findings-theater",
        "bottom-nav-report-center": "screen-report-center",
        "bottom-nav-settings": "screen-settings",
    }
    for nav_test_id, screen_test_id in bottom_screens.items():
        nav = loaded_page.get_by_test_id(nav_test_id)
        expect(nav).to_be_visible()
        nav.click()
        expect(loaded_page.get_by_test_id(screen_test_id)).to_be_visible()


def test_topbar_engagement_cleanup_label_matches_delete_modal(loaded_page: Page) -> None:
    cleanup_button = loaded_page.get_by_test_id("manage-engagements")
    expect(cleanup_button).to_have_text("Cleanup")
    expect(cleanup_button).not_to_have_text("Manage")
    assert cleanup_button.get_attribute("aria-label") == "Open engagement cleanup"
    assert cleanup_button.get_attribute("title") == "Open engagement cleanup"

    cleanup_button.click()
    modal = loaded_page.get_by_test_id("delete-modal-root")
    expect(modal).to_contain_text("Data Cleanup")
    expect(modal).to_contain_text("Engagement Cleanup")
    expect(loaded_page.get_by_test_id("manage-engagements-list")).to_be_visible()


def test_topbar_notifications_placeholder_is_removed_and_settings_still_opens(
    loaded_page: Page,
) -> None:
    expect(loaded_page.get_by_test_id("topbar-notifications")).to_have_count(0)
    expect(loaded_page.locator("[aria-label='Notifications']")).to_have_count(0)
    expect(loaded_page.locator("[aria-label='Open notification settings']")).to_have_count(0)
    expect(loaded_page.get_by_test_id("topbar").locator("[data-nav-screen='settings']")).to_have_count(1)

    settings_button = loaded_page.get_by_test_id("topbar-settings")
    expect(settings_button).to_be_visible()
    assert settings_button.get_attribute("data-nav-screen") == "settings"

    settings_button.click()
    expect(loaded_page.get_by_test_id("screen-settings")).to_be_visible()


def test_pack_forge_tool_library_catalogue_and_manual_proposal(loaded_page: Page) -> None:
    created: list[dict[str, object]] = []

    def capture_proposal(route):
        created.append(route.request.post_data_json)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "id": "33333333-3333-4333-8333-333333333333",
                    "run_id": "11111111-1111-4111-8111-111111111111",
                    "agent_reasoning_id": "44444444-4444-4444-8444-444444444444",
                    "proposed_tool": "metasploit",
                    "proposed_target": "10.0.0.5",
                    "proposed_params_json": {},
                    "reasoning_text": "Manual proposal",
                    "risk_tier": "intrusive",
                    "priority": 75,
                    "confidence_score": 1.0,
                    "status": "pending_review",
                    "approved_by": None,
                    "approved_at": None,
                    "metadata_json": {"proposal_kind": "tool_library_manual_task", "dispatches_work": False},
                    "created_at": "2026-05-04T12:00:00Z",
                    "updated_at": "2026-05-04T12:00:00Z",
                }
            ),
        )

    loaded_page.route("**/api/v1/runs/*/tool-proposals", capture_proposal)
    loaded_page.route(
        "**/api/v1/runs/*/ai-insights",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "run_id": "11111111-1111-4111-8111-111111111111",
                    "post_task_analysis_enabled": True,
                    "provider": "disabled",
                    "provider_status": {"status": "disabled"},
                    "reasoning_records": [],
                    "proposals": [],
                    "review_boundary": {},
                    "operator_workbench": {},
                }
            ),
        ),
    )
    loaded_page.get_by_test_id("nav-packs").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const packsModule = await import('/app/assets/modules/packs.js');
          const now = new Date().toISOString();
          runtimeModule.patchState({
            selectedRunId: '11111111-1111-4111-8111-111111111111',
            selectedRun: {
              id: '11111111-1111-4111-8111-111111111111',
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { hosts: ['10.0.0.5'] } },
              profile: { name: 'intrusive-exploitation', run_class: 'intrusive', limits_json: {} },
              tasks: [{
                id: '22222222-2222-4222-8222-222222222222',
                tool: 'nmap',
                target_id: '10.0.0.5',
                status: 'completed',
                params_json: {},
                created_at: now,
                updated_at: now,
              }],
            },
          }, 'test.tool-library.state');
          packsModule.createPacksModule().renderPackForge();
        }
        """
    )

    expect(loaded_page.get_by_test_id("tool-library")).to_be_visible()
    tool_card_count = loaded_page.get_by_test_id("tool-card").count()
    expect(loaded_page.get_by_test_id("tool-library-count")).to_have_text(f"{tool_card_count} tools")
    loaded_page.get_by_text("Metasploit", exact=True).click()
    expect(loaded_page.get_by_test_id("tool-detail")).to_contain_text("exploitation")
    expect(loaded_page.get_by_test_id("tool-detail")).to_contain_text("Controlled session proof")
    loaded_page.get_by_test_id("tool-add-current-run").click()
    expect(loaded_page.get_by_test_id("status-feed-focus")).to_contain_text("Manual proposal created for Metasploit")
    assert created
    assert created[0]["tool_id"] == "metasploit"
    assert created[0]["proposed_tool"] == "metasploit"
    assert created[0]["proposed_target"] == "10.0.0.5"


def test_application_shell_has_no_repeated_marketing_subtitle(loaded_page: Page) -> None:
    long_subtitle = (
        "Guided, evidence-first assessment operations across wizard-driven setup, "
        "live mission control, adaptive pack governance, evidence replay, and report delivery."
    )
    screens = {
        "nav-dashboard": "screen-dashboard",
        "nav-wizard": "screen-wizard",
        "nav-mission-control": "screen-mission-control",
        "bottom-nav-agents": "screen-agents",
        "nav-findings": "screen-findings-theater",
        "nav-reports": "screen-report-center",
        "nav-history": "screen-history",
        "nav-settings": "screen-settings",
    }

    for nav_test_id, screen_test_id in screens.items():
        loaded_page.get_by_test_id(nav_test_id).click()
        expect(loaded_page.get_by_test_id(screen_test_id)).to_be_visible()
        expect(loaded_page.locator("body")).not_to_contain_text(long_subtitle)

    topbar_box = loaded_page.get_by_test_id("topbar").bounding_box()
    assert topbar_box is not None
    assert 48 <= topbar_box["height"] <= 56


def test_topbar_actor_identity_is_read_only_and_settings_backed(loaded_page: Page) -> None:
    actor_pill = loaded_page.get_by_test_id("topbar-actor-pill")
    expect(actor_pill).to_be_visible()
    expect(actor_pill.locator("input")).to_have_count(0)
    expect(loaded_page.locator("#actor-input")).to_have_count(0)
    expect(loaded_page.locator("#actor-display")).to_contain_text("operator-ui")
    expect(loaded_page.locator("#topbar-avatar-mark")).to_have_text("O")
    expect(loaded_page.get_by_test_id("topbar-role-badge")).to_contain_text("admin")

    loaded_page.get_by_test_id("nav-settings").click()
    instance_panel = loaded_page.get_by_test_id("settings-instance")
    instance_panel.locator("summary").click()
    actor_setting = loaded_page.locator("[data-setting-key='instance.operator_display_name']")
    expect(actor_setting).to_be_visible()
    actor_setting.fill("alice-reviewer")
    loaded_page.get_by_test_id("settings-save").click()

    expect(loaded_page.locator("#actor-display")).to_have_text("alice-reviewer", timeout=15000)
    expect(loaded_page.locator("#topbar-avatar-mark")).to_have_text("A")
    expect(actor_pill.locator("input")).to_have_count(0)


def test_mission_control_chain_phase_progress_shows_pending_approval_and_posts_decision(
    loaded_page: Page,
) -> None:
    decisions: list[dict[str, object]] = []
    chain_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def capture_phase_decision(route):
        decisions.append(route.request.post_data_json)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "id": chain_id,
                    "engagement_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "assessment_mode": "FULL-INTERNAL-LAN",
                    "status": "active",
                    "current_phase_index": 1,
                    "current_step_index": 0,
                    "current_phase_key": "active-enrichment",
                    "current_run_id": "33333333-3333-4333-8333-333333333333",
                    "last_completed_run_id": "22222222-2222-4222-8222-222222222222",
                    "auto_advance_on_phase_complete": True,
                    "halt_requested": False,
                    "completed_phase_count": 1,
                    "phase_count": 4,
                    "phases": [],
                    "operator_state": {},
                    "created_at": "2026-05-05T08:00:00Z",
                    "updated_at": "2026-05-05T08:31:00Z",
                }
            ),
        )

    loaded_page.route(
        "**/api/v1/assessment-chains/*/phases/active-enrichment/decision",
        capture_phase_decision,
    )
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async ({ chainId }) => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const run = {
            id: '22222222-2222-4222-8222-222222222222',
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: '2026-05-05T08:00:00Z',
            updated_at: '2026-05-05T08:31:00Z',
            completed_at: '2026-05-05T08:31:00Z',
            configuration_json: {
              assessment_type: 'Internal Range / LAN',
              eta: { estimated_total_minutes: 100 },
            },
            profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
            tasks: [],
            assessment_chain: {
              id: chainId,
              engagement_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              assessment_mode: 'FULL-INTERNAL-LAN',
              status: 'pending_phase_approval',
              current_phase_index: 1,
              current_step_index: 0,
              current_phase_key: 'active-enrichment',
              current_run_id: null,
              last_completed_run_id: '22222222-2222-4222-8222-222222222222',
              auto_advance_on_phase_complete: true,
              halt_requested: false,
              completed_phase_count: 1,
              phase_count: 4,
              created_at: '2026-05-05T08:00:00Z',
              updated_at: '2026-05-05T08:31:00Z',
              operator_state: { primary_action: 'Approve Next Phase' },
              phases: [
                {
                  key: 'passive-discovery',
                  label: 'Phase 1 · Passive Discovery',
                  tier: 'passive',
                  status: 'completed',
                  requires_approval: false,
                  started_at: '2026-05-05T08:00:00Z',
                  completed_at: '2026-05-05T08:25:00Z',
                  authorization_state: { status: 'authorized', label: 'Authorized' },
                  steps: [
                    { profile_name: 'passive-network-discovery', status: 'completed', run_id: '22222222-2222-4222-8222-222222222222' },
                    { profile_name: 'passive-lan-iot-discovery', status: 'completed', run_id: '22222222-2222-4222-8222-222222222222' },
                  ],
                },
                {
                  key: 'active-enrichment',
                  label: 'Phase 2 · Active Enrichment',
                  tier: 'active',
                  status: 'pending_approval',
                  requires_approval: true,
                  started_at: null,
                  completed_at: null,
                  gate_reason: 'This phase is waiting for an explicit operator approval decision.',
                  safe_next_action: 'Approve, reject, or halt at this boundary after reviewing prerequisites.',
                  authorization_state: {
                    status: 'manual_approval_required',
                    label: 'Manual approval required',
                    gate_reason: 'This phase is waiting for an explicit operator approval decision.',
                    safe_next_action: 'Approve, reject, or halt at this boundary after reviewing prerequisites.',
                  },
                  steps: [
                    { profile_name: 'passive-network-service-enumeration', status: 'pending', run_id: null },
                    { profile_name: 'passive-web-nuclei-audit', status: 'pending', run_id: null },
                    { profile_name: 'active-ad-bloodhound', status: 'pending', run_id: null },
                  ],
                },
                {
                  key: 'intrusive-credential',
                  label: 'Phase 3 · Intrusive Credential Validation',
                  tier: 'intrusive-credential',
                  status: 'pending',
                  requires_approval: true,
                  started_at: null,
                  completed_at: null,
                  authorization_state: { status: 'manual_approval_required', label: 'Manual approval required' },
                  steps: [{ profile_name: 'intrusive-ad-password-spray', status: 'pending', run_id: null }],
                },
                {
                  key: 'intrusive-exploitation',
                  label: 'Phase 4 · Intrusive Exploitation',
                  tier: 'intrusive-exploitation',
                  status: 'pending',
                  requires_approval: true,
                  started_at: null,
                  completed_at: null,
                  authorization_state: { status: 'manual_approval_required', label: 'Manual exploitation approval required' },
                  steps: [{ profile_name: 'intrusive-exploitation', status: 'pending', run_id: null }],
                },
              ],
            },
          };
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedEngagementId: null,
            selectedRunId: run.id,
            selectedRun: run,
            selectedTaskId: null,
            mission: {
              scope: null,
              inventory: [{
                id: 'inventory-chain-phase',
                raw_inputs_json: { run_id: run.id },
                summary_json: { host_count: 12 },
              }],
              relevance: [],
              packs: [],
              runs: [run],
              internalValidations: [],
              findingsByRun: {
                [run.id]: [
                  {
                    id: 'finding-critical-1',
                    title: 'Critical exposure',
                    severity: 'critical',
                    target_id: '10.0.20.12',
                    created_at: '2026-05-05T08:20:00Z',
                    updated_at: '2026-05-05T08:20:00Z',
                  },
                ],
              },
            },
          }, 'ui.test.chainPhaseProgress');
          missionModule.createMissionModule().renderMissionControl();
        }
        """,
        {"chainId": chain_id},
    )

    phase_strip = loaded_page.get_by_test_id("assessment-chain-phase-strip")
    expect(phase_strip).to_be_visible()
    phase_cards = phase_strip.get_by_test_id("mission-phase-card")
    expect(phase_cards).to_have_count(4)
    expect(phase_cards.nth(0)).to_contain_text("Complete")
    expect(phase_cards.nth(0)).to_contain_text("Duration 25m")
    expect(phase_cards.nth(1)).to_have_attribute("data-phase-status", "waiting")
    expect(phase_cards.nth(1)).to_have_attribute("data-phase-current", "true")
    expect(phase_cards.nth(1)).to_contain_text("Awaiting Approval")

    approval_summary = loaded_page.get_by_test_id("assessment-chain-pending-approval-summary")
    expect(approval_summary).to_be_visible()
    expect(approval_summary).to_contain_text("Ready to start Phase 2")
    expect(approval_summary).to_contain_text("12 hosts visible")
    expect(approval_summary).to_contain_text("1 critical")
    expect(approval_summary).to_contain_text("Passive Web Nuclei Audit")
    approve_button = loaded_page.get_by_test_id("assessment-chain-approve")
    expect(approve_button).to_have_text("Approve Phase 2")
    expect(approve_button).to_have_count(1)

    approve_button.click()
    expect(loaded_page.get_by_test_id("status-feed-focus")).to_contain_text(
        "Phase active-enrichment approved",
        timeout=15000,
    )
    assert decisions == [{"decision": "approved"}]


def test_mission_control_hides_chain_phase_progress_for_non_chain_runs(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const run = {
            id: '55555555-5555-4555-8555-555555555555',
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: '2026-05-05T08:00:00Z',
            updated_at: '2026-05-05T08:10:00Z',
            configuration_json: { assessment_type: 'External Web' },
            profile: { name: 'passive-web-baseline', run_class: 'passive', limits_json: {} },
            tasks: [],
          };
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedEngagementId: null,
            selectedRunId: run.id,
            selectedRun: run,
            mission: {
              scope: null,
              inventory: [],
              relevance: [],
              packs: [],
              runs: [run],
              internalValidations: [],
              findingsByRun: { [run.id]: [] },
            },
          }, 'ui.test.nonChainRun');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    expect(loaded_page.get_by_test_id("assessment-chain-panel")).to_have_count(0)
    expect(loaded_page.get_by_test_id("assessment-chain-phase-strip")).to_have_count(0)
    expect(loaded_page.get_by_test_id("mission-run-summary")).to_have_count(0)


def test_settings_collapsed_sections_show_status_summaries_and_still_toggle(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            chatgptOAuthStatus: { connected: true, status: 'connected' },
            settingsUi: { openPanels: {} },
            operatorSettings: {
              tenant_id: 'default',
              sections: [
                {
                  id: 'ai_provider',
                  title: 'AI Provider',
                  description: 'Choose provider defaults.',
                  settings: [
                    { key: 'ai.provider', value: 'chatgpt_oauth', input_type: 'select', source: 'database', configured: true, options: [], description: '' },
                    { key: 'ai.finding_enrichment_enabled', value: true, input_type: 'checkbox', source: 'database', configured: true, options: [], description: '' },
                    { key: 'ai.post_task_analysis_enabled', value: false, input_type: 'checkbox', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
                {
                  id: 'default_network_scope',
                  title: 'Default Network Scope',
                  description: 'Reusable LAN defaults.',
                  settings: [
                    { key: 'network.default_lan_cidr', label: 'Default LAN CIDR', value: '10.0.20.0/24', input_type: 'text', source: 'database', configured: true, options: [], description: '' },
                    { key: 'network.default_vlan_cidrs', label: 'Additional VLAN CIDRs', value: ['10.0.30.0/24'], input_type: 'list', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
                {
                  id: 'default_scan_profile',
                  title: 'Default Scan Profile',
                  description: 'Preferred profile.',
                  settings: [
                    { key: 'scan.default_profile', value: 'Deep', input_type: 'select', source: 'database', configured: true, options: [], description: '' },
                    { key: 'scan.default_safety_level', value: 'passive', input_type: 'select', source: 'database', configured: true, options: [], description: '' },
                    { key: 'scan.default_execution_lane', value: 'passive-network-discovery', input_type: 'select', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
                {
                  id: 'runtime_execution',
                  title: 'Runtime Execution',
                  description: 'Execution limits.',
                  settings: [
                    { key: 'runtime.inline_task_workers', value: 6, input_type: 'number', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
                {
                  id: 'integrations',
                  title: 'Integrations',
                  description: 'Handoff defaults.',
                  settings: [
                    { key: 'integrations.jira_base_url', value: null, input_type: 'url', source: 'default', configured: false, options: [], description: '' },
                    { key: 'integrations.slack_webhook_url', value: null, input_type: 'password', source: 'default', sensitive: true, configured: false, options: [], description: '' },
                  ],
                },
                {
                  id: 'notifications',
                  title: 'Notifications',
                  description: 'Alert defaults.',
                  settings: [
                    { key: 'notifications.critical_destination', value: 'slack', input_type: 'select', source: 'database', configured: true, options: [], description: '' },
                    { key: 'notifications.run_completion', value: true, input_type: 'checkbox', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
                {
                  id: 'threat_intel',
                  title: 'Threat Intel',
                  description: 'Feed defaults.',
                  settings: [
                    { key: 'threat_intel.sync_enabled', value: true, input_type: 'checkbox', source: 'database', configured: true, options: [], description: '' },
                    { key: 'threat_intel.nvd_api_key', value: null, input_type: 'password', source: 'default', sensitive: true, configured: false, options: [], description: '' },
                  ],
                },
                {
                  id: 'instance',
                  title: 'Instance',
                  description: 'Instance identity.',
                  settings: [
                    { key: 'instance.operator_display_name', label: 'Operator display name', value: 'alice-reviewer', input_type: 'text', source: 'database', configured: true, options: [], description: '' },
                    { key: 'instance.app_public_base_url', label: 'App public base URL', value: 'https://aegispt.example.test', input_type: 'url', source: 'database', configured: true, options: [], description: '' },
                  ],
                },
              ],
            },
          }, 'ui.test.settingsSummaries');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    expected_summaries = {
        "ai_provider-summary": "AI Provider: ChatGPT connected · 1 helper on",
        "default_network_scope-summary": "Default scope: 10.0.20.0/24 · 1 VLAN range",
        "default_scan_profile-summary": "Profile: Deep · passive · passive-network-discovery",
        "runtime_execution-summary": "6 parallel task workers",
        "integrations-summary": "Configure Jira and webhook handoffs",
        "notifications-summary": "Critical alerts: slack · completion on",
        "threat_intel-summary": "Daily CVE sync on · NVD key not set",
        "instance-summary": "Operator: alice-reviewer · https://aegispt.example.test",
    }
    for test_id, text in expected_summaries.items():
        expect(loaded_page.get_by_test_id(test_id)).to_be_visible()
        expect(loaded_page.get_by_test_id(test_id)).to_have_text(text)

    network_panel = loaded_page.get_by_test_id("settings-default-network-scope")
    assert network_panel.evaluate("element => element.open") is False
    network_panel.locator("summary").evaluate("summary => summary.click()")
    assert network_panel.evaluate("element => element.open") is True
    expect(network_panel.locator("[data-setting-key='network.default_lan_cidr']")).to_be_visible()
    network_panel.locator("summary").evaluate("summary => summary.click()")
    assert network_panel.evaluate("element => element.open") is False
    expect(loaded_page.get_by_test_id("default_network_scope-summary")).to_be_visible()


def test_topbar_status_chip_labels_are_simple_and_readable(loaded_page: Page) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const run = {
            id: 'run-topbar-labels',
            status: 'running',
            profile: { name: 'passive-web-baseline' },
            configuration_json: { execution_profile: 'passive-web-baseline' },
            tasks: [
              { id: 'task-running-a', status: 'running' },
              { id: 'task-running-b', status: 'running' },
              { id: 'task-queued-a', status: 'queued' },
            ],
          };
          runtimeModule.patchState({
            selectedRunId: run.id,
            selectedRun: run,
            mission: {
              ...runtimeModule.state.mission,
              runs: [run],
            },
          }, 'ui.test.topbarStatusChipLabels');
          runtimeModule.runtime.actions.renderAll({ renderScreen: false });
        }
        """
    )

    status_chip = loaded_page.get_by_test_id("topbar-run-status")
    expect(status_chip).to_be_visible()
    expect(loaded_page.get_by_test_id("topbar-run-status-label")).to_have_text("2 Running Tasks")
    chip_text = status_chip.inner_text()
    assert "·" not in chip_text
    for redundant in ("DOSSIERS", "MISSIONS", "BASELINE"):
        assert redundant not in chip_text.upper()
    assert re.match(r"^\d+\s+[A-Z][A-Za-z]+\s+[A-Z][A-Za-z]+$", chip_text)

    font_size = loaded_page.evaluate(
        "() => parseFloat(window.getComputedStyle(document.querySelector('[data-testid=\"topbar-run-status\"]')).fontSize)"
    )
    assert font_size >= 11


def test_report_center_copy_is_operator_ready_and_empty_states_are_clear(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-reports").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const reportsModule = await import('/app/assets/modules/reports.js');
          const runId = '77777777-7777-4777-8777-777777777777';
          runtimeModule.patchState({
            activeScreen: 'report-center',
            selectedEngagementId: 'eng-report-copy',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              profile: { name: 'passive-web-baseline' },
              configuration_json: {
                assessment_type: 'Website / Web App',
                targets: { urls: ['https://app.example.test'] },
                access: {},
                test_profile: 'Standard',
              },
              tasks: [],
            },
            engagements: [{
              id: 'eng-report-copy',
              name: 'Report Copy Engagement',
              client: 'Example Co',
              roe_ref: 'ROE-REPORT-COPY',
            }],
            mission: {
              runs: [],
              inventory: [],
              findingsByRun: { [runId]: [] },
            },
            reportVariant: 'technical',
            reportCenterView: 'reports',
            reportPreview: '',
            reportHtml: '',
            reportDraft: null,
            reportCatalog: [{
              variant: 'technical',
              title: 'Technical Report',
              description: 'Technical, evidence-backed report for operators.',
              source_run_id: runId,
              generated_at: new Date().toISOString(),
              available_formats: ['markdown', 'html'],
              methodology_references: ['PTES'],
              source_scope_profile: {
                run_profile: 'passive-web-baseline',
                assessment_type: 'Website / Web App',
                targets: { urls: ['https://app.example.test'] },
              },
              included_findings: { count: 0, by_severity: {}, by_status: {}, report_sections: [], test_coverage: {} },
              included_inventory: {
                host_count: 1,
                service_count: 1,
                endpoint_count: 1,
                technology_count: 1,
                wireless_access_point_count: 0,
                wireless_network_count: 0,
                confidence_score: 0.9,
              },
              evidence_status: { linked_findings: 0, total_findings: 0, completeness_ratio: 1 },
              compliance_summary: {},
              assurance_summary: {},
              adaptive_change_summary: {},
              ai_draft_summary: {},
              run_narrative_summary: {},
              version_label: 'technical-v1',
              content_sha256: 'abc123',
              availability_status: 'export_ready',
              availability_label: 'Export ready',
              availability_reason: 'Run evidence is available for export.',
              preview_allowed: true,
              export_allowed: true,
              draft_allowed: true,
              lifecycle_summary: {},
              export_paths: {
                markdown: '/api/v1/runs/' + runId + '/report?format=markdown&variant=technical',
                html: '/api/v1/runs/' + runId + '/report?format=html&variant=technical',
              },
              download_names: { markdown: 'technical.md', html: 'technical.html' },
            }],
          }, 'ui.test.reportCopy');
          reportsModule.createReportsModule().renderReportCenter();
        }
        """
    )

    screen = loaded_page.get_by_test_id("screen-report-center")
    expect(screen).to_contain_text(
        "Review and export technical, executive, and compliance reports for the selected run."
    )
    expect(loaded_page.get_by_test_id("report-preview")).to_have_text(
        "Generate a markdown preview to review this report here."
    )
    assert (
        "Generate an HTML preview to review the rendered report here."
        in (loaded_page.locator("#report-frame").get_attribute("srcdoc") or "")
    )
    expect(loaded_page.locator("#report-compare")).to_contain_text(
        "Select a previous run to compare findings, coverage, and risk score changes."
    )

    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const reportsModule = await import('/app/assets/modules/reports.js');
          runtimeModule.patchState({ reportCenterView: 'dossier' }, 'ui.test.reportCopy.dossier');
          reportsModule.createReportsModule().renderReportCenter();
        }
        """
    )
    expect(loaded_page.get_by_test_id("report-dossier-context")).to_contain_text("Engagement orientation")
    full_text = screen.inner_text()
    banned = [
        "without a side metadata rail",
        "History & Compared",
        "History & Comparison",
        "metadata rail",
        "Prior Report Delta",
        "Open Explorer Compatibility",
        "now carries",
    ]
    assert not [copy for copy in banned if copy.lower() in full_text.lower()]


def test_history_empty_single_and_two_completed_run_states_are_guided(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-history").click()

    def seed_history(runs: list[dict], selected_run_id: str | None = None, baseline_run_id: str | None = None) -> None:
        loaded_page.evaluate(
            """
            async ({ runs, selectedRunId, baselineRunId }) => {
              const runtimeModule = await import('/app/assets/modules/runtime.js');
              const historyModule = await import('/app/assets/modules/explorer-history.js');
              const selectedRun = runs.find((run) => run.id === selectedRunId) || null;
              runtimeModule.patchState({
                activeScreen: 'history',
                selectedEngagementId: 'eng-history-guidance',
                selectedRunId,
                selectedRun,
                comparisonBaselineRunId: baselineRunId,
                historyQuery: '',
                engagements: [{
                  id: 'eng-history-guidance',
                  name: 'History Guidance Engagement',
                  client: 'Example Co',
                  roe_ref: 'ROE-HISTORY',
                }],
                mission: {
                  scope: null,
                  inventory: [],
                  relevance: [],
                  packs: [],
                  runs,
                  internalValidations: [],
                  findingsByRun: Object.fromEntries(runs.map((run) => [run.id, []])),
                },
                exposureScore: { history: [] },
              }, 'ui.test.historyGuidance');
              historyModule.createExplorerHistoryModule().renderHistoryComparison();
            }
            """,
            {"runs": runs, "selectedRunId": selected_run_id, "baselineRunId": baseline_run_id},
        )

    def run(run_id: str, name: str, created_at: str, status: str = "completed") -> dict:
        return {
            "id": run_id,
            "status": status,
            "created_at": created_at,
            "updated_at": created_at,
            "profile": {"name": name},
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "targets": {"cidr_ranges": ["10.30.0.0/24"]},
                "test_profile": "Standard",
            },
            "pack_binding": {"pack_version": "standard-baseline"},
            "tasks": [],
        }

    seed_history([])
    expect(loaded_page.get_by_test_id("history-toolbar-summary")).to_contain_text(
        "0 of 0 completed runs visible"
    )
    expect(loaded_page.get_by_test_id("history-comparison-disabled")).to_contain_text(
        "Complete a second run to compare posture changes."
    )
    expect(loaded_page.locator("#history-trend")).to_contain_text(
        "Completed runs appear here after an assessment finishes."
    )
    loaded_page.get_by_test_id("history-empty-mission-control").click()
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible()

    loaded_page.get_by_test_id("nav-history").click()
    single_run = run("history-run-one", "First Completed Scan", "2026-04-30T10:00:00.000Z")
    seed_history([single_run], selected_run_id=single_run["id"])
    expect(loaded_page.get_by_test_id("history-single-run-summary")).to_contain_text(
        "One completed run available"
    )
    expect(loaded_page.get_by_test_id("history-single-run-summary")).to_contain_text(
        "First Completed Scan is ready for review"
    )
    comparison_disabled = loaded_page.get_by_test_id("history-comparison-disabled")
    expect(comparison_disabled).to_contain_text("Complete a second run to compare posture changes.")
    assert comparison_disabled.get_attribute("title") == "Complete a second run to compare posture changes."
    expect(loaded_page.locator("#history-baseline-run")).to_be_disabled()
    expect(loaded_page.get_by_test_id("history-run-card")).to_have_count(1)

    second_run = run("history-run-two", "Second Completed Scan", "2026-05-01T10:00:00.000Z")
    seed_history([second_run, single_run], selected_run_id=second_run["id"], baseline_run_id=single_run["id"])
    expect(loaded_page.get_by_test_id("history-run-card")).to_have_count(2)
    expect(loaded_page.get_by_test_id("comparison-summary")).to_contain_text("Current vs baseline")
    expect(loaded_page.get_by_test_id("comparison-inventory-delta")).to_be_visible()
    expect(loaded_page.get_by_test_id("history-comparison-disabled")).to_have_count(0)


def test_pack_forge_build_lane_panels_are_gated_by_developer_mode(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-packs").click()
    expect(loaded_page.get_by_test_id("screen-pack-forge")).to_be_visible()

    expect(loaded_page.locator("#adaptive-form")).to_be_visible()
    expect(loaded_page.get_by_test_id("pack-summary")).to_be_visible()
    expect(loaded_page.get_by_test_id("validate-pack")).to_be_visible()
    expect(loaded_page.get_by_test_id("approve-pack")).to_be_visible()
    expect(loaded_page.get_by_test_id("deploy-pack")).to_be_visible()
    expect(loaded_page.locator("#pack-forge-detail")).to_be_visible()

    expect(loaded_page.get_by_test_id("pack-build-lane-task-planner")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("pack-build-lane-output")).not_to_be_visible()
    expect(loaded_page.locator("#codex-task-form")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("prepare-codex-task")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("codex-suggestions")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("codex-pack-preview")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("codex-context")).not_to_be_visible()
    expect(loaded_page.get_by_test_id("codex-task-result")).not_to_be_visible()

    loaded_page.get_by_test_id("nav-settings").click()
    instance_panel = loaded_page.get_by_test_id("settings-instance")
    instance_panel.locator("summary").click()
    expect(loaded_page.get_by_test_id("setting-instance-build-lane-mode")).to_be_visible()
    expect(loaded_page.locator("[data-setting-key='instance.build_lane_mode']")).to_have_attribute(
        "type", "checkbox"
    )

    loaded_page.get_by_test_id("nav-packs").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const packsModule = await import('/app/assets/modules/packs.js');
          const { state, patchState } = runtimeModule;
          const payload = state.operatorSettings || { tenant_id: 'default', sections: [] };
          const sections = JSON.parse(JSON.stringify(payload.sections || []));
          let instance = sections.find((section) => section.id === 'instance');
          if (!instance) {
            instance = { id: 'instance', title: 'Instance', description: '', settings: [] };
            sections.push(instance);
          }
          let setting = (instance.settings || []).find((item) => item.key === 'instance.build_lane_mode');
          if (!setting) {
            setting = {
              key: 'instance.build_lane_mode',
              label: 'Developer build-lane mode',
              input_type: 'checkbox',
              value: false,
              source: 'test',
              description: ''
            };
            instance.settings = [...(instance.settings || []), setting];
          }
          setting.value = true;
          patchState({ operatorSettings: { ...payload, sections } }, 'ui.test.buildLaneMode');
          packsModule.createPacksModule().renderPackForge();
        }
        """
    )

    expect(loaded_page.get_by_test_id("pack-build-lane-task-planner")).to_be_visible()
    expect(loaded_page.get_by_test_id("pack-build-lane-output")).to_be_visible()
    expect(loaded_page.locator("#codex-task-form")).to_be_visible()
    expect(loaded_page.get_by_test_id("prepare-codex-task")).to_be_visible()


def test_wizard_heading_is_recommended_intake_not_mandatory_gate(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-wizard").click()

    wizard_screen = loaded_page.get_by_test_id("screen-wizard")
    expect(wizard_screen).to_be_visible()
    heading = wizard_screen.locator(".screen-head h2").first
    expect(heading).to_be_visible()
    expect(heading).not_to_contain_text(re.compile("mandatory", re.IGNORECASE))

    expect(loaded_page.get_by_test_id("nav-wizard")).to_contain_text("Intake")
    expect(loaded_page.get_by_test_id("nav-wizard")).not_to_contain_text(
        re.compile("mandatory", re.IGNORECASE)
    )
    assert not re.search(r"mandatory\s+(assessment\s+)?wizard", wizard_screen.inner_text(), re.IGNORECASE)


def test_wizard_advanced_step_labels_are_short_and_do_not_wrap(loaded_page: Page) -> None:
    loaded_page.set_viewport_size({"width": 1280, "height": 900})
    labels = loaded_page.evaluate(
        """
        async () => {
          const constants = await import('/app/assets/modules/constants.js');
          return constants.WIZARD_STEPS;
        }
        """
    )
    assert labels == ["Type", "Scope", "Access", "Profile", "Modules", "Safety", "Confirm"]
    assert all(len(label) <= 12 for label in labels)

    loaded_page.get_by_test_id("nav-wizard").click()
    advanced_toggle = loaded_page.get_by_test_id("wizard-advanced-toggle")
    expect(advanced_toggle).to_be_visible()
    advanced_toggle.click()

    drawer = loaded_page.get_by_test_id("wizard-advanced-drawer")
    expect(drawer).to_be_visible()
    advanced_buttons = drawer.locator(".advanced-nav [data-advanced-step]")
    expect(advanced_buttons).to_have_count(6)

    first_top = None
    for index, label in enumerate(labels[:6]):
        button = advanced_buttons.nth(index)
        expect(button).to_have_text(label)
        box = button.bounding_box()
        assert box is not None
        if first_top is None:
            first_top = box["y"]
        assert abs(box["y"] - first_top) < 2, f"Wizard advanced step label wrapped onto another row: {label}"
        overflow = button.evaluate("(node) => node.scrollWidth > node.clientWidth")
        assert overflow is False, f"Wizard advanced step label overflows its button: {label}"


def test_complete_assessment_wizard_cta_is_scoped_to_missing_run_context(loaded_page: Page) -> None:
    cta = loaded_page.get_by_test_id("complete-assessment-wizard-cta")

    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()
    expect(cta).to_be_visible()
    expect(cta).to_have_text("Complete Assessment Wizard")
    expect(loaded_page.get_by_test_id("nav-wizard")).to_be_visible()

    loaded_page.evaluate(
        """
        async () => {
          const { runtime } = await import('/app/assets/modules/runtime.js');
          runtime.state.activeScreen = 'dashboard';
          runtime.state.selectedRun = null;
          runtime.state.selectedRunId = null;
          runtime.state.dashboard = { active_run: null, open_problems: {}, risk_score: {} };
          runtime.state.mission = {
            scope: null,
            inventory: [],
            relevance: [],
            packs: [],
            runs: [],
            internalValidations: [],
            findingsByRun: {},
          };
          runtime.actions.renderAll();
        }
        """
    )
    expect(loaded_page.get_by_test_id("complete-assessment-wizard-cta")).to_be_visible()
    loaded_page.get_by_test_id("complete-assessment-wizard-cta").click()
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()

    run = {
        "id": "run-cta-scope",
        "status": "running",
        "profile": {"name": "passive-network-discovery"},
        "configuration_json": {"execution_profile": "passive-network-discovery"},
        "tasks": [{"id": "task-1", "status": "running", "label": "Network discovery"}],
    }
    hidden_screens = ["mission-control", "findings-theater", "report-center", "history"]
    for screen in hidden_screens:
        loaded_page.evaluate(
            """
            async ({ screen, run }) => {
              const { runtime } = await import('/app/assets/modules/runtime.js');
              runtime.state.activeScreen = screen;
              runtime.state.selectedRun = run;
              runtime.state.selectedRunId = run.id;
              runtime.state.dashboard = {
                active_run: { id: run.id, status: run.status, tasks_running: 1 },
                open_problems: {},
                risk_score: {},
              };
              runtime.state.mission = {
                scope: null,
                inventory: [],
                relevance: [],
                packs: [],
                runs: [run],
                internalValidations: [],
                findingsByRun: {},
              };
              runtime.actions.renderAll();
            }
            """,
            {"screen": screen, "run": run},
        )
        expect(loaded_page.get_by_test_id("complete-assessment-wizard-cta")).to_have_count(0)

    loaded_page.get_by_test_id("nav-wizard").click()
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()


def test_mission_control_header_button_intent_classes(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()

    action_order = loaded_page.locator("#screen-mission-control .screen-head .screen-actions > button").evaluate_all(
        "(nodes) => nodes.map((node) => node.getAttribute('data-testid') || node.id || node.textContent.trim())"
    )
    assert action_order == [
        "mission-kill-run",
        "mission-dispatch-btn",
        "mission-view-findings",
        "mission-view-agents",
        "cinema-mode-open",
    ]

    view_agents = loaded_page.get_by_test_id("mission-view-agents")
    expect(view_agents).to_be_visible()
    expect(view_agents).to_have_text("View Agents ↗")
    assert view_agents.get_attribute("data-nav-screen") == "agents"
    view_agents_classes = view_agents.get_attribute("class") or ""
    assert "danger" not in view_agents_classes
    assert any(token in view_agents_classes.split() for token in ("secondary", "ghost"))
    dangerous_nav_buttons = loaded_page.locator(".screen-head [data-nav-screen].danger").evaluate_all(
        "(nodes) => nodes.map((node) => node.getAttribute('data-testid') || node.textContent.trim())"
    )
    assert dangerous_nav_buttons == []

    kill_run = loaded_page.get_by_test_id("mission-kill-run")
    expect(kill_run).to_be_visible()
    kill_run_classes = kill_run.get_attribute("class") or ""
    assert "danger" in kill_run_classes.split()

    dispatch = loaded_page.locator("#mission-dispatch-btn")
    dispatch_classes = dispatch.get_attribute("class") or ""
    assert "primary" in dispatch_classes.split()

    view_findings = loaded_page.get_by_test_id("mission-view-findings")
    view_findings_classes = view_findings.get_attribute("class") or ""
    assert "primary" in view_findings_classes.split()

    cinema = loaded_page.get_by_test_id("cinema-mode-open")
    cinema_classes = cinema.get_attribute("class") or ""
    assert "ghost" in cinema_classes.split()

    view_agents.click()
    expect(loaded_page.get_by_test_id("screen-agents")).to_be_visible()


def test_mission_control_ai_signal_provider_badge_and_live_text(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '11111111-1111-4111-8111-111111111111';
          const taskId = '22222222-2222-4222-8222-222222222222';
          Object.defineProperty(window, 'EventSource', { value: undefined, configurable: true });
          runtimeModule.patchState({
            selectedRunId: runId,
            selectedTaskId: taskId,
            selectedAiInsights: {
              run_id: runId,
              post_task_analysis_enabled: true,
              provider: 'chatgpt_oauth',
              provider_status: { mode: 'chatgpt_oauth', label: 'ChatGPT connected', status: 'connected', connected: true },
              reasoning_records: [],
              proposals: [],
              review_boundary: {},
              operator_workbench: {
                title: 'AI Operator Workbench',
                provider: { mode: 'chatgpt_oauth', label: 'ChatGPT connected', status: 'connected', connected: true, ready: true },
                summary: { signals: 1, pending_repair_proposals: 0, build_lane_tasks: 1, post_task_analysis_enabled: true },
                features: {
                  signal_inbox: { enabled: true, count: 1 },
                  repair_proposals: { enabled: true, pending: 0, created: 0 },
                  finding_enrichment: { enabled: true },
                  report_draft: { enabled: true },
                  build_lane_handoff: { enabled: true, created: 1 },
                },
                signals: [{ id: 'signal-1', kind: 'live_ai_signal', status: 'succeeded', title: 'Live AI signal' }],
                build_lane_tasks: [{
                  codex_task_id: 'task-20260430120000-ai-repair-build-lane-fix-demo',
                  task_file: 'codex/tasks/task-20260430120000-ai-repair-build-lane-fix-demo.json',
                  title: 'Repair fixture runner',
                  creates_runtime_tasks: false,
                }],
                boundary: {
                  active_runtime_mutated: false,
                  dispatches_work: false,
                  creates_runtime_tasks: false,
                  can_create_build_lane_tasks: true,
                  message: 'AI can create build-lane handoffs without mutating active runtime.',
                },
              },
            },
            selectedRun: {
              id: runId,
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
              tasks: [{
                id: taskId,
                tool: 'nmap',
                target_id: '10.0.20.0/24',
                status: 'completed',
                params_json: { target_kind: 'cidr' },
                created_at: now,
                updated_at: now,
              }],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {
                available: true,
                summary: 'Deterministic guidance remains available.',
                provider: { status: 'connected', name: 'chatgpt_oauth' },
              },
            },
            selectedAiSignalStream: {
              runId,
              taskId,
              status: 'streaming',
              text: 'Synthetic streamed AI Signal text for the selected task.',
              provider: { mode: 'chatgpt_oauth', label: 'ChatGPT connected', status: 'connected', connected: true },
              startedAt: now,
              updatedAt: now,
            },
          }, 'ui.test.aiSignalProvider');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    expect(loaded_page.get_by_test_id("ai-signal-provider-badge")).to_contain_text("ChatGPT connected")
    expect(loaded_page.get_by_test_id("ai-operator-workbench")).to_contain_text("AI Review Workspace")
    expect(loaded_page.get_by_test_id("ai-operator-workbench")).to_contain_text(
        "AI can create review handoffs without changing the active run."
    )
    expect(loaded_page.get_by_test_id("ai-workbench-provider-status")).to_contain_text("ChatGPT connected")
    expect(loaded_page.get_by_test_id("ai-workbench-build-lane-task")).to_contain_text("codex/tasks/")
    expect(loaded_page.get_by_test_id("ai-workbench-signal-row")).to_contain_text("Live AI signal")
    expect(loaded_page.get_by_test_id("ai-signal-stream")).to_contain_text("Synthetic streamed AI Signal text")
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).not_to_contain_text("DETERMINISTIC MODE")
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).not_to_contain_text("BUILD LANE")
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).not_to_contain_text("PROVIDER")
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).not_to_contain_text("SIGNALS")
    expect(loaded_page.get_by_test_id("mission-ai-signal-panel")).not_to_contain_text("REPAIRS")


def test_mission_control_ai_signal_select_run_when_chatgpt_connected_without_run(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          runtimeModule.patchState({
            selectedRunId: null,
            selectedRun: null,
            selectedTaskId: null,
            selectedAiInsights: null,
            selectedAiSignalStream: null,
            operatorSettings: {
              sections: [{
                id: 'ai_provider',
                settings: [{ key: 'ai.provider', value: 'chatgpt_oauth' }],
              }],
            },
            chatgptOAuthStatus: { connected: true, status: 'connected' },
          }, 'ui.test.aiSignalNoRunConnected');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    panel = loaded_page.get_by_test_id("mission-ai-signal-panel")
    expect(panel).to_contain_text("ChatGPT connected")
    expect(panel).to_contain_text("Select a run to see AI analysis.")
    expect(panel).not_to_contain_text("Connect ChatGPT in Settings")
    expect(panel).not_to_contain_text("AI Review Workspace")
    expect(panel).not_to_contain_text("AI Signal Inbox")


def test_mission_control_ai_signal_connect_chatgpt_when_provider_disconnected_without_run(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          runtimeModule.patchState({
            selectedRunId: null,
            selectedRun: null,
            selectedTaskId: null,
            selectedAiInsights: null,
            selectedAiSignalStream: null,
            operatorSettings: {
              sections: [{
                id: 'ai_provider',
                settings: [{ key: 'ai.provider', value: 'chatgpt_oauth' }],
              }],
            },
            chatgptOAuthStatus: { connected: false, status: 'not_connected' },
          }, 'ui.test.aiSignalNoRunDisconnected');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    panel = loaded_page.get_by_test_id("mission-ai-signal-panel")
    expect(panel).to_contain_text("Select a run to see AI analysis.")
    expect(panel).not_to_contain_text("Connect ChatGPT in Settings")
    expect(loaded_page.get_by_test_id("ai-signal-open-settings")).to_have_count(0)


def test_mission_control_phase_badges_expose_nfir_tooltips(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '77777777-7777-4777-8777-777777777777';
          runtimeModule.patchState({
            selectedRunId: runId,
            selectedTaskId: null,
            selectedRun: {
              id: runId,
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'full-internal-lan', run_class: 'active', limits_json: {} },
              tasks: [],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
              assessment_chain: {
                id: '88888888-8888-4888-8888-888888888888',
                status: 'active',
                assessment_mode: 'FULL-INTERNAL-LAN',
                current_phase_index: 1,
                phase_count: 4,
                completed_phase_count: 1,
                auto_advance_on_phase_complete: true,
                phases: [
                  {
                    key: 'phase-1',
                    label: 'Phase 1 · Passive Discovery',
                    status: 'completed',
                    authorization_state: { status: 'pre_authorized', label: 'Pre-authorized at launch' },
                    steps: [{ profile_name: 'passive-network-discovery', status: 'completed' }],
                  },
                  {
                    key: 'phase-2',
                    label: 'Phase 2 · Active Enrichment',
                    status: 'active',
                    authorization_state: { status: 'auto_advancing', label: 'Auto-advance authorized' },
                    steps: [{ profile_name: 'passive-web-nuclei-audit', tool: 'nuclei', status: 'running' }],
                  },
                  {
                    key: 'phase-3',
                    label: 'Phase 3 · Intrusive Credential Validation',
                    status: 'pending',
                    authorization_state: { status: 'waiting_on_prerequisite', label: 'Waiting on prerequisite' },
                    steps: [{ profile_name: 'active-ad-kerberoast', tool: 'bloodhound', status: 'pending' }],
                  },
                  {
                    key: 'phase-4',
                    label: 'Phase 4 · Intrusive Exploitation',
                    status: 'pending',
                    authorization_state: { status: 'manual_approval_required', label: 'Manual exploitation approval required' },
                    steps: [{ profile_name: 'intrusive-exploitation', tool: 'metasploit', status: 'pending' }],
                  },
                ],
              },
            },
          }, 'ui.test.nfirPhaseTooltips');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    phase_cards = loaded_page.get_by_test_id("mission-phase-card")
    expect(phase_cards.first).to_have_attribute("data-nfir-phase-label", "NFIR Phase 2 - Intelligence Gathering")
    expect(phase_cards.nth(1)).to_have_attribute("data-nfir-phase-label", "NFIR Phase 3 - Vulnerability Analysis")
    expect(phase_cards.nth(2)).to_have_attribute("data-nfir-phase-label", "NFIR Phase 5 - Post-Exploitation")
    expect(phase_cards.first).to_have_attribute("data-phase-auth-status", "pre_authorized")
    expect(phase_cards.nth(1)).to_have_attribute("data-phase-auth-status", "auto_advancing")
    expect(phase_cards.nth(3)).to_have_attribute("data-phase-auth-status", "manual_approval_required")
    expect(phase_cards.nth(3)).to_contain_text("Manual exploitation approval required")
    expect(phase_cards.nth(3)).to_have_attribute("title", re.compile("NFIR mapping: NFIR Phase 4"))


def test_dashboard_activity_feed_renders_human_readable_audit_items(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-dashboard").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const dashboardModule = await import('/app/assets/modules/dashboard.js');
          const now = new Date().toISOString();
          runtimeModule.patchState({
            activeScreen: 'dashboard',
            selectedEngagementId: '55555555-5555-4555-8555-555555555555',
            dashboard: {
              generated_at: now,
              has_engagements: true,
              active_run: null,
              risk_score: { score: 0, trend: 'stable', severity_breakdown: {}, history: [], advisory_note: 'Advisory only.' },
              open_problems: { critical: 0, high: 0, medium: 0, total: 0, overdue_critical_count: 0, overdue_high_count: 0 },
              upcoming_scans: [],
              recent_activity: [],
              activity_feed: [{
                id: 'audit-1',
                timestamp: now,
                label: 'Run started',
                icon: 'play',
                engagement_name: 'Activity Feed Demo',
                detail: 'passive-web-baseline',
              }],
              quick_actions: [],
              setup_checklist: [],
              engagements: [],
            },
          }, 'ui.test.dashboardActivityFeed');
          dashboardModule.createDashboardModule().renderDashboard();
        }
        """
    )

    expect(loaded_page.get_by_test_id("dashboard-recent-activity")).to_contain_text("Run started")
    expect(loaded_page.get_by_test_id("dashboard-recent-activity")).not_to_contain_text("run.dispatched")


def test_dashboard_zero_engagement_renders_first_run_empty_state(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-dashboard").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const dashboardModule = await import('/app/assets/modules/dashboard.js');
          const now = new Date().toISOString();
          runtimeModule.patchState({
            activeScreen: 'dashboard',
            selectedEngagementId: null,
            dashboard: {
              generated_at: now,
              has_engagements: false,
              active_run: null,
              risk_score: { score: 0, trend: 'stable', severity_breakdown: {}, history: [], advisory_note: 'Advisory only.' },
              open_problems: { critical: 0, high: 0, medium: 0, total: 0, overdue_critical_count: 0, overdue_high_count: 0 },
              upcoming_scans: [],
              recent_activity: [],
              activity_feed: [],
              quick_actions: [{ id: 'new-mission', label: 'New Mission', target_screen: 'wizard', enabled: true, description: 'Start intake.' }],
              setup_checklist_dismissed: false,
              setup_checklist: [{ id: 'first-run', label: 'Stale checklist item', done: false, detail: 'Should not render.' }],
              first_run_onboarding: {
                show: true,
                title: 'Start AegisPT in three steps',
                detail: 'Connect optional AI, create a scoped engagement, then run the first safe scan.',
                cards: [
                  { id: 'chatgpt-oauth', label: 'Connect ChatGPT OAuth', done: false, detail: 'Optional AI.', target_screen: 'settings' },
                  { id: 'create-engagement', label: 'Create your first engagement', done: false, detail: 'Use Intake.', target_screen: 'wizard' },
                  { id: 'run-first-scan', label: 'Run your first scan', done: false, detail: 'Open Mission Control after launch.', target_screen: 'wizard' },
                ],
              },
              engagements: [],
            },
          }, 'ui.test.dashboardFirstRun');
          dashboardModule.createDashboardModule().renderDashboard();
        }
        """
    )

    empty_state = loaded_page.get_by_test_id("dashboard-first-run-empty-state")
    expect(empty_state).to_be_visible()
    expect(empty_state).to_contain_text("Welcome to AegisPT")
    expect(empty_state).to_contain_text("Create a scoped assessment to collect evidence, track findings, and produce reports.")
    expect(loaded_page.get_by_test_id("dashboard-start-first-assessment")).to_have_text("Start Your First Assessment")
    expect(loaded_page.get_by_test_id("dashboard-zero-active-runs")).to_contain_text("0")
    expect(loaded_page.get_by_test_id("dashboard-zero-open-findings")).to_contain_text("0")
    expect(loaded_page.get_by_test_id("dashboard-zero-engagements")).to_contain_text("0")
    expect(loaded_page.get_by_test_id("dashboard-first-run-onboarding")).to_have_count(0)
    expect(loaded_page.get_by_test_id("dashboard-setup-checklist")).to_have_count(0)
    expect(loaded_page.get_by_test_id("dashboard-command-strip")).to_have_count(0)

    loaded_page.get_by_test_id("dashboard-start-first-assessment").click()
    expect(loaded_page.get_by_test_id("screen-wizard")).to_be_visible()


def test_dashboard_setup_checklist_dismiss_persists_in_settings(loaded_page: Page) -> None:
    dismissed_dashboard = {
        "generated_at": "2026-04-29T10:00:00+00:00",
        "has_engagements": True,
        "active_run": None,
        "risk_score": {"score": 0, "trend": "stable", "severity_breakdown": {}, "history": [], "advisory_note": "Advisory only."},
        "open_problems": {"critical": 0, "high": 0, "medium": 0, "total": 0, "overdue_critical_count": 0, "overdue_high_count": 0},
        "upcoming_scans": [],
        "recent_activity": [],
        "activity_feed": [],
        "quick_actions": [],
        "setup_checklist_dismissed": True,
        "setup_checklist": [],
        "first_run_onboarding": None,
        "engagements": [],
    }
    updated_settings = {
        "tenant_id": "default",
        "sections": [
            {
                "id": "instance",
                "title": "Instance",
                "description": "Instance settings",
                "settings": [
                    {
                        "key": "instance.setup_checklist_dismissed",
                        "label": "Setup checklist dismissed",
                        "value": True,
                        "input_type": "checkbox",
                        "source": "database",
                        "sensitive": False,
                        "configured": True,
                    }
                ],
            }
        ],
        "sensitive_plaintext_exposed": False,
    }

    loaded_page.route(
        "**/api/v1/settings",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(updated_settings),
        )
        if route.request.method == "PATCH"
        else route.continue_(),
    )
    loaded_page.route(
        "**/api/v1/dashboard**",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(dismissed_dashboard),
        ),
    )
    loaded_page.get_by_test_id("nav-dashboard").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const dashboardModule = await import('/app/assets/modules/dashboard.js');
          const now = new Date().toISOString();
          runtimeModule.patchState({
            activeScreen: 'dashboard',
            selectedEngagementId: '55555555-5555-4555-8555-555555555555',
            dashboard: {
              generated_at: now,
              has_engagements: true,
              active_run: null,
              risk_score: { score: 0, trend: 'stable', severity_breakdown: {}, history: [], advisory_note: 'Advisory only.' },
              open_problems: { critical: 0, high: 0, medium: 0, total: 0, overdue_critical_count: 0, overdue_high_count: 0 },
              upcoming_scans: [],
              recent_activity: [],
              activity_feed: [],
              quick_actions: [],
              setup_checklist_dismissed: false,
              setup_checklist: [
                { id: 'ai-provider', label: 'AI provider', done: false, detail: 'Disabled until configured' },
                { id: 'first-mission', label: 'First mission', done: true, detail: 'Engagement inventory exists' },
                { id: 'first-run', label: 'First completed scan', done: false, detail: 'Launch and finish a safe run' },
                { id: 'problem-review', label: 'Review first finding', done: false, detail: 'Open Findings after evidence lands' },
              ],
              first_run_onboarding: null,
              engagements: [],
            },
          }, 'ui.test.dashboardDismiss');
          dashboardModule.createDashboardModule().renderDashboard();
        }
        """
    )

    expect(loaded_page.get_by_test_id("dashboard-setup-checklist")).to_be_visible()
    loaded_page.get_by_test_id("dashboard-dismiss-checklist").click()
    expect(loaded_page.get_by_test_id("dashboard-setup-checklist")).to_have_count(0)


def test_settings_readiness_panel_exposes_tools_and_export(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            operatorSettings: { tenant_id: 'default', sections: [] },
            settingsUi: { openPanels: { runtime_readiness: true } },
            settingsReadinessLoading: false,
            settingsReadinessError: null,
            settingsReadiness: {
              tenant_id: 'default',
              generated_at: new Date().toISOString(),
              overall_status: 'degraded',
              artifact: { kind: 'aegispt.settings_readiness', tenant_id: 'default' },
              capabilities: [
                {
                  id: 'runtime_concurrency',
                  title: 'Runtime concurrency',
                  status: 'ready',
                  summary: '6 inline task workers configured.',
                  details: ['Minimum 1, maximum 32, default 4.', 'Applies to newly dispatched inline tasks.'],
                  operator_next_step: 'Tune workers when checks are too slow.',
                  affected_assessment_families: [],
                  metadata: { current: 6, min: 1, max: 32 },
                },
                {
                  id: 'tool_readiness',
                  title: 'Pentest tool readiness',
                  status: 'degraded',
                  summary: '1 optional tool group is not installed.',
                  details: ['3 of 4 tracked tool groups detected.'],
                  operator_next_step: 'Use missing tool rows as checklist.',
                  affected_assessment_families: ['Exploit confirmation'],
                  metadata: {},
                },
                {
                  id: 'wireless_readiness',
                  title: 'Wireless adapter readiness',
                  status: 'ready',
                  summary: '1 wireless adapter detected and passive WiFi tooling is available.',
                  details: ['Foundation WiFi support is passive-only.', 'No deauth, capture, WPS brute force, jamming, or rogue AP actions are enabled.'],
                  operator_next_step: 'Use passive WiFi survey only with explicit site, SSID/BSSID allowlist, adapter context, and wireless ROE.',
                  affected_assessment_families: ['WiFi discovery', 'Wireless security review'],
                  metadata: { detected_adapters: ['wlan0'], safe_parallelism_limit: 1 },
                },
                {
                  id: 'deployment_hardening',
                  title: 'Production deployment hardening',
                  status: 'blocked',
                  summary: 'Production deployment hardening has 2 blocking gaps.',
                  details: [
                    'Public base URL uses HTTPS: no.',
                    'TLS reverse proxy declared: no.',
                    'Secure browser cookies declared: no.',
                  ],
                  operator_next_step: 'Resolve blocking deployment gaps before treating this host as enterprise-production ready.',
                  affected_assessment_families: ['Enterprise deployment', 'Offline update operations'],
                  metadata: { production_like: true, secrets_plaintext_exposed: false },
                },
                {
                  id: 'ai_provider',
                  title: 'AI provider and ChatGPT OAuth',
                  status: 'degraded',
                  summary: 'AI provider is disabled.',
                  details: ['Feature toggles enabled: no.'],
                  operator_next_step: 'Select ChatGPT OAuth and connect an engagement-scoped account.',
                  affected_assessment_families: [],
                  metadata: {
                    provider: 'disabled',
                    actions: [
                      {
                        id: 'enable_chatgpt_oauth_provider',
                        kind: 'setting_patch',
                        label: 'Enable ChatGPT OAuth',
                        settings_patch: { 'ai.provider': 'chatgpt_oauth' },
                        safety_note: 'Writes provider configuration only.',
                      },
                    ],
                  },
                },
              ],
              tools: [
                {
                  id: 'nmap',
                  title: 'Nmap',
                  binary_names: ['nmap'],
                  required_binary_groups: [['nmap']],
                  missing_binaries: [],
                  required: true,
                  installed: true,
                  detected_path: '/usr/bin/nmap',
                  detected_paths: { nmap: '/usr/bin/nmap' },
                  status: 'ready',
                  affected_assessment_families: ['LAN discovery'],
                  operator_next_step: 'Ready.',
                  repair_command: 'sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh',
                },
                {
                  id: 'wifi',
                  title: 'WiFi analysis tools',
                  binary_names: ['iw', 'airodump-ng', 'aircrack-ng'],
                  required_binary_groups: [['iw'], ['airodump-ng'], ['aircrack-ng']],
                  missing_binaries: [],
                  required: false,
                  installed: true,
                  detected_path: '/usr/bin/iw',
                  detected_paths: { iw: '/usr/bin/iw' },
                  status: 'ready',
                  affected_assessment_families: ['WiFi discovery', 'Wireless security review'],
                  operator_next_step: 'Ready for passive fixture or authorized hardware evidence.',
                  repair_command: 'sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh',
                  hardware_required: true,
                },
                {
                  id: 'metasploit',
                  title: 'Metasploit',
                  binary_names: ['msfconsole', 'msfrpcd'],
                  required_binary_groups: [['msfconsole'], ['msfrpcd']],
                  missing_binaries: ['msfconsole', 'msfrpcd'],
                  required: false,
                  installed: false,
                  detected_path: null,
                  detected_paths: {},
                  status: 'degraded',
                  affected_assessment_families: ['Exploit confirmation'],
                  operator_next_step: 'Install Metasploit before exploit confirmation. Missing: msfconsole, msfrpcd.',
                  repair_command: 'sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh',
                  repair_action_label: 'Copy Install/Repair Command',
                },
              ],
            },
          }, 'ui.test.settingsReadiness');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    panel = loaded_page.get_by_test_id("settings-readiness-panel")
    expect(panel).to_contain_text("Runtime Readiness")
    expect(panel).to_contain_text("inline task workers configured")
    expect(panel).to_contain_text("Wireless adapter readiness")
    expect(panel).to_contain_text("Foundation WiFi support is passive-only")
    expect(panel).to_contain_text("Production deployment hardening")
    expect(panel).to_contain_text("AI provider and ChatGPT OAuth")
    expect(panel).to_contain_text("Enable ChatGPT OAuth")
    tool_readiness = loaded_page.get_by_test_id("settings-tool-readiness")
    expect(tool_readiness).to_contain_text("Metasploit")
    expect(tool_readiness).to_contain_text("WiFi analysis tools")
    expect(tool_readiness).to_contain_text("Exploit confirmation")
    expect(tool_readiness).to_contain_text("sudo bash scripts/install_security_tools.sh")
    expect(loaded_page.get_by_test_id("settings-tool-repair-command").first).to_be_visible()
    expect(loaded_page.get_by_test_id("settings-readiness-export")).to_be_visible()


def test_settings_diagnostics_panel_exposes_subsystems_failures_and_bundle_export(
    loaded_page: Page,
) -> None:
    diagnostics = {
        "tenant_id": "default",
        "generated_at": "2026-05-02T08:00:00Z",
        "overall_status": "degraded",
        "support_bundle_endpoint": "/api/v1/diagnostics/support-bundle",
        "subsystems": [
            {
                "id": "app_health",
                "title": "App health",
                "status": "ready",
                "summary": "FastAPI app responds to local health checks.",
                "details": ["/health/live is reachable."],
                "operator_next_step": "No action required.",
                "metadata": {},
            },
            {
                "id": "worker_dispatch",
                "title": "Worker and dispatch",
                "status": "degraded",
                "summary": "Inline dispatch is active; queued work depends on the web process.",
                "details": ["TASK_DISPATCH_MODE=inline"],
                "operator_next_step": "Use Settings > Runtime Readiness before starting long runs.",
                "metadata": {},
            },
            {
                "id": "feed_sync",
                "title": "Threat feed sync",
                "status": "blocked",
                "summary": "Last feed sync was rate limited.",
                "details": ["Retry window is visible to support."],
                "operator_next_step": "Wait for the provider retry window or disable the feed temporarily.",
                "metadata": {},
            },
            {
                "id": "deployment_hardening",
                "title": "Production deployment hardening",
                "status": "blocked",
                "summary": "Production deployment hardening has 2 blocking gaps.",
                "details": ["Public base URL uses HTTPS: no.", "Secure browser cookies declared: no."],
                "operator_next_step": "Resolve blocking deployment gaps before rollout.",
                "metadata": {"secrets_plaintext_exposed": False},
            },
        ],
        "recent_failures": [
            {
                "subsystem": "feed_sync",
                "status": "blocked",
                "summary": "CVE feed returned HTTP 429.",
                "object_type": "feed_sync",
                "object_id": "nvd",
                "occurred_at": "2026-05-02T08:01:00Z",
                "operator_next_step": "Retry after the provider limit resets.",
            },
        ],
    }
    loaded_page.route(
        "**/api/v1/diagnostics",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(diagnostics),
        ),
    )
    loaded_page.get_by_test_id("nav-settings").click()

    panel = loaded_page.get_by_test_id("settings-diagnostics-panel")
    expect(panel).to_contain_text("Support Diagnostics")
    expect(panel).to_contain_text("App health")
    expect(panel).to_contain_text("Worker and dispatch")
    expect(panel).to_contain_text("Threat feed sync")
    expect(panel).to_contain_text("Production deployment hardening")
    expect(panel).to_contain_text("Resolve blocking deployment gaps")
    expect(panel).to_contain_text("CVE feed returned HTTP 429")
    expect(panel).to_contain_text("Retry after the provider limit resets")
    expect(loaded_page.get_by_test_id("settings-support-bundle-export")).to_be_visible()


def test_settings_scheduled_scans_panel_exposes_required_fields(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          const engagementId = '12121212-1212-4121-8121-121212121212';
          runtimeModule.patchState({
            activeScreen: 'settings',
            selectedEngagementId: engagementId,
            engagements: [{ id: engagementId, name: 'Scheduled Demo', client: 'Acme' }],
            runProfiles: [
              { id: 'p1', name: 'passive-web-baseline', run_class: 'passive', limits_json: {} },
              { id: 'p2', name: 'active-web-safe', run_class: 'active', limits_json: {} },
            ],
            mission: {
              scope: { allowlist_json: { urls: ['https://example.com'] }, denylist_json: {} },
              inventory: [],
              relevance: [],
              packs: [],
              runs: [],
              internalValidations: [],
              findingsByRun: {},
            },
            scheduledRuns: [{
              id: 's1',
              engagement_id: engagementId,
              profile_name: 'passive-web-baseline',
              cadence: 'daily',
              status: 'enabled',
              next_run_at: new Date().toISOString(),
            }],
            operatorSettings: { tenant_id: 'default', sections: [] },
          }, 'ui.test.scheduledScansPanel');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    panel = loaded_page.get_by_test_id("settings-scheduled-scans-panel")
    expect(panel).to_contain_text("Scheduled Scans")
    expect(panel).to_contain_text("passive-web-baseline")
    expect(panel).not_to_contain_text("active-web-safe")
    expect(loaded_page.get_by_test_id("settings-schedule-form")).to_contain_text("Frequency")


def test_settings_threat_intel_nvd_rate_limit_hint_focuses_api_key_field(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            operatorSettings: {
              tenant_id: 'default',
              sections: [{
                id: 'threat_intel',
                title: 'Threat Intel',
                description: 'Threat intel feed settings.',
                settings: [{
                  key: 'threat_intel.nvd_api_key',
                  label: 'NVD API key',
                  source: 'operator',
                  input_type: 'text',
                  value: '',
                  sensitive: true,
                  configured: false,
                  read_only: false,
                  description: 'Optional NVD API key.',
                }],
              }],
            },
            settingsUi: { openPanels: { threat_intel_controls: true, threat_intel: false } },
            threatIntelStatus: {
              sources: [
                {
                  source: 'nvd',
                  label: 'NVD',
                  status: 'failed',
                  imported_count: 0,
                  updated_count: 0,
                  skipped_count: 0,
                  error: 'Provider returned HTTP 429',
                  metadata: { reason: 'rate_limited', http_status: 429 },
                },
              ],
            },
            threatIntelWatchlist: [],
            threatIntelRecords: [],
          }, 'ui.test.nvdRateLimitHint');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    source_card = loaded_page.get_by_test_id("threat-intel-source-nvd")
    expect(source_card).to_contain_text("Provider returned HTTP 429")
    expect(loaded_page.get_by_test_id("nvd-rate-limit-api-key-hint")).to_contain_text(
        "NVD rate-limits unauthenticated requests"
    )

    loaded_page.get_by_test_id("nvd-rate-limit-api-key-focus").click(force=True)
    expect(loaded_page.get_by_test_id("settings-threat-intel")).to_have_js_property("open", True)
    expect(loaded_page.locator('[data-setting-key="threat_intel.nvd_api_key"]')).to_be_focused()


def test_surface_map_renders_hosts_from_service_only_inventory_and_counts_tabs(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-attack-map").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '61616161-6161-4161-8161-616161616161';
          const snapshotId = '62626262-6262-4262-8262-626262626262';
          const run = {
            id: runId,
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: now,
            updated_at: now,
            configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
            profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
            tasks: [],
            findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
          };
          runtimeModule.patchState({
            activeScreen: 'surface-map',
            selectedEngagementId: '60606060-6060-4060-8060-606060606060',
            selectedRunId: runId,
            selectedRun: run,
            selectedAttackPathSummary: null,
            mission: {
              scope: { allowlist_json: { cidr_ranges: ['10.0.20.0/24'] }, denylist_json: {} },
              runs: [run],
              relevance: [],
              packs: [],
              internalValidations: [],
              findingsByRun: { [runId]: [] },
              inventory: [{
                id: snapshotId,
                engagement_id: '60606060-6060-4060-8060-606060606060',
                summary_json: { host_count: 0, service_count: 2, endpoint_count: 0, technology_count: 0 },
                raw_inputs_json: { run_id: runId },
                source_tools_json: ['nmap'],
                environment_notes_json: [],
                assumptions_json: [],
                confidence_score: 0.8,
                normalized_inventory_json: {
                  hosts: [],
                  services: [
                    { host: '10.0.20.10', port: 22, protocol: 'tcp', service: 'ssh', source: 'nmap', confidence: 0.8 },
                    { host: '10.0.20.11', port: 445, protocol: 'tcp', service: 'smb', source: 'nmap', confidence: 0.75 },
                  ],
                  http_endpoints: [],
                  technologies: [],
                  vendor_product_fingerprints: [],
                },
              }],
            },
            surfaceAssetFilter: 'all',
            surfaceAssetQuery: '',
            selectedSurfaceAssetKey: null,
          }, 'ui.test.surfaceMapServiceInventory');
          missionModule.createMissionModule().renderSurfaceMap();
        }
        """
    )

    canvas = loaded_page.locator("#surface-map-canvas")
    expect(canvas).to_contain_text("10.0.20.10")
    expect(canvas).to_contain_text("10.0.20.11")
    expect(canvas).to_contain_text("Derived from mapped services")
    expect(loaded_page.get_by_test_id("surface-browser-summary")).to_contain_text("2 total asset records")
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("Services (2)")
    expect(loaded_page.get_by_test_id("surface-asset-browser")).to_contain_text("Hosts (0)")
    expect(loaded_page.locator("#surface-insights")).to_contain_text("2 hosts or network objects")


def test_surface_map_empty_state_names_discovery_run_that_populates_it(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-attack-map").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '63636363-6363-4363-8363-636363636363';
          const run = {
            id: runId,
            status: 'completed',
            requested_by: 'operator-ui',
            created_at: now,
            updated_at: now,
            configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
            profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
            tasks: [],
            findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
          };
          runtimeModule.patchState({
            activeScreen: 'surface-map',
            selectedRunId: runId,
            selectedRun: run,
            mission: {
              scope: { allowlist_json: { cidr_ranges: ['10.0.20.0/24'] }, denylist_json: {} },
              runs: [run],
              relevance: [],
              packs: [],
              internalValidations: [],
              findingsByRun: { [runId]: [] },
              inventory: [],
            },
            selectedAttackPathSummary: null,
          }, 'ui.test.surfaceMapEmptyDiscoveryGuidance');
          missionModule.createMissionModule().renderSurfaceMap();
        }
        """
    )

    empty_state = loaded_page.get_by_test_id("surface-map-empty-state")
    expect(empty_state).to_contain_text("No inventory snapshot is available for this run yet")
    expect(empty_state).to_contain_text("Run a Passive Network Discovery scan to map your assets here")


def test_settings_jira_panel_exposes_configuration_fields(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            selectedEngagementId: '11111111-1111-4111-8111-111111111111',
            operatorSettings: {
              tenant_id: 'default',
              sections: [],
            },
            jiraIntegrationConfiguration: {
              id: '66666666-6666-4666-8666-666666666666',
              display_name: 'Security Jira',
              base_url: 'https://jira.example.test',
              project_key: 'AEGIS',
              auth_ref: 'secret://engagements/acme/jira-token',
              settings_json: { auth_method: 'api_token', issue_type: 'Bug' },
            },
            settingsUi: { openPanels: { engagement_jira: true } },
          }, 'ui.test.jiraSettings');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    panel = loaded_page.get_by_test_id("settings-jira-panel")
    expect(panel).to_contain_text("Jira Handoff")
    expect(loaded_page.get_by_test_id("settings-jira-form")).to_contain_text("Base URL")
    expect(loaded_page.get_by_test_id("settings-jira-test")).to_be_enabled()


def test_findings_jira_unconfigured_does_not_fetch_missing_integration(loaded_page: Page) -> None:
    jira_requests = []

    def handle_jira_config(route, request) -> None:
        jira_requests.append(request.method)
        route.fulfill(status=404, content_type="application/json", body='{"detail":"not configured"}')

    loaded_page.route("**/api/v1/engagements/*/integrations/jira", handle_jira_config)
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js');
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'SQL Injection',
            severity: 'critical',
            target_id: 'https://portal.example.test/graphql',
            evidence_ref: 'artifact://nuclei/sql',
            status: 'open',
            summary: 'SQL injection evidence is stored.',
            finding_origin: 'standard',
            methodology_tags: ['OWASP-WSTG'],
          };
          runtimeModule.runtime.actions.loadSelectedFinding = async () => {};
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            selectedEngagementId: '11111111-1111-4111-8111-111111111111',
            operatorSettings: {
              tenant_id: 'default',
              sections: [{
                id: 'integrations',
                settings: [{ key: 'integrations.jira_base_url', value: '' }],
              }],
            },
            jiraIntegrationLoadedEngagementId: null,
            jiraIntegrationConfiguration: null,
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...runtimeModule.state.mission,
              runs: [{
                id: runId,
                status: 'completed',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 0,
              confidence_label: 'high',
              exploitability: 'confirmed',
              business_impact: 'Stored exploit evidence needs remediation tracking.',
              technical_details: 'Stored evidence exists.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Immediate',
                summary: 'Fix the injection point.',
                detail: 'Patch and retest.',
                integrations: {},
              },
              verification_status: 'evidence-linked',
              next_steps: ['Configure Jira when engineering handoff is needed.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingJiraUnconfiguredNoFetch');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-jira-not-configured")).to_contain_text(
        "Configure Jira in Settings"
    )
    assert jira_requests == []


def test_findings_jira_configured_fetch_still_enables_handoff(loaded_page: Page) -> None:
    jira_requests = []

    def handle_jira_config(route, request) -> None:
        jira_requests.append(request.method)
        route.fulfill(
            status=200,
            content_type="application/json",
            body="""{
              "id": "66666666-6666-4666-8666-666666666666",
              "integration_type": "jira",
              "display_name": "Security Jira",
              "base_url": "https://jira.example.test",
              "project_key": "AEGIS",
              "auth_ref": "secret://engagements/acme/jira-token",
              "settings_json": {"issue_type": "Bug"}
            }""",
        )

    loaded_page.route("**/api/v1/engagements/*/integrations/jira", handle_jira_config)
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js');
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'SQL Injection',
            severity: 'critical',
            target_id: 'https://portal.example.test/graphql',
            evidence_ref: 'artifact://nuclei/sql',
            status: 'open',
            summary: 'SQL injection evidence is stored.',
            finding_origin: 'standard',
            methodology_tags: ['OWASP-WSTG'],
          };
          runtimeModule.runtime.actions.loadSelectedFinding = async () => {};
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            selectedEngagementId: '11111111-1111-4111-8111-111111111111',
            operatorSettings: {
              tenant_id: 'default',
              sections: [{
                id: 'integrations',
                settings: [{ key: 'integrations.jira_base_url', value: 'https://jira.example.test' }],
              }],
            },
            jiraIntegrationLoadedEngagementId: null,
            jiraIntegrationConfiguration: null,
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...runtimeModule.state.mission,
              runs: [{
                id: runId,
                status: 'completed',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 0,
              confidence_label: 'high',
              exploitability: 'confirmed',
              business_impact: 'Stored exploit evidence needs remediation tracking.',
              technical_details: 'Stored evidence exists.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Immediate',
                summary: 'Fix the injection point.',
                detail: 'Patch and retest.',
                integrations: {},
              },
              verification_status: 'evidence-linked',
              next_steps: ['Push to Jira for engineering triage.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingJiraConfiguredFetch');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-push-jira")).to_be_visible()
    assert jira_requests == ["GET"]


def test_topbar_role_badge_and_settings_users_panel_render(loaded_page: Page) -> None:
    expect(loaded_page.get_by_test_id("topbar-role-badge")).to_contain_text("admin")
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            currentActor: { actor_name: 'admin-ui', role: 'admin', auth_method: 'api_key' },
            operatorSettings: { tenant_id: 'default', sections: [] },
            apiKeys: [
              {
                id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                actor_name: 'review-ui',
                role: 'reviewer',
                created_at: new Date().toISOString(),
                last_used_at: null,
                revoked_at: null,
              },
            ],
            apiKeysLoading: false,
            apiKeysError: null,
            apiKeyCreateResult: {
              actor_name: 'operator-ui',
              role: 'operator',
              api_key: 'aegispt_visible_once',
            },
          }, 'ui.test.usersPanel');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    users_panel = loaded_page.get_by_test_id("settings-users-panel")
    expect(users_panel).to_contain_text("Users & API Keys")
    expect(users_panel).to_contain_text("review-ui")
    expect(users_panel).to_contain_text("reviewer")
    expect(loaded_page.get_by_test_id("settings-api-key-create-form")).to_contain_text("Create Key")
    expect(loaded_page.get_by_test_id("settings-api-key-create-result")).to_contain_text("aegispt_visible_once")


def test_settings_enterprise_identity_panel_shows_sso_and_session_state(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-settings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const settingsModule = await import('/app/assets/modules/settings.js');
          runtimeModule.patchState({
            activeScreen: 'settings',
            currentActor: { actor_name: 'admin-ui', role: 'admin', auth_method: 'x_actor_fallback' },
            operatorSettings: {
              tenant_id: 'default',
              sections: [{
                id: 'enterprise_identity',
                title: 'Enterprise Identity',
                description: 'SSO settings.',
                settings: [
                  {
                    key: 'identity.enterprise_sso_provider',
                    label: 'Enterprise SSO provider',
                    value: 'disabled',
                    input_type: 'select',
                    source: 'default',
                    options: [
                      { value: 'disabled', label: 'Disabled' },
                      { value: 'oidc', label: 'OIDC' },
                      { value: 'saml', label: 'SAML' },
                    ],
                  },
                  {
                    key: 'identity.session_timeout_minutes',
                    label: 'Session timeout minutes',
                    value: 480,
                    input_type: 'number',
                    source: 'default',
                    min_value: 5,
                    max_value: 1440,
                    step: 1,
                  },
                ],
              }],
            },
            enterpriseIdentityStatus: {
              tenant_id: 'default',
              provider: 'disabled',
              status: 'disabled',
              configured: false,
              summary: 'Enterprise SSO is disabled; local development fallback and API keys remain active.',
              operator_next_step: 'Configure OIDC or SAML when this host needs enterprise sign-in controls.',
              missing_fields: [],
              configured_secret_labels: [],
              session_policy: {
                timeout_minutes: 480,
                logout_redirect_url: null,
                server_session_enforced: false,
                local_fallback_has_server_session: false,
              },
              local_auth: {
                warning: 'Local X-Actor fallback is for supervised local/dev use and is not enterprise authentication.',
              },
              access_boundaries: {
                browser_sso: {
                  status: 'disabled',
                  summary: 'Enterprise browser SSO is disabled; local fallback and API-key auth are the active paths.',
                },
                tenant_membership: {
                  status: 'blocked',
                  summary: 'X-Tenant-ID narrows tenant-scoped records, but there is no authenticated tenant membership model yet.',
                },
                role_enforcement: {
                  status: 'enforced',
                  summary: 'API-key admin/operator/reviewer roles are enforced by protected endpoints.',
                },
                session_enforcement: {
                  status: 'configured_not_enforced',
                  summary: 'Session timeout and logout policy are visible and audit-backed, but local fallback has no server session.',
                },
                scim: {
                  status: 'unsupported',
                  summary: 'SCIM provisioning is not implemented in this slice.',
                },
                tenant_admin: {
                  status: 'unsupported',
                  summary: 'Tenant administration and tenant switching are not implemented in this slice.',
                },
              },
              current_actor: { actor_name: 'admin-ui', role: 'admin', auth_method: 'x_actor_fallback' },
              users: [
                { actor_name: 'admin-ui', role: 'admin', auth_method: 'x_actor_fallback', status: 'active', source: 'current_request', last_seen_at: null },
                { actor_name: 'integration-runner', role: 'operator', auth_method: 'api_key', status: 'active', source: 'api_key', last_seen_at: null },
              ],
              metadata: {
                full_sso_login_enabled: false,
                enterprise_ready: false,
                readiness_boundary: 'local_dev_identity_only',
              },
            },
            enterpriseIdentityLoading: false,
            enterpriseIdentityError: null,
            enterpriseIdentityLogoutResult: {
              message: 'Logout recorded. Local fallback has no server session; active runs were not changed.',
            },
            settingsUi: { openPanels: { enterprise_identity: true } },
          }, 'ui.test.enterpriseIdentity');
          settingsModule.createSettingsModule().renderSettingsScreen();
        }
        """
    )

    panel = loaded_page.get_by_test_id("settings-enterprise-identity-panel")
    expect(panel).to_contain_text("Enterprise Identity")
    expect(panel).to_contain_text("disabled")
    expect(panel).to_contain_text("480 minute timeout")
    expect(panel).to_contain_text("Local X-Actor fallback")
    expect(panel).to_contain_text("Enterprise Boundary Proof")
    expect(panel).to_contain_text("Tenant Membership")
    expect(panel).to_contain_text("blocked")
    expect(panel).to_contain_text("Role Enforcement")
    expect(panel).to_contain_text("enforced")
    expect(panel).to_contain_text("SCIM Provisioning")
    expect(panel).to_contain_text("unsupported")
    expect(panel).to_contain_text("integration-runner")
    expect(loaded_page.get_by_test_id("settings-enterprise-identity")).to_be_visible()
    expect(loaded_page.locator("[data-setting-key='identity.session_timeout_minutes']")).to_have_attribute("min", "5")
    expect(loaded_page.get_by_test_id("settings-identity-logout-result")).to_contain_text("active runs were not changed")


def test_mission_control_drift_summary_banner_renders(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '31313131-3131-4131-8131-313131313131';
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedRunId: runId,
            selectedTaskId: null,
            selectedRun: {
              id: runId,
              status: 'completed',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { urls: ['https://example.com'] } },
              profile: { name: 'passive-web-baseline', run_class: 'passive', limits_json: {} },
              tasks: [],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
              drift_summary: {
                id: '41414141-4141-4141-8141-414141414141',
                run_id: runId,
                previous_run_id: '51515151-5151-4151-8151-515151515151',
                new_finding_count: 2,
                resolved_finding_count: 1,
                exposure_delta: -5,
                computed_at: now,
              },
            },
          }, 'ui.test.driftSummary');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    banner = loaded_page.get_by_test_id("mission-drift-summary")
    expect(banner).to_contain_text("Change since previous baseline")
    expect(banner).to_contain_text("2 new findings")
    expect(banner).to_contain_text("1 resolved")


def test_mission_control_running_task_stdout_shows_live_indicator(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '66666666-6666-4666-8666-666666666666';
          const taskId = '77777777-7777-4777-8777-777777777777';
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedRunId: runId,
            selectedTaskId: taskId,
            selectedRun: {
              id: runId,
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
              tasks: [{
                id: taskId,
                tool: 'nmap',
                target_id: '10.0.20.0/24',
                status: 'running',
                params_json: { target_kind: 'cidr', profile_name: 'passive-network-discovery' },
                created_at: now,
                updated_at: now,
              }],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
            },
            selectedTask: {
              id: taskId,
              run_id: runId,
              tool: 'nmap',
              target_id: '10.0.20.0/24',
              status: 'running',
              params_json: { target_kind: 'cidr', profile_name: 'passive-network-discovery' },
              created_at: now,
              updated_at: now,
              executions: [],
            },
            taskStdoutStream: {
              source: null,
              taskId,
              status: 'running',
              sourceLabel: 'runner-buffer',
              fallbackReason: null,
              lines: [{ sequence: 1, text: 'nmap scan report for 10.0.20.1' }],
              lineCount: 1,
              truncated: false,
              terminal: false,
              lastEventAt: now,
            },
          }, 'ui.test.liveTaskStdout');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    expect(loaded_page.get_by_test_id("mission-task-stdout-live-indicator")).to_contain_text("Live")
    expect(loaded_page.get_by_test_id("mission-task-stdout-output")).to_contain_text("nmap scan report")


def test_mission_control_background_update_preserves_operator_text_selection(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    result = loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '67676767-6767-4676-8676-676767676767';
          const taskId = '78787878-7878-4787-8787-787878787878';
          const staleRecovery = {
            available: true,
            eligible_task_ids: [taskId],
            blocked_reasons: [],
            threshold_minutes: 10,
            operator_summary: 'This run has stale running task rows that can be closed with audit evidence.',
          };
          const staleTaskRecovery = {
            eligible: true,
            blocked_reasons: [],
            age_minutes: 31,
            threshold_minutes: 10,
            has_execution_evidence: false,
            operator_summary: 'This running task appears stale.',
          };
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedRunId: runId,
            selectedTaskId: taskId,
            selectedRun: {
              id: runId,
              status: 'cancelling',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
              tasks: [{
                id: taskId,
                tool: 'nmap',
                target_id: '10.0.20.0/24',
                status: 'running',
                params_json: { target_kind: 'cidr', profile_name: 'passive-network-discovery' },
                stale_recovery: staleTaskRecovery,
                created_at: now,
                updated_at: now,
              }],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
              stale_recovery: staleRecovery,
            },
            selectedTask: {
              id: taskId,
              run_id: runId,
              tool: 'nmap',
              target_id: '10.0.20.0/24',
              status: 'running',
              params_json: { target_kind: 'cidr', profile_name: 'passive-network-discovery' },
              created_at: now,
              updated_at: now,
              executions: [],
            },
            taskStdoutStream: {
              source: null,
              taskId,
              status: 'running',
              sourceLabel: 'runner-buffer',
              fallbackReason: null,
              lines: [{ sequence: 1, text: 'copyable operator evidence line' }],
              lineCount: 1,
              truncated: false,
              terminal: false,
              lastEventAt: now,
            },
          }, 'ui.test.selectionPreservation');
          missionModule.createMissionModule().renderMissionControl();
          const output = document.querySelector('[data-testid="mission-task-stdout-output"]');
          output.dataset.selectionProbe = 'kept';
          const range = document.createRange();
          range.selectNodeContents(output);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          runtimeModule.runtime.actions.renderAll({ background: true });
          return {
            selectedText: window.getSelection().toString(),
            probe: document.querySelector('[data-testid="mission-task-stdout-output"]')?.dataset.selectionProbe || '',
            staleNotice: document.querySelector('[data-testid="mission-stale-recovery-notice"]')?.textContent || '',
          };
        }
        """
    )

    assert "copyable operator evidence line" in result["selectedText"]
    assert result["probe"] == "kept"
    assert "Stale running task detected" in result["staleNotice"]


def test_wifi_mission_control_and_report_center_surface_wireless_context(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '88888888-8888-4888-8888-888888888888';
          const taskId = '99999999-9999-4999-8999-999999999999';
          const task = {
            id: taskId,
            run_id: runId,
            tool: 'wifi-survey',
            target_id: 'HQ-Amsterdam',
            status: 'running',
            params_json: {
              target_kind: 'wireless-site',
              profile_name: 'passive-wifi-survey',
              site: 'HQ-Amsterdam',
              adapter: 'wlan0',
              approved_ssids: ['CorpWiFi'],
              approved_bssids: ['aa:bb:cc:dd:ee:ff'],
              passive_only: true,
              rf_disruptive_actions: false,
            },
            created_at: now,
            updated_at: now,
            executions: [],
          };
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedRunId: runId,
            selectedTaskId: taskId,
            selectedRun: {
              id: runId,
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: {
                assessment_type: 'WiFi / Wireless',
                targets: { wireless_sites: ['HQ-Amsterdam'], ssids: ['CorpWiFi'], bssids: ['aa:bb:cc:dd:ee:ff'] },
              },
              profile: { name: 'passive-wifi-survey', run_class: 'passive', limits_json: {} },
              tasks: [task],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
            },
            selectedTask: task,
            taskStdoutStream: {
              source: null,
              taskId,
              status: 'running',
              sourceLabel: 'runner-buffer',
              fallbackReason: null,
              lines: [{ sequence: 1, text: 'wifi-survey: passive evidence imported for site HQ-Amsterdam using adapter context wlan0' }],
              lineCount: 1,
              truncated: false,
              terminal: false,
              lastEventAt: now,
            },
          }, 'ui.test.wifiMissionControl');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    expect(loaded_page.get_by_test_id("mission-task-focus")).to_contain_text("WiFi passive survey")
    expect(loaded_page.get_by_test_id("mission-wireless-task-focus")).to_contain_text("wlan0")
    expect(loaded_page.get_by_test_id("mission-wireless-task-focus")).to_contain_text("CorpWiFi")
    expect(loaded_page.get_by_test_id("mission-wireless-task-focus")).to_contain_text("Passive only")
    expect(loaded_page.get_by_test_id("mission-task-stdout-output")).to_contain_text("passive evidence imported")

    loaded_page.get_by_test_id("nav-reports").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const reportsModule = await import('/app/assets/modules/reports.js');
          const runId = '88888888-8888-4888-8888-888888888888';
          runtimeModule.patchState({
            activeScreen: 'report-center',
            selectedRunId: runId,
            reportVariant: 'technical',
            reportCenterView: 'reports',
            reportPreview: '## WiFi Security Summary\\n\\n- Wireless Networks Observed: 1\\n- Boundary: passive evidence only; no deauthentication, jamming, evil-twin, handshake capture, WPS brute force, or credential harvesting was performed.',
            reportHtml: '',
            reportCatalog: [{
              variant: 'technical',
              title: 'Technical Report',
              description: 'Technical report with WiFi Security Summary.',
              source_run_id: runId,
              generated_at: new Date().toISOString(),
              available_formats: ['markdown', 'html'],
              methodology_references: ['PTES'],
              source_scope_profile: { run_profile: 'passive-wifi-survey', assessment_type: 'WiFi / Wireless', targets: { wireless_sites: ['HQ-Amsterdam'] } },
              included_findings: { count: 1, by_severity: { info: 1 }, by_status: { open: 1 }, report_sections: ['wifi_security_summary'], test_coverage: {} },
              included_inventory: { host_count: 0, service_count: 0, endpoint_count: 0, technology_count: 0, wireless_access_point_count: 1, wireless_network_count: 1, confidence_score: 0.84 },
              evidence_status: { linked_findings: 1, total_findings: 1, completeness_ratio: 1 },
              compliance_summary: {},
              assurance_summary: {},
              adaptive_change_summary: {},
              ai_draft_summary: {},
              run_narrative_summary: {},
              version_label: 'technical-wifi',
              content_sha256: 'abcd',
              availability_status: 'export_ready',
              availability_label: 'Export ready',
              availability_reason: 'Wireless evidence is available for export.',
              preview_allowed: true,
              export_allowed: true,
              draft_allowed: true,
              lifecycle_summary: {},
              export_paths: { markdown: '/api/v1/runs/' + runId + '/report?format=markdown&variant=technical', html: '/api/v1/runs/' + runId + '/report?format=html&variant=technical' },
              download_names: { markdown: 'wifi.md', html: 'wifi.html' },
            }],
          }, 'ui.test.wifiReportCenter');
          reportsModule.createReportsModule().renderReportCenter();
        }
        """
    )

    expect(loaded_page.get_by_test_id("report-card")).to_contain_text("Technical Report")
    expect(loaded_page.get_by_test_id("report-metadata")).to_contain_text("WiFi APs 1")
    expect(loaded_page.get_by_test_id("report-preview")).to_contain_text("WiFi Security Summary")


def test_mission_control_chain_gap_keeps_tasks_panel_actionable_without_task_cards(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const missionModule = await import('/app/assets/modules/mission-control.js');
          const now = new Date().toISOString();
          const runId = '12121212-1212-4212-8212-121212121212';
          runtimeModule.patchState({
            activeScreen: 'mission-control',
            selectedRunId: runId,
            selectedTaskId: null,
            selectedRun: {
              id: runId,
              status: 'completed_with_errors',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'full-internal-lan', run_class: 'active', limits_json: {} },
              tasks: [],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
              assessment_chain: {
                id: '13131313-1313-4313-8313-131313131313',
                status: 'completed_with_gaps',
                assessment_mode: 'FULL-INTERNAL-LAN',
                current_phase_index: 1,
                current_step_index: 3,
                phase_count: 4,
                completed_phase_count: 2,
                auto_advance_on_phase_complete: true,
                operator_state: {
                  status: 'completed_with_gaps',
                  now: { phase_label: 'Phase 2 · Active Enrichment', profile_name: 'passive-web-baseline', status: 'skipped' },
                  next: null,
                  primary_action: 'Review Gaps',
                  safe_next_action: 'Review skipped checks and relaunch only the missing coverage with the required prerequisites.',
                  skipped_count: 1,
                  failed_count: 0,
                  running_count: 0,
                  pending_count: 0,
                },
                phases: [
                  {
                    key: 'passive-discovery',
                    label: 'Phase 1 · Passive Discovery',
                    status: 'completed',
                    steps: [{ profile_name: 'passive-network-discovery', status: 'completed' }],
                  },
                  {
                    key: 'active-enrichment',
                    label: 'Phase 2 · Active Enrichment',
                    status: 'completed_with_gaps',
                    steps: [{
                      profile_name: 'passive-web-baseline',
                      status: 'skipped',
                      skip_reason: 'passive-web-baseline had no in-scope targets to queue',
                      prerequisite: 'web target inventory',
                      evidence: 'No URL targets were discovered.',
                      safe_next_action: 'Continue with the remaining planned checks; add matching in-scope targets in a new mission if this coverage is required.',
                    }],
                  },
                ],
              },
            },
          }, 'ui.test.chainLifecycleFallback');
          missionModule.createMissionModule().renderMissionControl();
        }
        """
    )

    expect(loaded_page.get_by_test_id("assessment-chain-panel")).to_contain_text("finished every runnable check")
    expect(loaded_page.get_by_test_id("mission-chain-lifecycle-fallback")).to_contain_text("Review Gaps")
    expect(loaded_page.get_by_test_id("mission-run-activity")).not_to_contain_text("no execution tasks were queued")
    expect(loaded_page.get_by_test_id("assessment-chain-phase-runners")).to_contain_text("Safe next action")


def test_live_agents_prioritizes_running_task_and_uses_dispatch_label(loaded_page: Page) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const now = new Date().toISOString();
          const runId = '14141414-1414-4414-8414-141414141414';
          const runningTask = '15151515-1515-4515-8515-151515151515';
          runtimeModule.patchState({
            selectedRunId: runId,
            selectedTaskId: runningTask,
            selectedRun: {
              id: runId,
              status: 'running',
              requested_by: 'operator-ui',
              created_at: now,
              updated_at: now,
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
              tasks: [
                {
                  id: '16161616-1616-4616-8616-161616161616',
                  tool: 'nmap',
                  target_id: '10.0.20.1',
                  status: 'queued',
                  params_json: { profile_name: 'passive-network-discovery' },
                  created_at: now,
                  updated_at: now,
                },
                {
                  id: runningTask,
                  tool: 'nmap',
                  target_id: '10.0.20.2',
                  status: 'running',
                  params_json: { profile_name: 'passive-network-discovery' },
                  created_at: now,
                  updated_at: now,
                },
              ],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
            },
            selectedTask: null,
            taskStdoutStream: {
              taskId: runningTask,
              status: 'running',
              sourceLabel: 'runner-buffer',
              lines: [{ sequence: 1, text: 'Starting Nmap against 10.0.20.2' }],
              lineCount: 1,
              truncated: false,
              terminal: false,
              lastEventAt: now,
            },
          }, 'ui.test.liveAgentsRunning');
        }
        """
    )
    loaded_page.evaluate("() => document.querySelector('[data-testid=\"bottom-nav-agents\"]')?.click()")

    expect(loaded_page.get_by_test_id("agents-live-focus")).to_contain_text("10.0.20.2")
    expect(loaded_page.get_by_test_id("agents-live-terminal")).to_contain_text("Starting Nmap")
    expect(loaded_page.get_by_test_id("screen-agents")).not_to_contain_text("Start Validation")


def test_cinema_elapsed_uses_terminal_timestamps_without_redrawing_shell(loaded_page: Page) -> None:
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const runId = '17171717-1717-4717-8717-171717171717';
          runtimeModule.patchState({
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              requested_by: 'operator-ui',
              created_at: '2026-04-30T10:00:00.000Z',
              started_at: '2026-04-30T10:00:00.000Z',
              completed_at: '2026-04-30T10:07:00.000Z',
              updated_at: '2026-04-30T10:07:00.000Z',
              configuration_json: { targets: { cidr_ranges: ['10.0.20.0/24'] } },
              profile: { name: 'passive-network-discovery', run_class: 'passive', limits_json: {} },
              tasks: [{
                id: '18181818-1818-4818-8818-181818181818',
                tool: 'nmap',
                target_id: '10.0.20.1',
                status: 'completed',
                params_json: {},
                created_at: '2026-04-30T10:00:00.000Z',
                updated_at: '2026-04-30T10:07:00.000Z',
              }],
              findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
              ai_mission_guidance: {},
            },
            runStream: { status: 'connected', runId },
          }, 'ui.test.cinemaElapsed');
        }
        """
    )
    loaded_page.evaluate("() => document.querySelector('[data-testid=\"cinema-mode-open\"]')?.click()")
    shell = loaded_page.get_by_test_id("cinema-overlay")
    expect(shell).to_contain_text("7m")
    loaded_page.evaluate("() => { window.__aegisCinemaShell = document.querySelector('#c1'); }")
    loaded_page.wait_for_timeout(2200)
    assert loaded_page.evaluate("() => window.__aegisCinemaShell === document.querySelector('#c1')")


def test_findings_drawer_ai_enrichment_status_badge(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260429-auto-enrichment-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'Missing Security Header',
            severity: 'medium',
            target_id: 'https://portal.example.test',
            evidence_ref: 'artifact://headers/security',
            status: 'open',
            summary: 'The response did not include a hardening header.',
            finding_origin: 'standard',
            methodology_tags: [],
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'running',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'running',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 2,
              confidence_label: 'medium',
              exploitability: 'limited',
              business_impact: 'Fallback impact.',
              technical_details: 'Fallback technical context.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Routine',
                summary: 'Fix the affected control.',
                detail: 'Retest after remediation.',
              },
              ai_enrichment: {
                status: 'succeeded',
                available: true,
                provider: 'chatgpt_oauth',
                label: 'Enriched by chatgpt_oauth',
                business_impact: 'Customer-facing clickjacking risk is reduced by fixing this header.',
                technical_context: 'Stored response evidence shows the header was absent.',
                remediation_narrative: 'Add the missing security header and retest the affected endpoint.',
              },
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingAiEnrichment');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-ai-enrichment-status")).to_contain_text(
        "Enriched by chatgpt_oauth"
    )
    expect(loaded_page.get_by_test_id("finding-ai-enrichment")).to_contain_text(
        "Customer-facing clickjacking risk"
    )


def test_findings_drawer_shows_quality_cvss_owasp_and_reproduce(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260504-finding-quality-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'SQL Injection',
            severity: 'critical',
            target_id: 'https://portal.example.test/api/login',
            evidence_ref: 'artifact://nuclei/sql',
            status: 'open',
            summary: 'SQL injection evidence is stored.',
            finding_origin: 'standard',
            cvss_score: 9.8,
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            cvss_source: 'nvd-cache',
            owasp_framework: 'OWASP API Security Top 10 2023',
            owasp_category: 'API8: Security Misconfiguration',
            owasp_reference: 'OWASP-API8',
            owasp_mapping: {
              framework: 'OWASP API Security Top 10 2023',
              category: 'API8: Security Misconfiguration',
              reference: 'OWASP-API8',
              source: 'deterministic-finding-type',
            },
            proof_reference: {
              label: 'Reproduce from stored evidence',
              evidence_ref: 'artifact://nuclei/sql',
              replay_recipe_available: true,
              tool: 'nuclei',
              target: 'https://portal.example.test/api/login',
            },
            methodology_tags: ['api', 'injection', 'owasp-api8'],
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'completed',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 0,
              confidence_label: 'high',
              exploitability: 'operator-validated',
              business_impact: 'The login API may expose customer account data.',
              technical_details: 'Stored evidence supports SQL injection review.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {
                owasp: finding.owasp_mapping,
                methodology_tags: finding.methodology_tags,
              },
              remediation: {
                priority: 'Immediate',
                summary: 'Use parameterized database access.',
                detail: 'Retest the exact endpoint after remediation.',
              },
              ai_enrichment: {
                status: 'succeeded',
                available: true,
                provider: 'chatgpt_oauth',
                label: 'Enriched by chatgpt_oauth',
                business_impact: 'The login API may expose customer account data.',
                technical_context: 'Stored evidence supports SQL injection review.',
                remediation_narrative: '1. Replace string-built SQL with parameterized queries. 2. Add regression tests. 3. Retest this endpoint.',
              },
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingQualityDrawer');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-cvss-gauge")).to_contain_text("9.8")
    expect(loaded_page.get_by_test_id("finding-cvss-gauge")).to_contain_text("nvd-cache")
    expect(loaded_page.get_by_test_id("finding-owasp-badge")).to_contain_text("API8")
    expect(loaded_page.get_by_test_id("finding-proof-reference")).to_contain_text(
        "artifact://nuclei/sql"
    )
    expect(loaded_page.get_by_test_id("finding-reproduce-button")).to_be_visible()


def test_findings_drawer_ai_enrichment_unavailable_can_be_started_when_provider_ready(
    loaded_page: Page,
) -> None:
    finding_id = "44444444-4444-4444-8444-444444444444"
    enrich_requests: list[str] = []

    def handle_enrich(route) -> None:
        enrich_requests.append(route.request.method)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "status": "enriching",
                    "available": False,
                    "provider": "chatgpt_oauth",
                    "label": "Enriching",
                    "updated_at": "2026-04-30T10:08:00.000Z",
                    "metadata": {"background": True},
                }
            ),
        )

    loaded_page.route(f"**/api/v1/findings/{finding_id}/ai-enrich", handle_enrich)
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        f"""
        async () => {{
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260429-auto-enrichment-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {{
            id: '{finding_id}',
            title: 'Missing Security Header',
            severity: 'medium',
            target_id: 'https://portal.example.test',
            evidence_ref: 'artifact://headers/security',
            status: 'open',
            summary: 'The response did not include a hardening header.',
            finding_origin: 'standard',
            methodology_tags: [],
          }};
          runtimeModule.patchState({{
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {{
              id: runId,
              status: 'running',
              tasks: [],
              configuration_json: {{}},
              profile: {{ name: 'ui-test-run' }},
              ai_mission_guidance: {{ provider: {{ status: 'connected', name: 'chatgpt_oauth' }} }},
            }},
            selectedAiInsights: {{
              provider_status: {{ mode: 'chatgpt_oauth', label: 'ChatGPT connected', status: 'connected', connected: true }},
            }},
            chatgptOAuthStatus: {{ connected: true, status: 'connected' }},
            operatorSettings: {{
              tenant_id: 'default',
              sections: [{{
                id: 'ai_provider',
                settings: [
                  {{ key: 'ai.provider', value: 'chatgpt_oauth' }},
                  {{ key: 'ai.finding_enrichment_enabled', value: true }},
                ],
              }}],
            }},
            mission: {{
              ...state.mission,
              runs: [{{
                id: runId,
                status: 'running',
                tasks: [],
                configuration_json: {{}},
                profile: {{ name: 'ui-test-run' }},
              }}],
              findingsByRun: {{ [runId]: [finding] }},
            }},
            selectedFindingId: finding.id,
            selectedFindingTheater: {{
              finding,
              severity_rank: 2,
              confidence_label: 'medium',
              exploitability: 'limited',
              business_impact: 'Fallback impact.',
              technical_details: 'Fallback technical context.',
              evidence_summary: 'Evidence is linked.',
              provenance: {{ origin: 'standard' }},
              methodology: {{}},
              remediation: {{
                priority: 'Routine',
                summary: 'Fix the affected control.',
                detail: 'Retest after remediation.',
              }},
              ai_enrichment: {{
                status: 'unavailable',
                available: false,
                provider: 'disabled',
                label: 'Enrichment unavailable',
                failure_reason: 'No AI provider is configured for finding enrichment.',
              }},
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {{}},
            }},
            selectedFindingEvidence: {{ related_executions: [], artifacts: [] }},
          }}, 'ui.test.findingAiEnrichUnavailable');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({{ ...item, _runId: runId }}));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }}
        """
    )

    expect(loaded_page.get_by_test_id("finding-ai-enrichment-status")).to_contain_text("Not yet enriched")
    expect(loaded_page.get_by_test_id("finding-ai-enrichment")).to_contain_text("This finding has not been enriched yet.")
    loaded_page.get_by_test_id("finding-ai-enrich-now").click()
    expect(loaded_page.get_by_test_id("finding-ai-enrichment-status")).to_contain_text("Enriching")
    assert enrich_requests == ["POST"]


def test_findings_drawer_ai_autofix_disclaimer_and_suggestion(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260429-ai-autofix-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'SQL Injection',
            severity: 'critical',
            target_id: 'https://portal.example.test/graphql',
            evidence_ref: 'artifact://nuclei/sql',
            status: 'open',
            summary: 'SQL injection evidence is stored.',
            finding_origin: 'standard',
            methodology_tags: ['CWE-89'],
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'running',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'running',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 0,
              confidence_label: 'high',
              exploitability: 'confirmed',
              business_impact: 'Stored exploit evidence needs remediation tracking.',
              technical_details: 'Stored evidence exists.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Immediate',
                summary: 'Fix the injection point.',
                detail: 'Patch and retest.',
              },
              autofix: {
                available: true,
                enabled: true,
                provider: 'chatgpt_oauth',
                model: 'gpt-5.4',
                confidence: 'high',
                patch_language: 'javascript',
                patch_before: 'const sql = `SELECT * FROM users WHERE email = ${email}`;',
                patch_after: 'const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);',
                patch_explanation: 'Use Express parameter binding for the login lookup.',
                verification_command: 'npm test -- --runInBand security',
                ai_generated: true,
                ai_fix_suggestion: 'const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);',
                disclaimer: 'This is an AI-generated suggestion. Review before applying. Do not apply to production without testing.',
              },
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingAiAutofix');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-autofix")).to_contain_text("AI-generated remediation suggestion")
    expect(loaded_page.get_by_test_id("finding-autofix-ai-disclaimer")).to_contain_text(
        "Do not apply to production without testing"
    )
    expect(loaded_page.get_by_test_id("finding-autofix-diff")).to_contain_text("db.execute")


def test_findings_drawer_autofix_disabled_state_links_to_settings(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260501-ai-autofix-disabled-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333334';
          const finding = {
            id: '44444444-4444-4444-8444-444444444445',
            title: 'Missing Security Header',
            severity: 'medium',
            target_id: 'https://portal.example.test',
            evidence_ref: 'artifact://headers/security',
            status: 'open',
            summary: 'The response did not include a hardening header.',
            finding_origin: 'standard',
            methodology_tags: [],
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'completed',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 2,
              confidence_label: 'medium',
              exploitability: 'limited',
              business_impact: 'Fallback impact.',
              technical_details: 'Fallback technical context.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Routine',
                summary: 'Fix the affected control.',
                detail: 'Retest after remediation.',
              },
              autofix: {
                available: false,
                enabled: false,
                advisory_only: true,
                detail: 'AutoFix is disabled for this deployment.',
              },
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingAiAutofixDisabled');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-autofix")).to_contain_text("AutoFix is disabled")
    expect(loaded_page.get_by_test_id("finding-autofix")).to_contain_text(
        "enable in Settings > AI Provider"
    )
    expect(loaded_page.get_by_test_id("finding-autofix-settings")).to_be_visible()


def test_findings_drawer_autofix_enabled_without_suggestion_explains_rerun(
    loaded_page: Page,
) -> None:
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js?v=20260501-ai-autofix-empty-1');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333335';
          const finding = {
            id: '44444444-4444-4444-8444-444444444446',
            title: 'Weak TLS Configuration',
            severity: 'low',
            target_id: 'https://portal.example.test',
            evidence_ref: 'artifact://tls/config',
            status: 'open',
            summary: 'TLS hardening guidance is needed.',
            finding_origin: 'standard',
            methodology_tags: [],
          };
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'completed',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'completed',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 3,
              confidence_label: 'medium',
              exploitability: 'limited',
              business_impact: 'Fallback impact.',
              technical_details: 'Fallback technical context.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Routine',
                summary: 'Fix the affected control.',
                detail: 'Retest after remediation.',
              },
              autofix: {
                available: false,
                enabled: true,
                advisory_only: true,
                detail: 'No advisory patch has been generated for this finding yet.',
              },
              verification_status: 'evidence-linked',
              next_steps: ['Review remediation guidance.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingAiAutofixNoSuggestion');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    expect(loaded_page.get_by_test_id("finding-autofix")).to_contain_text("AutoFix suggested fix")
    expect(loaded_page.get_by_test_id("finding-autofix")).to_contain_text(
        "No suggestion available - re-run with AutoFix enabled"
    )


def test_findings_jira_handoff_button_creates_badge(loaded_page: Page) -> None:
    finding_id = "44444444-4444-4444-8444-444444444444"
    handoff_requests = []

    def handle_jira_handoff(route, request) -> None:
        handoff_requests.append(request.method)
        route.fulfill(
            status=200,
            content_type="application/json",
            body="""{
              "id": "55555555-5555-4555-8555-555555555555",
              "finding_id": "44444444-4444-4444-8444-444444444444",
              "integration_configuration_id": "66666666-6666-4666-8666-666666666666",
              "issue_key": "AEGIS-44444444",
              "issue_url": "https://jira.example.test/browse/AEGIS-44444444",
              "issue_status": "Ready for Jira triage",
              "last_sync_state": "not_synced",
              "last_synced_at": null,
              "last_sync_error": null,
              "last_sync_payload_json": {},
              "created_by": "operator-ui",
              "updated_by": "operator-ui",
              "created_at": "2026-04-29T09:00:00+00:00",
              "updated_at": "2026-04-29T09:00:00+00:00"
            }""",
        )

    loaded_page.route(f"**/api/v1/findings/{finding_id}/handoff-jira", handle_jira_handoff)
    loaded_page.get_by_test_id("nav-findings").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const findingsModule = await import('/app/assets/modules/findings.js');
          const state = runtimeModule.state;
          const runId = '33333333-3333-4333-8333-333333333333';
          const finding = {
            id: '44444444-4444-4444-8444-444444444444',
            title: 'SQL Injection',
            severity: 'critical',
            target_id: 'https://portal.example.test/graphql',
            evidence_ref: 'artifact://nuclei/sql',
            status: 'open',
            summary: 'SQL injection evidence is stored.',
            finding_origin: 'standard',
            methodology_tags: ['OWASP-WSTG'],
          };
          runtimeModule.runtime.actions.loadSelectedFinding = async () => {};
          runtimeModule.runtime.actions.refreshSelectedEngagement = async () => {};
          runtimeModule.patchState({
            activeScreen: 'findings-theater',
            activePhase: 'analysis',
            selectedEngagementId: '11111111-1111-4111-8111-111111111111',
            jiraIntegrationLoadedEngagementId: '11111111-1111-4111-8111-111111111111',
            jiraIntegrationConfiguration: {
              id: '66666666-6666-4666-8666-666666666666',
              base_url: 'https://jira.example.test',
              project_key: 'AEGIS',
            },
            selectedRunId: runId,
            selectedRun: {
              id: runId,
              status: 'running',
              tasks: [],
              configuration_json: {},
              profile: { name: 'ui-test-run' },
            },
            mission: {
              ...state.mission,
              runs: [{
                id: runId,
                status: 'running',
                tasks: [],
                configuration_json: {},
                profile: { name: 'ui-test-run' },
              }],
              findingsByRun: { [runId]: [finding] },
            },
            selectedFindingId: finding.id,
            selectedFindingTheater: {
              finding,
              severity_rank: 0,
              confidence_label: 'high',
              exploitability: 'confirmed',
              business_impact: 'Stored exploit evidence needs remediation tracking.',
              technical_details: 'Stored evidence exists.',
              evidence_summary: 'Evidence is linked.',
              provenance: { origin: 'standard' },
              methodology: {},
              remediation: {
                priority: 'Immediate',
                summary: 'Fix the injection point.',
                detail: 'Patch and retest.',
                integrations: {},
              },
              verification_status: 'evidence-linked',
              next_steps: ['Push to Jira for engineering triage.'],
              risk_snapshot: {},
            },
            selectedFindingEvidence: { related_executions: [], artifacts: [] },
          }, 'ui.test.findingJiraHandoff');
          runtimeModule.runtime.actions.engagementFindings = () => [finding].map((item) => ({ ...item, _runId: runId }));
          findingsModule.createFindingsModule().renderFindingsTheater();
        }
        """
    )

    loaded_page.get_by_test_id("finding-push-jira").click()
    expect(loaded_page.get_by_test_id("finding-jira-badge")).to_contain_text("AEGIS-44444444")
    assert handoff_requests == ["POST"]


def test_custom_vulnerability_library_create_smoke(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-custom-vulnerabilities").click()
    expect(loaded_page.get_by_test_id("screen-custom-vulnerabilities")).to_be_visible()
    expect(loaded_page.get_by_test_id("custom-vulnerability-create-form")).to_be_visible()

    form = loaded_page.get_by_test_id("custom-vulnerability-create-form")
    form.locator("input[name='title']").fill("Smoke-test proprietary gateway flaw")
    form.locator("textarea[name='description']").fill("Evidence-first internal vulnerability definition for UI smoke coverage.")
    form.locator("select[name='severity']").select_option("high")
    form.locator("input[name='affected_products']").fill("Gateway Appliance")
    form.locator("input[name='cwe_ids']").fill("CWE-287")
    form.locator("button[type='submit']").click()

    expect(loaded_page.get_by_test_id("custom-vulnerability-row").first).to_contain_text(
        "Smoke-test proprietary gateway flaw"
    )


def test_wizard_requires_written_authorization_checkbox_when_roe_is_missing(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-wizard").click()
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          const wizardModule = await import('/app/assets/modules/wizard.js');
          const wizard = runtimeModule.state.wizard;
          runtimeModule.patchState({
            wizard: {
              ...wizard,
              useExistingEngagement: false,
              intake: {
                ...wizard.intake,
                flowMode: "tile",
                flowStep: 4,
                flowDepthChoice: "active",
                selectedAssessmentTileKey: "internal-lan",
                selectedAssessmentTileKeys: ["internal-lan"],
              },
              data: {
                ...wizard.data,
                engagement_name: "No ROE UI gate",
                client: "Acme Corp",
                roe_ref: "",
                authorization_confirmed: false,
                assessment_type: "Internal Range / LAN",
                targets: {
                  ...wizard.data.targets,
                  cidr_ranges: ["10.0.20.0/24"],
                },
                assessment_mode: {
                  ...wizard.data.assessment_mode,
                  mode: "full-internal-lan",
                  authorization_level: "active",
                },
              },
            },
          }, "ui.test.roeGate");
          wizardModule.createWizardModule().renderWizard();
        }
        """
    )

    expect(loaded_page.get_by_test_id("wizard-roe-authorization-gate")).to_be_visible()
    create_button = loaded_page.locator('[data-wizard-create-mission="true"]')
    expect(create_button).to_be_disabled()

    loaded_page.get_by_test_id("wizard-roe-authorization-checkbox").check()
    expect(create_button).to_be_enabled()
