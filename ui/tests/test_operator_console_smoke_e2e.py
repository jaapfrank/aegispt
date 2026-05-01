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
    expect(loaded_page.get_by_test_id("ai-operator-workbench")).to_contain_text("AI Operator Workbench")
    expect(loaded_page.get_by_test_id("ai-workbench-provider-status")).to_contain_text("ChatGPT connected")
    expect(loaded_page.get_by_test_id("ai-workbench-build-lane-task")).to_contain_text("codex/tasks/")
    expect(loaded_page.get_by_test_id("ai-workbench-signal-row")).to_contain_text("Live AI signal")
    expect(loaded_page.get_by_test_id("ai-signal-stream")).to_contain_text("Synthetic streamed AI Signal text")


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
                    steps: [{ profile_name: 'passive-network-discovery', status: 'completed' }],
                  },
                  {
                    key: 'phase-2',
                    label: 'Phase 2 · Active Enrichment',
                    status: 'active',
                    steps: [{ profile_name: 'passive-web-nuclei-audit', tool: 'nuclei', status: 'running' }],
                  },
                  {
                    key: 'phase-3',
                    label: 'Phase 3 · Intrusive Credential Validation',
                    status: 'pending',
                    steps: [{ profile_name: 'active-ad-kerberoast', tool: 'bloodhound', status: 'pending' }],
                  },
                  {
                    key: 'phase-4',
                    label: 'Phase 4 · Intrusive Exploitation',
                    status: 'pending',
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


def test_dashboard_zero_engagement_renders_first_run_onboarding_banner(loaded_page: Page) -> None:
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

    expect(loaded_page.get_by_test_id("dashboard-first-run-onboarding")).to_be_visible()
    expect(loaded_page.get_by_test_id("dashboard-first-run-onboarding")).to_contain_text("Connect ChatGPT OAuth")
    expect(loaded_page.get_by_test_id("dashboard-setup-checklist")).to_have_count(0)


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
              ],
              tools: [
                {
                  id: 'nmap',
                  title: 'Nmap',
                  binary_names: ['nmap'],
                  required: true,
                  installed: true,
                  detected_path: '/usr/bin/nmap',
                  status: 'ready',
                  affected_assessment_families: ['LAN discovery'],
                  operator_next_step: 'Ready.',
                },
                {
                  id: 'metasploit',
                  title: 'Metasploit',
                  binary_names: ['msfconsole'],
                  required: false,
                  installed: false,
                  detected_path: null,
                  status: 'degraded',
                  affected_assessment_families: ['Exploit confirmation'],
                  operator_next_step: 'Install Metasploit before exploit confirmation.',
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
    expect(panel).to_contain_text("6 inline task workers configured")
    expect(loaded_page.get_by_test_id("settings-tool-readiness")).to_contain_text("Metasploit")
    expect(loaded_page.get_by_test_id("settings-tool-readiness")).to_contain_text("Exploit confirmation")
    expect(loaded_page.get_by_test_id("settings-readiness-export")).to_be_visible()


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
