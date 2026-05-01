from __future__ import annotations

import json
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.ui_fast, pytest.mark.feature]


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
            "total_recently_resolved": 1,
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
    jira_requests = []

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
    loaded_page.route(
        "**/api/v1/engagements/*/integrations/jira",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "id": "66666666-6666-4666-8666-666666666666",
                    "engagement_id": "11111111-1111-4111-8111-111111111111",
                    "integration_type": "jira",
                    "display_name": "Security Jira",
                    "base_url": "https://jira.example.test",
                    "project_key": "AEGIS",
                    "auth_ref": "secret://engagements/acme/jira-token",
                    "settings_json": {"auth_method": "api_token"},
                    "created_by": "ui-test",
                    "updated_by": "ui-test",
                    "created_at": "2026-04-29T09:00:00+00:00",
                    "updated_at": "2026-04-29T09:00:00+00:00",
                }
            ),
        ),
    )

    def handle_jira_handoff(route, request) -> None:
        jira_requests.append(request.method)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "id": "55555555-5555-4555-8555-555555555555",
                    "finding_id": problem_id,
                    "integration_configuration_id": "66666666-6666-4666-8666-666666666666",
                    "issue_key": "AEGIS-33333333",
                    "issue_url": "https://jira.example.test/browse/AEGIS-33333333",
                    "issue_status": "Ready for Jira triage",
                    "last_sync_state": "not_synced",
                    "last_synced_at": None,
                    "last_sync_error": None,
                    "last_sync_payload_json": {},
                    "created_by": "operator-ui",
                    "updated_by": "operator-ui",
                    "created_at": "2026-04-29T09:00:00+00:00",
                    "updated_at": "2026-04-29T09:00:00+00:00",
                }
            ),
        )

    loaded_page.route(f"**/api/v1/findings/{problem_id}/handoff-jira", handle_jira_handoff)
    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          runtimeModule.patchState({
            selectedEngagementId: '11111111-1111-4111-8111-111111111111',
            jiraIntegrationLoadedEngagementId: null,
            jiraIntegrationConfiguration: null,
          }, 'ui.test.problemsJiraEngagement');
        }
        """
    )
    if loaded_page.get_by_test_id("nav-problems").count():
        loaded_page.get_by_test_id("nav-problems").click()
    else:
        loaded_page.evaluate(
            """
            const button = document.createElement('button');
            button.dataset.navScreen = 'problems-center';
            document.body.appendChild(button);
            button.click();
            button.remove();
            """
        )

    expect(loaded_page.get_by_test_id("screen-problems-center")).to_be_visible()
    expect(loaded_page.get_by_test_id("problems-stats")).to_contain_text("Open critical")
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

    loaded_page.evaluate(
        """
        async () => {
          const runtimeModule = await import('/app/assets/modules/runtime.js');
          runtimeModule.patchState({
            jiraIntegrationConfiguration: {
              id: '66666666-6666-4666-8666-666666666666',
              base_url: 'https://jira.example.test',
              project_key: 'AEGIS',
            },
          }, 'ui.test.problemsJiraConfigured');
        }
        """
    )
    loaded_page.get_by_test_id("problem-row").first.locator("[data-problem-select]").check()
    expect(loaded_page.get_by_test_id("problems-bulk-jira")).to_be_enabled()
    loaded_page.get_by_test_id("problems-bulk-jira").click()
    for _ in range(50):
        if jira_requests:
            break
        loaded_page.wait_for_timeout(100)
    assert jira_requests == ["POST"]


def test_fix_forecast_updates_projection_without_status_patch(loaded_page: Page) -> None:
    payload = {
        "generated_at": "2026-04-26T12:00:00+00:00",
        "stats": {
            "open_critical": 1,
            "open_high": 1,
            "avg_days_to_resolve_30d": 4,
            "resolved_this_week": 0,
            "total_open": 3,
            "total_in_progress": 0,
            "total_recently_resolved": 0,
        },
        "filters": {
            "engagements": [{"id": "forecast-engagement", "name": "API Assessment"}],
            "assignees": [],
            "methodologies": ["OWASP-WSTG"],
            "severities": ["critical", "high", "medium", "low", "info", "unknown"],
            "statuses": ["open", "in_progress", "resolved", "verified", "reoccurred"],
            "age_buckets": [],
        },
        "items": [
            {
                "id": "ff-critical",
                "finding_id": "ff-critical",
                "run_id": "forecast-run",
                "engagement_id": "forecast-engagement",
                "engagement_name": "API Assessment",
                "title": "SQL Injection",
                "severity": "critical",
                "target_id": "api.example.test/graphql",
                "status": "open",
                "problem_status": "open",
                "assignee": "app-team",
                "days_open": 12,
                "age_bucket": "overdue",
                "remediation_state": "not_started",
                "verification_status": "Unverified",
                "methodology_tags": ["OWASP-WSTG"],
                "latest_retest_run_id": None,
                "latest_retest_status": None,
                "lifecycle": [],
                "created_at": "2026-04-14T12:00:00+00:00",
                "updated_at": "2026-04-26T12:00:00+00:00",
            },
            {
                "id": "ff-high",
                "finding_id": "ff-high",
                "run_id": "forecast-run",
                "engagement_id": "forecast-engagement",
                "engagement_name": "API Assessment",
                "title": "JWT Algorithm Confusion",
                "severity": "high",
                "target_id": "api.example.test/auth",
                "status": "open",
                "problem_status": "open",
                "assignee": "app-team",
                "days_open": 6,
                "age_bucket": "recent",
                "remediation_state": "not_started",
                "verification_status": "Unverified",
                "methodology_tags": ["OWASP-WSTG"],
                "latest_retest_run_id": None,
                "latest_retest_status": None,
                "lifecycle": [],
                "created_at": "2026-04-20T12:00:00+00:00",
                "updated_at": "2026-04-26T12:00:00+00:00",
            },
            {
                "id": "ff-medium",
                "finding_id": "ff-medium",
                "run_id": "forecast-run",
                "engagement_id": "forecast-engagement",
                "engagement_name": "API Assessment",
                "title": "Missing Security Header",
                "severity": "medium",
                "target_id": "www.example.test",
                "status": "open",
                "problem_status": "open",
                "assignee": "infra-team",
                "days_open": 2,
                "age_bucket": "recent",
                "remediation_state": "not_started",
                "verification_status": "Unverified",
                "methodology_tags": ["OWASP-WSTG"],
                "latest_retest_run_id": None,
                "latest_retest_status": None,
                "lifecycle": [],
                "created_at": "2026-04-24T12:00:00+00:00",
                "updated_at": "2026-04-26T12:00:00+00:00",
            },
        ],
        "recently_resolved": [],
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
                        "retest_run_ids": ["forecast-retest-run"],
                        "skipped": [],
                        "message": "Retest plan scheduled.",
                    }
                ),
            )
            return
        route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

    loaded_page.route("**/api/v1/problems**", handle_problems)
    loaded_page.get_by_test_id("nav-problems").click()

    expect(loaded_page.get_by_test_id("fix-forecast")).to_be_visible()
    expect(loaded_page.get_by_test_id("fix-forecast-current-score")).to_contain_text("42.5")
    expect(loaded_page.get_by_test_id("fix-forecast-projected-score")).to_contain_text("42.5")

    loaded_page.get_by_test_id("fix-forecast-selector-item").filter(has_text="SQL Injection").click()
    expect(loaded_page.get_by_test_id("fix-forecast-projected-score")).to_contain_text("17.5")
    expect(loaded_page.get_by_test_id("fix-forecast-diff-notes")).to_contain_text("Risk score drops from 42.5 to 17.5")
    expect(loaded_page.get_by_test_id("fix-forecast-current-item").filter(has_text="SQL Injection")).to_have_class(
        re.compile(r"is-fixed")
    )
    assert bulk_requests == []

    loaded_page.get_by_test_id("fix-forecast-selector-item").filter(has_text="JWT Algorithm Confusion").click()
    expect(loaded_page.get_by_test_id("fix-forecast-projected-score")).to_contain_text("5")
    expect(loaded_page.get_by_test_id("fix-forecast-diff-notes")).to_contain_text("Below 30 threshold achieved")
    assert bulk_requests == []

    loaded_page.get_by_test_id("fix-forecast-create-retest").click()
    for _ in range(50):
        if bulk_requests:
            break
        loaded_page.wait_for_timeout(100)
    assert bulk_requests == [
        {
            "finding_ids": ["ff-critical", "ff-high"],
            "action": "schedule_retest",
            "retest_notes": "Scheduled from Problems Center.",
        }
    ]
