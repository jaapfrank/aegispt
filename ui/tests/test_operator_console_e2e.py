from __future__ import annotations

from playwright.sync_api import Page, expect


def _complete_wizard(page: Page) -> None:
    page.get_by_test_id("wizard-next").click()
    expect(page.locator("#wizard-errors")).to_contain_text("Enter an engagement name.")

    page.get_by_test_id("wizard-engagement-name").fill("Acme Browser Validation")
    page.get_by_test_id("wizard-client").fill("Acme Corp")
    page.get_by_test_id("wizard-roe-ref").fill("ROE-2026-310")
    page.get_by_test_id("wizard-next").click()

    page.locator("#wizard-target-urls").fill("not-a-url")
    page.get_by_test_id("wizard-next").click()
    expect(page.locator("#wizard-errors")).to_contain_text("Invalid URL: not-a-url")

    page.locator("#wizard-target-domains").fill("app.example.com")
    page.locator("#wizard-target-urls").fill("https://app.example.com")
    page.get_by_test_id("wizard-next").click()

    page.locator('[data-account-field="username"]').first.fill("analyst@example.com")
    page.locator('[data-account-field="secret_ref"]').first.fill("DirectPassword!234")
    page.locator('[data-account-field="role"]').first.fill("Security Analyst")
    page.get_by_test_id("wizard-next").click()
    page.get_by_test_id("wizard-next").click()
    page.get_by_test_id("wizard-next").click()
    page.get_by_test_id("wizard-next").click()
    expect(page.get_by_test_id("wizard-review")).to_be_visible()
    page.get_by_test_id("wizard-confirm").click()


def test_operator_console_empty_states_render(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").click()
    expect(loaded_page.get_by_test_id("mission-activity")).to_contain_text(
        "Complete the Assessment Wizard"
    )

    loaded_page.get_by_test_id("nav-reports").click()
    expect(loaded_page.get_by_test_id("report-catalog")).to_contain_text(
        "Report variants become available once a run dossier exists."
    )

    loaded_page.get_by_test_id("nav-evidence").click()
    expect(loaded_page.get_by_test_id("evidence-overview")).to_contain_text(
        "Select a finding in Findings Theater"
    )


def test_operator_console_wizard_to_report_flow(loaded_page: Page) -> None:
    _complete_wizard(loaded_page)

    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible()
    expect(loaded_page.get_by_test_id("mission-activity")).not_to_be_empty()

    loaded_page.get_by_test_id("nav-findings").click()
    expect(loaded_page.get_by_test_id("screen-findings-theater")).to_be_visible()
    expect(loaded_page.get_by_test_id("findings-group-list")).to_contain_text(
        "No findings match the current filters."
    )

    loaded_page.get_by_test_id("nav-evidence").click()
    expect(loaded_page.get_by_test_id("screen-evidence-replay")).to_be_visible()
    expect(loaded_page.get_by_test_id("evidence-overview")).to_contain_text(
        "Select a finding in Findings Theater"
    )

    loaded_page.get_by_test_id("nav-packs").click()
    expect(loaded_page.get_by_test_id("screen-pack-forge")).to_be_visible()
    expect(loaded_page.get_by_test_id("pack-summary")).to_contain_text(
        "Generate or select a capability pack"
    )

    loaded_page.get_by_test_id("nav-reports").click()
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

    loaded_page.get_by_test_id("nav-history").click()
    expect(loaded_page.get_by_test_id("screen-history")).to_be_visible()
    expect(loaded_page.get_by_test_id("comparison-summary")).to_contain_text(
        "Choose a baseline run"
    )
