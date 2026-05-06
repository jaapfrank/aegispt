"""Capture current UI state for AI loop comparison."""
from __future__ import annotations
from pathlib import Path
import pytest
from playwright.sync_api import Page, expect

DIR = Path(__file__).resolve().parents[2] / "ui" / "test-results" / "ui-loop-audit"

def ss(page: Page, name: str) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(DIR / f"{name}.png"), full_page=True)

def load(page: Page) -> None:
    page.goto("/app/", wait_until="domcontentloaded")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    page.wait_for_timeout(500)

def js_click(page: Page, sel: str) -> None:
    page.evaluate("(s)=>{const n=[...document.querySelectorAll(s)];const el=n.find(x=>x.offsetParent!==null)||n[0];if(el)el.click();}", sel)

def reset_wizard(page: Page) -> None:
    page.evaluate("""async()=>{const r=await import('/app/assets/modules/runtime.js');r.patchState({activeScreen:'wizard',wizard:r.buildEmptyWizardState()},'audit');r.runtime.actions.navigateToScreen?.('wizard');r.runtime.actions.renderAll?.();}""")
    page.wait_for_timeout(500)
    expect(page.get_by_test_id("wizard-assessment-tile-external-web")).to_be_visible(timeout=6000)

def test_wizard_current_state(page: Page) -> None:
    load(page)
    reset_wizard(page)
    ss(page, "01-wizard-step1-tiles")

    # Go to step 2 (scope)
    js_click(page, '[data-testid="wizard-assessment-tile-external-web"]')
    page.wait_for_timeout(300)
    js_click(page, "[data-assessment-submit-selection]")
    page.locator('[data-testid="wizard-target-input"]:visible').wait_for(timeout=5000)
    page.locator('[data-testid="wizard-target-input"]:visible').fill("https://testphp.vulnweb.com")
    page.wait_for_timeout(300)
    ss(page, "02-wizard-step2-target-depth")

    # Preview
    js_click(page, '[data-wizard-depth-choice="active"]')
    page.wait_for_timeout(200)
    js_click(page, "[data-wizard-preview]")
    expect(page.locator('[data-testid="wizard-mission-preview"]:visible')).to_be_visible(timeout=8000)
    ss(page, "03-wizard-preview-and-plan")

    # Auth/launch step
    page.locator('[data-wizard-depth-choice="full"]:visible').first.click() if page.locator('[data-wizard-depth-choice="full"]:visible').count() > 0 else None
    page.wait_for_timeout(300)
    ss(page, "04-wizard-launch-authorize")

def test_mission_control_current_state(page: Page) -> None:
    load(page)
    page.locator("[data-nav-screen='mission-control']").first.click()
    page.wait_for_timeout(800)
    ss(page, "05-mission-control-empty")
    # Full page including all panels
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(300)
    ss(page, "06-mission-control-bottom")

def test_wizard_advanced_config_access_tab(page: Page) -> None:
    """Show the credentials/access tab in advanced config."""
    load(page)
    reset_wizard(page)
    page.get_by_test_id("wizard-advanced-toggle").click()
    page.wait_for_timeout(500)
    ss(page, "07-advanced-config-type-tab")
    # Click Access tab
    access = page.locator("[data-advanced-step='2'], button:has-text('Access')").first
    if access.count() > 0 and access.is_visible():
        access.click()
        page.wait_for_timeout(400)
        ss(page, "08-advanced-config-access-tab")
    # Click Modules tab
    modules = page.locator("[data-advanced-step='4'], button:has-text('Modules')").first
    if modules.count() > 0 and modules.is_visible():
        modules.click()
        page.wait_for_timeout(400)
        ss(page, "09-advanced-config-modules-tab")

def test_findings_and_report_current(page: Page) -> None:
    load(page)
    page.locator("[data-nav-screen='findings-theater']").first.click()
    page.wait_for_timeout(700)
    ss(page, "10-findings-theater")
    page.locator("[data-nav-screen='report-center']").first.click()
    page.wait_for_timeout(800)
    ss(page, "11-report-center")
