"""
Full visual audit 2026-05-03.
Takes a clean full-page screenshot of every screen + Settings sub-sections.
Uses reset_wizard pattern from existing tests for reliability.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

DIR = Path(__file__).resolve().parents[2] / "ui" / "test-results" / "visual-audit-2026-05-03"

def ss(page: Page, name: str) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(DIR / f"{name}.png"), full_page=True)

def load(page: Page) -> None:
    page.goto("/app/", wait_until="domcontentloaded")
    expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT")
    page.wait_for_timeout(600)
    for sel in ["[data-onboarding-dismiss]", "button:has-text('Skip for now')"]:
        el = page.locator(sel).first
        if el.count() > 0 and el.is_visible():
            el.click()
            page.wait_for_timeout(300)
            break

def nav(page: Page, screen: str) -> None:
    btn = page.locator(f"[data-nav-screen='{screen}'], [data-testid='nav-{screen}']").first
    if btn.count() > 0 and btn.is_visible():
        btn.click()
        page.wait_for_timeout(700)

def js_click(page: Page, sel: str) -> None:
    page.evaluate(
        "(s) => { const n=[...document.querySelectorAll(s)];"
        "const el=n.find(x=>x.offsetParent!==null)||n[0]; if(el) el.click(); }",
        sel)

# ── Every screen ──────────────────────────────────────────────────────────────

SCREENS = ["dashboard","wizard","mission-control","agents","surface-map",
           "problems-center","custom-vulnerabilities","findings-theater",
           "evidence-replay","pack-forge","report-center","history","settings"]

@pytest.mark.parametrize("screen", SCREENS)
def test_screen_screenshot(page: Page, screen: str) -> None:
    load(page)
    nav(page, screen)
    page.wait_for_timeout(600)
    ss(page, f"01-{screen}")

# ── Settings expanded sections ────────────────────────────────────────────────

SETTINGS_PANELS = [
    "chatgpt_oauth", "runtime_readiness", "users", "ai_provider",
    "default_network_scope", "runtime_execution", "integrations",
    "notifications", "threat_intel_controls", "scheduled_scans",
    "data_retention", "engagement_jira", "engagement_siem",
]

def test_settings_all_panels_expanded(page: Page) -> None:
    load(page)
    nav(page, "settings")
    page.wait_for_timeout(800)
    ss(page, "02-settings-initial")
    # Expand all panels
    toggles = page.locator("[data-settings-toggle], .settings-panel-toggle, details summary")
    for i in range(toggles.count()):
        t = toggles.nth(i)
        if t.is_visible():
            try:
                t.click()
                page.wait_for_timeout(150)
            except Exception:
                pass
    page.wait_for_timeout(500)
    ss(page, "02-settings-all-expanded")

# ── Wizard all steps ──────────────────────────────────────────────────────────

def test_wizard_full_visual(page: Page) -> None:
    load(page)
    page.evaluate(
        """async () => {
          const runtime = await import('/app/assets/modules/runtime.js');
          runtime.patchState({activeScreen:"wizard",wizard:runtime.buildEmptyWizardState()},"visual-audit");
          runtime.runtime.actions.navigateToScreen?.("wizard");
          runtime.runtime.actions.renderAll?.();
        }"""
    )
    page.wait_for_timeout(500)
    expect(page.get_by_test_id("wizard-assessment-tile-external-web")).to_be_visible()
    ss(page, "03-wizard-s1-tiles")

    # Step 1 — select web + show combo area
    js_click(page, '[data-testid="wizard-assessment-tile-internal-lan"]')
    page.wait_for_timeout(300)
    ss(page, "03-wizard-s1-lan-selected-combo-hint")

    js_click(page, '[data-testid="wizard-assessment-tile-external-web"]')
    page.wait_for_timeout(300)
    ss(page, "03-wizard-s1-web-selected")

    # Step 2 — scope + depth
    js_click(page, "[data-assessment-submit-selection]")
    page.locator('[data-testid="wizard-target-input"]:visible').wait_for(timeout=5000)
    ss(page, "03-wizard-s2-scope-empty")
    page.locator('[data-testid="wizard-target-input"]:visible').fill("https://testphp.vulnweb.com")
    page.wait_for_timeout(400)
    ss(page, "03-wizard-s2-scope-filled-depth")

    # Step 3 — preview
    js_click(page, "[data-wizard-preview]")
    page.locator('[data-testid="wizard-mission-preview"]:visible').wait_for(timeout=6000)
    ss(page, "03-wizard-s3-preview")

    # Advanced configuration drawer
    page.evaluate(
        """async () => {
          const runtime = await import('/app/assets/modules/runtime.js');
          runtime.patchState({activeScreen:"wizard",wizard:runtime.buildEmptyWizardState()},"visual-audit-adv");
          runtime.runtime.actions.navigateToScreen?.("wizard");
          runtime.runtime.actions.renderAll?.();
        }"""
    )
    page.wait_for_timeout(400)
    page.get_by_test_id("wizard-advanced-toggle").click()
    page.wait_for_timeout(500)
    ss(page, "03-wizard-advanced-config-open")
    # Click each advanced step
    for i in range(6):
        btn = page.locator(f"[data-advanced-step='{i}']:visible").first
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(300)
            ss(page, f"03-wizard-advanced-step-{i}")

# ── Mission Control detailed ───────────────────────────────────────────────────

def test_mission_control_visual(page: Page) -> None:
    load(page)
    nav(page, "mission-control")
    page.wait_for_timeout(700)
    ss(page, "04-mission-control")
    # Scroll down to capture full page
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(300)
    ss(page, "04-mission-control-bottom")

# ── Findings with drawer ──────────────────────────────────────────────────────

def test_findings_visual(page: Page) -> None:
    load(page)
    nav(page, "findings-theater")
    page.wait_for_timeout(700)
    ss(page, "05-findings-theater")

# ── Report center ─────────────────────────────────────────────────────────────

def test_report_center_visual(page: Page) -> None:
    load(page)
    nav(page, "report-center")
    page.wait_for_timeout(800)
    ss(page, "06-report-center")

# ── Pack forge ────────────────────────────────────────────────────────────────

def test_pack_forge_visual(page: Page) -> None:
    load(page)
    nav(page, "pack-forge")
    page.wait_for_timeout(600)
    ss(page, "07-pack-forge")

# ── Dashboard ─────────────────────────────────────────────────────────────────

def test_dashboard_visual(page: Page) -> None:
    load(page)
    nav(page, "dashboard")
    page.wait_for_timeout(700)
    ss(page, "08-dashboard")

# ── Sidebar close look ────────────────────────────────────────────────────────

def test_sidebar_visual(page: Page) -> None:
    load(page)
    ss(page, "09-sidebar-full")
    # Navigate through all sidebar items
    for screen in ["dashboard", "wizard", "mission-control", "problems-center", "findings-theater", "settings"]:
        nav(page, screen)
        page.wait_for_timeout(400)
    ss(page, "09-sidebar-settings-active")
