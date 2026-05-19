"""
Live system audit 2026-05-01.

Walks every wizard step, tests all assessment tiles, advanced mode,
credential flow, module toggles, safety settings, and confirmation.
Also visits every main screen and captures screenshots for visual review.
Does NOT launch actual runs — stops at confirmation.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

AUDIT_DIR = Path(__file__).resolve().parents[2] / "ui" / "test-results" / "audit-2026-05-01"


def _ss(page: Page, name: str) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(AUDIT_DIR / f"{name}.png"), full_page=True)


def _nav(page: Page, screen: str) -> None:
    btn = page.locator(f"[data-nav-screen='{screen}']").first
    if btn.count() > 0 and btn.is_visible():
        btn.click()
    else:
        page.locator(f"#nav-{screen}, [data-testid='nav-{screen}']").first.click()
    page.wait_for_timeout(600)


def _load(page: Page) -> None:
    page.goto("/app/")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)
    # skip onboarding if present
    dismiss = page.locator("[data-onboarding-dismiss], button:has-text('Skip'), button:has-text('Get started')").first
    if dismiss.count() > 0 and dismiss.is_visible():
        dismiss.click()
        page.wait_for_timeout(400)


def _goto_wizard(page: Page) -> None:
    _nav(page, "wizard")
    page.wait_for_timeout(400)
    restart = page.locator("[data-testid='wizard-restart']")
    if restart.is_visible():
        restart.click()
        page.wait_for_timeout(400)


def _next(page: Page) -> None:
    nxt = page.locator("[data-testid='wizard-next']")
    if nxt.is_visible() and nxt.is_enabled():
        nxt.click()
        page.wait_for_timeout(500)


# ─── 1. ALL SCREENS LOAD ─────────────────────────────────────────────────────

ALL_SCREENS = [
    "dashboard", "wizard", "mission-control", "agents", "surface-map",
    "problems-center", "custom-vulnerabilities", "findings-theater",
    "evidence-replay", "pack-forge", "report-center", "history", "settings",
]


@pytest.mark.parametrize("screen", ALL_SCREENS)
def test_every_screen_loads(page: Page, screen: str) -> None:
    _load(page)
    _nav(page, screen)
    page.wait_for_timeout(800)
    _ss(page, f"screen-{screen}")

    section = page.locator(f"#screen-{screen}")
    assert section.count() > 0, f"Section #screen-{screen} not in DOM"

    # No [object Object] or undefined in visible text
    text = section.inner_text()
    assert "[object Object]" not in text, f"[object Object] in {screen}"
    assert text.count("undefined") <= 2, f"Too many 'undefined' in {screen}: {text[:300]}"


# ─── 2. TOPBAR ───────────────────────────────────────────────────────────────

def test_topbar_cleanup_not_manage(page: Page) -> None:
    _load(page)
    btn = page.locator("#manage-engagements-btn")
    assert btn.count() > 0
    label = btn.inner_text().strip()
    _ss(page, "topbar-cleanup-btn")
    assert "Manage" != label, f"Button still says 'Manage' — should be 'Cleanup' or specific label, got: '{label}'"


def test_topbar_no_redundant_settings_buttons(page: Page) -> None:
    _load(page)
    bell = page.locator("[data-testid='topbar-notifications']")
    gear = page.locator("[data-testid='topbar-settings']")
    _ss(page, "topbar-duplicate-buttons")
    if bell.count() > 0 and gear.count() > 0:
        bell_dest = bell.get_attribute("data-nav-screen")
        gear_dest = gear.get_attribute("data-nav-screen")
        assert bell_dest != gear_dest, (
            f"DEFECT: Bell ('{bell_dest}') and gear ('{gear_dest}') both navigate to same screen. "
            "Remove the bell or give it a dedicated notifications panel."
        )


def test_actor_input_not_visible_editable_field(page: Page) -> None:
    _load(page)
    _ss(page, "topbar-actor-area")
    actor_input = page.locator("#actor-input[type='text']")
    if actor_input.count() > 0 and actor_input.is_visible():
        pytest.fail(
            "DEFECT: Actor identity is an editable <input> field visible in the topbar. "
            "Enterprise operators should not see a live-editable identity box. "
            "Move to Settings or make read-only."
        )


def test_topbar_stats_chips_no_redundant_labels(page: Page) -> None:
    _load(page)
    topbar = page.locator("[data-testid='topbar']")
    topbar_text = topbar.inner_text()
    _ss(page, "topbar-stats-chips")
    # 'DOSSIERS', 'MISSIONS', 'BASELINE' as suffixes after counts are confusing
    redundant = ["DOSSIERS", "MISSIONS", "BASELINE"]
    found = [r for r in redundant if r in topbar_text.upper()]
    assert not found, (
        f"DEFECT: Topbar stats chips contain redundant suffix labels: {found}. "
        f"Topbar text: '{topbar_text[:200]}'. "
        "Use simple 'N Engagements', 'N Runs' chips."
    )


# ─── 3. WIZARD HEADING ───────────────────────────────────────────────────────

def test_wizard_heading_not_mandatory(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _ss(page, "wizard-heading")
    heading = page.locator("#screen-wizard h2").first
    if heading.count() > 0:
        text = heading.inner_text()
        assert "Mandatory" not in text, (
            f"DEFECT: Wizard heading says '{text}'. "
            "Wizard is no longer mandatory (free navigation since backlog-58). "
            "Remove 'Mandatory' from the heading."
        )


def test_wizard_stepper_labels_short(page: Page) -> None:
    _goto_wizard(page)
    stepper = page.locator("#wizard-stepper")
    if not stepper.is_visible():
        return
    _ss(page, "wizard-stepper-labels")
    text = stepper.inner_text()
    labels = [label.strip() for label in re.split(r"[\n\r\t]+", text) if label.strip() and not label.strip().isdigit()]
    long = [label for label in labels if len(label) > 20]
    assert not long, (
        "DEFECT: Wizard step labels too long (>20 chars), will wrap on viewport:\n"
        + "\n".join(f"  '{lbl}'" for lbl in long)
    )


# ─── 4. WIZARD STEP 1 — ASSESSMENT TYPE ─────────────────────────────────────

def test_wizard_step1_panel_has_options(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    panel = page.locator("#wizard-panel")
    _ss(page, "wizard-step1-panel")
    content = panel.inner_text()
    assert len(content) > 80, f"Wizard step 1 panel is nearly empty: '{content[:200]}'"
    # Must have multiple assessment options
    option_keywords = ["Web", "LAN", "API", "Internal", "External", "Domain", "SSL", "Mixed", "IoT"]
    found = [k for k in option_keywords if k in content]
    assert len(found) >= 4, f"Step 1 shows too few options. Found: {found}. Text: {content[:400]}"


def test_wizard_step1_run_config_panel_visible(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    summary = page.locator("[data-testid='wizard-inline-context']")
    _ss(page, "wizard-step1-run-config")
    assert summary.count() > 0, "Run Configuration / wizard inline context panel missing from wizard"


def test_wizard_step1_complete_assessment_wizard_cta(page: Page) -> None:
    """CTA should NOT appear on non-wizard screens during an active engagement."""
    _load(page)
    _goto_wizard(page)
    # Create an engagement first by completing wizard
    # Then navigate away and check CTA visibility
    _nav(page, "mission-control")
    page.wait_for_timeout(500)
    _ss(page, "mission-control-wizard-cta-check")
    # Check if CTA still appears when on mission control
    cta = page.locator("button:has-text('Complete Assessment Wizard'), a:has-text('Complete Assessment Wizard')").first
    # If engagement exists and run is active, CTA should be hidden
    # We just document — fail only if CTA is very prominent (primary button) on non-wizard screen
    if cta.count() > 0 and cta.is_visible():
        classes = cta.get_attribute("class") or ""
        # Warning only — the CTA as a secondary hint is acceptable
        print(f"INFO: 'Complete Assessment Wizard' CTA visible on mission-control screen. Class: '{classes}'")


# ─── 5. WIZARD STEP 2 — SCOPE INPUT ─────────────────────────────────────────

def test_wizard_step2_web_url_scope(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _next(page)  # advance past step 1
    _ss(page, "wizard-step2-scope")

    panel = page.locator("#wizard-panel")
    content = panel.inner_text()
    assert len(content) > 30, f"Wizard step 2 panel empty: '{content}'"

    # Try filling a URL input if present
    url_inputs = panel.locator("input[type='url'], input[placeholder*='http'], input[placeholder*='example']")
    textarea_inputs = panel.locator("textarea")
    _ss(page, "wizard-step2-inputs")

    if url_inputs.count() > 0:
        url_inputs.first.fill("https://testphp.vulnweb.com")
        page.wait_for_timeout(300)
        _ss(page, "wizard-step2-url-filled")
    elif textarea_inputs.count() > 0:
        textarea_inputs.first.fill("https://testphp.vulnweb.com")
        page.wait_for_timeout(300)
        _ss(page, "wizard-step2-textarea-filled")


def test_wizard_step2_empty_scope_shows_error_not_crash(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _next(page)
    # Try advancing without filling scope
    _next(page)
    page.wait_for_timeout(400)
    _ss(page, "wizard-step2-empty-advance")

    panel_content = page.locator("#wizard-panel").inner_text()
    assert len(panel_content) > 20, (
        "DEFECT: Wizard panel went blank after empty scope submit — should show error or stay on step"
    )


# ─── 6. WIZARD STEP 3 — CREDENTIALS ─────────────────────────────────────────

def test_wizard_step3_credentials_step_renders(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _next(page)
    # Fill scope
    scope_input = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope_input.count() > 0:
        scope_input.fill("https://testphp.vulnweb.com")
    _next(page)
    _ss(page, "wizard-step3-credentials")
    panel = page.locator("#wizard-panel")
    content = panel.inner_text()
    assert len(content) > 30, f"Credentials step appears empty: '{content[:200]}'"


def test_wizard_step3_can_advance_without_credentials(page: Page) -> None:
    """Unauthenticated scan should be possible — no credentials required."""
    _load(page)
    _goto_wizard(page)
    _next(page)
    scope_input = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope_input.count() > 0:
        scope_input.fill("https://testphp.vulnweb.com")
    _next(page)
    _next(page)  # skip credentials
    page.wait_for_timeout(400)
    _ss(page, "wizard-step3-skip-creds")
    # Should be on step 4 now — check panel has content
    panel = page.locator("#wizard-panel").inner_text()
    assert len(panel) > 30, "Wizard got stuck or went blank after skipping credentials"


def test_wizard_step3_add_account_button_works(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _next(page)
    scope_input = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope_input.count() > 0:
        scope_input.fill("https://testphp.vulnweb.com")
    _next(page)
    _ss(page, "wizard-step3-add-account")

    add_btn = page.locator("#wizard-panel button:has-text('Add'), #wizard-panel button:has-text('Add Account')").first
    if add_btn.count() > 0 and add_btn.is_visible():
        add_btn.click()
        page.wait_for_timeout(400)
        _ss(page, "wizard-step3-add-account-open")
        # Should see credential fields
        cred_fields = page.locator("#wizard-panel input[placeholder*='user'], #wizard-panel input[placeholder*='email'], #wizard-panel input[type='password']")
        assert cred_fields.count() > 0, (
            "DEFECT: Add Account button clicked but no credential input fields appeared"
        )
    else:
        # Acceptable if unauthenticated is the default and credentials are optional
        print("INFO: No 'Add Account' button found on credentials step — may be optional/collapsed")


# ─── 7. WIZARD STEP 4 — TEST PROFILE ─────────────────────────────────────────

def test_wizard_step4_profile_options_complete(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(3):
        _next(page)

    _ss(page, "wizard-step4-profile")
    panel = page.locator("#wizard-panel").inner_text()
    expected = ["Light", "Standard", "Deep", "SSL"]
    found = [e for e in expected if e in panel]
    assert len(found) >= 2, (
        f"DEFECT: Step 4 profile options incomplete. Found: {found}. Panel: {panel[:400]}"
    )


def test_wizard_step4_each_option_selectable(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(3):
        _next(page)

    # Click each visible profile option
    options = page.locator("#wizard-panel input[type='radio'], #wizard-panel .tile, #wizard-panel [role='radio']")
    count = options.count()
    _ss(page, "wizard-step4-options-count")
    assert count >= 2, f"DEFECT: Step 4 shows only {count} profile options — expected at least 2"

    for i in range(min(count, 6)):
        opt = options.nth(i)
        if opt.is_visible():
            opt.click()
            page.wait_for_timeout(200)
    _ss(page, "wizard-step4-options-cycled")


# ─── 8. WIZARD STEP 5 — MODULES ──────────────────────────────────────────────

def test_wizard_step5_modules_listed(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(4):
        _next(page)

    _ss(page, "wizard-step5-modules")
    panel = page.locator("#wizard-panel").inner_text()
    module_keywords = ["Discovery", "Crawl", "Nuclei", "SSL", "TLS", "Auth", "Business", "Adaptive", "Content"]
    found = [m for m in module_keywords if m in panel]
    assert len(found) >= 3, (
        f"DEFECT: Step 5 modules too sparse. Found: {found}. Panel: {panel[:500]}"
    )


def test_wizard_step5_modules_are_toggleable(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(4):
        _next(page)

    checkboxes = page.locator("#wizard-panel input[type='checkbox']")
    _ss(page, "wizard-step5-toggles")
    if checkboxes.count() > 0:
        # Toggle first checkbox and check run config updates
        checkboxes.first.click()
        page.wait_for_timeout(300)
        _ss(page, "wizard-step5-toggled")
        # Run config should change (or at least not crash)
        panel_ok = len(page.locator("#wizard-panel").inner_text()) > 20
        assert panel_ok, "Wizard crashed after toggling a module checkbox"
    else:
        print("INFO: No checkboxes found in step 5 — modules may use different toggle component")


# ─── 9. WIZARD STEP 6 — SAFETY ───────────────────────────────────────────────

def test_wizard_step6_safety_fields_present(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(5):
        _next(page)

    _ss(page, "wizard-step6-safety")
    panel = page.locator("#wizard-panel").inner_text()
    safety_kw = ["rate", "concurren", "budget", "guard", "limit", "risk", "time", "safe"]
    found = [k for k in safety_kw if k.lower() in panel.lower()]
    assert len(found) >= 2, (
        f"DEFECT: Safety/limits step appears sparse. Found: {found}. Panel: {panel[:400]}"
    )


def test_wizard_step6_numeric_inputs_accept_values(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(5):
        _next(page)

    num_inputs = page.locator("#wizard-panel input[type='number']")
    _ss(page, "wizard-step6-numeric-inputs")
    if num_inputs.count() > 0:
        num_inputs.first.fill("3")
        page.wait_for_timeout(200)
        val = num_inputs.first.input_value()
        assert val == "3", f"DEFECT: Numeric input rejected valid value '3', got '{val}'"


def test_wizard_step6_select_dropdowns_have_options(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    for _ in range(5):
        _next(page)

    selects = page.locator("#wizard-panel select")
    _ss(page, "wizard-step6-selects")
    for i in range(selects.count()):
        sel = selects.nth(i)
        if sel.is_visible():
            options = sel.locator("option")
            assert options.count() >= 2, (
                f"DEFECT: Select #{i} in safety step has <2 options: {options.count()}"
            )


# ─── 10. WIZARD STEP 7 — REVIEW / CONFIRM ────────────────────────────────────

def test_wizard_step7_review_summary_complete(page: Page) -> None:
    _load(page)
    _goto_wizard(page)

    # Advance through all steps with minimal valid data
    _next(page)
    scope = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope.count() > 0:
        scope.fill("https://testphp.vulnweb.com")
    for _ in range(5):
        _next(page)

    _ss(page, "wizard-step7-review")
    panel = page.locator("#wizard-panel").inner_text()

    review_kw = ["Assessment", "Target", "Module", "Safety", "Confirm", "Mission", "Review"]
    found = [k for k in review_kw if k in panel]
    assert len(found) >= 3, (
        f"DEFECT: Step 7 review summary missing key sections. Found: {found}. Panel: {panel[:600]}"
    )


def test_wizard_step7_confirm_button_visible_and_labeled(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    _next(page)
    scope = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope.count() > 0:
        scope.fill("https://testphp.vulnweb.com")
    for _ in range(5):
        _next(page)

    _ss(page, "wizard-step7-confirm-btn")
    confirm = page.locator("[data-testid='wizard-confirm']")
    assert confirm.count() > 0, "DEFECT: Confirm button (#wizard-confirm) not in DOM on step 7"
    assert confirm.is_visible(), "DEFECT: Confirm button not visible on step 7"
    label = confirm.inner_text().strip()
    assert "Mission" in label or "Create" in label or "Confirm" in label, (
        f"DEFECT: Confirm button has unclear label: '{label}'"
    )


# ─── 11. ADVANCED CONFIGURATION ───────────────────────────────────────────────

def test_wizard_advanced_toggle_opens_drawer(page: Page) -> None:
    _load(page)
    _goto_wizard(page)

    toggle = page.locator("[data-testid='wizard-advanced-toggle']")
    _ss(page, "wizard-advanced-toggle")
    assert toggle.is_visible(), "DEFECT: 'Advanced Configuration' toggle not visible in wizard"
    toggle.click()
    page.wait_for_timeout(500)

    drawer = page.locator("[data-testid='wizard-advanced-drawer']")
    _ss(page, "wizard-advanced-drawer-open")
    assert not drawer.is_hidden(), "DEFECT: Advanced drawer did not open after clicking toggle"


def test_wizard_advanced_drawer_has_assessment_mode(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    toggle = page.locator("[data-testid='wizard-advanced-toggle']")
    if toggle.is_visible():
        toggle.click()
        page.wait_for_timeout(400)

    drawer = page.locator("[data-testid='wizard-advanced-drawer']")
    text = drawer.inner_text()
    _ss(page, "wizard-advanced-drawer-content")
    assert len(text) > 30, f"DEFECT: Advanced drawer empty or near-empty: '{text[:200]}'"

    # Should list assessment mode chain options
    chain_options = ["Full Internal LAN", "Full External Web", "Full AD Assessment", "Disabled"]
    found = [o for o in chain_options if o in text]
    assert len(found) >= 2, (
        f"DEFECT: Advanced drawer missing chain mode options. Found: {found}. Drawer: {text[:500]}"
    )


def test_wizard_advanced_mode_full_internal_lan_selectable(page: Page) -> None:
    _load(page)
    _goto_wizard(page)
    toggle = page.locator("[data-testid='wizard-advanced-toggle']")
    if toggle.is_visible():
        toggle.click()
        page.wait_for_timeout(400)

    drawer = page.locator("[data-testid='wizard-advanced-drawer']")
    full_internal = drawer.locator("text=Full Internal LAN").first
    _ss(page, "wizard-advanced-full-internal")
    if full_internal.count() > 0:
        full_internal.click()
        page.wait_for_timeout(300)
        _ss(page, "wizard-advanced-full-internal-selected")
        # Run config should reflect the chain mode
        config = page.locator("[data-testid='wizard-inline-context']").inner_text()
        print(f"Run config after Full Internal LAN selection: {config[:200]}")


# ─── 12. MISSION CONTROL BUTTON AUDIT ────────────────────────────────────────

def test_mission_control_view_agents_is_not_danger(page: Page) -> None:
    _load(page)
    _nav(page, "mission-control")
    btn = page.locator("[data-testid='mission-view-agents']")
    _ss(page, "mission-control-buttons")
    if btn.count() > 0:
        classes = btn.get_attribute("class") or ""
        assert "danger" not in classes, (
            f"DEFECT: 'View Agents' button uses 'action danger' class: '{classes}'. "
            "It is navigation-only, not a destructive action. Use 'action secondary' or 'action ghost'."
        )


def test_mission_control_kill_run_is_danger(page: Page) -> None:
    _load(page)
    _nav(page, "mission-control")
    btn = page.locator("[data-testid='mission-kill-run']")
    _ss(page, "mission-control-kill-run")
    if btn.count() > 0:
        classes = btn.get_attribute("class") or ""
        assert "danger" in classes, (
            f"DEFECT: 'Kill Run' button is NOT styled as danger: '{classes}'. "
            "This is a destructive action and must be clearly red."
        )


def test_mission_control_three_panels_present(page: Page) -> None:
    _load(page)
    _nav(page, "mission-control")
    page.wait_for_timeout(600)
    _ss(page, "mission-control-panels")

    assert page.locator(".mission-map-panel").count() > 0, "DEFECT: Scan Map panel missing"
    assert page.locator(".mission-task-panel").count() > 0, "DEFECT: Task panel missing"
    assert page.locator("[data-testid='mission-ai-signal-panel']").count() > 0, "DEFECT: AI Signal panel missing"


def test_mission_control_ai_signal_initial_state_documented(page: Page) -> None:
    """Document (not fail) the AI Signal initial state — captures current text for review."""
    _load(page)
    _nav(page, "mission-control")
    page.wait_for_timeout(800)
    ai_text = page.locator("#mission-ai-narrative").inner_text().strip()
    _ss(page, "mission-control-ai-signal-state")
    # We document the state; if it says "Connect ChatGPT" when ChatGPT IS connected that's wrong
    print(f"AI Signal initial state: '{ai_text[:300]}'")
    # Soft check: it should not be completely blank
    # Empty is acceptable (no run selected), but if there's text it should be meaningful
    if len(ai_text) > 5 and "[object" in ai_text:
        pytest.fail(f"AI Signal contains raw JS object output: '{ai_text[:200]}'")


# ─── 13. FINDINGS THEATER ────────────────────────────────────────────────────

def test_findings_theater_filter_bar_renders(page: Page) -> None:
    _load(page)
    _nav(page, "findings-theater")
    page.wait_for_timeout(600)
    _ss(page, "findings-theater-full")
    filter_bar = page.locator("#findings-filter-bar")
    assert filter_bar.count() > 0, "DEFECT: Findings filter bar not in DOM"


def test_findings_theater_empty_state_has_guidance(page: Page) -> None:
    _load(page)
    _nav(page, "findings-theater")
    page.wait_for_timeout(600)
    group_list = page.locator("#findings-group-list")
    content = group_list.inner_text().strip()
    _ss(page, "findings-theater-empty-state")
    if len(content) < 10:
        pytest.fail(
            "DEFECT: Findings Theater is blank with no guidance. "
            "Should show 'No findings yet — complete a run to see results here.'"
        )


def test_findings_remediation_portfolio_hidden_when_empty(page: Page) -> None:
    _load(page)
    _nav(page, "findings-theater")
    page.wait_for_timeout(500)
    portfolio = page.locator("#remediation-portfolio")
    if portfolio.count() > 0:
        # Should be hidden when no findings
        is_hidden = "hidden" in (portfolio.get_attribute("class") or "")
        _ss(page, "findings-remediation-portfolio")
        # Just document — not a hard failure
        print(f"Remediation portfolio visible: {not is_hidden}")


# ─── 14. SURFACE MAP ─────────────────────────────────────────────────────────

def test_surface_map_renders_without_crash(page: Page) -> None:
    _load(page)
    _nav(page, "surface-map")
    page.wait_for_timeout(800)
    _ss(page, "surface-map-full")
    canvas = page.locator("#surface-map-canvas")
    assert canvas.count() > 0, "DEFECT: Surface map canvas element missing"


def test_surface_map_empty_state_actionable(page: Page) -> None:
    _load(page)
    _nav(page, "surface-map")
    page.wait_for_timeout(600)
    canvas_text = page.locator("#surface-map-canvas").inner_text().strip()
    browser_text = page.locator("#surface-asset-browser").inner_text().strip()
    _ss(page, "surface-map-empty-state")

    combined = canvas_text + " " + browser_text
    vague = ["No inventory", "Nothing here", "No data"]
    for msg in vague:
        if msg.lower() in combined.lower() and len(combined) < 80:
            pytest.fail(
                f"DEFECT: Surface Map empty state is vague: '{combined}'. "
                "Should say what run type populates it."
            )


# ─── 15. REPORT CENTER ───────────────────────────────────────────────────────

def test_report_center_catalog_not_blank(page: Page) -> None:
    _load(page)
    _nav(page, "report-center")
    page.wait_for_timeout(800)
    _ss(page, "report-center-full")
    catalog = page.locator("#report-catalog").inner_text().strip()
    assert len(catalog) > 20, f"DEFECT: Report catalog is blank: '{catalog}'"


def test_report_center_no_internal_dev_copy(page: Page) -> None:
    _load(page)
    _nav(page, "report-center")
    page.wait_for_timeout(600)
    full_text = page.locator("#screen-report-center").inner_text()
    _ss(page, "report-center-copy-check")
    banned = [
        "without a side metadata rail",
        "History & Compared",
        "metadata rail",
        "Prior Report Delta",
    ]
    found = [b for b in banned if b.lower() in full_text.lower()]
    assert not found, (
        f"DEFECT: Report Center contains internal dev language: {found}. "
        "These must be replaced with operator-appropriate copy."
    )


def test_report_center_generate_markdown_preview(page: Page) -> None:
    _load(page)
    _nav(page, "report-center")
    page.wait_for_timeout(800)

    preview_btn = page.locator("button:has-text('Markdown Preview'), button:has-text('Generate Markdown')").first
    _ss(page, "report-center-preview-btn-state")
    if preview_btn.count() > 0 and preview_btn.is_enabled():
        preview_btn.click()
        page.wait_for_timeout(2000)
        _ss(page, "report-center-preview-generated")
        preview = page.locator("#report-preview, .report-reader-panel").inner_text().strip()
        print(f"Report preview length: {len(preview)} chars")
        assert len(preview) > 50, "DEFECT: Markdown preview generated but content is near-empty"
    else:
        print("INFO: Markdown preview button disabled — likely no run selected (expected)")


def test_report_center_download_buttons_labeled(page: Page) -> None:
    _load(page)
    _nav(page, "report-center")
    page.wait_for_timeout(800)
    _ss(page, "report-center-download-buttons")

    download_btns = page.locator("button:has-text('Download'), a:has-text('Download')")
    for i in range(download_btns.count()):
        btn = download_btns.nth(i)
        label = btn.inner_text().strip()
        assert len(label) > 3, f"DEFECT: Download button #{i} has empty or too-short label: '{label}'"


# ─── 16. SETTINGS SCREEN ─────────────────────────────────────────────────────

def test_settings_screen_key_sections_present(page: Page) -> None:
    _load(page)
    _nav(page, "settings")
    page.get_by_test_id("settings-tab-tools-runtime").click()
    page.wait_for_timeout(1000)
    _ss(page, "settings-full")
    text = page.locator("#settings-content").inner_text()
    required = ["AI", "Readiness", "Runtime"]
    found = [r for r in required if r in text]
    assert len(found) >= 2, (
        f"DEFECT: Settings missing key sections. Found: {found}. Text: {text[:400]}"
    )


def test_settings_integrations_visible(page: Page) -> None:
    _load(page)
    _nav(page, "settings")
    page.get_by_test_id("settings-tab-integrations").click()
    page.wait_for_timeout(800)
    text = page.locator("#settings-content").inner_text()
    _ss(page, "settings-integrations")
    integration_kw = ["Jira", "SIEM", "Integration", "Webhook", "Repository"]
    found = [k for k in integration_kw if k in text]
    assert len(found) >= 2, f"DEFECT: Settings missing integration sections. Found: {found}"


def test_settings_data_retention_section(page: Page) -> None:
    _load(page)
    _nav(page, "settings")
    page.get_by_test_id("settings-tab-data-security").click()
    page.wait_for_timeout(800)
    text = page.locator("#settings-content").inner_text()
    _ss(page, "settings-retention")
    assert "etention" in text, (
        "DEFECT: Settings missing data retention section — required for enterprise/GDPR compliance"
    )


def test_settings_chatgpt_connection_section(page: Page) -> None:
    _load(page)
    _nav(page, "settings")
    page.wait_for_timeout(800)
    text = page.locator("#settings-content").inner_text()
    _ss(page, "settings-chatgpt")
    assert "ChatGPT" in text or "AI Provider" in text or "OpenAI" in text, (
        "DEFECT: Settings missing ChatGPT/AI provider section"
    )


# ─── 17. DASHBOARD ───────────────────────────────────────────────────────────

def test_dashboard_shows_content_or_guidance(page: Page) -> None:
    _load(page)
    _nav(page, "dashboard")
    page.wait_for_timeout(800)
    _ss(page, "dashboard-full")
    content = page.locator("#dashboard-content").inner_text().strip()
    assert len(content) > 30, (
        f"DEFECT: Dashboard is blank for new operators: '{content[:200]}'. "
        "Should show welcome message and 'Start Your First Assessment' CTA."
    )


# ─── 18. PROBLEMS CENTER ─────────────────────────────────────────────────────

def test_problems_center_no_triple_zero(page: Page) -> None:
    _load(page)
    _nav(page, "problems-center")
    page.wait_for_timeout(800)
    _ss(page, "problems-center-full")
    content = page.locator("#problems-content").inner_text().strip()
    if re.search(r"0\s*[-–·]\s*0\s*[-–·]\s*0", content) and len(content) < 100:
        pytest.fail(
            f"DEFECT: Problems Center shows '0-0-0' as primary content: '{content[:200]}'. "
            "Replace with: 'No open problems — findings from completed runs appear here.'"
        )


# ─── 19. HISTORY ─────────────────────────────────────────────────────────────

def test_history_screen_not_blank(page: Page) -> None:
    _load(page)
    _nav(page, "history")
    page.wait_for_timeout(800)
    _ss(page, "history-full")
    toolbar = page.locator("#history-toolbar").inner_text().strip()
    summary = page.locator("#comparison-summary").inner_text().strip()
    combined = toolbar + summary
    if len(combined) < 10:
        pytest.fail(
            "DEFECT: History screen is completely blank. "
            "Should show empty state: 'Complete your first run to build history.'"
        )


# ─── 20. PACK FORGE ──────────────────────────────────────────────────────────

def test_pack_forge_codex_build_lane_not_prominent(page: Page) -> None:
    """Codex build lane / Task Planner should not be visible by default for operators."""
    _load(page)
    _nav(page, "pack-forge")
    page.wait_for_timeout(600)
    _ss(page, "pack-forge-full")

    codex_form = page.locator("#codex-task-form")

    if codex_form.count() > 0 and codex_form.is_visible():
        pytest.fail(
            "DEFECT: Codex build-lane Task Planner form (#codex-task-form) is visible to all operators. "
            "This is developer infrastructure that should be hidden by default. "
            "Gate behind a developer mode toggle in Settings."
        )


# ─── 21. SIDEBAR ─────────────────────────────────────────────────────────────

def test_sidebar_no_developer_section_labels(page: Page) -> None:
    _load(page)
    sidebar = page.locator("[data-testid='sidebar']")
    text = sidebar.inner_text()
    _ss(page, "sidebar-full")
    developer_labels = ["Operator Flow", "Build Lane", "VIEWS /"]
    found = [lbl for lbl in developer_labels if lbl in text]
    assert not found, (
        f"DEFECT: Sidebar contains developer-facing section labels: {found}. "
        f"Sidebar text: '{text[:400]}'"
    )


def test_sidebar_new_mission_button_present(page: Page) -> None:
    _load(page)
    btn = page.locator("[data-testid='sidebar-new-mission']")
    _ss(page, "sidebar-new-mission")
    assert btn.count() > 0 and btn.is_visible(), (
        "DEFECT: '+ New Mission' button not visible in sidebar"
    )


# ─── 22. FULL WIZARD FLOW END TO END ─────────────────────────────────────────

def test_full_wizard_flow_web_standard_to_confirm(page: Page) -> None:
    """Complete 7-step wizard flow: Web → URL → Skip auth → Standard → Default modules → Default safety → Confirm."""
    _load(page)
    _goto_wizard(page)
    _ss(page, "flow-step1-type")

    # Step 1: advance (keep default web selection)
    _next(page)
    _ss(page, "flow-step2-scope")

    # Step 2: fill URL
    scope = page.locator("#wizard-panel input[type='url'], #wizard-panel input[placeholder*='http'], #wizard-panel textarea").first
    if scope.count() > 0:
        scope.fill("https://testphp.vulnweb.com")
    page.wait_for_timeout(300)
    _next(page)
    _ss(page, "flow-step3-credentials")

    # Step 3: skip credentials
    _next(page)
    _ss(page, "flow-step4-profile")

    # Step 4: click Standard if visible, else advance
    standard = page.locator("#wizard-panel").locator("text=Standard").first
    if standard.count() > 0:
        standard.click()
        page.wait_for_timeout(200)
    _next(page)
    _ss(page, "flow-step5-modules")

    # Step 5: keep defaults
    _next(page)
    _ss(page, "flow-step6-safety")

    # Step 6: keep defaults
    _next(page)
    page.wait_for_timeout(600)
    _ss(page, "flow-step7-review")

    # Step 7: verify confirm button
    confirm = page.locator("[data-testid='wizard-confirm']")
    assert confirm.count() > 0, "DEFECT: Never reached wizard confirm step in full flow"
    if confirm.is_visible():
        label = confirm.inner_text().strip()
        _ss(page, "flow-confirm-btn")
        assert len(label) > 3, f"DEFECT: Confirm button has empty label: '{label}'"
    else:
        # Check what step we're actually on
        panel = page.locator("#wizard-panel").inner_text()
        pytest.fail(f"DEFECT: Confirm button not visible on step 7. Panel: {panel[:400]}")
