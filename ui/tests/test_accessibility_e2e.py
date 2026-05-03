from __future__ import annotations

from playwright.sync_api import Page, expect


PRIMARY_NAV_SCREENS = [
    ("nav-dashboard", "screen-dashboard"),
    ("nav-wizard", "screen-wizard"),
    ("nav-mission-control", "screen-mission-control"),
    ("nav-findings", "screen-findings-theater"),
    ("nav-reports", "screen-report-center"),
    ("nav-settings", "screen-settings"),
]


def _focused_test_id(page: Page) -> str:
    return page.evaluate(
        """
        () => document.activeElement?.getAttribute('data-testid')
          || document.activeElement?.closest('[data-testid]')?.getAttribute('data-testid')
          || ''
        """
    )


def _focus_visible_outline_width(page: Page) -> float:
    return page.evaluate(
        """
        () => {
          const style = window.getComputedStyle(document.activeElement);
          return Number.parseFloat(style.outlineWidth || '0') || 0;
        }
        """
    )


def _is_focus_inside(page: Page, selector: str) -> bool:
    return bool(
        page.evaluate(
            """
            (selector) => {
              const root = document.querySelector(selector);
              return Boolean(root && root.contains(document.activeElement));
            }
            """,
            selector,
        )
    )


def test_keyboard_can_reach_primary_screens_and_focus_is_visible(loaded_page: Page) -> None:
    for nav_test_id, screen_test_id in PRIMARY_NAV_SCREENS:
        target = loaded_page.get_by_test_id(nav_test_id)
        expect(target).to_be_visible()
        target.focus()
        expect(target).to_be_focused()
        assert _focus_visible_outline_width(loaded_page) >= 2
        loaded_page.keyboard.press("Enter")
        expect(loaded_page.get_by_test_id(screen_test_id)).to_be_visible()


def test_visible_buttons_and_form_controls_have_accessible_names(loaded_page: Page) -> None:
    violations = loaded_page.evaluate(
        """
        () => {
          const visible = (element) => {
            const style = window.getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return style.display !== 'none'
              && style.visibility !== 'hidden'
              && rect.width > 0
              && rect.height > 0;
          };
          const labelText = (element) => {
            const ariaLabel = element.getAttribute('aria-label') || '';
            const ariaLabelledBy = element.getAttribute('aria-labelledby') || '';
            const labelledText = ariaLabelledBy
              .split(/\\s+/)
              .map((id) => document.getElementById(id)?.textContent || '')
              .join(' ');
            const wrappingLabel = element.closest('label')?.textContent || '';
            const explicitLabel = element.id
              ? (document.querySelector(`label[for="${CSS.escape(element.id)}"]`)?.textContent || '')
              : '';
            return [
              ariaLabel,
              labelledText,
              wrappingLabel,
              explicitLabel,
              element.getAttribute('title') || '',
              element.textContent || '',
              element.value && element.tagName === 'BUTTON' ? element.value : '',
            ].join(' ').replace(/\\s+/g, ' ').trim();
          };
          return Array.from(document.querySelectorAll('button, input, select, textarea'))
            .filter((element) => visible(element) && element.type !== 'hidden')
            .map((element) => ({
              tag: element.tagName.toLowerCase(),
              type: element.getAttribute('type') || '',
              testid: element.getAttribute('data-testid') || '',
              id: element.id || '',
              text: labelText(element),
            }))
            .filter((item) => !item.text);
        }
        """
    )
    assert violations == []


def test_dialogs_trap_focus_escape_and_return_focus(loaded_page: Page) -> None:
    loaded_page.get_by_test_id("nav-mission-control").focus()
    loaded_page.keyboard.press("Enter")
    expect(loaded_page.get_by_test_id("screen-mission-control")).to_be_visible()

    cinema_button = loaded_page.get_by_test_id("cinema-mode-open")
    cinema_button.focus()
    loaded_page.keyboard.press("Enter")
    expect(loaded_page.get_by_test_id("cinema-overlay")).to_be_visible()
    expect(loaded_page.get_by_test_id("cinema-mode-close")).to_be_focused()

    loaded_page.keyboard.press("Tab")
    assert _is_focus_inside(loaded_page, "#cinema-overlay")
    loaded_page.keyboard.press("Shift+Tab")
    assert _is_focus_inside(loaded_page, "#cinema-overlay")
    loaded_page.keyboard.press("Escape")
    expect(loaded_page.locator("#cinema-overlay")).to_have_count(0)
    expect(cinema_button).to_be_focused()

    cleanup_button = loaded_page.get_by_test_id("manage-engagements")
    cleanup_button.focus()
    loaded_page.keyboard.press("Enter")
    expect(loaded_page.locator(".delete-modal")).to_be_visible()
    assert _is_focus_inside(loaded_page, ".delete-modal")
    loaded_page.keyboard.press("Shift+Tab")
    assert _is_focus_inside(loaded_page, ".delete-modal")
    loaded_page.keyboard.press("Escape")
    expect(loaded_page.locator(".delete-modal")).to_have_count(0)
    expect(cleanup_button).to_be_focused()


def test_reduced_motion_disables_live_animation_surfaces(loaded_page: Page) -> None:
    loaded_page.emulate_media(reduced_motion="reduce")
    loaded_page.get_by_test_id("nav-mission-control").focus()
    loaded_page.keyboard.press("Enter")
    loaded_page.get_by_test_id("cinema-mode-open").focus()
    loaded_page.keyboard.press("Enter")
    expect(loaded_page.get_by_test_id("cinema-overlay")).to_be_visible()

    animation_names = loaded_page.evaluate(
        """
        () => ['.c1-pulse', '.cinema-empty-ring', '.narrator-text']
          .map((selector) => window.getComputedStyle(document.querySelector(selector)).animationName)
        """
    )
    assert all(name == "none" for name in animation_names)
    loaded_page.keyboard.press("Escape")
