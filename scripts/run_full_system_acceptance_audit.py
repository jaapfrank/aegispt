from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

PRIMARY_SCREENS = [
    "dashboard",
    "wizard",
    "mission-control",
    "agents",
    "surface-map",
    "problems-center",
    "custom-vulnerabilities",
    "findings-theater",
    "report-center",
    "history",
    "pack-forge",
    "evidence-replay",
    "explorer",
    "settings",
]

SCREEN_JOURNEYS = {
    "dashboard": "command_center",
    "wizard": "intake_and_launch",
    "mission-control": "live_operations",
    "agents": "live_operations",
    "surface-map": "surface_truth",
    "problems-center": "analysis",
    "custom-vulnerabilities": "analysis",
    "findings-theater": "analysis",
    "report-center": "reporting",
    "history": "reporting",
    "pack-forge": "build",
    "evidence-replay": "analysis",
    "explorer": "analysis",
    "settings": "control_plane",
}

PLACEHOLDER_PATTERNS = [
    "mockup",
    "todo",
    "tbd",
    "coming soon",
    "not implemented",
    "placeholder",
    "lorem",
    "[object object]",
    "undefined",
    "nan",
]

SENSITIVE_FIELD_PATTERNS = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "client_secret",
]

BACKLOG_HINTS = [
    ("backlog-150", ["mission", "run", "task", "agent", "queued", "running", "blocked", "stdout", "validation"]),
    ("backlog-151", ["wizard", "intake", "target", "depth", "authorization", "launch", "assessment"]),
    ("backlog-152", ["ai", "chatgpt", "signal", "repair", "enrichment", "provider", "oauth"]),
    ("backlog-153", ["page", "navigation", "copy", "clarity", "ux", "mockup", "placeholder"]),
    ("backlog-154", ["settings", "tool", "concurrency", "environment", "readiness", "scheduler", "nvd"]),
    ("backlog-155", ["finding", "report", "history", "evidence", "jira", "export", "retest"]),
    ("backlog-156", ["enrichment", "unavailable", "chatgpt"]),
    ("backlog-157", ["jira", "404", "drawer"]),
    ("backlog-158", ["manage", "delete", "cleanup"]),
    ("backlog-159", ["autofix", "suggested fix"]),
    ("backlog-160", ["notification", "bell"]),
    ("backlog-161", ["ai signal", "connect chatgpt", "initial"]),
    ("backlog-162", ["nvd", "429", "api key"]),
    ("backlog-163", ["surface", "map", "canvas", "inventory"]),
    ("backlog-164", ["wifi", "wireless"]),
]


@dataclass
class Defect:
    severity: str
    code: str
    screen: str
    journey: str
    title: str
    evidence: str
    selector: str = ""
    duplicate_status: str = "new_or_unmapped"
    recommended_backlog_target: str = "triage"


@dataclass
class AuditResult:
    generated_at: str
    base_url: str
    duration_seconds: float
    live_environment_relevant: bool
    health: dict[str, Any] = field(default_factory=dict)
    api_checks: list[dict[str, Any]] = field(default_factory=list)
    screens: list[dict[str, Any]] = field(default_factory=list)
    safe_fill_events: list[dict[str, Any]] = field(default_factory=list)
    defects: list[dict[str, Any]] = field(default_factory=list)
    backlog_crosscheck: list[dict[str, Any]] = field(default_factory=list)
    crawl_notes: list[str] = field(default_factory=list)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def now_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def read_task_queue(root: Path) -> list[dict[str, str]]:
    queue_path = root / "TASK_QUEUE.md"
    if not queue_path.exists():
        return []
    items: list[dict[str, str]] = []
    pattern = re.compile(r"^\s*(\d+)\.\s+(.*?)\s+`(codex/tasks/[^`]+)`")
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            items.append({"index": match.group(1), "title": match.group(2), "task_file": match.group(3)})
    return items


def request_json(base_url: str, path: str, *, timeout: float = 5.0) -> dict[str, Any]:
    target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(target, headers={"Accept": "application/json", "X-Actor": "acceptance-auditor"})
    started = time.monotonic()
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(65536).decode("utf-8", errors="replace")
            try:
                body: Any = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                body = raw[:500]
            return {
                "path": path,
                "url": target,
                "status": response.status,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "body_type": type(body).__name__,
                "ok": response.status < 400,
            }
    except HTTPError as exc:
        body = exc.read(2000).decode("utf-8", errors="replace")
        return {
            "path": path,
            "url": target,
            "status": exc.code,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "body_excerpt": body[:500],
            "ok": False,
        }
    except URLError as exc:
        return {
            "path": path,
            "url": target,
            "status": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "error": str(exc),
            "ok": False,
        }


def _lower_join(*parts: object) -> str:
    return " ".join(str(part or "").lower() for part in parts)


def _selector_from_control(control: dict[str, Any]) -> str:
    for key in ("testid", "id", "name"):
        value = str(control.get(key) or "").strip()
        if value:
            return f"{key}={value}"
    label = str(control.get("label") or "").strip()
    if label:
        return f"text={label[:80]}"
    return str(control.get("selector") or "")


def map_defect_to_backlog(defect: Defect, queue_items: list[dict[str, str]]) -> None:
    haystack = _lower_join(defect.screen, defect.title, defect.evidence, defect.code)
    for target, keywords in BACKLOG_HINTS:
        if any(keyword in haystack for keyword in keywords):
            defect.duplicate_status = "covered_by_existing_backlog" if queue_items else "recommended_target"
            defect.recommended_backlog_target = target
            return
    for item in queue_items:
        index = item.get("index", "")
        title_words = [word for word in re.findall(r"[a-z0-9]+", item.get("title", "").lower()) if len(word) > 4]
        if title_words and sum(1 for word in title_words if word in haystack) >= 2:
            defect.duplicate_status = "possible_duplicate"
            defect.recommended_backlog_target = f"backlog-{index}"
            return


def detect_screen_defects(
    snapshot: dict[str, Any],
    *,
    console_errors: list[dict[str, str]] | None = None,
    network_errors: list[dict[str, Any]] | None = None,
    queue_items: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    screen = str(snapshot.get("screen") or "unknown")
    journey = SCREEN_JOURNEYS.get(screen, "unknown")
    defects: list[Defect] = []
    text = str(snapshot.get("text") or "")
    text_lower = text.lower()
    controls = list(snapshot.get("controls") or [])
    fields = list(snapshot.get("fields") or [])

    if not str(snapshot.get("heading") or "").strip():
        defects.append(
            Defect(
                "medium",
                "missing_primary_heading",
                screen,
                journey,
                "Screen has no visible primary heading",
                "No h1/h2/[role=heading] text was visible after navigation.",
            )
        )
    if len(text.strip()) < 40 and not controls and not fields:
        defects.append(
            Defect(
                "high",
                "empty_screen",
                screen,
                journey,
                "Screen appears empty",
                f"Visible text length={len(text.strip())}; no controls or fields were collected.",
            )
        )
    for pattern in PLACEHOLDER_PATTERNS:
        if pattern in text_lower:
            defects.append(
                Defect(
                    "medium",
                    "placeholder_or_internal_copy",
                    screen,
                    journey,
                    "Screen exposes placeholder or internal copy",
                    f"Visible text contains '{pattern}'.",
                )
            )

    for control in controls:
        label = str(control.get("label") or "").strip()
        selector = _selector_from_control(control)
        if not label and not str(control.get("aria_label") or "").strip():
            defects.append(
                Defect(
                    "high",
                    "button_without_accessible_name",
                    screen,
                    journey,
                    "Visible action has no accessible name",
                    "A visible button/link/summary had no text, aria-label, title, or stable label.",
                    selector,
                )
            )
        if str(control.get("disabled")).lower() == "true":
            explanation = _lower_join(label, control.get("title"), control.get("aria_description"), control.get("near_text"))
            if not any(word in explanation for word in ["select", "requires", "connect", "disabled", "unavailable", "complete", "confirm"]):
                defects.append(
                    Defect(
                        "medium",
                        "disabled_action_without_reason",
                        screen,
                        journey,
                        "Disabled action does not explain how to unlock it",
                        f"Disabled action label='{label or selector}' has no nearby unlock reason.",
                        selector,
                    )
                )
        label_lower = label.lower()
        if any(pattern in label_lower for pattern in PLACEHOLDER_PATTERNS):
            defects.append(
                Defect(
                    "high",
                    "clickable_placeholder_action",
                    screen,
                    journey,
                    "Clickable action uses placeholder copy",
                    f"Action label='{label}'.",
                    selector,
                )
            )
        if label_lower in {"manage", "run task", "start validation"}:
            defects.append(
                Defect(
                    "medium",
                    "ambiguous_operator_action",
                    screen,
                    journey,
                    "Operator action label is ambiguous",
                    f"Action label='{label}' does not clearly describe its preconditions or outcome.",
                    selector,
                )
            )

    for f in fields:
        label = str(f.get("label") or f.get("placeholder") or f.get("aria_label") or "").strip()
        selector = _selector_from_control(f)
        if not label:
            defects.append(
                Defect(
                    "medium",
                    "field_without_guidance",
                    screen,
                    journey,
                    "Input field has no visible guidance",
                    "A visible input/select/textarea had no label, placeholder, title, or aria-label.",
                    selector,
                )
            )
        if str(field.get("required")).lower() == "true" and not label:
            defects.append(
                Defect(
                    "high",
                    "required_field_without_guidance",
                    screen,
                    journey,
                    "Required input has no guidance",
                    "A required visible field had no label or placeholder.",
                    selector,
                )
            )

    if any(token in text_lower for token in ["unavailable", "not found", "failed", "error"]):
        if not any(str(control.get("label") or "").strip() for control in controls):
            defects.append(
                Defect(
                    "high",
                    "error_state_without_action",
                    screen,
                    journey,
                    "Error or unavailable state lacks an action",
                    "The screen contains an error/unavailable state but no visible action was collected.",
                )
            )

    for entry in console_errors or []:
        defects.append(
            Defect(
                "high",
                "console_error",
                screen,
                journey,
                "Browser console error while visiting screen",
                str(entry.get("message") or "")[:500],
            )
        )
    for entry in network_errors or []:
        status = int(entry.get("status") or 0)
        severity = "high" if status >= 500 or status == 0 else "medium"
        defects.append(
            Defect(
                severity,
                "network_error",
                screen,
                journey,
                "Network error while visiting screen",
                f"{entry.get('method', 'GET')} {entry.get('url', '')} returned {entry.get('status', 'failed')}",
            )
        )

    for defect in defects:
        map_defect_to_backlog(defect, queue_items or [])
    return [asdict(defect) for defect in defects]


def _safe_value_for_field(field: dict[str, Any]) -> str | None:
    identity = _lower_join(
        field.get("testid"),
        field.get("id"),
        field.get("name"),
        field.get("label"),
        field.get("placeholder"),
        field.get("input_type"),
    )
    if any(pattern in identity for pattern in SENSITIVE_FIELD_PATTERNS):
        return None
    if "cidr" in identity or "scope" in identity or "target" in identity or "network" in identity:
        return "127.0.0.1/32"
    if "url" in identity or "webhook" in identity or "endpoint" in identity:
        return "https://example.test"
    if "email" in identity:
        return "operator@example.test"
    if "actor" in identity or "name" in identity or "owner" in identity or "tenant" in identity:
        return "acceptance-auditor"
    if "concurrency" in identity or "limit" in identity or "timeout" in identity or str(field.get("input_type")) == "number":
        return "2"
    if "exclusion" in identity:
        return "none"
    if "search" in identity:
        return "acceptance"
    if str(field.get("tag") or "").lower() == "textarea":
        return "Acceptance audit safe fixture value."
    if str(field.get("input_type") or "").lower() in {"text", "url", "email", "search", "tel", ""}:
        return "acceptance-audit"
    return None


COLLECT_SCRIPT = r"""
() => {
  const active = document.querySelector('.screen.active') || document.querySelector('[data-screen].active') || document.querySelector('main') || document.body;
  const visible = (el) => {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
  };
  const labelFor = (el) => {
    const id = el.getAttribute('id');
    const label = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null;
    return label ? label.innerText.trim() : '';
  };
  const normalize = (text) => (text || '').replace(/\s+/g, ' ').trim();
  const controls = Array.from(active.querySelectorAll('button, a, [role="button"], summary')).filter(visible).map((el) => {
    const rect = el.getBoundingClientRect();
    const parentText = normalize(el.parentElement ? el.parentElement.innerText : '').slice(0, 220);
    return {
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute('role') || '',
      label: normalize(el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || ''),
      aria_label: el.getAttribute('aria-label') || '',
      aria_description: el.getAttribute('aria-description') || '',
      title: el.getAttribute('title') || '',
      href: el.getAttribute('href') || '',
      id: el.getAttribute('id') || '',
      name: el.getAttribute('name') || '',
      testid: el.getAttribute('data-testid') || '',
      nav_screen: el.getAttribute('data-nav-screen') || '',
      disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
      near_text: parentText,
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
    };
  });
  const fields = Array.from(active.querySelectorAll('input, textarea, select')).filter(visible).map((el) => {
    const rect = el.getBoundingClientRect();
    return {
      tag: el.tagName.toLowerCase(),
      input_type: el.getAttribute('type') || '',
      label: labelFor(el),
      placeholder: el.getAttribute('placeholder') || '',
      aria_label: el.getAttribute('aria-label') || '',
      id: el.getAttribute('id') || '',
      name: el.getAttribute('name') || '',
      testid: el.getAttribute('data-testid') || '',
      required: Boolean(el.required || el.getAttribute('aria-required') === 'true'),
      disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
      readonly: Boolean(el.readOnly),
      value_present: Boolean(el.value),
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
    };
  });
  const heading = normalize((active.querySelector('h1, h2, [role="heading"]') || {}).innerText || '');
  const text = normalize(active.innerText || active.textContent || '');
  return {
    heading,
    text: text.slice(0, 5000),
    text_length: text.length,
    controls,
    fields,
    control_count: controls.length,
    field_count: fields.length,
    active_nav: Array.from(document.querySelectorAll('[data-nav-screen].active, .nav-item.active')).map((el) => normalize(el.innerText || el.getAttribute('data-nav-screen') || '')).filter(Boolean),
  };
}
"""


FIELD_CANDIDATE_SCRIPT = r"""
() => {
  const active = document.querySelector('.screen.active') || document.querySelector('[data-screen].active') || document.querySelector('main') || document.body;
  const visible = (el) => {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
  };
  const fillableTypes = new Set(['', 'text', 'url', 'email', 'search', 'tel', 'number']);
  return Array.from(active.querySelectorAll('input, textarea')).filter((el) => {
    const type = (el.getAttribute('type') || '').toLowerCase();
    return visible(el) && !el.disabled && !el.readOnly && (el.tagName.toLowerCase() === 'textarea' || fillableTypes.has(type));
  }).map((el, index) => ({
    index,
    tag: el.tagName.toLowerCase(),
    input_type: el.getAttribute('type') || '',
    testid: el.getAttribute('data-testid') || '',
    id: el.getAttribute('id') || '',
    name: el.getAttribute('name') || '',
    placeholder: el.getAttribute('placeholder') || '',
    label: el.id ? ((document.querySelector(`label[for="${CSS.escape(el.id)}"]`) || {}).innerText || '') : '',
  })).slice(0, 24);
}
"""


def _locator_for_field(page: Any, field: dict[str, Any], index: int) -> Any:
    if field.get("testid"):
        return page.locator(f'[data-testid="{field["testid"]}"]').first
    if field.get("id"):
        return page.locator(f'#{field["id"]}').first
    if field.get("name"):
        tag = str(field.get("tag") or "input").lower()
        if tag not in {"input", "textarea"}:
            tag = "input"
        return page.locator(f'{tag}[name="{field["name"]}"]').first
    return page.locator("input, textarea").nth(index)


def safe_fill_visible_fields(page: Any, screen: str, events: list[dict[str, Any]], *, limit: int = 8) -> None:
    try:
        candidates = page.evaluate(FIELD_CANDIDATE_SCRIPT)
    except Exception as exc:  # pragma: no cover - defensive for live browser drift
        events.append({"screen": screen, "action": "field_collect_failed", "error": str(exc)})
        return
    filled = 0
    for index, f in enumerate(candidates):
        if filled >= limit:
            break
        value = _safe_value_for_field(f)
        selector = _selector_from_control(f)
        if not selector:
            events.append({"screen": screen, "field": "", "action": "skipped_no_stable_selector"})
            continue
        if value is None:
            events.append({"screen": screen, "field": selector, "action": "skipped_sensitive_or_unsupported"})
            continue
        try:
            locator = _locator_for_field(page, field, index)
            locator.fill(value, timeout=1500)
            events.append({"screen": screen, "field": selector, "action": "filled_safe_value", "value_shape": _shape_value(value)})
            filled += 1
        except Exception as exc:  # pragma: no cover - live browser state dependent
            events.append({"screen": screen, "field": selector, "action": "fill_failed", "error": str(exc)[:240]})


def _shape_value(value: str) -> str:
    if value == "127.0.0.1/32":
        return "safe_loopback_cidr"
    if value.startswith("https://example.test"):
        return "reserved_example_url"
    if "@" in value:
        return "example_email"
    if value.isdigit():
        return "numeric"
    return "non_sensitive_text"


def exercise_wizard_without_launch(page: Any, events: list[dict[str, Any]]) -> None:
    selectors = [
        '[data-testid="wizard-assessment-tile-internal-lan"]',
        '[data-testid="wizard-assessment-submit-selection"]',
        '[data-testid="wizard-target-input"]',
        '[data-testid="wizard-depth-tile-passive"]',
        '[data-wizard-preview="true"]',
    ]
    try:
        tile = page.locator(selectors[0]).first
        if tile.count() and tile.is_visible(timeout=1000):
            tile.click(timeout=2000)
            events.append({"screen": "wizard", "action": "clicked_safe_tile", "selector": selectors[0]})
        next_button = page.locator(selectors[1]).first
        if next_button.count() and next_button.is_visible(timeout=1000) and next_button.is_enabled(timeout=1000):
            next_button.click(timeout=2000)
            events.append({"screen": "wizard", "action": "advanced_to_target_step", "selector": selectors[1]})
        target = page.locator(selectors[2]).first
        if target.count() and target.is_visible(timeout=1000):
            target.fill("127.0.0.1/32", timeout=2000)
            events.append({"screen": "wizard", "action": "filled_safe_loopback_target", "selector": selectors[2]})
        passive = page.locator(selectors[3]).first
        if passive.count() and passive.is_visible(timeout=1000):
            passive.click(timeout=2000)
            events.append({"screen": "wizard", "action": "selected_passive_depth", "selector": selectors[3]})
        preview = page.locator(selectors[4]).first
        if preview.count() and preview.is_visible(timeout=1000) and preview.is_enabled(timeout=1000):
            preview.click(timeout=2000)
            events.append({"screen": "wizard", "action": "opened_preview_without_launch", "selector": selectors[4]})
    except Exception as exc:  # pragma: no cover - live browser state dependent
        events.append({"screen": "wizard", "action": "wizard_safe_exercise_failed", "error": str(exc)[:300]})


def expand_settings_without_saving(page: Any, events: list[dict[str, Any]]) -> None:
    try:
        expanded = page.evaluate(
            """() => {
              const panels = Array.from(document.querySelectorAll('details, [data-settings-panel]'));
              panels.forEach((panel) => {
                if ('open' in panel) panel.open = true;
                panel.setAttribute('data-acceptance-expanded', 'true');
              });
              return panels.length;
            }"""
        )
        events.append({"screen": "settings", "action": "expanded_settings_panels", "count": expanded})
    except Exception as exc:  # pragma: no cover
        events.append({"screen": "settings", "action": "settings_expand_failed", "error": str(exc)[:240]})


def collect_snapshot(page: Any, screen: str) -> dict[str, Any]:
    snapshot = page.evaluate(COLLECT_SCRIPT)
    snapshot["screen"] = screen
    snapshot["journey"] = SCREEN_JOURNEYS.get(screen, "unknown")
    return snapshot


def discover_nav_screens(page: Any) -> list[str]:
    discovered = page.evaluate(
        """() => Array.from(document.querySelectorAll('[data-nav-screen]'))
          .map((el) => el.getAttribute('data-nav-screen'))
          .filter(Boolean)"""
    )
    screens: list[str] = []
    for screen in PRIMARY_SCREENS + discovered:
        if screen not in screens:
            screens.append(screen)
    return screens


def navigate_to_screen(page: Any, screen: str) -> bool:
    selector = f'[data-nav-screen="{screen}"]'
    try:
        locator = page.locator(selector).first
        if locator.count() and locator.is_visible(timeout=1000):
            locator.click(timeout=2000)
            page.wait_for_timeout(400)
            return True
    except Exception:
        pass
    try:
        changed = page.evaluate(
            """(screen) => {
              const button = document.querySelector(`[data-nav-screen="${CSS.escape(screen)}"]`);
              if (button) {
                button.click();
                return true;
              }
              return false;
            }""",
            screen,
        )
        if changed:
            page.wait_for_timeout(400)
            return True
    except Exception:
        return False
    return False


def run_audit(base_url: str, *, output_json: Path, output_md: Path, max_seconds: int = 120, headed: bool = False) -> AuditResult:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Playwright is required for the full-system acceptance audit.") from exc

    root = repo_root()
    queue_items = read_task_queue(root)
    started = time.monotonic()
    result = AuditResult(
        generated_at=datetime.now(UTC).isoformat(),
        base_url=base_url.rstrip("/"),
        duration_seconds=0.0,
        live_environment_relevant=True,
    )
    result.health = request_json(base_url, "/health/live")
    for path in ["/api/v1/dashboard", "/api/v1/settings", "/api/v1/engagements", "/api/v1/runs"]:
        result.api_checks.append(request_json(base_url, path))

    current_screen = {"value": "bootstrap"}
    if not result.health.get("ok"):
        defect = Defect(
            "critical",
            "local_runtime_unreachable",
            "bootstrap",
            "control_plane",
            "Local runtime health check failed before browser audit",
            json.dumps(result.health, sort_keys=True)[:800],
            recommended_backlog_target="backlog-181",
        )
        result.defects.append(asdict(defect))
        result.crawl_notes.append("Browser crawl skipped because /health/live was unhealthy or unreachable.")
        result.duration_seconds = round(time.monotonic() - started, 2)
        _write_result_artifacts(result, output_json, output_md)
        return result

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not headed)
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            console_errors_by_screen: dict[str, list[dict[str, str]]] = {}
            network_errors_by_screen: dict[str, list[dict[str, Any]]] = {}

            def console_handler(message: Any) -> None:
                if message.type in {"error", "warning"}:
                    console_errors_by_screen.setdefault(current_screen["value"], []).append(
                        {"type": message.type, "message": message.text[:1000]}
                    )

            def response_handler(response: Any) -> None:
                status = response.status
                if status >= 400:
                    request = response.request
                    network_errors_by_screen.setdefault(current_screen["value"], []).append(
                        {
                            "url": response.url,
                            "status": status,
                            "method": request.method,
                            "resource_type": request.resource_type,
                        }
                    )

            def request_failed_handler(request: Any) -> None:
                network_errors_by_screen.setdefault(current_screen["value"], []).append(
                    {
                        "url": request.url,
                        "status": 0,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "failure": str(request.failure),
                    }
                )

            page.on("console", console_handler)
            page.on("response", response_handler)
            page.on("requestfailed", request_failed_handler)
            page.goto(urljoin(base_url.rstrip("/") + "/", "app/"), wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1000)
            screens = discover_nav_screens(page)
            result.crawl_notes.append(f"Discovered {len(screens)} primary/navigation screens.")

            for screen in screens:
                if time.monotonic() - started > max_seconds:
                    result.crawl_notes.append(f"Stopped early after max_seconds={max_seconds}.")
                    break
                current_screen["value"] = screen
                visited = navigate_to_screen(page, screen)
                if not visited:
                    result.screens.append(
                        {
                            "screen": screen,
                            "journey": SCREEN_JOURNEYS.get(screen, "unknown"),
                            "visited": False,
                            "heading": "",
                            "text_length": 0,
                            "control_count": 0,
                            "field_count": 0,
                            "controls": [],
                            "fields": [],
                        }
                    )
                    defect = Defect(
                        "high",
                        "unreachable_primary_screen",
                        screen,
                        SCREEN_JOURNEYS.get(screen, "unknown"),
                        "Primary screen is not reachable through visible navigation",
                        f"No visible or DOM navigation control with data-nav-screen='{screen}' could be activated.",
                    )
                    map_defect_to_backlog(defect, queue_items)
                    result.defects.append(asdict(defect))
                    continue
                if screen == "settings":
                    expand_settings_without_saving(page, result.safe_fill_events)
                if screen == "wizard":
                    exercise_wizard_without_launch(page, result.safe_fill_events)
                safe_fill_visible_fields(page, screen, result.safe_fill_events)
                snapshot = collect_snapshot(page, screen)
                snapshot["visited"] = True
                result.screens.append(snapshot)
                screen_defects = detect_screen_defects(
                    snapshot,
                    console_errors=console_errors_by_screen.get(screen, []),
                    network_errors=network_errors_by_screen.get(screen, []),
                    queue_items=queue_items,
                )
                result.defects.extend(screen_defects)

            browser.close()
    except Exception as exc:  # pragma: no cover - live audit resilience path
        defect = Defect(
            "critical",
            "audit_navigation_failed",
            current_screen["value"],
            SCREEN_JOURNEYS.get(current_screen["value"], "control_plane"),
            "Browser audit stopped before completing all screens",
            f"{type(exc).__name__}: {exc}",
            recommended_backlog_target="backlog-181",
        )
        result.defects.append(asdict(defect))
        result.crawl_notes.append(
            f"Partial audit evidence was written after browser failure on {current_screen['value']}: {type(exc).__name__}: {exc}"
        )

    result.duration_seconds = round(time.monotonic() - started, 2)
    _write_result_artifacts(result, output_json, output_md)
    return result


def _write_result_artifacts(result: AuditResult, output_json: Path, output_md: Path) -> None:
    result.backlog_crosscheck = build_backlog_crosscheck(result.defects)
    if not result.duration_seconds:
        result.duration_seconds = 0.0
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(asdict(result), indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(result, output_md)


def build_backlog_crosscheck(defects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for defect in defects:
        target = str(defect.get("recommended_backlog_target") or "triage")
        entry = grouped.setdefault(
            target,
            {
                "recommended_backlog_target": target,
                "defect_count": 0,
                "severities": {},
                "screens": set(),
            },
        )
        entry["defect_count"] += 1
        severity = str(defect.get("severity") or "unknown")
        entry["severities"][severity] = entry["severities"].get(severity, 0) + 1
        entry["screens"].add(str(defect.get("screen") or "unknown"))
    rows = []
    for entry in grouped.values():
        rows.append(
            {
                "recommended_backlog_target": entry["recommended_backlog_target"],
                "defect_count": entry["defect_count"],
                "severities": entry["severities"],
                "screens": sorted(entry["screens"]),
            }
        )
    return sorted(rows, key=lambda row: (-row["defect_count"], row["recommended_backlog_target"]))


def write_markdown(result: AuditResult, output_md: Path) -> None:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    defects = sorted(
        result.defects,
        key=lambda defect: (
            severity_order.get(str(defect.get("severity")), 9),
            str(defect.get("screen")),
            str(defect.get("code")),
        ),
    )
    lines = [
        "# Backlog 149 Full System Acceptance Defect Inventory",
        "",
        f"- Generated: `{result.generated_at}`",
        f"- Base URL: `{result.base_url}`",
        f"- Duration: `{result.duration_seconds}s`",
        f"- Screens visited/expected: `{sum(1 for screen in result.screens if screen.get('visited'))}/{len(result.screens)}`",
        f"- Defects recorded: `{len(defects)}`",
        f"- Safe field events: `{len(result.safe_fill_events)}`",
        "",
        "## API And Health",
        "",
        f"- `/health/live`: `{result.health.get('status')}` ok=`{result.health.get('ok')}`",
    ]
    for check in result.api_checks:
        lines.append(f"- `{check.get('path')}` status=`{check.get('status')}` ok=`{check.get('ok')}`")
    lines.extend(["", "## Defects", ""])
    if not defects:
        lines.append("No defects were detected by the automated heuristics.")
    else:
        lines.append("| Severity | Screen | Code | Evidence | Backlog |")
        lines.append("| --- | --- | --- | --- | --- |")
        for defect in defects:
            evidence = str(defect.get("evidence") or "").replace("\n", " ")[:180]
            lines.append(
                "| {severity} | `{screen}` | `{code}` | {evidence} | `{target}` ({dup}) |".format(
                    severity=defect.get("severity"),
                    screen=defect.get("screen"),
                    code=defect.get("code"),
                    evidence=evidence.replace("|", "\\|"),
                    target=defect.get("recommended_backlog_target"),
                    dup=defect.get("duplicate_status"),
                )
            )
    lines.extend(["", "## Screens", ""])
    for screen in result.screens:
        lines.append(
            "- `{screen}` visited=`{visited}` heading=`{heading}` controls=`{controls}` fields=`{fields}` text_length=`{text_length}`".format(
                screen=screen.get("screen"),
                visited=screen.get("visited"),
                heading=str(screen.get("heading") or "")[:80],
                controls=screen.get("control_count"),
                fields=screen.get("field_count"),
                text_length=screen.get("text_length"),
            )
        )
    lines.extend(["", "## Backlog Crosscheck", ""])
    if result.backlog_crosscheck:
        lines.append("| Backlog | Defects | Screens |")
        lines.append("| --- | ---: | --- |")
        for row in result.backlog_crosscheck:
            lines.append(
                f"| `{row['recommended_backlog_target']}` | {row['defect_count']} | {', '.join(row['screens'])} |"
            )
    else:
        lines.append("No backlog targets were inferred.")
    lines.extend(["", "## Safe Fill Evidence", ""])
    for event in result.safe_fill_events[:120]:
        lines.append(f"- `{event.get('screen')}` {event.get('action')} {event.get('field') or event.get('selector') or ''}".rstrip())
    if len(result.safe_fill_events) > 120:
        lines.append(f"- ... {len(result.safe_fill_events) - 120} additional safe-fill events omitted from markdown; see JSON.")
    lines.extend(["", "## Notes", ""])
    for note in result.crawl_notes:
        lines.append(f"- {note}")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_json = repo_root() / "codex" / "results" / f"backlog-149-full-system-acceptance-defect-inventory-{now_slug()}.json"
    default_md = default_json.with_suffix(".md")
    parser = argparse.ArgumentParser(description="Run the AegisPT full-system UI/API acceptance audit safely against localhost.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output-json", type=Path, default=default_json)
    parser.add_argument("--output-md", type=Path, default=default_md)
    parser.add_argument("--max-seconds", type=int, default=120)
    parser.add_argument("--headed", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = run_audit(
        args.base_url,
        output_json=args.output_json,
        output_md=args.output_md,
        max_seconds=args.max_seconds,
        headed=args.headed,
    )
    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    print(f"Visited {sum(1 for screen in result.screens if screen.get('visited'))}/{len(result.screens)} screens")
    print(f"Recorded {len(result.defects)} defects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
