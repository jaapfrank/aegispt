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

VIEWPORTS = {
    "desktop": {"width": 1440, "height": 1000},
    "narrow": {"width": 390, "height": 844},
}

STALE_PRODUCT_TERMS = [
    "mockup",
    "compatibility route",
    "coming soon",
    "not implemented",
    "placeholder",
    "lorem",
    "undefined",
    "nan",
]

INTERNAL_TERM_ALLOWLIST = {
    "legacy": set(),
}


@dataclass
class PageScore:
    screen: str
    viewport: str
    score: float
    heading: str
    screenshot: str
    purpose_ok: bool
    workflow_ok: bool
    empty_state_ok: bool
    error_state_ok: bool
    accessibility_ok: bool
    data_truth_ok: bool
    next_action_ok: bool
    controls: list[dict[str, Any]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    generated_at: str
    base_url: str
    duration_seconds: float
    pages: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    health: dict[str, Any] = field(default_factory=dict)
    failure_notes: list[str] = field(default_factory=list)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def now_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def request_json(base_url: str, path: str, *, timeout: float = 5.0) -> dict[str, Any]:
    target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(target, headers={"Accept": "application/json", "X-Actor": "ia-auditor"})
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
                "body": body,
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


def visible_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def js_snapshot() -> str:
    return r"""
    (screen) => {
      const active = document.querySelector(`#screen-${screen}`) || document.querySelector(".screen.active");
      const visible = (element) => {
        if (!element) return false;
        const style = window.getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity || "1") > 0 && rect.width > 0 && rect.height > 0;
      };
      const labelFor = (element) => {
        const text = (element.innerText || element.value || "").trim();
        const aria = element.getAttribute("aria-label") || "";
        const title = element.getAttribute("title") || "";
        const id = element.id ? document.querySelector(`label[for="${CSS.escape(element.id)}"]`)?.innerText || "" : "";
        const wrapped = element.closest("label")?.innerText || "";
        return (aria || title || text || id || wrapped || "").replace(/\s+/g, " ").trim();
      };
      const selectorFor = (element) => {
        if (element.dataset?.testid) return `[data-testid="${element.dataset.testid}"]`;
        if (element.id) return `#${element.id}`;
        if (element.name) return `[name="${element.name}"]`;
        return element.tagName.toLowerCase();
      };
      const controls = Array.from(active?.querySelectorAll("button,a,input,select,textarea,summary,[role='button']") || [])
        .map((element) => ({
          tag: element.tagName.toLowerCase(),
          label: labelFor(element),
          selector: selectorFor(element),
          visible: visible(element),
          disabled: Boolean(element.disabled || element.getAttribute("aria-disabled") === "true"),
          primary: element.classList.contains("primary") || element.classList.contains("sidebar-new-mission"),
        }));
      const text = (active?.innerText || "").replace(/\s+/g, " ").trim();
      const duplicateNavTargets = Array.from(document.querySelectorAll("[data-nav-screen]")).reduce((acc, element) => {
        const target = element.getAttribute("data-nav-screen");
        if (!target) return acc;
        acc[target] = acc[target] || { total: 0, visible: 0, hidden_focusable: 0 };
        acc[target].total += 1;
        if (visible(element)) acc[target].visible += 1;
        const style = window.getComputedStyle(element);
        const hiddenButStillRendered = style.display !== "none" && style.visibility !== "hidden";
        if (!visible(element) && hiddenButStillRendered && element.tabIndex >= 0 && !element.disabled) acc[target].hidden_focusable += 1;
        return acc;
      }, {});
      return {
        screen,
        heading: active?.querySelector("h1,h2")?.innerText || "",
        copy: active?.querySelector(".screen-copy")?.innerText || "",
        text,
        textLength: text.length,
        controls,
        visibleControls: controls.filter((control) => control.visible),
        emptyStates: Array.from(active?.querySelectorAll(".empty-state,.section-note,.inline-errors,[data-testid*='empty']") || [])
          .filter(visible)
          .map((element) => (element.innerText || "").replace(/\s+/g, " ").trim()),
        errorTexts: Array.from(active?.querySelectorAll(".inline-errors,.error,.tone-error,[data-testid*='error']") || [])
          .filter(visible)
          .map((element) => (element.innerText || "").replace(/\s+/g, " ").trim()),
        duplicateNavTargets,
      };
    }
    """


def score_snapshot(screen: str, viewport: str, snapshot: dict[str, Any], screenshot: Path) -> PageScore:
    issues: list[str] = []
    heading = visible_text(snapshot.get("heading"))
    text = visible_text(snapshot.get("text"))
    controls = snapshot.get("visibleControls") or []
    unlabeled = [
        control
        for control in controls
        if control.get("tag") in {"button", "a", "input", "select", "textarea", "summary"}
        and not visible_text(control.get("label"))
    ]
    hidden_focusable_nav: list[str] = []

    purpose_ok = bool(heading) and len(text) >= 40
    workflow_ok = bool(controls) or any(keyword in text.lower() for keyword in ["no ", "none ", "create", "open", "select"])
    empty_text = " ".join(snapshot.get("emptyStates") or [])
    empty_state_ok = not empty_text or any(keyword in empty_text.lower() for keyword in ["create", "open", "select", "after", "once", "use", "run", "available"])
    error_text = " ".join(snapshot.get("errorTexts") or [])
    error_state_ok = not error_text or any(keyword in error_text.lower() for keyword in ["open", "review", "retry", "settings", "detail", "resolve"])
    accessibility_ok = not unlabeled

    lower_text = text.lower()
    stale_terms = []
    for term in STALE_PRODUCT_TERMS:
        if term == "nan":
            if re.search(r"\bnan\b", lower_text):
                stale_terms.append(term)
        elif term in lower_text:
            stale_terms.append(term)
    for term, allowed_screens in INTERNAL_TERM_ALLOWLIST.items():
        if term in lower_text and screen not in allowed_screens:
            stale_terms.append(term)
    data_truth_ok = not stale_terms and "[object object]" not in lower_text
    next_action_ok = any(
        keyword in lower_text
        for keyword in ["open", "create", "select", "launch", "view", "refresh", "sync", "export", "validate", "approve", "deploy", "cleanup"]
    )

    if not purpose_ok:
      issues.append("missing clear heading or explanatory page text")
    if not workflow_ok:
      issues.append("no visible workflow controls or guided empty state")
    if not empty_state_ok:
      issues.append("empty state does not explain the next action")
    if not error_state_ok:
      issues.append("error state does not provide a recovery action")
    if unlabeled:
      issues.append("unlabeled visible controls: " + ", ".join(visible_text(item.get("selector")) for item in unlabeled[:5]))
    if stale_terms:
      issues.append("stale/internal product terms visible: " + ", ".join(sorted(set(stale_terms))))
    if not next_action_ok:
      issues.append("page does not expose an obvious next action")

    score = 10.0
    score -= 1.5 * (not purpose_ok)
    score -= 1.25 * (not workflow_ok)
    score -= 1.0 * (not empty_state_ok)
    score -= 1.0 * (not error_state_ok)
    score -= 1.25 * (not accessibility_ok)
    score -= 1.25 * (not data_truth_ok)
    score -= 0.75 * (not next_action_ok)

    return PageScore(
        screen=screen,
        viewport=viewport,
        score=round(max(score, 0.0), 2),
        heading=heading,
        screenshot=str(screenshot),
        purpose_ok=purpose_ok,
        workflow_ok=workflow_ok,
        empty_state_ok=empty_state_ok,
        error_state_ok=error_state_ok,
        accessibility_ok=accessibility_ok,
        data_truth_ok=data_truth_ok,
        next_action_ok=next_action_ok,
        controls=controls[:20],
        issues=issues,
    )


def write_markdown(result: AuditResult, output_path: Path) -> None:
    pages = result.pages
    lines = [
        "# Backlog 153 Enterprise IA Audit",
        "",
        f"- Generated: `{result.generated_at}`",
        f"- Base URL: `{result.base_url}`",
        f"- Duration: `{result.duration_seconds:.2f}s`",
        f"- `/health/live`: `{result.health.get('status')}` ok=`{result.health.get('ok')}`",
        f"- Average score: `{result.summary.get('average_score')}`",
        f"- Minimum score: `{result.summary.get('minimum_score')}`",
        "",
        "| Screen | Viewport | Score | Heading | Evidence | Issues |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for page in pages:
        issues = "; ".join(page.get("issues") or []) or "none"
        lines.append(
            "| {screen} | {viewport} | {score} | {heading} | {screenshot} | {issues} |".format(
                screen=page["screen"],
                viewport=page["viewport"],
                score=page["score"],
                heading=page["heading"].replace("|", "\\|"),
                screenshot=page["screenshot"],
                issues=issues.replace("|", "\\|"),
            )
        )
    lines.extend(
        [
            "",
            "## Failure Notes",
            "",
        ]
    )
    if result.failure_notes:
        for note in result.failure_notes:
            lines.append(f"- {note}")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Remaining Risks",
            "",
            "- This audit verifies product clarity, navigation, visible controls, and screenshots. It does not prove every backend runner or external integration path.",
            "- Pack Forge still uses build-lane task API identifiers internally; visible copy now explains the operator concept as supervised build-lane work.",
        ]
    )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_audit(args: argparse.Namespace) -> AuditResult:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - dependency guard for local operators.
        raise SystemExit(f"Playwright is required for the enterprise IA audit: {exc}") from exc

    started = time.monotonic()
    screenshot_dir = Path(args.screenshot_dir)
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    pages: list[PageScore] = []
    health = request_json(args.base_url, "/health/live")
    failure_notes: list[str] = []

    if not health.get("ok"):
        failure_notes.append(f"Browser audit skipped because /health/live was unhealthy or unreachable: {health}")
        return _build_audit_result(args, started, pages, health, failure_notes)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for viewport_name, viewport in VIEWPORTS.items():
                    context = browser.new_context(viewport=viewport)
                    page = context.new_page()
                    page.goto(args.base_url.rstrip("/") + "/app/", wait_until="domcontentloaded", timeout=args.page_timeout_ms)
                    page.wait_for_timeout(args.settle_ms)
                    for screen in PRIMARY_SCREENS:
                        clicked = page.evaluate(
                            """
                            (screen) => {
                              const controls = Array.from(document.querySelectorAll(`[data-nav-screen="${screen}"]`));
                              const visible = (element) => {
                                const style = window.getComputedStyle(element);
                                const rect = element.getBoundingClientRect();
                                return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
                              };
                              const target = controls.find(visible) || controls[0];
                              if (!target) return false;
                              target.click();
                              return true;
                            }
                            """,
                            screen,
                        )
                        if not clicked and screen != "wizard":
                            page.evaluate(
                                "(screen) => { document.querySelectorAll('.screen').forEach((item) => item.classList.remove('active')); document.querySelector(`#screen-${screen}`)?.classList.add('active'); }",
                                screen,
                            )
                        page.wait_for_timeout(args.settle_ms)
                        screenshot_path = screenshot_dir / f"{screen}-{viewport_name}.png"
                        page.screenshot(path=screenshot_path, full_page=True)
                        snapshot = page.evaluate(js_snapshot(), screen)
                        pages.append(score_snapshot(screen, viewport_name, snapshot, screenshot_path))
                    context.close()
            finally:
                browser.close()
    except Exception as exc:  # pragma: no cover - live audit resilience path
        failure_notes.append(
            f"Partial IA audit evidence was written after browser failure: {type(exc).__name__}: {exc}"
        )

    return _build_audit_result(args, started, pages, health, failure_notes)


def _build_audit_result(
    args: argparse.Namespace,
    started: float,
    pages: list[PageScore],
    health: dict[str, Any],
    failure_notes: list[str],
) -> AuditResult:
    scores = [page.score for page in pages]
    return AuditResult(
        generated_at=datetime.now(UTC).isoformat(),
        base_url=args.base_url,
        duration_seconds=round(time.monotonic() - started, 2),
        pages=[asdict(page) for page in pages],
        summary={
            "screen_count": len(PRIMARY_SCREENS),
            "viewport_count": len(VIEWPORTS),
            "page_checks": len(pages),
            "average_score": round(sum(scores) / len(scores), 2) if scores else 0,
            "minimum_score": min(scores) if scores else 0,
            "issue_count": sum(len(page.issues) for page in pages),
            "partial": bool(failure_notes) or len(pages) < len(PRIMARY_SCREENS) * len(VIEWPORTS),
        },
        health=health,
        failure_notes=failure_notes,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit AegisPT enterprise IA and page UX clarity.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output-json", default=f"codex/results/backlog-153-enterprise-ia-audit-{now_slug()}.json")
    parser.add_argument("--output-md", default=f"codex/results/backlog-153-enterprise-ia-audit-{now_slug()}.md")
    parser.add_argument("--screenshot-dir", default=f"codex/results/backlog-153-enterprise-ia-screenshots-{now_slug()}")
    parser.add_argument("--page-timeout-ms", type=int, default=30000)
    parser.add_argument("--settle-ms", type=int, default=500)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = repo_root()
    output_json = root / args.output_json
    output_md = root / args.output_md
    if not Path(args.screenshot_dir).is_absolute():
        args.screenshot_dir = str(root / args.screenshot_dir)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)

    result = run_audit(args)
    output_json.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(result, output_md)
    print(json.dumps(result.summary, indent=2, sort_keys=True))
    return 0 if result.summary.get("minimum_score", 0) >= 8.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
