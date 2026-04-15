from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from cryptography.fernet import Fernet
from playwright.sync_api import Page, Playwright, expect, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = REPO_ROOT / "ui" / "test-results"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_http(url: str, *, timeout_seconds: int = 30) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except URLError as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}") from last_error


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    result = outcome.get_result()
    setattr(item, f"rep_{result.when}", result)


@pytest.fixture(scope="session")
def operator_console_base_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    temp_root = tmp_path_factory.mktemp("ui-browser")
    database_path = temp_root / "aegispt-ui.db"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "AEGISPT_CODEX_REPO_ROOT": str(temp_root),
            "DATABASE_URL": f"sqlite+pysqlite:///{database_path}",
            "AUTO_CREATE_TABLES": "true",
            "TASK_DISPATCH_MODE": "inline",
            "APP_PUBLIC_BASE_URL": base_url,
            "LOCAL_SECRET_ENCRYPTION_KEY": Fernet.generate_key().decode("utf-8"),
        }
    )

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api.app.main:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_http(f"{base_url}/health/live")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.fixture(scope="session")
def playwright_instance() -> Iterator[Playwright]:
    with sync_playwright() as playwright:
        yield playwright


@pytest.fixture
def page(
    playwright_instance: Playwright, request: pytest.FixtureRequest, operator_console_base_url: str
) -> Iterator[Page]:
    browser = playwright_instance.chromium.launch()
    context = browser.new_context(base_url=operator_console_base_url, viewport={"width": 1600, "height": 1200})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.set_default_navigation_timeout(15000)
    yield page

    failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)
    if failed:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", request.node.nodeid)
        screenshot_path = ARTIFACTS_DIR / f"{slug}.png"
        trace_path = ARTIFACTS_DIR / f"{slug}.zip"
        page.screenshot(path=str(screenshot_path), full_page=True)
        context.tracing.stop(path=str(trace_path))
    else:
        context.tracing.stop()
    context.close()
    browser.close()


@pytest.fixture
def loaded_page(page: Page) -> Page:
    page.goto("/app/")
    expect(page.get_by_role("heading", name="Operator Console")).to_be_visible()
    return page
