from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest
from cryptography.fernet import Fernet
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, Playwright, expect, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = REPO_ROOT / "ui" / "test-results"


def _artifact_paths(nodeid: str) -> tuple[Path, Path]:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", nodeid).strip("_")
    digest = hashlib.sha1(nodeid.encode("utf-8")).hexdigest()[:10]
    compact_slug = slug[:110].rstrip("_") or "playwright-artifact"
    artifact_name = f"{compact_slug}_{digest}"
    return ARTIFACTS_DIR / f"{artifact_name}.png", ARTIFACTS_DIR / f"{artifact_name}.zip"


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


def _patch_operator_settings(base_url: str, payload: dict[str, object]) -> None:
    request = Request(
        f"{base_url}/api/v1/settings",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Actor": "ui-test"},
        method="PATCH",
    )
    with urlopen(request, timeout=10) as response:
        if response.status >= 400:
            raise RuntimeError(f"Failed to patch operator settings via {request.full_url}: {response.status}")


def _start_operator_console(
    tmp_path_factory: pytest.TempPathFactory,
    *,
    dispatch_mode: str,
) -> Iterator[str]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    temp_root = Path(
        tempfile.mkdtemp(
            prefix=f"aegispt-ui-browser-{dispatch_mode}-",
            dir=os.environ.get("AEGISPT_UI_TEST_TMPDIR", "/tmp"),
        )
    )
    database_path = temp_root / f"aegispt-ui-{dispatch_mode}.db"
    fake_nmap_binary = _build_fake_nmap_binary(temp_root)
    fake_nuclei_binary = _build_fake_nuclei_binary(temp_root)
    server_log_path = temp_root / "uvicorn.log"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "AEGISPT_CODEX_REPO_ROOT": str(temp_root),
            "DATABASE_URL": f"sqlite+pysqlite:///{database_path}",
            "AUTO_CREATE_TABLES": "true",
            "TASK_DISPATCH_MODE": dispatch_mode,
            "APP_PUBLIC_BASE_URL": base_url,
            "LOCAL_SECRET_ENCRYPTION_KEY": Fernet.generate_key().decode("utf-8"),
            "NMAP_BINARY": str(fake_nmap_binary),
            "NUCLEI_BINARY": str(fake_nuclei_binary),
        }
    )

    try:
        with server_log_path.open("w", encoding="utf-8") as server_log:
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
                stdout=server_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                _wait_for_http(f"{base_url}/health/live")
                yield base_url
            except RuntimeError as exc:
                log_tail = server_log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                raise RuntimeError(f"{exc}\nUvicorn log tail:\n{log_tail}") from exc
            finally:
                if process.poll() is not None:
                    preserved_log = ARTIFACTS_DIR / f"uvicorn-{dispatch_mode}-{port}.log"
                    shutil.copyfile(server_log_path, preserved_log)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _build_fake_nmap_binary(temp_root: Path) -> Path:
    binary_path = temp_root / "fake-nmap"
    binary_path.write_text(
        """#!/usr/bin/env python3
import ipaddress
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("Nmap version test-build")
    raise SystemExit(0)

output_path = Path(args[args.index("-oX") + 1])
discovery_only = "-sn" in args
targets = []
skip_next = False
for arg in args:
    if skip_next:
        skip_next = False
        continue
    if arg in {"-oX", "--top-ports"}:
        skip_next = True
        continue
    if arg.startswith("-"):
        continue
    targets.append(arg)

hosts = []
for target in targets:
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts.extend(str(host) for host in list(network.hosts())[:3])
    except ValueError:
        hosts.append(target)

if not hosts:
    hosts = ["10.0.20.1", "10.0.20.24", "10.0.20.42"]

if discovery_only:
    xml = "<?xml version='1.0'?><nmaprun>" + "".join(
        f"<host><status state='up'/><address addr='{host}' addrtype='ipv4'/></host>"
        for host in hosts
    ) + "</nmaprun>"
else:
    xml = "<?xml version='1.0'?><nmaprun>" + "".join(
        f\"\"\"<host>
<status state='up'/>
<address addr='{host}' addrtype='ipv4'/>
<ports>
  <port protocol='tcp' portid='80'>
    <state state='open'/>
    <service name='http' product='nginx' version='1.24'/>
  </port>
  <port protocol='tcp' portid='22'>
    <state state='open'/>
    <service name='ssh' product='OpenSSH' version='9.7'/>
  </port>
</ports>
</host>\"\"\"
        for host in hosts
    ) + "</nmaprun>"
output_path.write_text(xml, encoding="utf-8")
print(xml)
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return binary_path


def _build_fake_nuclei_binary(temp_root: Path) -> Path:
    binary_path = temp_root / "fake-nuclei"
    binary_path.write_text(
        """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
if "-version" in args:
    print("nuclei v-ui-test")
    raise SystemExit(0)

output_path = Path(args[args.index("-jsonl-export") + 1])
output_path.write_text("", encoding="utf-8")
print("", end="")
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return binary_path


class ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    result = outcome.get_result()
    setattr(item, f"rep_{result.when}", result)


@pytest.fixture
def operator_console_base_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    yield from _start_operator_console(tmp_path_factory, dispatch_mode="inline")


@pytest.fixture
def manual_operator_console_base_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    yield from _start_operator_console(tmp_path_factory, dispatch_mode="manual")


@pytest.fixture
def probe_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        yield f"http://{host}:{port}/health/live"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def playwright_instance() -> Iterator[Playwright]:
    with sync_playwright() as playwright:
        yield playwright


@pytest.fixture
def page(
    playwright_instance: Playwright, request: pytest.FixtureRequest, operator_console_base_url: str
) -> Iterator[Page]:
    _patch_operator_settings(
        operator_console_base_url,
        {"settings": {"instance.onboarding_completed": True}},
    )
    browser = playwright_instance.chromium.launch()
    context = browser.new_context(base_url=operator_console_base_url, viewport={"width": 1600, "height": 1200})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.set_default_navigation_timeout(15000)
    page_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    yield page

    failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)
    unexpected_page_errors = bool(page_errors)
    if failed or unexpected_page_errors:
        screenshot_path, trace_path = _artifact_paths(request.node.nodeid)
        page.screenshot(path=str(screenshot_path), full_page=True)
        context.tracing.stop(path=str(trace_path))
    else:
        context.tracing.stop()
    context.close()
    browser.close()
    if not failed and unexpected_page_errors:
        raise AssertionError(
            "Unexpected browser page errors occurred:\n" + "\n".join(page_errors)
        )


@pytest.fixture
def loaded_page(page: Page) -> Page:
    _load_operator_app(page)
    return page


@pytest.fixture
def first_run_page(
    playwright_instance: Playwright, request: pytest.FixtureRequest, operator_console_base_url: str
) -> Iterator[Page]:
    browser = playwright_instance.chromium.launch()
    context = browser.new_context(base_url=operator_console_base_url, viewport={"width": 1600, "height": 1200})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.set_default_navigation_timeout(15000)
    page_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    yield page

    failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)
    unexpected_page_errors = bool(page_errors)
    if failed or unexpected_page_errors:
        screenshot_path, trace_path = _artifact_paths(request.node.nodeid)
        page.screenshot(path=str(screenshot_path), full_page=True)
        context.tracing.stop(path=str(trace_path))
    else:
        context.tracing.stop()
    context.close()
    browser.close()
    if not failed and unexpected_page_errors:
        raise AssertionError(
            "Unexpected browser page errors occurred:\n" + "\n".join(page_errors)
        )


@pytest.fixture
def first_run_loaded_page(first_run_page: Page) -> Page:
    _goto_operator_app(first_run_page)
    expect(first_run_page.get_by_test_id("topbar")).to_contain_text("AegisPT", timeout=15000)
    expect(first_run_page.get_by_test_id("onboarding-overlay")).to_be_visible(timeout=15000)
    return first_run_page


@pytest.fixture
def manual_page(
    playwright_instance: Playwright, request: pytest.FixtureRequest, manual_operator_console_base_url: str
) -> Iterator[Page]:
    _patch_operator_settings(
        manual_operator_console_base_url,
        {"settings": {"instance.onboarding_completed": True}},
    )
    browser = playwright_instance.chromium.launch()
    context = browser.new_context(base_url=manual_operator_console_base_url, viewport={"width": 1600, "height": 1200})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.set_default_navigation_timeout(15000)
    page_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    yield page

    failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)
    unexpected_page_errors = bool(page_errors)
    if failed or unexpected_page_errors:
        screenshot_path, trace_path = _artifact_paths(request.node.nodeid)
        page.screenshot(path=str(screenshot_path), full_page=True)
        context.tracing.stop(path=str(trace_path))
    else:
        context.tracing.stop()
    context.close()
    browser.close()
    if not failed and unexpected_page_errors:
        raise AssertionError(
            "Unexpected browser page errors occurred:\n" + "\n".join(page_errors)
        )


@pytest.fixture
def manual_loaded_page(manual_page: Page) -> Page:
    _load_operator_app(manual_page)
    return manual_page


def _load_operator_app(page: Page) -> None:
    last_error: AssertionError | None = None
    for _ in range(3):
        _goto_operator_app(page)
        try:
            expect(page.get_by_test_id("topbar")).to_contain_text("AegisPT", timeout=15000)
            expect(page.get_by_test_id("conversation-question")).to_be_visible(timeout=15000)
            return
        except AssertionError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error


def _goto_operator_app(page: Page) -> None:
    last_error: PlaywrightError | None = None
    for _ in range(3):
        try:
            page.goto("/app/", wait_until="domcontentloaded")
            return
        except PlaywrightError as exc:
            if "ERR_NETWORK_CHANGED" not in str(exc):
                raise
            last_error = exc
            page.wait_for_timeout(250)
    if last_error is not None:
        raise last_error
