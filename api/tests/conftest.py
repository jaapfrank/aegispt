from __future__ import annotations

from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from fastapi.testclient import TestClient


def _build_client(tmp_path, monkeypatch, dispatch_mode: str) -> Iterator[TestClient]:
    database_path = tmp_path / f"aegispt-{dispatch_mode}.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", dispatch_mode)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()


@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    yield from _build_client(tmp_path, monkeypatch, dispatch_mode="manual")


@pytest.fixture
def inline_client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    yield from _build_client(tmp_path, monkeypatch, dispatch_mode="inline")


@pytest.fixture
def inline_s3_client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ARTIFACTS_STORAGE_MODE", "s3")
    yield from _build_client(tmp_path, monkeypatch, dispatch_mode="inline")


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


@pytest.fixture
def probe_server() -> str:
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
