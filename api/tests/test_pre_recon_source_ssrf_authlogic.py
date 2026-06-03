"""Regression: pre-recon-source must detect SSRF server-fetch sinks + forgeable
session secrets so the dispatch gate fires interactive-exploit on the SSRF /
auth-logic class (Joern has no SSRF taint query, so these reported sink_count=0 and
the loop chased web probes instead — XBEN-024, memory E#12).
"""
from __future__ import annotations

import json
from pathlib import Path

from workers.runners.pre_recon_source.runner import execute_pre_recon_source


def _audit(src: Path):
    r = execute_pre_recon_source([], source_dir=str(src))
    return json.loads(r.stdout), r.artifacts[0].data.decode()


def test_ssrf_urlretrieve_is_a_sink(tmp_path: Path):
    # XBEN-024 shape: server fetches an attacker-supplied URL.
    (tmp_path / "app.py").write_text(
        "import urllib.request\n"
        "def profile(url):\n"
        "    urllib.request.urlretrieve(url, '/tmp/x')\n",
        encoding="utf-8",
    )
    payload, md = _audit(tmp_path)
    assert payload["sink_count"] >= 1
    assert "ssrf-urlretrieve" in md


def test_ssrf_requests_and_urlopen_and_httpx(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import requests, httpx\n"
        "from urllib.request import urlopen\n"
        "def f(u):\n"
        "    requests.get(u)\n"
        "    urlopen(u)\n"
        "    httpx.post(u)\n",
        encoding="utf-8",
    )
    _, md = _audit(tmp_path)
    for label in ("ssrf-requests", "ssrf-urlopen", "ssrf-httpx"):
        assert label in md, f"expected {label}"


def test_forgeable_secret_key_surfaced_as_gate_token(tmp_path: Path):
    # a hardcoded Flask secret -> the agent can forge an admin session cookie.
    (tmp_path / "app.py").write_text(
        "app = Flask(__name__)\n"
        "app.secret_key = 'supersecretkey'\n",
        encoding="utf-8",
    )
    _, md = _audit(tmp_path)
    assert "forgeable-session-secret" in md
    assert "supersecretkey" in md  # the EXACT literal so the agent signs its cookie


def test_jwt_secret_and_config_form(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "JWT_SECRET = 'hunter2hunter2'\n"
        "app.config['SECRET_KEY'] = 'cfgsecretvalue'\n",
        encoding="utf-8",
    )
    _, md = _audit(tmp_path)
    assert "forgeable-session-secret" in md
    assert "hunter2hunter2" in md or "cfgsecretvalue" in md


def test_xben024_shape_dispatch_gate_unblocked(tmp_path: Path):
    # the combined XBEN-024 shape: SSRF + weak secret => sink_count>0 AND a gate token,
    # so the assessment_loop dispatch gate (sinks OR gate tokens) fires interactive-exploit.
    (tmp_path / "app.py").write_text(
        "import urllib.request\n"
        "app.secret_key = 'supersecretkey'\n"
        "def profile():\n"
        "    url = request.form.get('profile_picture_url')\n"
        "    urllib.request.urlretrieve(url, '/tmp/x')\n",
        encoding="utf-8",
    )
    payload, md = _audit(tmp_path)
    assert payload["sink_count"] >= 1
    assert "ssrf-urlretrieve" in md
    assert "forgeable-session-secret" in md
