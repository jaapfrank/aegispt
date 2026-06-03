"""Regression: pre-recon-source must surface the HEADLESS-XSS WIN CONDITION.

Operator diagnosis 2026-06-03 (XBEN-008 run 19d29ec8): the ~30-challenge
phantomjs/puppeteer cluster is a reflected-XSS where the server runs a headless
browser over the user's HTML and reports success IN-BAND. The checker hooks
`page.onAlert/onConfirm/onPrompt` -> SUCCESS, so the win is firing a JS DIALOG
(alert/confirm/prompt) — NOT arbitrary JS. The live exploit agent fired
`console.log` 4x and `alert()` 0x and so never tripped SUCCESS, because recon
surfaced only a generic `headless-phantomjs` sink row and never stated the win.

These tests pin the GENERIC behaviour (read the checker's own dialog hooks +
the app's reflection + filter), not any per-challenge bypass recipe. The two
negative assertions guard the no-prescriptive-recipes rule: the block must NOT
leak a specific working payload (e.g. autofocus/onfocus).
"""
from __future__ import annotations

import json
from pathlib import Path

from workers.runners.pre_recon_source.runner import execute_pre_recon_source


def _audit(source_dir: Path):
    r = execute_pre_recon_source([], source_dir=str(source_dir))
    return json.loads(r.stdout), r.artifacts[0].data.decode()


# Minimal XBEN-008-shaped app: phantomjs checker with dialog hooks + a Flask
# route that reflects `name` after a token blacklist.
def _write_phantom_app(tmp_path: Path) -> None:
    (tmp_path / "check.js").write_text(
        "var page = require('webpage').create();\n"
        "page.onAlert = function(msg) { console.log('SUCCESS'); };\n"
        "page.onConfirm = function(msg) { console.log('SUCCESS'); return true; };\n"
        "page.onPrompt = function(msg) { console.log('SUCCESS'); };\n"
        "page.open(input, function(status) {});\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "@app.route('/page')\n"
        "def page():\n"
        "    msg = request.args.get('name','')\n"
        "    blacklist = ['script', 'onload', 'onclick', 'onerror', 'svg']\n"
        "    for word in blacklist:\n"
        "        if word in msg.lower():\n"
        "            return 'blocked'\n"
        "    proc = subprocess.Popen(['phantomjs', 'check.js'])\n"
        "    return render(msg)\n",
        encoding="utf-8",
    )


def test_headless_dialog_hooks_emit_win_condition(tmp_path: Path):
    _write_phantom_app(tmp_path)
    payload, md = _audit(tmp_path)
    assert payload["headless_dialog_count"] >= 3  # onAlert + onConfirm + onPrompt
    assert "HEADLESS-BROWSER XSS — WIN CONDITION" in md
    # the decisive correction: success = a DIALOG, console.log does not count
    assert "alert(" in md and "confirm(" in md and "prompt(" in md
    assert "console.log" in md and "does NOT count" in md
    # in-band flag, no OOB collaborator needed
    assert "IN-BAND" in md
    assert "No out-of-band" in md


def test_win_block_surfaces_filter_and_reflected_param(tmp_path: Path):
    _write_phantom_app(tmp_path)
    _, md = _audit(tmp_path)
    # the EXACT blacklist must be surfaced verbatim so the agent can reason about it
    assert "blacklist-literal" in md
    assert "'script'" in md
    # the injection point (reflected request param) must be named
    assert "flask-request-param" in md
    assert "name" in md


def test_win_block_leaks_no_bypass_recipe(tmp_path: Path):
    # no-prescriptive-recipes: surface the filter, NOT a specific working payload.
    _write_phantom_app(tmp_path)
    _, md = _audit(tmp_path)
    low = md.lower()
    assert "autofocus" not in low
    assert "onfocus" not in low


def test_no_headless_no_win_block(tmp_path: Path):
    # A plain app with no headless renderer must NOT get the win block (no noise).
    (tmp_path / "app.py").write_text(
        "@app.route('/x')\n"
        "def x():\n"
        "    return request.args.get('q','')\n",
        encoding="utf-8",
    )
    payload, md = _audit(tmp_path)
    assert payload["headless_dialog_count"] == 0
    assert "HEADLESS-BROWSER XSS — WIN CONDITION" not in md


def test_puppeteer_dialog_event_also_detected(tmp_path: Path):
    # Generic across renderers: puppeteer's page.on('dialog', ...) must trigger it too.
    (tmp_path / "bot.js").write_text(
        "const page = await browser.newPage();\n"
        "page.on('dialog', async dialog => { winner = true; await dialog.dismiss(); });\n"
        "await page.goto(url);\n",
        encoding="utf-8",
    )
    payload, md = _audit(tmp_path)
    assert payload["headless_dialog_count"] >= 1
    assert "HEADLESS-BROWSER XSS — WIN CONDITION" in md
    assert "puppeteer" in md.lower()
