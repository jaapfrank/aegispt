"""Regression: pre-recon-source must detect PHP dangerous sinks.

Operator-flagged 2026-06-01 (XBEN-014): the source-audit runner had NO
PHP-specific sinks. `pickle.loads` covered Python deserialization but PHP
`unserialize()` (insecure deserialization / object injection) was absent, so a
PHP app whose only vuln is `unserialize($_COOKIE['creds'])` reported
`sink_count=0`. The loop never saw the real vuln and chased a smart-web-probe
false-positive "SQLi auth bypass" instead. These tests pin the generic PHP sink
CLASSES (not any challenge-specific recipe).
"""
from __future__ import annotations

import json
from pathlib import Path

from workers.runners.pre_recon_source.runner import execute_pre_recon_source


def _sinks(source_dir: Path) -> list[dict]:
    r = execute_pre_recon_source([], source_dir=str(source_dir))
    md = r.artifacts[0].data.decode()
    payload = json.loads(r.stdout)
    return payload, md


def test_unserialize_cookie_is_critical_sink(tmp_path: Path):
    # The exact XBEN-014 shape: PHP insecure deserialization of a cookie.
    (tmp_path / "index.php").write_text(
        "<?php $auth = unserialize(base64_decode($_COOKIE['creds'])); ?>",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    assert payload["sink_count"] >= 1
    assert payload["critical_sinks"] >= 1
    assert "php-unserialize" in md
    # the $_COOKIE source must be visible in the snippet so the LLM can taint-reason
    assert "$_COOKIE" in md


def test_ssti_jinja2_template_constructor_is_critical_sink(tmp_path: Path):
    # XBEN-080 shape: Jinja2 Template() over a runtime f-string -> SSTI -> RCE.
    # Joern's CPG misses this; without the sink the gate early-returns NOSINKS and
    # interactive-exploit is never dispatched.
    (tmp_path / "app.py").write_text(
        "from jinja2 import Template\n"
        "def submit(name):\n"
        "    return Template(f'Thank you {name}.').render()\n",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    assert payload["sink_count"] >= 1
    assert payload["critical_sinks"] >= 1
    assert "jinja2-Template" in md


def test_ssti_from_string_is_critical_sink(tmp_path: Path):
    # XBEN-053 shape: env.from_string(user_input).render().
    (tmp_path / "app.py").write_text(
        "from jinja2 import Environment\n"
        "def render(u):\n"
        "    return Environment().from_string('Welcome ' + u).render()\n",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    assert payload["sink_count"] >= 1
    assert "jinja2-from-string" in md


def test_render_template_file_not_flagged_as_template_constructor(tmp_path: Path):
    # render_template() / render_template_string() must NOT match the bare
    # `Template(` constructor pattern (no word boundary before embedded Template).
    (tmp_path / "safe.py").write_text(
        "from flask import render_template\n"
        "def page():\n"
        "    return render_template('index.html')\n",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    assert "jinja2-Template" not in md


def test_xxe_resolve_entities_is_critical_sink(tmp_path: Path):
    # XBEN-096/032 shape: lxml parser with external-entity resolution.
    (tmp_path / "app.py").write_text(
        "from lxml import etree\n"
        "def addbook(xml):\n"
        "    parser = etree.XMLParser(no_network=False, resolve_entities=True)\n"
        "    return etree.fromstring(str(xml), parser)\n",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    assert payload["sink_count"] >= 1
    assert payload["critical_sinks"] >= 1
    assert "xxe-resolve-entities" in md
    assert "lxml-xml-parse" in md


def test_php_command_and_include_sinks(tmp_path: Path):
    (tmp_path / "app.php").write_text(
        "<?php\n"
        "shell_exec($_GET['cmd']);\n"
        "include($_GET['page']);\n"
        "passthru($_REQUEST['x']);\n"
        "assert($_GET['code']);\n",
        encoding="utf-8",
    )
    payload, md = _sinks(tmp_path)
    for label in ("php-shell_exec", "php-dynamic-include", "php-passthru", "php-assert-var"):
        assert label in md, f"expected {label} sink"


def test_string_literal_include_not_flagged(tmp_path: Path):
    # A static include of a constant string is NOT an LFI sink (no variable).
    (tmp_path / "safe.php").write_text(
        "<?php include('config.php'); require_once('lib/db.php'); ?>",
        encoding="utf-8",
    )
    _, md = _sinks(tmp_path)
    assert "php-dynamic-include" not in md


def test_method_call_extract_not_flagged_as_php(tmp_path: Path):
    # Python `df.extract(...)` must NOT be mistaken for PHP extract() (lookbehind).
    (tmp_path / "data.py").write_text(
        "result = df.extract('(\\d+)')\n",
        encoding="utf-8",
    )
    _, md = _sinks(tmp_path)
    assert "php-extract" not in md
