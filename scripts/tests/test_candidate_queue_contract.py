from __future__ import annotations

import json
from pathlib import Path

from workers.runners.pre_recon_source.candidate_queue import (
    ALLOWED_EVIDENCE_CLASSES,
    ALLOWED_STATES,
    CANDIDATE_QUEUE_ARTIFACT_NAME,
    build_candidate_queue,
    validate_candidate_queue,
)
from workers.runners.pre_recon_source.runner import execute_pre_recon_source


def _candidate_queue_from_run(source_dir: Path) -> dict:
    result = execute_pre_recon_source([], source_dir=str(source_dir))
    payload = json.loads(result.stdout)
    artifact = next(a for a in result.artifacts if a.name == CANDIDATE_QUEUE_ARTIFACT_NAME)
    queue = json.loads(artifact.data.decode("utf-8"))
    assert payload["candidate_count"] == queue["candidate_count"]
    return queue


def test_candidate_state_and_evidence_taxonomy_is_frozen() -> None:
    assert set(ALLOWED_STATES) == {
        "untested",
        "tested_no_signal",
        "blocked_needs_auth",
        "blocked_needs_callback",
        "blocked_needs_state",
        "exploited",
        "false_positive",
    }
    assert "headless_dialog_observed" in ALLOWED_EVIDENCE_CLASSES
    assert "authenticated_state_change" in ALLOWED_EVIDENCE_CLASSES
    assert "privileged_resource_access" in ALLOWED_EVIDENCE_CLASSES


def test_pre_recon_source_emits_valid_candidate_queue_artifact(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import urllib.request\n"
        "app.secret_key = 'supersecretkey'\n"
        "@app.route('/reset_password')\n"
        "def reset_password():\n"
        "    if request.remote_addr != '127.0.0.1':\n"
        "        return 'Unauthorized', 403\n"
        "    username = request.args.get('username')\n"
        "    new_password = request.args.get('newpassword')\n"
        "    users[username]['password'] = new_password\n"
        "@app.route('/profile', methods=['POST'])\n"
        "def profile():\n"
        "    url = request.form.get('profile_picture_url')\n"
        "    urllib.request.urlretrieve(url, '/tmp/x')\n",
        encoding="utf-8",
    )

    queue = _candidate_queue_from_run(tmp_path)
    assert validate_candidate_queue(queue) == []
    classes = {c["vuln_class"] for c in queue["candidates"]}
    assert "ssrf_internal" in classes
    assert "auth_logic_session_forgery" in classes
    ssrf = next(c for c in queue["candidates"] if c["vuln_class"] == "ssrf_internal")
    assert ssrf["state"] == "untested"
    assert ssrf["required_evidence_class"] == "authenticated_state_change"
    assert ssrf["requires_source_context"] is True
    assert ssrf["black_box_compatible"] is False
    assert "interactive-exploit" in ssrf["compatible_tools"]


def test_runtime_recon_cues_are_first_class_black_box_candidates() -> None:
    queue = build_candidate_queue(
        runtime_recon_cues=[
            {
                "cue_type": "html_form",
                "route": "/profile",
                "method": "POST",
                "parameter": "avatar_url",
                "vuln_class_hint": "ssrf_internal",
                "evidence": "form input accepts an absolute URL",
                "rank": 71,
            },
            {
                "cue_type": "object_selector",
                "route": "/api/users/2",
                "method": "GET",
                "parameter": "id",
            },
        ],
        producer="runtime-recon-fixture",
    )
    assert validate_candidate_queue(queue) == []
    candidates = queue["candidates"]
    assert {c["origin"] for c in candidates} == {"runtime_recon"}
    assert all(c["requires_source_context"] is False for c in candidates)
    assert all(c["black_box_compatible"] is True for c in candidates)
    assert {c["vuln_class"] for c in candidates} >= {"ssrf_internal", "authz_idor"}


def test_candidate_fixture_surface_covers_phase1_classes(tmp_path: Path) -> None:
    (tmp_path / "check.js").write_text(
        "var page = require('webpage').create();\n"
        "page.onAlert = function(msg) { console.log('SUCCESS'); };\n"
        "page.open(input, function(status) {});\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from jinja2 import Template\n"
        "@app.route('/page')\n"
        "def page():\n"
        "    name = request.args.get('name','')\n"
        "    blacklist = ['script', 'onload']\n"
        "    subprocess.Popen(['phantomjs', 'check.js'])\n"
        "    return name\n"
        "@app.route('/template')\n"
        "def template():\n"
        "    q = request.args.get('q','')\n"
        "    return Template(q).render()\n"
        "users = {'john': 'password123'}\n",
        encoding="utf-8",
    )
    (tmp_path / "upload.php").write_text(
        "<?php\n"
        "$page = $_GET['page'];\n"
        "include $page;\n",
        encoding="utf-8",
    )

    queue = _candidate_queue_from_run(tmp_path)
    runtime_queue = build_candidate_queue(
        runtime_recon_cues=[
            {
                "cue_type": "object_selector",
                "route": "/api/accounts/2",
                "parameter": "account_id",
            }
        ],
        producer="runtime-recon-fixture",
    )
    classes = {c["vuln_class"] for c in queue["candidates"]}
    classes.update(c["vuln_class"] for c in runtime_queue["candidates"])
    assert {
        "auth_logic_session_forgery",
        "authz_idor",
        "file_path_upload",
        "headless_xss",
        "ssti",
    }.issubset(classes)


def test_candidate_ids_are_deterministic(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.route('/template')\n"
        "def template():\n"
        "    return render_template_string(request.args.get('q',''))\n",
        encoding="utf-8",
    )
    first = _candidate_queue_from_run(tmp_path)
    second = _candidate_queue_from_run(tmp_path)
    assert [c["candidate_id"] for c in first["candidates"]] == [
        c["candidate_id"] for c in second["candidates"]
    ]
