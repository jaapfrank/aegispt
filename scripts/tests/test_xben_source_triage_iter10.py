import json

from scripts.training.triage_xben_sources_iter10 import (
    build_triage,
    triage_one,
    write_outputs,
)


def write_backlog(path, ids):
    path.write_text(
        "\n".join(
            json.dumps({"lane": "source_triage_required", "xben_id": xben_id}, sort_keys=True)
            for xben_id in ids
        )
        + "\n",
        encoding="utf-8",
    )


def test_xben_source_triage_classifies_headless_without_snippets(tmp_path):
    root = tmp_path / "benchmarks" / "XBEN-013-24"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "from phantomjs import Phantom\nphantom = Phantom()\n",
        encoding="utf-8",
    )

    row = triage_one("XBEN-013", source_root=tmp_path / "benchmarks")

    assert row["triage_status"] == "source_classified"
    assert row["vuln_class"] == "headless_xss_ssrf"
    assert row["evidence"]
    assert "phantom = Phantom" not in json.dumps(row)
    assert row["evidence_policy"] == "file_line_rule_ids_only_no_source_snippets"


def test_xben_source_triage_keeps_unknown_without_rule_evidence(tmp_path):
    root = tmp_path / "benchmarks" / "XBEN-026-24"
    root.mkdir(parents=True)
    (root / "index.html").write_text("<h1>Hello</h1>\n", encoding="utf-8")

    row = triage_one("XBEN-026", source_root=tmp_path / "benchmarks")

    assert row["triage_status"] == "needs_manual_source_review"
    assert row["vuln_class"] == "unknown_untriaged"


def test_xben_source_triage_builds_and_writes_outputs(tmp_path):
    source_root = tmp_path / "benchmarks"
    challenge = source_root / "XBEN-091-24"
    challenge.mkdir(parents=True)
    (challenge / "app.py").write_text("from flask import render_template_string\n", encoding="utf-8")
    backlog = tmp_path / "backlog.jsonl"
    write_backlog(backlog, ["XBEN-091"])

    data = build_triage(backlog_path=backlog, source_root=source_root)
    summary = write_outputs(data, tmp_path / "out")

    assert data["stats"]["classified_count"] == 1
    assert data["rows"][0]["vuln_class"] == "ssti"
    assert summary["files"]["triage"].endswith(".json")
    assert (tmp_path / "out" / "aegispt_xben_source_triage_iter10.jsonl").exists()


def test_xben_source_triage_real_backlog_has_source_root():
    data = build_triage()

    assert data["stats"]["row_count"] == 57
    assert data["stats"]["source_missing_count"] == 0
