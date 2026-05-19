from __future__ import annotations

import json
from pathlib import Path

from api.app.services.cve_template_generator import validate_detection_only_nuclei_template
from workers.runners.nuclei.rce_catalog import (
    GENERIC_RCE_DETECTION_TEMPLATE,
    select_rce_template_ids,
)
from workers.runners.nuclei.runner import build_nuclei_command, execute_nuclei_scan


def _fake_nuclei_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-nuclei-rce"
    binary_path.write_text(
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if "-version" in args:
    print("nuclei v-rce-test")
    raise SystemExit(0)
if "-update-templates" in args:
    print("templates updated")
    raise SystemExit(0)
output_path = Path(args[args.index("-jsonl-export") + 1])
targets_path = Path(args[args.index("-l") + 1])
targets = [line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines() if line.strip()]
template_id = "aegispt-rce-generic-signal-detection"
if "-id" in args:
    template_id = args[args.index("-id") + 1].split(",")[0]
output_path.write_text(
    "\\n".join(
        json.dumps({"template-id": template_id, "info": {"severity": "high"}, "matched-at": target})
        for target in targets
    )
    + "\\n",
    encoding="utf-8",
)
print(output_path.read_text(encoding="utf-8"), end="")
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


def test_rce_generic_template_stays_in_detection_only_subset() -> None:
    validation = validate_detection_only_nuclei_template(GENERIC_RCE_DETECTION_TEMPLATE)

    assert validation["template_id"] == "aegispt-rce-generic-signal-detection"
    assert validation["detection_only"] is True
    assert validation["http_request_count"] == 3


def test_rce_selection_matches_jenkins_and_skips_oob_without_config() -> None:
    plan = select_rce_template_ids(
        targets=["https://jenkins.example.test:8080/"],
        service_evidence=[
            {"product": "Jenkins", "port": 8080},
            {"product": "Apache Log4j", "port": 8080},
        ],
        oob_enabled=False,
    )

    assert "CVE-2024-23897" in plan["selected_template_ids"]
    assert "CVE-2021-44228" not in plan["selected_template_ids"]
    assert any(
        item["template_id"] == "CVE-2021-44228" and item["reason"] == "oob_disabled"
        for item in plan["skipped"]
    )


def test_rce_selection_enables_oob_templates_only_when_configured() -> None:
    plan = select_rce_template_ids(
        targets=["https://solr.example.test/"],
        service_evidence=[{"product": "Apache Solr Log4j"}],
        oob_enabled=True,
    )

    assert "CVE-2021-44228" in plan["selected_template_ids"]


def test_nuclei_command_can_add_rce_ids_and_disable_interactsh(tmp_path: Path) -> None:
    command = build_nuclei_command(
        binary="nuclei",
        targets_file=tmp_path / "targets.txt",
        template_file=tmp_path / "generic-rce.yaml",
        output_file=tmp_path / "results.jsonl",
        template_ids=["CVE-2024-23897"],
        disable_interactsh=True,
    )

    assert command[:7] == [
        "nuclei",
        "-duc",
        "-l",
        str(tmp_path / "targets.txt"),
        "-t",
        str(tmp_path / "generic-rce.yaml"),
        "-jsonl",
    ]
    assert command[command.index("-id") + 1] == "CVE-2024-23897"
    assert "-no-interactsh" in command


def test_execute_nuclei_rce_scan_emits_plan_and_governed_update(
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_root = tmp_path / "nuclei-templates"
    template_path = template_root / "http" / "cves" / "2021" / "CVE-2021-43798.yaml"
    template_path.parent.mkdir(parents=True)
    template_path.write_text(
        """id: CVE-2021-43798
info:
  name: Grafana Path Traversal
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/public/plugins/alertlist/../../../../../conf/defaults.ini"
    matchers:
      - type: word
        words:
          - "[paths]"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_root))

    execution = execute_nuclei_scan(
        targets=["https://grafana.example.test/"],
        binary=_fake_nuclei_binary(tmp_path),
        rce_template_selection=True,
        service_evidence=[{"product": "Grafana", "port": 3000}],
        update_templates=True,
        template_update_approved=True,
        timeout_seconds=3,
    )

    assert execution.exit_code == 0
    assert execution.metadata["tool_version"] == "nuclei v-rce-test"
    assert execution.metadata["selected_template_ids"] == ["CVE-2021-43798"]
    assert execution.metadata["template_update_status"]["status"] == "ok"
    assert execution.metadata["oob_status"]["enabled"] is False

    plan_artifact = next(artifact for artifact in execution.artifacts if artifact.name == "nuclei-rce-plan.json")
    plan = json.loads(plan_artifact.data)
    assert plan["rce_template_selection"] is True
    assert plan["template_update"]["status"] == "ok"
    assert plan["candidate_template_ids"] == ["CVE-2021-43798"]
    assert plan["selected_template_ids"] == ["CVE-2021-43798"]
    assert plan["blocked_template_ids"] == []


def test_execute_nuclei_rce_scan_blocks_unsafe_official_templates(
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_root = tmp_path / "nuclei-templates"
    template_path = template_root / "javascript" / "cves" / "2024" / "CVE-2024-23897.yaml"
    template_path.parent.mkdir(parents=True)
    template_path.write_text(
        """id: CVE-2024-23897
info:
  name: Jenkins CLI RCE
  severity: critical
payload: unsafe
javascript:
  - code: |
      template.http.get("/cli")
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_root))

    execution = execute_nuclei_scan(
        targets=["https://jenkins.example.test:8080/"],
        binary=_fake_nuclei_binary(tmp_path),
        rce_template_selection=True,
        service_evidence=[{"product": "Jenkins", "port": 8080}],
        timeout_seconds=3,
    )

    assert execution.exit_code == 0
    assert execution.metadata["selected_template_ids"] == []
    plan_artifact = next(artifact for artifact in execution.artifacts if artifact.name == "nuclei-rce-plan.json")
    plan = json.loads(plan_artifact.data)
    assert plan["candidate_template_ids"] == ["CVE-2024-23897"]
    assert plan["selected_template_ids"] == []
    assert plan["blocked_template_ids"] == ["CVE-2024-23897"]
