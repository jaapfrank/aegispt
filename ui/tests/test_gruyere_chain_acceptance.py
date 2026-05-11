from __future__ import annotations

import json
import subprocess
import time
from datetime import UTC, datetime
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPCookieProcessor, build_opener, urlopen
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from api.app.models import AgentProposal, AgentReasoning, Finding, Run, Task
from api.app.services.ai_agent import AgentProposalReviewError, review_agent_proposal
from api.app.services.ai_shell_safety import ai_shell_command_sha256
from api.app.services.runs import derive_targets_from_target_map
from workers.runners.ai_shell.runner import execute_ai_shell_command

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO_ROOT / "codex" / "results" / "gruyere-chain-acceptance-report.json"
GRUYERE_PUBLIC_ROOT = "google-gruyere.appspot.com"


def test_gruyere_chain_acceptance_report_is_honest_about_ai_shell_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gruyere = _ensure_local_gruyere()
    assert GRUYERE_PUBLIC_ROOT not in gruyere["root_url"]

    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'gruyere-chain.db'}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "manual")
    monkeypatch.setenv("LOCAL_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            engagement_id = _create_scoped_engagement(
                client,
                root_url=gruyere["root_url"],
                container_ip=gruyere["container_ip"],
            )
            run_id = _create_ai_shell_run(client, engagement_id)
            layers = [
                _prove_reflected_xss_without_ai_shell(client, run_id, gruyere["root_url"]),
                _prove_stored_xss_without_ai_shell(client, run_id, gruyere["root_url"]),
            ]
            layers.extend(
                _attempt_ai_shell_layer(
                    client=client,
                    engagement_id=engagement_id,
                    layer=layer,
                    root_url=gruyere["root_url"],
                    container_ip=gruyere["container_ip"],
                )
                for layer in (3, 4, 5, 6)
            )

            with client.app.state.session_factory() as session:
                finding_count = session.scalar(
                    select(func.count(Finding.id)).where(Finding.run_id == UUID(run_id))
                )
                proposals = session.scalars(select(AgentProposal)).all()
                queued_tasks = session.scalars(select(Task).where(Task.tool == "ai-shell")).all()

            report = {
                "schema_version": 1,
                "task": "backlog-254-gruyere-multi-step-chain-acceptance-test",
                "generated_at": datetime.now(tz=UTC).isoformat(),
                "target": {
                    "kind": "local_docker_gruyere",
                    "root_url": gruyere["root_url"],
                    "container_name": gruyere["container_name"],
                    "container_ip": gruyere["container_ip"],
                    "image": gruyere["image"],
                    "public_target_touched": False,
                },
                "summary": {
                    "status": "blocked_current_contract",
                    "detected_layers": [item["layer"] for item in layers if item["status"] == "detected"],
                    "blocked_layers": [item["layer"] for item in layers if item["status"] != "detected"],
                    "all_six_detected": all(item["status"] == "detected" for item in layers),
                    "finding_database_count_for_detected_layers": int(finding_count or 0),
                    "ai_shell_proposals_created": len(proposals),
                    "ai_shell_tasks_queued": len(queued_tasks),
                    "blocking_reason": (
                        "AegisPT ai-shell is SSH-only, requires credential references, and blocks "
                        "loopback/AegisPT-host execution. The local Gruyere Docker fixture exposes "
                        "HTTP on loopback and has no approved SSH execution surface, so layers 3-6 "
                        "cannot be honestly marked detected through Free Bash execution."
                    ),
                },
                "layers": layers,
                "safety": {
                    "local_only": True,
                    "no_public_gruyere": True,
                    "manual_wizard_path_changed": False,
                    "approval_gates_bypassed": False,
                    "scope_bypassed": False,
                    "roe_bypassed": False,
                    "credential_gate_bypassed": False,
                    "kill_switch_bypassed": False,
                    "runtime_self_modification": False,
                    "uncontrolled_plugin_install": False,
                },
            }
            REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            assert report["summary"]["detected_layers"] == [1, 2]
            assert report["summary"]["blocked_layers"] == [3, 4, 5, 6]
            assert report["summary"]["all_six_detected"] is False
            assert report["target"]["public_target_touched"] is False
            assert all(GRUYERE_PUBLIC_ROOT not in json.dumps(layer) for layer in layers)
            assert len(proposals) == 4
            assert len(queued_tasks) == 4
            assert int(finding_count or 0) == 2
    finally:
        get_settings.cache_clear()


def _ensure_local_gruyere() -> dict[str, str]:
    subprocess.run(
        _compose_command("--profile", "benchmark", "up", "-d", "aegispt-benchmark-gruyere"),
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    root_url = _wait_for_gruyere_root("http://127.0.0.1:8008/")
    parsed = urlparse(root_url)
    assert parsed.hostname == "127.0.0.1"
    container_name = _compose_container_name()
    inspect = subprocess.run(
        [
            "docker",
            "inspect",
            container_name,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Config.Image}}",
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    container_ip, image = inspect.stdout.strip().split(maxsplit=1)
    assert container_ip
    return {
        "root_url": root_url,
        "container_name": container_name,
        "container_ip": container_ip,
        "image": image,
    }


def _wait_for_gruyere_root(url: str) -> str:
    deadline = time.time() + 90
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=5) as response:
                root_url = response.geturl()
                if response.status == 200 and "/lib.js" in response.read().decode("utf-8", "replace"):
                    return root_url
        except Exception as exc:  # noqa: BLE001 - preserves useful readiness context in assertion.
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for local Gruyere at {url}: {last_error}")


def _compose_container_name() -> str:
    completed = subprocess.run(
        _compose_command("ps", "-q", "aegispt-benchmark-gruyere"),
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    container_id = completed.stdout.strip()
    if not container_id:
        raise RuntimeError("docker compose did not return a Gruyere container id")
    name = subprocess.run(
        ["docker", "inspect", container_id, "--format", "{{.Name}}"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return name.lstrip("/")


def _compose_command(*args: str) -> list[str]:
    plugin_probe = subprocess.run(
        ["docker", "compose", "version"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if plugin_probe.returncode == 0:
        return ["docker", "compose", *args]
    return ["docker-compose", *args]


def _create_scoped_engagement(client: TestClient, *, root_url: str, container_ip: str) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "gruyere-chain-test"},
        json={
            "name": "Gruyere Chain Acceptance",
            "client": "AegisPT Local Lab",
            "roe_ref": "ROE-LOCAL-GRUYERE-ONLY",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_payload = {
        "allowlist_json": {
            "urls": [root_url],
            "hosts": [container_ip],
        },
        "denylist_json": {
            "domains": [GRUYERE_PUBLIC_ROOT],
        },
    }
    assert any(target["value"] == container_ip for target in derive_targets_from_target_map(scope_payload["allowlist_json"]))
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "gruyere-chain-test"},
        json=scope_payload,
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_ai_shell_run(client: TestClient, engagement_id: str) -> str:
    with client.app.state.session_factory() as session:
        from api.app.models import Approval, RunProfile
        from api.app.services.run_profiles import ensure_default_run_profiles

        ensure_default_run_profiles(session)
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "active-ai-shell"))
        assert profile is not None
        run = Run(
            engagement_id=UUID(engagement_id),
            profile=profile,
            requested_by="gruyere-chain-test",
            status="queued",
            configuration_json={
                "ai_shell": {"enabled": True},
                "safety": {"ai_shell_enabled": True},
            },
        )
        session.add(run)
        session.flush()
        session.add(
            Approval(
                run=run,
                step_id="active-ai-shell",
                approver_id="gruyere-chain-approver",
                decision="approved",
            )
        )
        session.commit()
        return str(run.id)


def _prove_reflected_xss_without_ai_shell(client: TestClient, run_id: str, root_url: str) -> dict[str, object]:
    payload = '<script>alert("aegispt-reflected")</script>'
    target = urljoin(root_url, payload)
    body = urlopen(target, timeout=10).read().decode("utf-8", "replace")
    assert payload in body
    finding_id = _record_finding(
        client,
        run_id=run_id,
        title="Gruyere Reflected XSS confirmed in invalid-path error",
        target=target,
        severity="medium",
        evidence_ref="gruyere-layer-1-reflected-xss",
        summary="Local Gruyere reflected a script marker in an invalid request path without AI shell execution.",
    )
    return {
        "layer": 1,
        "name": "Reflected XSS",
        "status": "detected",
        "ai_shell_used": False,
        "execution_path": "local-gruyere-http-proof-no-ai-shell",
        "finding_id": finding_id,
        "evidence": {
            "url": target,
            "marker_reflected": True,
        },
    }


def _prove_stored_xss_without_ai_shell(client: TestClient, run_id: str, root_url: str) -> dict[str, object]:
    jar = CookieJar()
    opener = build_opener(HTTPCookieProcessor(jar))
    uid = f"aegispt{int(time.time() * 1000) % 100000000}"
    password = "local-gruyere-lab"
    opener.open(
        urljoin(
            root_url,
            "saveprofile?"
            + urlencode({"action": "new", "uid": uid, "pw": password, "is_author": "True"}),
        ),
        timeout=10,
    )
    opener.open(urljoin(root_url, "login?" + urlencode({"uid": uid, "pw": password})), timeout=10)
    payload = '<img src=x onerror=alert("aegispt-stored")>'
    opener.open(urljoin(root_url, "newsnippet2?" + urlencode({"snippet": payload})), timeout=10)
    snippets_url = urljoin(root_url, "snippets.gtl")
    body = opener.open(snippets_url, timeout=10).read().decode("utf-8", "replace")
    assert payload in body
    finding_id = _record_finding(
        client,
        run_id=run_id,
        title="Gruyere Stored XSS confirmed in snippet rendering",
        target=snippets_url,
        severity="medium",
        evidence_ref="gruyere-layer-2-stored-xss",
        summary="Local Gruyere stored and rendered an HTML event-handler marker without AI shell execution.",
    )
    return {
        "layer": 2,
        "name": "Stored XSS via snippet",
        "status": "detected",
        "ai_shell_used": False,
        "execution_path": "local-gruyere-http-proof-no-ai-shell",
        "finding_id": finding_id,
        "evidence": {
            "url": snippets_url,
            "test_account": uid,
            "marker_rendered": True,
            "cookie_material_recorded": False,
        },
    }


def _attempt_ai_shell_layer(
    *,
    client: TestClient,
    engagement_id: str,
    layer: int,
    root_url: str,
    container_ip: str,
) -> dict[str, object]:
    run_id = _create_ai_shell_run(client, engagement_id)
    command = f"printf aegispt-gruyere-layer-{layer}-proof"
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        reasoning = AgentReasoning(
            run=run,
            reasoning_type="gruyere_chain_acceptance",
            status="recorded",
            context_snapshot_json={
                "layer": layer,
                "local_gruyere_root": root_url,
                "container_ip": container_ip,
                "public_target_touched": False,
            },
            observations_json=[
                {
                    "type": "layer_prerequisite",
                    "summary": "Previous local Gruyere layers require an approved follow-up step.",
                }
            ],
            hypotheses_json=[
                {
                    "type": "chain_hypothesis",
                    "summary": "A benign approved command would be needed to continue this layer.",
                }
            ],
            proposals_json=[
                {
                    "tool": "ai-shell",
                    "target": container_ip,
                    "command_sha256": ai_shell_command_sha256(command),
                }
            ],
            provider="deterministic-acceptance",
            confidence_score=0.8,
            metadata_json={
                "summary_text": f"Layer {layer} requires approved execution to continue.",
                "thought_text": "Use only the existing AI proposal review and ai-shell runner boundary.",
                "action_text": "Request operator approval for one benign SSH command.",
            },
        )
        proposal = AgentProposal(
            run=run,
            agent_reasoning=reasoning,
            proposed_tool="ai-shell",
            proposed_target=container_ip,
            proposed_params_json={
                "command": command,
                "via": "ssh",
                "credentials_ref": "secret://local-gruyere-ssh-lab",
                "target": container_ip,
                "output_cap_chars": 8000,
            },
            reasoning_text=f"Layer {layer} needs a governed Free Bash follow-up after prior evidence.",
            risk_tier="active",
            priority=layer,
            confidence_score=0.8,
            status="pending_review",
            metadata_json={"proposal_kind": "gruyere_chain_acceptance"},
        )
        session.add(reasoning)
        session.add(proposal)
        session.flush()
        proposal_id = proposal.id
        session.commit()

    review_block: dict[str, object] | None = None
    queued_task_id: str | None = None
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        try:
            reviewed = review_agent_proposal(
                session=session,
                run=run,
                proposal_id=proposal_id,
                actor="gruyere-chain-approver",
                decision="approved",
                note="Local acceptance test approval for one benign command.",
            )
            session.commit()
            queued_task_id = reviewed.metadata_json.get("queued_task_id")
        except AgentProposalReviewError as exc:
            session.rollback()
            review_block = {"reason": exc.reason, "message": str(exc)}

    runner_execution = execute_ai_shell_command(
        targets=[container_ip],
        scope_allowlist={"hosts": [container_ip]},
        command=command,
        via="ssh",
        credentials_ref="secret://local-gruyere-ssh-lab",
        output_cap_chars=8000,
        timeout_seconds=3.0,
    )
    runner_status = str(runner_execution.metadata.get("status") or "unknown")
    return {
        "layer": layer,
        "name": {
            3: "XSS via file upload",
            4: "Client-state manipulation / privilege escalation",
            5: "Path traversal plus write",
            6: "RCE via GTL injection",
        }[layer],
        "status": "blocked",
        "ai_shell_used": True,
        "proposal_id": str(proposal_id),
        "proposal_review": "blocked" if review_block else "approved_queued",
        "review_block": review_block,
        "queued_task_id": queued_task_id,
        "approved_execution_step": {
            "tool": "ai-shell",
            "target": container_ip,
            "via": "ssh",
            "credentials_ref_present": True,
            "command_sha256": ai_shell_command_sha256(command),
            "exact_command_recorded": command,
        },
        "proposal_rationale": f"Layer {layer} requires a governed Free Bash follow-up after prior evidence.",
        "runner_execution": {
            "tool": runner_execution.tool,
            "status": runner_status,
            "exit_code": runner_execution.exit_code,
            "stderr_excerpt": runner_execution.stderr[:300],
        },
        "finding_id": None,
        "blocking_truth": (
            "The current registered ai-shell runner is SSH-only. The local Gruyere HTTP Docker "
            "fixture is live, but it is not an approved SSH labhost and therefore cannot prove "
            "this layer through Free Bash execution."
        ),
    }


def _record_finding(
    client: TestClient,
    *,
    run_id: str,
    title: str,
    target: str,
    severity: str,
    evidence_ref: str,
    summary: str,
) -> str:
    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title=title,
            severity=severity,
            target_id=target,
            evidence_ref=evidence_ref,
            status="open",
            summary=summary,
            methodology_tags=["local-gruyere", "xss", "acceptance"],
            ptes_phase="vulnerability_analysis",
            nist_phase="discovery",
            wstg_id="WSTG-INPV-01",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)
