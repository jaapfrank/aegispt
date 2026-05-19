#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.app.config import Settings  # noqa: E402
from api.app.services.settings import _deployment_hardening_readiness  # noqa: E402
from scripts.verify_restore import run_safe_local_restore_drill  # noqa: E402

DEFAULT_OUTPUT_JSON = REPO_ROOT / "codex" / "results" / "production-deployment-proof-latest.json"
DEFAULT_OUTPUT_MD = REPO_ROOT / "codex" / "results" / "production-deployment-proof-latest.md"
SECRET_SENTINELS = (
    "proxy-pass",
    "secret-db-pass",
    "fixture-plaintext-secret-must-not-appear",
)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fetch_json(url: str, *, timeout_seconds: float = 5.0) -> tuple[int | None, dict[str, Any] | None, str | None]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return int(response.status), json.loads(response.read().decode("utf-8")), None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return None, None, str(exc)


def capability_summary(capability: dict[str, Any] | None) -> dict[str, Any]:
    if not capability:
        return {"status": "blocked", "reason": "deployment_hardening capability was not present"}
    metadata = capability.get("metadata") if isinstance(capability.get("metadata"), dict) else {}
    status = str(capability.get("status") or "missing")
    production_like = bool(metadata.get("production_like", False))
    enterprise_ready = metadata.get("enterprise_production_ready")
    if enterprise_ready is None:
        enterprise_ready = production_like and status == "ready"
    readiness_boundary = metadata.get("readiness_boundary")
    if not readiness_boundary:
        readiness_boundary = (
            "enterprise_production_ready"
            if enterprise_ready
            else "production_like_blocked"
            if production_like and status == "blocked"
            else "production_like_degraded"
            if production_like
            else "development_ready_not_enterprise_production"
        )
    return {
        "status": status,
        "summary": capability.get("summary"),
        "operator_next_step": capability.get("operator_next_step"),
        "metadata": {
            "production_like": production_like,
            "enterprise_production_ready": enterprise_ready,
            "readiness_boundary": readiness_boundary,
            "https_public_base_url": metadata.get("https_public_base_url"),
            "tls_terminated_by_proxy": metadata.get("tls_terminated_by_proxy"),
            "secure_cookies": metadata.get("secure_cookies"),
            "database_encryption_status": metadata.get("database_encryption_status"),
            "artifact_encryption_status": metadata.get("artifact_encryption_status"),
            "outbound_proxy": metadata.get("outbound_proxy"),
            "no_internet_mode": metadata.get("no_internet_mode"),
            "offline_update_path_configured": metadata.get("offline_update_path_configured"),
            "manual_tool_update_path_configured": metadata.get("manual_tool_update_path_configured"),
            "trusted_certificate_bundle_configured": metadata.get("trusted_certificate_bundle_configured"),
            "blocking_gap_count": metadata.get("blocking_gap_count"),
            "warning_gap_count": metadata.get("warning_gap_count"),
            "blocking_reasons": metadata.get("blocking_reasons", []),
            "warning_reasons": metadata.get("warning_reasons", []),
            "secrets_plaintext_exposed": metadata.get("secrets_plaintext_exposed"),
        },
    }


def evaluate_deployment_fixture(name: str, settings: Settings) -> dict[str, Any]:
    capability = _deployment_hardening_readiness(settings).model_dump(mode="json")
    return {
        "name": name,
        "deployment_hardening": capability_summary(capability),
    }


def production_tls_proxy_fixture() -> dict[str, Any]:
    return evaluate_deployment_fixture(
        "production_tls_proxy_s3_postgres",
        Settings(
            app_env="production",
            app_public_base_url="https://aegispt.example.test",
            database_url="postgresql+psycopg://aegispt:secret-db-pass@postgres.example.test:5432/aegispt",
            artifacts_storage_mode="s3",
            artifacts_s3_enforce_sse=True,
            deployment_tls_terminated_by_proxy=True,
            deployment_secure_cookies=True,
            deployment_trusted_certificate_bundle="/etc/aegispt/enterprise-ca.pem",
            deployment_outbound_proxy_url="http://proxy-user:proxy-pass@proxy.example.test:8080",
            deployment_no_internet_mode=False,
            deployment_database_encryption_confirmed=True,
            deployment_artifact_storage_encryption_confirmed=True,
        ),
    )


def airgapped_fixture() -> dict[str, Any]:
    return evaluate_deployment_fixture(
        "production_airgapped_offline_updates",
        Settings(
            app_env="production",
            app_public_base_url="https://aegispt-airgap.example.test",
            database_url="postgresql+psycopg://aegispt:secret-db-pass@postgres.example.test:5432/aegispt",
            artifacts_storage_mode="s3",
            artifacts_s3_enforce_sse=True,
            deployment_tls_terminated_by_proxy=True,
            deployment_secure_cookies=True,
            deployment_trusted_certificate_bundle="/etc/aegispt/enterprise-ca.pem",
            deployment_no_internet_mode=True,
            deployment_offline_update_path="/srv/aegispt/offline/feeds",
            deployment_manual_tool_update_path="/srv/aegispt/offline/tools",
            deployment_database_encryption_confirmed=True,
            deployment_artifact_storage_encryption_confirmed=True,
        ),
    )


def unsafe_production_fixture() -> dict[str, Any]:
    return evaluate_deployment_fixture(
        "unsafe_production_blocks",
        Settings(
            app_env="production",
            app_public_base_url="http://aegispt.example.test",
            database_url="sqlite+pysqlite:///./aegispt.db",
            artifacts_storage_mode="s3",
            artifacts_s3_enforce_sse=False,
            deployment_tls_terminated_by_proxy=False,
            deployment_secure_cookies=False,
            deployment_no_internet_mode=True,
            deployment_offline_update_path="/srv/aegispt/offline/feeds",
            deployment_manual_tool_update_path="",
            deployment_database_encryption_confirmed=False,
            deployment_artifact_storage_encryption_confirmed=False,
        ),
    )


def current_environment_fixture() -> dict[str, Any]:
    return evaluate_deployment_fixture("current_environment", Settings())


def compose_static_proof() -> dict[str, Any]:
    compose_path = REPO_ROOT / "infra" / "compose" / "docker-compose.yml"
    env_example_path = REPO_ROOT / "infra" / "compose" / ".env.example"
    if not compose_path.exists() or not env_example_path.exists():
        return {
            "status": "blocked",
            "reason": "infra/compose docker-compose.yml or .env.example is missing",
            "operator_next_step": "Restore the Compose deployment fixture before claiming production-like Compose support.",
        }

    compose_text = compose_path.read_text(encoding="utf-8")
    env_text = env_example_path.read_text(encoding="utf-8")
    required_services = ["api", "worker", "postgres", "redis", "minio", "zapd"]
    required_env_keys = [
        "APP_ENV",
        "APP_PUBLIC_BASE_URL",
        "DEPLOYMENT_TLS_TERMINATED_BY_PROXY",
        "DEPLOYMENT_SECURE_COOKIES",
        "DEPLOYMENT_NO_INTERNET_MODE",
        "DEPLOYMENT_OFFLINE_UPDATE_PATH",
        "DEPLOYMENT_MANUAL_TOOL_UPDATE_PATH",
        "DATABASE_URL",
        "AEGISPT_DB_KEY",
        "ARTIFACTS_STORAGE_MODE",
        "ARTIFACTS_S3_ENFORCE_SSE",
    ]
    services_present = {service: f"  {service}:" in compose_text for service in required_services}
    env_keys_present = {key: f"{key}=" in env_text for key in required_env_keys}
    postgres_persistence = "${POSTGRES_DATA_DIR" in compose_text and ":/var/lib/postgresql/data" in compose_text
    minio_persistence = "${MINIO_DATA_DIR" in compose_text and ":/data" in compose_text
    s3_declared = "ARTIFACTS_STORAGE_MODE=s3" in env_text and "ARTIFACTS_S3_ENFORCE_SSE" in env_text
    blockers = [
        f"missing Compose service {service}"
        for service, present in services_present.items()
        if not present
    ]
    blockers.extend(f"missing env key {key}" for key, present in env_keys_present.items() if not present)
    if not postgres_persistence:
        blockers.append("PostgreSQL data bind mount is not declared")
    if not minio_persistence:
        blockers.append("MinIO artifact data bind mount is not declared")
    if not s3_declared:
        blockers.append("S3/MinIO artifact storage declaration is incomplete")

    return {
        "status": "ready" if not blockers else "blocked",
        "compose_file": "infra/compose/docker-compose.yml",
        "env_example": "infra/compose/.env.example",
        "services_present": services_present,
        "env_keys_present": env_keys_present,
        "postgres_persistence_declared": postgres_persistence,
        "minio_persistence_declared": minio_persistence,
        "s3_artifact_storage_declared": s3_declared,
        "blocking_reasons": blockers,
        "operator_next_step": (
            "Start the approved Compose fixture and capture pg_dump/MinIO restore evidence before claiming a live production runtime."
            if not blockers
            else "Fix the missing Compose declarations before running a production-like deployment proof."
        ),
    }


def runtime_compose_restore_blocker() -> dict[str, Any]:
    return {
        "status": "blocked",
        "reason": (
            "No live Compose/PostgreSQL runtime was started by this safe build-lane proof; "
            "the current evidence is static Compose declaration plus the safe local backup/restore drill."
        ),
        "operator_next_step": (
            "Run an explicitly approved local Compose fixture, capture pg_dump/restore and MinIO artifact restore evidence, "
            "then attach that output under codex/results/."
        ),
    }


def safe_restore_drill(run_restore_drill: bool) -> dict[str, Any]:
    if not run_restore_drill:
        return {
            "status": "not_run",
            "reason": "Restore drill was disabled by caller.",
            "operator_next_step": "Run without --skip-restore-drill before using this as release evidence.",
        }

    try:
        with tempfile.TemporaryDirectory(prefix="aegispt-prod-proof-restore-") as work_dir:
            result = run_safe_local_restore_drill(Path(work_dir))
    except Exception as exc:  # pragma: no cover - exercised through CLI evidence path
        return {
            "status": "blocked",
            "reason": f"Safe local restore drill failed: {exc}",
            "operator_next_step": "Fix backup/restore drill blockers before claiming deployment persistence readiness.",
        }

    database_counts = result.get("database_checks", {}).get("counts", {})
    return {
        "status": "ready",
        "fixture": result.get("fixture"),
        "alembic_current": result.get("alembic_current"),
        "artifact_hash_verified": result.get("database_checks", {}).get("artifact_hash_verified"),
        "finding_evidence_ref_verified": result.get("database_checks", {}).get("finding_evidence_ref_verified"),
        "audit_event_verified": result.get("database_checks", {}).get("audit_event_verified"),
        "secret_metadata_verified": result.get("database_checks", {}).get("secret_metadata_verified"),
        "api_checks": result.get("api_checks", {}),
        "database_counts": {
            "engagements": database_counts.get("engagements"),
            "runs": database_counts.get("runs"),
            "tasks": database_counts.get("tasks"),
            "artifacts": database_counts.get("artifacts"),
            "findings": database_counts.get("findings"),
            "audit_events": database_counts.get("audit_events"),
            "secret_refs": database_counts.get("secret_refs"),
            "sensitive_settings": database_counts.get("sensitive_settings"),
        },
        "plaintext_secrets_exposed": result.get("plaintext_secrets_exposed"),
    }


def live_api_readiness(base_url: str | None) -> dict[str, Any]:
    if not base_url:
        return {
            "status": "not_configured",
            "reason": "No base URL supplied for live API acceptance.",
        }
    base = base_url.rstrip("/")
    health_status, health_payload, health_error = fetch_json(f"{base}/health/live")
    readiness_status, readiness_payload, readiness_error = fetch_json(f"{base}/api/v1/settings/readiness")
    diagnostics_status, diagnostics_payload, diagnostics_error = fetch_json(f"{base}/api/v1/diagnostics")

    readiness_capability = None
    if isinstance(readiness_payload, dict):
        readiness_capability = {
            item.get("id"): item
            for item in readiness_payload.get("capabilities", [])
            if isinstance(item, dict)
        }.get("deployment_hardening")
    diagnostics_subsystem = None
    if isinstance(diagnostics_payload, dict):
        diagnostics_subsystem = {
            item.get("id"): item
            for item in diagnostics_payload.get("subsystems", [])
            if isinstance(item, dict)
        }.get("deployment_hardening")

    blockers = []
    if health_status != 200:
        blockers.append(f"health endpoint unavailable: {health_error or health_status}")
    if readiness_capability is None:
        blockers.append(f"settings readiness deployment_hardening missing: {readiness_error or readiness_status}")
    if diagnostics_subsystem is None:
        blockers.append(f"diagnostics deployment_hardening missing: {diagnostics_error or diagnostics_status}")

    return {
        "status": "ready" if not blockers else "blocked",
        "base_url": base,
        "health_status": health_status,
        "runtime_state": health_payload.get("runtime_state") if isinstance(health_payload, dict) else None,
        "settings_readiness": capability_summary(readiness_capability),
        "diagnostics": capability_summary(diagnostics_subsystem),
        "blocking_reasons": blockers,
    }


def assert_no_secret_sentinels(payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    leaked = [sentinel for sentinel in SECRET_SENTINELS if sentinel in serialized]
    if leaked:
        raise AssertionError(f"secret sentinel leaked into production proof output: {', '.join(leaked)}")


def build_proof_report(
    *,
    base_url: str | None,
    run_restore_drill: bool,
) -> dict[str, Any]:
    current = current_environment_fixture()
    fixtures = [
        production_tls_proxy_fixture(),
        airgapped_fixture(),
        unsafe_production_fixture(),
    ]
    restore = safe_restore_drill(run_restore_drill)
    compose = compose_static_proof()
    compose_runtime = runtime_compose_restore_blocker()
    live_api = live_api_readiness(base_url)

    production_fixtures_ready = all(
        fixture["deployment_hardening"]["status"] == "ready"
        for fixture in fixtures
        if fixture["name"] != "unsafe_production_blocks"
    )
    unsafe_blocks = fixtures[-1]["deployment_hardening"]["status"] == "blocked"
    restore_ready = restore["status"] == "ready"
    compose_static_ready = compose["status"] == "ready"
    current_metadata = current["deployment_hardening"]["metadata"]

    report = {
        "kind": "aegispt.production_deployment_proof",
        "schema_version": 1,
        "generated_at": utc_now_iso(),
        "proof_summary": {
            "overall_status": (
                "degraded"
                if production_fixtures_ready and unsafe_blocks and restore_ready and compose_static_ready
                else "blocked"
            ),
            "enterprise_production_ready_claim_allowed": bool(current_metadata.get("enterprise_production_ready")),
            "development_mode_not_enterprise_production": current_metadata.get("readiness_boundary")
            == "development_ready_not_enterprise_production",
            "production_like_fixtures_ready": production_fixtures_ready,
            "unsafe_production_fails_closed": unsafe_blocks,
            "safe_local_backup_restore_ready": restore_ready,
            "compose_static_declarations_ready": compose_static_ready,
            "compose_postgres_runtime_restore_proven": False,
            "secrets_plaintext_exposed": False,
        },
        "current_environment": current,
        "production_like_fixtures": fixtures,
        "compose_static_proof": compose,
        "compose_postgres_runtime_restore": compose_runtime,
        "safe_local_backup_restore": restore,
        "live_api_acceptance": live_api,
        "safety": {
            "live_targets_touched": False,
            "runtime_self_modification": False,
            "uncontrolled_plugin_installation": False,
            "plaintext_secret_material_written": False,
        },
    }
    assert_no_secret_sentinels(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["proof_summary"]
    current = report["current_environment"]["deployment_hardening"]
    lines = [
        "# AegisPT Production-Like Deployment Proof",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Overall proof status: `{summary['overall_status']}`",
        f"- Enterprise-production-ready claim allowed for current host: `{str(summary['enterprise_production_ready_claim_allowed']).lower()}`",
        f"- Development mode kept separate from production hardening: `{str(summary['development_mode_not_enterprise_production']).lower()}`",
        f"- Compose/PostgreSQL runtime restore proven: `{str(summary['compose_postgres_runtime_restore_proven']).lower()}`",
        "",
        "## Current Host",
        "",
        f"- Deployment hardening status: `{current['status']}`",
        f"- Boundary: `{current['metadata'].get('readiness_boundary')}`",
        f"- Summary: {current['summary']}",
        "",
        "## Fixture Proof",
        "",
    ]
    for fixture in report["production_like_fixtures"]:
        hardening = fixture["deployment_hardening"]
        metadata = hardening["metadata"]
        lines.extend(
            [
                f"### {fixture['name']}",
                "",
                f"- Status: `{hardening['status']}`",
                f"- Enterprise production ready: `{str(metadata.get('enterprise_production_ready')).lower()}`",
                f"- Blocking reasons: {', '.join(metadata.get('blocking_reasons') or []) or 'none'}",
                f"- Warning reasons: {', '.join(metadata.get('warning_reasons') or []) or 'none'}",
                "",
            ]
        )
    restore = report["safe_local_backup_restore"]
    compose_runtime = report["compose_postgres_runtime_restore"]
    lines.extend(
        [
            "## Persistence",
            "",
            f"- Safe local backup/restore drill: `{restore['status']}`",
            f"- Artifact hash verified: `{str(restore.get('artifact_hash_verified')).lower()}`",
            f"- Finding evidence reference verified: `{str(restore.get('finding_evidence_ref_verified')).lower()}`",
            f"- Plaintext secrets exposed: `{str(restore.get('plaintext_secrets_exposed')).lower()}`",
            f"- Compose/PostgreSQL runtime restore: `{compose_runtime['status']}`",
            f"- Compose/PostgreSQL next step: {compose_runtime['operator_next_step']}",
            "",
            "## Live Acceptance",
            "",
            f"- Live API status: `{report['live_api_acceptance']['status']}`",
            f"- Health status: `{report['live_api_acceptance'].get('health_status')}`",
            f"- Runtime state: `{report['live_api_acceptance'].get('runtime_state')}`",
            "",
            "## Boundary",
            "",
            "This proof is safe-local and fail-closed. It does not install infrastructure, pull images, run live targets, mutate active assessments, expose secret material, or turn development mode into an enterprise-production claim.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build AegisPT production-like deployment proof evidence.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Local AegisPT base URL for read-only acceptance.")
    parser.add_argument("--output-json", type=Path, default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", type=Path, default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--skip-restore-drill", action="store_true", help="Only for focused tests; not valid release evidence.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_proof_report(base_url=args.base_url, run_restore_drill=not args.skip_restore_drill)
    write_json(args.output_json, report)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(render_markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": report["proof_summary"]["overall_status"],
                "enterprise_production_ready_claim_allowed": report["proof_summary"][
                    "enterprise_production_ready_claim_allowed"
                ],
                "output_json": str(args.output_json.resolve()),
                "output_md": str(args.output_md.resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
