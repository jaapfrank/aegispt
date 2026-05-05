from __future__ import annotations

from scripts.run_production_deployment_proof import build_proof_report, render_markdown


def test_production_deployment_proof_distinguishes_fixture_ready_from_current_host_claim() -> None:
    report = build_proof_report(base_url=None, run_restore_drill=False)

    summary = report["proof_summary"]
    fixtures = {item["name"]: item["deployment_hardening"] for item in report["production_like_fixtures"]}

    assert summary["enterprise_production_ready_claim_allowed"] is False
    assert summary["development_mode_not_enterprise_production"] is True
    assert fixtures["production_tls_proxy_s3_postgres"]["status"] == "ready"
    assert fixtures["production_airgapped_offline_updates"]["status"] == "ready"
    assert fixtures["unsafe_production_blocks"]["status"] == "blocked"
    assert fixtures["unsafe_production_blocks"]["metadata"]["blocking_reasons"]
    assert report["compose_static_proof"]["status"] == "ready"
    assert report["safe_local_backup_restore"]["status"] == "not_run"


def test_production_deployment_proof_redacts_fixture_secret_sentinels() -> None:
    report = build_proof_report(base_url=None, run_restore_drill=False)
    serialized = str(report)
    markdown = render_markdown(report)

    assert "secret-db-pass" not in serialized
    assert "proxy-pass" not in serialized
    assert "secret-db-pass" not in markdown
    assert "proxy-pass" not in markdown
    assert "development_ready_not_enterprise_production" in markdown
