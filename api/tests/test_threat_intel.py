from __future__ import annotations

from uuid import UUID

from api.app.models import Finding


def _create_run(client) -> dict:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "name": "Threat Intel Badges",
            "client": "Acme Corp",
            "roe_ref": "ROE-THREAT-INTEL-1",
        },
    ).json()
    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "allowlist_json": {"urls": ["https://portal.example.test"]},
            "denylist_json": {},
        },
    )
    response = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://portal.example.test"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()


def _seed_finding(
    client,
    *,
    run_id: str,
    title: str,
    summary: str,
    evidence_ref: str = "artifact://zap/threat-intel",
    severity: str = "high",
) -> str:
    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title=title,
            severity=severity,
            target_id="https://portal.example.test",
            evidence_ref=evidence_ref,
            status="open",
            summary=summary,
            methodology_tags=["T1190", "OWASP-WSTG"],
            control_family="web-application",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def test_feed_cache_import_normalizes_approved_sources_and_matching_uses_local_records(client) -> None:
    run = _create_run(client)
    finding_id = _seed_finding(
        client,
        run_id=run["id"],
        title="Apache Struts CVE-2026-0001 public-facing exploit evidence",
        summary="Stored evidence references CVE-2026-0001 and ATT&CK T1190 without claiming attribution.",
    )

    kev_response = client.post(
        "/api/v1/threat-intel/feed-cache/import",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "feed_type": "cisa_kev",
            "feed_name": "CISA KEV local fixture",
            "feed_cached_at": "2026-04-22T00:00:00Z",
            "stale_after_days": 30,
            "records": [
                {
                    "cveID": "CVE-2026-0001",
                    "vulnerabilityName": "Apache Struts remote code execution",
                    "vendorProject": "Apache",
                    "product": "Struts",
                    "knownRansomwareCampaignUse": "Known",
                    "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                }
            ],
        },
    )
    assert kev_response.status_code == 201
    kev_payload = kev_response.json()
    assert kev_payload["external_lookup_performed"] is False
    assert kev_payload["imported_count"] == 1
    assert kev_payload["records"][0]["metadata_json"]["kev"] is True
    assert kev_payload["records"][0]["metadata_json"]["approved_feed"] is True

    cvss_response = client.post(
        "/api/v1/threat-intel/feed-cache/import",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "feed_type": "cve_cvss",
            "feed_name": "CVE CVSS local fixture",
            "feed_cached_at": "2026-04-22T00:00:00Z",
            "records": [
                {
                    "cve_id": "CVE-2026-0001",
                    "title": "Apache Struts remote code execution",
                    "cvss_score": 9.8,
                    "cvss_severity": "critical",
                    "affected_products": ["Apache Struts"],
                    "cwe_ids": ["CWE-94"],
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
                }
            ],
        },
    )
    assert cvss_response.status_code == 201

    attack_response = client.post(
        "/api/v1/threat-intel/feed-cache/import",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "feed_type": "mitre_attack",
            "feed_name": "MITRE ATT&CK local fixture",
            "feed_cached_at": "2026-04-22T00:00:00Z",
            "records": [
                {
                    "technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "initial-access",
                    "platforms": ["IaaS", "Linux", "Windows"],
                    "references": ["https://attack.mitre.org/techniques/T1190/"],
                }
            ],
        },
    )
    assert attack_response.status_code == 201

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    badges = theater_response.json()["threat_intel_badges"]
    assert badges["available"] is True
    assert badges["boundary"]["external_lookup_performed"] is False
    assert badges["boundary"]["downloads_exploits"] is False
    assert badges["boundary"]["claims_actor_attribution"] is False
    assert badges["boundary"]["changes_finding_severity"] is False
    badge_types = {badge["type"] for badge in badges["badges"]}
    assert {"kev", "cvss", "attack"}.issubset(badge_types)
    assert all(badge["external_lookup_performed"] is False for badge in badges["badges"])
    assert all(badge["claims_actor_attribution"] is False for badge in badges["badges"])
    assert any(badge["label"] == "KEV CVE-2026-0001" for badge in badges["badges"])
    assert any(badge["label"] == "CVSS 9.8 critical" for badge in badges["badges"])
    assert any(badge["label"] == "ATT&CK T1190" for badge in badges["badges"])


def test_stale_feed_matches_are_labeled_truthfully(client) -> None:
    run = _create_run(client)
    finding_id = _seed_finding(
        client,
        run_id=run["id"],
        title="Legacy CVE-2020-0001 evidence",
        summary="The finding text references CVE-2020-0001 from a local feed record.",
        severity="medium",
    )

    response = client.post(
        "/api/v1/threat-intel/feed-cache/import",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "feed_type": "cve_cvss",
            "feed_name": "Stale CVE local fixture",
            "feed_cached_at": "2020-01-01T00:00:00Z",
            "stale_after_days": 30,
            "records": [
                {
                    "cve_id": "CVE-2020-0001",
                    "title": "Legacy advisory",
                    "cvss_score": 5.3,
                    "cvss_severity": "medium",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0001"],
                }
            ],
        },
    )
    assert response.status_code == 201

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    badges = theater_response.json()["threat_intel_badges"]
    assert badges["available"] is True
    assert badges["stale_record_count"] == 1
    assert badges["badges"][0]["cache_status"] == "stale"
    assert "stale threshold is 30 days" in badges["badges"][0]["cache_detail"]


def test_no_local_match_degrades_without_badges_or_fabrication(client) -> None:
    run = _create_run(client)
    finding_id = _seed_finding(
        client,
        run_id=run["id"],
        title="Missing security header",
        summary="No CVE, KEV, or ATT&CK technique is present in this finding.",
        severity="low",
    )
    response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert response.status_code == 200
    badges = response.json()["threat_intel_badges"]
    assert badges["available"] is False
    assert badges["badges"] == []
    assert "No locally cached approved-feed" in badges["no_badge_reason"]
    assert badges["boundary"]["external_lookup_performed"] is False


def test_feed_cache_import_rejects_external_url_fetch_shape(client) -> None:
    response = client.post(
        "/api/v1/threat-intel/feed-cache/import",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "feed_type": "cisa_kev",
            "feed_name": "External fetch attempt",
            "feed_cached_at": "2026-04-22T00:00:00Z",
            "source_url": "https://example.test/feed.json",
            "records": [],
        },
    )
    assert response.status_code == 422
