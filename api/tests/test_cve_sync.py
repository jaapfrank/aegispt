from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import CveProductWatchlistEntry, ThreatIntelRecord
from api.app.services.cve_sync import (
    FeedFetchResult,
    sync_cve_feeds,
    upsert_product_watchlist_entry,
)
from api.app.services.threat_intel import build_finding_threat_intel_badges


def test_cve_sync_imports_full_curated_feeds_and_filters_watchlist_sources(client) -> None:
    settings = get_settings()

    def fake_fetcher(*, url: str, headers: dict, params: dict, timeout: float) -> FeedFetchResult:
        if "known_exploited" in url:
            return FeedFetchResult(
                status_code=200,
                json_data={
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-0001",
                            "vendorProject": "Example",
                            "product": "RouterOS",
                            "vulnerabilityName": "Example Router exploited issue",
                            "dateAdded": "2026-04-20",
                        }
                    ]
                },
            )
        if "advisories.ncsc.nl" in url:
            return FeedFetchResult(
                status_code=200,
                text="""
                <rss><channel><item>
                  <title>NCSC advisory for CVE-2026-0002 in Example Gateway</title>
                  <link>https://advisories.ncsc.nl/advisory?id=NCSC-2026-0002</link>
                  <description>Security advisory references CVE-2026-0002.</description>
                  <pubDate>Sat, 25 Apr 2026 09:00:00 GMT</pubDate>
                </item></channel></rss>
                """,
            )
        if "services.nvd.nist.gov" in url:
            assert params["keywordSearch"] == "nginx"
            return FeedFetchResult(
                status_code=200,
                json_data={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2026-0003",
                                "published": "2026-04-21T00:00:00.000",
                                "lastModified": "2026-04-22T00:00:00.000",
                                "descriptions": [
                                    {"lang": "en", "value": "Critical nginx request smuggling issue."}
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseScore": 9.1}, "baseSeverity": "CRITICAL"}
                                    ]
                                },
                                "configurations": [
                                    {
                                        "nodes": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "criteria": "cpe:2.3:a:f5:nginx:1.25:*:*:*:*:*:*:*"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0003"}],
                            }
                        },
                        {
                            "cve": {
                                "id": "CVE-2026-0004",
                                "descriptions": [{"lang": "en", "value": "Low nginx issue."}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseScore": 4.2}, "baseSeverity": "LOW"}
                                    ]
                                },
                                "configurations": [],
                            }
                        },
                    ]
                },
            )
        raise AssertionError(f"unexpected feed URL: {url}")

    with client.app.state.session_factory() as session:
        upsert_product_watchlist_entry(session, tenant_id=None, query="nginx", actor="tester")
        result = sync_cve_feeds(session, tenant_id=None, settings=settings, fetcher=fake_fetcher, force=True)
        session.commit()

        assert result["status"] == "completed"
        assert {source["source"]: source["status"] for source in result["sources"]} == {
            "cisa_kev": "completed",
            "ncsc_nl": "completed",
            "nvd": "completed",
            "opencve": "skipped",
        }

        records = session.scalars(select(ThreatIntelRecord).order_by(ThreatIntelRecord.advisory_id)).all()
        assert [record.advisory_id for record in records] == [
            "CVE-2026-0001",
            "CVE-2026-0002",
            "CVE-2026-0003",
        ]
        assert all(record.metadata_json["external_lookup_performed"] is False for record in records)

        badges = build_finding_threat_intel_badges(
            session,
            SimpleNamespace(
                title="CVE-2026-0003 nginx request smuggling",
                summary="Observed nginx exposure",
                target_id="api.example.test",
                evidence_ref="artifact://nuclei/nginx",
                control_family="web",
                wstg_id=None,
                asvs_reference=None,
                methodology_tags=[],
            ),
        )
        assert badges["available"] is True
        assert badges["boundary"]["external_lookup_performed"] is False


def test_nvd_rate_limit_failure_is_non_blocking_and_explained(client) -> None:
    settings = get_settings()

    def rate_limited_fetcher(*, url: str, headers: dict, params: dict, timeout: float) -> FeedFetchResult:
        assert "services.nvd.nist.gov" in url
        return FeedFetchResult(status_code=429, json_data={"message": "rate limited"})

    with client.app.state.session_factory() as session:
        upsert_product_watchlist_entry(session, tenant_id=None, query="nginx", actor="tester")
        result = sync_cve_feeds(
            session,
            tenant_id=None,
            settings=settings,
            fetcher=rate_limited_fetcher,
            source_names=["nvd"],
            force=True,
        )
        session.commit()

    assert result["status"] == "completed"
    assert result["sources"][0]["source"] == "nvd"
    assert result["sources"][0]["status"] == "failed"
    assert result["sources"][0]["metadata"]["reason"] == "rate_limited"
    assert result["sources"][0]["metadata"]["non_blocking"] is True
    assert result["sources"][0]["metadata"]["watchlist_only"] is True


def test_threat_intel_watchlist_and_sync_endpoints(client, monkeypatch) -> None:
    response = client.get("/api/v1/threat-intel/feed-sync/status")
    assert response.status_code == 200
    assert response.json()["policy"]["full_cve_mirror"] is False

    add_response = client.post(
        "/api/v1/threat-intel/product-watchlist",
        headers={"X-Actor": "operator"},
        json={"query": "nginx"},
    )
    assert add_response.status_code == 201
    assert add_response.json()["status"] == "approved"

    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "operator"},
        json={"name": "CVE Sync Test", "client": "Acme", "roe_ref": "ROE-CVE"},
    )
    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "operator"},
        json={
            "engagement_id": engagement_response.json()["id"],
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "http",
                    "data": {
                        "technologies": [
                            {"name": "Apache httpd", "vendor": "Apache", "confidence": 0.9}
                        ]
                    },
                }
            ],
        },
    )
    watchlist_after_inventory = client.get("/api/v1/threat-intel/product-watchlist")
    assert watchlist_after_inventory.status_code == 200
    assert any(
        entry["query"] == "Apache Apache httpd" and entry["status"] == "suggested"
        for entry in watchlist_after_inventory.json()
    )

    suggest_response = client.post(
        "/api/v1/threat-intel/product-watchlist/suggest-from-inventory",
        headers={"X-Actor": "operator"},
        json={"inventory_snapshot_id": inventory_response.json()["id"]},
    )
    assert suggest_response.status_code == 200
    suggested = [entry for entry in suggest_response.json() if entry["status"] == "suggested"]
    assert any(entry["query"] == "Apache Apache httpd" for entry in suggested)

    approve_response = client.post(
        f"/api/v1/threat-intel/product-watchlist/{suggested[0]['id']}/approve",
        headers={"X-Actor": "operator"},
        json={},
    )
    assert approve_response.status_code == 200
    assert approve_response.json()["status"] == "approved"

    from api.app.routers import threat_intel as threat_intel_router

    def fake_sync(*args, **kwargs):
        now = datetime.now(UTC)
        return {
            "tenant_id": "default",
            "status": "completed",
            "sources": [
                {
                    "source": "cisa_kev",
                    "label": "CISA KEV",
                    "status": "completed",
                    "started_at": now,
                    "completed_at": now,
                    "imported_count": 1,
                    "updated_count": 0,
                    "skipped_count": 0,
                    "error": None,
                    "metadata": {"full_sync": True},
                }
            ],
            "imported_count": 1,
            "updated_count": 0,
            "skipped_count": 0,
            "policy": {"full_cve_mirror": False, "finding_time_external_lookup": False},
        }

    monkeypatch.setattr(threat_intel_router, "sync_cve_feeds", fake_sync)
    sync_response = client.post(
        "/api/v1/threat-intel/feed-sync/run",
        headers={"X-Actor": "operator"},
        json={"sources": ["cisa_kev"]},
    )
    assert sync_response.status_code == 200
    assert sync_response.json()["imported_count"] == 1

    delete_response = client.delete(
        f"/api/v1/threat-intel/product-watchlist/{add_response.json()['id']}",
        headers={"X-Actor": "operator"},
    )
    assert delete_response.status_code == 204

    with client.app.state.session_factory() as session:
        remaining = session.scalars(select(CveProductWatchlistEntry)).all()
        assert {entry.query for entry in remaining} == {"Apache Apache httpd"}
