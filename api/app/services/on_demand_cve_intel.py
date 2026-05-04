from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.models import InventorySnapshot, Run, Task, ThreatIntelRecord
from api.app.services.audit import write_audit_event
from api.app.services.cve_sync import FeedFetcher, FeedFetchResult

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GENERIC_PRODUCTS = {
    "http",
    "https",
    "ssl",
    "tls",
    "tcpwrapped",
    "unknown",
    "unknown-service",
    "application/json",
    "text/html",
    "text/plain",
    "open port",
    "domain",
    "dns",
}
DISCOVERY_TOOLS = {
    "nmap",
    "httpx",
    "easm-discover",
    "external-infra",
    "ldap-enum",
    "aws-inventory",
}


@dataclass(frozen=True, slots=True)
class DetectedProduct:
    query: str
    product: str
    vendor: str | None = None
    version: str | None = None
    source: str | None = None
    host: str | None = None
    port: int | None = None
    confidence: float = 0.5

    def read(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source": self.source,
            "host": self.host,
            "port": self.port,
            "confidence": self.confidence,
        }


def build_run_cve_intelligence(
    session: Session,
    *,
    run: Run,
    settings: Settings | None = None,
    allow_live_nvd: bool = False,
    fetcher: FeedFetcher | None = None,
    max_products: int = 5,
    max_records_per_product: int = 20,
) -> dict[str, Any]:
    runtime_settings = settings or get_settings()
    generated_at = datetime.now(UTC)
    products = extract_detected_products_for_run(session, run=run, limit=50)
    records = match_local_cve_records(session, products)
    failures: list[dict[str, Any]] = []

    if allow_live_nvd and products:
        try:
            records.extend(
                fetch_bounded_nvd_records(
                    products[:max_products],
                    settings=runtime_settings,
                    fetcher=fetcher,
                    max_records_per_product=max_records_per_product,
                )
            )
        except Exception as exc:  # noqa: BLE001 - CVE intelligence must not block a run.
            failures.append(
                {
                    "source": "nvd",
                    "message": str(exc),
                    "non_blocking": True,
                }
            )

    rows = build_cve_rows(products, records)
    return {
        "run_id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "status": "ready" if rows else ("no_products" if not products else "no_high_risk_cves"),
        "generated_at": generated_at.isoformat(),
        "product_count": len(products),
        "cve_count": len(rows),
        "products": [product.read() for product in products],
        "rows": rows,
        "failures": failures,
        "boundary": {
            "automatic_tests_started": False,
            "operator_action_required_for_testing": True,
            "exploitation_enabled": False,
            "template_downloads_performed": False,
            "local_template_cache_only": True,
            "live_nvd_lookup_performed": allow_live_nvd,
            "live_nvd_product_limit": max_products if allow_live_nvd else 0,
            "min_cvss_score": 7.0,
        },
    }


def refresh_run_cve_intelligence(
    session: Session,
    *,
    run: Run,
    actor: str = "system:on-demand-cve-intel",
    settings: Settings | None = None,
    allow_live_nvd: bool = False,
    fetcher: FeedFetcher | None = None,
) -> dict[str, Any]:
    payload = build_run_cve_intelligence(
        session,
        run=run,
        settings=settings,
        allow_live_nvd=allow_live_nvd,
        fetcher=fetcher,
    )
    configuration = dict(run.configuration_json or {})
    configuration["on_demand_cve_intelligence"] = payload
    run.configuration_json = configuration
    write_audit_event(
        session=session,
        actor=actor,
        action="run.cve_intelligence.refreshed",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "product_count": payload["product_count"],
            "cve_count": payload["cve_count"],
            "live_nvd_lookup_performed": allow_live_nvd,
            "automatic_tests_started": False,
        },
    )
    session.flush()
    return payload


def maybe_refresh_after_discovery_task(
    session: Session,
    *,
    task: Task,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    if task.run is None or task.status != "completed" or task.tool not in DISCOVERY_TOOLS:
        return None
    try:
        return refresh_run_cve_intelligence(
            session,
            run=task.run,
            actor=f"runner:{task.tool}",
            settings=settings,
            allow_live_nvd=False,
        )
    except Exception:
        return None


def extract_detected_products_for_run(
    session: Session,
    *,
    run: Run,
    limit: int = 50,
) -> list[DetectedProduct]:
    snapshots = _snapshots_for_run(session, run=run)
    candidates: list[DetectedProduct] = []
    for snapshot in snapshots:
        inventory = snapshot.normalized_inventory_json if isinstance(snapshot.normalized_inventory_json, dict) else {}
        candidates.extend(_products_from_inventory(inventory))

    unique: dict[str, DetectedProduct] = {}
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = "|".join([_norm(candidate.product), _norm(candidate.version)])
        if not candidate.product or _is_generic_product(candidate.product):
            continue
        existing = unique.get(key)
        if existing is None or (candidate.host and not existing.host):
            unique[key] = candidate
        if len(unique) >= limit:
            break
    return list(unique.values())


def match_local_cve_records(
    session: Session,
    products: list[DetectedProduct],
) -> list[dict[str, Any]]:
    if not products:
        return []
    records = session.scalars(
        select(ThreatIntelRecord).order_by(ThreatIntelRecord.updated_at.desc(), ThreatIntelRecord.created_at.desc())
    ).all()
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        if not _record_is_high_risk(record):
            continue
        for product in products:
            matched_terms = _record_product_match_terms(record, product)
            if not matched_terms:
                continue
            key = (record.source, record.advisory_id, product.query.lower())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "source": record.source,
                    "record_id": str(record.id),
                    "advisory_id": record.advisory_id,
                    "title": record.title,
                    "summary": record.summary,
                    "severity": record.severity,
                    "metadata": dict(record.metadata_json or {}),
                    "affected_products": list(record.affected_products_json or []),
                    "affected_versions": list(record.affected_versions_json or []),
                    "references": list(record.references_json or []),
                    "matched_product": product.read(),
                    "matched_terms": matched_terms,
                }
            )
    return matches


def fetch_bounded_nvd_records(
    products: list[DetectedProduct],
    *,
    settings: Settings,
    fetcher: FeedFetcher | None = None,
    max_records_per_product: int = 20,
) -> list[dict[str, Any]]:
    headers = {"apiKey": settings.cve_feed_nvd_api_key} if settings.cve_feed_nvd_api_key else {}
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for product in products:
        response = _fetch_json(
            settings.cve_feed_nvd_api_url,
            headers=headers,
            params={
                "keywordSearch": product.query,
                "resultsPerPage": max(1, min(int(max_records_per_product), 200)),
            },
            timeout=min(float(settings.cve_feed_timeout_seconds), 10.0),
            fetcher=fetcher,
        )
        for raw in response.get("vulnerabilities", []) if isinstance(response.get("vulnerabilities"), list) else []:
            parsed = _parse_nvd_vulnerability(raw)
            if parsed is None:
                continue
            score = parsed["metadata"].get("cvss_score")
            if not isinstance(score, (int, float)) or float(score) < 7.0:
                continue
            key = (parsed["advisory_id"], product.query.lower())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    **parsed,
                    "source": "nvd-live",
                    "record_id": None,
                    "matched_product": product.read(),
                    "matched_terms": [product.query],
                }
            )
    return matches


def build_cve_rows(
    products: list[DetectedProduct],
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    product_lookup = {_norm(product.query): product for product in products}
    for match in matches:
        advisory_id = _first_cve(match.get("advisory_id") or match.get("title") or "") or str(match.get("advisory_id") or "").upper()
        if not advisory_id:
            continue
        matched_product = match.get("matched_product") if isinstance(match.get("matched_product"), dict) else {}
        product_query = str(matched_product.get("query") or "").strip()
        product = product_lookup.get(_norm(product_query)) or DetectedProduct(
            query=product_query,
            product=str(matched_product.get("product") or product_query or "Detected product"),
            vendor=matched_product.get("vendor"),
            version=matched_product.get("version"),
            source=matched_product.get("source"),
            host=matched_product.get("host"),
            port=matched_product.get("port") if isinstance(matched_product.get("port"), int) else None,
            confidence=float(matched_product.get("confidence") or 0.5),
        )
        key = (advisory_id, product.query.lower())
        if key in rows_by_key:
            existing = rows_by_key[key]
            existing["sources"] = sorted(set(existing["sources"] + [str(match.get("source") or "unknown")]))
            existing["matched_terms"] = sorted(set(existing["matched_terms"] + list(match.get("matched_terms") or [])))
            continue

        metadata = dict(match.get("metadata") or {})
        template = find_local_nuclei_template(advisory_id)
        generated_template = metadata.get("generated_nuclei_template") if isinstance(metadata.get("generated_nuclei_template"), dict) else None
        can_generate = bool(match.get("record_id"))
        test_status = _test_status(template, generated_template, can_generate=can_generate)
        rows_by_key[key] = {
            "cve_id": advisory_id,
            "record_id": match.get("record_id"),
            "title": str(match.get("title") or advisory_id),
            "summary": match.get("summary"),
            "severity": _row_severity(match),
            "cvss_score": metadata.get("cvss_score"),
            "kev": bool(metadata.get("kev") or str(match.get("source") or "").lower() in {"cisa-kev", "cisa_kev"}),
            "sources": [str(match.get("source") or "unknown")],
            "affected_product": product.read(),
            "affected_versions": list(match.get("affected_versions") or []),
            "matched_terms": list(match.get("matched_terms") or []),
            "test_status": test_status,
            "template": template,
            "generated_template": generated_template,
            "actions": _row_actions(test_status),
            "fix_guidance": _fix_guidance(product, advisory_id, match),
            "references": list(match.get("references") or []),
            "operator_boundary": {
                "run_test_requires_click": True,
                "no_auto_execution": True,
                "detection_only": True,
            },
        }
    return sorted(
        rows_by_key.values(),
        key=lambda row: (
            0 if row["kev"] else 1,
            -float(row["cvss_score"] or 0.0),
            row["cve_id"],
            row["affected_product"]["query"],
        ),
    )


def queue_targeted_nuclei_task(
    session: Session,
    *,
    run: Run,
    cve_id: str,
    actor: str,
) -> Task:
    payload = build_run_cve_intelligence(session, run=run, allow_live_nvd=False)
    row = next((item for item in payload["rows"] if item["cve_id"].lower() == cve_id.lower()), None)
    if row is None:
        raise ValueError("CVE is not available for the selected run")
    if row["test_status"] != "ready":
        raise ValueError("No local ready Nuclei template is available for this CVE")
    template_path = str((row.get("template") or {}).get("path") or "").strip()
    if not template_path:
        raise ValueError("Local template path is missing")
    template_file = Path(template_path)
    if not template_file.exists() or not template_file.is_file():
        raise ValueError("Local template path is no longer available")
    template_body = template_file.read_text(encoding="utf-8", errors="replace")
    product = row.get("affected_product") if isinstance(row.get("affected_product"), dict) else {}
    target = str(product.get("host") or _first_run_target(run) or "").strip()
    if not target:
        raise ValueError("No concrete target is available for the targeted CVE test")
    task = Task(
        run=run,
        tool="nuclei",
        target_id=target,
        status="queued",
        params_json={
            "target_kind": "host" if product.get("host") else "target",
            "profile_name": "passive-web-nuclei-audit",
            "run_class": "passive",
            "limits": {"max_rps": 1, "max_concurrency": 1},
            "on_demand_cve_intelligence": {
                "cve_id": row["cve_id"],
                "affected_product": product,
                "queued_by": actor,
                "queued_at": datetime.now(UTC).isoformat(),
                "operator_approved": True,
                "automatic_tests_started": False,
            },
            "template_body": template_body,
            "template_id": row["cve_id"].lower(),
            "template_source": "local-nuclei-template-cache",
            "template_filename": template_file.name,
        },
    )
    session.add(task)
    session.flush()
    run.status = "queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="run.cve_intelligence.targeted_test_queued",
        object_type="task",
        object_id=str(task.id),
        metadata={
            "run_id": str(run.id),
            "cve_id": row["cve_id"],
            "target": target,
            "template_path": template_path,
            "operator_approved": True,
        },
    )
    return task


def _snapshots_for_run(session: Session, *, run: Run) -> list[InventorySnapshot]:
    snapshots: list[InventorySnapshot] = []
    if run.source_inventory_snapshot_id is not None:
        source = session.get(InventorySnapshot, run.source_inventory_snapshot_id)
        if source is not None:
            snapshots.append(source)
    run_id = str(run.id)
    derived = session.scalars(
        select(InventorySnapshot)
        .where(InventorySnapshot.engagement_id == run.engagement_id)
        .order_by(InventorySnapshot.created_at.desc(), InventorySnapshot.id.desc())
    ).all()
    for snapshot in derived:
        raw_inputs = snapshot.raw_inputs_json if isinstance(snapshot.raw_inputs_json, dict) else {}
        if str(raw_inputs.get("run_id") or "") != run_id:
            continue
        if snapshot.id not in {item.id for item in snapshots}:
            snapshots.append(snapshot)
    return snapshots


def _first_run_target(run: Run) -> str | None:
    for task in list(run.tasks or []):
        if task.target_id:
            return str(task.target_id)
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    targets = configuration.get("targets") if isinstance(configuration.get("targets"), dict) else {}
    for key in ("urls", "api_base_urls", "ip_addresses", "hosts", "cidr_ranges", "domains", "targets"):
        values = targets.get(key) if isinstance(targets, dict) else None
        if isinstance(values, list):
            for value in values:
                if str(value or "").strip():
                    return str(value).strip()
    return None


def _products_from_inventory(inventory: dict[str, Any]) -> list[DetectedProduct]:
    products: list[DetectedProduct] = []
    for entry in inventory.get("vendor_product_fingerprints", []) or []:
        if isinstance(entry, dict):
            products.append(_product_from_fields(entry, source=entry.get("source") or "fingerprint"))
    for entry in inventory.get("technologies", []) or []:
        if isinstance(entry, dict):
            products.append(
                _product_from_fields(
                    {
                        "vendor": entry.get("vendor"),
                        "product": entry.get("product") or entry.get("name"),
                        "version": entry.get("version"),
                        "confidence": entry.get("confidence"),
                        "source": entry.get("source") or "technology",
                    }
                )
            )
    for entry in inventory.get("services", []) or []:
        if isinstance(entry, dict):
            product = str(entry.get("product") or "").strip()
            if not product:
                continue
            products.append(
                _product_from_fields(
                    {
                        "vendor": entry.get("vendor"),
                        "product": product,
                        "version": entry.get("version"),
                        "confidence": entry.get("confidence"),
                        "source": entry.get("source") or entry.get("service") or "service",
                        "host": entry.get("host"),
                        "port": entry.get("port"),
                    }
                )
            )
    return [product for product in products if product.product]


def _product_from_fields(entry: dict[str, Any], *, source: str | None = None) -> DetectedProduct:
    vendor = _clean(entry.get("vendor"))
    product = _clean(entry.get("product") or entry.get("name")) or ""
    version = _clean(entry.get("version"))
    query = " ".join(part for part in [vendor, product, version] if part).strip() or product
    return DetectedProduct(
        query=query,
        vendor=vendor,
        product=product,
        version=version,
        source=_clean(source or entry.get("source")),
        host=_clean(entry.get("host")),
        port=entry.get("port") if isinstance(entry.get("port"), int) else None,
        confidence=_bounded_float(entry.get("confidence"), default=0.5),
    )


def _record_product_match_terms(record: ThreatIntelRecord | dict[str, Any], product: DetectedProduct) -> list[str]:
    if isinstance(record, ThreatIntelRecord):
        values = [
            record.advisory_id,
            record.title,
            record.summary,
            *(record.affected_products_json or []),
            *(record.product_match_hints_json or []),
            *(_metadata_values(dict(record.metadata_json or {}))),
        ]
    else:
        values = [
            record.get("advisory_id"),
            record.get("title"),
            record.get("summary"),
            *(record.get("affected_products") or []),
            *(_metadata_values(dict(record.get("metadata") or {}))),
        ]
    haystack = " ".join(str(value or "") for value in values).lower()
    candidates = [
        product.query,
        product.product,
        " ".join(part for part in [product.vendor, product.product] if part),
    ]
    if product.version:
        candidates.append(" ".join(part for part in [product.product, product.version] if part))
    matches = []
    for candidate in candidates:
        normalized = _norm(candidate)
        if len(normalized) < 3 or _is_generic_product(normalized):
            continue
        if normalized in haystack:
            matches.append(candidate)
    return list(dict.fromkeys(matches))


def _record_is_high_risk(record: ThreatIntelRecord) -> bool:
    metadata = dict(record.metadata_json or {})
    if bool(metadata.get("kev")) or record.source in {"cisa-kev", "cisa_kev"}:
        return True
    cvss_score = metadata.get("cvss_score")
    if isinstance(cvss_score, (int, float)) and float(cvss_score) >= 7.0:
        return True
    severity = str(record.severity or metadata.get("cvss_severity") or "").strip().lower()
    return severity in {"critical", "high", "known_exploited"}


def _parse_nvd_vulnerability(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or not isinstance(raw.get("cve"), dict):
        return None
    cve = raw["cve"]
    cve_id = _clean(cve.get("id"))
    if not cve_id:
        return None
    description = ""
    for item in cve.get("descriptions", []) if isinstance(cve.get("descriptions"), list) else []:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
            description = str(item["value"])
            break
    score, severity = _nvd_cvss(cve)
    affected_products = _nvd_products(cve)
    references = []
    raw_refs = cve.get("references") if isinstance(cve.get("references"), dict) else {}
    for item in raw_refs.get("referenceData", []) if isinstance(raw_refs.get("referenceData"), list) else []:
        if isinstance(item, dict) and item.get("url"):
            references.append(str(item["url"]))
    return {
        "advisory_id": cve_id.upper(),
        "title": cve_id.upper(),
        "summary": description,
        "severity": severity.lower() if severity else None,
        "affected_products": affected_products,
        "affected_versions": [],
        "references": references,
        "metadata": {
            "cvss_score": score,
            "cvss_severity": severity,
            "feed_type": "nvd",
            "external_lookup_performed": True,
        },
    }


def _nvd_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        first = rows[0] if isinstance(rows[0], dict) else {}
        cvss_data = first.get("cvssData") if isinstance(first.get("cvssData"), dict) else {}
        score = cvss_data.get("baseScore")
        severity = first.get("baseSeverity") or cvss_data.get("baseSeverity")
        return (float(score) if isinstance(score, (int, float)) else None, str(severity) if severity else None)
    return None, None


def _nvd_products(cve: dict[str, Any]) -> list[str]:
    products: list[str] = []
    configurations = cve.get("configurations") if isinstance(cve.get("configurations"), list) else []
    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) if isinstance(config.get("nodes"), list) else []:
            if not isinstance(node, dict):
                continue
            for cpe in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch"), list) else []:
                criteria = str((cpe or {}).get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) >= 6:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    version = parts[5].replace("_", " ")
                    products.append(" ".join(part for part in [vendor, product, None if version == "*" else version] if part))
    return list(dict.fromkeys(products))


def _fetch_json(
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any],
    timeout: float,
    fetcher: FeedFetcher | None,
) -> dict[str, Any]:
    if fetcher is not None:
        result = fetcher(url=url, headers=headers, params=params, timeout=timeout)
        if isinstance(result, FeedFetchResult):
            return result.json_data if isinstance(result.json_data, dict) else {}
        if isinstance(result, dict):
            return result
        if isinstance(result, tuple) and result:
            first = result[0]
            return first if isinstance(first, dict) else {}
        if isinstance(result, httpx.Response):
            return result.json()
        return {}
    response = httpx.get(url, headers=headers, params=params, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, dict) else {}


def find_local_nuclei_template(cve_id: str) -> dict[str, Any] | None:
    normalized = _first_cve(cve_id)
    if normalized is None:
        return None
    roots = tuple(_template_roots())
    template_path = _find_local_template_path(normalized.lower(), roots)
    if template_path is None:
        return None
    path = Path(template_path)
    return {
        "status": "local",
        "path": str(path),
        "template_id": path.stem,
        "source": "local-nuclei-template-cache",
    }


@lru_cache(maxsize=512)
def _find_local_template_path(cve_id: str, roots: tuple[str, ...]) -> str | None:
    candidates: list[Path] = []
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            candidates.append(root)
            continue
        patterns = [f"**/*{cve_id}*.yaml", f"**/*{cve_id}*.yml"]
        for pattern in patterns:
            candidates.extend(root.glob(pattern))
    for candidate in candidates[:250]:
        if candidate.is_file():
            return str(candidate)
    scanned = 0
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.exists() or not root.is_dir():
            continue
        for candidate in root.rglob("*.y*ml"):
            scanned += 1
            if scanned > 2000:
                return None
            try:
                if cve_id in candidate.read_text(encoding="utf-8", errors="ignore").lower():
                    return str(candidate)
            except OSError:
                continue
    return None


def _template_roots() -> list[str]:
    configured = [
        os.getenv("NUCLEI_TEMPLATES_DIR"),
        os.getenv("NUCLEI_TEMPLATE_PATH"),
    ]
    defaults = [
        "~/.local/nuclei-templates",
        "~/.nuclei-templates",
        "~/nuclei-templates",
        "/opt/nuclei-templates",
        "/usr/local/share/nuclei-templates",
    ]
    return [item for item in [*configured, *defaults] if item]


def _test_status(
    template: dict[str, Any] | None,
    generated_template: dict[str, Any] | None,
    *,
    can_generate: bool,
) -> str:
    if template is not None:
        return "ready"
    generated_status = str((generated_template or {}).get("status") or "").lower()
    if generated_status in {"deployed", "validated"}:
        return "ready"
    if generated_template or can_generate:
        return "generatable"
    return "informational"


def _row_actions(test_status: str) -> list[dict[str, Any]]:
    actions = []
    if test_status == "ready":
        actions.append(
            {
                "id": "run_test",
                "label": "Run Test",
                "requires_operator_approval": True,
                "starts_automatically": False,
            }
        )
    if test_status == "generatable":
        actions.append(
            {
                "id": "generate_template",
                "label": "Generate Template",
                "requires_pack_lifecycle": True,
                "starts_automatically": False,
            }
        )
    return actions


def _fix_guidance(product: DetectedProduct, cve_id: str, match: dict[str, Any]) -> str:
    version = f" {product.version}" if product.version else ""
    source = str(match.get("source") or "the advisory").replace("_", " ")
    return (
        f"Patch or upgrade {product.product}{version} according to {source} guidance for {cve_id}. "
        "Confirm the fixed vendor release in the asset owner change plan, then rerun only the approved targeted detection check."
    )


def _row_severity(match: dict[str, Any]) -> str:
    metadata = dict(match.get("metadata") or {})
    severity = str(match.get("severity") or metadata.get("cvss_severity") or "").strip().lower()
    if bool(metadata.get("kev")) or str(match.get("source") or "").lower() in {"cisa-kev", "cisa_kev"}:
        return "known_exploited"
    if severity:
        return severity
    score = metadata.get("cvss_score")
    if isinstance(score, (int, float)):
        if float(score) >= 9.0:
            return "critical"
        if float(score) >= 7.0:
            return "high"
    return "high"


def _metadata_values(metadata: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("cve_id", "cvss_severity", "feed_type", "required_action"):
        if metadata.get(key):
            values.append(str(metadata[key]))
    for key in ("cwe_ids", "badge_types", "products", "affected_products"):
        raw = metadata.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if item)
    return values


def _first_cve(value: str) -> str | None:
    match = CVE_PATTERN.search(str(value or ""))
    return match.group(0).upper() if match else None


def _bounded_float(value: Any, *, default: float) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    return default


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _is_generic_product(value: str) -> bool:
    normalized = _norm(value)
    return normalized in GENERIC_PRODUCTS or "/" in normalized and normalized in GENERIC_PRODUCTS
