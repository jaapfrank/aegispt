"""Read-only external knowledge lookup (ExploitDB / NVD / CISA KEV).

Per backlog-416 (sprint mythos-exploitation-foundation, task 10/15) +
user vision: *"kijk in interne geheugen en of documentatie. (mits niks
gevonden kijkt online)"*. Agents consult this module for CVE / exploit
hints AFTER local memory recall comes up empty.

Hard contract (Codex evidence-first + ANTI_DRIFT Rule 4):

- Every returned :class:`ExternalKnowledgeHint` has
  ``marked_as_hint_only=True``. The picker prompt section that consumes
  hints MUST forbid claiming impact based on KB results alone — only
  verified-exploited findings (via backlog-413's validator) count.
- Read-only. The module exposes ONLY ``lookup_*`` functions; there is
  NO write-back path to external systems.
- Per-provider caching (KEV 24h; NVD 1h; ExploitDB per-query) lives in
  ``AEGISPT_KNOWLEDGE_CACHE`` (default ``/tmp/aegispt-knowledge-cache``).
- Provenance score combines: source weight + freshness (newer = higher
  weight) + applicability (CVE match exact > product+version > product
  alone). Score is intentionally simple — picker treats it as one of
  several signals, never as a verdict.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


CACHE_ROOT_ENV = "AEGISPT_KNOWLEDGE_CACHE"
DEFAULT_CACHE_ROOT = "/tmp/aegispt-knowledge-cache"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEV_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h
NVD_CACHE_TTL_SECONDS = 60 * 60       # 1h
EXPLOITDB_CACHE_TTL_SECONDS = 60 * 60  # 1h

# Per-source weights for the provenance score. CISA KEV is the strongest
# "actively exploited" signal; ExploitDB is "PoC exists"; NVD is the
# authoritative metadata source but says nothing about exploitability.
SOURCE_WEIGHT = {
    "cisa_kev": 1.0,
    "exploitdb": 0.7,
    "nvd": 0.5,
}


@dataclass
class ExternalKnowledgeHint:
    """One result envelope. ALWAYS hint-only."""

    source: str                       # cisa_kev | exploitdb | nvd
    source_url: str
    title: str
    fetched_at: datetime
    applicability_score: float        # 0.0 - 1.0 — provenance + match strength
    body_excerpt: str = ""
    cve_id: str | None = None
    references: list[str] = field(default_factory=list)
    marked_as_hint_only: bool = True

    def to_picker_envelope(self) -> dict[str, Any]:
        return {
            "marker": "[KB HINT, VERIFY BEFORE USE — NEVER CLAIM IMPACT]",
            "source": self.source,
            "source_url": self.source_url,
            "title": self.title,
            "cve_id": self.cve_id,
            "applicability_score": round(self.applicability_score, 3),
            "fetched_at": self.fetched_at.isoformat(),
            "body_excerpt": self.body_excerpt[:600],
            "references": self.references[:5],
        }


# --- Cache helpers -----------------------------------------------------


def _cache_root() -> Path:
    root = Path(os.environ.get(CACHE_ROOT_ENV, DEFAULT_CACHE_ROOT)).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _cache_key(source: str, **kwargs: Any) -> Path:
    payload = json.dumps({"source": source, **kwargs}, sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return _cache_root() / f"{source}-{digest}.json"


def _cache_get(path: Path, ttl_seconds: int) -> Any | None:
    if not path.is_file():
        return None
    age = time.time() - path.stat().st_mtime
    if age > ttl_seconds:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(path: Path, payload: Any) -> None:
    try:
        path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    except OSError as exc:
        logger.debug("cache write failed: %s", exc)


# --- Provider: CISA KEV ------------------------------------------------


def _fetch_kev_feed() -> list[dict[str, Any]]:
    cache_path = _cache_key("cisa_kev_feed")
    cached = _cache_get(cache_path, KEV_CACHE_TTL_SECONDS)
    if cached is not None:
        return cached.get("vulnerabilities") or []
    try:
        resp = httpx.get(KEV_FEED_URL, timeout=20.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("external_knowledge: KEV fetch failed (%s); returning empty", exc)
        return []
    data = resp.json()
    _cache_put(cache_path, data)
    return data.get("vulnerabilities") or []


def _lookup_kev(cve_id: str | None, product: str | None) -> list[ExternalKnowledgeHint]:
    feed = _fetch_kev_feed()
    if not feed:
        return []
    out: list[ExternalKnowledgeHint] = []
    cve_norm = (cve_id or "").strip().upper()
    product_norm = (product or "").strip().lower()
    for entry in feed:
        entry_cve = str(entry.get("cveID") or "").upper()
        entry_product = " ".join(
            str(entry.get(k, "") or "")
            for k in ("vendorProject", "product")
        ).lower()
        applicability = 0.0
        if cve_norm and entry_cve == cve_norm:
            applicability = 1.0
        elif product_norm and product_norm in entry_product:
            applicability = 0.6
        if applicability == 0.0:
            continue
        out.append(
            ExternalKnowledgeHint(
                source="cisa_kev",
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={entry_cve}",
                title=str(entry.get("vulnerabilityName") or entry_cve),
                fetched_at=datetime.now(UTC),
                applicability_score=min(1.0, SOURCE_WEIGHT["cisa_kev"] * applicability),
                cve_id=entry_cve,
                body_excerpt=str(entry.get("shortDescription") or "")[:600],
                references=[r for r in [entry.get("dueDate"), entry.get("requiredAction")] if r],
            )
        )
        if len(out) >= 10:
            break
    return out


# --- Provider: NVD -----------------------------------------------------


def _fetch_nvd_cve(cve_id: str) -> dict[str, Any]:
    cve_norm = cve_id.strip().upper()
    cache_path = _cache_key("nvd_cve", cve=cve_norm)
    cached = _cache_get(cache_path, NVD_CACHE_TTL_SECONDS)
    if cached is not None:
        return cached
    try:
        resp = httpx.get(NVD_API_URL, params={"cveId": cve_norm}, timeout=20.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("external_knowledge: NVD fetch for %s failed (%s)", cve_norm, exc)
        return {}
    data = resp.json()
    _cache_put(cache_path, data)
    return data


def _lookup_nvd(cve_id: str) -> list[ExternalKnowledgeHint]:
    cve_norm = (cve_id or "").strip().upper()
    if not cve_norm or not cve_norm.startswith("CVE-"):
        return []
    data = _fetch_nvd_cve(cve_norm)
    if not data:
        return []
    items = data.get("vulnerabilities") or []
    out: list[ExternalKnowledgeHint] = []
    for entry in items[:5]:
        cve = entry.get("cve") or {}
        desc_list = cve.get("descriptions") or []
        desc = next(
            (d.get("value") for d in desc_list if d.get("lang") == "en"),
            "",
        )
        refs = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
        out.append(
            ExternalKnowledgeHint(
                source="nvd",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_norm}",
                title=cve_norm,
                fetched_at=datetime.now(UTC),
                applicability_score=SOURCE_WEIGHT["nvd"] * 1.0,
                cve_id=cve_norm,
                body_excerpt=str(desc or "")[:600],
                references=[str(r) for r in refs if r][:5],
            )
        )
    return out


# --- Provider: ExploitDB (via MCP-style HTTP proxy when configured) --


def _exploitdb_endpoint() -> str:
    return os.environ.get("EXPLOITDB_MCP_URL", "").strip()


def _lookup_exploitdb(cve_id: str | None, product: str | None) -> list[ExternalKnowledgeHint]:
    endpoint = _exploitdb_endpoint()
    if not endpoint:
        return []  # provider not configured — agents see only KEV/NVD
    query = (cve_id or product or "").strip()
    if not query:
        return []
    cache_path = _cache_key("exploitdb", query=query.lower())
    cached = _cache_get(cache_path, EXPLOITDB_CACHE_TTL_SECONDS)
    if cached is not None:
        return [_hint_from_cached(c) for c in cached.get("hits") or []]
    try:
        resp = httpx.get(
            endpoint,
            params={"q": query},
            timeout=15.0,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("external_knowledge: ExploitDB query %s failed (%s)", query, exc)
        return []
    raw_hits = data.get("hits") or data.get("results") or []
    hits: list[ExternalKnowledgeHint] = []
    for entry in raw_hits[:10]:
        score_match = 0.9 if cve_id and entry.get("cve_id") == cve_id else 0.6
        hits.append(
            ExternalKnowledgeHint(
                source="exploitdb",
                source_url=str(entry.get("url") or ""),
                title=str(entry.get("title") or "ExploitDB entry"),
                fetched_at=datetime.now(UTC),
                applicability_score=SOURCE_WEIGHT["exploitdb"] * score_match,
                cve_id=entry.get("cve_id"),
                body_excerpt=str(entry.get("description") or "")[:600],
                references=[str(entry.get("url") or "")],
            )
        )
    _cache_put(cache_path, {"hits": [h.__dict__ for h in hits]})
    return hits


def _hint_from_cached(cached: dict[str, Any]) -> ExternalKnowledgeHint:
    fetched_at = cached.get("fetched_at")
    if isinstance(fetched_at, str):
        try:
            fetched_at = datetime.fromisoformat(fetched_at)
        except ValueError:
            fetched_at = datetime.now(UTC)
    elif not isinstance(fetched_at, datetime):
        fetched_at = datetime.now(UTC)
    return ExternalKnowledgeHint(
        source=str(cached.get("source") or "exploitdb"),
        source_url=str(cached.get("source_url") or ""),
        title=str(cached.get("title") or ""),
        fetched_at=fetched_at,
        applicability_score=float(cached.get("applicability_score") or 0.0),
        body_excerpt=str(cached.get("body_excerpt") or ""),
        cve_id=cached.get("cve_id"),
        references=list(cached.get("references") or []),
        marked_as_hint_only=True,
    )


# --- Public lookup surface ---------------------------------------------


def lookup_exploits(
    *,
    cve_id: str | None = None,
    product: str | None = None,
    version: str | None = None,  # noqa: ARG001 — reserved for richer ExploitDB queries
) -> list[ExternalKnowledgeHint]:
    """Return a deduplicated, score-sorted list of hints across all sources."""
    hits: list[ExternalKnowledgeHint] = []
    hits.extend(_lookup_kev(cve_id, product))
    if cve_id:
        hits.extend(_lookup_nvd(cve_id))
    hits.extend(_lookup_exploitdb(cve_id, product))
    # Dedup by (source, source_url) keeping the highest-scoring entry.
    keyed: dict[tuple[str, str], ExternalKnowledgeHint] = {}
    for h in hits:
        key = (h.source, h.source_url)
        if key not in keyed or h.applicability_score > keyed[key].applicability_score:
            keyed[key] = h
    out = sorted(keyed.values(), key=lambda h: h.applicability_score, reverse=True)
    return out[:20]


def lookup_cve_details(cve_id: str) -> ExternalKnowledgeHint | None:
    """Single-CVE NVD lookup convenience wrapper."""
    hits = _lookup_nvd(cve_id)
    return hits[0] if hits else None


def cache_age_seconds(source: str, **kwargs: Any) -> float | None:
    """Diagnostic: how old is the cached entry for this source+key, if any."""
    path = _cache_key(source, **kwargs)
    if not path.is_file():
        return None
    return time.time() - path.stat().st_mtime


# Sentinel — explicitly enumerate the public read-only surface. A back-door
# write-helper added later would have to override this list, making review obvious.
__all__ = [
    "CACHE_ROOT_ENV",
    "ExternalKnowledgeHint",
    "KEV_CACHE_TTL_SECONDS",
    "NVD_CACHE_TTL_SECONDS",
    "SOURCE_WEIGHT",
    "cache_age_seconds",
    "lookup_cve_details",
    "lookup_exploits",
]


# A minimal sentinel to make absent write methods loud during refactors:
def __getattr__(name: str) -> Any:
    if name.startswith(("write_", "submit_", "publish_", "upload_")):
        raise AttributeError(
            f"external_knowledge is READ-ONLY; {name!r} is not exposed. "
            "Agents may not write back to external KB sources."
        )
    raise AttributeError(name)


_ = timedelta  # silence unused-import lint when used in future expansions
