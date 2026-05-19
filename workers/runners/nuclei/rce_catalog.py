from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

GENERIC_RCE_TEMPLATE_ID = "aegispt-rce-generic-signal-detection"
RCE_SELECTION_TEMPLATE_ID = "aegispt-rce-service-aware-selection"
RCE_TEMPLATE_SOURCE = "aegispt-curated-rce"
GENERIC_RCE_TEMPLATE_FILENAME = "aegispt-rce-generic-signal-detection.yaml"

GENERIC_RCE_DETECTION_TEMPLATE = """id: aegispt-rce-generic-signal-detection
info:
  name: AegisPT Generic RCE-Adjacent Signal Detection
  author: aegispt
  severity: medium
  tags: rce,detection,ssti,lfi,command-injection

http:
  - method: GET
    path:
      - "{{BaseURL}}/?aegispt_ssti_probe=%7B%7B7*7%7D%7D"
      - "{{BaseURL}}/?template=%7B%7B7*7%7D%7D"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "49"
      - type: status
        status:
          - 200
  - method: GET
    path:
      - "{{BaseURL}}/?file=php://filter/convert.base64-encode/resource=index.php"
      - "{{BaseURL}}/?page=php://filter/convert.base64-encode/resource=index.php"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "PD9waH|PGh0bW|aW5kZXg"
      - type: status
        status:
          - 200
  - method: GET
    path:
      - "{{BaseURL}}/?cmd=aegispt-rce-signal"
      - "{{BaseURL}}/?exec=aegispt-rce-signal"
      - "{{BaseURL}}/?command=aegispt-rce-signal"
      - "{{BaseURL}}/?ping=aegispt-rce-signal"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "aegispt-rce-signal"
      - type: status
        status:
          - 200
"""


@dataclass(frozen=True)
class RceTemplateEntry:
    cve_id: str
    template_id: str
    name: str
    service_keywords: tuple[str, ...]
    oob_required: bool = False
    protocol: str = "http"
    path_hints: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "template_id": self.template_id,
            "name": self.name,
            "service_keywords": list(self.service_keywords),
            "oob_required": self.oob_required,
            "protocol": self.protocol,
            "path_hints": list(self.path_hints),
        }


RCE_TEMPLATE_CATALOG: tuple[RceTemplateEntry, ...] = (
    RceTemplateEntry(
        cve_id="CVE-2021-44228",
        template_id="CVE-2021-44228",
        name="Log4Shell detection",
        service_keywords=("log4j", "java", "jndi", "solr", "elasticsearch", "tomcat"),
        oob_required=True,
        path_hints=("http/cves/2021/CVE-2021-44228.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2022-22965",
        template_id="CVE-2022-22965",
        name="Spring4Shell detection",
        service_keywords=("spring", "spring framework", "spring boot", "java", "tomcat"),
        path_hints=("http/cves/2022/CVE-2022-22965.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2024-36401",
        template_id="CVE-2024-36401",
        name="GeoServer RCE detection",
        service_keywords=("geoserver", "geotools"),
        path_hints=("http/cves/2024/CVE-2024-36401.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2024-23897",
        template_id="CVE-2024-23897",
        name="Jenkins CLI RCE detection",
        service_keywords=("jenkins", "x-jenkins"),
        protocol="javascript",
        path_hints=(
            "http/cves/2024/CVE-2024-23897.yaml",
            "javascript/cves/2024/CVE-2024-23897.yaml",
        ),
    ),
    RceTemplateEntry(
        cve_id="CVE-2021-25646",
        template_id="CVE-2021-25646",
        name="Apache Druid RCE detection",
        service_keywords=("druid", "apache druid"),
        path_hints=("http/cves/2021/CVE-2021-25646.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2021-43798",
        template_id="CVE-2021-43798",
        name="Grafana path traversal file-read detection",
        service_keywords=("grafana",),
        path_hints=("http/cves/2021/CVE-2021-43798.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2019-16113",
        template_id="CVE-2019-16113",
        name="Bludit RCE detection",
        service_keywords=("bludit",),
        path_hints=("http/cves/2019/CVE-2019-16113.yaml",),
    ),
    RceTemplateEntry(
        cve_id="CVE-2017-7494",
        template_id="CVE-2017-7494",
        name="SambaCry detection",
        service_keywords=("samba", "smb", "netbios"),
        protocol="network",
        path_hints=("network/cves/2017/CVE-2017-7494.yaml", "cves/2017/CVE-2017-7494.yaml"),
    ),
    RceTemplateEntry(
        cve_id="CVE-2018-7600",
        template_id="CVE-2018-7600",
        name="Drupalgeddon2 RCE detection",
        service_keywords=("drupal",),
        path_hints=("http/cves/2018/CVE-2018-7600.yaml",),
    ),
)

UNSAFE_TEMPLATE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("raw_request", r"(?im)^\s*-?\s*raw\s*:"),
    ("body_payload", r"(?im)^\s*-?\s*body\s*:"),
    ("payload_key", r"(?im)^\s*-?\s*payloads?\s*:"),
    ("attack_key", r"(?im)^\s*-?\s*attack\s*:"),
    ("unsafe_key", r"(?im)^\s*-?\s*unsafe\s*:"),
    ("javascript_protocol", r"(?im)^\s*-?\s*javascript\s*:"),
    ("code_protocol", r"(?im)^\s*-?\s*code\s*:"),
    ("interactsh_callback_payload", r"interactsh-url|interactsh_protocol"),
    ("jndi_callback_payload", r"\$\{jndi:"),
    ("command_execution_string", r"Runtime\.getRuntime|/bin/sh|passthru|cmd\.exe|powershell"),
    ("outbound_curl_payload", r"\bcurl[+ ]"),
)


def template_roots() -> list[str]:
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


def template_repository_status(
    *,
    roots: list[str] | None = None,
) -> list[dict[str, Any]]:
    root_values = roots or template_roots()
    result: list[dict[str, Any]] = []
    for entry in RCE_TEMPLATE_CATALOG:
        found_path = _find_template_path(entry, root_values)
        result.append(
            {
                **entry.as_dict(),
                "status": "present" if found_path else "not_verified",
                "local_path": found_path,
                "safety": inspect_template_safety(found_path) if found_path else _missing_safety(),
                "searched_roots": root_values,
                "gap": None
                if found_path
                else "local nuclei template repository is missing this template or is not installed",
            }
        )
    return result


def inspect_template_safety(path: str | None) -> dict[str, Any]:
    if not path:
        return _missing_safety()
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {"status": "not_verified", "blocked_reasons": ["template_read_failed"]}
    blocked_reasons = [
        reason for reason, pattern in UNSAFE_TEMPLATE_PATTERNS if re.search(pattern, text)
    ]
    if blocked_reasons:
        return {
            "status": "blocked_by_detection_only_policy",
            "blocked_reasons": blocked_reasons,
        }
    return {"status": "safe_detection_only", "blocked_reasons": []}


def service_evidence_from_inventory(inventory: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(inventory, dict):
        return []
    evidence: list[dict[str, Any]] = []
    for collection_name in ("services", "technologies", "fingerprints", "endpoints", "script_outputs"):
        values = inventory.get(collection_name)
        if not isinstance(values, list):
            continue
        for value in values[:500]:
            if not isinstance(value, dict):
                continue
            evidence.append({"source": collection_name, **value})
    return evidence


def select_rce_template_ids(
    *,
    targets: list[str],
    service_evidence: list[dict[str, Any]] | None = None,
    inventory: dict[str, Any] | None = None,
    requested_template_ids: list[str] | None = None,
    oob_enabled: bool = False,
) -> dict[str, Any]:
    evidence = [item for item in service_evidence or [] if isinstance(item, dict)]
    evidence.extend(service_evidence_from_inventory(inventory))
    evidence_text = [_evidence_text(item) for item in evidence]
    requested = {item.lower() for item in requested_template_ids or [] if item.strip()}
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for entry in RCE_TEMPLATE_CATALOG:
        matched_terms = _matched_terms(entry, evidence_text)
        requested_match = entry.template_id.lower() in requested or entry.cve_id.lower() in requested
        target_hint_match = _target_hint_matches(entry, targets)
        should_select = requested_match or bool(matched_terms) or target_hint_match
        if not should_select:
            skipped.append({**entry.as_dict(), "reason": "no matching service evidence"})
            continue
        if entry.oob_required and not oob_enabled:
            skipped.append({**entry.as_dict(), "reason": "oob_disabled"})
            continue
        selected.append(
            {
                **entry.as_dict(),
                "matched_terms": sorted(matched_terms),
                "requested": requested_match,
                "target_hint_match": target_hint_match,
            }
        )

    selected_ids = sorted({item["template_id"] for item in selected})
    return {
        "catalog": [entry.as_dict() for entry in RCE_TEMPLATE_CATALOG],
        "selected_template_ids": selected_ids,
        "selected": selected,
        "skipped": skipped,
        "service_evidence_count": len(evidence),
        "service_evidence_samples": evidence[:20],
    }


def _find_template_path(entry: RceTemplateEntry, roots: list[str]) -> str | None:
    normalized_cve = entry.cve_id.lower()
    normalized_id = entry.template_id.lower()
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.exists():
            continue
        for hint in entry.path_hints:
            candidate = root / hint
            if candidate.is_file():
                return str(candidate)
        if root.is_file() and _path_matches(root, normalized_cve, normalized_id):
            return str(root)
        if not root.is_dir():
            continue
        for pattern in (
            f"**/*{entry.cve_id}*.yaml",
            f"**/*{entry.cve_id}*.yml",
            f"**/*{normalized_cve}*.yaml",
            f"**/*{normalized_cve}*.yml",
        ):
            for candidate in root.glob(pattern):
                if candidate.is_file():
                    return str(candidate)
    return None


def _path_matches(path: Path, cve_id: str, template_id: str) -> bool:
    lowered = str(path).lower()
    return cve_id in lowered or template_id in lowered


def _evidence_text(item: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "service",
        "product",
        "version",
        "name",
        "vendor",
        "evidence",
        "title",
        "url",
        "host",
        "output",
        "id",
    ):
        value = item.get(key)
        if value is not None:
            values.append(str(value))
    return " ".join(values).lower()


def _missing_safety() -> dict[str, Any]:
    return {"status": "not_verified", "blocked_reasons": ["template_not_present"]}


def _matched_terms(entry: RceTemplateEntry, evidence_text: list[str]) -> set[str]:
    matches: set[str] = set()
    for keyword in entry.service_keywords:
        needle = keyword.lower()
        if any(needle in text for text in evidence_text):
            matches.add(keyword)
    return matches


def _target_hint_matches(entry: RceTemplateEntry, targets: list[str]) -> bool:
    target_text = " ".join(_target_tokens(target) for target in targets).lower()
    return any(keyword.lower() in target_text for keyword in entry.service_keywords)


def _target_tokens(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    values = [target]
    if parsed.hostname:
        values.append(parsed.hostname)
    if parsed.path:
        values.extend(re.split(r"[^a-zA-Z0-9_-]+", parsed.path))
    return " ".join(values)
