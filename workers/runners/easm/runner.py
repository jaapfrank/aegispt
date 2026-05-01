from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx as httpx_client

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

EASM_RESULTS_ARTIFACT_NAME = "easm-results.json"
DEFAULT_CRTSH_BASE_URL = "https://crt.sh/"
DEFAULT_DNS_WORDLIST_PATH = Path(__file__).with_name("default_dns_words.txt")
MAX_DNS_WORDLIST_ENTRIES = 10_000
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def normalize_root_domain(target: str) -> str:
    normalized = str(target or "").strip()
    if not normalized:
        raise ValueError("at least one target is required")

    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    host = str(parsed.hostname or parsed.path or "").strip().rstrip(".").lower()
    if not host or "." not in host:
        raise ValueError(f"invalid root domain target: {target}")
    return host


def _matches_root_domain(candidate: str, root_domain: str) -> bool:
    normalized_candidate = str(candidate or "").strip().rstrip(".").lower()
    return bool(
        normalized_candidate
        and (
            normalized_candidate == root_domain
            or normalized_candidate.endswith(f".{root_domain}")
        )
    )


def _extract_html_title(body: str) -> str | None:
    match = TITLE_PATTERN.search(body or "")
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def enumerate_subdomains_with_subfinder(
    root_domain: str,
    *,
    binary: str = "subfinder",
    timeout_seconds: float = 15.0,
) -> set[str]:
    normalized_binary = str(binary or "").strip()
    if not normalized_binary:
        return set()

    resolved_binary = shutil.which(normalized_binary) if "/" not in normalized_binary else normalized_binary
    if not resolved_binary or not Path(resolved_binary).exists():
        return set()

    try:
        process = subprocess.run(
            [resolved_binary, "-silent", "-d", root_domain],
            capture_output=True,
            text=True,
            check=False,
            timeout=max(timeout_seconds, 5.0),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()

    discovered: set[str] = set()
    for raw_line in (process.stdout or "").splitlines():
        candidate = raw_line.strip().rstrip(".").lower()
        if _matches_root_domain(candidate, root_domain):
            discovered.add(candidate)
    return discovered


def fetch_crtsh_subdomains(
    root_domain: str,
    *,
    crtsh_base_url: str = DEFAULT_CRTSH_BASE_URL,
    client: httpx_client.Client,
) -> set[str]:
    try:
        response = client.get(
            crtsh_base_url,
            params={"q": f"%.{root_domain}", "output": "json"},
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx_client.HTTPError, json.JSONDecodeError, ValueError):
        return set()

    if not isinstance(payload, list):
        return set()

    discovered: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        for field_name in ("name_value", "common_name"):
            raw_value = item.get(field_name)
            if not isinstance(raw_value, str):
                continue
            for part in raw_value.splitlines():
                candidate = part.strip().lower().lstrip("*.").rstrip(".")
                if _matches_root_domain(candidate, root_domain):
                    discovered.add(candidate)
    return discovered


def load_dns_wordlist(
    path: str | None = None,
    *,
    limit: int = MAX_DNS_WORDLIST_ENTRIES,
) -> list[str]:
    candidate_path = Path(path).expanduser() if str(path or "").strip() else DEFAULT_DNS_WORDLIST_PATH
    if not candidate_path.exists():
        return []

    prefixes: list[str] = []
    seen: set[str] = set()
    for raw_line in candidate_path.read_text(encoding="utf-8").splitlines():
        if len(prefixes) >= max(1, limit):
            break
        prefix = raw_line.strip().lower()
        if not prefix or prefix.startswith("#") or prefix in seen:
            continue
        seen.add(prefix)
        prefixes.append(prefix)
    return prefixes


def resolve_hostname_addresses(hostname: str) -> list[str]:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    addresses = sorted(
        {
            str(record[4][0]).strip()
            for record in records
            if isinstance(record, tuple)
            and len(record) >= 5
            and isinstance(record[4], tuple)
            and record[4]
            and str(record[4][0]).strip()
        }
    )
    return addresses


def enumerate_dns_wordlist_subdomains(
    root_domain: str,
    *,
    prefixes: list[str],
) -> set[str]:
    discovered: set[str] = set()
    for prefix in prefixes[:MAX_DNS_WORDLIST_ENTRIES]:
        candidate = f"{prefix}.{root_domain}"
        if resolve_hostname_addresses(candidate):
            discovered.add(candidate)
    return discovered


def probe_http_endpoints_for_host(
    host: str,
    *,
    client: httpx_client.Client,
) -> list[dict[str, object]]:
    endpoints: list[dict[str, object]] = []
    seen_urls: set[str] = set()
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = client.get(url, headers={"User-Agent": "AegisPT/0.1"})
        except httpx_client.HTTPError:
            continue

        final_url = str(response.url)
        if final_url in seen_urls:
            continue
        seen_urls.add(final_url)

        content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip()
        server_header = str(response.headers.get("server") or "").strip()
        endpoints.append(
            {
                "url": final_url,
                "scheme": scheme,
                "status_code": response.status_code,
                "title": _extract_html_title(response.text),
                "content_type": content_type or None,
                "server_header": server_header or None,
                "confidence": 0.84,
            }
        )
    return endpoints


def execute_easm_discovery(
    targets: list[str],
    *,
    scope_allowlist: dict[str, object] | None = None,
    subfinder_binary: str = "subfinder",
    crtsh_base_url: str = DEFAULT_CRTSH_BASE_URL,
    dns_wordlist_path: str | None = None,
    dns_wordlist_limit: int = MAX_DNS_WORDLIST_ENTRIES,
    timeout_seconds: float = 10.0,
    client_factory=httpx_client.Client,
) -> RunnerExecution:
    normalized_targets = [normalize_root_domain(target) for target in targets if str(target or "").strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_scope = scope_allowlist or {}
    unique_targets: list[str] = []
    seen_targets: set[str] = set()
    for target in normalized_targets:
        if not target_value_is_allowed(normalized_scope, target):
            raise ValueError(f"target outside scope: {target}")
        if target in seen_targets:
            continue
        seen_targets.add(target)
        unique_targets.append(target)

    dns_prefixes = load_dns_wordlist(dns_wordlist_path, limit=min(dns_wordlist_limit, MAX_DNS_WORDLIST_ENTRIES))
    results: list[dict[str, object]] = []
    warning_lines: list[str] = []

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for root_domain in unique_targets:
            subfinder_matches = enumerate_subdomains_with_subfinder(
                root_domain,
                binary=subfinder_binary,
                timeout_seconds=timeout_seconds,
            )
            crtsh_matches = fetch_crtsh_subdomains(
                root_domain,
                crtsh_base_url=crtsh_base_url,
                client=client,
            )
            dns_matches = enumerate_dns_wordlist_subdomains(
                root_domain,
                prefixes=dns_prefixes,
            )

            discovered_hosts = sorted(
                {
                    root_domain,
                    *subfinder_matches,
                    *crtsh_matches,
                    *dns_matches,
                }
            )

            assets: list[dict[str, object]] = []
            for host in discovered_hosts:
                discovery_sources = [
                    source
                    for source, matched in (
                        ("root-domain", host == root_domain),
                        ("subfinder", host in subfinder_matches),
                        ("crt.sh", host in crtsh_matches),
                        ("dns-wordlist", host in dns_matches),
                    )
                    if matched
                ]
                resolved_ips = resolve_hostname_addresses(host)
                http_endpoints = probe_http_endpoints_for_host(
                    host,
                    client=client,
                )
                assets.append(
                    {
                        "host": host,
                        "root_domain": root_domain,
                        "discovery_sources": discovery_sources,
                        "resolved_ips": resolved_ips,
                        "http_endpoints": http_endpoints,
                        "confidence": 0.88 if http_endpoints or resolved_ips else 0.62,
                    }
                )

            if not subfinder_matches:
                warning_lines.append(f"{root_domain}: subfinder returned no additional subdomains")
            results.append(
                {
                    "root_domain": root_domain,
                    "asset_count": len(assets),
                    "resolved_asset_count": sum(1 for asset in assets if asset["resolved_ips"]),
                    "http_endpoint_count": sum(len(asset["http_endpoints"]) for asset in assets),
                    "assets": assets,
                }
            )

    summary = {
        "root_target_count": len(unique_targets),
        "asset_count": sum(int(result.get("asset_count", 0)) for result in results),
        "resolved_asset_count": sum(int(result.get("resolved_asset_count", 0)) for result in results),
        "http_endpoint_count": sum(int(result.get("http_endpoint_count", 0)) for result in results),
        "dns_wordlist_size": len(dns_prefixes),
    }
    artifact_payload = {
        "results": results,
        "summary": summary,
    }
    artifact = EvidenceArtifact(
        name=EASM_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(artifact_payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="inventory-results",
    )

    return RunnerExecution(
        tool="easm-discover",
        exit_code=0,
        stdout=json.dumps(summary, sort_keys=True),
        stderr="\n".join(warning_lines),
        metadata={
            "status": "ok",
            "normalized_targets": unique_targets,
            "tool_version": "workers.easm.runner:v1",
            "runner_digest": "workers.easm.runner:v1",
            **summary,
        },
        artifacts=[artifact],
    )
