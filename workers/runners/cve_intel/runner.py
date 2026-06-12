from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

FINDING_PREFIX = "AEGISPT_FINDING:"
EXPLOIT_DB_BASE_URL = "https://www.exploit-db.com/exploits/"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _clean(value: Any) -> str:
    """Return a stripped string for any scalar-ish value (None -> "")."""
    if value is None:
        return ""
    return str(value).strip()


def build_searchsploit_command(
    product: str,
    version: str | None = None,
    *,
    binary: str = "searchsploit",
) -> list[str]:
    """Build the searchsploit invocation for a detected product (+ optional version).

    Uses ``-j`` (JSON output) and ``--colour`` disabled so the output parses
    deterministically regardless of the host terminal.
    """
    if not binary.strip():
        raise ValueError("binary must not be blank")

    normalized_product = _clean(product)
    if not normalized_product:
        raise ValueError("product must not be blank")

    command = [binary, "--colour", "-j"]
    command.extend(normalized_product.split())
    normalized_version = _clean(version)
    if normalized_version:
        command.extend(normalized_version.split())
    return command


def _fingerprint_key(product: str, version: str | None) -> tuple[str, str]:
    return (product.strip().lower(), _clean(version).lower())


def extract_fingerprints_from_params(params: dict[str, Any]) -> list[dict[str, str]]:
    """Collect product+version fingerprints from runner params.

    Sources (de-duplicated, in priority order):

    * ``params["fingerprints"]`` — explicit ``{"product", "version", "vendor"}`` dicts.
    * ``params["product"]`` / ``params["version"]`` — a single explicit fingerprint.
    * ``params["observations"]`` / ``params["inventory"]`` — prior recon inventory
      observations (the same shape nmap/httpx runners emit), so this runner
      auto-correlates against tech detected earlier in the run.
    """
    fingerprints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(product: Any, version: Any = None, vendor: Any = None) -> None:
        normalized_product = _clean(product)
        if not normalized_product:
            return
        normalized_version = _clean(version)
        key = _fingerprint_key(normalized_product, normalized_version)
        if key in seen:
            return
        seen.add(key)
        fingerprints.append(
            {
                "product": normalized_product,
                "version": normalized_version,
                "vendor": _clean(vendor),
            }
        )

    # 1. Single explicit product/version on the params root.
    add(params.get("product"), params.get("version"), params.get("vendor"))

    # 2. Explicit fingerprint list.
    raw_fingerprints = params.get("fingerprints")
    for entry in raw_fingerprints if isinstance(raw_fingerprints, list) else []:
        if isinstance(entry, str):
            add(entry)
        elif isinstance(entry, dict):
            add(
                entry.get("product") or entry.get("name"),
                entry.get("version"),
                entry.get("vendor"),
            )

    # 3. Prior recon inventory observations (auto-correlation after recon).
    observation_sources: list[Any] = []
    for source_key in ("observations", "inventory"):
        source = params.get(source_key)
        if isinstance(source, list):
            observation_sources.extend(source)
        elif isinstance(source, dict):
            observation_sources.append(source)

    for observation in observation_sources:
        if not isinstance(observation, dict):
            continue
        data = observation.get("data") if isinstance(observation.get("data"), dict) else observation
        if not isinstance(data, dict):
            continue
        for collection_key in ("fingerprints", "services"):
            collection = data.get(collection_key)
            if not isinstance(collection, list):
                continue
            for item in collection:
                if not isinstance(item, dict):
                    continue
                add(
                    item.get("product") or item.get("name"),
                    item.get("version"),
                    item.get("vendor"),
                )

    return fingerprints


def _normalize_exploit_records(payload: Any) -> list[dict[str, Any]]:
    """Pull the exploit record list out of a parsed searchsploit JSON payload."""
    if not isinstance(payload, dict):
        return []
    records: list[dict[str, Any]] = []
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        collection = payload.get(key)
        if isinstance(collection, list):
            records.extend(record for record in collection if isinstance(record, dict))
    return records


def _cves_from_record(record: dict[str, Any]) -> list[str]:
    codes = _clean(record.get("Codes"))
    found = CVE_PATTERN.findall(f"{codes} {_clean(record.get('Title'))}")
    seen: set[str] = set()
    cves: list[str] = []
    for raw in found:
        normalized = raw.upper()
        if normalized not in seen:
            seen.add(normalized)
            cves.append(normalized)
    return cves


def _exploit_url(record: dict[str, Any]) -> str:
    edb_id = _clean(record.get("EDB-ID"))
    if edb_id:
        return f"{EXPLOIT_DB_BASE_URL}{edb_id}"
    return _clean(record.get("Path"))


def _finding_payload(
    *,
    record: dict[str, Any],
    fingerprint: dict[str, str],
) -> dict[str, Any]:
    cves = _cves_from_record(record)
    title = _clean(record.get("Title")) or "Exploit-DB entry"
    matched_product = fingerprint["product"]
    matched_version = fingerprint.get("version") or None
    matched = matched_product + (f" {matched_version}" if matched_version else "")
    primary_cve = cves[0] if cves else None
    finding_id = primary_cve or f"EDB-{_clean(record.get('EDB-ID')) or 'unknown'}"
    return {
        "id": finding_id,
        "cves": cves,
        "title": title,
        "severity": "high" if cves else "medium",
        "exploit_path": _clean(record.get("Path")) or None,
        "exploit_url": _exploit_url(record) or None,
        "edb_id": _clean(record.get("EDB-ID")) or None,
        "matched_product": matched_product,
        "matched_version": matched_version,
        "matched_fingerprint": matched.strip(),
        "source": "exploit-db/searchsploit",
    }


def execute_cve_intel(
    *,
    params: dict[str, Any] | None = None,
    binary: str = "searchsploit",
    timeout_seconds: float = 30.0,
) -> RunnerExecution:
    """Correlate detected product+version fingerprints to known CVEs/public exploits.

    Queries the local Exploit-DB (searchsploit) for every fingerprint discovered
    in ``params`` (explicit, or auto-correlated from prior recon inventory) and
    emits ``AEGISPT_FINDING:`` stdout lines for each matched exploit so the picker
    can act on concrete, known-public exploits. Degrades to
    ``metadata.skipped = True`` when searchsploit is unavailable.
    """
    params = params or {}
    fingerprints = extract_fingerprints_from_params(params)

    if shutil.which(binary) is None:
        return RunnerExecution(
            tool="cve_intel",
            exit_code=0,
            stdout="",
            stderr=f"{binary} is not installed; skipping CVE correlation",
            metadata={
                "status": "skipped",
                "skipped": True,
                "reason": f"{binary} not found on PATH",
                "fingerprint_count": len(fingerprints),
                "tool_version": "searchsploit",
                "runner_digest": "workers.cve_intel.runner:v1",
            },
            artifacts=[],
        )

    if not fingerprints:
        return RunnerExecution(
            tool="cve_intel",
            exit_code=0,
            stdout="",
            stderr="no product fingerprints available for CVE correlation",
            metadata={
                "status": "skipped",
                "skipped": True,
                "reason": "no fingerprints",
                "fingerprint_count": 0,
                "tool_version": "searchsploit",
                "runner_digest": "workers.cve_intel.runner:v1",
            },
            artifacts=[],
        )

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    all_records: list[dict[str, Any]] = []
    finding_payloads: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    exit_code = 0

    for fingerprint in fingerprints:
        command = build_searchsploit_command(
            fingerprint["product"],
            fingerprint.get("version"),
            binary=binary,
        )
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            exit_code = 1
            stderr_lines.append(f"{' '.join(command)}: timed out after {timeout_seconds}s")
            continue
        except OSError as exc:
            exit_code = 1
            stderr_lines.append(f"{' '.join(command)}: {exc}")
            continue

        if process.stderr.strip():
            stderr_lines.append(process.stderr.strip())

        if not process.stdout.strip():
            continue

        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError:
            exit_code = 1
            stderr_lines.append(f"{fingerprint['product']}: unparseable searchsploit JSON")
            continue

        for record in _normalize_exploit_records(payload):
            all_records.append(record)
            finding = _finding_payload(record=record, fingerprint=fingerprint)
            dedupe_key = (finding["id"], finding["matched_fingerprint"].lower())
            if dedupe_key in seen_findings:
                continue
            seen_findings.add(dedupe_key)
            finding_payloads.append(finding)
            stdout_lines.append(f"{FINDING_PREFIX} {json.dumps(finding, sort_keys=True)}")

    artifact = EvidenceArtifact(
        name="cve-intel-results.json",
        content_type="application/json",
        data=(
            json.dumps(
                {
                    "fingerprints": fingerprints,
                    "findings": finding_payloads,
                    "raw_records": all_records,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
        kind="cve-intel-results",
    )

    status = "ok" if exit_code == 0 else "completed_with_errors"
    return RunnerExecution(
        tool="cve_intel",
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": status,
            "skipped": False,
            "fingerprint_count": len(fingerprints),
            "finding_count": len(finding_payloads),
            "tool_version": "searchsploit",
            "runner_digest": "workers.cve_intel.runner:v1",
        },
        artifacts=[artifact],
    )
