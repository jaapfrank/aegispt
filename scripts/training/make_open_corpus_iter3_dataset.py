"""Build a separate iter-3 open-corpus dataset for AegisPT SFT.

This deliberately does NOT read or overwrite the earlier
``aegispt_full_coverage_dora_loraplus_unsloth_*`` dataset. It creates a new
dataset family:

    aegispt_open_corpus_iter3_train.jsonl
    aegispt_open_corpus_iter3_eval.jsonl
    aegispt_open_corpus_iter3_test.jsonl

The builder consumes local open corpora already staged under
``~/.aegispt-tools/training/corpus``:

- NVD CVE JSONL produced by ``collect_cve.py``
- ExploitDB ``files_exploits.csv`` metadata

ExploitDB is transformed metadata-only. Raw PoC code and executable recipes are
not read, copied, or generated.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_open_corpus_iter3"
DEFAULT_CORPUS_DIR = DEFAULT_OUT_DIR / "corpus"
DEFAULT_CVE_JSONL = DEFAULT_CORPUS_DIR / "cve_2026.jsonl"
DEFAULT_EXPLOITDB_CSV = DEFAULT_CORPUS_DIR / "files_exploits.csv"
DEFAULT_COUNTS = {"train": 12000, "eval": 1500, "test": 1500}
SEED = 20260604

SYSTEM = (
    "You are AegisPT, an authorized, evidence-first penetration-testing agent. "
    "Return EXACTLY one JSON object with keys: reasoning, tool, args, evidence, "
    "finding, done. Treat external corpus records as intelligence only. Do not "
    "generate exploit code, brute-force steps, persistence, malware, destructive "
    "actions, or target-specific payload recipes. Convert public vulnerability "
    "metadata into safe triage, scope-aware verification planning, evidence "
    "expectations, remediation, and report mapping."
)

DOMAIN_KEYWORDS = {
    "active_directory": ("active directory", "ldap", "kerberos", "domain controller", "ntlm"),
    "api": ("api", "graphql", "oauth", "jwt", "rest endpoint", "swagger"),
    "cloud": ("aws", "azure", "gcp", "s3", "bucket", "iam", "kubernetes", "container"),
    "iot": (
        "camera",
        "router",
        "firmware",
        "edimax",
        "iot",
        "mqtt",
        "thermostat",
        "printer",
        "embedded",
    ),
    "lan": ("smb", "snmp", "rdp", "ssh", "tcp", "udp", "switch", "firewall"),
    "web": (
        "cross site scripting",
        "xss",
        "sql injection",
        "csrf",
        "file upload",
        "cookie",
        "browser",
        "web application",
    ),
}

CWE_STANDARDS = {
    "CWE-79": ["OWASP WSTG-INPV-02", "OWASP ASVS 5.3"],
    "CWE-89": ["OWASP WSTG-INPV-05", "OWASP API8:2023"],
    "CWE-200": ["OWASP WSTG-INFO-05", "OWASP ASVS 14.3"],
    "CWE-285": ["OWASP ASVS 4.1", "NIST SP 800-115"],
    "CWE-287": ["OWASP ASVS 2.1", "NIST SP 800-115"],
    "CWE-352": ["OWASP WSTG-SESS-05", "OWASP ASVS 4.2"],
    "CWE-502": ["OWASP WSTG-INPV-12", "OWASP ASVS 5.5"],
    "CWE-611": ["OWASP WSTG-INPV-07", "OWASP ASVS 5.5"],
    "CWE-918": ["OWASP WSTG-SRVR-10", "OWASP ASVS 5.2"],
}


def clean(value: Any, limit: int = 900) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def severity(value: str | None, fallback: str = "medium") -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return normalized
    if normalized == "none":
        return "info"
    return fallback


def infer_domain(text: str, cwes: list[str] | None = None, platform: str = "") -> str:
    haystack = " ".join([text.lower(), platform.lower(), " ".join(cwes or []).lower()])
    if any(cwe in {"cwe-79", "cwe-89", "cwe-352", "cwe-611", "cwe-918"} for cwe in (cwes or [])):
        return "web"
    for domain, keywords in DOMAIN_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return domain
    return "wan"


def standards_for(cwes: list[str], domain: str) -> list[str]:
    standards: list[str] = []
    for cwe in cwes:
        standards.extend(CWE_STANDARDS.get(cwe.upper(), []))
    if not standards:
        if domain == "cloud":
            standards.extend(["CIS Cloud Foundations", "NIST SP 800-115"])
        elif domain == "api":
            standards.extend(["OWASP API Security Top 10", "OWASP ASVS 4.1"])
        elif domain == "active_directory":
            standards.extend(["MITRE ATT&CK Enterprise", "NIST SP 800-115"])
        else:
            standards.extend(["PTES", "NIST SP 800-115"])
    return sorted(set(standards))


def assistant_json(
    *,
    reasoning: str,
    args: dict[str, Any],
    evidence: dict[str, Any],
    finding: dict[str, Any] | None,
) -> str:
    return json.dumps(
        {
            "args": args,
            "done": True,
            "evidence": evidence,
            "finding": finding,
            "reasoning": reasoning,
            "tool": "corpus_triage",
        },
        sort_keys=True,
    )


def base_row(
    *,
    case_id: str,
    source: str,
    source_id: str,
    domain: str,
    facet: str,
    safety_tags: list[str],
    user_content: str,
    assistant_content: str,
) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "case_id": case_id,
            "domain": domain,
            "facet": facet,
            "safety_tags": safety_tags,
            "source": source,
            "source_id": source_id,
        },
    }


def normalize_cve(record: dict[str, Any], idx: int) -> dict[str, Any] | None:
    cve_id = clean(record.get("id"), 80)
    desc = clean(record.get("desc"), 1100)
    if not cve_id or not desc:
        return None
    cwes = [clean(cwe, 32).upper() for cwe in record.get("cwe", []) if clean(cwe, 32)]
    sev = severity(record.get("severity"))
    domain = infer_domain(desc, cwes)
    standards = standards_for(cwes, domain)
    title = f"CVE triage: {cve_id}"
    user_content = (
        f"Open corpus item from NVD: {cve_id}. Severity={sev.upper()}. "
        f"CWE={', '.join(cwes) if cwes else 'not specified'}. Description: {desc}\n"
        "Convert this into a safe AegisPT training response for authorized "
        "assessment planning. Do not generate exploit steps."
    )
    finding = {
        "confidence": "medium",
        "evidence_ref": f"open-corpus-nvd-{idx:06d}",
        "impact": "Potential exposure depends on affected asset presence, version, reachability, and compensating controls.",
        "remediation": "Confirm affected inventory, apply vendor fixes or mitigations, and verify the control state with non-destructive evidence.",
        "severity": sev,
        "standards": standards,
        "title": title,
    }
    assistant_content = assistant_json(
        reasoning=(
            "Use the CVE record as vulnerability intelligence, not as an exploit "
            "recipe. The safe next step is inventory correlation, scope validation, "
            "non-destructive verification, and remediation mapping."
        ),
        args={
            "allowed_use": "triage_and_remediation",
            "corpus_source": "nvd",
            "id": cve_id,
            "requires_live_authorization": True,
        },
        evidence={
            "cve": cve_id,
            "cwe": cwes,
            "description_summary": desc,
            "evidence_ref": f"open-corpus-nvd-{idx:06d}",
            "severity": sev,
        },
        finding=finding,
    )
    return base_row(
        case_id=f"open-corpus-nvd-{idx:06d}",
        source="nvd_cve_2026",
        source_id=cve_id,
        domain=domain,
        facet="cve_triage",
        safety_tags=["public_metadata", "no_exploit_steps", "inventory_first", "non_destructive"],
        user_content=user_content,
        assistant_content=assistant_content,
    )


def exploitdb_severity(row: dict[str, str]) -> str:
    typ = (row.get("type") or "").lower()
    desc = (row.get("description") or "").lower()
    if "remote" in desc or typ in {"remote", "webapps"}:
        return "high"
    if typ in {"dos", "local"}:
        return "medium"
    return "medium"


def normalize_exploitdb(row: dict[str, str], idx: int) -> dict[str, Any] | None:
    exploit_id = clean(row.get("id"), 80)
    desc = clean(row.get("description"), 500)
    if not exploit_id or not desc:
        return None
    platform = clean(row.get("platform"), 120)
    typ = clean(row.get("type"), 80)
    verified = clean(row.get("verified"), 24) or "unknown"
    tags = clean(row.get("tags"), 180)
    domain = infer_domain(desc, platform=platform)
    sev = exploitdb_severity(row)
    safety_tags = ["public_metadata", "metadata_only", "no_poc_code", "no_execution"]
    if typ.lower() == "dos" or "crash" in desc.lower():
        safety_tags.append("do_not_execute_dos")
    user_content = (
        f"Open corpus item from ExploitDB metadata only. ID={exploit_id}. "
        f"Platform={platform or 'unknown'}. Type={typ or 'unknown'}. "
        f"Verified={verified}. Tags={tags or 'none'}. Description: {desc}\n"
        "Convert this public exploit reference into safe AegisPT training data. "
        "Do not include PoC code, payloads, exploitation commands, or target recipes."
    )
    finding = {
        "confidence": "medium",
        "evidence_ref": f"open-corpus-exploitdb-{idx:06d}",
        "impact": "A public exploit reference raises prioritization, but it is not proof that any assessed asset is vulnerable.",
        "remediation": "Correlate affected product/version in inventory, patch or decommission, and verify safely within written scope.",
        "severity": sev,
        "standards": standards_for([], domain),
        "title": f"Public exploit reference requires inventory correlation: {desc}",
    }
    assistant_content = assistant_json(
        reasoning=(
            "Treat the ExploitDB entry as metadata for prioritization only. Do not "
            "execute or reproduce exploit code. The safe path is scope validation, "
            "asset/version correlation, approval gating, and evidence-backed remediation."
        ),
        args={
            "allowed_use": "metadata_prioritization_only",
            "corpus_source": "exploitdb",
            "id": exploit_id,
            "requires_operator_approval_for_live_verification": True,
        },
        evidence={
            "description": desc,
            "evidence_ref": f"open-corpus-exploitdb-{idx:06d}",
            "platform": platform,
            "type": typ,
            "verified": verified,
        },
        finding=finding,
    )
    return base_row(
        case_id=f"open-corpus-exploitdb-{idx:06d}",
        source="exploitdb_metadata",
        source_id=exploit_id,
        domain=domain,
        facet="public_exploit_metadata_triage",
        safety_tags=safety_tags,
        user_content=user_content,
        assistant_content=assistant_content,
    )


def load_cve_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for idx, line in enumerate(handle):
            if not line.strip():
                continue
            row = normalize_cve(json.loads(line), idx)
            if row is not None:
                rows.append(row)
    return rows


def load_exploitdb_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, record in enumerate(reader):
            row = normalize_exploitdb(record, idx)
            if row is not None:
                rows.append(row)
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    domains = Counter()
    sources = Counter()
    safety_tags = Counter()
    for row in rows:
        metadata = row["metadata"]
        domains[metadata["domain"]] += 1
        sources[metadata["source"]] += 1
        safety_tags.update(metadata["safety_tags"])
        messages = row["messages"]
        if [message["role"] for message in messages] != ["system", "user", "assistant"]:
            raise ValueError(f"invalid role sequence for {metadata['case_id']}")
        parsed = json.loads(messages[-1]["content"])
        if set(parsed) != {"args", "done", "evidence", "finding", "reasoning", "tool"}:
            raise ValueError(f"invalid assistant schema for {metadata['case_id']}")
        if parsed["tool"] != "corpus_triage":
            raise ValueError(f"unexpected tool for {metadata['case_id']}")
        if parsed["finding"] is None or not parsed["finding"].get("evidence_ref"):
            raise ValueError(f"missing finding evidence for {metadata['case_id']}")
    if "no_poc_code" in safety_tags and "metadata_only" not in safety_tags:
        raise ValueError("ExploitDB safety tags incomplete")
    return {
        "domains": dict(sorted(domains.items())),
        "safety_tags": dict(sorted(safety_tags.items())),
        "sources": dict(sorted(sources.items())),
    }


def parse_counts(values: list[str] | None) -> dict[str, int]:
    counts = dict(DEFAULT_COUNTS)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(
    *,
    out_dir: Path,
    prefix: str,
    cve_jsonl: Path,
    exploitdb_csv: Path,
    counts: dict[str, int],
    seed: int,
) -> dict[str, Any]:
    pool = [*load_cve_rows(cve_jsonl), *load_exploitdb_rows(exploitdb_csv)]
    if not pool:
        raise ValueError("No open corpus rows were available")
    rng = random.Random(seed)
    rng.shuffle(pool)
    needed = sum(counts.values())
    if len(pool) < needed:
        raise ValueError(f"Need {needed} rows but only {len(pool)} normalized rows are available")
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "dataset": prefix,
        "does_not_modify": "aegispt_full_coverage_dora_loraplus_unsloth",
        "format": "jsonl with messages and metadata columns",
        "inputs": {
            "cve_jsonl": str(cve_jsonl),
            "exploitdb_csv": str(exploitdb_csv),
        },
        "policy": {
            "exploitdb_mode": "metadata_only",
            "raw_poc_code": "not_read_or_written",
            "runtime_mutation": False,
            "train_eval_test_separated": True,
        },
        "seed": seed,
        "splits": {},
        "total_normalized_pool": len(pool),
    }
    offset = 0
    for split, count in counts.items():
        rows = pool[offset: offset + count]
        offset += count
        stats = validate_rows(rows)
        path = out_dir / f"{prefix}_{split}.jsonl"
        write_jsonl(path, rows)
        manifest["splits"][split] = {"count": count, "path": str(path), "stats": stats}
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--cve-jsonl", type=Path, default=DEFAULT_CVE_JSONL)
    parser.add_argument("--exploitdb-csv", type=Path, default=DEFAULT_EXPLOITDB_CSV)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--count", action="append", help="Override split size, e.g. train=1000")
    args = parser.parse_args()
    manifest = build_dataset(
        out_dir=args.out_dir,
        prefix=args.prefix,
        cve_jsonl=args.cve_jsonl,
        exploitdb_csv=args.exploitdb_csv,
        counts=parse_counts(args.count),
        seed=args.seed,
    )
    print(json.dumps(manifest["splits"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
