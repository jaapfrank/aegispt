from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import AssessmentChain, Finding, Run, Task

ATTACK_KILL_CHAIN_STAGES: tuple[dict[str, Any], ...] = (
    {
        "id": "reconnaissance",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "label": "Recon",
        "techniques": (("T1595", "Active Scanning"), ("T1592", "Gather Victim Host Information")),
    },
    {
        "id": "initial_access",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "label": "Initial Access",
        "techniques": (("T1190", "Exploit Public-Facing Application"),),
    },
    {
        "id": "execution",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "label": "Execution",
        "techniques": (("T1059", "Command and Scripting Interpreter"),),
    },
    {
        "id": "persistence",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "label": "Persistence",
        "techniques": (("T1053", "Scheduled Task/Job"),),
    },
    {
        "id": "privilege_escalation",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "label": "Privilege Escalation",
        "techniques": (("T1068", "Exploitation for Privilege Escalation"),),
    },
    {
        "id": "defense_evasion",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "label": "Defense Evasion",
        "techniques": (("T1562", "Impair Defenses"),),
    },
    {
        "id": "credential_access",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "label": "Credential Access",
        "techniques": (("T1110", "Brute Force"), ("T1552", "Unsecured Credentials")),
    },
    {
        "id": "discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "label": "Discovery",
        "techniques": (("T1046", "Network Service Discovery"),),
    },
    {
        "id": "lateral_movement",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "label": "Lateral Movement",
        "techniques": (("T1021", "Remote Services"),),
    },
    {
        "id": "collection",
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "label": "Collection",
        "techniques": (("T1005", "Data from Local System"),),
    },
    {
        "id": "command_and_control",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "label": "Command & Control",
        "techniques": (("T1105", "Ingress Tool Transfer"),),
    },
    {
        "id": "exfiltration",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "label": "Exfiltration",
        "techniques": (("T1041", "Exfiltration Over C2 Channel"),),
    },
    {
        "id": "impact",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "label": "Impact",
        "techniques": (("T1499", "Endpoint Denial of Service"),),
    },
)

FINDING_ATTACK_MAP: tuple[dict[str, Any], ...] = (
    {
        "stage_id": "lateral_movement",
        "technique_id": "T1021",
        "match_label": "lateral movement evidence",
        "keywords": (
            "lateral movement",
            "psexec",
            "wmiexec",
            "smbexec",
            "remote services",
            "dcsync",
            "domain admin path",
        ),
    },
    {
        "stage_id": "privilege_escalation",
        "technique_id": "T1068",
        "match_label": "privilege escalation evidence",
        "keywords": (
            "privilege escalation",
            "priv-esc",
            "suid",
            "sgid",
            "sudo",
            "writable cron",
            "path hijacking",
            "root escalation",
        ),
    },
    {
        "stage_id": "credential_access",
        "technique_id": "T1110",
        "match_label": "credential access evidence",
        "keywords": (
            "credential",
            "password",
            "default password",
            "weak password",
            "password spray",
            "kerberoast",
            "as-rep",
            "asrep",
            "ntlm",
            "hash",
            "token replay",
            "session token",
            "jwt token",
        ),
    },
    {
        "stage_id": "execution",
        "technique_id": "T1059",
        "match_label": "execution evidence",
        "keywords": (
            "remote code execution",
            "code execution",
            "command injection",
            "rce",
            "ssti",
            "server-side template injection",
            "shell command",
            "payload executed",
            "deserialization execution",
        ),
    },
    {
        "stage_id": "persistence",
        "technique_id": "T1053",
        "match_label": "persistence evidence",
        "keywords": ("persistence", "startup", "scheduled task", "cron job", "service installed"),
    },
    {
        "stage_id": "defense_evasion",
        "technique_id": "T1562",
        "match_label": "defense evasion evidence",
        "keywords": (
            "defense evasion",
            "logging disabled",
            "monitoring bypass",
            "audit disabled",
            "log injection",
            "security tool disabled",
        ),
    },
    {
        "stage_id": "collection",
        "technique_id": "T1005",
        "match_label": "collection evidence",
        "keywords": (
            "sensitive file",
            "data exposure",
            "backup exposed",
            "database dump",
            "directory listing",
            "source code disclosure",
            "local file inclusion",
        ),
    },
    {
        "stage_id": "exfiltration",
        "technique_id": "T1041",
        "match_label": "exfiltration evidence",
        "keywords": ("exfiltration", "data exfil", "downloadable dump", "exported data"),
    },
    {
        "stage_id": "command_and_control",
        "technique_id": "T1105",
        "match_label": "command and control evidence",
        "keywords": ("command and control", "c2", "callback", "reverse shell", "ingress tool transfer"),
    },
    {
        "stage_id": "impact",
        "technique_id": "T1499",
        "match_label": "impact evidence",
        "keywords": ("impact", "denial of service", "dos", "destructive", "data destruction"),
    },
    {
        "stage_id": "initial_access",
        "technique_id": "T1190",
        "match_label": "initial access vulnerability evidence",
        "keywords": (
            "service vulnerability",
            "vulnerable service",
            "cve-",
            "exploit public-facing",
            "public-facing application",
            "xss",
            "cross-site scripting",
            "sql injection",
            "sqli",
            "idor",
            "broken access control",
            "ssrf",
            "xxe",
            "deserialization",
            "request smuggling",
            "oauth",
            "oidc",
            "jwt vulnerability",
            "file upload",
            "admin console exposed",
        ),
    },
    {
        "stage_id": "reconnaissance",
        "technique_id": "T1595",
        "match_label": "reconnaissance evidence",
        "keywords": (
            "nmap",
            "open port",
            "banner",
            "fingerprint",
            "host discovered",
            "service exposed",
            "http header",
            "tls service",
            "surface mapped",
        ),
    },
    {
        "stage_id": "discovery",
        "technique_id": "T1046",
        "match_label": "service discovery evidence",
        "keywords": ("network service discovery", "service discovery", "service enumeration"),
    },
)

TOOL_ATTACK_MAP: tuple[dict[str, Any], ...] = (
    {
        "stage_id": "lateral_movement",
        "technique_id": "T1021",
        "keywords": ("impacket", "netexec", "crackmapexec", "psexec", "wmiexec", "lateral"),
    },
    {
        "stage_id": "privilege_escalation",
        "technique_id": "T1068",
        "keywords": ("priv-esc", "privilege", "linux-privesc", "suid", "sudo"),
    },
    {
        "stage_id": "credential_access",
        "technique_id": "T1110",
        "keywords": (
            "credential",
            "hydra",
            "kerberoast",
            "asrep",
            "hashcat",
            "responder",
            "password-spray",
        ),
    },
    {
        "stage_id": "execution",
        "technique_id": "T1059",
        "keywords": ("metasploit", "ssti", "rce", "command-injection", "exploit"),
    },
    {
        "stage_id": "initial_access",
        "technique_id": "T1190",
        "keywords": (
            "zap",
            "burp",
            "nuclei",
            "sqlmap",
            "xss",
            "idor",
            "jwt",
            "oauth",
            "graphql",
            "ssrf",
            "xxe",
            "headers-security",
            "logging-probe",
            "playwright-web",
            "biz-logic",
        ),
    },
    {
        "stage_id": "collection",
        "technique_id": "T1005",
        "keywords": ("tcpdump", "packet-capture", "capture", "sensitive-data"),
    },
    {
        "stage_id": "discovery",
        "technique_id": "T1046",
        "keywords": ("bloodhound", "ldap", "ad-enumeration", "service-enumeration"),
    },
    {
        "stage_id": "reconnaissance",
        "technique_id": "T1595",
        "keywords": ("nmap", "httpx", "subfinder", "dns", "easm", "discovery", "fingerprint"),
    },
)

TESTED_TASK_STATUSES = {"completed", "completed_with_errors", "succeeded", "failed"}
ACTIVE_TASK_STATUSES = {"queued", "requested", "running", "active", "pending", "in_progress"}
FALSE_POSITIVE_STATUSES = {"false_positive"}
TESTED_PHASE_STATUSES = {"completed", "completed_with_gaps"}
ACTIVE_PHASE_STATUSES = {"active", "running", "pending_approval"}


def map_finding_to_attack_stage(finding: Finding) -> dict[str, str] | None:
    text = _text_blob(
        finding.title,
        finding.summary,
        finding.evidence_ref,
        finding.finding_origin,
        finding.target_id,
        finding.methodology_tags,
        finding.ptes_phase,
        finding.nist_phase,
        finding.wstg_id,
        finding.asvs_reference,
        finding.control_family,
    )
    return _match_mapping(text, FINDING_ATTACK_MAP)


def build_engagement_kill_chain_progress(
    session: Session,
    engagement_id: UUID,
) -> dict[str, Any]:
    runs = list(
        session.scalars(
            select(Run)
            .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
            .options(
                selectinload(Run.findings),
                selectinload(Run.tasks),
                selectinload(Run.assessment_chain),
            )
            .order_by(Run.created_at.asc(), Run.id.asc())
        )
    )
    chains = list(
        session.scalars(
            select(AssessmentChain)
            .where(AssessmentChain.engagement_id == engagement_id)
            .order_by(AssessmentChain.created_at.asc(), AssessmentChain.id.asc())
        )
    )
    progress = _empty_progress(engagement_id)
    active_stage_indices: set[int] = set()

    for run in runs:
        for finding in sorted(run.findings or [], key=lambda item: (item.created_at, item.id)):
            if StringStatus(finding.status).normalized in FALSE_POSITIVE_STATUSES:
                continue
            mapping = map_finding_to_attack_stage(finding)
            if mapping is None:
                continue
            _record_source(
                progress,
                mapping=mapping,
                source_kind="finding",
                source={
                    "source_type": "finding",
                    "id": str(finding.id),
                    "run_id": str(finding.run_id) if finding.run_id else None,
                    "title": finding.title,
                    "target_id": finding.target_id,
                    "severity": finding.severity,
                    "status": finding.status,
                    "evidence_ref": finding.evidence_ref,
                    "matched_on": mapping["match_label"],
                },
            )

        for task in sorted(run.tasks or [], key=lambda item: (item.created_at, item.id)):
            mapping = _map_task_to_attack_stage(task)
            if mapping is None:
                continue
            status = StringStatus(task.status).normalized
            if status in TESTED_TASK_STATUSES:
                _record_source(
                    progress,
                    mapping=mapping,
                    source_kind="task",
                    source={
                        "source_type": "task",
                        "id": str(task.id),
                        "run_id": str(task.run_id) if task.run_id else None,
                        "title": task.tool,
                        "target_id": task.target_id,
                        "status": task.status,
                        "matched_on": "tool execution",
                    },
                )
            elif status in ACTIVE_TASK_STATUSES:
                active_stage_indices.add(_stage_index(mapping["stage_id"]))

    for chain in chains:
        for phase_index, phase in enumerate(_chain_phases(chain)):
            mapping = _map_phase_to_attack_stage(phase)
            if mapping is None:
                continue
            status = StringStatus(phase.get("status")).normalized
            if status in TESTED_PHASE_STATUSES:
                _record_source(
                    progress,
                    mapping=mapping,
                    source_kind="phase",
                    source={
                        "source_type": "assessment_phase",
                        "id": f"{chain.id}:{phase.get('key') or phase_index}",
                        "run_id": str(phase.get("run_id") or chain.last_completed_run_id or ""),
                        "title": str(phase.get("label") or phase.get("key") or "Assessment phase"),
                        "target_id": str(chain.engagement_id),
                        "status": str(phase.get("status") or "unknown"),
                        "matched_on": "assessment phase completion",
                    },
                )
            elif status in ACTIVE_PHASE_STATUSES:
                active_stage_indices.add(_stage_index(mapping["stage_id"]))

    return _finalize_progress(progress, active_stage_indices)


def _empty_progress(engagement_id: UUID) -> dict[str, Any]:
    stage_states: dict[str, dict[str, Any]] = {}
    for order, stage in enumerate(ATTACK_KILL_CHAIN_STAGES):
        techniques = {
            technique_id: {
                "technique_id": technique_id,
                "name": name,
                "finding_sources": [],
                "task_sources": [],
                "phase_sources": [],
            }
            for technique_id, name in stage["techniques"]
        }
        stage_states[stage["id"]] = {
            "definition": stage,
            "order": order,
            "finding_sources": [],
            "task_sources": [],
            "phase_sources": [],
            "techniques": techniques,
        }
    return {
        "engagement_id": engagement_id,
        "stage_states": stage_states,
        "source_summary": {
            "finding_count": 0,
            "task_count": 0,
            "phase_count": 0,
            "mapping_source": "static finding/task/assessment-chain ATT&CK map",
        },
    }


def _finalize_progress(progress: dict[str, Any], active_stage_indices: set[int]) -> dict[str, Any]:
    stage_states = progress["stage_states"]
    reached_indices: list[int] = []
    stages: list[dict[str, Any]] = []
    matrix: list[dict[str, Any]] = []
    confirmed_count = 0
    tested_count = 0

    for state in stage_states.values():
        if state["finding_sources"] or state["task_sources"] or state["phase_sources"]:
            reached_indices.append(state["order"])
        if state["finding_sources"]:
            confirmed_count += 1
        elif state["task_sources"] or state["phase_sources"]:
            tested_count += 1

    highest_index = max(reached_indices, default=-1)
    total = len(ATTACK_KILL_CHAIN_STAGES)
    current_index = _current_stage_index(highest_index, active_stage_indices, total)
    completed_count = max(0, highest_index + 1)
    progress_percentage = round((completed_count / total) * 100) if total else 0

    for stage_id, state in stage_states.items():
        definition = state["definition"]
        status = _coverage_status(state)
        display_state = _display_state(state["order"], highest_index, current_index)
        techniques = _technique_payloads(state["techniques"])
        finding_count = len(state["finding_sources"])
        task_count = len(state["task_sources"])
        phase_count = len(state["phase_sources"])
        evidence_count = finding_count + task_count + phase_count
        summary = _stage_summary(
            label=definition["label"],
            status=status,
            finding_count=finding_count,
            task_count=task_count,
            phase_count=phase_count,
        )
        stage_payload = {
            "id": stage_id,
            "order": state["order"],
            "tactic_id": definition["tactic_id"],
            "tactic_name": definition["tactic_name"],
            "label": definition["label"],
            "status": status,
            "display_state": display_state,
            "progress_weight": 1,
            "finding_count": finding_count,
            "task_count": task_count,
            "phase_count": phase_count,
            "evidence_count": evidence_count,
            "summary": summary,
            "techniques": techniques,
        }
        stages.append(stage_payload)
        matrix.append(
            {
                "stage_id": stage_id,
                "tactic_id": definition["tactic_id"],
                "tactic_name": definition["tactic_name"],
                "status": status,
                "display_state": display_state,
                "techniques": techniques,
            }
        )

    highest_stage = stages[highest_index] if highest_index >= 0 else None
    current_stage = stages[current_index] if current_index is not None else None
    return {
        "engagement_id": progress["engagement_id"],
        "progress_percentage": progress_percentage,
        "completed_stage_count": completed_count,
        "total_stage_count": total,
        "confirmed_stage_count": confirmed_count,
        "tested_stage_count": tested_count,
        "current_stage_id": current_stage["id"] if current_stage else None,
        "current_stage_label": current_stage["label"] if current_stage else None,
        "highest_reached_stage_id": highest_stage["id"] if highest_stage else None,
        "highest_reached_stage_label": highest_stage["label"] if highest_stage else None,
        "stages": stages,
        "matrix": matrix,
        "source_summary": progress["source_summary"],
        "boundary": {
            "advisory_only": True,
            "mutates_findings": False,
            "dispatches_tasks": False,
            "changes_approval_or_runtime_binding": False,
            "mapping": "static deterministic ATT&CK tactic mapping",
        },
    }


def _record_source(
    progress: dict[str, Any],
    *,
    mapping: dict[str, str],
    source_kind: str,
    source: dict[str, Any],
) -> None:
    stage_state = progress["stage_states"].get(mapping["stage_id"])
    if stage_state is None:
        return
    key = f"{source_kind}_sources"
    stage_state[key].append(source)
    progress["source_summary"][f"{source_kind}_count"] += 1
    technique_id = mapping.get("technique_id") or _default_technique_id(stage_state)
    technique = stage_state["techniques"].get(technique_id)
    if technique is None:
        technique = {
            "technique_id": technique_id,
            "name": mapping.get("technique_name") or technique_id,
            "finding_sources": [],
            "task_sources": [],
            "phase_sources": [],
        }
        stage_state["techniques"][technique_id] = technique
    technique[key].append(source)


def _technique_payloads(techniques: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    payloads = []
    for technique in techniques.values():
        finding_sources = list(technique["finding_sources"])
        task_sources = list(technique["task_sources"])
        phase_sources = list(technique["phase_sources"])
        sources = finding_sources + task_sources + phase_sources
        status = "confirmed" if finding_sources else "tested" if task_sources or phase_sources else "untested"
        payloads.append(
            {
                "technique_id": technique["technique_id"],
                "name": technique["name"],
                "status": status,
                "source_count": len(sources),
                "sources": sources[:8],
            }
        )
    return sorted(payloads, key=lambda item: item["technique_id"])


def _coverage_status(stage_state: dict[str, Any]) -> str:
    if stage_state["finding_sources"]:
        return "confirmed"
    if stage_state["task_sources"] or stage_state["phase_sources"]:
        return "tested"
    return "untested"


def _display_state(index: int, highest_index: int, current_index: int | None) -> str:
    if index <= highest_index:
        return "complete"
    if current_index is not None and index == current_index:
        return "current"
    return "future"


def _current_stage_index(
    highest_index: int,
    active_stage_indices: set[int],
    total: int,
) -> int | None:
    candidates = sorted(index for index in active_stage_indices if 0 <= index < total)
    for index in candidates:
        if index > highest_index:
            return index
    if highest_index < total - 1:
        return highest_index + 1
    return None


def _stage_summary(
    *,
    label: str,
    status: str,
    finding_count: int,
    task_count: int,
    phase_count: int,
) -> str:
    if status == "confirmed":
        return f"{label} has {finding_count} mapped finding source(s)."
    if status == "tested":
        tested_count = task_count + phase_count
        return f"{label} has {tested_count} completed task or phase source(s), with no confirmed finding."
    return f"{label} has no mapped finding, completed task, or completed phase source yet."


def _map_task_to_attack_stage(task: Task) -> dict[str, str] | None:
    return _match_mapping(
        _text_blob(task.tool, task.target_id, task.params_json),
        TOOL_ATTACK_MAP,
    )


def _map_phase_to_attack_stage(phase: dict[str, Any]) -> dict[str, str] | None:
    steps = phase.get("steps")
    runner_text = ""
    if isinstance(steps, list):
        runner_text = " ".join(_text_blob(step) for step in steps if isinstance(step, dict))
    return _match_mapping(
        _text_blob(
            phase.get("key"),
            phase.get("label"),
            phase.get("tier"),
            phase.get("profile_name"),
            phase.get("tool"),
            phase.get("safe_next_action"),
            runner_text,
        ),
        TOOL_ATTACK_MAP,
    )


def _chain_phases(chain: AssessmentChain) -> list[dict[str, Any]]:
    phases = chain.phases_json if isinstance(chain.phases_json, list) else []
    return [phase for phase in phases if isinstance(phase, dict)]


def _match_mapping(text: str, mappings: tuple[dict[str, Any], ...]) -> dict[str, str] | None:
    for mapping in mappings:
        if any(keyword in text for keyword in mapping["keywords"]):
            return {
                "stage_id": mapping["stage_id"],
                "technique_id": mapping["technique_id"],
                "match_label": mapping.get("match_label") or "mapped source",
            }
    return None


def _text_blob(*values: Any) -> str:
    parts: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, dict):
            parts.extend(_text_blob(key, nested) for key, nested in value.items())
            continue
        if isinstance(value, (list, tuple, set)):
            parts.extend(_text_blob(item) for item in value)
            continue
        parts.append(str(value))
    return " ".join(parts).replace("_", "-").lower()


def _stage_index(stage_id: str) -> int:
    for index, stage in enumerate(ATTACK_KILL_CHAIN_STAGES):
        if stage["id"] == stage_id:
            return index
    return -1


def _default_technique_id(stage_state: dict[str, Any]) -> str:
    techniques = list(stage_state["techniques"])
    return techniques[0] if techniques else "unknown"


class StringStatus:
    def __init__(self, value: object) -> None:
        self.normalized = str(value or "").strip().lower().replace(" ", "_")
