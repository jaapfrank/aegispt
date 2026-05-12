"""LAN Intelligence Runner — AI-first pre-assessment for network/host targets.

Equivalent of target-intel but for LAN, host, CIDR, and AD targets.
After nmap runs and discovers services, this runner:

1. Parses nmap output: open ports, service versions, OS hints
2. Sends to Claude Haiku: "What services are running? Which CVEs apply?
   What should we test next?"
3. Returns targeted test plan: ssh-brute, ldap-enum, bloodhound, nuclei
   with specific CVE templates matched to discovered versions

Example:
  nmap finds: 445/SMB, 88/Kerberos, 389/LDAP, 3389/RDP
  → AI: "Active Directory domain controller detected"
  → Plan: bloodhound-collect, ldap-enum, credential-attacks (Kerberoast)

  nmap finds: 22/SSH OpenSSH 7.4, 6379/Redis
  → AI: "Old SSH (weak ciphers) + unauthenticated Redis"
  → Plan: ssh-brute, nuclei CVE-2022-0543 (Redis RCE)
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

LAN_INTEL_ARTIFACT_NAME = "lan-intel.json"

LAN_ANALYSIS_PROMPT = """You are an expert penetration tester analyzing network scan results.

Given nmap/service scan output, produce a targeted attack plan.
Base EVERYTHING on what you actually see — detected ports, versions, services.

Rules:
- Open port 88/Kerberos + 389/LDAP + 445/SMB = Active Directory → bloodhound + kerberoast
- Open port 22 with old OpenSSH version → ssh-brute + nuclei CVE check
- Open port 6379 Redis without auth banner → Redis RCE CVE check
- Open port 445 SMB → netexec smb enum, check for EternalBlue/PrintNightmare
- Open port 5985/5986 WinRM → credential attacks
- Open port 3389 RDP → credential attacks, BlueKeep if Windows 7/2008
- Open port 8080/8443/9200 → web app testing (Elasticsearch, Jenkins, etc.)
- Multiple Windows hosts = domain environment → AD chain

Return ONLY valid JSON, max 6 test_plan entries:
{
  "environment_type": "Active Directory domain | Linux servers | mixed | IoT | cloud | unknown",
  "hosts_summary": ["host:port:service:version for key findings"],
  "cves_to_check": [{"cve": "CVE-YYYY-NNNNN", "service": "affected service", "severity": "critical/high"}],
  "attack_surface": ["specific attack vectors visible from this scan"],
  "test_plan": [
    {"priority": 1, "tool": "aegispt_tool", "reason": "specific reason for THIS scan result", "params": {}}
  ],
  "credentials_needed": true/false
}

AegisPT tools for LAN: nmap, ssh-brute, netexec, bloodhound-collect, ldap-enum,
credential-attacks, impacket-lateral, nuclei, network-segmentation, snmp-enum,
responder, ipv6-discovery, mdns-ssdp"""


def _parse_nmap_output(stdout: str) -> dict[str, Any]:
    """Extract key information from nmap stdout for AI analysis."""
    context: dict[str, Any] = {
        "open_ports": [],
        "hosts": [],
        "os_hints": [],
        "services": [],
    }

    # Extract open ports and services
    port_re = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?')
    for m in port_re.finditer(stdout):
        port, proto, service, version = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        context["open_ports"].append(f"{port}/{proto}")
        context["services"].append({
            "port": int(port),
            "proto": proto,
            "service": service,
            "version": version.strip()[:80],
        })

    # Extract hosts
    host_re = re.compile(r'Nmap scan report for (.+)')
    context["hosts"] = host_re.findall(stdout)[:20]

    # OS hints
    os_re = re.compile(r'OS details?:(.+)')
    context["os_hints"] = [m.group(1).strip() for m in os_re.finditer(stdout)][:5]

    return context


def _call_claude_lan(nmap_context: dict[str, Any], target: str) -> dict[str, Any]:
    """Call Claude Haiku to analyze network scan and generate targeted plan."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return _heuristic_lan_analysis(nmap_context, target)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        services_text = "\n".join(
            f"  {s['port']}/{s['proto']} {s['service']} {s['version']}"
            for s in nmap_context["services"][:20]
        )
        hosts_text = "\n".join(f"  {h}" for h in nmap_context["hosts"][:10])

        user_content = (
            f"Target: {target}\n"
            f"Hosts discovered:\n{hosts_text or '  (single target)'}\n\n"
            f"Open ports and services:\n{services_text or '  none found'}\n\n"
            f"OS hints: {', '.join(nmap_context['os_hints']) or 'unknown'}\n\n"
            "Analyze these results and create a targeted attack plan."
        )

        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=LAN_ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_content}],
            timeout=30.0,
        )

        raw = msg.content[0].text.strip()
        if raw.startswith("{"):
            return json.loads(raw)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group(0)) if m else {}

    except Exception as exc:
        logger.debug("lan-intel Claude call failed: %s", exc)
        return _heuristic_lan_analysis(nmap_context, target)


def _heuristic_lan_analysis(nmap_context: dict[str, Any], target: str) -> dict[str, Any]:
    """Heuristic fallback: identify environment and attack plan without AI."""
    ports = {s["port"] for s in nmap_context["services"]}
    services_by_port = {s["port"]: s for s in nmap_context["services"]}

    test_plan = []
    cves = []
    env_type = "unknown"
    priority = 1

    # Active Directory detection
    is_ad = bool({88, 389, 636} & ports) and (445 in ports or 464 in ports)
    if is_ad:
        env_type = "Active Directory domain"
        test_plan.extend([
            {"priority": priority, "tool": "bloodhound-collect",
             "reason": "Kerberos (88) + LDAP (389) + SMB (445) = AD domain — map attack paths",
             "params": {}},
            {"priority": priority + 1, "tool": "ldap-enum",
             "reason": "Enumerate users, groups, GPOs, SPNs for Kerberoasting targets",
             "params": {}},
            {"priority": priority + 2, "tool": "credential-attacks",
             "reason": "Attempt Kerberoasting and AS-REP roasting on discovered SPNs",
             "params": {"attack_types": ["kerberoast", "asreproast"]}},
        ])
        priority += 3

    # SMB
    if 445 in ports:
        ver = services_by_port.get(445, {}).get("version", "")
        if "Windows" in ver or "Samba" in ver:
            test_plan.append({"priority": priority, "tool": "netexec",
                               "reason": f"SMB 445 open ({ver[:30]}) — enum shares, users, check signing",
                               "params": {"protocol": "smb"}})
            if "Windows 7" in ver or "2008" in ver or "2003" in ver:
                cves.append({"cve": "CVE-2017-0144", "service": "SMB",
                              "severity": "critical", "note": "EternalBlue — unpatched Windows"})
            priority += 1

    # SSH
    if 22 in ports:
        ver = services_by_port.get(22, {}).get("version", "")
        test_plan.append({"priority": priority, "tool": "ssh-brute",
                           "reason": f"SSH open ({ver[:30]}) — test default/weak credentials",
                           "params": {}})
        if any(v in ver for v in ["6.", "7.0", "7.1", "7.2", "7.3", "7.4"]):
            cves.append({"cve": "CVE-2018-15473", "service": "SSH",
                          "severity": "medium", "note": "Username enumeration"})
        priority += 1

    # Redis
    if 6379 in ports:
        cves.append({"cve": "CVE-2022-0543", "service": "Redis", "severity": "critical",
                      "note": "Lua sandbox escape → RCE if unauthenticated"})
        test_plan.append({"priority": priority, "tool": "nuclei",
                           "reason": "Redis 6379 open — check CVE-2022-0543 (sandbox RCE)",
                           "params": {"requested_template_ids": ["CVE-2022-0543", "redis-unauth-access"]}})
        priority += 1

    # WinRM
    if 5985 in ports or 5986 in ports:
        test_plan.append({"priority": priority, "tool": "credential-attacks",
                           "reason": "WinRM open — try default/weak credentials for remote execution",
                           "params": {"protocol": "winrm"}})
        priority += 1

    # SNMP
    if 161 in ports or 162 in ports:
        test_plan.append({"priority": priority, "tool": "snmp-enum",
                           "reason": "SNMP open — enumerate community strings, system info",
                           "params": {}})
        priority += 1

    # Nuclei for CVEs
    if cves:
        cve_ids = [c["cve"] for c in cves]
        test_plan.insert(0, {"priority": 0, "tool": "nuclei",
                              "reason": f"Run targeted CVE templates: {', '.join(cve_ids[:3])}",
                              "params": {"requested_template_ids": cve_ids}})

    return {
        "environment_type": env_type,
        "hosts_summary": [f"{h}" for h in nmap_context["hosts"][:5]],
        "cves_to_check": cves,
        "attack_surface": [f"Port {s['port']}/{s['proto']} {s['service']}" for s in nmap_context["services"][:8]],
        "test_plan": sorted(test_plan, key=lambda t: t["priority"])[:6],
        "credentials_needed": is_ad or (22 in ports) or (5985 in ports),
    }


def _build_lan_next_step_hints(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert LAN analysis into next_step_hints for the assessment loop."""
    hints = []

    # CVEs → nuclei
    cves = analysis.get("cves_to_check", [])
    if cves:
        cve_ids = [c["cve"] for c in cves if c.get("cve")]
        if cve_ids:
            hints.append({
                "tool": "nuclei",
                "reason": f"LAN scan found applicable CVEs: {', '.join(cve_ids[:3])}",
                "params": {"requested_template_ids": cve_ids[:10]},
            })

    # Test plan → hints
    seen: set[str] = {"nuclei"}
    for step in sorted(analysis.get("test_plan", []), key=lambda s: int(s.get("priority", 99))):
        tool = str(step.get("tool", "")).strip()
        if not tool or tool in seen:
            continue
        seen.add(tool)
        hints.append({
            "tool": tool,
            "reason": str(step.get("reason", ""))[:200],
            "params": dict(step.get("params") or {}),
        })
        if len(hints) >= 5:
            break

    return hints


def execute_lan_intel(
    targets: list[str],
    *,
    nmap_stdout: str | None = None,
    timeout_seconds: float = 20.0,
) -> RunnerExecution:
    """LAN/host intelligence analysis — runs AFTER nmap, BEFORE specific attack tools."""
    if not targets:
        raise ValueError("at least one target is required")

    base_target = targets[0].strip()

    # Parse nmap output if provided
    nmap_context: dict[str, Any] = {"open_ports": [], "hosts": [], "os_hints": [], "services": []}
    if nmap_stdout:
        nmap_context = _parse_nmap_output(nmap_stdout)

    # AI analysis
    analysis = _call_claude_lan(nmap_context, base_target)
    if not analysis:
        analysis = _heuristic_lan_analysis(nmap_context, base_target)

    result = {
        "tool": "lan-intel",
        "target": base_target,
        "analysis": analysis,
        "nmap_context": {
            "open_ports": nmap_context["open_ports"][:20],
            "hosts_found": len(nmap_context["hosts"]),
            "services_found": len(nmap_context["services"]),
        },
        "next_step_hints": _build_lan_next_step_hints(analysis),
        "summary": {
            "environment_type": analysis.get("environment_type", "unknown"),
            "cve_count": len(analysis.get("cves_to_check", [])),
            "test_plan_steps": len(analysis.get("test_plan", [])),
            "credentials_needed": analysis.get("credentials_needed", False),
        },
    }

    return RunnerExecution(
        tool="lan-intel",
        exit_code=0,
        stdout=json.dumps(result),
        stderr="",
        metadata={"status": "ok", "tool_version": "lan-intel:v1"},
        artifacts=[EvidenceArtifact(
            name=LAN_INTEL_ARTIFACT_NAME,
            content_type="application/json",
            data=(json.dumps(result, sort_keys=True) + "\n").encode("utf-8"),
            kind="runner-results",
        )],
    )
