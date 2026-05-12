"""Target Intelligence Runner — AI-first pre-assessment analysis.

This is the FIRST runner in every ai_loop assessment. Before any scanning tool
runs, this runner:

1. Fetches the target (HTTP headers, HTML, robots.txt, sitemap, common paths)
2. Sends everything to Claude Sonnet for analysis
3. Claude identifies: technology stack, attack surface, specific CVEs, ranked test plan
4. Returns a structured scan plan that the AI loop uses to drive tool selection

This replaces blind tool execution with targeted, intelligence-driven testing.
Example: azerty.nl → Magento detected → CosmicSting CVE-2024-34102 prioritized
instead of generic XSS/SQLi tests.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

logger = logging.getLogger(__name__)

TARGET_INTEL_ARTIFACT_NAME = "target-intel.json"

ANALYSIS_PROMPT = """You are an expert penetration tester. You just fetched a web target.
Analyze ONLY what you can see in the HTTP response and produce a targeted test plan.

Your job:
1. IDENTIFY: What technology is running? (server headers, HTML patterns, JS frameworks, CMS markers, API styles)
2. MATCH CVEs: What known vulnerabilities apply to the DETECTED version/technology?
3. PLAN: Which tools should run, in what order, and WHY for THIS specific target?

Rules:
- Base EVERYTHING on what you actually see in the response — not assumptions
- If you see WordPress markers: prioritize wp-specific CVE checks
- If you see Magento: prioritize Magento RCE CVEs (CosmicSting, etc.)
- If you see Angular/React: prioritize REST API enumeration and JWT testing
- If you see a login form: auth-flow and session-security are high priority
- If you see GraphQL: graphql-probe first
- If you see Java/.NET/PHP in headers: check known framework CVEs via nuclei
- If response reveals version numbers: immediately look up relevant CVEs
- Sensitive data in JS (API keys, tokens, internal URLs): report and prioritize

Return ONLY valid JSON, max 8 test_plan entries:
{
  "site_type": "concise description of what this application is and does",
  "technology_stack": ["technology:version if detectable"],
  "cves_to_check": [{"cve": "CVE-YYYY-NNNNN", "reason": "why this version/tech is affected", "severity": "critical/high/medium"}],
  "attack_surface": ["specific vectors visible in this response"],
  "test_plan": [{"priority": 1, "tool": "aegispt_tool_name", "reason": "why for THIS target specifically", "params": {}, "expected_finding": "what to look for"}],
  "sensitive_data_found": ["any keys/tokens/credentials visible in the response"]
}

AegisPT tools available: httpx, nmap, xss-extended, xss-proof, smart-web-probe,
ai-pentest-agent, zap, nikto, content-discovery, nuclei, sqlmap, ssrf-probe,
ssti-probe, auth-flow, session-security, idor-bac, headers-security, burp,
graphql-probe, jwt-probe, waf-detect"""


def _probe_target(base_url: str, timeout: float) -> dict[str, Any]:
    """Fetch target and discover technology fingerprints."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    context: dict[str, Any] = {
        "main_page": None,
        "headers": {},
        "extra_paths": {},
    }

    probe_paths = [
        "", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/wp-login.php", "/wp-json/wp/v2/", "/admin", "/administrator",
        "/magento_version", "/rest/V1/store/storeConfigs",
        "/graphql", "/api/", "/.env", "/README.md",
    ]

    with httpx_client.Client(
        follow_redirects=True,
        timeout=timeout,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Security Assessment; contact security@aegispt.io)"},
    ) as client:
        # Main page
        try:
            r = client.get(base_url)
            context["main_page"] = r.text[:6000]
            context["headers"] = {
                k: v for k, v in r.headers.items()
                if k.lower() in [
                    "server", "x-powered-by", "content-type", "x-generator",
                    "x-wp-total", "x-drupal-cache", "x-magento-vary",
                    "x-magento-tags", "via", "cf-ray", "x-shopify-stage",
                ]
            }
            context["status"] = r.status_code
            context["final_url"] = str(r.url)
        except httpx_client.HTTPError as exc:
            context["error"] = str(exc)

        # Probe additional paths
        for path in probe_paths[1:]:
            try:
                resp = client.get(f"{origin}{path}")
                if resp.status_code < 400 and resp.text.strip():
                    context["extra_paths"][path] = {
                        "status": resp.status_code,
                        "content": resp.text[:500],
                        "content_type": resp.headers.get("content-type", ""),
                    }
            except httpx_client.HTTPError:
                continue

    return context


def _call_claude(context: dict[str, Any], target_url: str) -> dict[str, Any]:
    """Call Claude Sonnet to analyze the target and generate a test plan."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return {}

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        extra_paths_summary = {
            k: f"HTTP {v['status']}: {v['content'][:100]}"
            for k, v in context.get('extra_paths', {}).items()
        }

        user_content = (
            f"Analyze for pen testing. Target: {target_url}\n"
            f"HTTP {context.get('status','?')} | Final: {context.get('final_url', target_url)}\n\n"
            f"Headers: {json.dumps(context.get('headers', {}), indent=2)}\n\n"
            f"HTML (first 2000 chars):\n{(context.get('main_page') or '')[:2000]}\n\n"
            f"Endpoints found: {json.dumps(extra_paths_summary, indent=2)[:1500]}\n\n"
            "Identify tech stack and return targeted test plan JSON."
        )

        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",  # Haiku: faster + cheaper for initial analysis
            max_tokens=2048,
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_content}],
            timeout=60.0,
        )

        raw = msg.content[0].text.strip()
        if raw.startswith("{"):
            return json.loads(raw)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group(0)) if m else {}

    except Exception as exc:
        logger.error("target-intel Claude call failed: %s", exc)
        return {}


def _fallback_analysis(context: dict[str, Any]) -> dict[str, Any]:
    """Heuristic fallback when no API key is available."""
    html = context.get("main_page", "").lower()
    headers = {k.lower(): v.lower() for k, v in context.get("headers", {}).items()}
    extra = context.get("extra_paths", {})

    tech = []
    test_plan = []
    priority = 1

    # Technology detection
    if "wp-login.php" in extra or "wp-json" in extra or "wordpress" in html:
        tech.append("WordPress")
        test_plan.append({"priority": priority, "tool": "nuclei",
                          "reason": "WordPress detected — scan for WP-specific CVEs",
                          "params": {"template_ids": ["wordpress-*"]}, "expected_finding": "WP CVE"})
        priority += 1

    if "magento" in html or "x-magento" in str(headers) or "/magento_version" in extra:
        tech.append("Magento/Adobe Commerce")
        test_plan.append({"priority": priority, "tool": "nuclei",
                          "reason": "Magento detected — check CosmicSting CVE-2024-34102 + CVE-2022-24086",
                          "params": {}, "expected_finding": "Magento RCE CVE"})
        priority += 1

    if "drupal" in html or "x-drupal" in str(headers):
        tech.append("Drupal")
        test_plan.append({"priority": priority, "tool": "nuclei",
                          "reason": "Drupal detected — check Drupalgeddon CVEs",
                          "params": {}, "expected_finding": "Drupal RCE"})
        priority += 1

    if "graphql" in extra or "graphql" in html:
        tech.append("GraphQL API")
        test_plan.append({"priority": priority, "tool": "graphql-probe",
                          "reason": "GraphQL endpoint found — test for introspection and injection",
                          "params": {}, "expected_finding": "GraphQL data exposure"})
        priority += 1

    # Always add
    test_plan.extend([
        {"priority": priority, "tool": "xss-extended", "reason": "Standard XSS check", "params": {}, "expected_finding": "Reflected XSS"},
        {"priority": priority+1, "tool": "headers-security", "reason": "Security header audit", "params": {}, "expected_finding": "Missing headers"},
        {"priority": priority+2, "tool": "smart-web-probe", "reason": "AI-driven vulnerability discovery", "params": {}, "expected_finding": "Application-specific vulns"},
    ])

    return {
        "site_type": "Unknown web application",
        "technology_stack": tech or ["Unknown"],
        "cves_to_check": [],
        "attack_surface": ["Web application — generic testing applied"],
        "test_plan": test_plan,
        "sensitive_data_found": [],
    }


def _build_next_step_hints(analysis: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    """Convert target-intel analysis into next_step_hints for the assessment loop.

    CVEs found → nuclei with those specific template IDs (not blind scan).
    Test plan → ordered tool queue with context-specific params.
    This is what makes target-intel drive the loop, not just annotate it.
    """
    hints: list[dict[str, Any]] = []

    # 1. CVEs → nuclei with specific templates
    cves = [c for c in analysis.get("cves_to_check", []) if isinstance(c, dict)]
    if cves:
        cve_ids = [c["cve"] for c in cves if c.get("cve")]
        if cve_ids:
            hints.append({
                "tool": "nuclei",
                "reason": (
                    f"Target-intel identified {len(cve_ids)} applicable CVEs: {', '.join(cve_ids[:3])}. "
                    "Run targeted nuclei templates for these specific vulnerabilities."
                ),
                "params": {
                    "requested_template_ids": cve_ids[:10],
                    "cve_context": [{"cve": c["cve"], "reason": c.get("reason",""), "severity": c.get("severity","")} for c in cves[:5]],
                    "priority": 1,
                },
            })

    # 2. Test plan steps → ordered tool hints
    seen_tools: set[str] = {"nuclei"}  # nuclei already added above
    for step in sorted(analysis.get("test_plan", []), key=lambda s: int(s.get("priority", 99))):
        tool = str(step.get("tool", "")).strip()
        if not tool or tool in seen_tools:
            continue
        seen_tools.add(tool)
        hints.append({
            "tool": tool,
            "reason": str(step.get("reason", f"Target-intel planned: {tool}"))[:200],
            "params": dict(step.get("params") or {}),
        })
        if len(hints) >= 6:  # cap total hints to avoid overwhelming the queue
            break

    return hints


def execute_target_intel(
    targets: list[str],
    *,
    timeout_seconds: float = 20.0,
) -> RunnerExecution:
    """Run pre-assessment target intelligence analysis."""
    if not targets:
        raise ValueError("at least one target is required")

    base_target = normalize_http_target(targets[0])

    # Step 1: probe the target
    context = _probe_target(base_target, min(timeout_seconds, 15.0))

    # Step 2: Claude analysis (or fallback)
    analysis = _call_claude(context, base_target)
    if not analysis:
        logger.info("target-intel: using heuristic fallback (no API key or Claude error)")
        analysis = _fallback_analysis(context)

    # Step 3: format result
    result = {
        "tool": "target-intel",
        "target": base_target,
        "analysis": analysis,
        "probe_context": {
            "headers": context.get("headers", {}),
            "status": context.get("status"),
            "extra_paths_found": list(context.get("extra_paths", {}).keys()),
        },
        "summary": {
            "site_type": analysis.get("site_type", "Unknown"),
            "technology_count": len(analysis.get("technology_stack", [])),
            "cve_count": len(analysis.get("cves_to_check", [])),
            "test_plan_steps": len(analysis.get("test_plan", [])),
            "sensitive_data_found": bool(analysis.get("sensitive_data_found")),
        },
        # next_step_hints: drive the assessment loop directly from target-intel output.
        # CVEs → nuclei with specific template IDs.
        # Test plan steps → other tools in priority order.
        "next_step_hints": _build_next_step_hints(analysis, base_target),
    }

    return RunnerExecution(
        tool="target-intel",
        exit_code=0,
        stdout=json.dumps(result),
        stderr="",
        metadata={"status": "ok", "tool_version": "target-intel:v1"},
        artifacts=[EvidenceArtifact(
            name=TARGET_INTEL_ARTIFACT_NAME,
            content_type="application/json",
            data=(json.dumps(result, sort_keys=True) + "\n").encode("utf-8"),
            kind="runner-results",
        )],
    )
