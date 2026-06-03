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
  "sensitive_data_found": ["any keys/tokens/credentials visible in the response"],
  "observed_paths": [
    {"url": "/path/seen-in-response", "source": "html-link|sitemap|robots|script-src|form-action|response-header",
     "hypothesis": "what this path likely does based on context", "confidence": 0.0-1.0}
  ],
  "attack_candidates": [
    {"path": "/path", "vuln_class": "info-leak|file-upload|register-action|stored-xss|auth-bypass|mass-assignment|other",
     "evidence_basis": "concrete reason from the response why you flagged this — quote or paraphrase the evidence",
     "suggested_runner_or_primitive": "info-disclosure-probe|file-upload-probe|stored-xss-probe|param-pollution-probe|cookie-tamper-probe|exec-plan|null"}
  ]
}

CRITICAL RULES for observed_paths and attack_candidates:
- ONLY include paths you actually SAW in the response (HTML hrefs, sitemap entries, robots.txt rules, form actions, script src, header values, JS-embedded URLs). Do NOT invent paths.
- Do NOT seed app-specific or stack-conventional paths you "expect to exist" — only what you observed.
- evidence_basis MUST quote or paraphrase the actual response text that triggered your hypothesis.
- vuln_class MUST come from the enum above (or "other"); generic strings like "potential issue" are useless to downstream probes.
- If you have no observed_paths or attack_candidates, emit empty arrays — do not invent.

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


# Common application web ports to probe BEFORE concluding "port unknown -> full
# nmap". Operator (2026-06-03): nmap is NOT useless — other open ports can host
# vulns too — but it must run AFTER the standard web recon, not block it. So when
# the default-port (:80) probe fails on a port-LESS target, cheaply sweep these
# common ports; if one serves, proceed with web recon THERE and schedule nmap as a
# LOW-priority follow-up (other-port discovery) instead of a blocking priority-1 scan.
_COMMON_WEB_PORTS = [5000, 8080, 8000, 3000, 8888, 8443, 9000, 5001, 4000, 8081]


def _sweep_common_web_ports(base_url: str, timeout: float) -> str | None:
    """Return the first ``http(s)://host:port`` that answers (<500), else None.
    Bounded + fast (short per-port timeout) so it never replaces nmap's job for a
    truly-unknown port — it only catches the common app ports the harness already
    serves on (e.g. :5000) that a bare :80 probe misses."""
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host or parsed.port is not None:
        return None
    scheme = parsed.scheme or "http"
    per_port = min(max(timeout, 1.0), 2.0)
    try:
        with httpx_client.Client(
            follow_redirects=True, timeout=per_port, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Security Assessment; contact security@aegispt.io)"},
        ) as client:
            for port in _COMMON_WEB_PORTS:
                url = f"{scheme}://{host}:{port}"
                try:
                    r = client.get(url)
                except httpx_client.HTTPError:
                    continue
                if r.status_code < 500:
                    return url
    except Exception:  # noqa: BLE001 — sweep is best-effort; fall back to nmap
        return None
    return None


def _deferred_nmap_step(host: str) -> dict[str, Any]:
    """Low-priority nmap step (operator: scan OTHER ports, but only AFTER web recon)."""
    return {
        "priority": 9,
        "tool": "nmap",
        "reason": (
            "A web service was found on the discovered port; scan the rest of the host "
            "for OTHER open ports/services AFTER the standard web recon — they may host "
            "additional vulnerabilities. This is a follow-up, not a blocker."
        ),
        "params": {"target": host, "ports": "1-65535", "service_detection": True},
        "expected_finding": "Additional open ports/services beyond the primary web app.",
    }


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
            # backlog-402: bumped from 2048 → 4096 because the extended schema
            # (observed_paths + attack_candidates) on real targets routinely
            # exceeds 2048 tokens and was truncating mid-JSON (live validation
            # 2026-05-19 produced JSON parse error at char 6408 with 2048).
            max_tokens=4096,
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
        params = _normalize_hint_target(dict(step.get("params") or {}), base_url)
        hints.append({
            "tool": tool,
            "reason": str(step.get("reason", f"Target-intel planned: {tool}"))[:200],
            "params": params,
        })
        if len(hints) >= 6:  # cap total hints to avoid overwhelming the queue
            break

    return hints


def _normalize_hint_target(params: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Preserve the canonical base URL's host:port (and path prefix) in any
    next-step hint URL. 2026-05-29 (operator flagged httpx hitting
    `http://127.0.0.155` 3x): the LLM/fallback test_plan frequently emits a
    BARE host (dropping the non-default port, e.g. :8088, or a path-based
    instance like Gruyere's /<id>/), so httpx/smart-web-probe fire against the
    wrong endpoint (port 80 → connection refused, or the codelab root instead
    of the instance). When a hint's url/target shares the base host but is
    missing the port or instance path, rewrite it to the canonical base_url.
    Generic — applies to any target, incl. external path-based instances.
    """
    base = urlparse(base_url)
    base_host = (base.hostname or "").lower()
    if not base_host:
        return params
    for key in ("url", "target"):
        val = params.get(key)
        if not isinstance(val, str) or not val:
            continue
        # nmap takes a bare host:port, leave it; only fix HTTP url-shaped values.
        if key == "target" and "://" not in val:
            continue
        u = urlparse(val if "://" in val else f"http://{val}")
        if (u.hostname or "").lower() != base_host:
            continue  # different host — out of our concern (scope guard handles it)
        # Same host: if the hint dropped the port or the base has a path prefix
        # the hint lacks, substitute the canonical base URL.
        hint_has_port = u.port is not None
        base_has_port = base.port is not None
        base_path = base.path.rstrip("/")
        if (base_has_port and not hint_has_port) or (base_path and not u.path.rstrip("/").startswith(base_path)):
            params[key] = base_url.rstrip("/") + (u.path if u.path not in ("", "/") else "")
    return params


def _port_discovery_required_analysis(base_target: str, context: dict[str, Any]) -> dict[str, Any] | None:
    """Codex Challenge-Readiness 2026-05-28: when the target URL has NO explicit
    port AND the default-port probe got no usable response, this is NOT an
    "empty site" — it's "service port unknown". With the dedicated-IP / whole-IP
    scope model a target is a HOST whose serving port must be DISCOVERED first.
    Returns a deterministic port-discovery-first plan (nmap at priority 1, then
    httpx with Host-header candidates, then web recon) instead of letting the
    LLM hallucinate a port-80 webapp analysis + waste httpx/nuclei steps.
    Returns None when the target already responded or has an explicit port.
    """
    parsed = urlparse(base_target)
    if parsed.port is not None:
        return None  # explicit port given — normal analysis applies
    status = context.get("status")
    if status is not None:
        return None  # default port answered — it really is a web target
    host = parsed.hostname or base_target
    return {
        "site_type": "port_discovery_required",
        "readiness_status": "service_port_unknown",
        "technology_stack": [],
        "cves_to_check": [],
        "attack_surface": [],
        "sensitive_data_found": [],
        "observed_paths": [],
        "attack_candidates": [],
        "target_envelope": {
            "connect_host": host,
            "scope_ports": "all",
            "explicit_port_present": False,
            "host_header_candidates": ["localhost", host],
        },
        # ONLY emit the port-discovery step. 2026-05-29 (operator flagged
        # httpx-on-bare-host failing repeatedly): previously this also emitted
        # priority-2 httpx + priority-3 smart-web-probe against `http://{host}`
        # (bare, port 80) — but the port is UNKNOWN at this stage, so those
        # fired prematurely and failed with connection-refused, producing the
        # recurring noise. Emit nmap alone; once it discovers the real port the
        # next recon iteration probes the correct host:port. No premature
        # bare-host HTTP hits.
        "test_plan": [
            {
                "priority": 1,
                "tool": "nmap",
                "reason": (
                    "URL has no explicit port and the default-port probe returned no "
                    "response. Discover which port actually serves BEFORE any HTTP recon. "
                    "Do NOT issue HTTP requests to this host until a port is known."
                ),
                "params": {"target": host, "ports": "1-65535", "service_detection": True},
                "expected_finding": "Open port(s) + service banners identifying the live service.",
            },
        ],
    }


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

    # Step 1b (2026-06-03, operator: "nmap is fine, but AFTER the standard web
    # recon, not as a blocking first step"): a port-LESS target whose :80 probe got
    # no response is NOT automatically "port unknown -> full nmap". First cheaply
    # sweep common app ports; if one serves (e.g. :5000), proceed with web recon
    # THERE and demote nmap to a low-priority OTHER-port follow-up.
    discovered_port_url = None
    if urlparse(base_target).port is None and context.get("status") is None:
        discovered_port_url = _sweep_common_web_ports(base_target, timeout_seconds)
        if discovered_port_url:
            logger.info(
                "target-intel: :80 probe failed but common-web-port sweep found %s — "
                "proceeding with web recon there; nmap deferred to a later other-port step",
                discovered_port_url,
            )
            base_target = discovered_port_url
            context = _probe_target(discovered_port_url, min(timeout_seconds, 15.0))

    # Step 2: readiness gate — if the port is STILL unknown (no explicit port + no
    # response + sweep found nothing), emit the deterministic port-discovery-first
    # plan (nmap priority 1). Otherwise run the normal Claude analysis.
    analysis = _port_discovery_required_analysis(base_target, context)
    if analysis is not None:
        logger.info(
            "target-intel: readiness=service_port_unknown for %s — emitting "
            "port-discovery-first plan (nmap priority 1)", base_target,
        )
    else:
        analysis = _call_claude(context, base_target)
        if not analysis:
            logger.info("target-intel: using heuristic fallback (no API key or Claude error)")
            analysis = _fallback_analysis(context)
        # operator nuance: nmap stays valuable for OTHER ports, but only AFTER the
        # standard web recon — append it as a low-priority follow-up when we reached
        # the web app via the common-port sweep (so other ports are still unknown).
        if discovered_port_url and isinstance(analysis, dict):
            tp = analysis.setdefault("test_plan", [])
            if isinstance(tp, list) and not any(
                isinstance(s, dict) and str(s.get("tool")) == "nmap" for s in tp
            ):
                tp.append(_deferred_nmap_step(urlparse(base_target).hostname or base_target))

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

    # Emit structured observations for the evidence graph (backlog-372).
    # The host itself becomes an asset; discovered extra_paths become apis.
    observations: list[dict[str, Any]] = []
    try:
        from api.app.services.evidence_ingest import make_observation

        host = urlparse(base_target).hostname or base_target
        observations.append(
            make_observation(
                entity_type="asset",
                entity_source_id=host,
                entity_label=host,
                entity_subtype="host",
                attributes={
                    "site_type": analysis.get("site_type"),
                    "technology_stack": analysis.get("technology_stack") or [],
                    "server_header": (context.get("headers") or {}).get("server"),
                    # backlog-402 — emergent per-target discovery payload.
                    # Downstream consumers: workers/runners/_path_augmentation.attack_candidates_for_run
                    # (probes), api/app/services/auth_discoverer.fetch_auth_pages
                    # (auth-flow). See SESSION_PROMPT.md for the smart-system
                    # contract that forbids static per-stack registries.
                    "observed_paths": (
                        analysis.get("observed_paths")
                        if isinstance(analysis.get("observed_paths"), list)
                        else []
                    ),
                    "attack_candidates": (
                        analysis.get("attack_candidates")
                        if isinstance(analysis.get("attack_candidates"), list)
                        else []
                    ),
                },
                confidence=0.85,
                evidence_refs=[base_target],
            )
        )
        for path, info in (context.get("extra_paths") or {}).items():
            if not isinstance(info, dict):
                continue
            url = f"{base_target.rstrip('/')}{path if path.startswith('/') else '/' + path}"
            observations.append(
                make_observation(
                    entity_type="api",
                    entity_source_id=url,
                    entity_label=path,
                    entity_subtype="discovered_endpoint",
                    attributes={
                        "status": info.get("status"),
                        "content_type": info.get("content_type"),
                    },
                    confidence=0.75,
                    evidence_refs=[base_target],
                )
            )
    except Exception as obs_exc:  # observations are advisory
        logger.debug("target-intel observation emit skipped: %s", obs_exc)
        observations = []

    return RunnerExecution(
        tool="target-intel",
        exit_code=0,
        stdout=json.dumps(result),
        stderr="",
        metadata={
            "status": "ok",
            "tool_version": "target-intel:v1",
            "observations": observations,
        },
        artifacts=[EvidenceArtifact(
            name=TARGET_INTEL_ARTIFACT_NAME,
            content_type="application/json",
            data=(json.dumps(result, sort_keys=True) + "\n").encode("utf-8"),
            kind="runner-results",
        )],
    )
