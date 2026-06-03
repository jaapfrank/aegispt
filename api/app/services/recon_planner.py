"""AI-elective recon planning (T-AI1, 2026-06-03).

North-star gap (operator, verified): today the recon phase is a HARDCODED decision
tree — `_goal_tool_sequence` returns fixed lists and picks nmap by RULE
(`first = "nmap" if target_type in {"cidr","ip_or_host"} else "httpx"`), so nmap runs
on a known single-web-service target where a smart agent would skip it (it was already
flagged running with 0 hosts in nearly every solved run). This module lets the MODEL
choose the recon set + order instead.

Design contract:
- Provider-agnostic + side-effect free: the LLM is injected as `call_llm(prompt)->str`
  so the whole module is unit-testable with a mock and reusable across providers.
- FALLBACK-SAFE: any failure (no call_llm, bad JSON, empty/invalid selection, an
  exception) returns the caller's deterministic `default_sequence` unchanged. The
  planner can only ever REORDER/SUBSET the menu — it never invents an unsupported
  tool, and it never returns an empty plan.
- The model may DROP tools that add no value (the whole point — e.g. nmap on a known
  web port) but every returned tool must be in the allowed menu.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Tools that are never worth dropping by the planner — keep the agent from
# accidentally skipping the cheap, always-useful web baseline.
_ALWAYS_KEEP_IF_PRESENT: set[str] = set()


def summarize_target_envelope(targets: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Compress the run's targets into the few facts that decide recon value:
    is it a single resolved web URL with a known port (=> nmap pointless), or an
    IP/host/CIDR / unknown-port (=> port+service discovery genuinely helps)?"""
    targets = targets or []
    schemes: set[str] = set()
    hosts: set[str] = set()
    ports_known = True
    is_cidr = False
    n = 0
    for t in targets:
        val = str((t or {}).get("value") or (t or {}).get("url") or "").strip()
        if not val:
            continue
        n += 1
        if "/" in val and re.search(r"/\d{1,2}$", val):
            is_cidr = True
        parsed = urlparse(val if "://" in val else f"//{val}", scheme="")
        if parsed.scheme:
            schemes.add(parsed.scheme.lower())
        host = parsed.hostname or val
        hosts.add(host)
        # port known iff explicit in the URL OR the scheme implies a default
        if not parsed.port and parsed.scheme not in {"http", "https"}:
            ports_known = False
    is_web = bool(schemes & {"http", "https"}) and not is_cidr
    single_known_web = is_web and len(hosts) <= 1 and ports_known and not is_cidr
    return {
        "target_count": n,
        "schemes": sorted(schemes),
        "host_count": len(hosts),
        "is_web": is_web,
        "is_cidr": is_cidr,
        "ports_known": ports_known,
        "single_known_web_service": single_known_web,
    }


def _build_prompt(
    *,
    envelope: dict[str, Any],
    default_sequence: list[str],
    menu: list[str],
    source_available: bool,
) -> str:
    return (
        "You are the recon planner for an autonomous web/host pentest agent. Decide "
        "WHICH recon tools to run and IN WHAT ORDER for this target. You may DROP any "
        "tool that adds no value for THIS target (do not run recon for its own sake).\n\n"
        "=== TARGET ENVELOPE ===\n"
        f"{json.dumps(envelope, indent=1)}\n\n"
        f"Source code available to read: {source_available}\n\n"
        "=== DEFAULT (hardcoded) SEQUENCE — a baseline you may prune/reorder ===\n"
        f"{default_sequence}\n\n"
        "=== ALLOWED TOOL MENU (you may ONLY choose from these exact names) ===\n"
        f"{menu}\n\n"
        "Guidance: `nmap` is PORT/SERVICE discovery — it is pointless when the target "
        "is a single web service on a KNOWN port (you already know the address + that "
        "it is HTTP); keep it only for IP/CIDR/unknown-port/multi-service scopes. Prefer "
        "content-discovery + source analysis for a known web app. Keep the plan minimal "
        "but sufficient to reach the vuln.\n\n"
        "Output STRICT JSON only, no prose:\n"
        '{\"recon_tools\": [\"<ordered tool names from the menu>\"], '
        '\"skipped\": [\"<tools you deliberately dropped>\"], \"reason\": \"<one line>\"}'
    )


def _parse_plan(raw: str, *, menu: set[str]) -> list[str] | None:
    """Extract the recon_tools list from the model's reply; keep only allowed,
    de-duplicated, order-preserving names. Returns None if nothing usable."""
    if not raw:
        return None
    text = raw.strip()
    # tolerate code fences / surrounding prose: grab the first {...} object
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    tools = obj.get("recon_tools") if isinstance(obj, dict) else None
    if not isinstance(tools, list):
        return None
    seen: set[str] = set()
    chosen: list[str] = []
    for t in tools:
        name = str(t).strip()
        if name in menu and name not in seen:
            seen.add(name)
            chosen.append(name)
    return chosen or None


def plan_recon_tools(
    *,
    default_sequence: list[str],
    targets: list[dict[str, Any]] | None,
    supported_tools: set[str] | list[str],
    source_available: bool = False,
    call_llm: Callable[[str], str] | None = None,
) -> tuple[list[str], str]:
    """Return (ordered recon tool list, provenance). Provenance is "ai" when the
    model chose, else "fallback:<reason>". FALLBACK-SAFE: never raises, never
    returns empty, never an unsupported tool.

    The allowed menu is the default sequence INTERSECT supported tools (so the model
    can only prune/reorder the baseline, not invent steps) — keeps the change low-risk
    while still letting the AI own the recon decision."""
    supported = set(supported_tools or [])
    # menu = the baseline steps the system already considered, restricted to runnable
    menu_list = [t for t in default_sequence if t in supported] or list(default_sequence)
    menu = set(menu_list)
    if not menu:
        return (list(default_sequence), "fallback:empty_menu")
    if call_llm is None:
        return (menu_list, "fallback:no_llm")
    envelope = summarize_target_envelope(targets)
    try:
        prompt = _build_prompt(
            envelope=envelope,
            default_sequence=menu_list,
            menu=menu_list,
            source_available=source_available,
        )
        raw = call_llm(prompt)
        chosen = _parse_plan(raw or "", menu=menu)
    except Exception as exc:  # noqa: BLE001 — planner must never break dispatch
        logger.warning("recon_planner: LLM planning failed, using fallback: %s", exc)
        return (menu_list, "fallback:exception")
    if not chosen:
        return (menu_list, "fallback:unparsable")
    # safety: never drop an always-keep tool that was in the baseline
    for keep in _ALWAYS_KEEP_IF_PRESENT:
        if keep in menu and keep not in chosen:
            chosen.append(keep)
    logger.info(
        "PROOF_EXEC_AI_ELECTIVE_RECON_2026060301 chose=%s skipped=%s envelope_web=%s",
        chosen,
        [t for t in menu_list if t not in chosen],
        envelope.get("single_known_web_service"),
    )
    return (chosen, "ai")
