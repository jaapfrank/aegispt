"""T-AI1: AI-elective recon. The model chooses the recon set/order (and may skip
nmap on a known web target); the hardcoded sequence stays only as a fallback.

These pin the FALLBACK-SAFE contract: the planner can only prune/reorder the allowed
menu, never invents a tool, never returns empty, never raises — so a flaky LLM can
never break dispatch."""
from __future__ import annotations

from api.app.services.recon_planner import (
    plan_recon_tools,
    summarize_target_envelope,
)

WEB = [{"kind": "url", "value": "http://127.0.0.94:5000"}]
IP = [{"kind": "ip_or_host", "value": "10.0.0.5"}]
CIDR = [{"kind": "cidr", "value": "10.0.0.0/24"}]
DEFAULT = ["nmap", "content-discovery", "api-assessment", "sqlmap"]
SUPPORTED = {"nmap", "content-discovery", "api-assessment", "sqlmap", "httpx"}


def test_envelope_detects_known_web_service():
    env = summarize_target_envelope(WEB)
    assert env["single_known_web_service"] is True
    assert env["is_web"] is True and env["is_cidr"] is False


def test_envelope_ip_and_cidr_not_known_web():
    assert summarize_target_envelope(IP)["single_known_web_service"] is False
    c = summarize_target_envelope(CIDR)
    assert c["is_cidr"] is True
    assert c["single_known_web_service"] is False


def test_ai_drops_nmap_for_web_target():
    # model decides nmap is pointless on a known web port
    def llm(_prompt: str) -> str:
        return '{"recon_tools": ["content-discovery", "api-assessment", "sqlmap"], "skipped": ["nmap"], "reason": "known web port"}'

    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=WEB, supported_tools=SUPPORTED,
        source_available=True, call_llm=llm,
    )
    assert prov == "ai"
    assert "nmap" not in tools
    assert tools == ["content-discovery", "api-assessment", "sqlmap"]


def test_ai_keeps_nmap_for_ip_target():
    def llm(_prompt: str) -> str:
        return '{"recon_tools": ["nmap", "content-discovery"], "reason": "unknown ports"}'

    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=IP, supported_tools=SUPPORTED, call_llm=llm,
    )
    assert prov == "ai" and tools[0] == "nmap"


def test_fallback_when_no_llm():
    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=WEB, supported_tools=SUPPORTED, call_llm=None,
    )
    assert prov.startswith("fallback")
    assert tools == DEFAULT  # all default tools are supported here


def test_fallback_on_unparsable_llm():
    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=WEB, supported_tools=SUPPORTED,
        call_llm=lambda _p: "I think you should run some tools, maybe nmap?",
    )
    assert prov == "fallback:unparsable"
    assert tools == DEFAULT


def test_fallback_on_llm_exception():
    def boom(_p: str) -> str:
        raise RuntimeError("backend down")

    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=WEB, supported_tools=SUPPORTED, call_llm=boom,
    )
    assert prov == "fallback:exception"
    assert tools == DEFAULT


def test_planner_never_invents_unsupported_tool():
    # model hallucinates a tool not in the menu -> it is dropped
    def llm(_p: str) -> str:
        return '{"recon_tools": ["content-discovery", "metasploit-pro", "nmap"], "reason": "x"}'

    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=IP, supported_tools=SUPPORTED, call_llm=llm,
    )
    assert "metasploit-pro" not in tools
    assert set(tools) <= SUPPORTED


def test_planner_never_returns_empty():
    # model returns only junk -> fallback (never an empty dispatch plan)
    def llm(_p: str) -> str:
        return '{"recon_tools": ["nonexistent-1", "nonexistent-2"]}'

    tools, prov = plan_recon_tools(
        default_sequence=DEFAULT, targets=WEB, supported_tools=SUPPORTED, call_llm=llm,
    )
    assert tools == DEFAULT and prov == "fallback:unparsable"


def test_menu_restricted_to_supported():
    # a default tool not supported in this deployment is filtered out of the menu
    tools, _ = plan_recon_tools(
        default_sequence=["nmap", "exotic-tool", "content-discovery"],
        targets=WEB, supported_tools={"nmap", "content-discovery"},
        call_llm=lambda _p: '{"recon_tools": ["exotic-tool", "content-discovery"]}',
    )
    # exotic-tool was never in the allowed menu -> cannot be chosen
    assert "exotic-tool" not in tools
    assert tools == ["content-discovery"]
