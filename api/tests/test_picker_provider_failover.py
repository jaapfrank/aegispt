"""Spoor 0 (2026-06-11): picker provider failover chain.

The recurring `picker_retry_exhausted` death came from the picker being pinned to a
single provider (Anthropic, hardcoded `claude-opus-4-8`) that returns HTTP 400 the
moment credits lapse. These tests lock the failover contract: an ordered chain that
prefers cheap/available providers, keeps Anthropic as the LAST resort, adds DeepSeek
(uncensored cloud) as a first-class picker provider, and is overridable via env.
"""
from __future__ import annotations

from api.app.services.assessment_loop import (
    _picker_provider_chain,
    _provider_is_deepseek,
    _provider_kind,
)
from api.app.services.llm_provider import LLMProvider, LLMProviderConfig


def _provider(model: str) -> LLMProvider:
    return LLMProvider(LLMProviderConfig.for_model(model))


# ---- provider detection --------------------------------------------------

def test_deepseek_detected_by_model_and_keyenv():
    p = _provider("deepseek-v3")
    assert _provider_is_deepseek(p) is True
    assert _provider_kind(p) == "deepseek"


def test_claude_is_not_deepseek():
    p = _provider("claude-opus-4-8")
    assert _provider_is_deepseek(p) is False
    assert _provider_kind(p) == "anthropic"


# ---- chain ordering ------------------------------------------------------

def _set_creds(monkeypatch, *, deepseek=True, anthropic=True, local=False, chain=None):
    for var in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "AEGISPT_LOCAL_LLM_URL",
                "AEGISPT_PICKER_PROVIDER_CHAIN"):
        monkeypatch.delenv(var, raising=False)
    if deepseek:
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    if anthropic:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    if local:
        monkeypatch.setenv("AEGISPT_LOCAL_LLM_URL", "http://127.0.0.1:8801")
    if chain:
        monkeypatch.setenv("AEGISPT_PICKER_PROVIDER_CHAIN", chain)


def test_default_config_puts_anthropic_last(monkeypatch):
    # Configured provider is the Anthropic default; creds: deepseek + anthropic.
    _set_creds(monkeypatch, deepseek=True, anthropic=True, local=False)
    chain = _picker_provider_chain(run=None, configured_provider=_provider("claude-opus-4-8"))
    assert chain == ["deepseek", "chatgpt_oauth", "anthropic"]
    # The whole point: Anthropic is never first when it is the lapsing default.
    assert chain[-1] == "anthropic"


def test_all_providers_available_default_order(monkeypatch):
    _set_creds(monkeypatch, deepseek=True, anthropic=True, local=True)
    chain = _picker_provider_chain(run=None, configured_provider=_provider("claude-opus-4-8"))
    assert chain == ["local_qwen", "deepseek", "chatgpt_oauth", "anthropic"]


def test_explicit_deepseek_goes_first(monkeypatch):
    _set_creds(monkeypatch, deepseek=True, anthropic=True, local=True)
    chain = _picker_provider_chain(run=None, configured_provider=_provider("deepseek-v3"))
    assert chain[0] == "deepseek"
    assert "anthropic" in chain and chain[-1] == "anthropic"


def test_unavailable_providers_filtered_out(monkeypatch):
    # No local endpoint, no anthropic key -> only deepseek + the always-offered oauth.
    _set_creds(monkeypatch, deepseek=True, anthropic=False, local=False)
    chain = _picker_provider_chain(run=None, configured_provider=_provider("claude-opus-4-8"))
    assert chain == ["deepseek", "chatgpt_oauth"]
    assert "anthropic" not in chain
    assert "local_qwen" not in chain


def test_env_override_respected_but_filtered(monkeypatch):
    _set_creds(monkeypatch, deepseek=True, anthropic=True, local=False,
               chain="anthropic,local_qwen,deepseek")
    chain = _picker_provider_chain(run=None, configured_provider=_provider("claude-opus-4-8"))
    # local_qwen has no endpoint -> dropped; order otherwise honoured.
    assert chain == ["anthropic", "deepseek"]


def test_oauth_always_offered_even_with_no_env_keys(monkeypatch):
    _set_creds(monkeypatch, deepseek=False, anthropic=False, local=False)
    chain = _picker_provider_chain(run=None, configured_provider=_provider("claude-opus-4-8"))
    # chatgpt_oauth has no env var (DB-stored token) so it is always a candidate;
    # the chain is therefore never empty in practice.
    assert chain == ["chatgpt_oauth"]
