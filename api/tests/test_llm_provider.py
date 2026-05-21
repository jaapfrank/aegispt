"""Unit tests for backlog-417 LLM provider abstraction."""
from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

from api.app.services.llm_provider import (
    DEFAULT_MODEL,
    KNOWN_PROVIDERS,
    LLMProvider,
    LLMProviderConfig,
    LLMResponse,
)

# --- Config shape -------------------------------------------------------


def test_default_model_is_claude_opus() -> None:
    assert DEFAULT_MODEL == "claude-opus-4-7"
    cfg = LLMProviderConfig.for_model(None)
    assert cfg.model == "claude-opus-4-7"


def test_unknown_model_falls_back_to_default() -> None:
    cfg = LLMProviderConfig.for_model("hallucinated-7b")
    assert cfg.model == DEFAULT_MODEL


def test_known_providers_include_all_required() -> None:
    expected = {
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "gpt-4o",
        "gemini-2.0-pro",
        "deepseek-v3",
        "chatgpt_oauth",
        "gpt-5.4",
    }
    assert expected.issubset(set(KNOWN_PROVIDERS))


def test_config_for_gpt_4o_uses_openai_env() -> None:
    cfg = LLMProviderConfig.for_model("gpt-4o")
    assert cfg.api_key_env == "OPENAI_API_KEY"
    assert cfg.litellm_model == "openai/gpt-4o"


def test_config_for_gemini_uses_gemini_env() -> None:
    cfg = LLMProviderConfig.for_model("gemini-2.0-pro")
    assert cfg.api_key_env == "GEMINI_API_KEY"


def test_for_run_picks_config_from_run_configuration() -> None:
    provider = LLMProvider.for_run({"llm_provider": "gpt-4o"})
    assert provider.config.model == "gpt-4o"
    provider = LLMProvider.for_run({})
    assert provider.config.model == DEFAULT_MODEL
    provider = LLMProvider.for_run(None)
    assert provider.config.model == DEFAULT_MODEL


def test_for_run_picks_chatgpt_oauth_provider_from_run_configuration() -> None:
    provider = LLMProvider.for_run({"llm_provider": "chatgpt_oauth"})
    assert provider.config.model == "gpt-5.4"
    assert provider.config.api_key_env == "CHATGPT_OAUTH_TOKEN"

    provider = LLMProvider.for_run({"ai_provider": "chatgpt_oauth"})
    assert provider.config.model == "gpt-5.4"
    assert provider.config.api_key_env == "CHATGPT_OAUTH_TOKEN"


# --- Response shape ----------------------------------------------------


def test_response_succeeded_only_when_text_present_and_no_error() -> None:
    assert LLMResponse(text="hi", model="x").succeeded is True
    assert LLMResponse(text="", model="x").succeeded is False
    assert LLMResponse(text="hi", model="x", provider_error="boom").succeeded is False


# --- Anthropic-direct fallback (LiteLLM unavailable) ------------------


def _install_fake_litellm_unavailable(monkeypatch) -> None:
    """Force the import in `_litellm_available` to fail."""
    real_import = __import__

    def fake_import(name: str, *args: Any, **kwargs: Any):
        if name == "litellm":
            raise ImportError("simulated missing litellm")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)


def test_chat_fallbacks_to_anthropic_when_litellm_missing(monkeypatch) -> None:
    _install_fake_litellm_unavailable(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub")

    class FakeMessages:
        def create(self, **_kw: Any):
            return SimpleNamespace(
                content=[SimpleNamespace(text="opus response")],
                usage=SimpleNamespace(input_tokens=11, output_tokens=22),
            )

    fake_anthropic = ModuleType("anthropic")
    fake_anthropic.Anthropic = lambda api_key=None: SimpleNamespace(messages=FakeMessages())  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)

    provider = LLMProvider()
    resp = provider.chat(system="sys", messages=[{"role": "user", "content": "hi"}])
    assert resp.succeeded is True
    assert resp.text == "opus response"
    assert resp.input_tokens == 11
    assert resp.output_tokens == 22
    assert resp.raw.get("backend") == "anthropic-direct"


def test_chat_returns_error_when_key_missing(monkeypatch) -> None:
    _install_fake_litellm_unavailable(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = LLMProvider()
    resp = provider.chat(system="", messages=[{"role": "user", "content": "x"}])
    assert resp.succeeded is False
    assert "ANTHROPIC_API_KEY" in (resp.provider_error or "")


# --- LiteLLM primary path (mocked module) -----------------------------


def _install_fake_litellm(monkeypatch, completion_impl):
    """Patch sys.modules so `import litellm` inside the provider returns a fake."""
    fake = ModuleType("litellm")
    fake.completion = completion_impl  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "litellm", fake)


def test_litellm_primary_path_normalizes_response(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "stub")

    def completion(**_kwargs: Any):
        return {
            "choices": [{"message": {"content": "gpt-4o text"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        }

    _install_fake_litellm(monkeypatch, completion)
    provider = LLMProvider(LLMProviderConfig.for_model("gpt-4o"))
    resp = provider.chat(system="sys", messages=[{"role": "user", "content": "go"}])
    assert resp.succeeded is True
    assert resp.text == "gpt-4o text"
    assert resp.input_tokens == 5
    assert resp.output_tokens == 7
    assert resp.raw.get("backend") == "litellm"


def test_litellm_failure_then_anthropic_fallback(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "stub")

    def completion(**_kwargs: Any):
        raise RuntimeError("simulated litellm 5xx")

    _install_fake_litellm(monkeypatch, completion)

    class FakeMessages:
        def create(self, **_kw: Any):
            return SimpleNamespace(
                content=[SimpleNamespace(text="anthropic fallback")],
                usage=SimpleNamespace(input_tokens=3, output_tokens=4),
            )

    fake_anthropic = ModuleType("anthropic")
    fake_anthropic.Anthropic = lambda api_key=None: SimpleNamespace(messages=FakeMessages())  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)

    provider = LLMProvider()  # default = claude → anthropic fallback path eligible
    resp = provider.chat(system="sys", messages=[{"role": "user", "content": "go"}])
    assert resp.succeeded is True
    assert resp.text == "anthropic fallback"
    assert resp.raw.get("backend") == "anthropic-direct"


def test_litellm_failure_for_non_anthropic_model_returns_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "stub")

    def completion(**_kwargs: Any):
        raise RuntimeError("simulated 5xx")

    _install_fake_litellm(monkeypatch, completion)

    provider = LLMProvider(LLMProviderConfig.for_model("gpt-4o"))
    resp = provider.chat(system="sys", messages=[{"role": "user", "content": "go"}])
    assert resp.succeeded is False
    assert "litellm completion failed" in (resp.provider_error or "")


# --- Defense-in-depth: no anthropic.Anthropic() in picker hot path ---


def test_picker_module_no_longer_calls_anthropic_directly() -> None:
    """Per ANTI_DRIFT Rule 3: after the refactor, `_claude_select_next_action`
    must route through LLMProvider. Sentinel asserts the legacy direct call
    is gone from the picker module."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "api" / "app" / "services" / "assessment_loop.py"
    text = src.read_text(encoding="utf-8")
    # Allow `import anthropic` (other modules may still need types) but the
    # specific construction must be gone from the picker.
    assert "anthropic.Anthropic(" not in text, (
        "_claude_select_next_action still constructs anthropic.Anthropic directly; "
        "refactor it through LLMProvider per backlog-417."
    )


def test_exploit_developer_no_longer_calls_anthropic_directly() -> None:
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "api" / "app" / "services" / "exploit_developer.py"
    text = src.read_text(encoding="utf-8")
    assert "anthropic.Anthropic(" not in text, (
        "exploit_developer still constructs anthropic.Anthropic directly; "
        "route through LLMProvider per backlog-417."
    )
