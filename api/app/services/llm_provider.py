"""Provider-agnostic LLM access (LiteLLM-wrapped).

Per backlog-417 (sprint mythos-exploitation-foundation, task 11/15): every
LLM round trip routes through one ``LLMProvider`` interface so AegisPT can
swap brain (Claude Opus 4.7 default → GPT-4o / Gemini 2.0 Pro / DeepSeek
V3) per run-config without forking prompts or call sites. Per OpenClaw
research: model-agnostic from day 1 is a product requirement, not a
bonus.

Design:

- ``LLMProviderConfig`` captures everything the caller needs to vary
  per provider: ``model`` (litellm-style id), ``api_key_env``, default
  ``temperature`` + ``max_tokens``.
- ``LLMProvider.chat(system, messages, ...)`` calls LiteLLM and returns
  a normalized ``LLMResponse`` (text + usage + raw provider data).
- When LiteLLM is unavailable (not installed, or import fails), the
  provider falls back to direct ``anthropic.Anthropic`` calls IF the
  selected model is an Anthropic model. Per Codex constraint
  ``graceful_degradation``: agent runtime never blocks on the optional
  dep.
- @traced decorator (backlog-407) emits per-call OTEL spans with usage
  attributes for cost telemetry.

Per ANTI_DRIFT Rule 3: callers that previously instantiated
``anthropic.Anthropic(api_key=...)`` directly MUST route through this
module. The migration of the picker hot path
(``_claude_select_next_action``) and the ``exploit_developer`` composer
lands in the same commit.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from api.app.observability import traced

logger = logging.getLogger(__name__)


DEFAULT_MODEL = "claude-opus-4-7"

# Known provider configs the run-config can name. Operators can override
# by passing an LLMProviderConfig directly.
KNOWN_PROVIDERS: dict[str, dict[str, Any]] = {
    "claude-opus-4-7": {
        "model": "claude-opus-4-7",
        "litellm_model": "anthropic/claude-opus-4-7-20260201",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "claude-sonnet-4-6": {
        "model": "claude-sonnet-4-6",
        "litellm_model": "anthropic/claude-sonnet-4-6-20260201",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "gpt-4o": {
        "model": "gpt-4o",
        "litellm_model": "openai/gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
    },
    "gemini-2.0-pro": {
        "model": "gemini-2.0-pro",
        "litellm_model": "gemini/gemini-2.0-pro",
        "api_key_env": "GEMINI_API_KEY",
    },
    "deepseek-v3": {
        "model": "deepseek-v3",
        "litellm_model": "deepseek/deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
    },
}


@dataclass
class LLMProviderConfig:
    """Per-call LLM provider configuration."""

    model: str = DEFAULT_MODEL
    litellm_model: str | None = None
    api_key_env: str = "ANTHROPIC_API_KEY"
    temperature: float = 0.4
    max_tokens: int = 4096

    @classmethod
    def for_model(cls, model: str | None) -> "LLMProviderConfig":
        key = (model or DEFAULT_MODEL).strip().lower()
        entry = KNOWN_PROVIDERS.get(key)
        if entry is None:
            logger.info("llm_provider: unknown model %r — falling back to %s", model, DEFAULT_MODEL)
            entry = KNOWN_PROVIDERS[DEFAULT_MODEL]
        return cls(
            model=entry["model"],
            litellm_model=entry["litellm_model"],
            api_key_env=entry["api_key_env"],
        )


@dataclass
class LLMResponse:
    """Normalized response across all providers."""

    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)
    provider_error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.provider_error is None and bool(self.text)


def _litellm_available() -> bool:
    try:
        import litellm  # noqa: F401
        return True
    except ImportError:
        return False


def _anthropic_direct_chat(
    config: LLMProviderConfig,
    *,
    system: str,
    messages: list[dict[str, Any]],
    timeout: float,
) -> LLMResponse:
    """Fallback path when LiteLLM is unavailable but the model is Anthropic."""
    api_key = os.environ.get(config.api_key_env, "").strip()
    if not api_key:
        return LLMResponse(
            text="",
            model=config.model,
            provider_error=f"{config.api_key_env} not configured",
        )
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=config.model,
            max_tokens=config.max_tokens,
            system=system,
            messages=messages,
            timeout=timeout,
        )
        text = msg.content[0].text if msg.content else ""
        usage = getattr(msg, "usage", None)
        return LLMResponse(
            text=text,
            model=config.model,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            raw={"backend": "anthropic-direct"},
        )
    except Exception as exc:  # noqa: BLE001
        return LLMResponse(
            text="",
            model=config.model,
            provider_error=f"anthropic direct call failed: {exc}",
        )


def _litellm_chat(
    config: LLMProviderConfig,
    *,
    system: str,
    messages: list[dict[str, Any]],
    timeout: float,
) -> LLMResponse:
    """Primary path: route through LiteLLM."""
    try:
        import litellm
    except ImportError:
        return LLMResponse(
            text="",
            model=config.model,
            provider_error="litellm not installed",
        )
    api_key = os.environ.get(config.api_key_env, "").strip()
    if not api_key:
        return LLMResponse(
            text="",
            model=config.model,
            provider_error=f"{config.api_key_env} not configured",
        )
    full_messages = [{"role": "system", "content": system}, *messages] if system else list(messages)
    try:
        resp = litellm.completion(
            model=config.litellm_model or config.model,
            messages=full_messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            api_key=api_key,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return LLMResponse(
            text="",
            model=config.model,
            provider_error=f"litellm completion failed: {exc}",
        )
    try:
        choices = resp.get("choices") if isinstance(resp, dict) else getattr(resp, "choices", None)
        first = choices[0] if choices else None
        content = ""
        if first is not None:
            message = first.get("message") if isinstance(first, dict) else getattr(first, "message", None)
            if isinstance(message, dict):
                content = str(message.get("content") or "")
            elif message is not None:
                content = str(getattr(message, "content", "") or "")
        usage = resp.get("usage") if isinstance(resp, dict) else getattr(resp, "usage", None)
        input_tokens = 0
        output_tokens = 0
        if isinstance(usage, dict):
            input_tokens = int(usage.get("prompt_tokens", 0) or 0)
            output_tokens = int(usage.get("completion_tokens", 0) or 0)
        elif usage is not None:
            input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
            output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        return LLMResponse(
            text=content,
            model=config.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw={"backend": "litellm", "litellm_model": config.litellm_model},
        )
    except Exception as exc:  # noqa: BLE001
        return LLMResponse(
            text="",
            model=config.model,
            provider_error=f"litellm response parse failed: {exc}",
        )


class LLMProvider:
    """The single entry point every AegisPT LLM round trip goes through."""

    def __init__(self, config: LLMProviderConfig | None = None) -> None:
        self.config = config or LLMProviderConfig.for_model(DEFAULT_MODEL)

    @classmethod
    def for_run(cls, run_configuration: dict[str, Any] | None) -> "LLMProvider":
        cfg = run_configuration or {}
        model = str(cfg.get("llm_provider") or cfg.get("llm_model") or DEFAULT_MODEL)
        return cls(LLMProviderConfig.for_model(model))

    def raw_anthropic_client(self) -> Any:
        """Return a configured ``anthropic.Anthropic`` client.

        The picker's tool-use loop (``_claude_select_next_action``) needs
        Anthropic-specific features (``tools=``, ``output_config=``,
        beta headers, structured JSON-schema output) that LiteLLM does
        not yet proxy. Until the LiteLLM tools/output_schema support
        lands in :meth:`chat`, the picker uses this raw client — but it
        still goes through ``LLMProvider`` so api-key lookup + model
        selection + future swap-in stays centralized. Raises when the
        configured model is not Anthropic.
        """
        if not self.config.api_key_env.upper().startswith("ANTHROPIC"):
            raise RuntimeError(
                f"raw_anthropic_client() is Anthropic-only; configured model "
                f"{self.config.model!r} uses env {self.config.api_key_env!r}. "
                "Wait for LiteLLM tools/output_schema support to migrate."
            )
        api_key = os.environ.get(self.config.api_key_env, "").strip()
        if not api_key:
            raise RuntimeError(f"{self.config.api_key_env} not configured")
        import anthropic
        return anthropic.Anthropic(api_key=api_key)

    @traced("llm.chat")
    def chat(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        timeout: float = 60.0,
    ) -> LLMResponse:
        """Single round-trip call. Picks LiteLLM when available, otherwise
        falls back to direct Anthropic SDK if the configured model is an
        Anthropic model. Per ``graceful_degradation``: never raises — the
        caller checks ``response.succeeded``.
        """
        if _litellm_available():
            resp = _litellm_chat(self.config, system=system, messages=messages, timeout=timeout)
            if resp.succeeded or not self.config.api_key_env.startswith("ANTHROPIC"):
                return resp
            # Anthropic models can still try the direct path when LiteLLM errored.
            logger.info("llm_provider: litellm failed (%s); trying anthropic direct", resp.provider_error)
        return _anthropic_direct_chat(self.config, system=system, messages=messages, timeout=timeout)


__all__ = [
    "DEFAULT_MODEL",
    "KNOWN_PROVIDERS",
    "LLMProvider",
    "LLMProviderConfig",
    "LLMResponse",
]


# Silence unused-import lint when json isn't needed by callers of this module.
_ = json
