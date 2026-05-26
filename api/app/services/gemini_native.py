"""Native Gemini provider call — direct REST to Google's generativelanguage API.

Mirrors the shape of ``api.app.services.chatgpt_oauth.send_chatgpt_backend_streaming_json_request``
so the picker code paths can swap providers without rewriting their callers.
Uses GEMINI_API_KEY from the environment (sourced by the systemd
EnvironmentFile mechanism via /home/administrator/.aegispt-secrets).

Why native + REST rather than via LiteLLM:
- LiteLLM is not installed in this venv.
- The ChatGPT-OAuth provider is also native REST; staying native keeps
  the provider call-shape consistent and avoids hidden retry / streaming
  behaviour differences between LiteLLM versions.
- The Gemini surface we need (generateContent with responseSchema) is a
  single endpoint; no benefit from an abstraction layer.

Sources:
- https://ai.google.dev/api/generate-content
- https://ai.google.dev/gemini-api/docs/quickstart
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_TIMEOUT_SECONDS = 240.0


def _api_key() -> str:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set in the environment. Add it to "
            "/home/administrator/.aegispt-secrets and restart aegispt-api."
        )
    return key


def send_gemini_picker_request(
    *,
    model: str,
    instructions: str,
    user_content: str,
    response_schema: dict[str, Any] | None = None,
    thinking_budget: int | None = None,
    max_output_tokens: int = 8192,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Call Gemini generateContent and return the parsed JSON response.

    Args:
        model: e.g. "gemini-2.5-pro", "gemini-2.5-flash".
        instructions: system-prompt text (goes into systemInstruction.parts).
        user_content: user-turn text (single turn).
        response_schema: optional JSON-schema constraint. When present,
            responseMimeType is set to application/json.
        thinking_budget: optional thinking-mode token budget (Gemini 2.5
            feature, analogue to reasoning.effort). None = default.
        max_output_tokens: hard cap on output tokens.
        timeout_seconds: HTTP timeout.

    Returns:
        The parsed JSON dict from the model when response_schema is set,
        otherwise the raw text wrapped as ``{"text": "..."}``. Returns
        None on transport / parse failure (caller logs + falls back).
    """
    key = _api_key()
    url = f"{GEMINI_BASE_URL}/models/{model}:generateContent"

    generation_config: dict[str, Any] = {"maxOutputTokens": max_output_tokens}
    if response_schema is not None:
        generation_config["responseMimeType"] = "application/json"
        generation_config["responseSchema"] = response_schema
    if thinking_budget is not None:
        generation_config["thinkingConfig"] = {"thinkingBudget": int(thinking_budget)}

    payload: dict[str, Any] = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_content}],
            }
        ],
        "systemInstruction": {
            "parts": [{"text": instructions}],
        },
        "generationConfig": generation_config,
    }

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.post(
                url,
                json=payload,
                headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        logger.warning("gemini_native: transport error: %s", exc)
        return None

    if resp.status_code != 200:
        body_preview = resp.text[:400] if isinstance(resp.text, str) else ""
        logger.warning(
            "gemini_native: HTTP %d on %s — body=%r",
            resp.status_code,
            model,
            body_preview,
        )
        return None

    try:
        body = resp.json()
    except json.JSONDecodeError as exc:
        logger.warning("gemini_native: response JSON decode failed: %s", exc)
        return None

    candidates = body.get("candidates") or []
    if not candidates:
        # Check for prompt_feedback safety block; surface why.
        pf = body.get("promptFeedback") or {}
        logger.warning(
            "gemini_native: empty candidates — promptFeedback=%r",
            pf,
        )
        return None

    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(str(p.get("text") or "") for p in parts).strip()
    if not text:
        logger.warning("gemini_native: candidates[0] had no text parts")
        return None

    if response_schema is None:
        return {"text": text}

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "gemini_native: schema response was not valid JSON: %s — raw=%r",
            exc, text[:240],
        )
        return None
