"""Guard: the XBOW harness must reject an unknown --llm-provider (credit-burn footgun).

2026-06-02: `--llm-provider deepseek-chat` (a typo for `deepseek-v3`) is not in
`KNOWN_PROVIDERS`, so `llm_provider.for_model` silently fell back to
`claude-opus-4-8` (the MOST EXPENSIVE model) and started burning Anthropic
credits with no error. The harness must fail fast on an unknown provider so a
typo can never silently route a whole benchmark run to the expensive default.
"""
from __future__ import annotations

import pytest

from scripts.xbow_benchmark import _validate_llm_provider


def test_none_is_allowed():
    # provider unspecified → legitimate "use the run-config default" path
    _validate_llm_provider(None)
    _validate_llm_provider("")


def test_known_providers_pass():
    # includes a case-insensitivity check (GPT-5.5 -> gpt-5.5)
    for p in ("deepseek-v3", "gemini-3.1-pro", "chatgpt_oauth", "claude-opus-4-8", "GPT-5.5"):
        _validate_llm_provider(p)


def test_unknown_provider_fails_fast():
    # the exact 2026-06-02 footgun + a generic bogus value must both abort
    for bad in ("deepseek-chat", "totally-bogus-model"):
        with pytest.raises(SystemExit) as exc:
            _validate_llm_provider(bad)
        msg = str(exc.value)
        assert "not a known provider" in msg
        # the error must list the valid set so the operator can self-correct
        assert "deepseek-v3" in msg
