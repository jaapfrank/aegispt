"""Specialist orchestrator (Phase 1c of landscape-plan 2026-05-22).

Fans out to 5 OWASP-category specialists in parallel, each focused on
ONE vulnerability family. Merges their ranked hypothesis lists into a
single global queue the executor consumes.

Pattern from Shannon Lite (apps/worker/prompts/vuln-*.txt + 5 concurrent
agents) — proven to hit 96.15% on XBOW vs our single-picker 0/1.

Routes per provider:
- Anthropic provider → 5 parallel client.messages.create with
  output_config.format.json_schema enforcement (one per specialist).
- ChatGPT-OAuth provider → 5 parallel send_chatgpt_backend_streaming_json_request
  with the specialist's instructions block + structured-output schema
  embedded as JSON.

Failure modes (each handled per specialist, NOT fatal globally):
- Specialist returns invalid JSON → log + skip its hypotheses
- Specialist times out → log + skip
- Specialist returns no hypotheses (no_hypotheses_reason set) → record
  that specialist marked the category n/a; do not retry

Output: a single sorted hypothesis list. The first executor iteration
takes hypothesis[0], dispatches its tool, validates the success_condition,
and either keeps the finding or downgrades it to info.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable

from . import (
    VULN_AUTH_HYPOTHESIS_SCHEMA,
    VULN_AUTH_PROMPT,
    VULN_AUTHZ_HYPOTHESIS_SCHEMA,
    VULN_AUTHZ_PROMPT,
    VULN_INJECTION_HYPOTHESIS_SCHEMA,
    VULN_INJECTION_PROMPT,
    VULN_SSRF_HYPOTHESIS_SCHEMA,
    VULN_SSRF_PROMPT,
    VULN_XSS_HYPOTHESIS_SCHEMA,
    VULN_XSS_PROMPT,
)

logger = logging.getLogger(__name__)


SPECIALISTS: list[dict[str, Any]] = [
    {"name": "vuln_auth", "prompt": VULN_AUTH_PROMPT, "schema": VULN_AUTH_HYPOTHESIS_SCHEMA},
    {"name": "vuln_authz", "prompt": VULN_AUTHZ_PROMPT, "schema": VULN_AUTHZ_HYPOTHESIS_SCHEMA},
    {"name": "vuln_injection", "prompt": VULN_INJECTION_PROMPT, "schema": VULN_INJECTION_HYPOTHESIS_SCHEMA},
    {"name": "vuln_ssrf", "prompt": VULN_SSRF_PROMPT, "schema": VULN_SSRF_HYPOTHESIS_SCHEMA},
    {"name": "vuln_xss", "prompt": VULN_XSS_PROMPT, "schema": VULN_XSS_HYPOTHESIS_SCHEMA},
]


def _build_user_content_for_specialist(
    *,
    recon_deliverable: str,
    available_tools: list[str],
    prior_findings_summary: str,
) -> str:
    """Same user-content envelope for every specialist; only the
    instructions (system prompt) differ. Keeps the orchestrator simple
    and lets the specialist's schema enforce its category boundary."""
    return (
        "=== RECON DELIVERABLE ===\n"
        f"{recon_deliverable}\n\n"
        "=== AVAILABLE TOOLS ===\n"
        f"{', '.join(sorted(available_tools)) or '(none)'}\n\n"
        "=== PRIOR FINDINGS (this run) ===\n"
        f"{prior_findings_summary or '(none yet)'}\n\n"
        "Now produce your ranked hypothesis list per your category's schema."
    )


def run_specialists_parallel(
    *,
    call_specialist: Callable[[dict[str, Any], str], dict[str, Any] | None],
    recon_deliverable: str,
    available_tools: list[str],
    prior_findings_summary: str,
    max_workers: int = 5,
    per_specialist_timeout_s: float = 120.0,
) -> dict[str, Any]:
    """Fan out to all 5 specialists in parallel via a thread pool.

    ``call_specialist`` is the provider-specific call factory:
    ``call_specialist(specialist_meta, user_content) -> dict | None``. The
    orchestrator does not care which LLM provider runs underneath —
    it only assembles results.

    Returns a single merged dict:
        {
          "specialists_called": ["vuln_auth", "vuln_authz", ...],
          "specialists_errored": [{"name": str, "reason": str}, ...],
          "hypothesis_queue": [hypothesis, ...]  # globally sorted by rank
        }
    """
    user_content = _build_user_content_for_specialist(
        recon_deliverable=recon_deliverable,
        available_tools=available_tools,
        prior_findings_summary=prior_findings_summary,
    )

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    started = time.time()

    def _invoke(meta: dict[str, Any]) -> tuple[str, dict[str, Any] | Exception]:
        name = str(meta["name"])
        try:
            t0 = time.time()
            payload = call_specialist(meta, user_content)
            elapsed = time.time() - t0
            logger.info(
                "PROOF_EXEC_SPECIALIST_2026052211 specialist=%s ran=%s elapsed=%.1fs",
                name,
                "ok" if payload else "empty",
                elapsed,
            )
            if payload is None:
                return name, RuntimeError("specialist returned None")
            return name, payload
        except Exception as exc:  # noqa: BLE001
            return name, exc

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_invoke, meta): meta for meta in SPECIALISTS}
        for fut in futures:
            try:
                name, payload = fut.result(timeout=per_specialist_timeout_s)
            except Exception as exc:  # noqa: BLE001
                meta = futures[fut]
                errors.append({"name": str(meta["name"]), "reason": str(exc)[:200]})
                continue
            if isinstance(payload, Exception):
                errors.append({"name": name, "reason": str(payload)[:200]})
                continue
            results.append({"name": name, "payload": payload})

    total_elapsed = time.time() - started

    queue: list[dict[str, Any]] = []
    n_a: list[str] = []
    for entry in results:
        name = entry["name"]
        payload = entry["payload"]
        hypotheses = payload.get("hypotheses") if isinstance(payload, dict) else None
        if not hypotheses:
            n_a.append(name)
            continue
        if isinstance(hypotheses, list):
            for h in hypotheses:
                if isinstance(h, dict):
                    h = dict(h)
                    h["__specialist"] = name
                    queue.append(h)

    queue.sort(key=lambda h: int(h.get("rank", 99)))

    logger.info(
        "specialist_orchestrator: fanned out to %d, errored=%d, n_a=%d, "
        "hypotheses=%d, elapsed=%.1fs",
        len(SPECIALISTS),
        len(errors),
        len(n_a),
        len(queue),
        total_elapsed,
    )

    return {
        "specialists_called": [s["name"] for s in SPECIALISTS],
        "specialists_errored": errors,
        "specialists_no_hypotheses": n_a,
        "hypothesis_queue": queue,
        "elapsed_sec": round(total_elapsed, 1),
    }
