"""LLM-driven narrator for the Mission Control Story view.

After each Claude decision in the AI loop, this service generates a new
"comic panel" — a JSON snippet with a plain-language caption, emoji scene,
glossary entries for any new vulnerability classes, and a next-move
description. The frontend renders these as a sequential comic strip.

The intent: the agent Claude (Opus) does the technical pentest; the
narrator (Haiku, separate call) writes the human-facing story so a
non-technical reader can follow along. They are intentionally different
calls — the agent stays focused on action, the narrator on prose.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.models import Finding, Run, Task

logger = logging.getLogger(__name__)

NARRATIVE_MAX_PANELS = 30  # keep storage bounded
NARRATIVE_SCHEMA_VERSION = "narrator-v1.2026-05-13"


_NARRATOR_SYSTEM = """You are the narrator of a live offensive-security
operation against a single target. A separate AI (Claude) is doing the
actual pentest — you only observe and describe what is happening.

Your audience is BOTH a security engineer and a non-technical manager. They
need to follow along in real time and understand:
- what just happened
- what is happening right now (visualised as a metaphor)
- what is coming next
- what any technical term means, in plain language

TONE
- First person, as if YOU are the operator narrating live.
- Short sentences. Concrete verbs. No jargon. No marketing language.
- When a technical term appears (XSS, IDOR, CSRF, JSONP, RCE, traversal, etc.),
  define it inline using a real-world analogy a 12-year-old could follow.
- Be honest about setbacks — a failed tool is not a problem to hide.

OUTPUT — STRICT JSON ONLY (no prose around it). Fields:
{
  "hero": "1-2 sentences summarising current overall status. First person.",
  "scene_emoji": "single emoji that best represents what the active tool is doing right now",
  "alt_emoji": "optional second emoji (e.g. 🔑 next to 🚪). Empty string if not needed.",
  "scene_caption": "1 sentence plain-language metaphor of what the agent is doing right now (e.g. 'Slipping notes under doors to see which ones write back').",
  "panel_caption": "2-3 sentences describing what happened SINCE the previous panel — the new development. Be specific.",
  "next_move": "1 sentence describing the agent's planned next step. Plain language.",
  "glossary": {
    "<term>": "<one-sentence plain-language definition with analogy>",
    ...
  },
  "vibe": "recon | try | win | block | idle"
}

`glossary` should ONLY contain terms that appear in `panel_caption` or
`scene_caption` and might confuse a non-technical reader. Re-defining the
same term across panels is fine — assume each panel is read standalone.
"""


def _summarise_findings(findings: list[Finding], limit: int = 10) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings[:limit]:
        out.append({
            "severity": str(f.severity or "info"),
            "title": str(f.title or "")[:140],
            "target": str(f.target_id or "")[:160],
        })
    return out


def _summarise_recent_tasks(tasks: list[Task], limit: int = 8) -> list[dict[str, Any]]:
    sorted_tasks = sorted(
        tasks,
        key=lambda t: str(getattr(t, "updated_at", "") or getattr(t, "created_at", "") or ""),
        reverse=True,
    )
    out: list[dict[str, Any]] = []
    for t in sorted_tasks[:limit]:
        out.append({
            "tool": str(t.tool or ""),
            "status": str(t.status or "").lower(),
            "target_tail": str(t.target_id or "")[-60:],
        })
    return out


def _active_task(tasks: list[Task]) -> dict[str, Any] | None:
    for t in tasks:
        status = str(t.status or "").lower()
        if status in {"running", "dispatching", "queued", "requested"}:
            return {"tool": str(t.tool or ""), "status": status, "target_tail": str(t.target_id or "")[-60:]}
    return None


def _previous_panel_caption(narrative: dict[str, Any]) -> str:
    panels = narrative.get("panels") or []
    if not panels:
        return ""
    last = panels[-1]
    if isinstance(last, dict):
        return str(last.get("panel_caption") or "")
    return ""


def generate_narrative_panel(
    *,
    session: Session,
    run: Run,
    findings: list[Finding],
    tasks: list[Task],
    last_decision_reasoning: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Call ChatGPT to produce one new comic panel. Returns the parsed dict
    on success, or None on any failure (network, OAuth, parse).

    The panel is NOT persisted here — caller appends to loop_state and
    commits along with its own transaction.
    """
    effective_settings = settings or get_settings()
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    if run.engagement_id is None:
        return None

    prev_caption = _previous_panel_caption(_as_dict(_as_dict(run.configuration_json or {}).get("ai_assessment_loop")).get("narrative") or {})
    state = {
        "target": _target_for_narrative(run, tasks),
        "minutes_elapsed": _minutes_since_start(run),
        "findings_total": len(findings),
        "findings_by_severity": _severity_counts(findings),
        "top_findings": _summarise_findings(findings, limit=8),
        "recent_tasks": _summarise_recent_tasks(tasks, limit=8),
        "active_task": _active_task(tasks),
        "last_decision_reasoning": (last_decision_reasoning or "")[:600],
        "previous_panel_caption": prev_caption[:400],
    }

    user_message = (
        "Current state of the pentest:\n"
        + json.dumps(state, indent=2)
        + "\n\nWrite the next comic panel as strict JSON (see system instructions)."
    )

    logger.info("narrator: requesting panel (findings=%d, tasks=%d)", len(findings), len(tasks))

    # Try ChatGPT via OAuth first — that's the user's preferred narrator.
    # Fall back to Claude Opus if OAuth fails (no token, network, etc.).
    raw_text = ""
    used_provider = "none"
    try:
        from api.app.services.chatgpt_oauth import (
            ChatGPTOAuthError,
            send_chatgpt_backend_streaming_json_request,
        )
        try:
            gpt_payload = send_chatgpt_backend_streaming_json_request(
                session=session,
                engagement_id=run.engagement_id,
                settings=effective_settings,
                model=effective_settings.chatgpt_oauth_model,
                instructions=_NARRATOR_SYSTEM,
                input_items=[{
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_message}],
                }],
            )
            # ChatGPT returns the JSON dict directly (already parsed by the
            # send_chatgpt_backend_streaming_json_request helper). We just
            # serialize it back to a string so the rest of the panel
            # pipeline (which expects raw_text) can re-parse.
            if isinstance(gpt_payload, dict):
                raw_text = json.dumps(gpt_payload)
                used_provider = "chatgpt-oauth"
        except ChatGPTOAuthError as exc:
            logger.info("narrator: ChatGPT OAuth unavailable (%s) — falling back to Claude Opus", str(exc)[:200])
    except Exception as exc:
        # Try to extract HTTP response body for HTTPStatusError
        body_excerpt = ""
        try:
            from httpx import HTTPStatusError
            if isinstance(exc, HTTPStatusError):
                body_excerpt = " body=" + str(exc.response.text)[:300]
        except Exception:
            pass
        logger.info(
            "narrator: ChatGPT path errored (%s)%s — falling back to Claude Opus",
            str(exc)[:200], body_excerpt,
        )

    if not raw_text:
        try:
            import anthropic
        except ImportError:
            return None
        try:
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model="claude-opus-4-7",
                max_tokens=1024,
                system=_NARRATOR_SYSTEM,
                messages=[{"role": "user", "content": user_message}],
                timeout=90.0,
            )
            for block in msg.content or []:
                if getattr(block, "type", None) == "text":
                    raw_text = getattr(block, "text", "") or ""
                    used_provider = "claude-opus-4-7"
                    break
        except Exception as exc:
            logger.warning("narrator: Claude Opus call failed: %s", exc)
            return None

    if not raw_text:
        logger.warning("narrator: no text in response")
        return None
    parsed = _parse_panel_json(raw_text)
    if parsed is None:
        logger.warning("narrator: parse failed, raw=%r", raw_text[:300])
        return None
    logger.info(
        "narrator: panel produced via %s — vibe=%s emoji=%r caption=%r",
        used_provider, parsed.get("vibe"), parsed.get("scene_emoji"),
        str(parsed.get("panel_caption") or "")[:120],
    )

    parsed["at"] = _now_iso()
    parsed["schema"] = NARRATIVE_SCHEMA_VERSION
    parsed["provider"] = used_provider
    return parsed


def append_panel_to_loop_state(
    loop_state: dict[str, Any],
    panel: dict[str, Any],
) -> None:
    """Mutate loop_state to add a new narrative panel (newest at end).
    Caller is responsible for committing the run.configuration_json change.

    NOTE: this is the in-memory path. For race-safe append across concurrent
    advance calls, use `append_panel_atomic_sql()` after commit.
    """
    narrative = _as_dict(loop_state.get("narrative"))
    panels = list(narrative.get("panels") or [])
    panels.append(panel)
    if len(panels) > NARRATIVE_MAX_PANELS:
        panels = panels[-NARRATIVE_MAX_PANELS:]
    narrative["panels"] = panels
    narrative["latest_at"] = panel.get("at")
    narrative["schema"] = NARRATIVE_SCHEMA_VERSION
    loop_state["narrative"] = narrative


def append_panel_atomic_sql(
    session: Session,
    run_id: Any,
    panel: dict[str, Any],
) -> None:
    """Race-free append: insert one row into `audit_events` per panel.

    The ORM's flush of `runs.configuration_json` was overwriting any
    JSONB jsonb_set we did on `configuration_json`. Audit_events is
    append-only — no race possible. The runs read endpoint joins these
    rows into the response under `narrative.panels`.
    """
    from sqlalchemy import text
    import uuid as _uuid
    sql = text(
        """
        INSERT INTO audit_events (id, actor, action, object_type, object_id, metadata_json, created_at, updated_at)
        VALUES (
            (:event_id)::uuid,
            'narrator',
            'narrative.panel',
            'run',
            (:run_id)::varchar,
            (:metadata_json)::json,
            NOW(),
            NOW()
        )
        """
    )
    try:
        engine = session.get_bind()
        with engine.begin() as conn:
            conn.execute(sql, {
                "event_id": str(_uuid.uuid4()),
                "run_id": str(run_id),
                "metadata_json": json.dumps(panel),
            })
        logger.info(
            "narrator: panel persisted to audit_events (run=%s, vibe=%s)",
            str(run_id)[:8], panel.get("vibe"),
        )
    except Exception as exc:
        logger.warning("narrator: audit insert failed: %s", exc)


def fetch_panels_for_run(session: Session, run_id: Any, limit: int = NARRATIVE_MAX_PANELS) -> list[dict[str, Any]]:
    """Read narrative panels for a run from audit_events, chronological order."""
    from sqlalchemy import text
    sql = text(
        """
        SELECT metadata_json, created_at
        FROM audit_events
        WHERE object_type = 'run' AND object_id = (:run_id)::varchar AND action = 'narrative.panel'
        ORDER BY created_at ASC
        LIMIT (:limit_n)
        """
    )
    out: list[dict[str, Any]] = []
    try:
        engine = session.get_bind()
        with engine.connect() as conn:
            rows = conn.execute(sql, {"run_id": str(run_id), "limit_n": int(limit)}).fetchall()
        for row in rows:
            meta = row[0]
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except json.JSONDecodeError:
                    continue
            if isinstance(meta, dict):
                out.append(meta)
    except Exception as exc:
        logger.warning("narrator: fetch_panels failed: %s", exc)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _minutes_since_start(run: Run) -> int:
    started = getattr(run, "started_at", None) or getattr(run, "created_at", None)
    if started is None:
        return 0
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        delta = (now - started).total_seconds()
        return max(0, int(delta // 60))
    except Exception:
        return 0


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.severity or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _target_for_narrative(run: Run, tasks: list[Task]) -> str:
    for t in tasks:
        if t.target_id:
            return str(t.target_id)
    return ""


def _extract_text_from_response(payload: Any) -> str:
    """ChatGPT OAuth backend returns a streaming JSON response. The shape
    varies — we look for the final assistant message text.
    """
    if not isinstance(payload, dict):
        return ""
    # Common shapes in OpenAI Responses API style:
    output = payload.get("output")
    if isinstance(output, list):
        for item in reversed(output):
            if isinstance(item, dict) and item.get("type") in ("message", "output_text"):
                content = item.get("content")
                if isinstance(content, list):
                    for c in content:
                        if isinstance(c, dict) and c.get("type") in ("output_text", "text"):
                            t = c.get("text")
                            if isinstance(t, str) and t.strip():
                                return t
                elif isinstance(content, str):
                    return content
    if isinstance(payload.get("text"), str):
        return payload["text"]
    if isinstance(payload.get("response"), str):
        return payload["response"]
    return ""


def _parse_panel_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    if text.startswith("```"):
        # Strip markdown fences
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    # Find JSON object if there's prose around it
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = text[start : end + 1]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    # Validate minimum fields
    required = ("hero", "scene_emoji", "scene_caption", "panel_caption", "next_move", "vibe")
    for field in required:
        if field not in parsed:
            parsed[field] = ""
    if "glossary" not in parsed or not isinstance(parsed["glossary"], dict):
        parsed["glossary"] = {}
    if "alt_emoji" not in parsed:
        parsed["alt_emoji"] = ""
    return parsed
