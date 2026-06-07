import json

from scripts.training import teacher_demonstration_gen as gen


def _assistant_payload(done, url="/admin/marker", state=None):
    return {
        "role": "assistant",
        "content": json.dumps(
            {
                "done": done,
                "next_action": {
                    "args": {"method": "GET", "url": url} if not done else {},
                    "tool": "lab_http_request" if not done else "none",
                },
                "state": state or {},
            },
            sort_keys=True,
        ),
    }


def _row(*, blocked=True, held_out=False):
    observed = "TOOL OBSERVATION: HTTP 403 blocked; hint: inspect /case for scoped token"
    if not blocked:
        observed = "TOOL OBSERVATION: pivot observed directly"
    marker = "flag{deep-eval-5b7c2}" if held_out else "AEGISPT_TEACHER_OK"
    return {
        "messages": [
            {"role": "system", "content": "synthetic lab"},
            {"role": "user", "content": "solve bounded fictional lab"},
            _assistant_payload(False),
            {"role": "user", "content": observed},
            _assistant_payload(False, "/case", {"pivot": "token"}),
            {"role": "user", "content": "TOOL OBSERVATION: token=CASE-TOKEN-1"},
            _assistant_payload(True, state={"marker": marker, "token_reused": True}),
        ]
    }


def test_teacher_skeleton_requires_blocked_goal_recovery_arc():
    assert gen._valid(_row(blocked=True)) is True
    assert gen._valid(_row(blocked=False)) is False


def test_teacher_skeleton_rejects_held_out_markers():
    assert gen._valid(_row(blocked=True, held_out=True)) is False


def test_teacher_skeleton_extracts_json_from_reasoner_prose():
    raw = 'thinking first\n```json\n{"messages":[{"role":"system","content":"ok"}]}\n```\nextra'

    assert gen._extract_messages_obj(raw) == '{"messages":[{"role":"system","content":"ok"}]}'


def test_teacher_skeleton_prompt_names_recovery_contract():
    assert "premature goal attempt" in gen.SYS
    assert "403/blocked" in gen.SYS
