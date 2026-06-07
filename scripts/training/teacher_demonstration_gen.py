#!/usr/bin/env python3
"""Teacher-demonstration generator (P1 skeleton — validated 2026-06-07).

A frontier TEACHER (DeepSeek V4-Pro) generates multi-turn agentic chains that SOLVE
authorized synthetic labs, as SFT rows ({"messages":[...]}). This is the now-unblocked
distillation lever: SFT on synthetic deterministic chains hit a generalization wall
(iter7-chaintype regressed the held-out deep-chain), so we need richer, teacher-quality
demonstrations.

Proven: V4-Pro emits a valid 9-message / 4-assistant-turn IDOR->token-reuse chain
(done=true) with concrete actions. This file is the SKELETON; Codex scales it
(diversity + volume) and runs every row through the V4-Pro demonstration ingest guard
(schema + held-out collision check) before it enters the SFT mix. See
docs/strategy/codex-handoff-2026-06-07.md.

Key: read DEEPSEEK_API_KEY from ~/.aegispt-secrets at runtime; NEVER echo/commit it.
V4-Pro reasons internally -> max_tokens must be generous (>=5000) or the JSON truncates.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-v4-pro"
SECRETS = os.path.expanduser("~/.aegispt-secrets")

# Held-out tokens that must NEVER appear in generated data (contamination guard).
HELD_OUT_FORBIDDEN = ["shop.lab", "/notes/", "/admin/config", "X-Admin-Token",
                      "flag{deep-eval-5b7c2}", "ADM-7741-KQ"]

SYS = (
    "You generate ONE training example for a pentest agent: a multi-turn agentic chain "
    "that SOLVES an authorized synthetic lab. Output EXACTLY one JSON object: "
    '{"messages":[{"role":"system","content":...},{"role":"user","content":...},'
    '{"role":"assistant","content":"<JSON action>"},{"role":"user","content":"<observation>"},...]} '
    'where each assistant turn is a JSON action {"next_action":{"args":{"method","url"}},"done":bool}, '
    "state is carried forward, and the LAST assistant turn has done=true after reaching the goal. "
    "Do NOT use any of: " + ", ".join(HELD_OUT_FORBIDDEN) + "."
)


def _api_key():
    with open(SECRETS) as fh:
        m = re.search(r"DEEPSEEK_API_KEY=(\S+)", fh.read())
    if not m:
        raise SystemExit("DEEPSEEK_API_KEY not found in ~/.aegispt-secrets")
    return m.group(1)


def _extract_messages_obj(s):
    """Balanced-brace extraction anchored at {"messages" (reasoners emit prose first)."""
    if "```" in s:
        parts = s.replace("```json", "```").split("```")
        s = max(parts, key=len)
    start = s.find('{"messages"')
    if start < 0:
        m = re.search(r'\{\s*"messages"', s)
        if not m:
            return None
        start = m.start()
    depth = 0
    instr = esc = False
    for i in range(start, len(s)):
        c = s[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            instr = not instr
            continue
        if instr:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[start:i + 1]
    return None


def generate(chain_type, lab_hint, max_tokens=5000, temperature=0.4):
    """Return a validated {"messages":[...]} row, or None on failure."""
    user = (f"Chain type: {chain_type}. Lab: {lab_hint}. 4-6 assistant turns. "
            "Respond with ONLY the JSON object on the first line, no preamble or reasoning text.")
    body = json.dumps({"model": MODEL,
                       "messages": [{"role": "system", "content": SYS},
                                    {"role": "user", "content": user}],
                       "max_tokens": max_tokens, "temperature": temperature}).encode()
    req = urllib.request.Request(ENDPOINT, data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + _api_key()})
    msg = json.loads(urllib.request.urlopen(req, timeout=240).read().decode())["choices"][0]["message"]
    txt = msg.get("content") or msg.get("reasoning_content") or ""
    obj = _extract_messages_obj(txt)
    if not obj:
        return None
    try:
        row = json.loads(obj)
    except Exception:
        return None
    return row if _valid(row) else None


def _valid(row):
    if not isinstance(row, dict) or "messages" not in row:
        return False
    msgs = row["messages"]
    if not isinstance(msgs, list) or sum(1 for m in msgs if m.get("role") == "assistant") < 2:
        return False
    blob = json.dumps(row)
    if any(tok in blob for tok in HELD_OUT_FORBIDDEN):  # contamination guard
        return False
    return "done" in str(msgs[-1].get("content", ""))


# Default diversity set; Codex expands this for scale (P1).
CHAIN_TYPES = [
    ("IDOR object-swap -> steal another user's token -> reuse it for a privileged read", "a fictional notes app"),
    ("SSRF to an internal metadata endpoint -> extract a credential -> privileged action", "a fictional image-proxy service"),
    ("low-priv account -> privilege escalation -> read an admin-only resource", "a fictional ticketing app"),
    ("info disclosure in an error page -> credential reuse -> lateral move", "a fictional CI dashboard"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1, help="rows per chain type")
    ap.add_argument("--out", default="", help="append JSONL path (omit = print one + exit)")
    args = ap.parse_args()
    if not args.out:
        row = generate(*CHAIN_TYPES[0])
        if not row:
            print("generation failed"); sys.exit(1)
        ac = sum(1 for m in row["messages"] if m.get("role") == "assistant")
        print(f"VALID row: {len(row['messages'])} msgs, {ac} assistant turns")
        return
    ok = 0
    with open(args.out, "a") as fh:
        for ct, lab in CHAIN_TYPES:
            for _ in range(args.n):
                row = generate(ct, lab)
                if row:
                    fh.write(json.dumps(row) + "\n")
                    ok += 1
                    print(f"  ok: {ct[:40]}...")
                else:
                    print(f"  FAIL: {ct[:40]}...")
    print(f"wrote {ok} validated demonstrated rows -> {args.out}")


if __name__ == "__main__":
    main()
