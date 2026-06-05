"""Generate model predictions for the LLMSVS adversarial gate by querying a served
OpenAI-compatible endpoint with Codex's batch request file.

The request rows are OpenAI batch format: {custom_id, method, url, body} where body
is a Python-dict-repr string {'max_tokens':..,'messages':[...]}. We POST each to the
endpoint and emit prediction rows the scorer understands: {case_id, content}
(score_llmsvs_adversarial_eval_iter5.py reads case_id + response/content).

  AEGISPT_EVAL_ENDPOINT=http://127.0.0.1:8810/v1/chat/completions \
  AEGISPT_LLMSVS_REQUESTS=/path/requests.jsonl \
  AEGISPT_LLMSVS_OUT=/path/predictions.jsonl python llmsvs_predict.py
"""
from __future__ import annotations

import ast
import json
import os
import urllib.request
from pathlib import Path

ENDPOINT = os.environ.get("AEGISPT_EVAL_ENDPOINT", "")
MODEL = os.environ.get("AEGISPT_EVAL_MODEL", "candidate")
REQUESTS = os.environ.get("AEGISPT_LLMSVS_REQUESTS",
                          str(Path.home() / ".aegispt-tools" / "training" /
                              "aegispt_llmsvs_prediction_requests_iter5.jsonl"))
OUT = os.environ.get("AEGISPT_LLMSVS_OUT", "/tmp/llmsvs_predictions.jsonl")


def _body(raw):
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return ast.literal_eval(raw)  # Codex emits a Python-dict repr


def _ask(messages, max_tokens):
    data = json.dumps({"model": MODEL, "messages": messages, "max_tokens": max_tokens,
                       "temperature": 0, "stream": False}).encode()
    req = urllib.request.Request(ENDPOINT, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())["choices"][0]["message"]["content"]


def main():
    if not ENDPOINT:
        raise SystemExit("set AEGISPT_EVAL_ENDPOINT")
    rows = [json.loads(line) for line in Path(REQUESTS).read_text().splitlines() if line.strip()]
    n_ok = 0
    with open(OUT, "w") as fh:
        for r in rows:
            body = _body(r.get("body", {}))
            msgs = body.get("messages", [])
            mt = int(body.get("max_tokens", 512))
            try:
                content = _ask(msgs, mt)
                n_ok += 1
            except Exception as e:
                content = f"__ERROR__ {e}"
            fh.write(json.dumps({"case_id": r.get("custom_id", ""), "content": content}) + "\n")
    print(f"[llmsvs_predict] {n_ok}/{len(rows)} predictions -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
