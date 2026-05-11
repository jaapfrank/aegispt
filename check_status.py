import json
import urllib.request


def req(method, path, data=None):
    r = urllib.request.Request(
        "http://127.0.0.1:8000" + path,
        json.dumps(data or {}).encode() if data else None,
        {"Content-Type": "application/json", "X-Actor": "operator-ui"},
        method=method,
    )
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode(), e.code

engs, _ = req("GET", "/api/v1/engagements?limit=10")
for eng in engs:
    eid = eng["id"]
    runs, _ = req("GET", f"/api/v1/engagements/{eid}/runs?limit=5")
    for run in runs:
        status = run.get("status", "?")
        if status in ("running", "queued", "cancelling"):
            rid = run["id"]
            profile = (run.get("profile") or {}).get("name", "?")
            print(f"\nEngagement: {eng['name'][:50]}")
            print(f"Run: {rid}")
            print(f"Status: {status} | Profile: {profile}")

            # Try force cancel
            if status in ("running", "cancelling"):
                r, s = req("POST", f"/api/v1/runs/{rid}/cancel")
                print(f"Cancel attempt: HTTP {s} -> {str(r)[:80]}")

            tasks = run.get("tasks") or []
            for task in tasks:
                ts = task.get("status", "?")
                print(f"  Task: {task.get('tool','?')} | {ts} | id: {task.get('id','?')[:8]}...")
