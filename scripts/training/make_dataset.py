"""Synthesize a GENERIC multi-step agentic tool-use dataset (JSON-action format).

Targets the empirically observed gap (XBEN-024, 2026-06-04): the local model does
the hard single-step exploit (SSRF reset) but does NOT follow through the plan —
it never logs in as the user whose password it just reset, loops on one step, and
declares done. So we teach GENERIC agentic discipline, not app-specific exploits:

  1. carry session state forward (Set-Cookie -> Cookie),
  2. after a state-changing action SUCCEEDS, ADVANCE to the dependent next step,
  3. reuse a value/credential revealed in an earlier observation,
  4. NEVER repeat an identical failing request — change the approach,
  5. when the goal state is reached, READ the target resource (then done).

Output: JSONL, one {"messages":[...]} conversation per line, mirroring the
interactive-exploit loop (system rules + alternating user-observation /
assistant-JSON-action turns).
"""
import json
import random

random.seed(2026)

SYSTEM = (
    "You are an authorized penetration-testing agent driving a target via ONE tool: "
    "http_request. Respond with EXACTLY one JSON object: "
    '{"reasoning":"...","request":{"method":"GET|POST","url":"...","headers":{},"body":"..."},"done":false}. '
    "Maintain a running PLAN. Carry session state (Set-Cookie -> Cookie) forward. "
    "After an action SUCCEEDS, advance to the NEXT plan step — never repeat it. "
    "Reuse credentials/tokens revealed in earlier responses. If a request fails the "
    "same way twice, CHANGE the approach. When the goal is reached, read it, then set done."
)

HOSTS = ["http://10.0.0.5", "http://target.lab", "http://app.internal:8080", "http://10.0.0.42:5000"]
USERS = ["alice", "bob", "carol", "dave", "operator", "svc_user"]
PRIV = ["admin", "root", "superuser", "manager"]
SECRETS = ["token", "api_key", "session", "reset_code", "otp"]
GOAL_PATHS = ["/dashboard", "/profile", "/account", "/admin/panel", "/settings"]


def J(reasoning, method=None, url=None, headers=None, body=None, done=False):
    req = None
    if url is not None:
        req = {"method": method or "GET", "url": url}
        if headers:
            req["headers"] = headers
        if body is not None:
            req["body"] = body
    obj = {"reasoning": reasoning, "request": req, "done": done}
    return json.dumps(obj)


def obs(status, headers=None, body=""):
    return "HTTP RESPONSE:\n" + json.dumps({"status": status, "headers": headers or {}, "body": body})


def traj_login_followthrough():
    """Login -> carry cookie -> reach a privileged page -> read it. Teaches
    state-carry + advance-after-success."""
    h = random.choice(HOSTS); u = random.choice(USERS); pw = "pw_" + str(random.randint(100, 999))
    goal = random.choice(GOAL_PATHS); cookie = "session=" + "".join(random.choice("abcdef0123456789") for _ in range(16))
    flag = "flag{" + "".join(random.choice("abcdef0123456789") for _ in range(8)) + "}"
    msgs = [{"role": "system", "content": SYSTEM}]
    msgs += [{"role": "user", "content": f"Goal: read {goal}. You have creds {u}:{pw}. Begin."}]
    msgs += [{"role": "assistant", "content": J(f"Log in as {u} to get a session.", "POST", f"{h}/login",
              {"Content-Type": "application/x-www-form-urlencoded"}, f"username={u}&password={pw}")}]
    msgs += [{"role": "user", "content": obs(302, {"set-cookie": cookie + "; Path=/", "location": goal})}]
    msgs += [{"role": "assistant", "content": J(f"Login succeeded (302, Set-Cookie). Advance: carry the cookie and read {goal}.",
              "GET", f"{h}{goal}", {"Cookie": cookie})}]
    msgs += [{"role": "user", "content": obs(200, {"content-type": "text/html"}, f"<h1>Welcome {u}</h1><div>{flag}</div>")}]
    msgs += [{"role": "assistant", "content": J(f"Goal page returned and contains the target value {flag}. Done.", done=True)}]
    return msgs


def traj_chain_then_relogin():
    """Generic: change another principal's credential via a privileged action, then
    LOG IN AS THAT PRINCIPAL (the exact follow-through the model missed), then read."""
    h = random.choice(HOSTS); victim = random.choice(PRIV); newpw = "np_" + str(random.randint(100, 999))
    goal = random.choice(GOAL_PATHS); acookie = "session=" + "".join(random.choice("abcdef0123456789") for _ in range(16))
    flag = "flag{" + "".join(random.choice("abcdef0123456789") for _ in range(8)) + "}"
    me = random.choice(USERS); mycookie = "session=" + "".join(random.choice("abcdef0123456789") for _ in range(16))
    msgs = [{"role": "system", "content": SYSTEM}]
    msgs += [{"role": "user", "content": f"Goal: read {victim}'s {goal}. There is a privileged /set_credential action you can reach; you are logged in as {me} (Cookie {mycookie})."}]
    msgs += [{"role": "assistant", "content": J(f"Step 1: set {victim}'s credential to a value I control.", "POST",
              f"{h}/set_credential", {"Cookie": mycookie, "Content-Type": "application/x-www-form-urlencoded"},
              f"user={victim}&newpassword={newpw}")}]
    msgs += [{"role": "user", "content": obs(200, {}, "credential updated")}]
    # the critical follow-through: now log in AS the victim, not repeat the set
    msgs += [{"role": "assistant", "content": J(f"Credential set succeeded. The plan now ADVANCES: log in AS {victim} with {newpw} (do not repeat the set).",
              "POST", f"{h}/login", {"Content-Type": "application/x-www-form-urlencoded"}, f"username={victim}&password={newpw}")}]
    msgs += [{"role": "user", "content": obs(302, {"set-cookie": acookie + "; Path=/", "location": goal})}]
    msgs += [{"role": "assistant", "content": J(f"Now authenticated AS {victim}. Carry the new cookie and read {goal}.",
              "GET", f"{h}{goal}", {"Cookie": acookie})}]
    msgs += [{"role": "user", "content": obs(200, {}, f"<h2>{victim} home</h2>{flag}")}]
    msgs += [{"role": "assistant", "content": J(f"Read {victim}'s page; target value {flag} present. Done.", done=True)}]
    return msgs


def traj_no_loop():
    """A request fails the SAME way twice -> the assistant CHANGES approach instead
    of repeating (directly counters the observed loop)."""
    h = random.choice(HOSTS); param = random.choice(["url", "redirect", "next", "callback"])
    inner = "http://127.0.0.1/internal?user=admin&grant=1"
    goal = random.choice(GOAL_PATHS); flag = "flag{" + "".join(random.choice("abcdef0123456789") for _ in range(8)) + "}"
    msgs = [{"role": "system", "content": SYSTEM}]
    msgs += [{"role": "user", "content": f"Goal: invoke an internal action via the {param} parameter on /fetch, then read {goal}."}]
    msgs += [{"role": "assistant", "content": J("Try the fetch with the internal URL as a normal value.", "GET",
              f"{h}/fetch?{param}={inner}")}]
    msgs += [{"role": "user", "content": obs(400, {}, "bad request: unexpected parameters")}]
    msgs += [{"role": "assistant", "content": J("400 — the '&' in the URL value split the query. Same error would repeat; CHANGE approach: percent-encode the '&' as %26 so it stays one value.",
              "GET", f"{h}/fetch?{param}=http://127.0.0.1/internal?user=admin%26grant=1")}]
    msgs += [{"role": "user", "content": obs(200, {}, "internal action executed")}]
    msgs += [{"role": "assistant", "content": J(f"Encoding fix worked; action executed. Advance: read {goal}.", "GET", f"{h}{goal}")}]
    msgs += [{"role": "user", "content": obs(200, {}, f"<div>{flag}</div>")}]
    msgs += [{"role": "assistant", "content": J(f"Target value {flag} present. Done.", done=True)}]
    return msgs


def traj_reuse_revealed_value():
    """Reuse a token revealed in an earlier response on the next request."""
    h = random.choice(HOSTS); sec = random.choice(SECRETS); val = "".join(random.choice("ABCDEF0123456789") for _ in range(12))
    goal = random.choice(GOAL_PATHS); flag = "flag{" + "".join(random.choice("abcdef0123456789") for _ in range(8)) + "}"
    msgs = [{"role": "system", "content": SYSTEM}]
    msgs += [{"role": "user", "content": f"Goal: read {goal}. First fetch /init which reveals a {sec}."}]
    msgs += [{"role": "assistant", "content": J(f"Fetch /init to obtain the {sec}.", "GET", f"{h}/init")}]
    msgs += [{"role": "user", "content": obs(200, {}, json.dumps({sec: val}))}]
    msgs += [{"role": "assistant", "content": J(f"Response revealed {sec}={val}. Reuse it as the auth header to read {goal}.",
              "GET", f"{h}{goal}", {"X-Auth": val})}]
    msgs += [{"role": "user", "content": obs(200, {}, f"{flag}")}]
    msgs += [{"role": "assistant", "content": J(f"Authenticated with the revealed {sec}; target value {flag} present. Done.", done=True)}]
    return msgs


def traj_deep_chain():
    """A LONG (6-8 step) multi-stage chain: recon -> register -> login -> explore
    -> IDOR a higher-privileged record -> reuse a token it LEAKED -> reach the
    gated resource -> extract. Teaches sustained coherent planning over depth,
    each step advancing on the LAST observation (no premature jumps, no re-login,
    no loops). Generic names/endpoints, parameterised."""
    h = random.choice(HOSTS)
    me = random.choice(USERS); pw = "pw_" + str(random.randint(100, 999))
    victim = random.choice(PRIV)
    cookie = "session=" + "".join(random.choice("abcdef0123456789") for _ in range(12))
    token = "TKN-" + "".join(random.choice("ABCDEF0123456789") for _ in range(8))
    rid = random.randint(2, 9)
    notes = random.choice(["/notes", "/records", "/orders", "/tickets"])
    gated = random.choice(["/admin/config", "/internal/secrets", "/admin/export"])
    flag = "flag{" + "".join(random.choice("abcdef0123456789") for _ in range(8)) + "}"
    hdr_name = random.choice(["X-Admin-Token", "X-Api-Key", "Authorization"])
    m = [{"role": "system", "content": SYSTEM},
         {"role": "user", "content": f"Goal: read the secret at {gated} on {h}. Start from nothing; explore, authenticate, pivot."}]
    # 1 recon
    m += [{"role": "assistant", "content": J("Recon the app surface first.", "GET", f"{h}/")}]
    m += [{"role": "user", "content": obs(200, {}, f"<a href={'/register'}>Register</a> <a href=/login>Login</a> <a href={notes}>{notes}</a> <a href={gated}>Admin</a>")}]
    # 2 register
    m += [{"role": "assistant", "content": J("No session yet. Register an account to get authenticated access.", "POST", f"{h}/register",
            {"Content-Type": "application/x-www-form-urlencoded"}, f"username={me}&password={pw}")}]
    m += [{"role": "user", "content": obs(200, {}, f"account created for {me}")}]
    # 3 login
    m += [{"role": "assistant", "content": J(f"Registered. Log in as {me} to obtain a session.", "POST", f"{h}/login",
            {"Content-Type": "application/x-www-form-urlencoded"}, f"username={me}&password={pw}")}]
    m += [{"role": "user", "content": obs(302, {"set-cookie": cookie + "; Path=/", "location": notes})}]
    # 4 explore with cookie
    m += [{"role": "assistant", "content": J(f"Logged in (Set-Cookie). Carry the cookie and list {notes} to map records.", "GET", f"{h}{notes}", {"Cookie": cookie})}]
    m += [{"role": "user", "content": obs(200, {}, f"your record #{rid} (yours). Other records: {notes}/1 ... {notes}/{rid}")}]
    # 5 IDOR a privileged record
    m += [{"role": "assistant", "content": J(f"Other records are referenced by id — try IDOR to {victim}'s record #1.", "GET", f"{h}{notes}/1", {"Cookie": cookie})}]
    m += [{"role": "user", "content": obs(200, {}, f"record #1 (owner {victim}): keep the {hdr_name}: {token}")}]
    # 6 try gated with user cookie (gets blocked) -> shows it needs the token
    m += [{"role": "assistant", "content": J(f"That leaked {victim}'s {hdr_name}={token}. Reuse it as the header to reach {gated}.",
            "GET", f"{h}{gated}", {hdr_name: token})}]
    m += [{"role": "user", "content": obs(200, {}, f"<config><secret>{flag}</secret></config>")}]
    # 7 read the flag, done
    m += [{"role": "assistant", "content": J(f"{gated} returned the secret {flag}. Goal reached.", done=True)}]
    return m


GENS = [traj_login_followthrough, traj_chain_then_relogin, traj_no_loop,
        traj_reuse_revealed_value, traj_deep_chain, traj_deep_chain]  # weight deep chains 2x


def main(n=600, out="/home/administrator/.aegispt-tools/training/agentic_followthrough.jsonl"):
    with open(out, "w") as f:
        for _ in range(n):
            msgs = random.choice(GENS)()
            f.write(json.dumps({"messages": msgs}) + "\n")
    print(f"wrote {n} trajectories -> {out}")


if __name__ == "__main__":
    main()
