# Kali / Modern-Offensive Tooling Gap Analysis — 2026-06-12

Research deliverable. Identifies **powerful tools AegisPT does NOT yet wrap** that would
materially expand real capability across web / LAN / WAN / AD / cloud / IoT / wireless /
recon / exploitation. Skeptical: only tools that fill a *genuine* gap vs the existing
~77 runners are listed. No code was modified.

Inventory source of truth: `workers/runners/*` (77 runner dirs) + `workers/runners/capabilities.json`
+ the `SUPPORTED_TOOLS` set in `workers/orchestration/tasks.py`.

---

## 1. What AegisPT ALREADY covers (so we don't recommend duplicates)

Grouped by the underlying tool/technique each runner wraps. This is the "do not duplicate" baseline.

| Domain | Existing runners (tool wrapped) |
|---|---|
| **Web recon/scan** | `httpx` (python-httpx probe), `nuclei`, `nikto`, `zap`, `burp` (disabled), `content-discovery` (bounded dirb-style), `waf-detect`, `headers-security`, `crypto-audit` (TLS), `vuln-components`, `target-intel` (AI fingerprint) |
| **Web exploit** | `sqlmap`, `xss-extended`, `xss-proof`, `stored-xss-probe`, `ssti-probe`, `xxe-probe`, `ssrf-probe`, `http-smuggling`, `deserialization-probe`, `file-upload-probe`, `param-pollution-probe`, `cookie-tamper-probe`, `info-disclosure-probe`, `logging-probe`, `idor-bac`, `client-state` |
| **Web auth / API** | `auth-flow`, `session-security`, `jwt-probe`, `oauth-probe`, `api-assessment`, `graphql-probe`, `graphql-command-injection`, `llm-probe`, `biz-logic-probe` |
| **Network recon** | `nmap`, `ipv6-discovery`, `mdns-ssdp`, `network-capture` (passive pcap/ARP), `network-segmentation` (reachability matrix), `snmp-enum`, `easm-discover` (subdomain/OSINT), `external-osint`, `external-infra` |
| **AD / identity** | `bloodhound-collect` (BloodHound collector), `ldap-enum`, `netexec` (nxc/SMB), `impacket-lateral`, `responder` (LLMNR/NBT-NS capture), `credential-attacks` (spray), `ssh-brute` (hydra), `leak-check` (imported leak metadata) |
| **Cloud** | `aws-inventory` (read-only boto3), `cloud-native` (k8s/manifest review) |
| **Host / privesc** | `priv-esc-linux` (LinPEAS-style signals), `ai-shell`, `metasploit` (controlled-proof) |
| **IoT / wireless** | `iot-default-creds`, `camera-test`, `smart-home`, `wifi-survey` (passive survey only) |
| **Code / supply chain** | `semgrep` (SAST), `cicd-security`, `desktop-client`, `mobile-android`, `pre-recon-source`, `pre-recon-cpg` (Joern CPG) |
| **AI exploit loop** | `interactive-exploit`, `code-exec-attack`, `exec-plan`, `exploit-developer-agent`, `ai-pentest-agent`, `smart-web-probe`, `recon-deliverable`, `lan-intel` |
| **Defensive / import-only** | `c2-ingest`, `malware-sim`, `social-campaign` |

**Net read:** web exploitation is *very* deep. AD has the **collection/lateral** primitives
(BloodHound, netexec, impacket, responder) but is **missing the modern AD-CS, Kerberos, and
coercion/relay attack layer**. Cloud is **read-only inventory only** — no multi-cloud audit, no
attack-path graphing, no offensive enumeration. There is **no pivoting/tunneling** capability at
all (segmentation is *measured*, never *traversed*). Secret-hunting exists only as `semgrep`
patterns + *imported* leak metadata — no live secret discovery/verification across repos/filesystems.

---

## 2. Tool survey — current & verified (June 2026)

Each entry verified against current project pages / 2025-2026 write-ups. Marked GAP only where no
existing runner overlaps.

- **Certipy** (`ly4k/Certipy`) — AD CS (ADCS) enumeration + abuse, full ESC1–ESC16 coverage. **GAP.** BloodHound/netexec don't request or forge certificates.
- **kerbrute** (`ropnop/kerbrute`) — unauthenticated Kerberos user-enum / password-spray / AS-REP discovery via AS-REQ pre-auth. **GAP** (no pre-auth Kerberos user-enum; `credential-attacks` is generic spray, `netexec` needs creds).
- **Coercer + mitm6 + ntlmrelayx** (the coercion→relay chain) — force a host to authenticate, then relay NTLM to LDAP/SMB/AD-CS. **GAP** (we *capture* with `responder` but never *coerce* or *relay*).
- **ligolo-ng** (`nicocha30/ligolo-ng`) — TUN-interface pivoting/tunneling; lets nmap/nxc/etc. run natively over a foothold into segmented networks. **GAP** (no pivot at all).
- **chisel** (`jpillora/chisel`) — HTTP-tunneled TCP/SOCKS pivot; firewall-friendly fallback to ligolo. **GAP** (same).
- **trufflehog** (`trufflesecurity/trufflehog`) — finds *and live-verifies* 700+ credential types across git/filesystem/S3/CI. **GAP** (`semgrep` ≠ secret verifier; `leak-check` is import-only).
- **Nosey Parker** (`praetorian-inc/noseyparker`) — ML-denoised secret scanner, very low FP, hundreds of MB/s. Overlaps trufflehog; pick one. Partial GAP.
- **ScoutSuite** (`nccgroup/ScoutSuite`) — multi-cloud (AWS/Azure/GCP/OCI/Alibaba) read-only security posture audit. **GAP** (`aws-inventory` is AWS-only + thin; nothing for Azure/GCP).
- **Prowler** (`prowler-cloud/prowler`) — multi-cloud CIS/NIST/PCI benchmark auditor, read-only. Overlaps ScoutSuite; pick one. Partial GAP.
- **CloudFox** (`BishopFox/cloudfox`) — finds *exploitable attack paths* in AWS/Azure (privesc, exposed resources, secrets in EC2 userdata). **GAP** (no cloud attack-path reasoning).
- **Pacu** (`RhinoSecurityLabs/pacu`) — AWS exploitation/post-exploitation framework ("Metasploit for AWS"). **GAP** but **intrusive** — lower priority for a read-first product.
- **katana** (`projectdiscovery/katana`) — next-gen JS-aware headless crawler; feeds endpoints/params to the exploit runners. **GAP** (`content-discovery` is path-bruteforce; `httpx` only parses static HTML; no JS/SPA route discovery).
- **ffuf** / **feroxbuster** — fast content + parameter/vhost fuzzers with recursion & filtering. Partial overlap with `content-discovery`; main delta is **parameter fuzzing** (discover injectable params the exploit runners need). Partial GAP.
- **subfinder** + **dnsx** (`projectdiscovery`) — fast passive subdomain enum + DNS resolution. Overlaps `easm-discover`/`external-osint`; mostly covered. **NOT a gap** (skip).
- **naabu** (`projectdiscovery`) — fast SYN/CONNECT port scanner. Overlaps `nmap`. **NOT a gap** (skip).
- **BloodHound CE** — already covered conceptually by `bloodhound-collect`; CE is a UI/DB upgrade, not a new capability. **NOT a gap** (skip).
- **WebGoat/firmware tooling (binwalk, firmwalker)** — IoT firmware extraction/static analysis. Real GAP but niche; below the cut line.

---

## 3. Prioritized recommendations — TOP 10

Effort key: **S** = wrap an existing CLI binary, parse JSON/text → findings (like `nuclei`/`netexec`);
**M** = CLI + multi-step orchestration or background process; **L** = stateful agent/long-running listener.

| # | Tool | What it does | Gap filled (domain) | Why high-impact | Integration effort | Scope / safety |
|---|------|--------------|---------------------|-----------------|--------------------|----------------|
| **1** | **Certipy** | Enumerate + abuse AD CS; ESC1–ESC16; request/forge certs → Kerberos TGT as any user | **AD** | AD-CS is the #1 modern AD privesc/persistence path; we have BloodHound/netexec but cannot *find or weaponize* cert misconfig — a glaring hole in an "AD-capable" product | **S–M**: `certipy find` is read-only JSON (easy); abuse paths (`req`/`auth`) are intrusive, gate behind 2-approval like `impacket-lateral` | `find` = active read; abuse = intrusive (cert request mutates CA state) → ROE + kill-switch |
| **2** | **trufflehog** | Find + **live-verify** 700+ secret types across git/fs/S3/CI/container | **recon/cloud/code** | Verified live creds are the highest-signal finding type; turns passive code access into real credential leads that feed `credential-attacks`/cloud. `semgrep`+`leak-check` don't verify or hunt | **S**: single Go binary, `--json` ndjson out → findings, same shape as `nuclei` | Verification makes outbound API calls to 3rd-party services → must be allowlist-gated; offer `--no-verification` passive mode |
| **3** | **ligolo-ng** | TUN-interface pivot into segmented internal networks; tools run natively over the foothold | **LAN/WAN/AD** | Unlocks *everything else* post-foothold. Today `network-segmentation` only *measures* unreachable subnets — AegisPT can't actually traverse them. Force-multiplier for nmap/netexec/Certipy | **L**: proxy + agent processes, TUN iface, session lifecycle (start/route/teardown) | Intrusive (establishes covert tunnel); strict scope-binding of routed CIDRs + mandatory teardown + kill-switch |
| **4** | **kerbrute** | Unauth Kerberos user-enum / password-spray / AS-REP discovery | **AD** | Stealthy pre-auth recon that needs *no creds*; bootstraps the whole AD chain (valid users → spray → AS-REP roast). No current pre-auth Kerberos enum | **S**: single binary, line output → findings | Spray = lockout risk → reuse `credential-attacks` lockout guard + ROE; user-enum alone is low-risk |
| **5** | **ScoutSuite** | Multi-cloud (AWS/Azure/GCP/OCI) read-only posture audit | **cloud** | AegisPT cloud = AWS-only thin inventory. ScoutSuite adds **Azure + GCP** and a real misconfig ruleset, read-only (safe-by-default) | **S–M**: CLI → JSON report dir → parse findings | Read-only API calls; needs scoped read creds; no mutation → low risk, low approval |
| **6** | **CloudFox** | Find exploitable **attack paths** in AWS/Azure (privesc, exposed endpoints, secrets in userdata) | **cloud** | Complements #5: posture→*paths*. Surfaces chained cloud privesc the inventory runner can't reason about | **S**: Go binary, JSON/loot out → findings | Read-only enumeration; scoped creds; pairs with ScoutSuite |
| **7** | **katana** | JS-aware headless crawler; discovers SPA routes/params/APIs | **web recon** | Feeds the deep web-exploit arsenal with endpoints it currently can't see (SPA/JS apps). `content-discovery` is wordlist brute; `httpx` only static HTML | **S–M**: binary, `-jsonl` out → routes feed exploit runners | Active crawl (rate-limit + scope-bind); honor robots/scope allowlist |
| **8** | **Coercer (+ntlmrelayx)** | Coerce host auth (MS-EFSR/MS-RPRN/…) then relay NTLM to LDAP/SMB/AD-CS | **AD** | Completes the capture→coerce→relay triad (`responder` is only step 1). With #1 enables ESC8 (relay-to-AD-CS) → domain takeover | **M–L**: coerce CLI + relay listener (background) + capture correlation | Highly intrusive (forces auth, relays creds) → 2-approval + explicit ROE + kill-switch; note CVE-2025-33073 limits SMB Kerberos relay |
| **9** | **feroxbuster** (or **ffuf**) | Recursive content + **parameter** fuzzing with smart filtering | **web recon** | Discovers injectable params/hidden endpoints the exploit runners need; current `content-discovery` lacks recursion + param fuzzing | **S**: binary, `--json` out → routes/params | Active fuzzing → strict rate-limit + scope; can be noisy (FP filtering needed) |
| **10** | **Pacu** | AWS exploitation/post-exploitation framework | **cloud** | Turns cloud findings into proven impact (S3 exfil sim, IAM privesc, EC2 impersonation) | **M–L**: module-driven framework, session state | **Intrusive** (mutates cloud state) → strictest gating; lowest priority for read-first product |

### Integrate FIRST — top 3

1. **Certipy** — closes the single biggest hole in AegisPT's AD story (AD-CS / ESC). It slots cleanly
   next to the existing AD runners (`bloodhound-collect`, `netexec`, `impacket-lateral`), reuses their
   credential/scope plumbing, and `certipy find` is a *safe read-only* first slice that delivers value
   before any intrusive abuse path is enabled.
2. **trufflehog** — highest signal-to-effort ratio in the whole list: a single binary with JSON output
   that converts AegisPT's existing source/artifact access into **verified live credentials**, which
   directly feed `credential-attacks` and the cloud runners. Pure additive capability, trivial wrap.
3. **ligolo-ng** — the force-multiplier: without a pivot, every LAN/AD/cloud-internal capability is
   stranded at the network edge. It transforms `network-segmentation`'s "here's what you *can't* reach"
   into "now reach it." Higher effort (session lifecycle), but it unblocks the entire post-foothold game.

> Deliberately ranked **above** the pure web-recon tools (katana/feroxbuster): AegisPT's web exploitation
> is already its deepest area, so marginal web-recon gains are smaller than opening up AD-CS, verified
> secrets, and pivoting — all areas where AegisPT currently has *no* equivalent capability.

---

## 4. Integration sketch — #1 Certipy (runner contract)

Studied `workers/runners/nuclei/runner.py` (shell-out + JSON parse + `RunnerExecution`),
`workers/runners/netexec/runner.py` (AD/creds plumbing, kill-switch, protected outputs),
`workers/runners/base/contracts.py` (`RunnerExecution` / `EvidenceArtifact` /
`ProtectedSecretMaterial`), and the dispatch/registration points
(`SUPPORTED_TOOLS` + the `if request.tool == ...` table in `workers/orchestration/tasks.py`).

**This is a sketch only — not an implementation.**

### 4.1 New file: `workers/runners/certipy/runner.py`

```python
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

CERTIPY_RESULTS_ARTIFACT = "certipy-find.json"
DEFAULT_BINARY = "certipy"
DEFAULT_TIMEOUT_SECONDS = 240.0

# First slice is FIND only (read-only ADCS enumeration). Abuse verbs
# (req/auth/forge) are intentionally NOT wired here — they are intrusive
# and must be gated behind the 2-approval ROE path like impacket-lateral.
_ALLOWED_MODES = {"find"}


def build_certipy_command(
    *,
    binary: str,
    mode: str,                       # "find"
    domain: str,
    dc_ip: str,
    username: str,
    output_stem: Path,
    vulnerable_only: bool = True,
) -> list[str]:
    if mode not in _ALLOWED_MODES:
        raise ValueError(f"certipy mode '{mode}' not allowed in this runner")
    # `certipy find -vulnerable -json` enumerates CA + templates and flags
    # ESC1..ESC16 misconfigurations. Read-only: it only queries LDAP + the CA.
    command = [
        binary, mode,
        "-u", username,              # creds come from auth_contexts (see dispatch)
        "-dc-ip", dc_ip,
        "-target", domain,
        "-json",
        "-output", str(output_stem),
    ]
    if vulnerable_only:
        command.append("-vulnerable")
    return command


def execute_certipy_find(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]],   # {username, password|hash, domain, dc_ip}
    binary: str = DEFAULT_BINARY,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Callable[[], bool] | None = None,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one AD target is required")
    if not auth_contexts:
        # No creds -> emit a benign blocked execution, mirror netexec's pattern.
        return RunnerExecution(
            tool="certipy", exit_code=0, stdout="", stderr="",
            metadata={"status": "blocked", "reason": "no_credentials_ref"},
        )
    if kill_switch_check and kill_switch_check():
        return RunnerExecution(
            tool="certipy", exit_code=0, stdout="", stderr="",
            metadata={"status": "blocked", "reason": "kill_switch_enabled"},
        )

    ctx = auth_contexts[0]
    findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="aegispt-certipy-") as tmp:
        stem = Path(tmp) / "certipy"
        command = build_certipy_command(
            binary=binary, mode="find",
            domain=ctx["domain"], dc_ip=ctx["dc_ip"], username=ctx["username"],
            output_stem=stem,
        )
        # Secret material (password/hash) is passed via env, NEVER argv,
        # so it can't leak into the redacted command record (netexec pattern).
        proc = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=max(timeout_seconds, 1.0),
            env=_certipy_env(ctx),
        )
        out_json = stem.with_suffix(".json")
        raw = out_json.read_bytes() if out_json.exists() else b"{}"

        # Each ESC* flagged template -> a finding the planner can act on
        # (e.g. ESC1 -> hand off to an intrusive certipy-abuse / impacket TGT step).
        for esc in _parse_esc_findings(raw):
            findings.append({
                "title": f"AD CS misconfiguration: {esc['esc_id']}",
                "severity": esc["severity"],          # ESC1/ESC8 -> CRITICAL
                "evidence": esc,                       # template, CA, enrollment rights
            })

    artifact = EvidenceArtifact(
        name=CERTIPY_RESULTS_ARTIFACT,
        content_type="application/json",
        data=raw,
        kind="adcs-enumeration",
    )
    return RunnerExecution(
        tool="certipy",
        exit_code=proc.returncode,
        stdout=json.dumps({"findings": findings}, sort_keys=True),
        stderr=proc.stderr[:4000],
        metadata={
            "status": "ok" if proc.returncode == 0 else "failed",
            "mode": "find",
            "vulnerable_template_count": len(findings),
            "runner_digest": "workers.certipy.runner:v1",
            "command": _redacted_command(command),   # creds were in env, not argv
        },
        artifacts=[artifact],
        # If `find` recovers usable cert/key material later (abuse verbs),
        # emit it as ProtectedSecretMaterial like netexec does — never plaintext.
        protected_outputs=[],
    )
```

Helpers `_certipy_env`, `_parse_esc_findings`, `_redacted_command` follow the exact patterns
already in `netexec/runner.py` (env-passed secrets, regex/JSON parse, argv redaction).

### 4.2 Registration (three edits — sketch only, not applied)

1. **`workers/runners/capabilities.json`** — add a capability entry:
   ```json
   {
     "name": "certipy",
     "category": "identity",
     "risk_tier": "active",
     "cost": "low",
     "description": "Enumerates AD CS (ADCS) for ESC1-ESC16 certificate-template misconfigurations using provided domain credentials. Read-only `certipy find`; abuse paths are gated separately.",
     "estimated_minutes": 8,
     "expected_evidence": ["adcs_inventory", "vulnerable_template_evidence", "esc_finding"],
     "false_positive_rate": "low",
     "triggers": ["active_directory_context", "ldap_service_present", "ca_endpoint_present"],
     "weak_triggers": ["smb_service_present"],
     "blockers": ["no_ad_context", "no_credentials_ref"],
     "follow_up_tools": ["bloodhound-collect", "impacket-lateral", "credential-attacks"],
     "required_approvals": 1,
     "prerequisites": ["approved_scope", "credentials_ref"]
   }
   ```
2. **`workers/orchestration/tasks.py`** — add `"certipy"` to the `SUPPORTED_TOOLS` set, and add a
   dispatch branch mirroring the `netexec` one (~line 1517):
   ```python
   if request.tool == "certipy":
       return execute_certipy_find(
           targets=request.targets,
           auth_contexts=request.params.get("auth_contexts", []),
           binary=os.getenv("CERTIPY_BINARY", "certipy"),
           scope_allowlist=request.scope_allowlist,
           timeout_seconds=timeout_seconds,
           kill_switch_check=execution_kill_switch_enabled,
       )
   ```
   plus the top-of-file import `from workers.runners.certipy.runner import execute_certipy_find`.
3. **`workers/runners/certipy/__init__.py`** — empty package marker (as every runner dir has).

### 4.3 Evidence emitted
- **stdout**: `{"findings": [...]}` — one finding per vulnerable template (ESC id, severity, CA,
  template name, enrollment rights), consumed by the planner the same way `netexec` findings are.
- **artifact** `certipy-find.json`: raw Certipy JSON (full ADCS inventory) for audit/replay.
- **metadata**: status, vulnerable_template_count, redacted command, runner_digest.
- **protected_outputs**: reserved for recovered cert/key material when abuse verbs are added later
  (kept out of plaintext via `ProtectedSecretMaterial`, exactly like `netexec`'s loot handling).

### 4.4 Why `find`-only first
`certipy find -vulnerable` is **read-only** (LDAP query + CA metadata) — it ships value (CRITICAL
ESC findings) with **active**, not **intrusive**, risk. The abuse verbs (`req`/`auth`/`forge`,
which mutate CA state and forge auth) are a **separate follow-up runner** gated behind the
2-approval ROE + kill-switch path used by `impacket-lateral` / `metasploit`. This mirrors how
`netexec` ships a safe `passive` mode before any intrusive mode — and matches the repo's
"read-first, gate the intrusive slice" posture.

---

## Sources
- [Certipy (ly4k/Certipy)](https://github.com/ly4k/Certipy) · [certipy.com](https://certipy.com/) · [AD CS ESC techniques (Vaadata)](https://www.vaadata.com/blog/ad-cs-security-understanding-and-exploiting-esc-techniques/) · [AD CS escalation (HackTricks)](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)
- [kerbrute](https://kerbrute.com/) · [Kerberoasting/AS-REP cheatsheet](https://www.hackingdream.net/2025/12/kerberoasting-and-as-rep-roasting-cheatsheet.html)
- [Coercer / NTLM relay 2025 guide](https://www.0xczr.com/tools/NTLM_Relay_Cheatsheet/) · [Windows coercion 2025 (RedTeam Pentesting)](https://blog.redteam-pentesting.de/2025/windows-coercion/) · [mitm6 + NTLM relay](https://cyberpress.org/mitm6-ntlm-relay-attack/)
- [ligolo-ng (nicocha30)](https://github.com/nicocha30/ligolo-ng) · [Chisel/Ligolo pivoting guide 2026](https://morimori-dev.github.io/posts/tech-chisel-ligolo-ligolo-mp/)
- [trufflehog (trufflesecurity)](https://github.com/trufflesecurity/trufflehog) · [Nosey Parker (praetorian-inc)](https://github.com/praetorian-inc/noseyparker)
- [ScoutSuite vs Pacu vs CloudFox (DeepStrike)](https://deepstrike.io/blog/best-tools-for-cloud-penetration-testing-in-2025) · [CloudFox (BishopFox)](https://github.com/BishopFox/cloudfox)
- [ProjectDiscovery (subfinder/dnsx/naabu/katana)](https://github.com/projectdiscovery) · [subfinder](https://github.com/projectdiscovery/subfinder)
