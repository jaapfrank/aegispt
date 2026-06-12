# Broad-Scope Activation Roadmap (LAN / WAN / AD / Cloud / IoT / Wireless)

**Date:** 2026-06-12
**Author:** broad-scope audit (read-only)
**Scope of this doc:** honest audit of the ~33 non-web "frozen" runners + a staged roadmap to make
credible non-web engagements first-class **without** undoing the 2026-06-11 web/API picker focus.

> **Method note (read first):** the authoritative current state is the `clean-slate-2026-06-11`
> branch (74 runners, `_FROZEN_PICKER_TOOLS` present in source). The checked-out worktree is a
> sparse stub (5–7 runner dirs); all file:line citations below are against the `clean-slate-2026-06-11`
> tree. Nothing in this audit modifies runtime code.

---

## 0. TL;DR

- **The non-web capability is NOT deleted and is mostly real code.** All 33 frozen tools are live
  `SUPPORTED_TOOLS` entries (`workers/orchestration/tasks.py:247`), each backed by a runner module
  with a real dispatch branch and (in almost every case) a deterministic test file. The 2026-06-11
  change is **picker-menu gating only** (`assessment_loop.py:6101` `_FROZEN_PICKER_TOOLS`), exactly
  as the in-code comment claims.
- **The binding constraint is NOT runner code — it is the AI loop's inability to *iterate* on a
  non-web engagement.** Seeds and the goal-oriented chain can still *dispatch* frozen tools, but the
  picker — the only component that reacts to findings and decides "given this SMB host, run BloodHound
  next" — is hard-blocked from every LAN/AD/cloud/IoT tool. A LAN engagement therefore runs its static
  seed chain and then stalls; it cannot do emergent recon→exploit chaining the way web engagements do.
- **Highest-leverage single change:** introduce an **engagement-mode → active-tool-set** switch so the
  picker menu is `supported_tools − (frozen tools NOT in this engagement's surface)` instead of the
  flat `supported_tools − _FROZEN_PICKER_TOOLS`. The domain taxonomy needed to drive this **already
  exists** as `SURFACE_RULES` in `api/app/services/coverage_truth.py:23` (web/api/internal_network/
  cloud/iot_lan/wifi_wireless/intrusive_validation, each with `target_kinds` + `representative_tools`).
  This is a wiring job, not a new subsystem.

---

## 1. How tool selection works today (the gating architecture)

Five facts establish exactly what was narrowed and what was left intact:

1. **`SUPPORTED_TOOLS`** (`workers/orchestration/tasks.py:247-331`) is the complete dispatch table —
   all 33 non-web tools are present. `dispatch_runner` (`tasks.py:340`) has a real `if request.tool ==`
   branch for each (e.g. `aws-inventory` → `execute_aws_inventory` at `tasks.py:355`; `cloud-native`,
   `cicd-security`, `mobile-android`, `desktop-client` branches follow). **Dispatch is untouched.**

2. **Target typing is mature and complete.** `_target_kind_for_value` (`ai_agent.py:2439`) classifies a
   raw value into `url / cidr / host / domain` via `ipaddress`. The scope allowlist already accepts
   `cidrs, hosts, ip_addresses, ldap_hosts, ad_domains, aws_accounts, apk_paths, container_images,
   wireless sites, …` (`runs.py:39` `TARGET_KEY_MAP`). `derive_targets_for_run` (`runs.py:291`) carries
   `{kind,value}` dicts into the loop, and `_target_type` (`assessment_loop.py:5021`) collapses them to
   `cidr / url / ip_or_host / domain`. **Target typing is NOT the gap.**

3. **A hardcoded per-objective recon seed already includes the full AD chain.**
   `_goal_tool_sequence` (`assessment_loop.py:5338`):
   - `identity_admin_objective` → `["nmap","ldap-enum","bloodhound-collect","netexec","credential-attacks"]`
   - `data_access` / `sensitive_file` pick `nmap` first when `target_type in {cidr, ip_or_host}`.
   `_objective_type` (`assessment_loop.py:5320`) routes to `identity_admin_objective` when the objective
   text mentions *"domain admin / active directory / kerberos / ldap / bloodhound"*. So an AD engagement
   **can** seed the AD recon chain today — purely off objective text.

4. **The goal-oriented + seed dispatchers are NOT subject to the freeze.** `_goal_oriented_candidate`
   (`assessment_loop.py:5642`), the `_lan_intel_candidate` seed (`assessment_loop.py:7088`, fired after
   nmap, with `follow_up_hints=["bloodhound-collect","ldap-enum","ssh-brute","credential-attacks"]`), and
   the `_target_intel_candidate` seed all gate on `tool in supported_execution_tools()` — **not** minus
   `_FROZEN_PICKER_TOOLS`. So the *static* chain steps can still queue frozen tools.

5. **Only the AI picker menu is frozen.** `assessment_loop.py:7228`:
   ```python
   available_tools = supported_execution_tools() - _FROZEN_PICKER_TOOLS
   ```
   and the picker prompt instructs *"Pick exactly ONE tool from available_tools"*
   (`picker_system_prompt.py:298`). The picker is the **only** component that reacts to *findings* and
   chooses the next tool. Freezing the LAN/AD/cloud/IoT tools out of it means: the seed chain can fire a
   fixed sequence, but the moment the chain needs an emergent decision ("BloodHound shows a Kerberoastable
   SPN → run `credential-attacks` with GetUserSPNs"), the picker has no AD tool to offer and the
   engagement degrades to web-only candidates or stops.

**Net:** the freeze is correctly minimal and reversible, but it severs the *intelligence* layer for
non-web work. Static seed dispatch ≠ a credible engagement; the loop's whole value is adaptive chaining.

---

## 2. Inventory of the frozen / non-web runners (grouped by domain)

Maturity tiers used below:
- **REAL (binary-backed)** — shells out to a real industry tool; degrades to a config-skip if the binary
  is absent.
- **REAL (lib/native)** — uses a real Python lib (boto3/ldap3/pysnmp) or raw sockets; needs creds/iface.
- **REAL (analysis-of-input)** — genuine logic, but consumes operator-supplied artifacts/telemetry rather
  than performing live acquisition (static-only).
- **STUB / foundation-slice** — explicitly defers live acquisition ("intentionally unavailable in this
  slice"); parses fixtures only.

Evidence columns: `sub` = count of subprocess/shell-out call sites; `tests` = `def test_` in the
runner's test file. (`-` = no dedicated `test_<name>_runner.py`; some are covered indirectly.)

### Active Directory / identity
| Tool | Module | Real tool wrapped | Tier | sub | tests |
|---|---|---|---|---|---|
| `bloodhound-collect` | `bloodhound/runner.py` | `bloodhound-python` collector | REAL (binary) | 3 | 3 |
| `ldap-enum` | `ldap_enum/runner.py` | `ldap3` live bind/search (`runner.py:283-318`) | REAL (lib) | 0 | 7 |
| `netexec` | `netexec/runner.py` | `nxc smb` (`runner.py:147`) | REAL (binary) | 5 | 4 |
| `impacket-lateral` | `impacket/runner.py` | `secretsdump.py / psexec.py / wmiexec.py` (`runner.py:152`) | REAL (binary) | 3 | 5 |
| `credential-attacks` | `credential_attacks/runner.py` | `GetUserSPNs.py / GetNPUsers.py / hashcat / kerbrute` (`runner.py:355`) | REAL (binary) | 3 | -¹ |
| `responder` | `responder/runner.py` | `Responder` LLMNR/NBT-NS (`runner.py:66`) | REAL (binary) | 7 | 3 |

¹ `credential-attacks` is referenced by 3 test files (dispatch/integration) but has no dedicated unit file.

### LAN / WAN / network recon + post-exploit
| Tool | Module | Real tool wrapped | Tier | sub | tests |
|---|---|---|---|---|---|
| `nmap` | `nmap/runner.py` | `nmap -n …` (`runner.py:203`) | REAL (binary) | — | yes |
| `lan-intel` | `lan_intel/runner.py` | AI analysis of nmap stdout (no live acquisition itself) | REAL (analysis) | 0 | - |
| `snmp-enum` | `snmp_enum/runner.py` | `pysnmp` walk; notes "pysnmp not installed" (`runner.py:212,520`) | REAL (lib) | 0 | 6 |
| `mdns-ssdp` | `mdns_ssdp/runner.py` | raw multicast sockets (`runner.py:545`) | REAL (native) | 0 | 4 |
| `ipv6-discovery` | `ipv6_discovery/runner.py` | IPv6 neighbour/discovery | REAL | 2 | 4 |
| `network-capture` | `network_capture/runner.py` | `tcpdump / arping / arpspoof` (binary group, matrix) | REAL (binary) | 12 | 8 |
| `network-segmentation` | `network_segmentation/runner.py` | subprocess + socket reachability probes (`runner.py:221,256`) | REAL | 5 | 5 |
| `priv-esc-linux` | `priv_esc_linux/runner.py` | ssh + sshpass binary enum (`runner.py:615`) | REAL (binary) | 3 | 3 |
| `ssh-brute` | `ssh_brute/runner.py` | `hydra` (`runner.py:356`) | REAL (binary) | 4 | 4 |

### Cloud / external infra / supply-chain
| Tool | Module | Real tool wrapped | Tier | sub | tests |
|---|---|---|---|---|---|
| `aws-inventory` | `aws_inventory/runner.py` | `boto3` live API (`runner.py:124`); needs creds | REAL (lib) | 0 | 4 |
| `cloud-native` | `cloud_native/runner.py` | K8s manifest analysis; **no live cluster calls** (`runner.py:64` skip) | REAL (analysis) | 0 | 5 |
| `cicd-security` | `cicd_security/runner.py` | pipeline-config analysis; skips w/o supplied config (`runner.py:739-762`) | REAL (analysis) | 0 | 5 |
| `external-infra` | `external_infra/runner.py` | orchestrates httpx + nmap observations (`runner.py:16`) | REAL (web-adjacent) | 0 | 4 |
| `easm-discover` | `easm/runner.py` | external attack-surface discovery | REAL | 3 | 3 |
| `external-osint` | (maps to `web_depth/runner`) | OSINT passive | REAL (web-adjacent) | — | indirect |

### IoT / smart-home / wireless / mobile / physical
| Tool | Module | Real tool wrapped | Tier | sub | tests |
|---|---|---|---|---|---|
| `iot-default-creds` | `iot_default_creds/runner.py` | live HTTP default-cred probing (`runner.py:502+`) | REAL (native) | 0 | 6 |
| `smart-home` | `smart_home/runner.py` | live sockets + httpx (`runner.py:132,186`) | REAL (native) | 0 | 4 |
| `camera-test` | `camera_test/runner.py` | UDP/RTSP sockets + httpx (`runner.py:150,179,211`) | REAL (native) | 0 | 4 |
| `mobile-android` | `mobile_android/runner.py` | **static** APK analysis; skips w/o APK (`runner.py:573`) | REAL (analysis, static-only) | 0 | 5 |
| `desktop-client` | `desktop_client/runner.py` | artifact analysis; skips w/o artifact (`runner.py:440`) | REAL (analysis) | 0 | 4 |
| `wifi-survey` | `wifi_survey/runner.py` | **"live RF scanning intentionally unavailable in this foundation slice"** (`runner.py:451`); fixtures only | **STUB / foundation-slice** | 0 | 3 |

### Offensive infrastructure / red-team simulation
| Tool | Module | Nature | Tier | sub | tests |
|---|---|---|---|---|---|
| `metasploit` | `metasploit/runner.py` | `msfrpcd` RPC, curated safe modules only (`runner.py:189`) | REAL (binary, bounded) | 7 | 4 |
| `c2-ingest` | `c2_ingest/runner.py` | ingests/parses C2 telemetry (no acquisition) | REAL (analysis) | 0 | -¹ |
| `malware-sim` | `malware_sim/runner.py` | reviews supplied lab telemetry for detection gaps (`runner.py:142`) | REAL (analysis) | 0 | -¹ |
| `social-campaign` | `social_campaign/runner.py` | redacts/hashes PII; planning only, **not a live sender** (by design) | REAL (analysis, safety-bounded) | 0 | -¹ |

¹ covered indirectly (1 referencing test file each) but no dedicated unit file.

### Web-adjacent tools also in the freeze (NOT part of the non-web vision)
`zap`, `nikto`, `waf-detect` are frozen as *"heavy passive scanners de-emphasized by No-Exploit-No-Report"*
(`assessment_loop.py:6116`). These are web tools intentionally de-prioritised, not LAN/cloud capability;
out of scope for this roadmap except to note the freeze rationale differs.

---

## 3. Honest quality verdict per domain

The repo has a formal **certification matrix** (`scripts/build_runner_tool_certification_matrix.py`,
asserted by `workers/tests/test_runner_tool_certification_matrix.py`) that classifies every runner as
`certified / supported-with-gap / blocked`. **Important caveat:** that status measures *software
readiness* (deterministic test + declared artifact contract + a finding/inventory mapping), **not**
empirical proof against a live target. A tool can be `certified` and still never have fired against a
real AD forest or AWS account. The XBOW solve history (MEMORY.md) is **entirely web** — there is no
recorded live LAN/AD/cloud/IoT solve. So the most honest framing is two axes: *code maturity* (high for
most) vs *live-validation* (near-zero outside web).

| Domain | Verdict | Why |
|---|---|---|
| **AD / identity** | **SOLID (code) / UNPROVEN (live)** | Real, complete arsenal: BloodHound, ldap3, NetExec, Impacket (secretsdump/psexec/wmiexec), Kerberoast/AS-REP-roast via GetUserSPNs/GetNPUsers + hashcat/kerbrute, Responder. Seed chain (`identity_admin_objective`) already wires nmap→ldap→bloodhound→netexec→creds. Strong tests. **No live forest run on record; binaries must be present on the worker host.** |
| **LAN / WAN** | **SOLID (code) / UNPROVEN (live)** | nmap, snmp (pysnmp), mDNS/SSDP (raw sockets), IPv6 discovery, network-capture (tcpdump/arp), segmentation probing, ssh-brute (hydra), priv-esc-linux. `lan-intel` AI-analysis seed exists. Real and tested. Same live-validation gap. |
| **Cloud** | **THIN-TO-MODERATE** | `aws-inventory` is real boto3 (needs creds). `cloud-native` and `cicd-security` are **analysis-of-supplied-input only** — no live cluster/registry enumeration, no Azure/GCP, no live IAM-misconfig attack path. Credible for *config review*, not for *active cloud exploitation*. |
| **IoT / smart-home** | **MODERATE** | `iot-default-creds`, `smart-home`, `camera-test` do real live HTTP/socket/RTSP probing with a default-cred DB — genuinely usable on a LAN once `mdns-ssdp` feeds an inventory. Solid first slice; no MQTT/CoAP/Zigbee/BLE breadth. |
| **Wireless** | **MISSING (stub)** | `wifi-survey` explicitly disables live RF capture ("foundation slice", `runner.py:451`); certification matrix marks it `blocked` on a hardware lab requirement. Fixture parser only. **Treat as not-yet-a-capability.** |
| **Mobile / desktop** | **THIN** | `mobile-android` is static APK analysis only (no dynamic/Frida/emulator); `desktop-client` is artifact analysis. Useful but narrow. |
| **Red-team infra (C2/malware/social)** | **INTENTIONALLY BOUNDED** | `metasploit` is curated-safe-modules + bounded proof; `c2-ingest`/`malware-sim`/`social-campaign` are analysis/planning, deliberately not live attack senders (safety posture). Fine as-is; do not "unstub" without an explicit RoE decision. |

**One-line per domain:** AD = **solid (code), unproven (live)** · LAN/WAN = **solid (code), unproven (live)** ·
Cloud = **thin** · IoT = **moderate** · Wireless = **missing/stub** · Mobile/Desktop = **thin** ·
Red-team-sim = **intentionally bounded**.

---

## 4. The gap to first-class non-web engagements

What is **already present** (do not rebuild):
- Target typing (`url/cidr/host/domain` + cloud/mobile/container kinds) — `runs.py:39`, `ai_agent.py:2439`.
- Scope allowlist that expresses those kinds — `TARGET_KEY_MAP`.
- Per-objective recon seeds incl. the AD chain — `_goal_tool_sequence`.
- A LAN intelligence seed that fires after nmap and hints AD tools — `_lan_intel_candidate`.
- Frozen-tool dispatch, validation, and tests — untouched.
- **A domain taxonomy** mapping surface → `target_kinds` + `representative_tools` —
  `coverage_truth.py:23` `SURFACE_RULES` (web_application, api, internal_network, cloud, iot_lan,
  wifi_wireless, intrusive_validation).

What is **missing** (the actual work):
1. **No engagement-mode concept.** There is no `engagement_mode` field on a run/scope (confirmed: no
   `engagement_mode`/`engagement_type` token exists in `api/app/services`). The picker menu is the flat
   `supported_tools − _FROZEN_PICKER_TOOLS` regardless of whether the target is a CIDR or a URL.
2. **The picker can't iterate on non-web findings.** Because every LAN/AD/cloud/IoT tool is frozen out
   of `available_tools`, the loop cannot do finding-driven chaining for these domains — the single most
   valuable behaviour the loop provides.
3. **No per-domain "intelligence seed" parity.** Web has `target-intel` (analyse site → plan). LAN has a
   partial `lan-intel` (post-nmap). AD/cloud/IoT have no equivalent "analyse the surface → propose the
   next exploit step" seed feeding the picker.
4. **Live validation is absent.** No recorded end-to-end LAN/AD/cloud run; binary availability on the
   worker host (`nxc`, `bloodhound-python`, impacket scripts, `hydra`, `msfrpcd`, `snmpwalk`) is asserted
   only by the certification matrix's host-probe, not by a green live engagement.

---

## 5. Staged activation roadmap

Design principle: **gate by engagement surface, not by a global freeze.** Keep web the default; make the
non-web tool set light up only when the engagement's targets/objective say so. Reuse `SURFACE_RULES` as
the single source of truth.

### Stage A — Engagement-mode switch + scoped picker menu (unlocks LAN+AD end-to-end)
The smallest change that makes a credible LAN+AD engagement possible.

1. **Derive an active surface set for the run** from existing signals (no new operator UI required to
   start): the run's `target_kinds` (via `derive_targets_for_run`) + objective text. Map through
   `SURFACE_RULES` (`coverage_truth.py:23`): a CIDR/host/ad_domain target ⇒ `internal_network`
   (+ `intrusive_validation` if `autonomous_intrusive_allowed`); an `aws-account` ⇒ `cloud`; a
   url/domain ⇒ `web_application`/`api`. Optionally let the operator pin an explicit
   `engagement_mode` in run config to override the inference.
2. **Replace the flat freeze in the picker** (`assessment_loop.py:7228`). Instead of
   `supported_tools − _FROZEN_PICKER_TOOLS`, compute
   `supported_tools − (frozen tools whose surface is NOT in the active set)`. For a pure web run this is
   byte-for-byte the current behaviour (web surface ⇒ all LAN/AD/cloud/IoT stay hidden); for an
   `internal_network` run, `nmap/ldap-enum/bloodhound-collect/netexec/impacket-lateral/lan-intel/snmp-
   enum/responder/ssh-brute/priv-esc-linux` become pickable.
3. **Keep the `intrusive_validation` surface behind the existing approval gate** (`requires_explicit_signal`
   is already set on that rule) — Responder/Impacket/Metasploit only enter the menu when the operator
   opted into autonomous-intrusive.
4. **No new runner code.** Seeds, dispatch, tests unchanged.

**Acceptance criteria (Stage A):**
- A web-only run's `available_tools` set is identical pre/post change (snapshot test).
- A run scoped to a CIDR + objective "compromise the Active Directory domain" produces, in one loop:
  `nmap → lan-intel → ldap-enum/bloodhound-collect → netexec/credential-attacks`, with at least one
  **picker-elected** AD tool (not just the static seed) chosen in response to a prior finding.
- A `PROOF_EXEC_*` log marker on the new menu-scoping branch fires on a live LAN run and is grep-able in
  the API log (per the repo's log-entry-proof convention).
- Worker-host binary check (certification matrix `software_readiness`) green for the AD/LAN binary
  groups, OR the run cleanly emits `exit_code=78` skips that the picker hides — never silent no-ops.

### Stage B — Per-domain intelligence seed parity (makes the chain *smart*, not just *ordered*)
Give LAN/AD (then IoT, then cloud) the `target-intel`-equivalent that turns observations into the next
exploit step and feeds the picker.

1. Promote `lan-intel` from a single post-nmap hint into a recurring "analyse current LAN/AD evidence →
   propose next tool+target with rationale" seed, mirroring `_target_intel_candidate`.
2. Add an `ad-intel` analysis pass over BloodHound/ldap output (Kerberoastable SPNs, AS-REP-roastable
   users, unconstrained delegation → propose `credential-attacks` with the right impacket sub-tool).
3. Surface these as picker `follow_up_hints` so the loop's emergent decisions stay evidence-driven.

**Acceptance:** on a lab AD forest, the loop reaches a credential/lateral finding via a chain where ≥2
steps were picker-elected from intel output, not seed-fixed.

### Stage C — IoT engagement
Wire `iot_lan` surface: `mdns-ssdp` discovery → builds device inventory → `iot-default-creds` +
`smart-home` + `camera-test` against discovered hosts. These runners are already live-capable.
**Acceptance:** a CIDR run with IoT objective discovers a device via mDNS/SSDP and lands a default-cred
or no-auth finding on it, picker-elected.

### Stage D — Cloud engagement (requires real runner work, not just wiring)
`aws-inventory` (boto3) is wireable now (needs a creds-ref in scope). But `cloud-native`/`cicd-security`
are analysis-only; first-class cloud exploitation needs **new** live-enumeration capability (live K8s
API, IAM privesc path-finding, Azure/GCP). Treat Stage D as a capability-build, not an activation.
**Acceptance:** `aws-inventory` runs against a sandbox account creds-ref and emits an IAM/S3 misconfig
finding; a follow-up exploit step is picker-elected. (Live K8s/Azure/GCP tracked as new runners.)

### Wireless — explicitly deferred
`wifi-survey` is a stub + hardware-blocked. Do not advertise wireless as a capability until a
monitor-mode adapter lab exists and the runner gains real `iw/airodump-ng/aircrack-ng` acquisition. Keep
it `blocked` in the matrix.

---

## 6. Tie-in to the "specialist via winning trajectories" method

The same trajectory-harvest→train loop that produces web specialists generalises directly, and **only
becomes possible once Stage A lets the picker drive these domains**:

- Today, winning trajectories can only be harvested for web because the picker only makes decisions for
  web. There is no LAN/AD trajectory data because the loop never *chooses* AD tools — it only replays a
  static seed. **Stage A is the prerequisite for any non-web specialist training.**
- Once the picker elects AD/LAN/IoT tools against lab targets (BloodHound test forests, IoT lab subnets),
  each solved engagement yields a multi-turn trajectory (`nmap → lan-intel → ldap → bloodhound →
  GetUserSPNs → hashcat → secretsdump`) in exactly the agentic, multi-turn shape the training pipeline
  needs — and which the project's own retro (MEMORY: *"multi-step gap is the frontier"*) identifies as
  the real lever over single-turn data.
- Recommend a per-surface eval split (an `internal_network` / `ad` deep-chain env alongside the existing
  web deep-chain) so a non-web specialist's promotion gate measures multi-step persistence on its own
  domain, not web — otherwise the promotion gate false-positives exactly as the shallow web eval did.

---

## 7. The single highest-leverage change

**Make the picker's `available_tools` engagement-surface-scoped (Stage A, step 2), driven by the existing
`SURFACE_RULES` taxonomy.** It is a localized change at `assessment_loop.py:7228`, requires no new runner
code, is byte-for-byte non-regressive for web runs, and is the unlock for (a) credible LAN+AD engagements
*today* (the AD arsenal is already real and tested) and (b) every downstream non-web specialist, because
it is the only way the loop ever generates non-web winning trajectories.

Everything else (intel-seed parity, IoT wiring, cloud capability-build, wireless hardware) is sequenced
*after* that switch, because none of it produces a credible adaptive engagement until the picker can
choose the tools.
