# Active Task

## Title

WiFi / Wireless Assessment Surface Foundation

## Promoted From

`codex/tasks/backlog-164-wifi-wireless-assessment-surface.json`

## Goal

Add WiFi as a first-class AegisPT assessment surface with passive-first wireless discovery, explicit site/SSID/BSSID authorization, adapter readiness checks, AP security posture review, rogue/unknown AP detection against an allowlist, and clearly gated intrusive wireless options.

## Scope

Implement the active backlog package `codex/tasks/backlog-164-wifi-wireless-assessment-surface.json`.

Expected slice:

- add a WiFi / Wireless Assessment wizard tile with site/location, approved SSIDs, approved BSSIDs where known, exclusions, and adapter/interface context before launch
- expose wireless readiness in Settings, including detected adapters, monitor-mode capability, required binaries, channel support, safe parallelism limits, and clear blocked/degraded states
- add a passive WLAN survey runner that records SSID, BSSID, channel, band, encryption/auth mode, PMF/WPA2/WPA3/WEP/open/WPS hints, vendor/OUI, signal strength, and observation timestamp without disruption
- store wireless access points/networks using existing provenance/evidence patterns
- create conservative evidence-backed findings for observable weak or unexpected wireless posture
- show wireless task focus and evidence capture in Mission Control and Live Agents
- add WiFi Security Summary report output only when WiFi evidence exists

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not run live customer, RF-disruptive, intrusive, or out-of-scope wireless actions.
- Keep the first WiFi slice passive-first and evidence-first.
- Do not add deauthentication, jamming, evil-twin simulation, WPS PIN brute force, credential harvesting, or handshake/password cracking in this foundation task.
- Do not claim WiFi support without adapter/tool readiness and fixture-backed validation evidence.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`
- Focused runner unit tests with fixture iw/airodump-style outputs and no RF hardware dependency
- API tests proving WiFi profile creation, scope/ROE validation, and inventory import
- Browser tests for the WiFi wizard tile, Settings readiness states, Mission Control task visibility, and WiFi report section
- Safe host-readiness validation showing supported, degraded, and missing-adapter states without launching RF-disruptive actions

## Acceptance

- A WiFi assessment can be prepared and launched only after explicit wireless ROE is acknowledged.
- A fixture-backed passive survey produces inventory, findings, Mission Control visibility, and report output.
- Intrusive wireless actions remain blocked/unavailable in this foundation slice.
- A readiness artifact under `codex/results/` documents adapter/tool state and remaining lab-validation gaps.
