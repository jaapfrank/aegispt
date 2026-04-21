from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import RunProfile
from api.app.policy.engine import RunClass, normalize_profile_limits

DEFAULT_RUN_PROFILES: tuple[dict[str, object], ...] = (
    {
        "name": "passive-network-discovery",
        "run_class": RunClass.PASSIVE.value,
        "limits_json": {
            "description": "Passive-safe host and range discovery using Nmap ping scan semantics.",
            "required_approvals": 0,
            "tools": ["nmap"],
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "passive-network-service-enumeration",
        "run_class": RunClass.PASSIVE.value,
        "limits_json": {
            "description": "Passive-safe service identification across discovered hosts using Nmap top-port and service detection.",
            "required_approvals": 0,
            "tools": ["nmap"],
            "discovery_only": False,
            "service_detection": True,
            "skip_discovery": True,
            "top_ports": 50,
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "passive-web-baseline",
        "run_class": RunClass.PASSIVE.value,
        "limits_json": {
            "description": "Passive HTTP fingerprinting with the Python httpx runner.",
            "required_approvals": 0,
            "tools": ["httpx"],
            "max_rps": 2,
            "max_concurrency": 2,
        },
    },
    {
        "name": "passive-code-semgrep-audit",
        "run_class": RunClass.PASSIVE.value,
        "limits_json": {
            "description": "Passive Semgrep scan over allowlisted local code paths with curated rules.",
            "required_approvals": 0,
            "tools": ["semgrep"],
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "passive-web-nuclei-audit",
        "run_class": RunClass.PASSIVE.value,
        "limits_json": {
            "description": "Passive-safe nuclei validation with a pinned local template.",
            "required_approvals": 0,
            "tools": ["nuclei"],
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "active-web-safe",
        "run_class": RunClass.ACTIVE.value,
        "limits_json": {
            "description": "Approval-gated ZAP crawl and passive validation with safer defaults.",
            "required_approvals": 1,
            "tools": ["zap"],
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "active-web-zap-active",
        "run_class": RunClass.ACTIVE.value,
        "limits_json": {
            "description": "Approval-gated ZAP spider plus active scan against allowlisted web targets.",
            "required_approvals": 1,
            "tools": ["zap"],
            "scan_mode": "spider-active-passive",
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
    {
        "name": "intrusive-validation",
        "run_class": RunClass.INTRUSIVE.value,
        "limits_json": {
            "description": "Higher-risk internal validation flow with two-person approval.",
            "required_approvals": 2,
            "tools": ["zap", "nuclei"],
            "max_rps": 1,
            "max_concurrency": 1,
        },
    },
)


def ensure_default_run_profiles(session: Session) -> bool:
    existing = {
        profile.name: profile for profile in session.scalars(select(RunProfile)).all()
    }
    changed = False

    for definition in DEFAULT_RUN_PROFILES:
        name = str(definition["name"])
        run_class = str(definition["run_class"])
        limits_json = normalize_profile_limits(run_class, dict(definition["limits_json"]))

        profile = existing.get(name)
        if profile is None:
            session.add(
                RunProfile(
                    name=name,
                    run_class=run_class,
                    limits_json=limits_json,
                )
            )
            changed = True
            continue

        if profile.run_class != run_class:
            profile.run_class = run_class
            changed = True
        if profile.limits_json != limits_json:
            profile.limits_json = limits_json
            changed = True

    if changed:
        session.flush()

    return changed
