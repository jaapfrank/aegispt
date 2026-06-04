from __future__ import annotations

import json
from html import escape


def format_json_block(payload: dict[str, object] | None) -> str:
    return json.dumps(payload or {}, indent=2, sort_keys=True)


def humanize_key(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def humanize_value(value: object) -> str:
    if value is None:
        return "Not recorded"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip() or "Not recorded"
    if isinstance(value, list):
        items = [humanize_value(item) for item in value if humanize_value(item) != "Not recorded"]
        return ", ".join(items) if items else "Not recorded"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            rendered = humanize_value(value[key])
            if rendered != "Not recorded":
                parts.append(f"{humanize_key(str(key))}: {rendered}")
        return "; ".join(parts) if parts else "Not recorded"
    return str(value)


def render_key_values_markdown(values: dict[str, object], *, empty_label: str = "Not recorded") -> list[str]:
    if not values:
        return [f"- {empty_label}"]
    return [f"- {humanize_key(str(key))}: {humanize_value(values[key])}" for key in sorted(values)]


def render_key_values_html(values: dict[str, object], *, empty_label: str = "Not recorded") -> str:
    if not values:
        return f"<p>{escape(empty_label)}</p>"
    rows = "".join(
        f"<tr><th>{escape(humanize_key(str(key)))}</th><td>{escape(humanize_value(values[key]))}</td></tr>"
        for key in sorted(values)
    )
    return f"<table>{rows}</table>"


def target_values(configuration: dict[str, object]) -> list[str]:
    targets = configuration.get("targets", {})
    if not isinstance(targets, dict):
        return []
    values: list[str] = []
    for key in sorted(targets):
        raw = targets[key]
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item.strip():
                    values.append(f"{humanize_key(str(key))}: {item.strip()}")
        elif isinstance(raw, str) and raw.strip():
            values.append(f"{humanize_key(str(key))}: {raw.strip()}")
    return values


def report_target_summary(context: dict[str, object]) -> str:
    configuration = context.get("configuration", {})
    if isinstance(configuration, dict):
        targets = target_values(configuration)
        if targets:
            return "; ".join(targets)
    latest_scope = context.get("latest_scope")
    if latest_scope is not None:
        allowlist = getattr(latest_scope, "allowlist_json", {})
        if isinstance(allowlist, dict):
            rendered = humanize_value(allowlist)
            if rendered != "Not recorded":
                return rendered
    return "No target recorded"
