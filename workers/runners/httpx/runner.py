from __future__ import annotations

import json
import re
from collections.abc import Mapping
from hashlib import sha256
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urljoin

import httpx as httpx_client
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

_PASSIVE_HEADER_NAMES = {
    "authorization",
    "content-type",
    "server",
    "x-application-context",
    "x-generator",
    "x-powered-by",
    "x-spring-application-context",
}
_JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_SERIALIZED_COOKIE_MARKERS = ("rO0", "O%3A", "a%3A", "gAS")
_BODY_EXCERPT_LIMIT = 8192


class _PassiveHtmlSignalsParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag == "a" and attributes.get("href"):
            self.links.append(urljoin(self.base_url, attributes["href"]))
            return
        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attributes.get("action") or self.base_url),
                "method": (attributes.get("method") or "GET").upper(),
                "inputs": [],
            }
            return
        if tag == "input" and self._current_form is not None:
            inputs = self._current_form.setdefault("inputs", [])
            if isinstance(inputs, list):
                inputs.append(
                    {
                        "name": attributes.get("name", ""),
                        "type": (attributes.get("type") or "text").lower(),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _body_excerpt(body_bytes: bytes) -> str:
    return body_bytes[:_BODY_EXCERPT_LIMIT].decode("utf-8", errors="replace")


def _passive_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in _PASSIVE_HEADER_NAMES and value
    }


def _cookie_value_shape(value: str) -> str | None:
    if _JWT_PATTERN.match(value):
        return "jwt"
    if any(value.startswith(marker) for marker in _SERIALIZED_COOKIE_MARKERS):
        return "serialized"
    return None


def _passive_cookie_signals(headers: Mapping[str, str]) -> list[dict[str, object]]:
    cookies: list[dict[str, object]] = []
    if hasattr(headers, "get_list"):
        set_cookie_headers = headers.get_list("set-cookie")  # type: ignore[attr-defined]
    else:
        value = headers.get("set-cookie", "")
        set_cookie_headers = [value] if value else []
    for header in set_cookie_headers:
        parsed = SimpleCookie()
        parsed.load(header)
        for morsel in parsed.values():
            cookie = {
                "name": morsel.key,
                "httponly": bool(morsel["httponly"]),
                "secure": bool(morsel["secure"]),
                "samesite": morsel["samesite"] or None,
            }
            value_shape = _cookie_value_shape(morsel.value)
            if value_shape:
                cookie["value_shape"] = value_shape
            cookies.append(cookie)
    return cookies


def _passive_html_signals(body_excerpt: str, base_url: str) -> dict[str, object]:
    parser = _PassiveHtmlSignalsParser(base_url)
    parser.feed(body_excerpt)
    parser.close()
    return {
        "forms": parser.forms,
        "links": list(dict.fromkeys(parser.links)),
    }


def build_httpx_command(targets: list[str], rate_limit: int = 25) -> list[str]:
    if not targets:
        raise ValueError("at least one target is required")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")

    command = ["httpx-toolkit", "-silent", "-json", "-rl", str(rate_limit)]
    for target in targets:
        if not target.strip():
            raise ValueError("targets must not be blank")
        command.extend(["-u", target])

    return command


def normalize_http_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("targets must not be blank")
    if normalized.startswith(("http://", "https://")):
        return normalized
    return f"https://{normalized}"


def execute_httpx_probe(
    targets: list[str],
    rate_limit: int = 25,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    results: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    normalized_targets: list[str] = []
    exit_code = 0

    with httpx_client.Client(
        follow_redirects=True,
        timeout=timeout_seconds,
        verify=False,
        headers={"User-Agent": "AegisPT/0.1"},
    ) as client:
        for target in targets:
            request_url = normalize_http_target(target)
            normalized_targets.append(request_url)

            try:
                response = client.get(request_url)
                body_bytes = response.content
                excerpt = _body_excerpt(body_bytes)
                html_signals = _passive_html_signals(excerpt, str(response.url))
                results.append(
                    {
                        "input_target": target,
                        "request_url": request_url,
                        "final_url": str(response.url),
                        "status_code": response.status_code,
                        "reason_phrase": response.reason_phrase,
                        "content_type": response.headers.get("content-type"),
                        "content_length": len(body_bytes),
                        "body_sha256": sha256(body_bytes).hexdigest(),
                        "body_excerpt": excerpt,
                        "body_truncated": len(body_bytes) > _BODY_EXCERPT_LIMIT,
                        "response_headers": _passive_response_headers(response.headers),
                        "cookies": _passive_cookie_signals(response.headers),
                        "forms": html_signals["forms"],
                        "links": html_signals["links"],
                        "ok": True,
                    }
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                error_message = f"{request_url}: {exc}"
                stderr_lines.append(error_message)
                _etxt = str(exc).lower()
                _unreachable = any(tok in _etxt for tok in (
                    "connection refused", "errno 111", "econnrefused", "timed out",
                    "timeout", "name or service not known", "no route to host",
                    "connecterror", "connecttimeout", "readtimeout", "unreachable",
                ))
                results.append(
                    {
                        "input_target": target,
                        "request_url": request_url,
                        "ok": False,
                        "error": str(exc),
                        "unreachable": _unreachable,
                    }
                )

    # A probe that only ever hit UNREACHABLE targets (connection refused / timeout —
    # e.g. the service wasn't up yet on the probed port) is NOT a tool failure.
    # Operator repeatedly flagged misleading FAILED rows; map all-unreachable to the
    # exit_code=78 SKIPPED path (task.status=skipped) instead of a hard failure.
    if exit_code == 1 and results and all(
        (not r.get("ok")) and r.get("unreachable") for r in results
    ):
        exit_code = 78

    artifact_data = ("\n".join(json.dumps(result, sort_keys=True) for result in results) + "\n").encode()
    artifact = EvidenceArtifact(
        name="httpx-results.jsonl",
        content_type="application/x-ndjson",
        data=artifact_data,
        kind="probe-results",
    )

    return RunnerExecution(
        tool="httpx",
        exit_code=exit_code,
        stdout=json.dumps({"results": results}, sort_keys=True),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": ("ok" if exit_code == 0 else "skipped" if exit_code == 78 else "completed_with_errors"),
            "normalized_targets": normalized_targets,
            "rate_limit": rate_limit,
            "timeout_seconds": timeout_seconds,
            "verify_tls": False,
            "tool_version": f"python-httpx/{httpx_client.__version__}",
            "runner_digest": "workers.httpx.runner:v1",
            "result_count": len(results),
        },
        artifacts=[artifact],
    )
