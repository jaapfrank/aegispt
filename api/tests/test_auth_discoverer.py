"""Tests for auth_discoverer service — Mythos task #325 (backlog-375).

All tests use HTML fixtures under api/tests/fixtures/auth_pages/* to avoid
any live HTTP. fetch_auth_pages is exercised via httpx MockTransport so
the scope-allowlist enforcement and probe loop can be verified
deterministically.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from api.app.services.auth_discoverer import (
    DEFAULT_PROBE_LIMIT,
    FINGERPRINT_MAX_BYTES,
    REGISTER_PATHS,
    fetch_auth_pages,
    fingerprint_application,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "auth_pages"


def _load_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def _page(url: str, html: str, *, kind: str = "register", status: int = 200,
          headers: dict[str, str] | None = None,
          cookies: list[str] | None = None) -> dict:
    return {
        "url": url,
        "kind": kind,
        "status_code": status,
        "html": html,
        "response_headers": headers or {},
        "set_cookie_names": cookies or [],
    }


# ---------------------------------------------------------------------------
# fingerprint_application — pure function tests
# ---------------------------------------------------------------------------


def test_fingerprint_empty_input_is_stable() -> None:
    fp = fingerprint_application([])
    assert fp["stack_hints"] == []
    assert fp["register_form"] is None
    assert fp["login_form"] is None
    assert fp["session_cookie_hint"] is None
    assert fp["fingerprint_version"] == "auth-discoverer-v1"
    # Empty fingerprint is deterministic.
    assert fingerprint_application([])["fingerprint_hash"] == fp["fingerprint_hash"]


def test_fingerprint_non_list_input_handled() -> None:
    fp = fingerprint_application("not a list")  # type: ignore[arg-type]
    assert fp["stack_hints"] == []


def test_gruyere_fingerprint_picks_up_python_stack() -> None:
    html = _load_fixture("gruyere_signup.html")
    page = _page(
        "https://google-gruyere.appspot.com/12345/signup",
        html,
        kind="register",
        cookies=["GRUYERE"],
    )
    fp = fingerprint_application([page])
    assert "python_gruyere" in fp["stack_hints"]
    assert fp["register_form"] is not None
    assert fp["register_form"]["method"] == "GET"
    assert "/saveprofile" in fp["register_form"]["action"]
    field_names = {f["name"] for f in fp["register_form"]["fields"]}
    assert "uid" in field_names
    assert "pw" in field_names
    assert fp["session_cookie_hint"] == "GRUYERE"


def test_testfire_fingerprint_picks_up_aspnet_stack() -> None:
    html = _load_fixture("testfire_register.html")
    page = _page(
        "https://demo.testfire.net/bank/register.aspx",
        html,
        kind="register",
        headers={"server": "Microsoft-IIS/8.5", "x-aspnet-version": "4.0.30319"},
        cookies=["ASPNET_SessionId"],
    )
    fp = fingerprint_application([page])
    assert "aspnet" in fp["stack_hints"]
    assert fp["register_form"] is not None
    assert ".aspx" in fp["register_form"]["action"]
    field_names = {f["name"] for f in fp["register_form"]["fields"]}
    # Confirms confirm-password detection drove the register score.
    assert "txtPassword" in field_names
    assert "txtPasswordConfirm" in field_names
    # Hidden ASP.NET signatures are present.
    assert "__VIEWSTATE" in field_names or any(
        f["name"] == "__VIEWSTATE" for f in fp["register_form"]["fields"]
    )


def test_testasp_fingerprint_picks_up_php_stack() -> None:
    html = _load_fixture("testasp_register.html")
    page = _page(
        "http://testphp.vulnweb.com/signup.php",
        html,
        kind="register",
        headers={"server": "nginx/1.19.0", "x-powered-by": "PHP/5.6.40"},
        cookies=["PHPSESSID"],
    )
    fp = fingerprint_application([page])
    assert "php" in fp["stack_hints"]
    assert fp["register_form"] is not None
    assert ".php" in fp["register_form"]["action"]
    field_names = {f["name"] for f in fp["register_form"]["fields"]}
    assert "upass" in field_names
    assert "upass2" in field_names  # confirm-password signature


def test_juiceshop_spa_fingerprint_still_emits_stack_hint_without_forms() -> None:
    html = _load_fixture("juiceshop_index.html")
    page = _page(
        "https://juice-shop.herokuapp.com/",
        html,
        kind="index",
        headers={"server": "nginx", "x-powered-by": "Express"},
        cookies=["connect.sid"],
    )
    fp = fingerprint_application([page])
    # SPA — no traditional <form>, so neither register_form nor login_form
    # is detected, but stack hints + cookie still classify the app.
    assert fp["register_form"] is None
    assert fp["login_form"] is None
    assert "angular" in fp["stack_hints"]
    assert "node_express" in fp["stack_hints"]
    assert fp["session_cookie_hint"] == "connect.sid"


def test_fingerprint_distinguishes_four_stacks() -> None:
    fixtures = [
        ("gruyere_signup.html", "https://gruyere.example/12345/signup",
         {"cookies": ["GRUYERE"]}),
        ("testfire_register.html", "https://demo.testfire.net/bank/register.aspx",
         {"headers": {"server": "Microsoft-IIS/8.5"}, "cookies": ["ASPNET_SessionId"]}),
        ("testasp_register.html", "http://testphp.vulnweb.com/signup.php",
         {"headers": {"x-powered-by": "PHP/5.6.40"}, "cookies": ["PHPSESSID"]}),
        ("juiceshop_index.html", "https://juice-shop.herokuapp.com/",
         {"headers": {"x-powered-by": "Express"}, "cookies": ["connect.sid"]}),
    ]
    hashes: set[str] = set()
    for fname, url, extras in fixtures:
        page = _page(url, _load_fixture(fname), **extras)  # type: ignore[arg-type]
        fp = fingerprint_application([page])
        hashes.add(fp["fingerprint_hash"])
    # Four distinct stacks must produce four distinct hashes.
    assert len(hashes) == 4


def test_fingerprint_deterministic_for_same_input() -> None:
    html = _load_fixture("gruyere_signup.html")
    pages = [
        _page("https://x.test/12345/signup", html, kind="register", cookies=["GRUYERE"])
    ]
    fp_a = fingerprint_application(pages)
    fp_b = fingerprint_application([dict(p) for p in pages])  # fresh dict copies
    assert fp_a["fingerprint_hash"] == fp_b["fingerprint_hash"]
    assert fp_a["stack_hints"] == fp_b["stack_hints"]


def test_fingerprint_under_2kb() -> None:
    # All four fixtures combined should still fit.
    pages = [
        _page("https://gruyere.test/", _load_fixture("gruyere_signup.html"),
              kind="register", cookies=["GRUYERE"]),
        _page("https://demo.testfire.net/bank/register.aspx",
              _load_fixture("testfire_register.html"),
              kind="register", cookies=["ASPNET_SessionId"]),
        _page("http://testphp.vulnweb.com/signup.php",
              _load_fixture("testasp_register.html"),
              kind="register", cookies=["PHPSESSID"]),
        _page("https://juice-shop.herokuapp.com/",
              _load_fixture("juiceshop_index.html"),
              kind="index", cookies=["connect.sid"]),
    ]
    fp = fingerprint_application(pages)
    serialized = json.dumps(fp).encode("utf-8")
    assert len(serialized) <= 2048, (
        f"fingerprint serialized to {len(serialized)} bytes (target <2 KB)"
    )
    assert len(serialized) <= FINGERPRINT_MAX_BYTES + 200  # internal soft cap


def test_no_gruyere_strings_in_module() -> None:
    """The production module must not hardcode Gruyere-specific identifiers.
    Only test fixtures may reference saveprofile / GRUYERE / google-gruyere.
    """
    source = (
        Path(__file__).parent.parent / "app" / "services" / "auth_discoverer.py"
    ).read_text(encoding="utf-8")
    # GRUYERE cookie name + python_gruyere stack hint ARE allowed as
    # generic catalog entries (analogous to PHPSESSID, JSESSIONID, etc.).
    # We forbid: hardcoded `saveprofile` path, hardcoded scope-path tokens,
    # hardcoded usernames/passwords.
    # NOTE: `aegispt_` is the platform-wide emergent-username prefix
    # used by acquire_session (#328) and by reference runners
    # (xss_proof, param_pollution_probe). It is a structural platform
    # tag, not a Gruyere-specific token — exempt from this check.
    forbidden = [
        "/saveprofile",
        "google-gruyere",
        "482338906867472456097470474631954304306",
    ]
    for needle in forbidden:
        assert needle.lower() not in source.lower(), (
            f"Production module must not contain Gruyere-specific token: {needle}"
        )


def test_form_score_penalizes_missing_password_field() -> None:
    # A form with NO password input should be downscored so it never
    # becomes the picked login or register form.
    page = _page(
        "https://x.test/search",
        '<form action="/search" method="get"><input name="q" type="text" /></form>',
        kind="index",
    )
    fp = fingerprint_application([page])
    assert fp["register_form"] is None
    assert fp["login_form"] is None


# ---------------------------------------------------------------------------
# fetch_auth_pages — via httpx MockTransport (no live HTTP)
# ---------------------------------------------------------------------------


def _mock_transport(routes: dict[str, tuple[int, str, dict[str, str]]]):
    """Build an httpx MockTransport that returns canned (status, body, headers)
    keyed by request URL path."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for prefix, (status, body, headers) in routes.items():
            if url == prefix or url.endswith(prefix):
                return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


def test_fetch_auth_pages_returns_200_pages_only() -> None:
    routes = {
        "/": (200, "<html><a href='/signup'>Sign up</a></html>", {"server": "nginx"}),
        "/signup": (200, _load_fixture("gruyere_signup.html"), {"server": "nginx"}),
        "/login": (404, "", {}),
    }
    transport = _mock_transport(routes)
    client = httpx.Client(transport=transport, base_url="https://example.test")

    pages = fetch_auth_pages(
        "https://example.test/",
        scope_allowlist={"hosts": ["example.test"], "urls": ["https://example.test/"]},
        client=client,
    )
    urls = [p["url"] for p in pages]
    # Index + signup discovered
    assert any(u.endswith("/") for u in urls)
    assert any("/signup" in u for u in urls)
    # All returned pages are 200
    assert all(p["status_code"] == 200 for p in pages)


def test_fetch_auth_pages_respects_scope_allowlist() -> None:
    routes = {
        "/": (200, "<html></html>", {}),
        "/register": (200, _load_fixture("gruyere_signup.html"), {}),
    }
    transport = _mock_transport(routes)
    client = httpx.Client(transport=transport, base_url="https://outofscope.test")

    # Scope allowlist only includes a different host
    pages = fetch_auth_pages(
        "https://outofscope.test/",
        scope_allowlist={"hosts": ["allowed.test"], "urls": ["https://allowed.test/"]},
        client=client,
    )
    # All probes rejected because they target outofscope.test, not allowed.test
    assert pages == []


def test_fetch_auth_pages_probe_limit_respected() -> None:
    # All routes return 200 — without a cap the probe would grow unbounded.
    handler_call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        handler_call_count["n"] += 1
        return httpx.Response(200, text="<html></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pages = fetch_auth_pages(
        "https://x.test/",
        scope_allowlist={"hosts": ["x.test"], "urls": ["https://x.test/"]},
        probe_limit=5,
        client=client,
    )
    # Respect the cap (allowing for the initial index probe and short tail).
    assert len(pages) <= 7  # cap=5 + small headroom for index + link-scan
    assert handler_call_count["n"] <= 10


def test_fetch_auth_pages_handles_http_errors_gracefully() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "register" in str(request.url):
            raise httpx.ConnectError("network down")
        return httpx.Response(200, text="<html></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pages = fetch_auth_pages(
        "https://x.test/",
        scope_allowlist={"hosts": ["x.test"], "urls": ["https://x.test/"]},
        client=client,
    )
    # Should not raise — failed candidates are silently skipped.
    assert isinstance(pages, list)
    # Some non-/register URL should have returned 200.
    assert any(p["status_code"] == 200 for p in pages)


def test_register_paths_constant_does_not_leak_gruyere() -> None:
    # /saveprofile is Gruyere-specific and must NOT be in the generic list.
    assert "/saveprofile" not in REGISTER_PATHS
    # But common patterns should be present.
    assert "/register" in REGISTER_PATHS
    assert "/signup" in REGISTER_PATHS


def test_default_probe_limit_is_reasonable() -> None:
    # Sanity: defaults must not be huge (avoid hammering targets).
    assert DEFAULT_PROBE_LIMIT <= 20
    assert DEFAULT_PROBE_LIMIT >= 4


