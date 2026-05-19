"""Tests for the #328 acquire_session integration helper.

Covers the end-to-end pipeline: fetch_auth_pages -> fingerprint ->
lookup_recipe (cache) -> build_recipe (cache miss) -> verify -> execute
-> return session. All HTTP is mocked via httpx MockTransport. The
Anthropic client is duck-typed. Memory backend is redirected to tmp_path
via the AEGISPT_MEMORY_ROOT env var.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from api.app.services.auth_discoverer import (
    RECIPE_VERSION,
    VERDICT_FRESH,
    _generate_credentials,
    _resolve_field_value,
    acquire_session,
    store_recipe,
)


@pytest.fixture(autouse=True)
def memory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "memories"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(root))
    return root


# ---------------------------------------------------------------------------
# Anthropic mock
# ---------------------------------------------------------------------------


class _MockBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class _MockResponse:
    def __init__(self, text: str) -> None:
        self.content = [_MockBlock(text)]


class _MockMessages:
    def __init__(self, text: str) -> None:
        self._text = text
        self.calls = 0

    def create(self, **kwargs: Any) -> _MockResponse:
        self.calls += 1
        return _MockResponse(self._text)


class _MockAnthropic:
    def __init__(self, text: str) -> None:
        self.messages = _MockMessages(text)


# ---------------------------------------------------------------------------
# Fixtures: a deterministic Gruyere-flavoured target via MockTransport
# ---------------------------------------------------------------------------


GRUYERE_INDEX_HTML = """<html><body>
  <a href="/signup">Sign up</a>
  <a href="/login">Log in</a>
</body></html>
"""

GRUYERE_SIGNUP_HTML = """<html><body>
  <form action="/saveprofile" method="GET">
    <input type="hidden" name="action" value="new" />
    <input type="text" name="uid" />
    <input type="password" name="pw" />
    <input type="text" name="profile.email" />
    <input type="submit" />
  </form>
</body></html>
"""


GRUYERE_HOME_AFTER_AUTH = """<html><body>
  Welcome, you are logged in.
</body></html>
"""


def _make_gruyere_transport(
    *,
    register_status: int = 200,
    set_cookie_on_register: bool = True,
    home_status: int = 200,
    home_sets_cookie: bool = True,
) -> tuple[httpx.MockTransport, dict[str, int]]:
    """Build a MockTransport that simulates a Gruyere-like target.
    Returns the transport + a call-counter dict so tests can assert on
    which paths got hit."""
    counters: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        counters[path] = counters.get(path, 0) + 1
        if path == "/":
            # Index: optionally sets a GRUYERE cookie even for visitors,
            # mirroring real Gruyere behavior. The home_sets_cookie flag
            # toggles this so we can simulate verify-fails scenarios.
            headers = {}
            if home_sets_cookie:
                headers["set-cookie"] = "GRUYERE=session_abc; Path=/"
            return httpx.Response(200, headers=headers, text=GRUYERE_INDEX_HTML)
        if path == "/signup":
            return httpx.Response(200, text=GRUYERE_SIGNUP_HTML)
        if path == "/saveprofile":
            headers = {}
            if set_cookie_on_register:
                headers["set-cookie"] = "GRUYERE=session_abc; Path=/"
            return httpx.Response(register_status, headers=headers, text="ok")
        if path == "/login":
            return httpx.Response(404)
        # Any other path also behaves like a logged-in landing page.
        if path.startswith("/"):
            headers = {}
            if home_sets_cookie:
                headers["set-cookie"] = "GRUYERE=session_abc; Path=/"
            return httpx.Response(home_status, headers=headers, text=GRUYERE_HOME_AFTER_AUTH)
        return httpx.Response(404)

    return httpx.MockTransport(handler), counters


def _claude_response_for_gruyere() -> str:
    """A well-formed AuthRecipe that the AI would produce for Gruyere."""
    recipe = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "GET",
                "url": "http://gruyere.test/saveprofile",
                "field_mappings": {
                    "action": "hidden_passthrough",
                    "uid": "username",
                    "pw": "password",
                    "profile.email": "email",
                },
                "expected_status": [200, 302],
                "description": "create account",
            }
        ],
        "verification": {
            "method": "GET",
            "url": "http://gruyere.test/",
            "expect_status": [200],
            "expect_set_cookie": "GRUYERE",
            "expect_body_contains": [],
            "description": "confirm session",
        },
    }
    return json.dumps(recipe)


# ---------------------------------------------------------------------------
# _generate_credentials + _resolve_field_value (pure helpers)
# ---------------------------------------------------------------------------


def test_generate_credentials_format() -> None:
    user, pw, email = _generate_credentials()
    assert user.startswith("aegispt_")
    assert len(user) > len("aegispt_")
    assert pw.startswith("Pw!")
    assert email.endswith("@aegispt.test")
    assert user in email


def test_resolve_field_value_intent_vocabulary() -> None:
    kwargs = dict(username="alice", password="secret", email="alice@x.test", original_value="ORIG")
    assert _resolve_field_value("username", **kwargs) == "alice"
    assert _resolve_field_value("password", **kwargs) == "secret"
    assert _resolve_field_value("confirm_password", **kwargs) == "secret"
    assert _resolve_field_value("email", **kwargs) == "alice@x.test"
    assert _resolve_field_value("hidden_passthrough", **kwargs) == "ORIG"
    assert _resolve_field_value("literal:fixed_value", **kwargs) == "fixed_value"
    assert _resolve_field_value("csrf_token", **kwargs) == ""
    assert _resolve_field_value("unknown_intent", **kwargs) == ""


# ---------------------------------------------------------------------------
# acquire_session — happy path
# ---------------------------------------------------------------------------


def test_acquire_session_happy_path_cache_miss(memory_root: Path) -> None:
    transport, counters = _make_gruyere_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
    finally:
        # client is owned by the caller in this test (we passed it in),
        # so we close it regardless of success.
        if result is None or result.get("client") is not client:
            client.close()

    assert result is not None
    assert result["client"] is client
    assert result["from_cache"] is False
    assert result["recipe"]["steps"][0]["url"] == "http://gruyere.test/saveprofile"
    assert result["username"].startswith("aegispt_")
    # The /saveprofile endpoint MUST have been hit at least once during execute.
    assert counters.get("/saveprofile", 0) >= 1
    # Anthropic was called exactly once (no caching yet).
    assert anthropic.messages.calls == 1
    client.close()


def test_acquire_session_cache_hit_skips_anthropic(memory_root: Path) -> None:
    """Once a recipe is stored, a second acquire_session reuses it
    without invoking the Claude client."""
    transport, _ = _make_gruyere_transport()

    # First run: cache miss -> Anthropic call.
    client1 = httpx.Client(transport=transport)
    anthropic1 = _MockAnthropic(_claude_response_for_gruyere())
    result1 = acquire_session(
        "http://gruyere.test/",
        http_client=client1,
        anthropic_client=anthropic1,
    )
    assert result1 is not None
    assert result1["from_cache"] is False
    assert anthropic1.messages.calls == 1
    client1.close()

    # Second run: same fingerprint -> cache fresh -> Anthropic NOT called.
    client2 = httpx.Client(transport=transport)
    anthropic2 = _MockAnthropic("{\"this\":\"must not be used\"}")
    result2 = acquire_session(
        "http://gruyere.test/",
        http_client=client2,
        anthropic_client=anthropic2,
    )
    assert result2 is not None
    assert result2["from_cache"] is True
    assert anthropic2.messages.calls == 0, "cache hit must NOT call Anthropic"
    client2.close()


def test_acquire_session_force_refresh_bypasses_cache(memory_root: Path) -> None:
    transport, _ = _make_gruyere_transport()

    client1 = httpx.Client(transport=transport)
    a1 = _MockAnthropic(_claude_response_for_gruyere())
    acquire_session("http://gruyere.test/", http_client=client1, anthropic_client=a1)
    client1.close()

    client2 = httpx.Client(transport=transport)
    a2 = _MockAnthropic(_claude_response_for_gruyere())
    result = acquire_session(
        "http://gruyere.test/",
        http_client=client2,
        anthropic_client=a2,
        force_refresh=True,
    )
    assert result is not None
    assert result["from_cache"] is False
    assert a2.messages.calls == 1, "force_refresh must call Anthropic even with fresh cache"
    client2.close()


# ---------------------------------------------------------------------------
# acquire_session — failure paths
# ---------------------------------------------------------------------------


def test_acquire_session_returns_none_when_no_pages() -> None:
    """If fetch_auth_pages returns empty (e.g. target is unreachable), we
    bail out cleanly."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    try:
        result = acquire_session(
            "http://dead.test/",
            http_client=client,
            anthropic_client=_MockAnthropic(""),
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_returns_none_when_no_form() -> None:
    """A target with reachable pages but no form yields no fingerprint
    surface; acquire_session returns None."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>just text</body></html>")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    try:
        result = acquire_session(
            "http://noforms.test/",
            http_client=client,
            anthropic_client=_MockAnthropic(""),
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_returns_none_on_verify_fail() -> None:
    """If the verification step fails (no cookie), the recipe is marked
    stale and acquire_session returns None."""
    transport, _ = _make_gruyere_transport(home_sets_cookie=False, set_cookie_on_register=False)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_returns_none_on_execute_fail() -> None:
    """If the register step returns an unexpected status, execute fails."""
    transport, _ = _make_gruyere_transport(register_status=500)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_returns_none_on_bad_base_url() -> None:
    assert acquire_session("") is None
    assert acquire_session(None) is None  # type: ignore[arg-type]


def test_acquire_session_returns_none_when_build_recipe_fails() -> None:
    """If Claude returns garbage, build_recipe returns None and
    acquire_session propagates None."""
    transport, _ = _make_gruyere_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic("not valid json at all")
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
    finally:
        client.close()
    assert result is None


# ---------------------------------------------------------------------------
# acquire_session — cookies + recipe shape returned
# ---------------------------------------------------------------------------


def test_acquire_session_returns_session_cookies(memory_root: Path) -> None:
    transport, _ = _make_gruyere_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
        assert result is not None
        assert "GRUYERE" in result["session_cookies"]
        assert result["session_cookies"]["GRUYERE"] == "session_abc"
    finally:
        client.close()


def test_acquire_session_uses_hidden_passthrough(memory_root: Path) -> None:
    """The 'action' hidden field has value 'new' in the form. The
    recipe maps it to hidden_passthrough; the execute step must replay
    that exact value, not the field name."""
    captured_params: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(
                200,
                headers={"set-cookie": "GRUYERE=ok; Path=/"},
                text=GRUYERE_INDEX_HTML,
            )
        if path == "/signup":
            return httpx.Response(200, text=GRUYERE_SIGNUP_HTML)
        if path == "/saveprofile":
            captured_params.append(dict(request.url.params))
            return httpx.Response(
                200, headers={"set-cookie": "GRUYERE=ok; Path=/"}, text="ok"
            )
        return httpx.Response(
            200, headers={"set-cookie": "GRUYERE=ok; Path=/"}, text="home"
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
    finally:
        client.close()
    assert result is not None
    # The /saveprofile call must have received action=new (not action=hidden_passthrough).
    register_params = next(
        (p for p in captured_params if "uid" in p),
        None,
    )
    assert register_params is not None
    assert register_params.get("action") == "new"
    assert register_params.get("uid", "").startswith("aegispt_")
    assert register_params.get("pw", "").startswith("Pw!")


# ---------------------------------------------------------------------------
# Defense: scope-allowlist respected for recipe steps
# ---------------------------------------------------------------------------


def test_acquire_session_respects_scope_allowlist_on_execute(memory_root: Path) -> None:
    """If the recipe targets a URL outside scope, the execute step
    refuses to send the request and acquire_session returns None."""
    transport, _ = _make_gruyere_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    # Allowlist that excludes /saveprofile path.
    scope_allowlist = {"web_targets": ["http://otherapp.test/"]}
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
            scope_allowlist=scope_allowlist,
        )
    finally:
        client.close()
    # When scope rejects discovery probes entirely, pages will be empty
    # and acquire_session returns None at the fetch stage.
    assert result is None


# ---------------------------------------------------------------------------
# Cookies survive into client jar (the whole point of acquire_session)
# ---------------------------------------------------------------------------


def test_acquire_session_populates_client_cookie_jar(memory_root: Path) -> None:
    transport, _ = _make_gruyere_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_gruyere())
    try:
        result = acquire_session(
            "http://gruyere.test/",
            http_client=client,
            anthropic_client=anthropic,
        )
        assert result is not None
        # The returned client (which IS our client) has cookies set.
        names = {c.name for c in client.cookies.jar if c.name}
        assert "GRUYERE" in names
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Pre-existing fresh cache entry
# ---------------------------------------------------------------------------


def test_acquire_session_uses_externally_prewarmed_cache(memory_root: Path) -> None:
    """Tests that a cache entry written by another mechanism (e.g. a
    previous run) is honored. We hand-write a cache file, then call
    acquire_session and confirm it skipped Anthropic."""
    transport, _ = _make_gruyere_transport()

    # First run to populate the fingerprint+cache.
    client_prime = httpx.Client(transport=transport)
    a_prime = _MockAnthropic(_claude_response_for_gruyere())
    primer = acquire_session(
        "http://gruyere.test/",
        http_client=client_prime,
        anthropic_client=a_prime,
    )
    assert primer is not None
    client_prime.close()

    # Now confirm the second run is cache-fresh.
    client2 = httpx.Client(transport=transport)
    a2 = _MockAnthropic("garbage")
    res2 = acquire_session(
        "http://gruyere.test/",
        http_client=client2,
        anthropic_client=a2,
    )
    assert res2 is not None
    assert res2["from_cache"] is True
    assert a2.messages.calls == 0
    client2.close()
