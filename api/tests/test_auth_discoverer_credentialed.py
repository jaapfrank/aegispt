"""Tests for the #345 operator-credentialed auth strategy.

Covers the new `acquire_session_with_credentials` function plus the
vault-lookup dispatch inside `acquire_session(session=..., run=...)`.
All HTTP is mocked via httpx MockTransport; the Anthropic client is
duck-typed; the run credential vault is monkeypatched module-side so
the tests do not need a real DB session.

The 5 migrated probes from #328 still call `acquire_session(base_url,
scope_allowlist=...)` WITHOUT `session`/`run` kwargs, so the dispatch
must be inert in that case — covered by
`test_acquire_session_without_session_or_run_keeps_emergent_path`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from api.app.services.auth_discoverer import (
    RECIPE_VERSION,
    _base_url_host,
    _login_only_fingerprint,
    _lookup_operator_credentials,
    acquire_session,
    acquire_session_with_credentials,
)


@pytest.fixture(autouse=True)
def memory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "memories"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(root))
    return root


# ---------------------------------------------------------------------------
# Anthropic mock (duck-typed)
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

    def create(self, **_kwargs: Any) -> _MockResponse:
        self.calls += 1
        return _MockResponse(self._text)


class _MockAnthropic:
    def __init__(self, text: str) -> None:
        self.messages = _MockMessages(text)


# ---------------------------------------------------------------------------
# DVWA-style login-only target fixture
# ---------------------------------------------------------------------------


_DVWA_INDEX_HTML = """<html><body>
  <a href="/login">Log in</a>
  <p>DVWA — please log in to continue.</p>
</body></html>
"""

_DVWA_LOGIN_HTML = """<html><body>
  <form action="/login.php" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="hidden" name="user_token" value="abc123" />
    <input type="submit" name="Login" value="Login" />
  </form>
</body></html>
"""

_DVWA_HOME_HTML = """<html><body>
  Welcome, admin. Vulnerability training menu below.
</body></html>
"""


def _make_dvwa_transport(
    *,
    login_status: int = 302,
    set_cookie_on_login: bool = True,
    capture: dict[str, Any] | None = None,
) -> httpx.MockTransport:
    """Login-only target — no register surface at all. /login returns the
    login form. /login.php (the form action) returns 302 + a session
    cookie on POST. The verification GET (against the populated cookie
    jar) lands on / and returns the logged-in home page.

    Crucially: unknown paths return 404. fetch_auth_pages probes a long
    REGISTER_PATHS list; if ALL of them return 200 (e.g. via a generic
    'everything returns home') the probe budget gets exhausted on noise
    and /login is never reached.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if capture is not None:
            capture.setdefault("paths", []).append(path)
            if path == "/login.php" and request.method == "POST":
                # Decode the POST body so tests can assert that the
                # operator's username + password ended up on the wire.
                body = request.read().decode("utf-8", errors="replace")
                capture["last_login_body"] = body
        if path == "/":
            # Index: also issues a session cookie so the verification
            # GET against / sees PHPSESSID and the "Welcome" body, even
            # before the login POST has run. This mirrors many real
            # apps that pre-issue a session id on first contact.
            headers = {}
            if set_cookie_on_login:
                headers["set-cookie"] = "PHPSESSID=session_dvwa_xyz; Path=/"
            # On post-login GETs the response body should look logged in.
            body = (
                _DVWA_HOME_HTML
                if request.headers.get("cookie", "").find("PHPSESSID") >= 0
                else _DVWA_INDEX_HTML
            )
            return httpx.Response(200, headers=headers, text=body)
        if path == "/login":
            return httpx.Response(200, text=_DVWA_LOGIN_HTML)
        if path == "/login.php":
            headers = {}
            if set_cookie_on_login:
                headers["set-cookie"] = "PHPSESSID=session_dvwa_xyz; Path=/"
            return httpx.Response(login_status, headers=headers, text="")
        # All other paths (incl. every entry in REGISTER_PATHS) → 404 so
        # the probe budget stays available for /login.
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _claude_response_for_dvwa_login() -> str:
    """A well-formed LOGIN AuthRecipe targeting the DVWA login form."""
    recipe = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "login",
                "intent": "login",
                "method": "POST",
                "url": "http://dvwa.test/login.php",
                "field_mappings": {
                    "username": "username",
                    "password": "password",
                    "user_token": "hidden_passthrough",
                },
                "expected_status": [200, 302],
                "description": "submit operator credentials",
            }
        ],
        "verification": {
            "method": "GET",
            "url": "http://dvwa.test/",
            "expect_status": [200],
            "expect_set_cookie": "PHPSESSID",
            "expect_body_contains": [],
            "description": "confirm session",
        },
    }
    return json.dumps(recipe)


# ---------------------------------------------------------------------------
# _base_url_host (pure helper)
# ---------------------------------------------------------------------------


def test_base_url_host_lowercases_and_strips_port() -> None:
    assert _base_url_host("http://target.test/") == "target.test"
    assert _base_url_host("https://target.test:8080/admin") == "target.test"
    assert _base_url_host("HTTPS://Target.Test/") == "target.test"


def test_base_url_host_returns_empty_on_garbage() -> None:
    assert _base_url_host("") == ""
    assert _base_url_host("not a url") == ""
    assert _base_url_host("file:///etc/passwd") == ""


# ---------------------------------------------------------------------------
# _login_only_fingerprint
# ---------------------------------------------------------------------------


def test_login_only_fingerprint_strips_register_form_without_mutating_input() -> None:
    fp = {
        "fingerprint_hash": "abc",
        "register_form": {"action": "/saveprofile"},
        "login_form": {"action": "/login.php"},
    }
    out = _login_only_fingerprint(fp)
    assert out["register_form"] is None
    assert out["login_form"] == {"action": "/login.php"}
    # Input untouched.
    assert fp["register_form"] == {"action": "/saveprofile"}


# ---------------------------------------------------------------------------
# acquire_session_with_credentials — happy path on DVWA-style target
# ---------------------------------------------------------------------------


def test_acquire_session_with_credentials_login_happy_path(memory_root: Path) -> None:
    capture: dict[str, Any] = {}
    transport = _make_dvwa_transport(capture=capture)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_dvwa_login())
    try:
        result = acquire_session_with_credentials(
            "http://dvwa.test/",
            username="admin",
            password="hunter2-operator-supplied",
            http_client=client,
            anthropic_client=anthropic,
            probe_limit=30,
        )
    finally:
        if result is None or result.get("client") is not client:
            client.close()

    assert result is not None, "credentialed acquire should succeed on login-only target"
    assert result["client"] is client
    assert result["username"] == "admin"
    # password MUST NOT appear in the returned dict.
    assert "password" not in result, (
        "operator password leaked into session dict — credential_handling "
        "rule violated"
    )
    # The flag distinguishes credentialed runs from emergent ones.
    assert result["from_credentials"] is True
    assert result["from_cache"] is False
    # The login body must contain operator creds.
    body = capture.get("last_login_body") or ""
    assert "username=admin" in body
    assert "password=hunter2-operator-supplied" in body
    # Hidden passthrough must have carried the original user_token value.
    assert "user_token=abc123" in body
    # Session cookie populated.
    assert "PHPSESSID" in result["session_cookies"]


def test_acquire_session_with_credentials_returns_none_when_no_login_form(
    memory_root: Path,
) -> None:
    """If fingerprint has no login_form, credentialed path bails. Distinct
    from emergent path's None which means no register+login at all."""

    def handler(request: httpx.Request) -> httpx.Response:
        # All paths return a generic index with no login form.
        return httpx.Response(200, text="<html>no auth surface</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = acquire_session_with_credentials(
            "http://no-auth.test/",
            username="admin",
            password="x",
            http_client=client,
            anthropic_client=_MockAnthropic("{}"),
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_with_credentials_login_fails_returns_none(
    memory_root: Path,
) -> None:
    """A 401 from the login POST → recipe execute fails → returns None."""
    transport = _make_dvwa_transport(login_status=401, set_cookie_on_login=False)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_dvwa_login())
    try:
        result = acquire_session_with_credentials(
            "http://dvwa.test/",
            username="admin",
            password="wrong",
            http_client=client,
            anthropic_client=anthropic,
            probe_limit=30,
        )
    finally:
        client.close()
    assert result is None


def test_acquire_session_with_credentials_rejects_empty_username_password(
    memory_root: Path,
) -> None:
    client = httpx.Client(transport=_make_dvwa_transport())
    try:
        assert acquire_session_with_credentials(
            "http://dvwa.test/", username="", password="x", http_client=client,
        ) is None
        assert acquire_session_with_credentials(
            "http://dvwa.test/", username="admin", password="", http_client=client,
        ) is None
        assert acquire_session_with_credentials(
            "", username="admin", password="x", http_client=client,
        ) is None
    finally:
        client.close()


# ---------------------------------------------------------------------------
# acquire_session — vault dispatch
# ---------------------------------------------------------------------------


def _build_vault_ref(
    *,
    secret_kind: str = "password",
    target: str = "http://dvwa.test/login",
    username: str = "admin",
    decrypted_password: str = "hunter2-operator-supplied",
    encrypted_value: str = "ENCRYPTED:hunter2",
    storage_backend: str = "encrypted_local",
) -> Any:
    """Build a duck-typed SecretRef-like object for vault tests."""
    ref = MagicMock()
    ref.id = "11111111-1111-1111-1111-111111111111"
    ref.secret_kind = secret_kind
    ref.storage_backend = storage_backend
    ref.encrypted_value = encrypted_value
    ref.metadata_json = {
        "ephemeral_run_vault": True,
        "run_id": "22222222-2222-2222-2222-222222222222",
        "target": target,
        "username": username,
        "binding_key": "password",
    }
    # Stash the expected decryption result on the ref so the
    # patched decrypt_secret_value can return it.
    ref._decrypted = decrypted_password
    return ref


def _patch_vault(
    monkeypatch: pytest.MonkeyPatch,
    refs: list[Any],
) -> None:
    """Monkeypatch the lazy vault imports inside _lookup_operator_credentials
    so they return our fake refs + a trivial decryption."""
    import api.app.services.run_credential_vault as vault_mod
    import api.app.services.secrets as secrets_mod

    def _fake_vault_refs_for_run(_session, *, run):  # noqa: ARG001
        return refs

    def _fake_decrypt(value, _settings, *, storage_backend="encrypted_local"):
        for ref in refs:
            if getattr(ref, "encrypted_value", None) == value:
                return getattr(ref, "_decrypted", "")
        return value  # passthrough for un-matched

    monkeypatch.setattr(vault_mod, "_vault_refs_for_run", _fake_vault_refs_for_run)
    monkeypatch.setattr(secrets_mod, "decrypt_secret_value", _fake_decrypt)


def test_lookup_credentials_vault_hit_returns_username_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref = _build_vault_ref()
    _patch_vault(monkeypatch, [ref])
    result = _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    )
    assert result == ("admin", "hunter2-operator-supplied")


def test_lookup_credentials_vault_skips_non_password_secret_kinds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vault with only a bearer_token entry must NOT be picked up by the
    login-credentialed path."""
    ref = _build_vault_ref(secret_kind="bearer_token")
    _patch_vault(monkeypatch, [ref])
    assert _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    ) is None


def test_lookup_credentials_vault_host_match_ignores_port_and_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """vault target 'http://dvwa.test:8080/admin' matches base_url
    'http://dvwa.test/' — credentials are scope-of-host."""
    ref = _build_vault_ref(target="http://dvwa.test:8080/admin")
    _patch_vault(monkeypatch, [ref])
    assert _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    ) == ("admin", "hunter2-operator-supplied")


def test_lookup_credentials_vault_miss_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault has a ref for a different host — current base_url should
    not pick it up."""
    ref = _build_vault_ref(target="http://other.test/")
    _patch_vault(monkeypatch, [ref])
    assert _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    ) is None


def test_lookup_credentials_requires_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ref = _build_vault_ref(username="")
    _patch_vault(monkeypatch, [ref])
    assert _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    ) is None


def test_lookup_credentials_swallows_decrypt_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If decrypt_secret_value raises, the helper must skip that ref +
    continue (no propagation), returning None when no other ref matches."""
    import api.app.services.run_credential_vault as vault_mod
    import api.app.services.secrets as secrets_mod

    ref = _build_vault_ref()

    def _fake_refs(_s, *, run):  # noqa: ARG001
        return [ref]

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated decrypt failure")

    monkeypatch.setattr(vault_mod, "_vault_refs_for_run", _fake_refs)
    monkeypatch.setattr(secrets_mod, "decrypt_secret_value", _boom)

    assert _lookup_operator_credentials(
        session=object(), run=object(), base_url="http://dvwa.test/",
    ) is None


# ---------------------------------------------------------------------------
# acquire_session dispatch — vault hit triggers credentialed, miss falls back
# ---------------------------------------------------------------------------


def test_acquire_session_without_session_or_run_keeps_emergent_path(
    monkeypatch: pytest.MonkeyPatch, memory_root: Path,
) -> None:
    """The 5 #328 probes call acquire_session(base_url, scope_allowlist=...).
    The new session/run kwargs default to None, dispatch is inert, the
    emergent path runs unchanged. This sentinel guards the #328 contract.
    """
    # The vault patching must NOT be hit if dispatch is inert.
    called = {"vault": False}

    def _trap(_session, *, run):  # noqa: ARG001
        called["vault"] = True
        return []

    import api.app.services.run_credential_vault as vault_mod
    monkeypatch.setattr(vault_mod, "_vault_refs_for_run", _trap)

    # Use the same Gruyere-style fixture as the existing emergent tests —
    # we just need *some* successful emergent path to verify dispatch is
    # inert. We mock the recipe response inline because the goal is the
    # dispatch check, not the full pipeline.
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html><a href='/signup'>up</a></html>")
        if path == "/signup":
            return httpx.Response(200, text="""<html><body>
                <form action="/register" method="POST">
                  <input type="text" name="uid" />
                  <input type="password" name="pw" />
                </form></body></html>""")
        return httpx.Response(200, text="ok",
                              headers={"set-cookie": "SID=xx; Path=/"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    try:
        # No session/run kwargs ⇒ dispatch must be inert ⇒ vault NEVER called.
        acquire_session(
            "http://sandbox.test/",
            http_client=client,
            anthropic_client=_MockAnthropic(json.dumps({
                "recipe_version": RECIPE_VERSION,
                "steps": [{
                    "name": "register", "intent": "register",
                    "method": "POST", "url": "http://sandbox.test/register",
                    "field_mappings": {"uid": "username", "pw": "password"},
                    "expected_status": [200, 302],
                    "description": "x",
                }],
                "verification": {
                    "method": "GET", "url": "http://sandbox.test/",
                    "expect_status": [200],
                    "expect_set_cookie": "SID",
                    "expect_body_contains": [],
                    "description": "y",
                },
            })),
        )
    finally:
        client.close()

    assert called["vault"] is False, (
        "acquire_session without session/run MUST NOT consult the vault — "
        "this would break the #328 probe contract"
    )


def test_acquire_session_with_vault_hit_dispatches_to_credentialed(
    monkeypatch: pytest.MonkeyPatch, memory_root: Path,
) -> None:
    """When session+run are passed AND vault has matching creds, dispatch
    should go to acquire_session_with_credentials. End-to-end on the
    DVWA-style fixture: the resulting session dict carries
    from_credentials=True (not from_cache=False alone)."""
    ref = _build_vault_ref()
    _patch_vault(monkeypatch, [ref])

    capture: dict[str, Any] = {}
    transport = _make_dvwa_transport(capture=capture)
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_dvwa_login())
    try:
        result = acquire_session(
            "http://dvwa.test/",
            http_client=client,
            anthropic_client=anthropic,
            session=object(),
            run=object(),
            probe_limit=30,
        )
    finally:
        if result is None or result.get("client") is not client:
            client.close()

    assert result is not None
    assert result.get("from_credentials") is True
    assert result["username"] == "admin"
    assert "password" not in result
    # Operator credentials actually went over the wire.
    assert "password=hunter2-operator-supplied" in (capture.get("last_login_body") or "")


def test_acquire_session_with_vault_miss_falls_back_to_emergent(
    monkeypatch: pytest.MonkeyPatch, memory_root: Path,
) -> None:
    """session+run provided BUT vault has no matching ref ⇒ falls through
    to the emergent path. The emergent recipe is what the AI produces;
    against a DVWA-style login-only target (no /signup, no register_form)
    the emergent path returns None (no register surface). This proves the
    fallback works AND that login-only targets without vault creds remain
    correctly classified as un-authable via emergent."""
    # Empty vault ⇒ vault miss.
    _patch_vault(monkeypatch, [])

    transport = _make_dvwa_transport()
    client = httpx.Client(transport=transport)
    try:
        result = acquire_session(
            "http://dvwa.test/",
            http_client=client,
            anthropic_client=_MockAnthropic("{}"),
            session=object(),
            run=object(),
            probe_limit=30,
        )
    finally:
        client.close()
    # No register surface + no vault hit ⇒ None. This is the failure
    # mode #345 was filed to fix; backlog-395 doesn't fix the case where
    # the operator forgot to pre-stage credentials, just the case where
    # creds ARE in the vault.
    assert result is None


def test_acquire_session_credentialed_dispatch_session_dict_omits_password(
    monkeypatch: pytest.MonkeyPatch, memory_root: Path,
) -> None:
    """Greppable assertion: the password value MUST NOT appear anywhere
    in the returned session dict. Including via session_cookies (server
    cookies don't echo passwords) or as a string in any nested value.
    This is the core credential_handling guarantee of #345."""
    secret_password = "DO_NOT_LEAK_THIS_VALUE_42x9z"
    ref = _build_vault_ref(decrypted_password=secret_password)
    _patch_vault(monkeypatch, [ref])

    transport = _make_dvwa_transport()
    client = httpx.Client(transport=transport)
    anthropic = _MockAnthropic(_claude_response_for_dvwa_login())
    try:
        result = acquire_session(
            "http://dvwa.test/",
            http_client=client,
            anthropic_client=anthropic,
            session=object(),
            run=object(),
            probe_limit=30,
        )
    finally:
        if result is None or result.get("client") is not client:
            client.close()

    assert result is not None
    # Flatten the dict to strings and grep for the password value.
    def _flatten(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            out: list[str] = []
            for v in value.values():
                out.extend(_flatten(v))
            return out
        if isinstance(value, (list, tuple)):
            out: list[str] = []
            for v in value:
                out.extend(_flatten(v))
            return out
        return []

    # Exclude the live client object — it has the cookie jar which is
    # fine to inspect separately.
    safe_subset = {k: v for k, v in result.items() if k != "client"}
    for s in _flatten(safe_subset):
        assert secret_password not in s, (
            f"password value leaked into result field: {s[:200]!r}"
        )
