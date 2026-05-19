"""Tests for build_recipe — Mythos task #326 (backlog-376).

No live HTTP and no live Anthropic API. A duck-typed mock client is
injected. All recipe shapes are exercised against fingerprints covering
3+ distinct stacks (Python-Gruyere-like, ASP.NET WebForms, PHP).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from api.app.services.auth_discoverer import (
    RECIPE_MAX_STEPS,
    RECIPE_MODEL,
    RECIPE_VERSION,
    _extract_json_object,
    build_recipe,
    fingerprint_application,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "auth_pages"


# ---------------------------------------------------------------------------
# Duck-typed Anthropic SDK mock
# ---------------------------------------------------------------------------


class _MockBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class _MockResponse:
    def __init__(self, text: str) -> None:
        self.content = [_MockBlock(text)]


class _MockMessages:
    def __init__(self, text: str | Exception, *, capture: dict | None = None) -> None:
        self._text = text
        self._capture = capture

    def create(self, **kwargs: Any) -> _MockResponse:
        if self._capture is not None:
            self._capture.update(kwargs)
        if isinstance(self._text, Exception):
            raise self._text
        return _MockResponse(self._text)


class _MockClient:
    def __init__(self, text: str | Exception, *, capture: dict | None = None) -> None:
        self.messages = _MockMessages(text, capture=capture)


# ---------------------------------------------------------------------------
# Fingerprint fixtures (built once from real HTML fixtures from #325)
# ---------------------------------------------------------------------------


def _page(url: str, html: str, *, kind: str, status: int = 200,
          headers: dict | None = None, cookies: list | None = None) -> dict:
    return {
        "url": url,
        "kind": kind,
        "status_code": status,
        "html": html,
        "response_headers": headers or {},
        "set_cookie_names": cookies or [],
    }


@pytest.fixture
def gruyere_fp() -> dict:
    html = (FIXTURES_DIR / "gruyere_signup.html").read_text(encoding="utf-8")
    return fingerprint_application(
        [_page("http://gruyere.local/signup", html, kind="register",
               cookies=["GRUYERE"])]
    )


@pytest.fixture
def testfire_fp() -> dict:
    html = (FIXTURES_DIR / "testfire_register.html").read_text(encoding="utf-8")
    return fingerprint_application(
        [_page("http://testfire.local/bank/register.aspx", html, kind="register",
               headers={"server": "Microsoft-IIS/8.5", "x-aspnet-version": "4.0"})]
    )


@pytest.fixture
def testasp_fp() -> dict:
    html = (FIXTURES_DIR / "testasp_register.html").read_text(encoding="utf-8")
    return fingerprint_application(
        [_page("http://testasp.local/register.php", html, kind="register",
               headers={"x-powered-by": "PHP/7.4"}, cookies=["PHPSESSID"])]
    )


# ---------------------------------------------------------------------------
# Recipe-text helpers — build well-formed responses that reference real URLs
# ---------------------------------------------------------------------------


def _recipe_text_from_fp(fp: dict, *, with_verification: bool = True) -> str:
    """Build a valid recipe JSON string that references the fingerprint's
    register_form.action and field names. Used to simulate a well-behaved
    Claude response."""
    reg = fp.get("register_form") or {}
    action = reg.get("action") or ""
    field_names = [f["name"] for f in reg.get("fields") or []]

    mappings: dict[str, str] = {}
    for name in field_names:
        lname = name.lower()
        if "confirm" in lname or "pw2" in lname or "upass2" in lname:
            mappings[name] = "confirm_password"
        elif "pass" in lname or lname in {"pw", "upass"}:
            mappings[name] = "password"
        elif "email" in lname:
            mappings[name] = "email"
        elif "csrf" in lname or "viewstate" in lname.lower() or "eventvalidation" in lname.lower():
            mappings[name] = "hidden_passthrough"
        elif lname.startswith("__"):
            mappings[name] = "hidden_passthrough"
        else:
            mappings[name] = "username"

    parsed = urlparse_helper(action)
    origin = f"{parsed[0]}://{parsed[1]}" if parsed[1] else "http://gruyere.local"

    recipe = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": action,
                "field_mappings": mappings,
                "expected_status": [200, 302],
                "description": "create test account",
            }
        ],
        "verification": (
            {
                "method": "GET",
                "url": f"{origin}/",
                "expect_status": [200],
                "expect_set_cookie": fp.get("session_cookie_hint"),
                "expect_body_contains": [],
                "description": "confirm session established",
            }
            if with_verification
            else None
        ),
    }
    return json.dumps(recipe)


def urlparse_helper(url: str) -> tuple[str, str]:
    from urllib.parse import urlparse
    p = urlparse(url)
    return (p.scheme, p.netloc)


# ---------------------------------------------------------------------------
# build_recipe — happy paths across 3 stacks
# ---------------------------------------------------------------------------


def test_build_recipe_gruyere_register(gruyere_fp: dict) -> None:
    client = _MockClient(_recipe_text_from_fp(gruyere_fp))
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    assert recipe is not None
    assert recipe["recipe_version"] == RECIPE_VERSION
    assert recipe["model"] == RECIPE_MODEL
    assert recipe["fingerprint_hash"] == gruyere_fp["fingerprint_hash"]
    assert len(recipe["steps"]) == 1
    step = recipe["steps"][0]
    assert step["intent"] == "register"
    assert step["method"] == "POST"
    assert step["url"] == gruyere_fp["register_form"]["action"]
    assert step["field_mappings"]  # at least one field mapped
    assert recipe["verification"] is not None
    assert recipe["verification"]["method"] == "GET"


def test_build_recipe_testfire_aspnet(testfire_fp: dict) -> None:
    client = _MockClient(_recipe_text_from_fp(testfire_fp))
    recipe = build_recipe(testfire_fp, anthropic_client=client)
    assert recipe is not None
    step = recipe["steps"][0]
    # ViewState/EventValidation should be mapped as hidden_passthrough.
    mappings = step["field_mappings"]
    assert any(v == "hidden_passthrough" for v in mappings.values()), (
        f"expected hidden_passthrough mapping for ASP.NET hidden fields, got {mappings}"
    )


def test_build_recipe_testasp_php(testasp_fp: dict) -> None:
    client = _MockClient(_recipe_text_from_fp(testasp_fp))
    recipe = build_recipe(testasp_fp, anthropic_client=client)
    assert recipe is not None
    step = recipe["steps"][0]
    # Confirm-password style field should be flagged as confirm_password.
    assert any(v == "confirm_password" for v in step["field_mappings"].values())


def test_build_recipe_three_stacks_yield_three_distinct_urls(
    gruyere_fp: dict, testfire_fp: dict, testasp_fp: dict
) -> None:
    urls = set()
    for fp in (gruyere_fp, testfire_fp, testasp_fp):
        client = _MockClient(_recipe_text_from_fp(fp))
        recipe = build_recipe(fp, anthropic_client=client)
        assert recipe is not None
        urls.add(recipe["steps"][0]["url"])
    assert len(urls) == 3, "each stack should produce a distinct step URL"


# ---------------------------------------------------------------------------
# Output is JSON-serializable (cache contract for #327)
# ---------------------------------------------------------------------------


def test_recipe_is_json_serializable(gruyere_fp: dict) -> None:
    client = _MockClient(_recipe_text_from_fp(gruyere_fp))
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    blob = json.dumps(recipe)
    roundtrip = json.loads(blob)
    assert roundtrip == recipe


# ---------------------------------------------------------------------------
# Guard: AI returns URLs not present in fingerprint → reject
# ---------------------------------------------------------------------------


def test_build_recipe_rejects_url_hijack(gruyere_fp: dict) -> None:
    """If the model returns a step URL not in the fingerprint, validation
    drops it. With no valid steps left, build_recipe returns None — this
    prevents prompt-injection from redirecting requests to attacker URLs."""
    hijack = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": "http://evil.example.com/exfil",
                "field_mappings": {"uid": "username", "pw": "password"},
                "expected_status": [200],
                "description": "x",
            }
        ],
        "verification": None,
    }
    client = _MockClient(json.dumps(hijack))
    assert build_recipe(gruyere_fp, anthropic_client=client) is None


def test_build_recipe_filters_unknown_field_names(gruyere_fp: dict) -> None:
    """Field names not observed on the form must be dropped (defense
    against the AI smuggling arbitrary parameters)."""
    action = gruyere_fp["register_form"]["action"]
    payload = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": action,
                "field_mappings": {
                    "uid": "username",
                    "pw": "password",
                    "admin_override": "literal:1",  # not a real field
                },
                "expected_status": [200],
                "description": "x",
            }
        ],
        "verification": None,
    }
    client = _MockClient(json.dumps(payload))
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    assert recipe is not None
    assert "admin_override" not in recipe["steps"][0]["field_mappings"]


def test_build_recipe_rejects_cross_origin_verification(gruyere_fp: dict) -> None:
    action = gruyere_fp["register_form"]["action"]
    payload = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": action,
                "field_mappings": {"uid": "username"},
                "expected_status": [200],
                "description": "x",
            }
        ],
        "verification": {
            "method": "GET",
            "url": "http://attacker.example.com/profile",
            "expect_status": [200],
            "expect_set_cookie": None,
            "expect_body_contains": [],
            "description": "x",
        },
    }
    client = _MockClient(json.dumps(payload))
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    assert recipe is not None
    # Steps survive, verification is dropped to None.
    assert recipe["verification"] is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_build_recipe_returns_none_when_no_forms() -> None:
    empty = fingerprint_application([])
    assert build_recipe(empty, anthropic_client=_MockClient("{}")) is None


def test_build_recipe_returns_none_on_non_dict_input() -> None:
    assert build_recipe([], anthropic_client=_MockClient("{}")) is None  # type: ignore[arg-type]
    assert build_recipe(None, anthropic_client=_MockClient("{}")) is None  # type: ignore[arg-type]


def test_build_recipe_returns_none_on_client_exception(gruyere_fp: dict) -> None:
    client = _MockClient(RuntimeError("api down"))
    assert build_recipe(gruyere_fp, anthropic_client=client) is None


def test_build_recipe_returns_none_on_unparseable_json(gruyere_fp: dict) -> None:
    client = _MockClient("not valid json at all { ")
    assert build_recipe(gruyere_fp, anthropic_client=client) is None


def test_build_recipe_returns_none_when_no_steps_field(gruyere_fp: dict) -> None:
    client = _MockClient(json.dumps({"recipe_version": RECIPE_VERSION}))
    assert build_recipe(gruyere_fp, anthropic_client=client) is None


def test_build_recipe_no_anthropic_key_returns_none(
    gruyere_fp: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # No injected client → must return None without crashing.
    assert build_recipe(gruyere_fp) is None


# ---------------------------------------------------------------------------
# Validation: prompt + model selection
# ---------------------------------------------------------------------------


def test_build_recipe_uses_haiku_model_and_passes_fingerprint(gruyere_fp: dict) -> None:
    capture: dict = {}
    client = _MockClient(_recipe_text_from_fp(gruyere_fp), capture=capture)
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    assert recipe is not None
    assert capture.get("model") == RECIPE_MODEL
    # Prompt must contain the fingerprint payload.
    user_msg = capture["messages"][0]["content"]
    assert gruyere_fp["fingerprint_hash"] in user_msg
    assert "register_form" in user_msg


def test_build_recipe_prompt_seed_has_no_app_specific_text() -> None:
    """Per feedback_no_prescriptive_recipes: the *seeded* prompt text
    (system prompt + scaffolding template inside _recipe_user_prompt)
    MUST NOT name Gruyere/juice-shop/testfire-specific patterns. The
    relayed fingerprint is data from the target — exempt from this check.

    To test the seed cleanly, build a recipe from an empty fingerprint
    where the data portion contains no app-specific strings, then
    inspect the captured prompt."""
    from api.app.services.auth_discoverer import (
        _RECIPE_SYSTEM_PROMPT,
        _recipe_user_prompt,
    )

    forbidden = ["gruyere", "juice-shop", "juiceshop", "testfire",
                 "/saveprofile", "altoro", "google-gruyere", "aegispt_"]

    # Build the user prompt from a minimal generic fingerprint — the
    # only non-seeded content is the JSON shell, which contains no
    # app-specific terms.
    generic_fp = {
        "stack_hints": [],
        "register_form": None,
        "login_form": None,
        "session_cookie_hint": None,
        "fingerprint_hash": "x",
        "fingerprint_version": "auth-discoverer-v1",
    }
    seeded_user_prompt = _recipe_user_prompt(generic_fp)
    combined_seed = (_RECIPE_SYSTEM_PROMPT + "\n" + seeded_user_prompt).lower()
    for term in forbidden:
        assert term not in combined_seed, (
            f"seeded prompt text contains app-specific term '{term}'"
        )


# ---------------------------------------------------------------------------
# _extract_json_object helper — defensive parsing
# ---------------------------------------------------------------------------


def test_extract_json_object_strips_fences() -> None:
    text = "```json\n{\"a\": 1}\n```"
    assert _extract_json_object(text) == {"a": 1}


def test_extract_json_object_finds_object_in_prose() -> None:
    text = "Here is the recipe:\n{\"x\": 2}\nThanks!"
    assert _extract_json_object(text) == {"x": 2}


def test_extract_json_object_returns_none_for_garbage() -> None:
    assert _extract_json_object("") is None
    assert _extract_json_object("no json here") is None


# ---------------------------------------------------------------------------
# Defense in depth: step cap
# ---------------------------------------------------------------------------


def test_build_recipe_caps_steps(gruyere_fp: dict) -> None:
    action = gruyere_fp["register_form"]["action"]
    field_names = list(gruyere_fp["register_form"]["fields"][0]["name"] for _ in range(1))
    one_step = {
        "name": "register",
        "intent": "register",
        "method": "POST",
        "url": action,
        "field_mappings": {field_names[0]: "username"} if field_names else {},
        "expected_status": [200],
        "description": "x",
    }
    payload = {
        "recipe_version": RECIPE_VERSION,
        "steps": [one_step] * (RECIPE_MAX_STEPS + 4),
        "verification": None,
    }
    client = _MockClient(json.dumps(payload))
    recipe = build_recipe(gruyere_fp, anthropic_client=client)
    assert recipe is not None
    assert len(recipe["steps"]) <= RECIPE_MAX_STEPS
