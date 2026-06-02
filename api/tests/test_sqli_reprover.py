"""E#8: independent SQL-injection re-prover in the cross-runner verifier.

smart-web-probe emits `Vulnerability: SQL Injection - <variant>` critical findings
on dead login forms with no backend SQL (XBEN-014/005). Before E#8 these had no
verifier strategy -> `inconclusive` -> M2 gate `UNCLASSIFIED` -> kept (false
positives leaked). `_verify_sqli` re-proves them: a no-SQL dead form is
conclusively `failed` (-> droppable), real error-based / auth-bypass SQLi is
`confirmed`, and anything ambiguous stays `inconclusive` (never dropped on doubt).
"""
from __future__ import annotations

from urllib.parse import unquote_plus

import httpx

from api.app.models import Finding, Run
from api.app.services.finding_verifier import _select_strategy, verify_finding

LOGIN_PAGE = (
    '<html><body><h1>Login</h1>'
    '<form method="post" action="/index.php">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<button>Login</button></form></body></html>'
)


def _sqli_finding(*, replay=None):
    return Finding(
        title="Vulnerability: SQL Injection - Classic Auth Bypass",
        severity="critical", target_id="http://target.test/index.php",
        evidence_ref="memory://test", finding_origin="standard",
        methodology_tags=[], replay_recipe_json=replay, status="open",
    )


def _verdict(handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        return verify_finding(_sqli_finding(), Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()


def test_select_strategy_sqli_from_title():
    assert _select_strategy(_sqli_finding()) == "sqli"


def test_dead_login_form_no_sql_is_failed_and_downgraded():
    # Static login page, server does nothing with the input -> the SQLi payload
    # response is identical to the control -> demonstrably inert -> FAILED.
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=LOGIN_PAGE)

    v = _verdict(handler)
    assert v.verdict == "failed"
    assert v.verifier_used == "sqli"
    assert v.new_severity == "high"  # critical downgraded one notch
    assert v.evidence["injection_inert"] is True
    assert v.evidence["saw_sql_error"] is False


def test_error_based_sqli_is_confirmed():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and "%27" in str(req.url):
            return httpx.Response(200, text="<b>You have an error in your SQL syntax near \"'\"</b>")
        return httpx.Response(200, text=LOGIN_PAGE)

    v = _verdict(handler)
    assert v.verdict == "confirmed"
    assert v.evidence["saw_sql_error"] is True
    assert v.new_severity == "critical"


def test_auth_bypass_differential_is_confirmed():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            body = unquote_plus(req.content.decode())
            if "OR '1'='1'" in body:
                return httpx.Response(200, text="<html>Welcome admin! dashboard logout</html>")
            return httpx.Response(200, text="<html>Invalid credentials</html>")
        return httpx.Response(200, text=LOGIN_PAGE)

    v = _verdict(handler)
    assert v.verdict == "confirmed"
    assert v.evidence["auth_bypass_differential"] is True


def test_ambiguous_difference_is_inconclusive_not_dropped():
    # Responses differ but no SQL error and no success differential -> KEEP.
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            body = unquote_plus(req.content.decode())
            if "OR '1'='1'" in body:
                return httpx.Response(200, text="<html>" + ("A" * 800) + "</html>")
            return httpx.Response(200, text="<html>" + ("B" * 60) + "</html>")
        return httpx.Response(200, text=LOGIN_PAGE)

    v = _verdict(handler)
    assert v.verdict == "inconclusive"
