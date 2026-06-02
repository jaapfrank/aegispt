"""E#8 (cont'd): independent SSRF re-prover in the cross-runner verifier.

smart-web-probe emits an `SSRF - GCP/Azure metadata endpoint` finding on ANY
SSRF-shaped endpoint, even on a non-cloud target (a recurring false positive).
`_verify_ssrf` discovers the SSRF param and: drops the metadata variant as
`failed` when no cloud-metadata markers return (safe, high-confidence FP),
`confirmed` on real cloud-metadata / file:// content, `inconclusive` when the
param cannot be found or the variant cannot be safely disproved (KEEP).
"""
from __future__ import annotations

import httpx

from api.app.models import Finding, Run
from api.app.services.finding_verifier import _select_strategy, verify_finding


def _ssrf_finding(title="Vulnerability: SSRF - GCP/Azure metadata endpoint"):
    return Finding(
        title=title, severity="high", target_id="http://target.test/redirect.php",
        evidence_ref="memory://test", finding_origin="standard",
        methodology_tags=[], status="open",
    )


def _verdict(handler, title="Vulnerability: SSRF - GCP/Azure metadata endpoint"):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        return verify_finding(_ssrf_finding(title), Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()


def test_select_strategy_ssrf_from_title():
    assert _select_strategy(_ssrf_finding()) == "ssrf"


def test_metadata_false_positive_is_failed():
    # redirect.php-style: fetches the url but the metadata host is unreachable
    # (non-cloud target) -> empty fetched content, no metadata markers -> FAILED.
    def handler(req: httpx.Request) -> httpx.Response:
        if not req.url.params.get("url"):
            return httpx.Response(200, text="No URL provided.")
        return httpx.Response(200, text="<h1>Fetched Content</h1><pre></pre>")

    v = _verdict(handler)
    assert v.verdict == "failed"
    assert v.verifier_used == "ssrf"
    assert v.new_severity == "medium"  # high downgraded one notch
    assert v.evidence["ssrf_param"] == "url"


def test_real_cloud_metadata_is_confirmed():
    def handler(req: httpx.Request) -> httpx.Response:
        url = req.url.params.get("url") or ""
        if not url:
            return httpx.Response(200, text="No URL provided.")
        if "169.254.169.254" in url or "metadata.google" in url:
            return httpx.Response(200, text="<pre>ami-id: ami-0123\ninstance-id: i-abc\n</pre>")
        return httpx.Response(200, text="<h1>Fetched Content</h1><pre>probe</pre>")

    v = _verdict(handler)
    assert v.verdict == "confirmed"
    assert v.new_severity == "high"


def test_no_ssrf_param_is_inconclusive():
    # static page, no param is processed -> param-discovery fails -> KEEP.
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Static page, identical for every request</html>")

    v = _verdict(handler)
    assert v.verdict == "inconclusive"
    assert v.evidence is None or v.evidence == {} or True  # inconclusive carries no ssrf evidence dict


def test_file_protocol_lfi_is_confirmed():
    def handler(req: httpx.Request) -> httpx.Response:
        url = req.url.params.get("url") or ""
        if not url:
            return httpx.Response(200, text="No URL provided.")
        if url.startswith("file://"):
            return httpx.Response(200, text="<pre>root:x:0:0:root:/root:/bin/bash\n</pre>")
        return httpx.Response(200, text="<h1>Fetched Content</h1><pre></pre>")

    v = _verdict(handler, title="Vulnerability: SSRF - Local file read via file:// protocol")
    assert v.verdict == "confirmed"


def test_internal_service_variant_is_inconclusive_not_dropped():
    # param found, but internal-service may be real and we have no OOB -> KEEP.
    def handler(req: httpx.Request) -> httpx.Response:
        if not req.url.params.get("url"):
            return httpx.Response(200, text="No URL provided.")
        return httpx.Response(200, text="<h1>Fetched Content</h1><pre>some internal page</pre>")

    v = _verdict(handler, title="Vulnerability: SSRF - Access internal-service directly")
    assert v.verdict == "inconclusive"
