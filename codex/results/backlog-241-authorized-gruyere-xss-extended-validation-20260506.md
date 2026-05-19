# Backlog 241 - Authorized Gruyere XSS Extended Validation

Timestamp: 2026-05-06T10:11:45+02:00

## Scope Decision

- Active task: `codex/tasks/backlog-241-authorized-gruyere-xss-extended-validation.json`
- Authorized live validation root: `https://google-gruyere.appspot.com/482338906867472456097470474631954304306/`
- `http://127.0.0.1:8000` relevance: not used. This task validates the existing direct `xss-extended` runner against the explicitly authorized hosted Gruyere instance root; no AegisPT UI/API browser path was needed for acceptance.
- Read-only documentation/source lookups used official Gruyere pages outside the instance root; live validation requests stayed under the authorized root.

## Official Gruyere-Derived Contexts

- File-upload XSS:
  - Official codelab: `https://google-gruyere.appspot.com/part2` section `File Upload XSS` says HTML files can be uploaded and can contain script.
  - Official source: `https://google-gruyere.appspot.com/code/resources/upload.gtl` posts multipart form data to `/{{_unique_id}}/upload2` with file field `upload_file`.
  - Official source: `https://google-gruyere.appspot.com/code/resources/upload2.gtl` renders the uploaded `url` as plain response text.
  - Official source: `https://google-gruyere.appspot.com/code/gruyere.py` stores the uploaded file under `/<unique_id>/<uid>/<filename>`.
  - Runner context used: `POST upload2`, field `upload_file`, filename `aegispt-xss-241-final.html`.
- AJAX/JSON XSS:
  - Official codelab: `https://google-gruyere.appspot.com/part2` section `Reflected XSS via AJAX` says the refresh path uses `/feed.gtl?uid=value` and gives the exploit form `/feed.gtl?uid=<script>alert(1)</script>`.
  - Official source: `https://google-gruyere.appspot.com/code/resources/feed.gtl` emits `_feed((["<uid>"]))` for the `uid` query path.
  - Runner context used: `GET feed.gtl?uid=cheddar` with `uid` replaced by the existing `DEFAULT_AJAX_PAYLOAD`.
- XSSI:
  - Official codelab: `https://google-gruyere.appspot.com/part3` section `XSSI Challenge` says a cross-site page can include `<script src="https://google-gruyere.appspot.com/123/feed.gtl"></script>` and read `s['private_snippet']` through `_feed(s)`.
  - Official source: `https://google-gruyere.appspot.com/code/resources/feed.gtl` emits `_feed(({ "private_snippet": ... }))` when no `uid` query is supplied.
  - Runner context used: `GET feed.gtl`.

## Narrow Runner Repair

The pre-repair direct runner detected file-upload XSS and AJAX/JSON XSS, but missed XSSI because Gruyere returns `_feed((...))` as `text/html`, not bare JSON. The runner also initially selected the Gruyere navigation link before the upload result URL. The repair was limited to:

- prefer absolute URLs in upload responses before navigation `href`/`src` links
- recognize JSONP-like `_callback((...))` wrappers as JSON-like XSSI payloads
- treat `private_snippet` as sensitive XSSI evidence

## Live Runner Result

Command form: direct `execute_xss_extended_scan(...)` call from `.venv` with `scope_allowlist={"urls": [authorized_root]}` and a logging `httpx.Client` wrapper.

Summary:

```json
{
  "ajax_json_findings": 1,
  "check_count": 4,
  "file_upload_findings": 1,
  "finding_count": 3,
  "target_count": 1,
  "xssi_findings": 1
}
```

Outbound validation requests:

```json
[
  {
    "method": "POST",
    "url": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/upload2"
  },
  {
    "method": "GET",
    "url": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/None/aegispt-xss-241-final.html"
  },
  {
    "method": "GET",
    "url": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/feed.gtl?uid=%3Cscript%3Ealert%28%27aegispt-json-xss%27%29%3C%2Fscript%3E"
  },
  {
    "method": "GET",
    "url": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/feed.gtl"
  }
]
```

Checks:

```json
[
  {
    "check_type": "file_upload_xss",
    "returned_url": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/None/aegispt-xss-241-final.html",
    "status_code": 200,
    "target": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/upload2"
  },
  {
    "check_type": "uploaded_file_retrieval",
    "content_type": "text/html",
    "status_code": 200,
    "target": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/None/aegispt-xss-241-final.html"
  },
  {
    "check_type": "ajax_json_xss",
    "content_type": "text/html",
    "dangerous_context": true,
    "payload_reflected": true,
    "status_code": 200,
    "target": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/feed.gtl?uid=%3Cscript%3Ealert%28%27aegispt-json-xss%27%29%3C%2Fscript%3E"
  },
  {
    "check_type": "xssi",
    "content_type": "text/html",
    "missing_protections": [
      "x-content-type-options:nosniff",
      "vary:origin",
      "csrf-or-csp-signal"
    ],
    "sensitive_json": true,
    "status_code": 200,
    "target": "https://google-gruyere.appspot.com/482338906867472456097470474631954304306/feed.gtl"
  }
]
```

Detected variants:

- File-upload XSS: detected. Uploaded HTML was served from the same origin as `text/html` without attachment protections.
- AJAX/JSON XSS: detected. `feed.gtl?uid=...` reflected the payload inside a browser-executable `text/html` `_feed((...))` response.
- XSSI: detected. `feed.gtl` exposed `private_snippet` inside a JSONP-like `_feed((...))` response and lacked the expected anti-XSSI protections.

No reset, quit, overload, DoS, code execution, path traversal, SQLi, or account takeover endpoint was called.
