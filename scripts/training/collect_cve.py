"""Robust NVD CVE collector — User-Agent, paced, flushed, visible errors.

The NVD 2.0 API rate-limits unauthenticated callers hard (5 req / 30s) and
rejects/hangs requests without a User-Agent. Use a UA, 2000/page (the max), a
6.5s gap, retry with backoff, and FLUSH every line so progress is visible.
"""
import json
import time
import urllib.request

OUT = "/home/administrator/.aegispt-tools/training/corpus/cve_2026.jsonl"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD rejects ranges >120 days with HTTP 404. Use the most recent ~120-day
# window — that IS the "newest attacks" currency we want.
WINDOW = "pubStartDate=2026-02-06T00:00:00.000&pubEndDate=2026-06-04T23:59:59.999"
UA = {"User-Agent": "AegisPT-security-research/1.0"}


def log(m):
    print(m, flush=True)


def fetch(start):
    url = f"{BASE}?{WINDOW}&resultsPerPage=2000&startIndex={start}"
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.load(r)
        except Exception as e:
            log(f"  [retry {attempt+1}/6 @start={start}] {str(e)[:90]}")
            time.sleep(12 + attempt * 6)
    return None


def main():
    start, total, n = 0, None, 0
    with open(OUT, "w") as f:
        while True:
            d = fetch(start)
            if d is None:
                log(f"giving up at start={start} (NVD unreachable)")
                break
            total = d.get("totalResults", 0)
            vulns = d.get("vulnerabilities", [])
            for v in vulns:
                cve = v.get("cve", {})
                descs = [x["value"] for x in cve.get("descriptions", []) if x.get("lang") == "en"]
                sev = ""
                m = cve.get("metrics", {})
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if m.get(k):
                        cd = m[k][0]
                        sev = cd.get("cvssData", {}).get("baseSeverity") or cd.get("baseSeverity") or ""
                        break
                cwes = [d2["value"] for w in cve.get("weaknesses", [])
                        for d2 in w.get("description", []) if d2.get("value", "").startswith("CWE")]
                f.write(json.dumps({"id": cve.get("id"), "desc": descs[0] if descs else "",
                                    "severity": sev, "cwe": cwes}) + "\n")
                n += 1
            f.flush()
            log(f"collected {n}/{total}")
            start += len(vulns)
            if not vulns or start >= (total or 0):
                break
            time.sleep(6.5)
    log(f"DONE -> {OUT} ({n} CVEs)")


if __name__ == "__main__":
    main()
