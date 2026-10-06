#!/usr/bin/env python3
"""Discover OSV CVE entries with GIT fix commits and CWE abstraction labels."""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "orchestrator"))
from shift_left.cwe.mitre_export import mitre_weakness_meta

PACKAGES: dict[str, str] = {
    "django": "django/django",
    "flask": "pallets/flask",
    "pillow": "python-pillow/Pillow",
    "lxml": "lxml/lxml",
    "pyyaml": "yaml/pyyaml",
    "cryptography": "pyca/cryptography",
    "tornado": "tornadoweb/tornado",
    "jinja2": "pallets/jinja",
    "aiohttp": "aio-libs/aiohttp",
    "requests": "psf/requests",
    "urllib3": "urllib3/urllib3",
    "werkzeug": "pallets/werkzeug",
    "sentry-sdk": "getsentry/sentry-python",
    "twisted": "twisted/twisted",
    "scrapy": "scrapy/scrapy",
    "paramiko": "paramiko/paramiko",
    "pygments": "pygments/pygments",
    "markupsafe": "pallets/markupsafe",
    "itsdangerous": "pallets/itsdangerous",
    "redis": "redis/redis-py",
    "httpx": "encode/httpx",
    "starlette": "encode/starlette",
    "restrictedpython": "zopefoundation/RestrictedPython",
}


def _osv_query(package: str) -> dict:
    body = json.dumps({"package": {"ecosystem": "PyPI", "name": package}}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def _osv_get(vuln_id: str) -> dict:
    with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=60) as resp:
        return json.loads(resp.read())


def _nvd_cwe(cve: str) -> str | None:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    req = urllib.request.Request(url, headers={"User-Agent": "shift-left-multidefect-discovery"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    for item in data.get("vulnerabilities", []):
        for weakness in item.get("cve", {}).get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = str(desc.get("value", ""))
                if value.startswith("CWE-") and value != "NVD-CWE-Other":
                    return value
    return None


def _abstraction_bucket(cwe: str) -> str:
    meta = mitre_weakness_meta(cwe) or {}
    abstraction = str(meta.get("abstraction") or "")
    if abstraction in {"Base", "Variant"}:
        return "Base"
    if abstraction in {"Class", "Pillar"}:
        return "Class"
    return "Other"


def harvest(package: str, default_repo: str, *, nvd_delay_s: float = 0.65) -> list[dict]:
    found: list[dict] = []
    query = _osv_query(package)
    for brief in query.get("vulns", []):
        try:
            vuln = _osv_get(brief["id"])
        except Exception:
            continue
        cve = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")), None)
        if not cve:
            continue
        cwe = None
        db_cwes = vuln.get("database_specific", {}).get("cwe_ids") or []
        if db_cwes:
            cwe = str(db_cwes[0])
        if not cwe:
            cwe = _nvd_cwe(cve)
            time.sleep(nvd_delay_s)
        if not cwe:
            continue
        bucket = _abstraction_bucket(cwe)
        if bucket == "Other":
            continue
        git_fix = None
        repo = default_repo
        for affected in vuln.get("affected", []):
            for range_ in affected.get("ranges", []):
                if range_.get("type") != "GIT":
                    continue
                if range_.get("repo"):
                    repo = str(range_["repo"]).replace("https://github.com/", "").rstrip("/")
                for event in range_.get("events", []):
                    if "fixed" in event:
                        git_fix = str(event["fixed"])
            if git_fix:
                break
        if not git_fix:
            continue
        found.append(
            {
                "entry_id": f"{cve}-{package}",
                "cve": cve,
                "repo": repo,
                "cwe": cwe,
                "cwe_abstraction": mitre_weakness_meta(cwe).get("abstraction"),
                "abstraction_bucket": bucket,
                "osv_fix_commit": git_fix,
                "summary": str(vuln.get("summary") or "")[:120],
            }
        )
    return found


def main() -> int:
    all_entries: list[dict] = []
    for package, repo in PACKAGES.items():
        entries = harvest(package, repo)
        print(f"{package}: {len(entries)}", file=sys.stderr)
        all_entries.extend(entries)

    deduped: dict[str, dict] = {}
    for entry in all_entries:
        deduped[entry["cve"]] = entry
    entries = list(deduped.values())

    matrix: dict[str, dict[str, int]] = defaultdict(lambda: {"Base": 0, "Class": 0})
    for entry in entries:
        matrix[entry["repo"]][entry["abstraction_bucket"]] += 1

    out = {
        "entry_count": len(entries),
        "design_matrix": {repo: dict(counts) for repo, counts in sorted(matrix.items())},
        "repos_with_both_abstractions": sorted(
            repo for repo, counts in matrix.items() if counts["Base"] and counts["Class"]
        ),
        "entries": entries,
    }
    out_path = Path(__file__).parent / "osv_candidates.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("entry_count", "design_matrix", "repos_with_both_abstractions")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
