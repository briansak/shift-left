#!/usr/bin/env python3
"""Build a de-confounded multidefect manifest (repo x abstraction balance)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).parent / "manifest.json"
OSV_CANDIDATES = Path(__file__).parent / "osv_candidates.json"

# Manual overrides: OSV release tags, non-default fix commits, or explicit CWE.
_MANUAL: list[dict[str, object]] = [
    {
        "entry_id": "CVE-2024-22195-jinja",
        "cve": "CVE-2024-22195",
        "repo": "pallets/jinja",
        "cwe": "CWE-79",
        "osv_fix_commit": "d9de4bb215fd1cc8092a410fb834c7c4060b1fc1",
        "fix_commit": "7dd3680e6eea0d77fde024763657aa4d884ddb23",
        "ground_truth_files": ["src/jinja2/filters.py"],
    },
    {
        "entry_id": "CVE-2024-27306-aiohttp",
        "cve": "CVE-2024-27306",
        "repo": "aio-libs/aiohttp",
        "cwe": "CWE-79",
        "osv_fix_commit": "b3397c7ac44fc80206d28f1dd0d1f3b10c4ec572",
        "fix_commit": "28335525d1eac015a7e7584137678cbb6ff19397",
        "ground_truth_files": ["aiohttp/web_urldispatcher.py"],
    },
    {
        "entry_id": "CVE-2024-23334-aiohttp",
        "cve": "CVE-2024-23334",
        "repo": "aio-libs/aiohttp",
        "cwe": "CWE-22",
        "osv_fix_commit": "24a6d64966d99182e95f5d3a29541ef2fec397ad",
        "fix_commit": "1c335944d6a8b1298baf179b7c0b3069f10c514b",
        "ground_truth_files": ["aiohttp/web_urldispatcher.py"],
    },
    {
        "entry_id": "CVE-2024-34064-jinja",
        "cve": "CVE-2024-34064",
        "repo": "pallets/jinja",
        "cwe": "CWE-79",
        "osv_fix_commit": "dd4a8b5466d8790540c181590b14db4d889d57",
    },
    {
        "entry_id": "CVE-2023-46136-werkzeug",
        "cve": "CVE-2023-46136",
        "repo": "pallets/werkzeug",
        "cwe": "CWE-400",
        "osv_fix_commit": "ce4eff5902d4a6b41a20ecc6e4029741284a87fd",
    },
    {
        "entry_id": "CVE-2023-43804-urllib3",
        "cve": "CVE-2023-43804",
        "repo": "urllib3/urllib3",
        "cwe": "CWE-200",
        "osv_fix_commit": "c9016bf464751a02b7e46f8b86504f47d4238784",
    },
    {
        "entry_id": "CVE-2024-35195-requests",
        "cve": "CVE-2024-35195",
        "repo": "psf/requests",
        "cwe": "CWE-670",
        "osv_fix_commit": "a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac",
    },
    {
        "entry_id": "CVE-2024-40647-sentry",
        "cve": "CVE-2024-40647",
        "repo": "getsentry/sentry-python",
        "cwe": "CWE-200",
        "osv_fix_commit": "763e40aa4cb57ecced467f48f78f335c87e9bdff",
    },
    {
        "entry_id": "CVE-2023-37271-restrictedpython",
        "cve": "CVE-2023-37271",
        "repo": "zopefoundation/RestrictedPython",
        "cwe": "CWE-913",
        "osv_fix_commit": "f9ef13be3f38cb55fb6f714c608075e3c895032e",
    },
    {
        "entry_id": "CVE-2019-1010083-flask",
        "cve": "CVE-2019-1010083",
        "repo": "pallets/flask",
        "cwe": "CWE-400",
        "osv_fix_commit": "d92b64aa275841b0c9aea3903aba72fbc4275d91",
    },
    {
        "entry_id": "CVE-2023-30861-flask",
        "cve": "CVE-2023-30861",
        "repo": "pallets/flask",
        "cwe": "CWE-539",
        "osv_fix_commit": "afd63b16170b7c047f5758eb910c416511e9c965",
    },
    {
        "entry_id": "CVE-2017-18342-pyyaml",
        "cve": "CVE-2017-18342",
        "repo": "yaml/pyyaml",
        "cwe": "CWE-502",
        "osv_fix_commit": "e471e86bf6dabdad45a1438c20a4a5c033eb9034",
        # OSV tag is release-only; substantive fix is PR #257 merge (first parent = pre-fix).
        "fix_commit": "83b73947530bab216fb8fdb9ded521497a6d1920",
        "parent_commit": "ccc40f3e2ba384858c0d32263ac3e3a6626ab15e",
        "ground_truth_files": [
            "lib/yaml/__init__.py",
            "lib/yaml/constructor.py",
            "lib/yaml/cyaml.py",
            "lib/yaml/loader.py",
            "lib3/yaml/__init__.py",
            "lib3/yaml/constructor.py",
            "lib3/yaml/cyaml.py",
            "lib3/yaml/loader.py",
        ],
    },
    {
        "entry_id": "CVE-2020-14343-pyyaml",
        "cve": "CVE-2020-14343",
        "repo": "yaml/pyyaml",
        "cwe": "CWE-20",
        "osv_fix_commit": "58d0cb7ee09954c67fabfbd714c5673b03e7a9e1",
        # OSV tag is release-only; substantive fix moves python/object* to UnsafeLoader.
        "fix_commit": "a001f2782501ad2d24986959f0239a354675f9dc",
        "ground_truth_files": [
            "lib/yaml/constructor.py",
            "lib3/yaml/constructor.py",
        ],
    },
    {
        "entry_id": "CVE-2024-26130-cryptography",
        "cve": "CVE-2024-26130",
        "repo": "pyca/cryptography",
        "cwe": "CWE-476",
        "osv_fix_commit": "97d231672763cdb5959a3b191e692a362f1b9e55",
    },
    {
        "entry_id": "CVE-2023-23931-cryptography",
        "cve": "CVE-2023-23931",
        "repo": "pyca/cryptography",
        "cwe": "CWE-754",
        "osv_fix_commit": "d6951dca25de45abd52da51b608055371fbcde4e",
    },
    {
        "entry_id": "CVE-2024-52804-tornado",
        "cve": "CVE-2024-52804",
        "repo": "tornadoweb/tornado",
        "cwe": "CWE-400",
        "osv_fix_commit": "d5ba4a1695fbf7c6a3e54313262639b198291533",
    },
    {
        "entry_id": "CVE-2014-1932-pillow",
        "cve": "CVE-2014-1932",
        "repo": "python-pillow/Pillow",
        "cwe": "CWE-59",
        "osv_fix_commit": "4e9f367dfd3f04c8f5d23f7f759ec12782e10ee7",
    },
    {
        "entry_id": "CVE-2014-3589-pillow",
        "cve": "CVE-2014-3589",
        "repo": "python-pillow/Pillow",
        "cwe": "CWE-20",
        "osv_fix_commit": "205e056f8f9b06ed7b925cf8aa0874bc4aaf8a7d",
    },
    {
        "entry_id": "CVE-2021-28957-lxml",
        "cve": "CVE-2021-28957",
        "repo": "lxml/lxml",
        "cwe": "CWE-79",
        "osv_fix_commit": "a5f9cb52079dc57477c460dbe6ba0f775e14a999",
        # OSV tag is release-only; substantive fix is PR #316 (not on current default branch tip).
        "fix_commit": "10ec1b4e9f93713513a3264ed6158af22492f270",
        "parent_commit": "e986a9cb5d54827c59aefa8803bc90954d67221e",
        "ground_truth_files": ["src/lxml/html/defs.py"],
    },
]

# CVEs to import from OSV discovery (deduped by CVE id).
_OSU_PICK_IDS = {
    "CVE-2020-7471-django",
    "CVE-2015-8213-django",
    "CVE-2016-2513-django",
    "CVE-2018-19787-lxml",
    "CVE-2021-21330-aiohttp",
    "CVE-2023-47627-aiohttp",
    "CVE-2023-32681-requests",
    "CVE-2020-26137-urllib3",
    "CVE-2023-45803-urllib3",
    "CVE-2023-25577-werkzeug",
    "CVE-2019-12387-twisted",
    "CVE-2024-41810-twisted",
    "CVE-2021-41125-scrapy",
    "CVE-2024-1892-scrapy",
    "CVE-2018-7750-paramiko",
}


def _load_osv_picks() -> list[dict[str, object]]:
    if not OSV_CANDIDATES.is_file():
        return []
    payload = json.loads(OSV_CANDIDATES.read_text(encoding="utf-8"))
    picked: list[dict[str, object]] = []
    for entry in payload.get("entries", []):
        if entry.get("entry_id") in _OSU_PICK_IDS:
            picked.append(
                {
                    "entry_id": entry["entry_id"],
                    "cve": entry["cve"],
                    "repo": entry["repo"],
                    "cwe": entry["cwe"],
                    "osv_fix_commit": entry["osv_fix_commit"],
                }
            )
    return picked


def _merge_entries() -> list[dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    for entry in _load_osv_picks() + _MANUAL:
        merged[str(entry["cve"])] = entry
    return [merged[key] for key in sorted(merged)]


def _design_matrix(entries: list[dict[str, object]]) -> dict[str, object]:
    from collections import defaultdict

    import sys

    sys.path.insert(0, str(ROOT / "services" / "orchestrator"))
    from shift_left.cwe.mitre_export import mitre_weakness_meta

    matrix: dict[str, dict[str, int]] = defaultdict(lambda: {"Base": 0, "Class": 0})
    for entry in entries:
        meta = mitre_weakness_meta(str(entry["cwe"])) or {}
        abstraction = str(meta.get("abstraction") or "")
        bucket = "Base" if abstraction in {"Base", "Variant"} else "Class"
        matrix[str(entry["repo"])][bucket] += 1
    both = sorted(
        repo for repo, counts in matrix.items() if counts["Base"] and counts["Class"]
    )
    return {
        "repo_x_abstraction": {repo: dict(counts) for repo, counts in sorted(matrix.items())},
        "repos_with_both_abstractions": both,
        "repos_with_both_count": len(both),
    }


def main() -> int:
    entries = _merge_entries()
    design = _design_matrix(entries)
    payload = {
        "_meta": {
            "methodology": (
                "VLoc Bench-style multi-defect corpus: real CVEs, fix commits from OSV/GitHub "
                "advisories, ground truth = non-test/doc/changelog/version files in the effective "
                "fix commit, checkout at parent (pre-fix), .git stripped. Expanded for within-repo "
                "abstraction comparison."
            ),
            "runs_per_entry": 3,
            "size_cap_mib": 20,
            "target_entry_count": len(entries),
            "design_matrix": design,
        },
        "entries": entries,
    }
    MANIFEST_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "entry_count": len(entries),
                "repos_with_both_abstractions": design["repos_with_both_abstractions"],
                "repo_x_abstraction": design["repo_x_abstraction"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
