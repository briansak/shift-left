"""Operator-run reference data sync — the ONLY component permitted egress."""

from __future__ import annotations

import json
import os
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

DATA_VERSION = "phase2-v2"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# TODO: verify MITRE CWE catalog archive URL and redistribution terms for your environment.
MITRE_CWE_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NVD_API_VERSION = "nvd-api-2.0"
CWE_CATALOG_SOURCE = "mitre-cwec-xml-zip"
MAX_NVD_WINDOW_DAYS = 120
CURSOR_FILENAME = "sync-cursor.json"


def sync_reference_cache(
    cache_dir: Path,
    *,
    seed_dir: Path | None = None,
    fetch_nvd: bool = False,
    nvd_api_key: str | None = None,
    resume: bool = True,
) -> dict:
    """
    Populate local CVE/CWE cache. Called only from operator CLI — never at review runtime.

    1. Copy bundled seed data (always)
    2. Optionally refresh CWE catalog from MITRE archive
    3. Optionally incrementally fetch NVD CVE records (resumable cursor)
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cwe_dir = cache_dir / "cwe"
    cve_dir = cache_dir / "cve"
    cwe_dir.mkdir(exist_ok=True)
    cve_dir.mkdir(exist_ok=True)

    if seed_dir is None:
        seed_dir = Path(__file__).resolve().parents[4] / "reference-seed"
    if seed_dir.exists():
        _copy_seed(seed_dir, cache_dir)

    cwe_result = {"fetched": 0, "catalog_version": None}
    if fetch_nvd or os.environ.get("SHIFT_LEFT_SYNC_CWE", "").lower() in {"1", "true", "yes"}:
        cwe_result = sync_cwe_catalog(cwe_dir)

    nvd_result = {"added": 0, "newest_last_modified": None}
    if fetch_nvd:
        nvd_result = sync_nvd_cves(
            cve_dir,
            cache_dir,
            api_key=nvd_api_key,
            resume=resume,
        )

    cwe_count = len(list(cwe_dir.glob("*.json")))
    cve_count = len(list(cve_dir.glob("*.json")))
    synced_at = datetime.now(timezone.utc).isoformat()

    manifest = {
        "synced_at": synced_at,
        "data_version": DATA_VERSION,
        "source": "shift-left sync-reference-data",
        "cwe_count": cwe_count,
        "cve_count": cve_count,
        "cwe_catalog_version": cwe_result.get("catalog_version"),
        "cwe_catalog_source": CWE_CATALOG_SOURCE if cwe_result.get("fetched") else "seed",
        "nvd_api_version": NVD_API_VERSION,
        "nvd_added_this_run": nvd_result.get("added", 0),
        "newest_last_modified": nvd_result.get("newest_last_modified"),
        "note": "Runtime pipeline reads this cache only — no network enrichment.",
    }
    (cache_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def sync_cwe_catalog(cwe_dir: Path) -> dict:
    """Fetch MITRE CWE catalog archive (separate from NVD pagination)."""
    request = urllib.request.Request(MITRE_CWE_ZIP)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"CWE catalog fetch skipped or failed: {exc}")
        return {"fetched": 0, "catalog_version": None}

    fetched = 0
    catalog_version: str | None = None
    with zipfile.ZipFile(BytesIO(payload)) as archive:
        xml_names = [name for name in archive.namelist() if name.endswith(".xml")]
        if not xml_names:
            return {"fetched": 0, "catalog_version": None}
        xml_name = xml_names[0]
        catalog_version = xml_name
        root = ElementTree.fromstring(archive.read(xml_name))
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
        for weakness in root.findall(".//cwe:Weakness", ns):
            cwe_id = weakness.get("ID")
            if not cwe_id:
                continue
            name_el = weakness.find("cwe:Name", ns)
            desc_el = weakness.find("cwe:Description", ns)
            record = {
                "id": f"CWE-{cwe_id}",
                "name": name_el.text if name_el is not None else "",
                "description": desc_el.text if desc_el is not None else "",
                "source": CWE_CATALOG_SOURCE,
                "catalog_version": catalog_version,
            }
            (cwe_dir / f"CWE-{cwe_id}.json").write_text(json.dumps(record, indent=2) + "\n")
            fetched += 1

    return {"fetched": fetched, "catalog_version": catalog_version}


def sync_nvd_cves(
    cve_dir: Path,
    cache_dir: Path,
    *,
    api_key: str | None,
    resume: bool,
) -> dict:
    cursor_path = cache_dir / CURSOR_FILENAME
    cursor = _load_cursor(cursor_path) if resume else {}
    window_start = _parse_dt(cursor.get("window_start")) or datetime(2002, 1, 1, tzinfo=timezone.utc)
    start_index = int(cursor.get("start_index", 0))
    newest_last_modified = cursor.get("newest_last_modified")
    added = 0

    now = datetime.now(timezone.utc)
    while window_start < now:
        window_end = min(window_start + timedelta(days=MAX_NVD_WINDOW_DAYS), now)
        while True:
            batch, total = _fetch_nvd_window(
                window_start,
                window_end,
                start_index=start_index,
                api_key=api_key,
            )
            if not batch:
                break

            for item in batch:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                last_modified = cve.get("lastModified")
                if last_modified and (not newest_last_modified or last_modified > newest_last_modified):
                    newest_last_modified = last_modified
                record = _normalize_nvd_cve(cve)
                (cve_dir / f"{cve_id}.json").write_text(json.dumps(record, indent=2) + "\n")
                added += 1

            start_index += len(batch)
            _save_cursor(
                cursor_path,
                {
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "start_index": start_index,
                    "newest_last_modified": newest_last_modified,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
            )

            if start_index >= total:
                break

        window_start = window_end + timedelta(seconds=1)
        start_index = 0
        _save_cursor(
            cursor_path,
            {
                "window_start": window_start.isoformat(),
                "start_index": 0,
                "newest_last_modified": newest_last_modified,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    return {"added": added, "newest_last_modified": newest_last_modified}


def _normalize_nvd_cve(cve: dict) -> dict:
    descriptions = cve.get("descriptions") or []
    summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return {
        "id": cve.get("id"),
        "summary": summary[:2000],
        "cwes": cwes,
        "last_modified": cve.get("lastModified"),
        "published": cve.get("published"),
        "source": NVD_API_VERSION,
        "api_version": NVD_API_VERSION,
    }


def _fetch_nvd_window(
    start: datetime,
    end: datetime,
    *,
    start_index: int,
    api_key: str | None,
    results_per_page: int = 2000,
) -> tuple[list[dict], int]:
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "startIndex": str(start_index),
        "resultsPerPage": str(results_per_page),
    }
    url = f"{NVD_CVE_API}?{urllib.parse.urlencode(params)}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(6):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode())
            total = int(payload.get("totalResults", 0))
            return payload.get("vulnerabilities", []), total
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < 5:
                delay = min(60, 2 ** attempt)
                print(f"NVD rate limited (429); backing off {delay}s")
                time.sleep(delay)
                continue
            print(f"NVD fetch failed: HTTP {exc.code}")
            return [], 0
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"NVD fetch failed: {exc}")
            return [], 0
    return [], 0


def _copy_seed(seed_dir: Path, cache_dir: Path) -> None:
    for sub in ("cwe", "cve"):
        src = seed_dir / sub
        if not src.exists():
            continue
        dest = cache_dir / sub
        dest.mkdir(exist_ok=True)
        for item in src.glob("*.json"):
            shutil.copy2(item, dest / item.name)


def _load_cursor(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _save_cursor(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
