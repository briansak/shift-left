"""MITRE CWE XML export parsing (local file only — no network)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

from shift_left.config import resolve_repo_root
from shift_left.cwe.localization_candidates import load_localization_candidates
from shift_left.ui.cwe_dictionary import normalize_cwe_id

_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(element.itertext()).strip()


def mitre_export_path() -> Path:
    meta = load_localization_candidates().get("_meta", {})
    export_name = str(meta.get("mitre_export") or "cwec_v4.20.xml")
    return resolve_repo_root() / "data" / "cwe" / "source" / export_name


@lru_cache(maxsize=1)
def load_mitre_weakness_catalog() -> dict[str, dict[str, object]]:
    path = mitre_export_path()
    if not path.is_file():
        return {}
    tree = ET.parse(path)
    root = tree.getroot()
    weaknesses = root.findall(".//cwe:Weakness", _NS)
    if not weaknesses:
        weaknesses = [node for node in root.iter() if local_tag(node.tag) == "Weakness"]
    catalog: dict[str, dict[str, object]] = {}
    for weakness in weaknesses:
        weakness_id = weakness.get("ID") or weakness.get("id")
        if not weakness_id:
            continue
        cwe_id = normalize_cwe_id(str(weakness_id))
        name = (weakness.get("Name") or weakness.get("name") or "").strip()
        abstraction = (weakness.get("Abstraction") or weakness.get("abstraction") or "").strip()
        catalog[cwe_id] = {
            "id": cwe_id,
            "name": name,
            "abstraction": abstraction,
        }
    return catalog


def mitre_weakness_meta(cwe_id: str) -> dict[str, object]:
    normalized = normalize_cwe_id(cwe_id)
    return load_mitre_weakness_catalog().get(normalized, {})
