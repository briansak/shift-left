"""Shared MITRE CWE XML export parsing (local file only — no network)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(element.itertext()).strip()


def trim_sentences(text: str, max_sentences: int = 3) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return ""
    parts = [part.strip() for part in _SENTENCE_SPLIT.split(cleaned) if part.strip()]
    return " ".join(parts[:max_sentences])


def normalize_cwe_id(value: str) -> str:
    text = value.strip().upper()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def applicable_languages(weakness: ET.Element) -> list[str]:
    """Language applicability from MITRE Applicable_Platforms / Language nodes.

    Records ``Name`` when present; otherwise records ``Class`` (e.g. ``Not Language-Specific``).
    """
    languages: list[str] = []
    for child in weakness:
        if local_tag(child.tag) != "Applicable_Platforms":
            continue
        for platform in child:
            if local_tag(platform.tag) != "Language":
                continue
            name = (platform.get("Name") or "").strip()
            if name:
                languages.append(name)
                continue
            language_class = (platform.get("Class") or "").strip()
            if language_class:
                languages.append(language_class)
    return sorted(set(languages))


def parse_weakness(weakness: ET.Element) -> dict[str, object] | None:
    weakness_id = weakness.get("ID") or weakness.get("id")
    if not weakness_id:
        return None
    cwe_id = normalize_cwe_id(str(weakness_id))
    name = (weakness.get("Name") or weakness.get("name") or "").strip()
    abstraction = (weakness.get("Abstraction") or weakness.get("abstraction") or "").strip()
    description = ""
    for child in weakness:
        if local_tag(child.tag) == "Description":
            description = element_text(child)
            break
    if not description:
        for child in weakness:
            if local_tag(child.tag) == "Extended_Description":
                description = element_text(child)
                break
    return {
        "id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "short_description": trim_sentences(description),
        "applicable_languages": applicable_languages(weakness),
    }


def load_export(export_path: Path) -> dict[str, dict[str, object]]:
    tree = ET.parse(export_path)
    root = tree.getroot()
    weaknesses = root.findall(".//cwe:Weakness", _NS)
    if not weaknesses:
        weaknesses = [node for node in root.iter() if local_tag(node.tag) == "Weakness"]
    catalog: dict[str, dict[str, object]] = {}
    for weakness in weaknesses:
        entry = parse_weakness(weakness)
        if entry:
            catalog[str(entry["id"])] = entry
    return catalog
