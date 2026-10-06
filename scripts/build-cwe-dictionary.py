#!/usr/bin/env python3
"""Regenerate data/cwe/cwe-dictionary.json from a local MITRE CWE export (no network).

Usage:
  python scripts/build-cwe-dictionary.py /path/to/cwec_latest.xml

Download the CWE catalog XML from MITRE on a connected machine (operator-initiated
egress only), then copy the file into the air-gapped environment:

  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

The script reads CWE ids required by the registry, default gate policies, and known
model-asserted ids (see shift_left.ui.cwe_dictionary.required_dictionary_cwe_ids).

Output: data/cwe/cwe-dictionary.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / "services" / "orchestrator"
if str(ORCHESTRATOR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR))

from shift_left.ui.cwe_dictionary import (  # noqa: E402
    cwe_dictionary_path,
    normalize_cwe_id,
    required_dictionary_cwe_ids,
)

_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(element.itertext()).strip()


def _trim_sentences(text: str, max_sentences: int = 3) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return ""
    parts = [part.strip() for part in _SENTENCE_SPLIT.split(cleaned) if part.strip()]
    return " ".join(parts[:max_sentences])


def _parse_weakness(weakness: ET.Element) -> dict[str, str] | None:
    weakness_id = weakness.get("ID") or weakness.get("id")
    if not weakness_id:
        return None
    cwe_id = normalize_cwe_id(str(weakness_id))
    name = weakness.get("Name") or weakness.get("name") or ""
    abstraction = weakness.get("Abstraction") or weakness.get("abstraction") or ""
    description = ""
    for child in weakness:
        if _local_tag(child.tag) == "Description":
            description = _element_text(child)
            break
    if not description:
        for child in weakness:
            if _local_tag(child.tag) == "Extended_Description":
                description = _element_text(child)
                break
    return {
        "id": cwe_id,
        "name": name.strip(),
        "abstraction": abstraction.strip(),
        "short_description": _trim_sentences(description),
        "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html",
    }


def load_export(export_path: Path) -> dict[str, dict[str, str]]:
    tree = ET.parse(export_path)
    root = tree.getroot()
    weaknesses = root.findall(".//cwe:Weakness", _NS)
    if not weaknesses:
        weaknesses = [node for node in root.iter() if _local_tag(node.tag) == "Weakness"]
    catalog: dict[str, dict[str, str]] = {}
    for weakness in weaknesses:
        entry = _parse_weakness(weakness)
        if entry:
            catalog[entry["id"]] = entry
    return catalog


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build offline CWE dictionary from a local MITRE XML export."
    )
    parser.add_argument(
        "export_path",
        type=Path,
        help="Path to cwec_*.xml (local file only — never downloaded by this script)",
    )
    args = parser.parse_args()
    if not args.export_path.is_file():
        print(f"Export file not found: {args.export_path}", file=sys.stderr)
        return 1

    required = sorted(required_dictionary_cwe_ids())
    catalog = load_export(args.export_path)
    output: dict[str, dict[str, str]] = {}
    missing: list[str] = []
    for cwe_id in required:
        entry = catalog.get(cwe_id)
        if entry is None:
            missing.append(cwe_id)
            continue
        output[cwe_id] = entry
    if missing:
        print("Missing CWE ids in export:", ", ".join(missing), file=sys.stderr)
        return 1

    out_path = cwe_dictionary_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(output)} entries to {out_path}")
    orphans = sorted(set(catalog) - set(required))
    if orphans:
        print(f"Note: {len(orphans)} export entries were not required by registry/gate policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
