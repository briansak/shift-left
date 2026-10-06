#!/usr/bin/env python3
"""Regenerate data/cwe/localization-candidates.json from a local MITRE CWE export (no network).

Usage:
  python scripts/build-localization-candidates.py /path/to/cwec_latest.xml

Download the CWE catalog XML from MITRE on a connected machine (operator-initiated
egress only), then copy the file into the air-gapped environment:

  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

Output: data/cwe/localization-candidates.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from cwe_mitre_export import load_export, normalize_cwe_id  # noqa: E402

LOCALIZATION_ABSTRACTIONS = frozenset({"Base", "Variant"})
TRACTABILITY_SOURCE = {
    "document": "models/1b/README.md",
    "section": "Limitations",
    "item": 2,
    "quote": (
        "The model performs best on vulnerability types with distinctive, grep-able code "
        "patterns (e.g., CWE-843 Type Confusion, CWE-1321 Prototype Pollution). It performs "
        "poorly on CWE types requiring semantic understanding of code behavior rather than "
        "pattern matching (e.g., CWE-732 Incorrect Permissions, CWE-667 Improper Locking, "
        "CWE-401 Memory Leak)."
    ),
    "strong_cwes": ["CWE-843", "CWE-1321"],
    "weak_cwes": ["CWE-732", "CWE-667", "CWE-401"],
    "model_card_weak_examples": {
        "weak_cwes_named": ["CWE-732", "CWE-667", "CWE-401"],
        "excluded_class_abstractions": ["CWE-732", "CWE-667"],
        "localizable_weak_example": "CWE-401",
        "finding": (
            "Two of three Antares model-card weak-tractability examples (CWE-732, CWE-667) are "
            "Class abstractions in MITRE and are excluded here as not file-localizable. That is "
            "partly a category-abstraction mismatch, not purely a model limitation — worth "
            "reporting upstream to the Antares model-card authors."
        ),
    },
}
STRONG_CWES = frozenset(TRACTABILITY_SOURCE["strong_cwes"])
WEAK_CWES = frozenset(TRACTABILITY_SOURCE["weak_cwes"])


def localization_candidates_path() -> Path:
    return ROOT / "data" / "cwe" / "localization-candidates.json"


def cwe_top_25_path() -> Path:
    return ROOT / "data" / "cwe" / "cwe-top-25-2024.json"


def load_cwe_top_25_ids() -> frozenset[str]:
    payload = json.loads(cwe_top_25_path().read_text(encoding="utf-8"))
    return frozenset(normalize_cwe_id(entry["id"]) for entry in payload.get("entries", []))


def tractability_for(cwe_id: str) -> str:
    if cwe_id in STRONG_CWES:
        return "strong"
    if cwe_id in WEAK_CWES:
        return "weak"
    return "unrated"


def build_candidates(catalog: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    top_25 = load_cwe_top_25_ids()
    candidates: list[dict[str, object]] = []
    for cwe_id in sorted(catalog):
        entry = catalog[cwe_id]
        abstraction = str(entry.get("abstraction") or "")
        if abstraction not in LOCALIZATION_ABSTRACTIONS:
            continue
        short_description = str(entry.get("short_description") or "").strip()
        if not short_description:
            raise ValueError(f"{cwe_id} has no dictionary description in the export")
        tractability = tractability_for(cwe_id)
        candidate: dict[str, object] = {
            "id": cwe_id,
            "name": str(entry.get("name") or ""),
            "abstraction": abstraction,
            "short_description": short_description,
            "applicable_languages": list(entry.get("applicable_languages") or []),
            "tractability": tractability,
            "in_cwe_top_25": cwe_id in top_25,
        }
        if tractability in {"strong", "weak"}:
            candidate["tractability_source"] = TRACTABILITY_SOURCE["document"]
        candidates.append(candidate)
    return candidates


_LANGUAGE_AGNOSTIC = "Not Language-Specific"
_NAMED_LANGUAGE_COUNTS = ("Python", "JavaScript", "Go", "Java", "C", "C++")


def _language_applicability_analysis(entries: list[dict[str, object]]) -> dict[str, object]:
    specific_named_only = 0
    language_agnostic_only = 0
    both_agnostic_and_named = 0
    no_applicable_languages = 0
    named_language_counts: dict[str, int] = {name: 0 for name in _NAMED_LANGUAGE_COUNTS}

    for entry in entries:
        languages = list(entry.get("applicable_languages") or [])
        if not languages:
            no_applicable_languages += 1
            continue
        named = [lang for lang in languages if lang != _LANGUAGE_AGNOSTIC]
        has_agnostic = _LANGUAGE_AGNOSTIC in languages
        if has_agnostic and named:
            both_agnostic_and_named += 1
        elif has_agnostic:
            language_agnostic_only += 1
        else:
            specific_named_only += 1
        for lang in named:
            if lang in named_language_counts:
                named_language_counts[lang] += 1

    def _survives_filter(target_languages: set[str]) -> int:
        count = 0
        for entry in entries:
            languages = list(entry.get("applicable_languages") or [])
            if not languages:
                continue
            named = {lang for lang in languages if lang != _LANGUAGE_AGNOSTIC}
            if _LANGUAGE_AGNOSTIC in languages:
                count += 1
                continue
            if named & target_languages:
                count += 1
        return count

    dictionary_path = ROOT / "data" / "cwe" / "cwe-dictionary.json"
    dictionary_ids = set()
    if dictionary_path.is_file():
        dictionary_ids = set(json.loads(dictionary_path.read_text(encoding="utf-8")).keys())
    in_ui_dictionary = sum(1 for entry in entries if str(entry["id"]) in dictionary_ids)
    with_model_prompt_description = sum(
        1 for entry in entries if str(entry.get("short_description") or "").strip()
    )

    return {
        "entry_count": len(entries),
        "specific_named_languages_only": specific_named_only,
        "language_agnostic_only": language_agnostic_only,
        "both_language_agnostic_and_named": both_agnostic_and_named,
        "no_applicable_languages": no_applicable_languages,
        "named_language_counts": named_language_counts,
        "named_language_c_cpp_combined": named_language_counts["C"] + named_language_counts["C++"],
        "picker_survivors": {
            "python_only_repo": _survives_filter({"Python"}),
            "python_and_javascript_repo": _survives_filter({"Python", "JavaScript"}),
            "filter_rule": (
                "Include when MITRE lists Not Language-Specific, or when any named language "
                "overlaps the repo's detected languages. Entries with no applicable_languages "
                "cannot be language-filtered."
            ),
        },
        "no_applicable_languages_policy": (
            "Pending — 30 entries have no MITRE Language platform data and cannot be "
            "language-filtered. Exclude from language-scoped picker until curated or enriched."
        ),
        "descriptions": {
            "with_model_prompt_description": with_model_prompt_description,
            "in_ui_dictionary": in_ui_dictionary,
            "would_need_ui_dictionary_entry": len(entries) - in_ui_dictionary,
            "note": (
                "Model prompt descriptions come from short_description in this file (MITRE export). "
                "cwe-dictionary.json is a separate 9-entry UI popover subset."
            ),
        },
    }


def build_payload(catalog: dict[str, dict[str, object]], export_path: Path) -> dict[str, object]:
    entries = build_candidates(catalog)
    return {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "mitre_export": export_path.name,
            "entry_count": len(entries),
            "abstraction_filter": sorted(LOCALIZATION_ABSTRACTIONS),
            "abstraction_filter_note": (
                "Base/Variant filter removed 131 of 969 MITRE weaknesses; 838 remain and are "
                "still too broad for a repo picker without language filtering."
            ),
            "tractability_source": TRACTABILITY_SOURCE,
            "language_applicability": _language_applicability_analysis(entries),
            "cwe_top_25": {
                "year": 2024,
                "source": "data/cwe/cwe-top-25-2024.json",
            },
            "vloc_bench_cwes": {
                "available_offline": False,
                "note": (
                    "VLoc Bench 147 CWE list is not vendored in this repository; "
                    "in_vloc_bench flags are omitted."
                ),
            },
        },
        "entries": entries,
    }


def summarize(entries: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    by_abstraction: dict[str, int] = {}
    by_tractability: dict[str, int] = {}
    for entry in entries:
        abstraction = str(entry["abstraction"])
        tractability = str(entry["tractability"])
        by_abstraction[abstraction] = by_abstraction.get(abstraction, 0) + 1
        by_tractability[tractability] = by_tractability.get(tractability, 0) + 1
    return {"abstraction": by_abstraction, "tractability": by_tractability}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build localization CWE candidate catalog from a local MITRE XML export."
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

    catalog = load_export(args.export_path)
    payload = build_payload(catalog, args.export_path)
    out_path = localization_candidates_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    counts = summarize(payload["entries"])
    print(f"Wrote {payload['_meta']['entry_count']} entries to {out_path}")
    print("By abstraction:", counts["abstraction"])
    print("By tractability:", counts["tractability"])
    top_25_hits = sum(1 for entry in payload["entries"] if entry.get("in_cwe_top_25"))
    print(f"In CWE Top 25: {top_25_hits}")
    lang = payload["_meta"]["language_applicability"]
    print("Language applicability:", json.dumps(lang, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
