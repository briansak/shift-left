"""Localization CWE candidate catalog integrity."""

from __future__ import annotations

import inspect

from shift_left.cwe import localization_candidates as localization_candidates_module
from shift_left.cwe.localization_candidates import (
    abstraction_counts,
    entries_missing_descriptions,
    entries_with_invalid_abstraction,
    entries_with_tractability_missing_citation,
    localization_candidate_entries,
    localization_candidates_path,
    tractability_counts,
)
from shift_left.investigations.suitability import STRONG_CWES, WEAK_CWES


def test_localization_candidates_file_exists() -> None:
    path = localization_candidates_path()
    assert path.is_file(), f"Missing catalog: {path}"


def test_every_entry_has_dictionary_description() -> None:
    missing = entries_missing_descriptions()
    assert not missing, f"Entries missing short_description: {missing[:10]}"


def test_abstraction_filter_enforced() -> None:
    invalid = entries_with_invalid_abstraction()
    assert not invalid, f"Non-Base/Variant entries present: {invalid[:10]}"


def test_strong_weak_entries_have_model_card_citation() -> None:
    missing = entries_with_tractability_missing_citation()
    assert not missing, f"Rated entries missing tractability_source: {missing}"


def test_tractability_ratings_match_model_card_only() -> None:
    for entry in localization_candidate_entries():
        cwe_id = str(entry["id"])
        tractability = str(entry["tractability"])
        if cwe_id in STRONG_CWES:
            assert tractability == "strong"
        elif cwe_id in WEAK_CWES:
            assert tractability == "weak"
        else:
            assert tractability == "unrated"


def test_model_card_tractability_examples_in_catalog_when_localizable() -> None:
    """Strong/weak model-card examples that are Base/Variant appear with correct ratings."""
    catalog_ids = {str(entry["id"]) for entry in localization_candidate_entries()}
    # CWE-732 and CWE-667 are Class abstractions in MITRE — excluded from localization picker.
    localizable_examples = {"CWE-843", "CWE-1321", "CWE-401"}
    assert localizable_examples <= catalog_ids


def test_catalog_has_base_and_variant_entries() -> None:
    counts = abstraction_counts()
    assert counts.get("Base", 0) > 0
    assert counts.get("Variant", 0) > 0
    assert sum(counts.values()) == len(localization_candidate_entries())


def test_tractability_breakdown_includes_unrated_majority() -> None:
    counts = tractability_counts()
    assert counts.get("strong", 0) == len(STRONG_CWES)
    # Only CWE-401 among model-card weak examples is Base/Variant in the MITRE export.
    assert counts.get("weak", 0) == 1
    assert counts.get("unrated", 0) > 0


def test_vloc_bench_list_not_available_offline() -> None:
    payload = localization_candidates_module.load_localization_candidates()
    vloc = payload.get("_meta", {}).get("vloc_bench_cwes", {})
    assert vloc.get("available_offline") is False


def test_meta_records_language_applicability_analysis() -> None:
    payload = localization_candidates_module.load_localization_candidates()
    lang = payload["_meta"]["language_applicability"]
    assert lang["entry_count"] == len(localization_candidate_entries())
    assert lang["no_applicable_languages"] == 30
    assert lang["picker_survivors"]["python_only_repo"] == 643
    assert lang["picker_survivors"]["python_and_javascript_repo"] == 645
    assert lang["descriptions"]["with_model_prompt_description"] == lang["entry_count"]


def test_meta_records_model_card_class_abstraction_finding() -> None:
    payload = localization_candidates_module.load_localization_candidates()
    weak = payload["_meta"]["tractability_source"]["model_card_weak_examples"]
    assert weak["excluded_class_abstractions"] == ["CWE-732", "CWE-667"]
    assert "category-abstraction" in weak["finding"]


def test_localization_candidates_reads_local_file_only() -> None:
    source = inspect.getsource(localization_candidates_module)
    lowered = source.lower()
    assert "httpx" not in lowered
    assert "urllib.request" not in lowered
    assert "requests." not in lowered
    assert "aiohttp" not in lowered
    assert "urlopen" not in lowered
