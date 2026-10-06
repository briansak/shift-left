"""CWE localization candidate reference — read-only catalog browser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlencode

from shift_left.cwe.handler_assertions import (
    HandlerAssertion,
    handler_asserted_cwe_ids,
    handler_asserted_in_catalog_ids,
    handler_asserted_out_of_catalog_ids,
    handler_assertions_for_cwe,
)
from shift_left.cwe.mitre_export import mitre_weakness_meta
from shift_left.cwe.localization_candidates import (
    load_localization_candidates,
    localization_candidate_entries,
)
from shift_left.ui.cwe_dictionary import normalize_cwe_id

PAGE_SIZE = 50
LanguageMode = Literal["", "specific", "includes_agnostic", "agnostic_only"]
_NOT_LANGUAGE_SPECIFIC = "Not Language-Specific"


@dataclass(frozen=True)
class HandlerRuleView:
    rule_id: str
    source: str
    description: str
    target_type: str | None


@dataclass(frozen=True)
class CweReferenceRowView:
    cwe_id: str
    name: str
    abstraction: str
    languages_label: str
    tractability: str
    in_top25: bool
    has_handler_rule: bool
    short_description: str
    applicable_languages: tuple[str, ...]
    tractability_source: str | None
    handler_rules: tuple[HandlerRuleView, ...]
    launch_href: str | None


@dataclass(frozen=True)
class HandlerOutOfCatalogRowView:
    cwe_id: str
    mitre_abstraction: str
    name: str
    rule_count: int
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class CweReferenceFilterView:
    q: str
    abstraction: str
    tractability: str
    top25_only: bool
    handler_only: bool
    language: str
    language_mode: LanguageMode
    language_mode_options: tuple[tuple[str, str, int | None], ...]


@dataclass(frozen=True)
class CweReferenceListView:
    rows: tuple[CweReferenceRowView, ...]
    page: int
    page_size: int
    total_pages: int
    total_results: int
    filters: CweReferenceFilterView
    active_filter_summary: str
    empty_message: str | None
    prev_href: str | None
    next_href: str | None
    catalog_note: str
    handler_coverage_note: str
    tractability_note: str
    mitre_export: str
    entry_count: int
    can_launch_investigation: bool
    out_of_catalog_rows: tuple[HandlerOutOfCatalogRowView, ...]


def _catalog_meta() -> dict[str, Any]:
    return load_localization_candidates().get("_meta", {})


def _entry_languages(entry: dict[str, Any]) -> list[str]:
    return [str(lang) for lang in (entry.get("applicable_languages") or [])]


def _languages_label(languages: list[str]) -> str:
    if not languages:
        return "—"
    if languages == [_NOT_LANGUAGE_SPECIFIC]:
        return _NOT_LANGUAGE_SPECIFIC
    if len(languages) <= 2:
        return ", ".join(languages)
    return f"{languages[0]}, {languages[1]} +{len(languages) - 2}"


def language_mode_count(mode: LanguageMode, language: str) -> int:
    """Return survivor count for a language filter mode (offline catalog only)."""
    if mode == "agnostic_only":
        return sum(
            1
            for entry in localization_candidate_entries()
            if _entry_languages(entry) == [_NOT_LANGUAGE_SPECIFIC]
        )
    if not language:
        return 0
    if mode == "specific":
        return sum(
            1
            for entry in localization_candidate_entries()
            if language in _entry_languages(entry)
        )
    if mode == "includes_agnostic":
        return sum(
            1
            for entry in localization_candidate_entries()
            if _NOT_LANGUAGE_SPECIFIC in _entry_languages(entry)
            or language in _entry_languages(entry)
        )
    return len(localization_candidate_entries())


def _matches_language_filter(
    entry: dict[str, Any],
    *,
    language_mode: LanguageMode,
    language: str,
) -> bool:
    if not language_mode:
        return True
    langs = _entry_languages(entry)
    if language_mode == "agnostic_only":
        return langs == [_NOT_LANGUAGE_SPECIFIC]
    if not language:
        return True
    if language_mode == "specific":
        return language in langs
    if language_mode == "includes_agnostic":
        return _NOT_LANGUAGE_SPECIFIC in langs or language in langs
    return True


def _matches_search(entry: dict[str, Any], query: str) -> bool:
    if not query:
        return True
    needle = query.casefold()
    haystacks = (
        str(entry.get("id") or ""),
        str(entry.get("name") or ""),
        str(entry.get("short_description") or ""),
    )
    return any(needle in value.casefold() for value in haystacks)


def filter_localization_entries(
    *,
    q: str = "",
    abstraction: str = "",
    tractability: str = "",
    top25_only: bool = False,
    handler_only: bool = False,
    language_mode: LanguageMode = "",
    language: str = "",
) -> list[dict[str, Any]]:
    handler_ids = handler_asserted_cwe_ids()
    results: list[dict[str, Any]] = []
    for entry in localization_candidate_entries():
        cwe_id = normalize_cwe_id(str(entry.get("id") or ""))
        if abstraction and str(entry.get("abstraction") or "") != abstraction:
            continue
        entry_tractability = str(entry.get("tractability") or "unrated")
        if tractability and entry_tractability != tractability:
            continue
        if top25_only and not entry.get("in_cwe_top_25"):
            continue
        if handler_only and cwe_id not in handler_ids:
            continue
        if not _matches_language_filter(
            entry,
            language_mode=language_mode,
            language=language,
        ):
            continue
        if not _matches_search(entry, q.strip()):
            continue
        results.append(entry)
    results.sort(key=lambda item: (not bool(item.get("in_cwe_top_25")), str(item.get("id") or "")))
    return results


def _active_filter_labels(
    *,
    q: str,
    abstraction: str,
    tractability: str,
    top25_only: bool,
    handler_only: bool,
    language_mode: LanguageMode,
    language: str,
) -> list[str]:
    labels: list[str] = []
    if q.strip():
        labels.append(f'search "{q.strip()}"')
    if abstraction:
        labels.append(f"abstraction {abstraction}")
    if tractability:
        labels.append(f"tractability {tractability}")
    if top25_only:
        labels.append("Top 25 only")
    if handler_only:
        labels.append("handler-asserted only")
    if language_mode == "agnostic_only":
        labels.append("language-agnostic only")
    elif language_mode and language:
        if language_mode == "specific":
            labels.append(f"names {language} specifically")
        elif language_mode == "includes_agnostic":
            labels.append(f"includes {language} or language-agnostic")
    return labels


def _empty_message(active_labels: list[str]) -> str | None:
    if not active_labels:
        return None
    joined = ", ".join(active_labels)
    return f"No entries match the active filters ({joined}). Clear or adjust filters to see catalog rows."


def _build_query(
    *,
    page: int,
    q: str,
    abstraction: str,
    tractability: str,
    top25_only: bool,
    handler_only: bool,
    language_mode: LanguageMode,
    language: str,
) -> str:
    params: dict[str, str] = {}
    if q.strip():
        params["q"] = q.strip()
    if abstraction:
        params["abstraction"] = abstraction
    if tractability:
        params["tractability"] = tractability
    if top25_only:
        params["top25"] = "1"
    if handler_only:
        params["handler"] = "1"
    if language_mode:
        params["language_mode"] = language_mode
    if language:
        params["language"] = language
    if page > 1:
        params["page"] = str(page)
    return urlencode(params)


def build_handler_out_of_catalog_rows() -> tuple[HandlerOutOfCatalogRowView, ...]:
    rows: list[HandlerOutOfCatalogRowView] = []
    for cwe_id in handler_asserted_out_of_catalog_ids():
        assertions = handler_assertions_for_cwe(cwe_id)
        meta = mitre_weakness_meta(cwe_id)
        rule_ids = tuple(sorted({item.rule_id for item in assertions}))
        rows.append(
            HandlerOutOfCatalogRowView(
                cwe_id=cwe_id,
                mitre_abstraction=str(meta.get("abstraction") or "unknown"),
                name=str(meta.get("name") or cwe_id),
                rule_count=len(rule_ids),
                rule_ids=rule_ids,
            )
        )
    rows.sort(key=lambda item: (-item.rule_count, item.cwe_id))
    return tuple(rows)


def handler_coverage_partition() -> tuple[frozenset[str], frozenset[str]]:
    """Return (in-catalog handler CWE ids, out-of-catalog handler CWE ids)."""
    in_catalog = handler_asserted_in_catalog_ids()
    out_of_catalog = handler_asserted_out_of_catalog_ids()
    return in_catalog, out_of_catalog


def _handler_rule_views(assertions: list[HandlerAssertion]) -> tuple[HandlerRuleView, ...]:
    return tuple(
        HandlerRuleView(
            rule_id=item.rule_id,
            source=item.source,
            description=item.description,
            target_type=item.target_type,
        )
        for item in assertions
    )


def build_cwe_reference_list_view(
    *,
    page: int,
    q: str = "",
    abstraction: str = "",
    tractability: str = "",
    top25_only: bool = False,
    handler_only: bool = False,
    language_mode: LanguageMode = "",
    language: str = "",
    can_launch_investigation: bool = False,
) -> CweReferenceListView:
    meta = _catalog_meta()
    filtered = filter_localization_entries(
        q=q,
        abstraction=abstraction,
        tractability=tractability,
        top25_only=top25_only,
        handler_only=handler_only,
        language_mode=language_mode,
        language=language,
    )
    total_results = len(filtered)
    total_pages = max(1, (total_results + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(page, 1), total_pages)
    start = (page - 1) * PAGE_SIZE
    page_entries = filtered[start : start + PAGE_SIZE]

    handler_ids = handler_asserted_cwe_ids()
    rows: list[CweReferenceRowView] = []
    for entry in page_entries:
        cwe_id = normalize_cwe_id(str(entry.get("id") or ""))
        langs = tuple(_entry_languages(entry))
        description = str(entry.get("short_description") or "")
        assertions = handler_assertions_for_cwe(cwe_id)
        launch_href = None
        if can_launch_investigation:
            params = urlencode(
                {
                    "task_cwe": cwe_id,
                    "task_cwe_description": description,
                }
            )
            launch_href = f"/ui/investigations?{params}"
        rows.append(
            CweReferenceRowView(
                cwe_id=cwe_id,
                name=str(entry.get("name") or ""),
                abstraction=str(entry.get("abstraction") or ""),
                languages_label=_languages_label(list(langs)),
                tractability=str(entry.get("tractability") or "unrated"),
                in_top25=bool(entry.get("in_cwe_top_25")),
                has_handler_rule=cwe_id in handler_ids,
                short_description=description,
                applicable_languages=langs,
                tractability_source=str(entry.get("tractability_source") or "").strip() or None,
                handler_rules=_handler_rule_views(assertions),
                launch_href=launch_href,
            )
        )

    label_language = language or "Python"
    language_mode_options = (
        ("specific", f"Names {label_language} specifically", language_mode_count("specific", label_language)),
        ("includes_agnostic", "Includes language-agnostic", language_mode_count("includes_agnostic", label_language)),
        ("agnostic_only", "Language-agnostic only", language_mode_count("agnostic_only", label_language)),
    )

    active_labels = _active_filter_labels(
        q=q,
        abstraction=abstraction,
        tractability=tractability,
        top25_only=top25_only,
        handler_only=handler_only,
        language_mode=language_mode,
        language=language,
    )

    query_kwargs = {
        "q": q,
        "abstraction": abstraction,
        "tractability": tractability,
        "top25_only": top25_only,
        "handler_only": handler_only,
        "language_mode": language_mode,
        "language": language,
    }
    prev_href = None
    if page > 1:
        prev_href = f"/ui/cwe?{_build_query(page=page - 1, **query_kwargs)}"
    next_href = None
    if page < total_pages:
        next_href = f"/ui/cwe?{_build_query(page=page + 1, **query_kwargs)}"

    tractability_meta = meta.get("tractability_source", {})
    weak_examples = tractability_meta.get("model_card_weak_examples", {})
    excluded = ", ".join(weak_examples.get("excluded_class_abstractions", []))
    handler_total = len(handler_asserted_cwe_ids())
    handler_out_count = len(handler_asserted_out_of_catalog_ids())

    return CweReferenceListView(
        rows=tuple(rows),
        page=page,
        page_size=PAGE_SIZE,
        total_pages=total_pages,
        total_results=total_results,
        filters=CweReferenceFilterView(
            q=q,
            abstraction=abstraction,
            tractability=tractability,
            top25_only=top25_only,
            handler_only=handler_only,
            language=language,
            language_mode=language_mode,
            language_mode_options=language_mode_options,
        ),
        active_filter_summary=(
            f"{total_results} of {meta.get('entry_count', len(localization_candidate_entries()))} entries"
            + (f" · filters: {', '.join(active_labels)}" if active_labels else "")
        ),
        empty_message=_empty_message(active_labels) if total_results == 0 else None,
        prev_href=prev_href,
        next_href=next_href,
        catalog_note=(
            "Base and Variant abstractions only — Pillar, Class, Category, and Compound "
            "entries are excluded as not file-localizable."
        ),
        handler_coverage_note=(
            "Handler badges in the catalog table cover Base/Variant entries only; "
            f"{handler_out_count} of {handler_total} handler-asserted CWEs are Pillar or Class "
            "and appear in the section below — do not read the badge as full gate coverage."
        ),
        tractability_note=(
            "Tractability is rated for 3 of "
            f"{meta.get('entry_count', 838)} entries, sourced from the Antares model card "
            f"({tractability_meta.get('document', 'models/1b/README.md')}). "
            f"Two of the model card's three weak examples ({excluded}) are Class abstractions "
            "and therefore absent from this catalog."
        ),
        mitre_export=str(meta.get("mitre_export") or "unknown"),
        entry_count=int(meta.get("entry_count") or len(localization_candidate_entries())),
        can_launch_investigation=can_launch_investigation,
        out_of_catalog_rows=build_handler_out_of_catalog_rows(),
    )
