"""Inputs for Experiment F: cookbook prose review per labeled corpus file."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cookbook_prose_prompt import build_cookbook_prompt
from eval_handlers import HOLDOUT_CORPUS_DIR, GENERATED_CORPUS_DIR, CorpusEntry, load_corpus
from eval_model import RULE_SEMANTICS

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class CookbookFileRun:
    file_key: str
    corpus: str
    rel_path: str
    target_type: str
    virtual_path: str
    expected_rule_ids: tuple[str, ...]
    prompt: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LabeledDefect:
    instance_id: str
    file_key: str
    corpus: str
    rel_path: str
    target_type: str
    rule_id: str
    defect_summary: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def corpus_dirs() -> list[tuple[str, Path]]:
    return [
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ]


def build_cookbook_inputs() -> tuple[list[CookbookFileRun], list[LabeledDefect]]:
    file_runs: list[CookbookFileRun] = []
    instances: list[LabeledDefect] = []

    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            if not entry.expected_rule_ids:
                continue
            content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
            file_key = f"{corpus_name}/{entry.rel_path}"
            file_runs.append(
                CookbookFileRun(
                    file_key=file_key,
                    corpus=corpus_name,
                    rel_path=entry.rel_path,
                    target_type=entry.target_type,
                    virtual_path=entry.virtual_path,
                    expected_rule_ids=tuple(sorted(entry.expected_rule_ids)),
                    prompt=build_cookbook_prompt(
                        file_path=entry.virtual_path,
                        content=content,
                    ),
                )
            )
            for rule_id in sorted(entry.expected_rule_ids):
                sem = RULE_SEMANTICS[rule_id]
                instances.append(
                    LabeledDefect(
                        instance_id=f"{file_key}#{rule_id}",
                        file_key=file_key,
                        corpus=corpus_name,
                        rel_path=entry.rel_path,
                        target_type=entry.target_type,
                        rule_id=rule_id,
                        defect_summary=sem.defect_summary,
                    )
                )

    return file_runs, instances
