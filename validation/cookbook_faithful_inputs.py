"""Inputs for Experiment H: cookbook-faithful config assessment (production chat path)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cookbook_faithful_prompt import build_cookbook_faithful_prompt
from cookbook_prose_inputs import corpus_dirs
from eval_handlers import CorpusEntry, load_corpus
from eval_model import RULE_SEMANTICS

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class FaithfulFileRun:
    file_key: str
    corpus: str
    rel_path: str
    target_type: str
    virtual_path: str
    expected_rule_ids: tuple[str, ...]
    config_content: str
    prompt: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FaithfulLabeledDefect:
    instance_id: str
    file_key: str
    corpus: str
    rel_path: str
    target_type: str
    rule_id: str
    defect_summary: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_faithful_inputs() -> tuple[list[FaithfulFileRun], list[FaithfulLabeledDefect]]:
    file_runs: list[FaithfulFileRun] = []
    instances: list[FaithfulLabeledDefect] = []

    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            if not entry.expected_rule_ids:
                continue
            content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
            file_key = f"{corpus_name}/{entry.rel_path}"
            file_runs.append(
                FaithfulFileRun(
                    file_key=file_key,
                    corpus=corpus_name,
                    rel_path=entry.rel_path,
                    target_type=entry.target_type,
                    virtual_path=entry.virtual_path,
                    expected_rule_ids=tuple(sorted(entry.expected_rule_ids)),
                    config_content=content,
                    prompt=build_cookbook_faithful_prompt(config_text=content),
                )
            )
            for rule_id in sorted(entry.expected_rule_ids):
                sem = RULE_SEMANTICS[rule_id]
                instances.append(
                    FaithfulLabeledDefect(
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
