#!/usr/bin/env python3
"""Assemble a multi-defect localization corpus from real CVE fix commits."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "validation"
sys.path.insert(0, str(VALIDATION))

from multidefect.ground_truth import (  # noqa: E402
    ground_truth_from_fix,
    is_excluded_ground_truth_path,
    resolve_effective_fix_commit,
)

sys.path.insert(0, str(ROOT / "services" / "antares-server"))
from antares_server.snapshot_materialize import materialize_tree_snapshot, remove_snapshot  # noqa: E402

MANIFEST_PATH = VALIDATION / "multidefect" / "manifest.json"
CORPUS_ROOT = VALIDATION / "corpus" / "multidefect"
SIDECAR_PATH = VALIDATION / "multidefect" / "ground-truth.json"
SIZE_CAP_BYTES = 20 * 1024 * 1024
_SPARSE_CHECKOUT_PATHS: dict[str, list[str]] = {
    "django/django": ["django"],
    "pyca/cryptography": ["src"],
}


def _repo_dir(entry_id: str) -> Path:
    return CORPUS_ROOT / entry_id


def _clone_repo(repo: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    sparse_paths = _SPARSE_CHECKOUT_PATHS.get(repo)
    if sparse_paths:
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--sparse",
                f"https://github.com/{repo}.git",
                str(dest),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set", *sparse_paths],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        subprocess.run(
            ["git", "clone", f"https://github.com/{repo}.git", str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )


def _ensure_commits(repo_path: Path, *commits: str) -> None:
    for commit in commits:
        if not commit:
            continue
        present = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{commit}^{{commit}}"],
            capture_output=True,
        )
        if present.returncode != 0:
            subprocess.run(
                ["git", "-C", str(repo_path), "fetch", "--depth", "1", "origin", commit],
                check=True,
                capture_output=True,
                text=True,
            )


def _checkout_commit(repo_path: Path, commit: str) -> None:
    subprocess.run(["git", "-C", str(repo_path), "checkout", "--force", commit], check=True)


def _strip_git(repo_path: Path) -> None:
    git_dir = repo_path / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)


def _materialize_corpus(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    snapshot_root = materialize_tree_snapshot(
        source,
        max_bytes=SIZE_CAP_BYTES,
        exclude_test_paths=True,
    )
    try:
        shutil.copytree(
            snapshot_root,
            dest,
            ignore=shutil.ignore_patterns(".git"),
            dirs_exist_ok=False,
        )
    finally:
        remove_snapshot(snapshot_root)

    # Drop docs/changelog paths excluded from VLoc GT but not test-path rules.
    for path in list(dest.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(dest).as_posix()
        if is_excluded_ground_truth_path(rel):
            path.unlink(missing_ok=True)
    for path in sorted((p for p in dest.rglob("*") if p.is_dir()), reverse=True):
        if not any(path.iterdir()):
            path.rmdir()


def _corpus_stats(repo_path: Path) -> dict[str, object]:
    files = [path for path in repo_path.rglob("*") if path.is_file()]
    py_files = [path for path in files if path.suffix == ".py"]
    total_bytes = sum(path.stat().st_size for path in files)
    languages: dict[str, int] = {}
    for path in py_files:
        languages["python"] = languages.get("python", 0) + 1
    return {
        "file_count": len(files),
        "python_file_count": len(py_files),
        "size_bytes": total_bytes,
        "size_mib": round(total_bytes / (1024 * 1024), 2),
        "language_mix": languages,
    }


def _mitre_and_catalog_flags(cwe: str) -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "services" / "orchestrator"))
    from shift_left.cwe.localization_candidates import localization_candidate_by_id
    from shift_left.cwe.mitre_export import mitre_weakness_meta

    meta = mitre_weakness_meta(cwe)
    abstraction = str(meta.get("abstraction") or "")
    in_catalog = localization_candidate_by_id(cwe) is not None
    localizable = abstraction in {"Base", "Variant"}
    return {
        "cwe_abstraction": abstraction,
        "cwe_in_localization_catalog": in_catalog,
        "cwe_file_localizable": localizable,
        "cwe_localization_flag": (
            "catalog"
            if in_catalog
            else ("pillar_or_class" if abstraction in {"Pillar", "Class"} else "absent")
        ),
    }


def _resolve_entry(entry: dict[str, object], work_repo: Path) -> dict[str, object]:
    fix_commit = entry.get("fix_commit")
    parent_commit = entry.get("parent_commit")
    ground_truth_files = entry.get("ground_truth_files")

    if fix_commit and parent_commit and ground_truth_files:
        gt_files = list(ground_truth_files)
    elif fix_commit and ground_truth_files:
        parent_commit = subprocess.check_output(
            ["git", "-C", str(work_repo), "rev-parse", f"{fix_commit}^"],
            text=True,
        ).strip()
        gt_files = list(ground_truth_files)
    else:
        fix_commit, parent_commit, gt_files = resolve_effective_fix_commit(
            work_repo,
            str(entry["osv_fix_commit"]),
        )

    if not gt_files:
        raise RuntimeError(f"No ground-truth files for {entry['entry_id']}")

    return {
        "fix_commit": str(fix_commit),
        "parent_commit": str(parent_commit),
        "ground_truth_files": gt_files,
    }


def build_entry(entry: dict[str, object]) -> dict[str, object]:
    entry_id = str(entry["entry_id"])
    repo = str(entry["repo"])
    work_repo = _repo_dir(f".work-{entry_id}")
    corpus_path = _repo_dir(entry_id)

    _clone_repo(repo, work_repo)
    _ensure_commits(
        work_repo,
        str(entry.get("fix_commit") or ""),
        str(entry.get("parent_commit") or ""),
        str(entry.get("osv_fix_commit") or ""),
    )
    resolved = _resolve_entry(entry, work_repo)
    _checkout_commit(work_repo, resolved["parent_commit"])

    _materialize_corpus(work_repo, corpus_path)
    _strip_git(corpus_path)
    shutil.rmtree(work_repo, ignore_errors=True)

    stats = _corpus_stats(corpus_path)
    if int(stats["size_bytes"]) > SIZE_CAP_BYTES:
        shutil.rmtree(corpus_path, ignore_errors=True)
        raise RuntimeError(
            f"{entry_id} exceeds size cap ({stats['size_mib']} MiB > 20 MiB)"
        )

    cwe_flags = _mitre_and_catalog_flags(str(entry["cwe"]))
    return {
        "entry_id": entry_id,
        "cve": entry["cve"],
        "repo": repo,
        "cwe": entry["cwe"],
        "osv_fix_commit": entry.get("osv_fix_commit"),
        "fix_commit": resolved["fix_commit"],
        "parent_commit": resolved["parent_commit"],
        "ground_truth_files": resolved["ground_truth_files"],
        "ground_truth_file_count": len(resolved["ground_truth_files"]),
        "corpus_path": str(corpus_path.relative_to(ROOT)),
        **stats,
        **cwe_flags,
    }


def _load_existing_sidecar_entry(entry_id: str) -> dict[str, object] | None:
    if not SIDECAR_PATH.is_file():
        return None
    payload = json.loads(SIDECAR_PATH.read_text(encoding="utf-8"))
    for item in payload.get("entries", []):
        if str(item.get("entry_id")) == entry_id:
            corpus_path = ROOT / str(item.get("corpus_path", ""))
            if corpus_path.is_dir():
                return item
    return None


def build(*, reuse_existing: bool = True) -> dict[str, object]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    built: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for entry in manifest["entries"]:
        entry_id = str(entry.get("entry_id"))
        if reuse_existing:
            existing = _load_existing_sidecar_entry(entry_id)
            if existing is not None:
                built.append(existing)
                continue
        try:
            built.append(build_entry(entry))
        except Exception as exc:
            skipped.append({"entry_id": entry.get("entry_id"), "error": str(exc)})

    payload = {
        "manifest": manifest["_meta"],
        "entries": built,
        "skipped": skipped,
        "entry_count": len(built),
    }
    SIDECAR_PATH.parent.mkdir(parents=True, exist_ok=True)
    SIDECAR_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    payload = build()
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
