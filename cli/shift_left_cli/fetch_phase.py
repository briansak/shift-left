"""Fetch images, model weights, and reference seed."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from shift_left_cli.compose_util import detect_compose


def fetch_all(root: Path) -> None:
    from shift_left_cli.models_check import inspect_model_staging, print_model_staging_report
    from shift_left_cli.preflight import ensure_docker_daemon

    ensure_docker_daemon(root)
    staging = print_model_staging_report(root)

    compose = detect_compose(root)
    print("Pulling container images…")
    subprocess.check_call(compose.cmd("pull", "postgres", "forgejo", "orchestrator"), cwd=root)
    print("Building forgejo-runner image (curl for Actions host-mode jobs)…")
    subprocess.check_call(compose.cmd("build", "forgejo-runner"), cwd=root)
    print("Building orchestrator image…")
    subprocess.check_call(compose.cmd("build", "orchestrator"), cwd=root)

    if staging.needs_foundation_sec_download:
        _fetch_foundation_sec_q4(root)
    _verify_foundation_sec_weights(root)
    _seed_reference(root)


def _fetch_foundation_sec_q4(root: Path) -> None:
    from shift_left_cli.hf_download import download_repo_file
    from shift_left_cli.models_check import inspect_model_staging
    from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M

    if not inspect_model_staging(root).needs_foundation_sec_download:
        return

    dest = root / VERIFIED_FOUNDATION_SEC_Q4_K_M["local_path_default"]
    print("Downloading Foundation-Sec Q4_K_M via huggingface_hub…")
    download_repo_file(
        root,
        repo_id=VERIFIED_FOUNDATION_SEC_Q4_K_M["hf_repo_id"],
        filename=VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_filename"],
        dest_dir=dest,
    )
    print("Foundation-Sec Q4_K_M download complete.")


def _verify_foundation_sec_weights(root: Path) -> None:
    from shift_left_cli.models_check import inspect_model_staging
    from shift_left_shared.weights import (
        VERIFIED_FOUNDATION_SEC_Q4_K_M,
        VERIFIED_FOUNDATION_SEC_Q8_0,
        load_prewarm_manifest,
        verify_gguf_weight,
    )

    staging = inspect_model_staging(root)
    gguf = staging.active_gguf_path
    if gguf is None:
        raise FileNotFoundError(
            "Foundation-Sec weights not found under models/. "
            "Restore your GGUF backup and re-run ./shift-left up."
        )

    if staging.foundation_sec_q4_path is not None:
        meta = VERIFIED_FOUNDATION_SEC_Q4_K_M
        label = "Q4_K_M"
    else:
        meta = VERIFIED_FOUNDATION_SEC_Q8_0
        label = "Q8_0"

    manifest = load_prewarm_manifest(root)
    verify_gguf_weight(
        gguf.parent,
        manifest,
        manifest_key=meta["manifest_key"],
        verified_meta=meta,
    )
    print(f"Foundation-Sec {label} SHA256 verified ({gguf.relative_to(root)}).")


def _seed_reference(root: Path) -> None:
    from shift_left_cli.sync_reference import sync_reference_data

    print("Seeding reference data cache from bundled seed…")
    sync_reference_data(root, fetch_nvd=False)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
