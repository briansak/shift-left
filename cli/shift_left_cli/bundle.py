"""Offline bundle builder and installer."""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path


def bundle_build(root: Path, output: Path) -> None:
    """
    Build a portable offline bundle on a connected machine.

    Contents: docker image tarballs, model directory, reference data, compose files.
    TODO: verify image digests and sign bundle for integrity verification.
    """
    print(f"Building offline bundle at {output}")
    staging = root / "data" / "bundle-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    images = [
        "postgres:16-alpine",
        "codeberg.org/forgejo/forgejo:11-rootless",
        "code.forgejo.org/forgejo/runner:6",
    ]
    images_dir = staging / "images"
    images_dir.mkdir()
    for image in images:
        tar_name = image.replace("/", "_").replace(":", "_") + ".tar"
        tar_path = images_dir / tar_name
        print(f"Saving image {image}...")
        subprocess.check_call(["docker", "save", "-o", str(tar_path), image])

    for name in ("config", "services", "templates", "scripts", "docker-compose.yml"):
        src = root / name
        if src.exists():
            dest = staging / name
            if src.is_dir():
                shutil.copytree(src, dest)
            else:
                shutil.copy2(src, dest)

    models_src = root / "models"
    if models_src.exists():
        shutil.copytree(models_src, staging / "models")
    else:
        legacy_models = root / "data" / "models"
        if legacy_models.exists():
            shutil.copytree(legacy_models, staging / "models")

    ref_src = root / "data" / "reference"
    if ref_src.exists():
        shutil.copytree(ref_src, staging / "reference")
    else:
        seed_src = root / "reference-seed"
        if seed_src.exists():
            shutil.copytree(seed_src, staging / "reference-seed")

    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "shift_left_root": str(root),
        "images": images,
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:xz") as archive:
        archive.add(staging, arcname="shift-left-bundle")

    shutil.rmtree(staging)
    print(f"Bundle written: {output}")


def bundle_install(root: Path, bundle: Path) -> None:
    """Install or update from an offline bundle on an air-gapped host."""
    if not bundle.exists():
        raise FileNotFoundError(bundle)

    print(f"Installing from bundle {bundle}")
    extract_dir = root / "data" / "bundle-extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)

    with tarfile.open(bundle, "r:xz") as archive:
        archive.extractall(extract_dir)

    bundle_root = extract_dir / "shift-left-bundle"
    images_dir = bundle_root / "images"
    if images_dir.exists():
        for tar_file in images_dir.glob("*.tar"):
            print(f"Loading image {tar_file.name}...")
            subprocess.check_call(["docker", "load", "-i", str(tar_file)])

    models_src = bundle_root / "models"
    if models_src.exists():
        dest = root / "data" / "models"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(models_src, dest)

    ref_src = bundle_root / "reference"
    if ref_src.exists():
        dest = root / "data" / "reference"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(ref_src, dest)
    else:
        seed_src = bundle_root / "reference-seed"
        if seed_src.exists():
            from shift_left_cli.sync_reference import sync_reference_data

            sync_reference_data(root)

    print("Offline bundle install complete. Run self-check and docker compose up -d.")
