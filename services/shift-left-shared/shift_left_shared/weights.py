"""Verified model weight metadata, manifest loading, and SHA256 verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Operator-verified staging metadata — do not assert unverified repo ids elsewhere.
VERIFIED_ANTARES_350M = {
    "manifest_key": "antares-350m",
    "hf_repo_id": "fdtn-ai/antares-350m",
    "weight_filename": "model.safetensors",
    "sha256": "298dc28c73ba1e02528d5dbc16a064a654c60a5853c131f55934678d85abf121",
    "license": "Apache-2.0",
    "hf_gated": True,
    "local_path_default": "models/350m",
}

VERIFIED_ANTARES_1B = {
    "manifest_key": "antares-1b",
    "hf_repo_id": "fdtn-ai/antares-1b",
    "weight_filename": "model.safetensors",
    "sha256": "6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675",
    "license": "Apache-2.0",
    "hf_gated": True,
    "local_path_default": "models/1b",
}

VERIFIED_FOUNDATION_SEC_Q8_0 = {
    "manifest_key": "foundation-sec",
    "hf_repo_id": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF",
    "gguf_filename": "foundation-sec-1.1-8b-instruct-q8_0.gguf",
    "gguf_glob": "foundation-sec-1.1-8b-instruct-q8_0.gguf",
    "sha256": "ea401b43ee9e79607ae34157e88c3b03c468b50b5f4194e7c82b9e3130e0b2e5",
    "license": "Apache-2.0",
    "hf_gated": False,
    "local_path_default": "models/foundation-sec-q8_0",
}

VERIFIED_FOUNDATION_SEC_Q4_K_M = {
    "manifest_key": "foundation-sec-low-memory",
    "hf_repo_id": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF",
    "gguf_filename": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
    "gguf_glob": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
    "sha256": "5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed",
    "license": "Apache-2.0",
    "hf_gated": False,
    "local_path_default": "models/foundation-sec-q4_k_m",
    "model_variant": "instruct",
}

VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M = {
    "manifest_key": "foundation-sec-reasoning",
    "hf_repo_id": "fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF",
    "gguf_filename": "foundation-sec-8b-reasoning-q4_k_m.gguf",
    "gguf_glob": "foundation-sec-8b-reasoning-q4_k_m.gguf",
    "sha256": "7a61e41b1ca1b339d41caf3001ea7832469d866e7c52a23980a1e95cbf5cd58b",
    "license": "Apache-2.0",
    "hf_gated": False,
    "local_path_default": "models/foundation-sec-reasoning-q4_k_m",
    "model_variant": "reasoning",
}


@dataclass(frozen=True)
class WeightVerificationError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_path(repo_root: Path) -> Path:
    return repo_root / "models" / ".prewarm-manifest.json"


def load_prewarm_manifest(repo_root: Path) -> dict[str, Any]:
    path = manifest_path(repo_root)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _entry(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    models = manifest.get("models") or {}
    entry = models.get(key)
    return entry if isinstance(entry, dict) else {}


def verify_file_sha256(path: Path, expected_sha256: str, *, label: str) -> None:
    if not expected_sha256 or expected_sha256.startswith("TODO"):
        raise WeightVerificationError(
            f"{label}: SHA256 not pinned — update models/.prewarm-manifest.json from "
            "config/prewarm-manifest.example.json after staging weights."
        )
    if not path.exists():
        raise WeightVerificationError(f"{label}: weight file missing at {path}")
    actual = sha256_file(path)
    if actual != expected_sha256.lower():
        raise WeightVerificationError(
            f"{label}: SHA256 mismatch for {path.name}: expected {expected_sha256}, got {actual}"
        )


VERIFIED_ANTARES_VARIANTS: tuple[dict[str, str], ...] = (
    VERIFIED_ANTARES_1B,
    VERIFIED_ANTARES_350M,
)


def antares_manifest_meta_for_dir(model_dir: Path) -> dict[str, str]:
    """Resolve staged Antares variant from directory name or weight SHA256."""
    resolved = model_dir.resolve()
    if resolved.name == "1b":
        return VERIFIED_ANTARES_1B
    if resolved.name == "350m":
        return VERIFIED_ANTARES_350M

    weight_path = resolved / VERIFIED_ANTARES_1B["weight_filename"]
    if weight_path.is_file():
        actual = sha256_file(weight_path)
        for meta in VERIFIED_ANTARES_VARIANTS:
            if actual == meta["sha256"]:
                return meta
    return VERIFIED_ANTARES_1B


def verify_antares_weights(model_dir: Path, manifest: dict[str, Any]) -> Path:
    meta = antares_manifest_meta_for_dir(model_dir)
    entry = _entry(manifest, meta["manifest_key"])
    expected_name = entry.get("weight_filename") or meta["weight_filename"]
    expected_sha = entry.get("sha256") or meta["sha256"]
    weight_path = model_dir / expected_name
    verify_file_sha256(weight_path, expected_sha, label=meta["manifest_key"])
    return weight_path


def verify_gguf_weight(
    model_dir: Path,
    manifest: dict[str, Any],
    *,
    manifest_key: str,
    verified_meta: dict[str, str],
) -> Path:
    entry = _entry(manifest, manifest_key)
    expected_name = entry.get("gguf_filename") or verified_meta["gguf_filename"]
    expected_sha = entry.get("sha256") or verified_meta["sha256"]
    gguf_path = model_dir / expected_name
    verify_file_sha256(gguf_path, expected_sha, label=manifest_key)
    return gguf_path


def example_manifest() -> dict[str, Any]:
    """Authoritative pinned metadata for config/prewarm-manifest.example.json."""
    return {
        "_comment": "Copy to models/.prewarm-manifest.json after staging weights.",
        "models": {
            VERIFIED_ANTARES_350M["manifest_key"]: {
                "hf_repo_id": VERIFIED_ANTARES_350M["hf_repo_id"],
                "weight_filename": VERIFIED_ANTARES_350M["weight_filename"],
                "sha256": VERIFIED_ANTARES_350M["sha256"],
                "license": VERIFIED_ANTARES_350M["license"],
                "hf_gated": VERIFIED_ANTARES_350M["hf_gated"],
            },
            VERIFIED_ANTARES_1B["manifest_key"]: {
                "hf_repo_id": VERIFIED_ANTARES_1B["hf_repo_id"],
                "weight_filename": VERIFIED_ANTARES_1B["weight_filename"],
                "sha256": VERIFIED_ANTARES_1B["sha256"],
                "license": VERIFIED_ANTARES_1B["license"],
                "hf_gated": VERIFIED_ANTARES_1B["hf_gated"],
            },
            VERIFIED_FOUNDATION_SEC_Q8_0["manifest_key"]: {
                "hf_repo_id": VERIFIED_FOUNDATION_SEC_Q8_0["hf_repo_id"],
                "gguf_filename": VERIFIED_FOUNDATION_SEC_Q8_0["gguf_filename"],
                "sha256": VERIFIED_FOUNDATION_SEC_Q8_0["sha256"],
                "license": VERIFIED_FOUNDATION_SEC_Q8_0["license"],
                "hf_gated": VERIFIED_FOUNDATION_SEC_Q8_0["hf_gated"],
            },
            VERIFIED_FOUNDATION_SEC_Q4_K_M["manifest_key"]: {
                "hf_repo_id": VERIFIED_FOUNDATION_SEC_Q4_K_M["hf_repo_id"],
                "gguf_filename": VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_filename"],
                "sha256": VERIFIED_FOUNDATION_SEC_Q4_K_M["sha256"],
                "license": VERIFIED_FOUNDATION_SEC_Q4_K_M["license"],
                "hf_gated": VERIFIED_FOUNDATION_SEC_Q4_K_M["hf_gated"],
            },
            VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["manifest_key"]: {
                "hf_repo_id": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["hf_repo_id"],
                "gguf_filename": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["gguf_filename"],
                "sha256": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["sha256"],
                "license": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["license"],
                "hf_gated": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["hf_gated"],
            },
        },
    }
