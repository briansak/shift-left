"""Tests for offline bundle licensing compliance enforcement."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SHARED = ROOT / "services" / "shift-left-shared"
sys.path.insert(0, str(SHARED))

from shift_left_shared.compliance import check_offline_bundle  # noqa: E402
from shift_left_shared.weights import sha256_file  # noqa: E402


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    licenses = tmp_path / "licenses"
    licenses.mkdir()
    (licenses / "APACHE-2.0.txt").write_text("Apache License 2.0 placeholder")
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text("# Third party notices\n")
    models = tmp_path / "models" / "350m"
    models.mkdir(parents=True)
    (models / "LICENSE").write_text("Apache-2.0")
    (models / "README.md").write_text("model card")
    weight = models / "model.safetensors"
    weight.write_bytes(b"test-weight")
    manifest = {
        "models": {
            "antares-350m": {
                "sha256": sha256_file(weight),
            }
        }
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return tmp_path


def test_bundle_compliance_ok(bundle_dir: Path) -> None:
    assert check_offline_bundle(bundle_dir) == []


def test_bundle_compliance_fails_without_license(bundle_dir: Path) -> None:
    (bundle_dir / "licenses" / "APACHE-2.0.txt").unlink()
    errors = check_offline_bundle(bundle_dir)
    assert any("APACHE-2.0" in err for err in errors)


def test_bundle_compliance_fails_without_model_license(bundle_dir: Path) -> None:
    (bundle_dir / "models" / "350m" / "LICENSE").unlink()
    errors = check_offline_bundle(bundle_dir)
    assert any("missing upstream LICENSE" in err for err in errors)


def test_quant_modification_notice_records_hashes(tmp_path: Path) -> None:
    source = tmp_path / "source.gguf"
    output = tmp_path / "output-q4.gguf"
    source.write_bytes(b"upstream")
    output.write_bytes(b"quantized")
    notice = tmp_path / "output-q4.gguf.MODIFICATIONS.json"

    script = ROOT / "scripts" / "emit-quant-modification-notice.py"
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--source",
            str(source),
            "--output",
            str(output),
            "--notice-path",
            str(notice),
            "--tool-version",
            "b1234",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(notice.read_text())
    assert payload["modification"] is True
    assert payload["source_artifact"]["sha256"] == sha256_file(source)
    assert payload["output_artifact"]["sha256"] == sha256_file(output)
