#!/usr/bin/env python3
"""Emit MODIFICATIONS notice for locally quantized GGUF artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "shift-left-shared"))

from shift_left_shared.weights import sha256_file  # noqa: E402


def emit_modifications_notice(
    *,
    output_path: Path,
    source_artifact: Path,
    output_artifact: Path,
    tool_name: str,
    tool_version: str,
    change_summary: str,
) -> Path:
    if not source_artifact.is_file():
        raise FileNotFoundError(f"source artifact not found: {source_artifact}")
    if not output_artifact.is_file():
        raise FileNotFoundError(f"output artifact not found: {output_artifact}")

    notice = {
        "modification": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": change_summary,
        "tool": {"name": tool_name, "version": tool_version},
        "source_artifact": {
            "path": str(source_artifact),
            "sha256": sha256_file(source_artifact),
        },
        "output_artifact": {
            "path": str(output_artifact),
            "sha256": sha256_file(output_artifact),
        },
        "obligation": (
            "Apache 2.0 Section 4 requires a prominent notice that these files were "
            "modified. Retain this notice alongside redistributed weights."
        ),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(notice, indent=2) + "\n")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Record local quantization modifications")
    parser.add_argument("--source", type=Path, required=True, help="Upstream source artifact")
    parser.add_argument("--output", type=Path, required=True, help="Locally produced artifact")
    parser.add_argument(
        "--notice-path",
        type=Path,
        default=None,
        help="Where to write MODIFICATIONS.json (default: beside output artifact)",
    )
    parser.add_argument("--tool", default="llama.cpp", help="Quantization tool name")
    parser.add_argument("--tool-version", required=True, help="Quantization tool version")
    parser.add_argument(
        "--summary",
        default="Locally quantized GGUF from upstream Foundation-Sec weights",
        help="Human-readable change summary",
    )
    args = parser.parse_args()
    notice_path = args.notice_path or args.output.with_suffix(args.output.suffix + ".MODIFICATIONS.json")
    emit_modifications_notice(
        output_path=notice_path,
        source_artifact=args.source,
        output_artifact=args.output,
        tool_name=args.tool,
        tool_version=args.tool_version,
        change_summary=args.summary,
    )
    print(f"Wrote modification notice: {notice_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
