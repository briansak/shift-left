#!/usr/bin/env python3
"""Capture verbatim Antares prompts and raw completions (pre-parse)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES = ROOT / "services" / "antares-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES):
    sys.path.insert(0, str(path))

from antares_server.inference import AntaresEngine, _ANALYSIS_PROMPT  # noqa: E402

FIXTURES = [
    {
        "name": "sqli_python",
        "path": "app/db.py",
        "hunk": {
            "new_start": 2,
            "new_end": 3,
            "content": (
                " def lookup_user(username):\n"
                "-    query = \"SELECT * FROM users WHERE id = ?\"\n"
                "+    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                "     cursor.execute(query)\n"
            ),
        },
    },
    {
        "name": "path_traversal",
        "path": "app/files.py",
        "hunk": {
            "new_start": 5,
            "new_end": 6,
            "content": (
                " def read_user_file(user_id, filename):\n"
                "-    path = os.path.join(UPLOAD_DIR, user_id, filename)\n"
                "+    path = f\"/var/data/{user_id}/{filename}\"\n"
                "     return open(path).read()\n"
            ),
        },
    },
    {
        "name": "hardcoded_secret",
        "path": "config/settings.py",
        "hunk": {
            "new_start": 1,
            "new_end": 2,
            "content": (
                "-API_KEY = os.environ.get('API_KEY')\n"
                "+API_KEY = 'example-api-token-placeholder'\n"
            ),
        },
    },
]


def main() -> int:
    model_path = os.environ.get("ANTARES_MODEL_PATH", str(ROOT / "models" / "350m"))
    engine = AntaresEngine(model_path, load_strategy="on_demand")
    engine.load()

    captures: list[dict] = []
    for fixture in FIXTURES:
        hunk = fixture["hunk"]
        prompt = _ANALYSIS_PROMPT.format(
            file_path=fixture["path"],
            line_start=hunk["new_start"],
            line_end=hunk["new_end"],
            content=hunk["content"][:4000],
        )
        raw = engine._generate(prompt)
        parsed_count = len(engine._parse_findings(raw, fixture["path"]))
        captures.append(
            {
                "fixture": fixture["name"],
                "file_path": fixture["path"],
                "prompt_verbatim": prompt,
                "raw_completion_verbatim": raw,
                "raw_completion_chars": len(raw),
                "parsed_findings_count": parsed_count,
                "max_new_tokens": 1024,
                "stop_sequences": [],
                "structured_output_constraint": None,
                "do_sample": False,
            }
        )

    engine.unload()
    out = {
        "model_path": model_path,
        "variant": "350m",
        "device": engine._device,
        "load_strategy": engine._load_strategy,
        "inference_settings": {
            "max_new_tokens": 1024,
            "do_sample": False,
            "stop_sequences": "none configured",
            "grammar_json_mode": "none — raw generate() only",
        },
        "captures": captures,
    }
    out_path = ROOT / "validation" / "reports" / "antares-raw-captures.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
