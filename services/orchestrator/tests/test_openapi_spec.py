"""Committed OpenAPI spec must match the FastAPI app (same discipline as coverage-report)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (ORCH, SHARED):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from shift_left.api.openapi_models import (  # noqa: E402
    REVIEW_REQUEST_EXAMPLE,
    REVIEW_RESPONSE_EXAMPLE,
    SYNTHETIC_OWNER,
    SYNTHETIC_REPO,
    SYNTHETIC_SHA,
    SYNTHETIC_TOKEN,
)
from shift_left.api.route_docs import (  # noqa: E402
    TAG_INTERNAL,
    build_openapi_document,
    missing_route_metadata,
)
from shift_left.main import app  # noqa: E402

YAML_PATH = ROOT / "docs" / "openapi.yaml"
JSON_PATH = ROOT / "docs" / "openapi.json"

FORBIDDEN_IN_EXAMPLES = (
    "sample-firewall",
    "demo-app",
    "validation/corpus",
    "/Users/",
    "slt_live",
    "ghp_",
)


def _load_committed() -> tuple[dict, dict]:
    yaml_text = YAML_PATH.read_text(encoding="utf-8")
    json_text = JSON_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(yaml_text), json.loads(json_text)


def test_committed_openapi_matches_app() -> None:
    app.openapi_schema = None
    generated = build_openapi_document(app)
    committed_yaml, committed_json = _load_committed()
    assert committed_yaml == generated, (
        "docs/openapi.yaml drifted from the FastAPI app. Run: make docs-openapi"
    )
    assert committed_json == generated, (
        "docs/openapi.json drifted from the FastAPI app. Run: make docs-openapi"
    )


def test_every_route_has_openapi_metadata() -> None:
    app.openapi_schema = None
    missing = missing_route_metadata(app)
    assert missing == [], "routes missing OpenAPI metadata:\n" + "\n".join(missing)


def test_review_examples_are_synthetic() -> None:
    assert REVIEW_REQUEST_EXAMPLE["owner"] == SYNTHETIC_OWNER
    assert REVIEW_REQUEST_EXAMPLE["repo"] == SYNTHETIC_REPO
    assert REVIEW_REQUEST_EXAMPLE["commit_sha"] == SYNTHETIC_SHA
    assert REVIEW_RESPONSE_EXAMPLE["repo"] == f"{SYNTHETIC_OWNER}/{SYNTHETIC_REPO}"
    blob = json.dumps({"request": REVIEW_REQUEST_EXAMPLE, "response": REVIEW_RESPONSE_EXAMPLE})
    for needle in FORBIDDEN_IN_EXAMPLES:
        assert needle not in blob, f"example leaked {needle!r}"
    assert SYNTHETIC_TOKEN not in blob or SYNTHETIC_TOKEN == "slt_EXAMPLE"


def test_spec_security_and_unauthenticated_paths() -> None:
    app.openapi_schema = None
    spec = build_openapi_document(app)
    scheme = spec["components"]["securitySchemes"]["shiftLeftToken"]
    assert scheme["scheme"] == "bearer"
    for cap in ("review", "approve", "triage", "admin"):
        assert cap in scheme["description"]
    servers = spec["servers"]
    assert servers[0]["url"] == "http://127.0.0.1:8080"
    health = spec["paths"]["/health"]["get"]
    self_check = spec["paths"]["/self-check"]["get"]
    assert health.get("security") == []
    assert self_check.get("security") == []
    webhook_paths = [path for path in spec["paths"] if "webhook" in path.lower()]
    assert webhook_paths == [], webhook_paths
    review = spec["paths"]["/api/v1/review"]["post"]
    assert review["security"] == [{"shiftLeftToken": []}]
    example = review["requestBody"]["content"]["application/json"]["examples"]["synthetic"]["value"]
    assert example["owner"] == SYNTHETIC_OWNER
    response_desc = review["responses"]["200"]["description"].lower()
    assert "advisory" in response_desc and "omitted" in response_desc


def test_internal_tag_covers_ui_routes() -> None:
    app.openapi_schema = None
    spec = build_openapi_document(app)
    ui_home = spec["paths"]["/ui/"]["get"]
    assert TAG_INTERNAL in ui_home["tags"]
    assert "not" in ui_home["description"].lower()
    sandbox = spec["paths"]["/api/v1/internal/antares/sandbox-command-audit"]["post"]
    assert TAG_INTERNAL in sandbox["tags"]
    assert "slat_" in sandbox["description"]


def test_generated_examples_have_no_fixture_residue() -> None:
    app.openapi_schema = None
    spec = build_openapi_document(app)
    dumped = json.dumps(spec)

    def _walk_examples(node, acc: list[str]) -> None:
        if isinstance(node, dict):
            if "examples" in node or "example" in node:
                acc.append(json.dumps(node.get("examples") or node.get("example")))
            for value in node.values():
                _walk_examples(value, acc)
        elif isinstance(node, list):
            for item in node:
                _walk_examples(item, acc)

    blobs: list[str] = []
    _walk_examples(spec, blobs)
    combined = "\n".join(blobs)
    for needle in FORBIDDEN_IN_EXAMPLES:
        assert needle not in combined
    assert "example-org" in combined
    assert re.search(r"slt_(?!EXAMPLE)", combined) is None
    assert "/Users/" not in dumped
