#!/usr/bin/env python3
"""Rewrite legacy FMC fixture HCL to CiscoDevNet/fmc v2.0.1 assignment syntax."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCAN_ROOTS = [
    ROOT / "validation" / "corpus",
    ROOT / "services" / "orchestrator" / "tests" / "fixtures" / "ftd",
    ROOT / "examples" / "ftdv-firewall" / "terraform",
    ROOT / "examples" / "config" / "firewall",
    ROOT / "validation" / "holdout-terraform",
]

NETWORK_LITERAL_BLOCK = re.compile(
    r"^([ \t]*)(source|destination)_network_literals\s*\{\s*\n"
    r"[ \t]*literal\s*\{\s*value\s*=\s*([^}\n]+)\s*\}\s*\n"
    r"[ \t]*\}\s*$",
    re.MULTILINE,
)

NETWORK_LITERAL_INLINE = re.compile(
    r"([ \t]*)(source|destination)_network_literals\s*\{\s*literal\s*\{\s*value\s*=\s*([^}]+)\s*\}\s*\}"
)

PORT_LITERAL_BLOCK = re.compile(
    r"^([ \t]*)(source|destination)_port_literals\s*\{\s*\n"
    r"[ \t]*literal\s*\{([^}]+)\}\s*\n"
    r"[ \t]*\}\s*$",
    re.MULTILINE,
)

PORT_LITERAL_INLINE = re.compile(
    r"([ \t]*)(source|destination)_port_literals\s*\{\s*literal\s*\{([^}]+)\}\s*\}"
)

NETWORK_OBJECT_BLOCK = re.compile(
    r"^([ \t]*)(source|destination)_network_objects\s*\{\s*\n"
    r"[ \t]*objects\s*\{\s*id\s*=\s*([^}\n]+)\s*type\s*=\s*([^}\n]+)\s*\}\s*\n"
    r"[ \t]*\}\s*$",
    re.MULTILINE,
)

NETWORK_OBJECT_INLINE = re.compile(
    r"([ \t]*)(source|destination)_network_objects\s*\{\s*objects\s*\{\s*id\s*=\s*([^}\s]+)\s*type\s*=\s*([^}]+)\s*\}\s*\}"
)

BULK_PORT_LITERAL = re.compile(
    r"(destination_port_literals\s*=\s*\[\{[^}]*protocol\s*=\s*[^,}]+,\s*port\s*=\s*[^,}]+)(\})"
)

ACCESS_POLICY_RESOURCE = re.compile(
    r'^resource\s+"fmc_access_policy"\s+"[^"]+"\s*\{[^}]*\}\s*\n?',
    re.MULTILINE,
)

ACCESS_POLICY_REF = re.compile(
    r"fmc_access_policy\.([A-Za-z0-9_-]+)\.id"
)

NETWORK_GROUP_OBJECTS_BLOCK = re.compile(
    r"^([ \t]*)objects\s*\{\s*\n"
    r"([ \t]*id\s*=\s*[^\n]+\n)"
    r"([ \t]*type\s*=\s*[^\n]+\n)"
    r"[ \t]*\}\s*$",
    re.MULTILINE,
)

STUB_POLICY_ID = '"76d24097-41c4-4558-a4d0-a8c07ac08470"'


def _normalize_port_literal_body(body: str) -> str:
    body = body.strip()
    if "type" not in body:
        if "protocol" in body and "port" in body:
            body = re.sub(
                r'protocol\s*=\s*(".*?"|[^\s,}]+)\s+port\s*=',
                r"protocol = \1, port =",
                body,
            )
            body = f'type = "PortLiteral", {body}'
        elif re.search(r"\bvalue\s*=", body):
            body = re.sub(
                r"value\s*=\s*([^,\s}]+)",
                r'type = "PortLiteral", protocol = "6", port = \1',
                body,
            )
    return body


def migrate_content(content: str) -> str:
    def _net_block(match: re.Match[str]) -> str:
        indent, side, value = match.group(1), match.group(2), match.group(3).strip()
        return f"{indent}{side}_network_literals = [{{ value = {value} }}]"

    def _net_inline(match: re.Match[str]) -> str:
        indent, side, value = match.group(1), match.group(2), match.group(3).strip()
        return f"{indent}{side}_network_literals = [{{ value = {value} }}]"

    def _port_block(match: re.Match[str]) -> str:
        indent, side, body = match.group(1), match.group(2), match.group(3)
        body = _normalize_port_literal_body(body)
        return f'{indent}{side}_port_literals = [{{ {body} }}]'

    def _port_inline(match: re.Match[str]) -> str:
        indent, side, body = match.group(1), match.group(2), match.group(3)
        body = _normalize_port_literal_body(body)
        return f'{indent}{side}_port_literals = [{{ {body} }}]'

    def _obj_block(match: re.Match[str]) -> str:
        indent, side, ref, obj_type = match.groups()
        return (
            f"{indent}{side}_network_objects = [{{ id = {ref.strip()}, "
            f"type = {obj_type.strip()} }}]"
        )

    def _obj_inline(match: re.Match[str]) -> str:
        indent, side, ref, obj_type = match.groups()
        return (
            f"{indent}{side}_network_objects = [{{ id = {ref.strip()}, "
            f"type = {obj_type.strip()} }}]"
        )

    updated = NETWORK_LITERAL_BLOCK.sub(_net_block, content)
    updated = NETWORK_LITERAL_INLINE.sub(_net_inline, updated)
    updated = PORT_LITERAL_BLOCK.sub(_port_block, updated)
    updated = PORT_LITERAL_INLINE.sub(_port_inline, updated)
    updated = NETWORK_OBJECT_BLOCK.sub(_obj_block, updated)
    updated = NETWORK_OBJECT_INLINE.sub(_obj_inline, updated)

    def _bulk_port(match: re.Match[str]) -> str:
        inner, close = match.group(1), match.group(2)
        if "type" in inner:
            return match.group(0)
        return f"{inner}, type = \"PortLiteral\"{close}"

    updated = BULK_PORT_LITERAL.sub(_bulk_port, updated)
    updated = NETWORK_GROUP_OBJECTS_BLOCK.sub(_group_objects_block, updated)
    updated = ACCESS_POLICY_REF.sub(STUB_POLICY_ID, updated)
    updated = ACCESS_POLICY_RESOURCE.sub("", updated)
    return updated


def _group_objects_block(match: re.Match[str]) -> str:
    indent, id_line, type_line = match.group(1), match.group(2), match.group(3)
    id_val = id_line.split("=", 1)[1].strip()
    type_val = type_line.split("=", 1)[1].strip()
    return f"{indent}objects = [{{ id = {id_val}, type = {type_val} }}]"


def main() -> int:
    changed: list[Path] = []
    for base in SCAN_ROOTS:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.tf")):
            if "fmc_" not in path.read_text(encoding="utf-8") and "fmc_access" not in path.name:
                continue
            original = path.read_text(encoding="utf-8")
            updated = migrate_content(original)
            if updated != original:
                path.write_text(updated, encoding="utf-8")
                changed.append(path)
    corpus_py = ROOT / "validation" / "generate_config_corpus.py"
    if corpus_py.is_file():
        original = corpus_py.read_text(encoding="utf-8")
        updated = migrate_content(original)
        if updated != original:
            corpus_py.write_text(updated, encoding="utf-8")
            changed.append(corpus_py)
    for path in changed:
        print(path.relative_to(ROOT))
    print(f"migrated {len(changed)} files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
