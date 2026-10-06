#!/usr/bin/env python3
"""Assemble a terraform module for validating a single FMC corpus fixture."""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSIONS_TF = '''terraform {
  required_version = ">= 1.5.0"
  required_providers {
    fmc = {
      source  = "CiscoDevNet/fmc"
      version = "2.0.1"
    }
  }
}
'''

PROVIDER_TF = '''provider "fmc" {
  url      = "https://fmc.example.invalid"
  username = "validate"
  password = "validate"
}
'''

STUB_POLICY_ID = '"76d24097-41c4-4558-a4d0-a8c07ac08470"'

REF_PATTERN = re.compile(
    r"\b(fmc_(?:network|network_group|host|range|port))\.([A-Za-z0-9_-]+)\."
)

RESOURCE_BLOCK = re.compile(
    r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)

ACCESS_POLICY_RESOURCE = re.compile(
    r'^resource\s+"fmc_access_policy"\s+"[^"]+"\s*\{[^}]*\}\s*\n?',
    re.MULTILINE,
)

ACCESS_POLICY_REF = re.compile(r"fmc_access_policy\.[A-Za-z0-9_-]+\.id")


def _extract_fmc_blocks(content: str) -> str:
    """Keep only FMC provider resources; drop other providers from mixed fixtures."""
    lines = content.splitlines(keepends=True)
    kept: list[str] = []
    depth = 0
    in_fmc = False
    for line in lines:
        if depth == 0:
            match = RESOURCE_BLOCK.match(line)
            if match:
                resource_type = match.group(1)
                in_fmc = resource_type.startswith("fmc_")
                if not in_fmc:
                    continue
                depth = line.count("{") - line.count("}")
                kept.append(line)
                continue
            if line.strip() and not line.strip().startswith("#"):
                continue
            kept.append(line)
            continue
        kept.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            depth = 0
            in_fmc = False
    return "".join(kept)


def _normalize_for_provider(content: str) -> str:
    content = ACCESS_POLICY_RESOURCE.sub("", content)
    content = ACCESS_POLICY_REF.sub(STUB_POLICY_ID, content)
    return content


def defined_resources(content: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for match in re.finditer(r'resource\s+"(fmc_[^"]+)"\s+"([^"]+)"', content):
        found.add((match.group(1), match.group(2)))
    return found


def referenced_resources(content: str) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for match in REF_PATTERN.finditer(content):
        refs.add((match.group(1), match.group(2)))
    return refs


def stub_for(resource_type: str, name: str) -> str:
    if resource_type == "fmc_network":
        return (
            f'resource "fmc_network" "{name}" {{\n'
            f'  name   = "stub-{name}"\n'
            f'  prefix = "10.255.0.0/24"\n'
            f"}}\n"
        )
    if resource_type == "fmc_network_group":
        return f'resource "fmc_network_group" "{name}" {{\n  name = "stub-{name}"\n}}\n'
    if resource_type == "fmc_host":
        return (
            f'resource "fmc_host" "{name}" {{\n'
            f'  name = "stub-{name}"\n'
            f'  ip   = "10.255.0.1"\n'
            f"}}\n"
        )
    if resource_type == "fmc_range":
        return (
            f'resource "fmc_range" "{name}" {{\n'
            f'  name     = "stub-{name}"\n'
            f'  ip_range = "10.255.0.1-10.255.0.9"\n'
            f"}}\n"
        )
    if resource_type == "fmc_port":
        return (
            f'resource "fmc_port" "{name}" {{\n'
            f'  name     = "stub-{name}"\n'
            f'  protocol = "TCP"\n'
            f'  port     = "443"\n'
            f"}}\n"
        )
    return ""


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: prepare_validate_module.py <fixture.tf> <out_dir>", file=sys.stderr)
        return 2
    fixture = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    content = _normalize_for_provider(_extract_fmc_blocks(fixture.read_text(encoding="utf-8")))
    stubs: list[str] = []
    defined = defined_resources(content)
    for resource_type, name in sorted(referenced_resources(content)):
        if (resource_type, name) not in defined:
            stub = stub_for(resource_type, name)
            if stub:
                stubs.append(stub)
    (out_dir / "versions.tf").write_text(VERSIONS_TF, encoding="utf-8")
    (out_dir / "provider.tf").write_text(PROVIDER_TF, encoding="utf-8")
    stub_text = "\n".join(stubs)
    if stub_text:
        stub_text += "\n"
    (out_dir / "fixture.tf").write_text(stub_text + content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
