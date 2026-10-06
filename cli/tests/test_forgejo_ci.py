"""Tests for Forgejo Actions CI auth automation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from shift_left_cli.forgejo_ci import (
    CI_TOKEN_BOOTSTRAP_KEY,
    configured_ci_repo_slugs,
    get_or_mint_ci_review_token,
    parse_repo_slug,
)


def test_parse_repo_slug() -> None:
    assert parse_repo_slug("shiftleft-admin/sample-firewall") == ("shiftleft-admin", "sample-firewall")


def test_parse_repo_slug_rejects_invalid() -> None:
    with pytest.raises(Exception, match="Invalid repo slug"):
        parse_repo_slug("not-a-slug")


def test_configured_ci_repo_slugs_reads_gate_check_repo(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "shift-left.yaml").write_text(
        yaml.safe_dump({"gate": {"check_repo": "shiftleft-admin/sample-firewall"}})
    )
    assert configured_ci_repo_slugs(tmp_path) == ["shiftleft-admin/sample-firewall"]


def test_get_or_mint_ci_review_token_reuses_bootstrap_secret(tmp_path: Path) -> None:
    from shift_left_cli.forgejo_bootstrap import _persist_bootstrap_secrets

    (tmp_path / ".shift-left").mkdir()
    _persist_bootstrap_secrets(tmp_path, {CI_TOKEN_BOOTSTRAP_KEY: "slt_cached"})
    assert get_or_mint_ci_review_token(tmp_path) == "slt_cached"
