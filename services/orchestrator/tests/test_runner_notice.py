"""Runner notice behavior when Forgejo list API is unavailable."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from shift_left.config import AppConfig
from shift_left.git.forgejo_read import ForgejoEmbedService


@pytest.mark.asyncio
async def test_runner_notice_suppressed_when_api_404_and_registration_present(tmp_path: Path) -> None:
    (tmp_path / "data" / "forgejo-runner").mkdir(parents=True)
    (tmp_path / "data" / "forgejo-runner" / ".runner").write_text("{}\n")

    config = AppConfig.model_validate({"git": {"backend": "bundled-forgejo"}})
    git = AsyncMock()
    git.list_action_runners = AsyncMock(
        return_value=(False, "Runner API returned HTTP 404", []),
    )
    service = ForgejoEmbedService(config=config, git=git)

    with patch("shift_left.system.runner_local.resolve_repo_root", return_value=tmp_path):
        notice = await service.runner_notice()

    assert notice is None


@pytest.mark.asyncio
async def test_runner_notice_warns_when_api_404_and_not_registered(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"git": {"backend": "bundled-forgejo"}})
    git = AsyncMock()
    git.list_action_runners = AsyncMock(
        return_value=(False, "Runner API returned HTTP 404", []),
    )
    service = ForgejoEmbedService(config=config, git=git)

    with patch("shift_left.system.runner_local.resolve_repo_root", return_value=tmp_path):
        notice = await service.runner_notice()

    assert notice is not None
    assert "404" in notice or "unavailable" in notice.lower()
