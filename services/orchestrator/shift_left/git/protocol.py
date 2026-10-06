"""Git backend protocol — customer repos vs tool source (GitHub)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable


class GitBackendKind(str, Enum):
    """Where customer repos, PRs, and review comments live."""

    BUNDLED_FORGEJO = "bundled-forgejo"
    GITHUB = "github"
    GITLAB = "gitlab"


@runtime_checkable
class GitBackend(Protocol):
    """
    Abstraction over git hosting for the review pipeline.

    Sovereign default: bundled Forgejo on the local host (customer code never leaves).
    Optional: GitHub/GitLab — customer diffs and findings comments traverse that provider.
    """

    @property
    def kind(self) -> GitBackendKind: ...

    @property
    def provider_label(self) -> str: ...

    @property
    def is_sovereign(self) -> bool:
        """True when customer repos and review I/O stay on the installed host."""
        ...

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]: ...

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str: ...

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]: ...

    async def get_commit_author(self, owner: str, repo: str, commit_sha: str) -> str: ...

    async def publish_commit_status(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        *,
        context: str,
        state: str,
        description: str,
        target_url: str | None = None,
    ) -> dict[str, Any]: ...

    async def branch_protection_requires_status_check(
        self,
        owner: str,
        repo: str,
        branch: str,
        context: str,
    ) -> bool | None: ...

    async def health(self) -> bool: ...
