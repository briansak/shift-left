"""Read-heavy Forgejo embedding — TTL cache for browse data, never for head SHA decisions."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from shift_left.config import AppConfig
from shift_left.git.protocol import GitBackend
from shift_left.routing.config_scope import classify_paths, paths_from_unified_diff


@dataclass
class _CacheEntry:
    value: Any
    expires_at: float


class ForgejoReadCache:
    """In-memory TTL cache for Forgejo browse metadata (not head SHA for decisions)."""

    def __init__(self, ttl_seconds: float = 30.0) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, _CacheEntry] = {}

    def _get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if time.monotonic() >= entry.expires_at:
            del self._entries[key]
            return None
        return entry.value

    def _set(self, key: str, value: Any) -> None:
        self._entries[key] = _CacheEntry(value=value, expires_at=time.monotonic() + self._ttl)

    def last_fetched_at(self) -> datetime:
        return datetime.now(timezone.utc)


class ForgejoEmbedService:
    """
    Cached Forgejo reads for UI embedding.

    FORGEJO_TOKEN is used server-side only and must never appear in responses or logs.
    """

    def __init__(self, *, config: AppConfig, git: GitBackend, cache_ttl_seconds: float = 30.0) -> None:
        self._config = config
        self._git = git
        self._cache = ForgejoReadCache(ttl_seconds=cache_ttl_seconds)

    @property
    def forgejo_base_url(self) -> str:
        bundled = self._config.git.bundled
        return (bundled.url if bundled else "http://localhost:3000").rstrip("/")

    def pr_url(self, owner: str, repo: str, pr_number: int) -> str:
        return f"{self.forgejo_base_url}/{owner}/{repo}/pulls/{pr_number}"

    def repo_url(self, owner: str, repo: str) -> str:
        return f"{self.forgejo_base_url}/{owner}/{repo}"

    async def get_pull_request_cached(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> dict[str, Any]:
        key = f"pr:{owner}/{repo}/{pr_number}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        payload = await self._git.get_pull_request(owner, repo, pr_number)
        self._cache._set(key, payload)
        return payload

    async def get_pull_diff_cached(self, owner: str, repo: str, pr_number: int) -> str:
        key = f"diff:{owner}/{repo}/{pr_number}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        payload = await self._git.get_pull_diff(owner, repo, pr_number)
        self._cache._set(key, payload)
        return payload

    async def list_open_pull_requests_cached(self, owner: str, repo: str) -> list[dict[str, Any]]:
        key = f"open_prs:{owner}/{repo}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        list_open = getattr(self._git, "list_open_pull_requests", None)
        if list_open is None:
            return []
        payload = await list_open(owner, repo)
        self._cache._set(key, payload)
        return payload

    async def list_pr_comments_cached(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        key = f"comments:{owner}/{repo}/{pr_number}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        list_comments = getattr(self._git, "list_pull_request_comments", None)
        if list_comments is None:
            return []
        payload = await list_comments(owner, repo, pr_number)
        self._cache._set(key, payload)
        return payload

    async def list_pr_commits_cached(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        key = f"commits:{owner}/{repo}/{pr_number}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        list_commits = getattr(self._git, "list_pull_request_commits", None)
        if list_commits is None:
            return []
        payload = await list_commits(owner, repo, pr_number)
        self._cache._set(key, payload)
        return payload

    async def list_commit_statuses_cached(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
    ) -> list[dict[str, Any]]:
        key = f"statuses:{owner}/{repo}/{commit_sha}"
        cached = self._cache._get(key)
        if cached is not None:
            return cached
        list_statuses = getattr(self._git, "list_commit_statuses", None)
        if list_statuses is None:
            return []
        payload = await list_statuses(owner, repo, commit_sha)
        self._cache._set(key, payload)
        return payload

    async def classify_pr_scope(self, owner: str, repo: str, pr_number: int) -> str:
        try:
            diff = await self.get_pull_diff_cached(owner, repo, pr_number)
        except Exception:
            return "config"
        return classify_paths(paths_from_unified_diff(diff), self._config.routing)

    async def runner_notice(self) -> str | None:
        list_runners = getattr(self._git, "list_action_runners", None)
        if list_runners is None:
            return None
        ok, message, runners = await list_runners()
        if not ok:
            from shift_left.system.runner_local import runner_registration_present

            if "404" in message and runner_registration_present():
                # Forgejo 11.0.x often lacks list-runners API; local registration is authoritative.
                return None
            return (
                f"Forgejo Actions runner status unavailable ({message}). "
                "PRs may sit unreviewed if the runner is offline or labels do not match."
            )
        if not runners:
            return (
                "No Forgejo Actions runners registered. "
                "Validation workflows will not run until a runner is online with label self-hosted:host."
            )
        online = [
            item
            for item in runners
            if str(item.get("status", "")).lower() in {"online", "idle", "active"}
        ]
        if not online:
            labels = sorted(
                {
                    label
                    for item in runners
                    for label in (item.get("labels") or [])
                }
            )
            return (
                "Forgejo Actions runners are registered but none are online. "
                f"Registered labels: {', '.join(labels) or 'unknown'}."
            )
        return None

    def browse_fetched_at(self) -> datetime:
        return self._cache.last_fetched_at()
