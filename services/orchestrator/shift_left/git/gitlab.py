"""GitLab backend — optional; customer code transits GitLab's infrastructure."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlparse

from shift_left.git.protocol import GitBackendKind
from shift_left.http.local_client import LocalOnlyAsyncClient


class GitLabBackend:
    """
    GitLab.com or self-managed GitLab API v4.

    Sovereignty tradeoff: merge request diffs and notes traverse GitLab's API.
    Self-managed GitLab on the local network reduces but may not eliminate egress
    depending on deployment — document per organization.
    """

    def __init__(
        self,
        api_url: str,
        token: str,
        *,
        timeout: float = 60.0,
        allowed_endpoints: frozenset[tuple[str, int]] | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._headers = {"PRIVATE-TOKEN": token} if token else {}
        self._http = LocalOnlyAsyncClient(timeout=timeout, allowed_endpoints=allowed_endpoints)
        self._api_host = urlparse(self._api_url).hostname or "gitlab.com"

    @property
    def kind(self) -> GitBackendKind:
        return GitBackendKind.GITLAB

    @property
    def provider_label(self) -> str:
        return "gitlab"

    @property
    def is_sovereign(self) -> bool:
        return False

    @property
    def api_host(self) -> str:
        return self._api_host

    def _project_path(self, owner: str, repo: str) -> str:
        return quote(f"{owner}/{repo}", safe="")

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/merge_requests/{pr_number}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.json()

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/merge_requests/{pr_number}/changes"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        data = response.json()
        # Synthesize unified diff text from GitLab changes payload for the orchestrator.
        chunks: list[str] = []
        for change in data.get("changes", []):
            path = change.get("new_path") or change.get("old_path") or "unknown"
            diff_body = change.get("diff") or ""
            chunks.append(f"diff --git a/{path} b/{path}\n{diff_body}")
        return "\n".join(chunks)

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/merge_requests/{pr_number}/notes"
        response = await self._http.post(
            url,
            headers=self._headers,
            json={"body": body},
        )
        response.raise_for_status()
        return response.json()

    async def health(self) -> bool:
        url = f"{self._api_url}/version"
        try:
            response = await self._http.get(url, headers=self._headers)
            return response.status_code == 200
        except Exception:
            return False

    async def get_commit_author(self, owner: str, repo: str, commit_sha: str) -> str:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/repository/commits/{commit_sha}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        data = response.json()
        author_email = (data.get("author_email") or "").strip()
        author_name = (data.get("author_name") or "").strip()
        return author_email or author_name or "unknown"

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
    ) -> dict[str, Any]:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/statuses/{commit_sha}"
        payload: dict[str, Any] = {
            "context": context,
            "state": state,
            "description": description[:255],
        }
        if target_url:
            payload["target_url"] = target_url
        response = await self._http.post(url, headers=self._headers, json=payload)
        response.raise_for_status()
        return response.json()

    async def branch_protection_requires_status_check(
        self,
        owner: str,
        repo: str,
        branch: str,
        context: str,
    ) -> bool | None:
        project = self._project_path(owner, repo)
        url = f"{self._api_url}/projects/{project}/protected_branches/{quote(branch, safe='')}"
        try:
            response = await self._http.get(url, headers=self._headers)
            if response.status_code == 404:
                return False
            response.raise_for_status()
            data = response.json()
        except Exception:
            return None
        return context in (data.get("required_status_checks") or [])
