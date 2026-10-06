"""GitHub backend — optional; customer code transits GitHub's infrastructure."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from shift_left.git.protocol import GitBackendKind
from shift_left.http.local_client import LocalOnlyAsyncClient


class GitHubBackend:
    """
    GitHub.com or GitHub Enterprise API.

    Sovereignty tradeoff: PR diffs and review comments are fetched/posted via
    GitHub's API — customer source leaves the local host for review I/O.
    Model inference can still run locally if models are on-host.
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
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._http = LocalOnlyAsyncClient(timeout=timeout, allowed_endpoints=allowed_endpoints)
        self._api_host = urlparse(self._api_url).hostname or "api.github.com"

    @property
    def kind(self) -> GitBackendKind:
        return GitBackendKind.GITHUB

    @property
    def provider_label(self) -> str:
        return "github"

    @property
    def is_sovereign(self) -> bool:
        return False

    @property
    def api_host(self) -> str:
        return self._api_host

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        url = f"{self._api_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.json()

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        url = f"{self._api_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        headers = {**self._headers, "Accept": "application/vnd.github.v3.diff"}
        response = await self._http.get(url, headers=headers)
        response.raise_for_status()
        return response.text

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        # PRs are issues on GitHub — issue number equals PR number.
        url = f"{self._api_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        response = await self._http.post(
            url,
            headers=self._headers,
            json={"body": body},
        )
        response.raise_for_status()
        return response.json()

    async def health(self) -> bool:
        url = f"{self._api_url}/zen"
        try:
            response = await self._http.get(url, headers=self._headers)
            return response.status_code == 200
        except Exception:
            return False

    async def get_commit_author(self, owner: str, repo: str, commit_sha: str) -> str:
        url = f"{self._api_url}/repos/{owner}/{repo}/commits/{commit_sha}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        data = response.json()
        author = data.get("commit", {}).get("author") or {}
        email = (author.get("email") or "").strip()
        name = (author.get("name") or "").strip()
        login = (data.get("author") or {}).get("login") or ""
        if login:
            return str(login)
        if email:
            return email
        return name or "unknown"

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
        url = f"{self._api_url}/repos/{owner}/{repo}/statuses/{commit_sha}"
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
        url = f"{self._api_url}/repos/{owner}/{repo}/branches/{branch}/protection"
        try:
            response = await self._http.get(url, headers=self._headers)
            if response.status_code == 404:
                return False
            response.raise_for_status()
            data = response.json()
        except Exception:
            return None
        contexts = (data.get("required_status_checks") or {}).get("contexts") or []
        return context in contexts
