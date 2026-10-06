"""Bundled Forgejo/Gitea backend — sovereign default for customer repos."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from shift_left.git.protocol import GitBackendKind
from shift_left.http.local_client import LocalOnlyAsyncClient


class BundledForgejoBackend:
    """
    Self-hosted Forgejo (or Gitea-compatible) on the local host.

    Hosts the customer's repos, PRs, branch protection, and review workflow.
    Distinct from GitHub, which hosts this tool's open-source source only.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        provider: str = "forgejo",
        timeout: float = 60.0,
        allowed_endpoints: frozenset[tuple[str, int]] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._provider = provider
        self._headers = {"Authorization": f"token {token}"} if token else {}
        self._http = LocalOnlyAsyncClient(timeout=timeout, allowed_endpoints=allowed_endpoints)
        host = urlparse(self._base_url).hostname or "forgejo"
        self._api_host = host

    @property
    def kind(self) -> GitBackendKind:
        return GitBackendKind.BUNDLED_FORGEJO

    @property
    def provider_label(self) -> str:
        return self._provider

    @property
    def is_sovereign(self) -> bool:
        return True

    @property
    def api_host(self) -> str:
        return self._api_host

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/pulls/{pr_number}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.json()

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/pulls/{pr_number}.diff"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.text

    async def list_open_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List open pull requests (Forgejo API v1 — Gitea-compatible)."""
        url = (
            f"{self._base_url}/api/v1/repos/{owner}/{repo}/pulls"
            f"?state=open&limit={limit}&sort=recentupdate"
        )
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def list_pull_request_commits(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/pulls/{pr_number}/commits"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def list_pull_request_comments(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/issues/{pr_number}/comments"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def list_commit_statuses(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
    ) -> list[dict[str, Any]]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/statuses/{commit_sha}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/issues/{pr_number}/comments"
        response = await self._http.post(
            url,
            headers=self._headers,
            json={"body": body},
        )
        response.raise_for_status()
        return response.json()

    async def health(self) -> bool:
        url = f"{self._base_url}/api/v1/version"
        try:
            response = await self._http.get(url, headers=self._headers)
            return response.status_code == 200
        except Exception:
            return False

    async def verify_api_reachable(self) -> tuple[bool, str, dict[str, Any]]:
        """Confirm Forgejo HTTP API responds (version endpoint)."""
        url = f"{self._base_url}/api/v1/version"
        try:
            response = await self._http.get(url, headers=self._headers)
            if response.status_code != 200:
                return False, f"Forgejo API returned HTTP {response.status_code}", {}
            payload = response.json()
            return True, "Forgejo API responding.", {"version": payload.get("version")}
        except Exception as exc:  # noqa: BLE001
            return False, str(exc), {}

    async def verify_token(self) -> tuple[bool, str, dict[str, Any]]:
        """
        Validate configured token authenticates and holds scopes required for review.

        Required capabilities (Forgejo PAT scopes / repo permissions):
        - read user identity
        - read repository content (PR diffs)
        - write repository (commit statuses) or issue comments
        """
        if not self._headers.get("Authorization"):
            return False, "No API token configured.", {"missing_scopes": ["token"]}

        user_url = f"{self._base_url}/api/v1/user"
        try:
            response = await self._http.get(user_url, headers=self._headers)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc), {}

        if response.status_code == 401:
            return False, "FORGEJO_TOKEN rejected (HTTP 401).", {"missing_scopes": ["valid_token"]}
        if response.status_code == 403:
            body = response.text
            return False, f"Token forbidden: {body[:200]}", {"missing_scopes": ["read:user"]}
        response.raise_for_status()
        user = response.json()

        missing: list[str] = []
        repos_url = f"{self._base_url}/api/v1/user/repos?limit=1"
        repos_resp = await self._http.get(repos_url, headers=self._headers)
        if repos_resp.status_code in {401, 403}:
            missing.append("read:repository")

        details: dict[str, Any] = {
            "login": user.get("login"),
            "missing_scopes": missing,
        }
        if missing:
            return (
                False,
                f"Token authenticates as {user.get('login')!r} but lacks scope(s): {', '.join(missing)}.",
                details,
            )
        return True, f"Token valid for user {user.get('login')!r}.", details

    async def list_action_runners(self) -> tuple[bool, str, list[dict[str, Any]]]:
        """List registered Forgejo Actions runners (requires admin token).

        Forgejo 11.0.x may not expose runner list routes (HTTP 404 on all known paths).
        Registration-token and secrets APIs use mixed legacy/new URL prefixes.
        """
        urls = (
            f"{self._base_url}/api/v1/admin/actions/runners?visible=true",
            f"{self._base_url}/api/v1/admin/actions/runners",
            f"{self._base_url}/api/v1/admin/runners",
        )
        last_status = 0
        for url in urls:
            try:
                response = await self._http.get(url, headers=self._headers)
            except Exception as exc:  # noqa: BLE001
                return False, str(exc), []
            if response.status_code == 403:
                return (
                    False,
                    "Cannot list runners — token lacks admin scope. Use an admin PAT or verify runner locally.",
                    [],
                )
            if response.status_code == 200:
                payload = response.json()
                runners = payload if isinstance(payload, list) else payload.get("data") or []
                return True, f"{len(runners)} runner(s) registered.", list(runners)
            last_status = response.status_code
            if response.status_code not in {404, 405}:
                return False, f"Runner API returned HTTP {response.status_code}", []
        return False, f"Runner API returned HTTP {last_status}", []

    async def get_commit_author(self, owner: str, repo: str, commit_sha: str) -> str:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/git/commits/{commit_sha}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        data = response.json()
        author = data.get("author") or {}
        email = (author.get("email") or "").strip()
        name = (author.get("name") or "").strip()
        login = (author.get("login") or "").strip()
        if login:
            return login
        if email:
            return email
        if name:
            return name
        return "unknown"

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
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/statuses/{commit_sha}"
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

    async def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/branches/{branch}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.json()

    async def list_repo_commits(
        self,
        owner: str,
        repo: str,
        *,
        sha: str,
        path: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/commits?sha={sha}&limit={limit}"
        if path:
            from urllib.parse import quote

            url += f"&path={quote(path, safe='')}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        from base64 import b64decode
        from urllib.parse import quote

        url = (
            f"{self._base_url}/api/v1/repos/{owner}/{repo}/contents/"
            f"{quote(path, safe='')}?ref={quote(ref, safe='')}"
        )
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, list):
            raise FileNotFoundError(f"{path} is a directory, not a file")
        encoding = payload.get("encoding")
        content = payload.get("content") or ""
        if encoding == "base64":
            return b64decode(content).decode("utf-8", errors="replace")
        return str(content)

    async def compare_commits(
        self,
        owner: str,
        repo: str,
        base: str,
        head: str,
    ) -> dict[str, Any]:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/compare/{base}...{head}"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        return response.json()

    async def list_repo_tree_paths(
        self,
        owner: str,
        repo: str,
        ref: str,
    ) -> list[str]:
        """Return blob paths at ref via recursive git tree API."""
        branch = await self.get_branch(owner, repo, ref)
        commit_sha = (branch.get("commit") or {}).get("id") or ref
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"
        response = await self._http.get(url, headers=self._headers)
        response.raise_for_status()
        payload = response.json()
        tree = payload.get("tree") or []
        return sorted(
            item["path"]
            for item in tree
            if item.get("type") == "blob" and isinstance(item.get("path"), str)
        )

    async def branch_protection_requires_status_check(
        self,
        owner: str,
        repo: str,
        branch: str,
        context: str,
    ) -> bool | None:
        url = f"{self._base_url}/api/v1/repos/{owner}/{repo}/branch_protections/{branch}"
        try:
            response = await self._http.get(url, headers=self._headers)
            if response.status_code == 404:
                return False
            response.raise_for_status()
            data = response.json()
        except Exception:
            return None
        contexts = data.get("status_check_contexts") or []
        return context in contexts
