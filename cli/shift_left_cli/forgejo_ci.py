"""Forgejo Actions CI auth — mint review tokens and sync SHIFT_LEFT_TOKEN secrets."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from shift_left_cli.forgejo_secrets import ForgejoSecretError, set_repo_secret

CI_SECRET_NAME = "SHIFT_LEFT_TOKEN"
CI_TOKEN_BOOTSTRAP_KEY = "shift_left_ci_token"
CI_TOKEN_LABEL = "forgejo-actions-ci"
CI_TOKEN_ACTOR = "ci"
WORKFLOW_REL = ".forgejo/workflows/shift-left-review.yml"


class ForgejoCiError(RuntimeError):
    pass


def forgejo_base_url() -> str:
    return os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")


def parse_repo_slug(slug: str) -> tuple[str, str]:
    if "/" not in slug or slug.count("/") != 1:
        raise ForgejoCiError(f"Invalid repo slug {slug!r} — expected owner/name")
    owner, name = slug.split("/", 1)
    if not owner or not name:
        raise ForgejoCiError(f"Invalid repo slug {slug!r} — expected owner/name")
    return owner, name


def configured_ci_repo_slugs(root: Path) -> list[str]:
    config_path = root / "config" / "shift-left.yaml"
    if not config_path.is_file():
        return []
    raw = yaml.safe_load(config_path.read_text()) or {}
    slugs: list[str] = []
    check_repo = (raw.get("gate") or {}).get("check_repo")
    if check_repo:
        slugs.append(str(check_repo).strip())
    return slugs


def get_or_mint_ci_review_token(root: Path) -> str:
    from shift_left.auth.context import TokenCapability
    from shift_left.auth.tokens import TokenStore, mint_api_token
    from shift_left.config import load_config, resolve_auth_sqlite_path

    from shift_left_cli.forgejo_bootstrap import _persist_bootstrap_secrets, _read_bootstrap_secret

    existing = _read_bootstrap_secret(root, CI_TOKEN_BOOTSTRAP_KEY)
    if existing:
        return existing

    config_path = root / "config" / "shift-left.yaml"
    if not config_path.is_file():
        raise ForgejoCiError("config/shift-left.yaml missing — run ./shift-left up configure first")
    config = load_config(config_path)
    store = TokenStore(resolve_auth_sqlite_path(config))
    _, plaintext = mint_api_token(
        store,
        label=CI_TOKEN_LABEL,
        actor=CI_TOKEN_ACTOR,
        capabilities=[TokenCapability.REVIEW],
    )
    _persist_bootstrap_secrets(root, {CI_TOKEN_BOOTSTRAP_KEY: plaintext})
    print(
        "Minted Forgejo Actions CI token (review capability; "
        "stored in .shift-left/bootstrap-secrets.json)."
    )
    return plaintext


def ensure_repo_actions_secret(
    root: Path,
    base: str,
    forgejo_token: str,
    owner: str,
    repo: str,
) -> None:
    ci_token = get_or_mint_ci_review_token(root)
    try:
        set_repo_secret(base, forgejo_token, owner, repo, CI_SECRET_NAME, ci_token)
    except ForgejoSecretError as exc:
        raise ForgejoCiError(
            f"{exc}. Set Forgejo repo secret {CI_SECRET_NAME} manually with a review-capable slt_ token."
        ) from exc
    print(f"Forgejo Actions secret {CI_SECRET_NAME!r} configured on {owner}/{repo}.")


def push_review_workflow(
    root: Path,
    base: str,
    forgejo_token: str,
    owner: str,
    repo: str,
    *,
    branch: str = "main",
) -> None:
    workflow_src = root / "templates" / "forgejo" / "workflows" / "shift-left-review.yml"
    if not workflow_src.is_file():
        raise ForgejoCiError(f"Missing workflow template {workflow_src}")
    _upsert_file(
        base,
        forgejo_token,
        owner,
        repo,
        WORKFLOW_REL,
        workflow_src.read_text(),
        branch=branch,
    )


def sync_repo_ci_auth(
    root: Path,
    base: str,
    forgejo_token: str,
    owner: str,
    repo: str,
) -> None:
    """Idempotent: ensure review workflow and SHIFT_LEFT_TOKEN exist on a Forgejo repo."""
    if not repo_exists(base, forgejo_token, owner, repo):
        raise ForgejoCiError(f"Forgejo repo {owner}/{repo} not found")
    push_review_workflow(root, base, forgejo_token, owner, repo)
    ensure_repo_actions_secret(root, base, forgejo_token, owner, repo)


def sync_configured_ci_repos(root: Path, forgejo_token: str) -> int:
    """Sync workflow + SHIFT_LEFT_TOKEN for gate.check_repo repos that exist on Forgejo."""
    base = forgejo_base_url()
    synced = 0
    for slug in configured_ci_repo_slugs(root):
        owner, name = parse_repo_slug(slug)
        if not repo_exists(base, forgejo_token, owner, name):
            print(f"Skipping {slug} — not found on Forgejo yet.")
            continue
        sync_repo_ci_auth(root, base, forgejo_token, owner, name)
        synced += 1
    return synced


def resolve_forgejo_owner(root: Path, forgejo_token: str) -> str:
    """Pick the namespace used for operator-created repos."""
    base = forgejo_base_url()
    preferred = os.environ.get("FORGEJO_DEFAULT_OWNER", "shift-left").strip()
    if org_exists(base, forgejo_token, preferred):
        return preferred
    login = authenticated_login(base, forgejo_token)
    if login:
        return login
    from shift_left_cli.forgejo_bootstrap import _read_bootstrap_secret

    bootstrap_user = _read_bootstrap_secret(root, "forgejo_admin_user")
    if bootstrap_user:
        return bootstrap_user
    return preferred


def create_forgejo_review_repo(
    root: Path,
    name: str,
    *,
    forgejo_token: str,
    owner: str | None = None,
) -> str:
    """Create repo on Forgejo with workflow + SHIFT_LEFT_TOKEN (fully automated)."""
    base = forgejo_base_url()
    repo_owner = owner or resolve_forgejo_owner(root, forgejo_token)
    ensure_repo(base, forgejo_token, repo_owner, name)
    sync_repo_ci_auth(root, base, forgejo_token, repo_owner, name)
    readme = f"# {name}\n\nShift-Left managed config repo with review workflow.\n"
    _upsert_file(base, forgejo_token, repo_owner, name, "README.md", readme)
    return f"{repo_owner}/{name}"


def repo_exists(base: str, token: str, owner: str, name: str) -> bool:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise ForgejoCiError(f"Failed to inspect repo {owner}/{name}: HTTP {exc.code}") from exc


def org_exists(base: str, token: str, org: str) -> bool:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/orgs/{org}",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise ForgejoCiError(f"Failed to inspect Forgejo org {org!r}: HTTP {exc.code}") from exc


def authenticated_login(base: str, token: str) -> str | None:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/user",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise ForgejoCiError(f"Forgejo token rejected: HTTP {exc.code}") from exc
    login = payload.get("login")
    return str(login) if login else None


def ensure_repo(base: str, token: str, owner: str, name: str) -> None:
    if repo_exists(base, token, owner, name):
        print(f"Forgejo repo {owner}/{name} already exists.")
        return
    body = json.dumps({"name": name, "auto_init": True, "private": False}).encode()
    if org_exists(base, token, owner):
        url = f"{base}/api/v1/orgs/{owner}/repos"
    else:
        url = f"{base}/api/v1/user/repos"
    request = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            print(f"Created Forgejo repo {owner}/{name}.")
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return
        raise ForgejoCiError(f"Failed to create Forgejo repo {owner}/{name}: HTTP {exc.code}") from exc


def _upsert_file(
    base: str,
    token: str,
    owner: str,
    name: str,
    path: str,
    content: str,
    *,
    branch: str = "main",
) -> None:
    import base64

    sha = _file_sha(base, token, owner, name, path, branch=branch)
    payload: dict[str, str] = {
        "content": base64.b64encode(content.encode()).decode(),
        "message": f"Update {path}",
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    encoded = json.dumps(payload).encode()
    method = "PUT" if sha else "POST"
    url = f"{base}/api/v1/repos/{owner}/{name}/contents/{path}"
    request = urllib.request.Request(  # noqa: S310
        url,
        data=encoded,
        method=method,
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            pass
    except urllib.error.HTTPError as exc:
        raise ForgejoCiError(f"Failed to write {path} on {owner}/{name}: HTTP {exc.code}") from exc


def _file_sha(base: str, token: str, owner: str, name: str, path: str, *, branch: str) -> str | None:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}/contents/{path}?ref={branch}",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
        return str(payload.get("sha") or "")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ForgejoCiError(f"Failed to read {path} on {owner}/{name}: HTTP {exc.code}") from exc
