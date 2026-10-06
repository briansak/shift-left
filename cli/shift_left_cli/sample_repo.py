"""Sample repo scaffolding and PR creation."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from shift_left_cli.forgejo_ci import WORKFLOW_REL, sync_repo_ci_auth

PREFERRED_SAMPLE_OWNER = "shift-left"
SAMPLE_REPO_NAME = "sample-firewall"


class SampleRepoError(RuntimeError):
    pass


def scaffold_sample_repo(root: Path, *, admin_token: str) -> dict[str, str]:
    base = os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")
    owner = _resolve_sample_owner(base, admin_token, root)
    name = SAMPLE_REPO_NAME
    repo_slug = f"{owner}/{name}"
    _ensure_repo(base, admin_token, owner, name)
    _push_sample_content(root, base, admin_token, owner, name)
    try:
        sync_repo_ci_auth(root, base, admin_token, owner, name)
    except Exception as exc:
        raise SampleRepoError(str(exc)) from exc
    pr_number = _open_sample_pr(base, admin_token, owner, name)
    return {"repo": repo_slug, "pr_number": str(pr_number)}


def _resolve_sample_owner(base: str, token: str, root: Path) -> str:
    preferred = os.environ.get("FORGEJO_DEFAULT_OWNER", PREFERRED_SAMPLE_OWNER).strip()
    if _repo_exists(base, token, preferred, SAMPLE_REPO_NAME):
        return preferred

    login = _authenticated_login(base, token)
    if login and _repo_exists(base, token, login, SAMPLE_REPO_NAME):
        print(f"Sample repo found under {login}/{SAMPLE_REPO_NAME}.")
        return login

    if _org_exists(base, token, preferred):
        return preferred

    from shift_left_cli.forgejo_bootstrap import _read_bootstrap_secret

    bootstrap_user = _read_bootstrap_secret(root, "forgejo_admin_user")
    if bootstrap_user and _repo_exists(base, token, bootstrap_user, SAMPLE_REPO_NAME):
        print(f"Sample repo found under {bootstrap_user}/{SAMPLE_REPO_NAME}.")
        return bootstrap_user

    if _create_org(base, token, preferred):
        return preferred

    if login:
        print(f"Using Forgejo user namespace {login!r} for sample repo.")
        return login
    if bootstrap_user:
        return bootstrap_user
    raise SampleRepoError("Could not determine Forgejo owner for sample repo.")


def _authenticated_login(base: str, token: str) -> str | None:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/user",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise SampleRepoError(f"Forgejo token rejected while resolving sample owner: HTTP {exc.code}") from exc
    login = payload.get("login")
    return str(login) if login else None


def _org_exists(base: str, token: str, org: str) -> bool:
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
        raise SampleRepoError(f"Failed to inspect Forgejo org {org!r}: HTTP {exc.code}") from exc


def _create_org(base: str, token: str, org: str) -> bool:
    body = json.dumps(
        {
            "username": org,
            "full_name": "Shift-Left",
            "description": "Shift-Left onboarding sample repositories",
            "visibility": "public",
        }
    ).encode()
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/orgs",
        data=body,
        method="POST",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            print(f"Created Forgejo organization {org!r}.")
            return True
    except urllib.error.HTTPError as exc:
        if exc.code in {409, 422}:
            return _org_exists(base, token, org)
        return False


def _ensure_repo(base: str, token: str, owner: str, name: str) -> None:
    if _repo_exists(base, token, owner, name):
        print(f"Sample repo {owner}/{name} already exists.")
        return
    body = json.dumps({"name": name, "auto_init": True, "private": False}).encode()
    if _org_exists(base, token, owner):
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
            print(f"Created sample repo {owner}/{name}.")
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return
        raise SampleRepoError(f"Failed to create sample repo at {url}: HTTP {exc.code}") from exc


def _repo_exists(base: str, token: str, owner: str, name: str) -> bool:
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
        raise SampleRepoError(f"Failed to inspect repo {owner}/{name}: HTTP {exc.code}") from exc


def _push_sample_content(root: Path, base: str, token: str, owner: str, name: str) -> None:
    workflow_src = root / "templates" / "forgejo" / "workflows" / "shift-left-review.yml"
    terraform_src = root / "examples" / "ftdv-firewall" / "terraform" / "lab"
    if not workflow_src.exists():
        raise SampleRepoError(f"Missing workflow template {workflow_src}")

    files = {
        "README.md": "# Sample firewall repo\n\nBaseline Terraform with Shift-Left review workflow.\n",
        WORKFLOW_REL: workflow_src.read_text(),
    }
    if (terraform_src / "main.tf").exists():
        files["terraform/main.tf"] = (terraform_src / "main.tf").read_text()

    for path, content in files.items():
        _upsert_file(base, token, owner, name, path, content)


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
        "message": f"Add {path}",
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
        raise SampleRepoError(f"Failed to write {path} on {owner}/{name}: HTTP {exc.code}") from exc


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
        raise SampleRepoError(f"Failed to read {path} on {owner}/{name}: HTTP {exc.code}") from exc


def _create_branch(base: str, token: str, owner: str, name: str, branch: str, from_ref: str = "main") -> None:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}/git/refs/heads/{from_ref}",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise SampleRepoError(
            f"Failed to read base branch {from_ref!r} on {owner}/{name}: HTTP {exc.code}"
        ) from exc
    if isinstance(payload, list):
        if not payload:
            raise SampleRepoError(f"Base branch {from_ref!r} not found on {owner}/{name}.")
        payload = payload[0]
    sha = payload["object"]["sha"]
    body = json.dumps({"new_branch_name": branch, "old_ref_name": from_ref}).encode()
    create = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}/branches",
        data=body,
        method="POST",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(create, timeout=15):
            return
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return
    ref_body = json.dumps({"ref": f"refs/heads/{branch}", "sha": sha}).encode()
    ref_req = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}/git/refs",
        data=ref_body,
        method="POST",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(ref_req, timeout=15):
            pass
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise SampleRepoError(
                f"Failed to create branch {branch!r} on {owner}/{name}: HTTP {exc.code}"
            ) from exc


def _open_sample_pr(base: str, token: str, owner: str, name: str) -> int:
    branch = "sample/insecure-rule"
    existing = _find_open_pr(base, token, owner, name, branch)
    if existing is not None:
        print(f"Sample PR #{existing} already open on {owner}/{name}.")
        return existing

    _create_branch(base, token, owner, name, branch)
    insecure_rule = (
        'resource "azurerm_network_security_rule" "sample_any_any" {\n'
        '  name                       = "allow-any-any"\n'
        '  direction                  = "Inbound"\n'
        '  access                     = "Allow"\n'
        '  protocol                   = "*"\n'
        '  source_port_range          = "*"\n'
        '  destination_port_range     = "*"\n'
        '  source_address_prefix      = "*"\n'
        '  destination_address_prefix = "*"\n'
        "}\n"
    )
    _upsert_file(base, token, owner, name, "terraform/insecure.tf", insecure_rule, branch=branch)
    body = json.dumps(
        {
            "title": "Sample: unrestricted any/any permit",
            "head": branch,
            "base": "main",
            "body": "Introduces a known-flaggable any/any rule for onboarding.",
        }
    ).encode()
    url = f"{base}/api/v1/repos/{owner}/{name}/pulls"
    request = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise SampleRepoError(f"Failed to open sample PR on {owner}/{name}: HTTP {exc.code}") from exc
    return int(payload["number"])


def _find_open_pr(base: str, token: str, owner: str, name: str, head_branch: str) -> int | None:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/repos/{owner}/{name}/pulls?state=open",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            pulls = json.loads(response.read().decode())
    except urllib.error.HTTPError:
        return None
    if not isinstance(pulls, list):
        return None
    for pull in pulls:
        head = pull.get("head") or {}
        if head.get("ref") == head_branch:
            number = pull.get("number")
            if number is not None:
                return int(number)
    return None


def create_repo_from_template(root: Path, name: str, *, admin_token: str) -> str:
    owner = os.environ.get("FORGEJO_DEFAULT_OWNER", PREFERRED_SAMPLE_OWNER)
    repo = f"{owner}/{name}"
    scaffold_sample_repo(root, admin_token=admin_token)
    return repo
