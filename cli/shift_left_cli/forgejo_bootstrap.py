"""Automate Forgejo admin, token, and runner registration."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import base64
from pathlib import Path

from shift_left_cli.compose_util import detect_compose

RUNNER_LABEL = "self-hosted"
RUNNER_REGISTER_LABEL = "self-hosted:host"
OPERATOR_TOKEN_NAME = "shift-left-operator"
# TODO: verify Forgejo 11.x admin CLI flags and PAT scope names against your deployment.


class ForgejoBootstrapError(RuntimeError):
    pass


def bootstrap_forgejo(root: Path, *, admin_user: str = "shiftleft-admin") -> dict[str, str]:
    from shift_left_cli.forgejo_config import ensure_forgejo_app_config, sync_postgres_password

    compose = detect_compose(root)
    if ensure_forgejo_app_config(root):
        print("Forgejo: updated app.ini for headless install — restarting container…")
        _restart_forgejo(root, compose)
    sync_postgres_password(root)
    _run_forgejo_migrate(root, compose)
    _wait_forgejo_api(root)

    password = _ensure_admin_password(root, compose, admin_user)
    token = _ensure_access_token(root, compose, admin_user, password)

    runner_token = _read_bootstrap_secret(root, "forgejo_runner_token")
    if not runner_token:
        runner_token = _fetch_runner_registration_token(root, token)

    runner_token = _read_bootstrap_secret(root, "forgejo_runner_token")
    if not runner_token:
        runner_token = _fetch_runner_registration_token(root, token)

    _register_runner(root, compose, runner_token)
    _verify_runner_online(root, token)

    _update_env(root, {"FORGEJO_TOKEN": token, "FORGEJO_RUNNER_TOKEN": runner_token})
    secrets = {
        "forgejo_admin_user": admin_user,
        "forgejo_admin_password": password,
        "forgejo_token": token,
    }
    _persist_bootstrap_secrets(root, secrets)
    return secrets


def _wait_forgejo_api(root: Path, timeout: float = 120.0) -> None:
    base = os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")
    version_url = f"{base}/api/v1/version"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(version_url, timeout=2) as response:  # noqa: S310
                if response.status == 200:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code == 200:
                return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(2)
    if _install_page_visible(base):
        raise ForgejoBootstrapError(
            "Forgejo is still on the web install wizard (INSTALL_LOCK=false). "
            "Run ./shift-left up --force configure and resume."
        )
    raise ForgejoBootstrapError("Forgejo API did not become reachable — resume with ./shift-left up")


def _install_page_visible(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/", timeout=2) as response:  # noqa: S310
            body = response.read(8192).decode("utf-8", errors="ignore")
    except Exception:
        return False
    return "Installation" in body and "install-config-container" in body


def _restart_forgejo(root: Path, compose) -> None:
    from shift_left_cli.stack import _wait_tcp, service_host_port

    subprocess.check_call(compose.cmd("restart", "forgejo"), cwd=root)
    host, port = service_host_port("forgejo")
    _wait_tcp(host, port, "forgejo", timeout=120.0)
    time.sleep(2)


def _run_forgejo_migrate(root: Path, compose) -> None:
    result = subprocess.run(
        compose.cmd("exec", "-T", "forgejo", "forgejo", "migrate"),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout or "").strip()
    if "already" in detail.lower():
        return
    raise ForgejoBootstrapError(f"forgejo migrate failed: {detail or result.returncode}")


def _admin_exists(root: Path, compose, username: str) -> bool:
    result = subprocess.run(
        compose.cmd("exec", "-T", "forgejo", "forgejo", "admin", "user", "list"),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return username in (result.stdout or "")


def _ensure_admin_password(root: Path, compose, admin_user: str) -> str:
    saved = _read_bootstrap_secret(root, "forgejo_admin_password")
    if saved and _admin_exists(root, compose, admin_user):
        return saved

    if not _admin_exists(root, compose, admin_user):
        password = _generate_secret()
        subprocess.check_call(
            compose.cmd(
                "exec",
                "-T",
                "forgejo",
                "forgejo",
                "admin",
                "user",
                "create",
                "--admin",
                "--username",
                admin_user,
                "--password",
                password,
                "--email",
                f"{admin_user}@shift-left.local",
                "--must-change-password=false",
            ),
            cwd=root,
        )
    else:
        password = _generate_secret()
        subprocess.check_call(
            compose.cmd(
                "exec",
                "-T",
                "forgejo",
                "forgejo",
                "admin",
                "user",
                "change-password",
                "--username",
                admin_user,
                "--password",
                password,
                "--must-change-password=false",
            ),
            cwd=root,
        )

    _persist_bootstrap_secrets(
        root,
        {
            "forgejo_admin_user": admin_user,
            "forgejo_admin_password": password,
            **_read_bootstrap_secrets(root),
        },
    )
    return password


def _ensure_access_token(root: Path, compose, username: str, password: str) -> str:
    for candidate in (
        os.environ.get("FORGEJO_TOKEN", "").strip(),
        _read_bootstrap_secret(root, "forgejo_token") or "",
    ):
        if candidate and _token_valid(candidate):
            return candidate

    try:
        token = _create_access_token(root, compose, username)
    except ForgejoBootstrapError as exc:
        message = str(exc).lower()
        if "has been used already" not in message and "already exists" not in message:
            raise
        _delete_access_token_by_name(username, password, OPERATOR_TOKEN_NAME)
        token = _create_access_token(root, compose, username)

    _persist_bootstrap_secrets(root, {"forgejo_token": token})
    return token


def _token_valid(token: str) -> bool:
    base = os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/user",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False


def _delete_access_token_by_name(username: str, password: str, token_name: str) -> None:
    base = os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")
    auth = _basic_auth_header(username, password)
    list_request = urllib.request.Request(  # noqa: S310
        f"{base}/api/v1/users/{username}/tokens",
        headers={"Authorization": auth},
    )
    try:
        with urllib.request.urlopen(list_request, timeout=10) as response:
            tokens = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise ForgejoBootstrapError(
            f"Could not list Forgejo access tokens for {username!r}: HTTP {exc.code}"
        ) from exc

    if not isinstance(tokens, list):
        raise ForgejoBootstrapError("Unexpected Forgejo token list response.")

    for entry in tokens:
        if entry.get("name") != token_name:
            continue
        token_id = entry.get("id")
        if token_id is None:
            continue
        delete_request = urllib.request.Request(  # noqa: S310
            f"{base}/api/v1/users/{username}/tokens/{token_id}",
            method="DELETE",
            headers={"Authorization": auth},
        )
        with urllib.request.urlopen(delete_request, timeout=10):
            return
    raise ForgejoBootstrapError(
        f"Forgejo access token {token_name!r} exists but could not be deleted — resume with ./shift-left up"
    )


def _basic_auth_header(username: str, password: str) -> str:
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {credentials}"


def _create_access_token(root: Path, compose, username: str) -> str:
    # TODO: verify token scope list for Forgejo 11.x (repo, issue, admin required for runner token).
    result = subprocess.run(
        compose.cmd(
            "exec",
            "-T",
            "forgejo",
            "forgejo",
            "admin",
            "user",
            "generate-access-token",
            "--username",
            username,
            "--token-name",
            OPERATOR_TOKEN_NAME,
            "--scopes",
            "all",
            "--raw",
        ),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ForgejoBootstrapError(
            f"Failed to generate Forgejo access token: {(result.stderr or result.stdout).strip()}"
        )
    token = (result.stdout or "").strip().splitlines()[-1].strip()
    if not token:
        raise ForgejoBootstrapError("Forgejo access token generation returned empty output.")
    return token


def _fetch_runner_registration_token(root: Path, admin_token: str) -> str:
    compose = detect_compose(root)
    result = subprocess.run(
        compose.cmd("exec", "-T", "forgejo", "forgejo", "actions", "generate-runner-token"),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        token = (result.stdout or "").strip().splitlines()[-1].strip()
        if token:
            return token

    base = os.environ.get("FORGEJO_ROOT_URL", "http://localhost:3000").rstrip("/")
    for path in (
        "/api/v1/admin/actions/runners/registration-token",
        "/api/v1/admin/runners/registration-token",
    ):
        request = urllib.request.Request(  # noqa: S310
            f"{base}{path}",
            headers={"Authorization": f"token {admin_token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode())
        except urllib.error.HTTPError:
            continue
        token = payload.get("token")
        if token:
            return str(token)
    raise ForgejoBootstrapError(
        "Runner registration token unavailable (HTTP 404 on known endpoints). "
        "Ensure [actions] ENABLED=true in Forgejo app.ini."
    )


def _register_runner(root: Path, compose, runner_token: str) -> None:
    runner_file = root / "data" / "forgejo-runner" / ".runner"
    if runner_file.exists():
        print("Forgejo runner already registered (idempotent).")
        return
    url = os.environ.get("FORGEJO_RUNNER_URL", "http://forgejo:3000")
    subprocess.check_call(
        compose.cmd(
            "run",
            "--rm",
            "forgejo-runner",
            "forgejo-runner",
            "register",
            "--no-interactive",
            "--instance",
            url,
            "--token",
            runner_token,
            "--name",
            "shift-left-runner",
            "--labels",
            RUNNER_REGISTER_LABEL,
        ),
        cwd=root,
    )


def _verify_runner_online(root: Path, admin_token: str) -> None:
    runner_file = root / "data" / "forgejo-runner" / ".runner"
    if not runner_file.exists():
        raise ForgejoBootstrapError(
            "Forgejo runner is not registered — remove data/forgejo-runner/.runner and re-run ./shift-left up"
        )

    compose = detect_compose(root)
    subprocess.check_call(compose.cmd("up", "-d", "forgejo-runner"), cwd=root)

    deadline = time.time() + 90.0
    while time.time() < deadline:
        result = subprocess.run(
            compose.cmd("logs", "--tail", "30", "forgejo-runner"),
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        logs = (result.stdout or "") + (result.stderr or "")
        if "declared successfully" in logs and RUNNER_LABEL in logs:
            print(f"Runner online with label {RUNNER_LABEL!r}")
            return
        if "declared successfully" in logs:
            print("Forgejo runner declared successfully.")
            return
        time.sleep(2)

    raise ForgejoBootstrapError(
        "Forgejo runner did not start — check: docker compose logs forgejo-runner"
    )


def _update_env(root: Path, updates: dict[str, str]) -> None:
    path = root / ".env"
    lines = path.read_text().splitlines() if path.exists() else []
    existing = {}
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            existing[key] = value
    existing.update(updates)
    out = []
    for key, value in existing.items():
        out.append(f"{key}={value}")
    path.write_text("\n".join(out) + "\n")


def _read_bootstrap_secret(root: Path, key: str) -> str | None:
    return _read_bootstrap_secrets(root).get(key)


def _read_bootstrap_secrets(root: Path) -> dict[str, str]:
    from shift_left_cli.state import state_dir

    path = state_dir(root) / "bootstrap-secrets.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        return {}
    return {str(key): str(value) for key, value in payload.items() if value}


def _persist_bootstrap_secrets(root: Path, secrets: dict[str, str]) -> None:
    from shift_left_cli.state import state_dir

    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "bootstrap-secrets.json"
    merged = _read_bootstrap_secrets(root)
    merged.update(secrets)
    path.write_text(json.dumps(merged))


def _generate_secret() -> str:
    import secrets

    return secrets.token_urlsafe(24)
