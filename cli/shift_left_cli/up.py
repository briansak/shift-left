"""./shift-left up — idempotent first-run bootstrap."""

from __future__ import annotations

import os
import subprocess
import webbrowser
from pathlib import Path

from shift_left_cli.configure import ensure_layout, generate_config, generate_env
from shift_left_cli.fetch_phase import fetch_all
from shift_left_cli.forgejo_bootstrap import bootstrap_forgejo
from shift_left_cli.model_packages import ensure_foundation_sec_server_package
from shift_left_cli.preflight import PreflightError, run_preflight
from shift_left_cli.stack import start_compose_stack
from shift_left_cli.state import credentials_shown, mark_credentials_shown, mark_phase, phase_complete

PHASES = (
    "preflight",
    "fetch",
    "configure",
    "start",
    "forgejo",
    "sample",
    "verify",
    "open",
)


class UpError(RuntimeError):
    pass


def load_dotenv(root: Path) -> None:
    path = root / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def operator_up(root: Path, *, force: bool = False, no_browser: bool = False) -> None:
    load_dotenv(root)
    ensure_layout(root)
    platform_info: dict[str, str] = {}

    for phase in PHASES:
        ALWAYS_RUN = {"start", "verify"}
        if not force and phase_complete(root, phase) and phase not in ALWAYS_RUN:
            print(f"[skip] {phase} — already complete (re-run with --force to redo)")
            continue
        print(f"\n=== Phase: {phase} ===")
        try:
            if phase == "preflight":
                platform_info = run_preflight(root)
            elif phase == "fetch":
                fetch_all(root)
            elif phase == "configure":
                generate_env(root, force=force, platform=platform_info)
                generate_config(root, force=force, platform=platform_info)
            elif phase == "start":
                start_compose_stack(root)
                _start_model_servers(root, platform_info)
            elif phase == "forgejo":
                secrets = bootstrap_forgejo(root)
                if not credentials_shown(root):
                    _print_credentials_once(root, secrets)
            elif phase == "sample":
                from shift_left_cli.sample_repo import scaffold_sample_repo

                token = os.environ.get("FORGEJO_TOKEN", "")
                if token:
                    scaffold_sample_repo(root, admin_token=token)
            elif phase == "verify":
                _verify_health(root)
            elif phase == "open":
                if not no_browser:
                    port = os.environ.get("ORCHESTRATOR_PORT", "8080")
                    webbrowser.open(f"http://127.0.0.1:{port}/ui/health")
            mark_phase(root, phase)
        except PreflightError as exc:
            raise UpError(f"Preflight failed: {exc}\nResume with: ./shift-left up") from exc
        except subprocess.CalledProcessError as exc:
            raise UpError(
                f"Phase {phase} failed (exit {exc.returncode}). Resume with: ./shift-left up"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            from shift_left_cli.hf_download import HfDownloadError
            from shift_left_cli.sample_repo import SampleRepoError

            if isinstance(exc, HfDownloadError):
                raise UpError(f"Phase {phase} failed: {exc}\nResume with: ./shift-left up") from exc
            if isinstance(exc, SampleRepoError):
                raise UpError(f"Phase {phase} failed: {exc}\nResume with: ./shift-left up") from exc
            raise UpError(f"Phase {phase} failed: {exc}\nResume with: ./shift-left up") from exc

    print("\nShift-Left is up. Open http://127.0.0.1:8080/ui/health")


def _start_model_servers(root: Path, platform: dict[str, str]) -> None:
    from shift_left.system.supervisor import start_service

    if platform.get("model_hosting") == "compose-linux":
        compose = __import__("shift_left_cli.compose_util", fromlist=["detect_compose"]).detect_compose(root)
        subprocess.check_call(
            compose.cmd("--profile", "linux-cpu", "up", "-d", "foundation-sec-server"),
            cwd=root,
        )
        return
    ensure_foundation_sec_server_package(root)
    print("Starting host-native foundation-sec-server (supervised)…")
    info = start_service(root, "foundation-sec-server")
    print(f"  PID {info['pid']} — log {info['log_path']}")


def _verify_health(root: Path) -> None:
    _sync_forgejo_actions_auth(root)
    config_path = root / "config" / "shift-left.yaml"
    if config_path.is_dir():
        raise UpError(
            "config/shift-left.yaml is a directory (Docker mount artifact). "
            "Run ./shift-left up --force configure, then ./shift-left up"
        )

    env = os.environ.copy()
    env["PYTHONPATH"] = ":".join(
        [
            str(root / "cli"),
            str(root / "services" / "orchestrator"),
            str(root / "services" / "shift-left-shared"),
            env.get("PYTHONPATH", ""),
        ]
    )
    subprocess.check_call(
        [str(root / "scripts" / "shift-left"), "status"],
        cwd=root,
        env=env,
    )


def _sync_forgejo_actions_auth(root: Path) -> None:
    """Re-sync SHIFT_LEFT_TOKEN + workflow on gate.check_repo (idempotent; safe on every verify)."""
    import os

    from shift_left_cli.forgejo_bootstrap import _read_bootstrap_secret
    from shift_left_cli.forgejo_ci import ForgejoCiError, sync_configured_ci_repos

    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        token = _read_bootstrap_secret(root, "forgejo_token") or ""
    if not token:
        print("Skipping Forgejo Actions auth sync — FORGEJO_TOKEN not available.")
        return
    try:
        count = sync_configured_ci_repos(root, token)
    except ForgejoCiError as exc:
        print(f"Warning: Forgejo Actions auth sync failed: {exc}")
        return
    if count:
        print(f"Forgejo Actions auth synced on {count} repo(s) (workflow + SHIFT_LEFT_TOKEN).")


def _print_credentials_once(root: Path, secrets: dict[str, str]) -> None:
    operator_token = _mint_operator_token_once(root)
    print("\n" + "=" * 60)
    print("SAVE THESE CREDENTIALS NOW — shown once, not recoverable from logs")
    print("=" * 60)
    print(f"Forgejo admin user: {secrets.get('forgejo_admin_user')}")
    print(f"Forgejo admin password: {secrets.get('forgejo_admin_password')}")
    print(f"Forgejo API token: {secrets.get('forgejo_token')}")
    if operator_token:
        print(f"Operator UI/API token: {operator_token}")
    print("=" * 60 + "\n")
    mark_credentials_shown(root, {"shown": True})


def _mint_operator_token_once(root: Path) -> str | None:
    from shift_left.auth.context import TokenCapability
    from shift_left.auth.tokens import mint_api_token
    from shift_left_cli.state import state_dir

    marker = state_dir(root) / "operator-token-once.json"
    if marker.exists():
        return None
    try:
        from shift_left_cli.tokens import _load_store

        store = _load_store(root)
        _, plaintext = mint_api_token(
            store,
            label="bootstrap-admin",
            actor="admin",
            capabilities=[
                TokenCapability.ADMIN,
                TokenCapability.REVIEW,
                TokenCapability.TRIAGE,
                TokenCapability.APPROVE,
                TokenCapability.OVERRIDE,
            ],
        )
        marker.write_text('{"minted": true}\n')
        return plaintext
    except Exception:  # noqa: BLE001 — orchestrator DB may not be ready yet
        return None
