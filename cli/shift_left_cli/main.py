"""Shift-Left operator CLI entrypoint."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from shift_left_cli import __version__
from shift_left_cli.bundle import bundle_build, bundle_install
from shift_left_cli.down import operator_down
from shift_left_cli.doctor import operator_doctor
from shift_left_cli.install import connected_install
from shift_left_cli.install_antares import install_antares
from shift_left_cli.model_cmd import operator_model
from shift_left_cli.new_target import operator_new_target
from shift_left_cli.repos import import_config_repo, new_repo_scaffold
from shift_left_cli.reset import operator_reset
from shift_left_cli.status_cmd import operator_status
from shift_left_cli.sync_reference import sync_reference_data
from shift_left_cli.up import UpError, operator_up
from shift_left_cli.update import operator_update
from shift_left_cli.audit_prune import audit_prune
from shift_left_cli.tokens import token_list, token_mint, token_revoke
from shift_left_cli.verify_runtime import verify_runtime_sovereignty


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="shift-left",
        description=(
            "Shift-Left operator CLI. Install/update/sync may use network access. "
            "The running pipeline never does."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Shift-Left installation root (default: current directory)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install", help="Connected install: pull images, stage models, sync reference data")

    up_parser = sub.add_parser("up", help="Idempotent first-run bootstrap (install, start, verify)")
    up_parser.add_argument("--force", action="store_true", help="Regenerate config/.env and redo completed phases")
    up_parser.add_argument("--no-browser", action="store_true", help="Do not open the UI in a browser")

    sub.add_parser("down", help="Stop Compose stack and supervised model servers")
    sub.add_parser("status", help="Print prerequisite health report")
    sub.add_parser("doctor", help="Diagnose setup issues")
    reset_parser = sub.add_parser("reset", help="Destroy local state (destructive)")
    reset_parser.add_argument(
        "--confirm",
        required=True,
        help='Type exactly: DESTROY SHIFT-LEFT LOCAL STATE',
    )

    sub.add_parser("install-antares", help="Optional Antares install (HF terms + HF_TOKEN)")

    model_parser = sub.add_parser("model", help="Start/stop/restart host-native model servers")
    model_parser.add_argument("action", choices=["start", "stop", "restart"])
    model_parser.add_argument(
        "service",
        help="foundation-sec-server | antares-server (aliases: foundation-sec, antares)",
    )

    new_repo_parser = sub.add_parser("new-repo", help="Create a Forgejo repo with the review workflow")
    new_repo_parser.add_argument("name", help="Repository name")

    new_target_parser = sub.add_parser("new-target", help="Scaffold a managed target in config/shift-left.yaml")
    new_target_parser.add_argument("display_name", help='Display name (e.g. "edge-fw-01")')
    new_target_parser.add_argument("target_type", help="Target type (e.g. cisco_secure_firewall)")
    new_target_parser.add_argument("repo", help="owner/repo slug")
    new_target_parser.add_argument("--branch", default="main", help="Tracked branch (default: main)")
    new_target_parser.add_argument(
        "--config-paths",
        default="",
        help="Comma-separated config path globs (default: terraform/**)",
    )
    new_target_parser.add_argument("--environment", default="", help="Environment label")
    new_target_parser.add_argument("--criticality", default="", help="Criticality label")
    new_target_parser.add_argument("--owner", default="", help="Responsible team or owner")
    new_target_parser.add_argument(
        "--deployment-adapter",
        default="unconfigured",
        choices=["none", "fmc", "unconfigured"],
        help="Deployment adapter (default: unconfigured)",
    )

    import_parser = sub.add_parser("import-config", help="Report glob matches for an existing Terraform tree")
    import_parser.add_argument("path", type=Path, help="Directory containing Terraform files")

    sub.add_parser("update", help="Operator-initiated update (never automatic)")
    sync_parser = sub.add_parser(
        "sync-reference-data",
        help="Refresh local CVE/CWE/advisory cache (operator-initiated egress only)",
    )
    sync_parser.add_argument(
        "--fetch-nvd",
        action="store_true",
        help="Fetch sample CVEs from NVD API 2.0 (requires network)",
    )

    bundle = sub.add_parser("bundle-build", help="Build offline install bundle on a connected machine")
    bundle.add_argument("--output", required=True, help="Output bundle path (.tar.zst)")

    bun_inst = sub.add_parser("bundle-install", help="Install from offline bundle")
    bun_inst.add_argument("--bundle", required=True, help="Bundle path produced by bundle-build")

    verify_parser = sub.add_parser(
        "verify-runtime",
        help="Run code + config review test with egress disabled",
    )
    verify_parser.add_argument(
        "--real",
        action="store_true",
        help="Use host-native Antares (:8090) and Foundation-Sec (:8091) instead of mocks",
    )

    self_check = sub.add_parser("self-check", help="Pre-flight checks before starting stack")
    self_check.add_argument("--runtime-only", action="store_true", help="Skip install-time image checks")

    token_parser = sub.add_parser("token", help="Mint, list, or revoke API tokens")
    token_sub = token_parser.add_subparsers(dest="token_command", required=True)
    mint_parser = token_sub.add_parser("mint", help="Issue a new API token")
    mint_parser.add_argument("--label", required=True)
    mint_parser.add_argument("--actor", required=True, help="Identity bound to this token")
    mint_parser.add_argument(
        "--capabilities",
        required=True,
        help="Comma-separated: review,triage,approve,override,admin",
    )
    token_sub.add_parser("list", help="List token metadata (never plaintext secrets)")
    revoke_parser = token_sub.add_parser("revoke", help="Revoke a token immediately")
    revoke_parser.add_argument("--id", required=True, dest="token_id")

    prune_parser = sub.add_parser(
        "audit-prune",
        help="Export then delete audit events before a date (operator-initiated only)",
    )
    prune_parser.add_argument("--before", required=True, help="ISO-8601 cutoff (events before this)")
    prune_parser.add_argument("--export", required=True, type=Path, help="Export destination JSON path")

    args = parser.parse_args()
    root = args.root.resolve()

    if args.command == "install":
        connected_install(root)
    elif args.command == "up":
        try:
            operator_up(root, force=args.force, no_browser=args.no_browser)
        except UpError as exc:
            print(exc, file=sys.stderr)
            raise SystemExit(1) from exc
    elif args.command == "down":
        operator_down(root)
    elif args.command == "status":
        raise SystemExit(operator_status(root))
    elif args.command == "doctor":
        operator_doctor(root)
    elif args.command == "reset":
        operator_reset(root, confirmation=args.confirm)
    elif args.command == "install-antares":
        install_antares(root)
    elif args.command == "model":
        operator_model(root, args.action, args.service)
    elif args.command == "new-repo":
        try:
            repo = new_repo_scaffold(root, args.name)
        except RuntimeError as exc:
            print(exc, file=sys.stderr)
            raise SystemExit(1) from exc
        print(f"Created Forgejo repo with review workflow and SHIFT_LEFT_TOKEN: {repo}")
    elif args.command == "new-target":
        raise SystemExit(operator_new_target(args))
    elif args.command == "import-config":
        report = import_config_repo(root, args.path.resolve())
        print(f"Config globs: {report['config_globs']}")
        print(f"Matched ({len(report['matched'])}): {', '.join(report['matched']) or '—'}")
        if report["skipped"]:
            print(f"Outside globs ({len(report['skipped'])}) — will be silently skipped by review:")
            for path in report["skipped"]:
                print(f"  - {path}")
        else:
            print("All files matched configured globs.")
    elif args.command == "update":
        operator_update(root)
    elif args.command == "sync-reference-data":
        sync_reference_data(root, fetch_nvd=getattr(args, "fetch_nvd", False))
    elif args.command == "bundle-build":
        bundle_build(root, Path(args.output))
    elif args.command == "bundle-install":
        bundle_install(root, Path(args.bundle))
    elif args.command == "verify-runtime":
        verify_runtime_sovereignty(root, real_inference=getattr(args, "real", False))
    elif args.command == "self-check":
        script = root / "scripts" / "self-check.sh"
        cmd = [str(script)]
        if args.runtime_only:
            cmd.append("--runtime-only")
        raise SystemExit(subprocess.call(cmd, cwd=root))
    elif args.command == "token":
        if args.token_command == "mint":
            token_mint(
                root,
                label=args.label,
                actor=args.actor,
                capabilities=args.capabilities,
            )
        elif args.token_command == "list":
            token_list(root)
        elif args.token_command == "revoke":
            token_revoke(root, token_id=args.token_id)
    elif args.command == "audit-prune":
        audit_prune(root, before=args.before, export_path=args.export)


if __name__ == "__main__":
    main()
