"""Hugging Face downloads via project .venv (avoids macOS SSL issues with standalone hf)."""

from __future__ import annotations

import os
from pathlib import Path


class HfDownloadError(RuntimeError):
    pass


def configure_ssl_environment() -> str | None:
    """Apply certifi CA bundle for httpx/requests. Returns bundle path if set."""
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    try:
        import certifi

        bundle = certifi.where()
        os.environ["SSL_CERT_FILE"] = bundle
        os.environ["REQUESTS_CA_BUNDLE"] = bundle
        os.environ["CURL_CA_BUNDLE"] = bundle
        return bundle
    except ImportError:
        return None


def _configure_ssl() -> None:
    configure_ssl_environment()


def _read_hf_token(root: Path) -> str | None:
    from shift_left_cli.up import load_dotenv

    load_dotenv(root)
    for key in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_HUB_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return None


def download_repo_file(
    root: Path,
    *,
    repo_id: str,
    filename: str,
    dest_dir: Path,
    token: str | None = None,
) -> Path:
    """Download a single file into dest_dir using huggingface_hub."""
    bundle = configure_ssl_environment()
    dest_dir.mkdir(parents=True, exist_ok=True)
    resolved_token = token if token is not None else _read_hf_token(root)

    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise HfDownloadError(
            "huggingface_hub is not installed — re-run ./shift-left up to bootstrap .venv."
        ) from exc

    print(f"Downloading {repo_id}/{filename} → {dest_dir}")
    print("(Operator-initiated egress — not used at review runtime.)")
    try:
        path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            local_dir=str(dest_dir),
            token=resolved_token,
        )
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        rel = dest_dir
        try:
            rel = dest_dir.relative_to(root)
        except ValueError:
            pass
        ssl_failed = "CERTIFICATE_VERIFY_FAILED" in message or "certificate verify failed" in message.lower()
        if ssl_failed:
            cert_hint = (
                f"  SSL_CERT_FILE=$(.venv/bin/python -m certifi) ./shift-left up"
                if bundle
                else "  .venv/bin/pip install certifi && ./shift-left up"
            )
            raise HfDownloadError(
                "Hugging Face download failed due to SSL certificate verification.\n"
                "  Option A — restore weights manually (recommended if you have a backup):\n"
                f"    mkdir -p {rel}\n"
                f"    cp <your-backup>/{filename} {rel}/\n"
                "  Option B — fix SSL and retry:\n"
                f"    {cert_hint}\n"
                f"  Detail: {message}"
            ) from exc
        raise HfDownloadError(f"Hugging Face download failed: {message}") from exc

    return Path(path)
