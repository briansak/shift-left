"""Runtime sovereignty — no hosted inference fallback."""

from __future__ import annotations


class LocalInferenceRequiredError(RuntimeError):
    """Raised when inference cannot complete locally — never fall back to hosted APIs."""


FORBIDDEN_RUNTIME_PATTERNS = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTARES_REMOTE_API",
    "SHIFT_LEFT_CLOUD_API",
    "HF_INFERENCE_ENDPOINT",
)


def assert_no_remote_inference_fallback(env: dict[str, str]) -> None:
    """Reject configuration that would send code/config to hosted model APIs."""
    present = [key for key in FORBIDDEN_RUNTIME_PATTERNS if env.get(key)]
    if present:
        raise LocalInferenceRequiredError(
            "Hosted inference environment variables are set: "
            f"{', '.join(present)}. "
            "Shift-Left uses local models only. Remove these variables — "
            "the pipeline fails closed rather than sending artifacts externally."
        )
