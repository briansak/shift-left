"""Runtime sovereignty guarantees — re-exports shared implementation."""

from shift_left_shared.runtime import (  # noqa: F401
    FORBIDDEN_RUNTIME_PATTERNS,
    LocalInferenceRequiredError,
    assert_no_remote_inference_fallback,
)

# Intentionally absent: telemetry, analytics, crash reporting, phone-home.
