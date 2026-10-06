"""Sentinel values for investigation trace rows that are not sandbox commands."""

CANCELLATION_MARKER_COMMAND = "[operator cancellation]"
CANCELLATION_MARKER_EXIT_STATUS = -1
CANCELLATION_MARKER_OUTPUT = (
    "Investigation cancelled by operator; no sandbox command was interrupted."
)
