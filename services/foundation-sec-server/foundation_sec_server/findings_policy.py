"""Model-server finding invariants — must not influence gate severity."""

from __future__ import annotations

# Model-sourced findings never carry handler_asserted_cwe; policy_severity stays
# UNCLASSIFIED after orchestrator normalization (derive_policy_severity ignores model CWE).
MODEL_SERVER_HANDLER_ASSERTED_CWE: None = None
