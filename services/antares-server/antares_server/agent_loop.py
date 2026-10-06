"""Official Antares agent loop — CWE-conditioned terminal exploration."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from antares_server.adapters import ModelAdapter, default_adapter
from antares_server.agent_tools import (
    SubmitNoVulnerabilityFound,
    SubmitVulnerableFiles,
    TerminalToolCall,
)
from antares_server.chat_prompt import (
    build_assistant_parse_failure_message,
    build_assistant_tool_message,
    build_duplicate_tool_message,
    build_harness_notice_tool_message,
    build_initial_messages,
    build_malformed_tool_message,
    build_tool_message,
    duplicate_command_notice,
    format_duplicate_tool_response_trace,
    format_harness_notice_tool_response_trace,
    format_malformed_tool_response_trace,
    format_tool_response_trace,
)
from antares_server.loop_control import (
    BUDGET_ESCALATION_NOTICE,
    CONSECUTIVE_DEGENERATE_HARD_STOP_THRESHOLD,
    CONSECUTIVE_DUPLICATE_HARD_STOP_THRESHOLD,
    CONSECUTIVE_UNPARSEABLE_HARD_STOP_THRESHOLD,
    DEFAULT_INVESTIGATION_WALL_CLOCK_SECONDS,
    DEFAULT_MAX_TERMINAL_ATTEMPTS,
    DUPLICATE_LOOP_FORCED_SUBMISSION_NOTICE,
    FORCED_SUBMISSION_TERMINAL_REJECTED_NOTICE,
    MAX_FORCED_SUBMISSION_GENERATIONS,
    LoopControlState,
    append_harness_notice,
    budget_escalation_threshold,
    classify_duplicate_loop_failure,
    detect_degenerate_repetition,
    inspected_paths_from_command,
    record_search_hits_from_command,
    with_unread_search_hit_pressure,
)
from antares_server.sandbox import (
    InvestigationSandbox,
    ReadOnlySandbox,
    new_investigation_id,
    open_investigation_sandbox,
)
from antares_server.sandbox_audit import (
    CollectedAuditSink,
    SandboxAuditSink,
    SandboxCommandAudit,
    audit_payload_from_sink,
    audit_timestamp,
)

logger = logging.getLogger(__name__)

OUTCOME_COMPLETED = "completed"
OUTCOME_FAILED = "failed"
QUERY_COMPLETED_WITH_FILES = "completed_with_files"
QUERY_COMPLETED_NO_FILES = "completed_no_files"
QUERY_FAILED = "failed"
QUERY_FAILED_UNSUBMITTED = "failed_unsubmitted"

_CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-284": "Improper Access Control",
}

@dataclass(frozen=True)
class AgentQueryResult:
    task_cwe: str
    outcome: str
    ranked_files: list[str] = field(default_factory=list)
    exploration_trace: str = ""
    terminal_calls_used: int = 0
    total_terminal_attempts: int = 0
    duplicate_commands_suppressed: int = 0
    degenerate_repetition_rejections: int = 0
    duplicate_loop_hard_stop_fired: bool = False
    forced_submission: bool = False
    submission_salvaged: bool = False
    budget_escalation_fired: bool = False
    attempt_cap_reached: bool = False
    inspected_files: list[str] = field(default_factory=list)
    search_hit_files: list[str] = field(default_factory=list)
    failure_class: str | None = None
    failure_message: str | None = None
    investigation_id: str = ""
    sandbox_audit: tuple[dict[str, object], ...] = ()
    terminal_budget: int = 0
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = field(default_factory=dict)
    generation_params: dict[str, object] = field(default_factory=dict)


class TextGenerator(Protocol):
    def generate(self, prompt: str, *, temperature: float, top_p: float) -> str: ...


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def normalize_cwe(value: str) -> str:
    text = value.upper().strip()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def default_cwe_description(task_cwe: str) -> str:
    normalized = normalize_cwe(task_cwe)
    return _CWE_DESCRIPTIONS.get(normalized, "Security weakness matching the supplied CWE category.")


def filter_ranked_files(
    ranked_files: list[str],
    *,
    changed_paths: list[str],
    snapshot_paths: set[str],
) -> list[str]:
    """Keep repo-relative paths that exist in snapshot; prefer changed paths when provided."""
    cleaned: list[str] = []
    seen: set[str] = set()
    allowed = {path.lstrip("./") for path in changed_paths} if changed_paths else set()

    for raw in ranked_files:
        path = raw.strip().lstrip("./")
        if not path or path in seen:
            continue
        if snapshot_paths and path not in snapshot_paths:
            continue
        if allowed and path not in allowed:
            continue
        seen.add(path)
        cleaned.append(path)
    return cleaned


class ScriptedTextGenerator:
    """Deterministic agent for tests — explores snapshot then submits ranked files."""

    def __init__(self, sandbox: InvestigationSandbox, *, task_cwe: str) -> None:
        self._sandbox = sandbox
        self._task_cwe = normalize_cwe(task_cwe)
        self._turn = 0

    def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
        self._turn += 1
        if self._turn == 1:
            return '<tool_call> {"name": "terminal", "arguments": {"command": "find . -type f"}} </tool_call>'
        if self._turn == 2:
            return '<tool_call> {"name": "terminal", "arguments": {"command": "grep -R -l -E \\"execute|SELECT|password|secret|\\.\\./\\" . || true"}} </tool_call>'

        ranked = self._scripted_rank()
        if ranked:
            import json

            payload = json.dumps({"name": "submit_vulnerable_files", "arguments": {"ranked_files": ranked}})
            return f"<tool_call> {payload} </tool_call>"
        return '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} </tool_call>'

    def _scripted_rank(self) -> list[str]:
        patterns: dict[str, list[str]] = {
            "CWE-89": [r"execute\s*\(", r"SELECT\s+.+\+", r"f\"SELECT", r"format\s*\(\s*[\"']SELECT"],
            "CWE-798": [r"password\s*=\s*[\"']", r"api_key\s*=\s*[\"']", r"secret\s*=\s*[\"']"],
            "CWE-22": [r"\.\./", r"os\.path\.join\s*\(\s*[^,]+,\s*user"],
            "CWE-78": [r"os\.system\s*\(", r"subprocess\.(run|call|Popen).*shell\s*=\s*True"],
        }
        import re

        selected = patterns.get(self._task_cwe, [])
        if not selected:
            return []

        ranked: list[str] = []
        for path in sorted(self._sandbox.root.rglob("*")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = path.relative_to(self._sandbox.root).as_posix()
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in selected):
                ranked.append(rel)
        return ranked


def run_agent_query(
    *,
    sandbox_root: Path,
    task_cwe: str,
    task_cwe_description: str | None,
    changed_paths: list[str],
    generator: TextGenerator,
    max_terminal_calls: int | None = None,
    max_terminal_attempts: int = DEFAULT_MAX_TERMINAL_ATTEMPTS,
    temperature: float | None = None,
    top_p: float | None = None,
    investigation_id: str | None = None,
    audit_sink: SandboxAuditSink | None = None,
    adapter: ModelAdapter | None = None,
    loop_control_enabled: bool | None = None,
    max_wall_clock_seconds: float | None = None,
) -> AgentQueryResult:
    active_adapter = adapter or default_adapter()
    terminal_budget = (
        active_adapter.terminal_budget if max_terminal_calls is None else max_terminal_calls
    )
    generation_params = active_adapter.generation_params()
    generation_temperature = (
        float(generation_params["temperature"]) if temperature is None else temperature
    )
    generation_top_p = float(generation_params["top_p"]) if top_p is None else top_p
    control_enabled = (
        _env_flag("ANTARES_LOOP_CONTROL", True)
        if loop_control_enabled is None
        else loop_control_enabled
    )
    normalized_cwe = normalize_cwe(task_cwe)
    description = task_cwe_description or default_cwe_description(normalized_cwe)
    inv_id = investigation_id or new_investigation_id()
    audit = audit_sink if audit_sink is not None else CollectedAuditSink()

    snapshot_paths = {
        path.relative_to(sandbox_root).as_posix()
        for path in sandbox_root.rglob("*")
        if path.is_file()
    }

    changed_paths_label = ", ".join(changed_paths) if changed_paths else "(all snapshot files)"
    messages: list[dict[str, object]] = build_initial_messages(
        model_name=active_adapter.identity.name,
        max_calls=terminal_budget,
        task_cwe=normalized_cwe,
        task_cwe_description=description,
        repo_root=str(sandbox_root),
        changed_paths=changed_paths_label,
    )
    trace_parts: list[str] = []
    terminal_calls = 0
    duplicate_commands_suppressed = 0
    command_history: dict[str, tuple[int, int, str]] = {}
    loop_control = LoopControlState(
        enabled=control_enabled,
        terminal_budget=terminal_budget,
        adapter_identity=active_adapter.identity.to_dict(),
        generation_params=dict(generation_params),
    )
    budget_warning_threshold = budget_escalation_threshold(terminal_budget)
    wall_clock_limit = (
        max_wall_clock_seconds
        if max_wall_clock_seconds is not None
        else float(
            os.environ.get(
                "ANTARES_INVESTIGATION_WALL_CLOCK_SECONDS",
                str(DEFAULT_INVESTIGATION_WALL_CLOCK_SECONDS),
            )
        )
    )
    # Allow submission turns after loop-control termination signals.
    max_loop_iterations = max_terminal_attempts + terminal_budget + 5
    investigation_started = time.monotonic()

    from antares_server.cancellation_registry import is_cancelled, register, unregister

    cancel_event = register(inv_id)
    try:
        with open_investigation_sandbox(sandbox_root, investigation_id=inv_id, audit_sink=audit) as sandbox:
            for _turn in range(max_loop_iterations):
                if time.monotonic() - investigation_started >= wall_clock_limit:
                    return _terminal_limit_result(
                        normalized_cwe,
                        trace_parts,
                        terminal_calls,
                        inv_id,
                        audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        reason="wall_clock_exceeded",
                        message=(
                            f"Exceeded investigation wall-clock limit ({wall_clock_limit:.0f}s)"
                        ),
                    )
                if cancel_event.is_set() or is_cancelled(inv_id):
                    from antares_server.docker_sandbox import destroy_investigation_container

                    destroy_investigation_container(inv_id)
                    sandbox.close()
                    return _agent_result(
                        normalized_cwe,
                        QUERY_FAILED,
                        trace_parts,
                        terminal_calls,
                        inv_id,
                        audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        failure_class="cancelled",
                        failure_message="investigation cancelled",
                    )
                prompt = active_adapter.render_prompt(messages, active_adapter.tools)
                raw = generator.generate(
                    prompt,
                    temperature=generation_temperature,
                    top_p=generation_top_p,
                )
                trace_parts.append(f"Assistant:\n{raw}")

                if control_enabled and detect_degenerate_repetition(raw):
                    degenerate_result = _handle_degenerate_repetition(
                        normalized_cwe,
                        raw=raw,
                        trace_parts=trace_parts,
                        messages=messages,
                        terminal_calls=terminal_calls,
                        inv_id=inv_id,
                        audit=audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        max_terminal_attempts=max_terminal_attempts,
                        max_terminal_calls=terminal_budget,
                    )
                    if degenerate_result is not None:
                        return degenerate_result
                    continue

                action, submission_salvaged = active_adapter.parse_action(raw)
                if action is None:
                    loop_control.consecutive_unparseable_generations += 1
                    if control_enabled and (
                        loop_control.consecutive_unparseable_generations
                        >= CONSECUTIVE_UNPARSEABLE_HARD_STOP_THRESHOLD
                    ):
                        return _harness_failure_result(
                            normalized_cwe,
                            trace_parts,
                            terminal_calls,
                            inv_id,
                            audit,
                            loop_control=loop_control,
                            duplicate_commands_suppressed=duplicate_commands_suppressed,
                            failure_class="unparseable_submission_loop",
                            message=(
                                "Investigation terminated after consecutive unparseable generations"
                            ),
                        )
                    messages.append(build_assistant_parse_failure_message(raw))
                    continue

                loop_control.consecutive_unparseable_generations = 0
                loop_control.consecutive_degenerate_rejections = 0
                messages.append(build_assistant_tool_message(action))

                if loop_control.forced_submission_mode:
                    forced_result = _process_forced_submission_action(
                        normalized_cwe,
                        action,
                        trace_parts=trace_parts,
                        messages=messages,
                        terminal_calls=terminal_calls,
                        inv_id=inv_id,
                        audit=audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        changed_paths=changed_paths,
                        snapshot_paths=snapshot_paths,
                        submission_salvaged=submission_salvaged,
                    )
                    if forced_result is not None:
                        return forced_result
                    continue

                if isinstance(action, TerminalToolCall):
                    if loop_control.total_terminal_attempts >= max_terminal_attempts:
                        loop_control.attempt_cap_reached = True
                        return _terminal_limit_result(
                            normalized_cwe,
                            trace_parts,
                            terminal_calls,
                            inv_id,
                            audit,
                            loop_control=loop_control,
                            duplicate_commands_suppressed=duplicate_commands_suppressed,
                            reason="attempt_cap_exceeded",
                            message=(
                                f"Exceeded max terminal attempts ({max_terminal_attempts}) "
                                "including duplicate suppressions"
                            ),
                        )

                    prior = command_history.get(action.command) if control_enabled else None
                    if prior is not None:
                        prior_turn, exit_code, output = prior
                        duplicate_commands_suppressed += 1
                        loop_control.total_terminal_attempts += 1
                        loop_control.consecutive_duplicate_suppressions += 1
                        duplicate_output = (
                            f"{duplicate_command_notice(prior_turn=prior_turn)}\n"
                            f"exit={exit_code}\n{output}"
                        )
                        audit.record(
                            SandboxCommandAudit(
                                investigation_id=inv_id,
                                command=action.command,
                                exit_code=exit_code,
                                output_truncated=duplicate_output,
                                truncated=False,
                                recorded_at=audit_timestamp(),
                                charged=False,
                                duplicate_of_turn=prior_turn,
                            )
                        )
                        tool_response = format_duplicate_tool_response_trace(
                            prior_turn=prior_turn,
                            exit_code=exit_code,
                            output=output,
                        )
                        trace_parts.append(tool_response)
                        messages.append(
                            build_duplicate_tool_message(
                                prior_turn=prior_turn,
                                exit_code=exit_code,
                                output=output,
                            )
                        )
                        if (
                            loop_control.consecutive_duplicate_suppressions
                            >= CONSECUTIVE_DUPLICATE_HARD_STOP_THRESHOLD
                            and not loop_control.duplicate_loop_hard_stop_fired
                        ):
                            _begin_forced_submission(
                                loop_control,
                                trace_parts=trace_parts,
                                messages=messages,
                            )
                            continue
                        if loop_control.total_terminal_attempts >= max_terminal_attempts:
                            loop_control.attempt_cap_reached = True
                            return _terminal_limit_result(
                                normalized_cwe,
                                trace_parts,
                                terminal_calls,
                                inv_id,
                                audit,
                                loop_control=loop_control,
                                duplicate_commands_suppressed=duplicate_commands_suppressed,
                                reason="attempt_cap_exceeded",
                                message=(
                                    f"Exceeded max terminal attempts ({max_terminal_attempts}) "
                                    "including duplicate suppressions"
                                ),
                            )
                        continue

                    if terminal_calls >= terminal_budget:
                        return _terminal_limit_result(
                            normalized_cwe,
                            trace_parts,
                            terminal_calls,
                            inv_id,
                            audit,
                            loop_control=loop_control,
                            duplicate_commands_suppressed=duplicate_commands_suppressed,
                            reason="budget_exhausted",
                            message=f"Exceeded max terminal calls ({terminal_budget})",
                        )

                    terminal_calls += 1
                    loop_control.total_terminal_attempts += 1
                    loop_control.consecutive_duplicate_suppressions = 0
                    result = sandbox.execute(action.command)
                    command_history[action.command] = (
                        terminal_calls,
                        result.exit_code,
                        result.output,
                    )
                    if result.exit_code == 0:
                        loop_control.inspected_files.update(
                            inspected_paths_from_command(
                                action.command,
                                snapshot_paths,
                            )
                        )
                        record_search_hits_from_command(
                            command=action.command,
                            exit_code=result.exit_code,
                            output=result.output,
                            snapshot_paths=snapshot_paths,
                            search_hit_files=loop_control.search_hit_files,
                        )
                    output = result.output
                    if control_enabled and terminal_calls >= budget_warning_threshold:
                        loop_control.budget_escalation_fired = True
                        output = append_harness_notice(output, BUDGET_ESCALATION_NOTICE)
                        output = with_unread_search_hit_pressure(output, loop_control)
                    tool_response = format_tool_response_trace(
                        exit_code=result.exit_code,
                        output=output,
                    )
                    if control_enabled and terminal_calls >= budget_warning_threshold:
                        tool_response = (
                            "[loop-control: budget-escalation]\n" + tool_response
                        )
                    trace_parts.append(tool_response)
                    messages.append(
                        build_tool_message(exit_code=result.exit_code, output=output)
                    )
                    continue

                if isinstance(action, SubmitNoVulnerabilityFound):
                    return _agent_result(
                        normalized_cwe,
                        QUERY_COMPLETED_NO_FILES,
                        trace_parts,
                        terminal_calls,
                        inv_id,
                        audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        submission_salvaged=submission_salvaged,
                    )

                if isinstance(action, SubmitVulnerableFiles):
                    ranked = filter_ranked_files(
                        action.ranked_files,
                        changed_paths=changed_paths,
                        snapshot_paths=snapshot_paths,
                    )
                    outcome = QUERY_COMPLETED_WITH_FILES if ranked else QUERY_COMPLETED_NO_FILES
                    return _agent_result(
                        normalized_cwe,
                        outcome,
                        trace_parts,
                        terminal_calls,
                        inv_id,
                        audit,
                        loop_control=loop_control,
                        duplicate_commands_suppressed=duplicate_commands_suppressed,
                        ranked_files=ranked,
                        submission_salvaged=submission_salvaged,
                    )
    finally:
        unregister(inv_id)

    return _terminal_limit_result(
        normalized_cwe,
        trace_parts,
        terminal_calls,
        inv_id,
        audit,
        loop_control=loop_control,
        duplicate_commands_suppressed=duplicate_commands_suppressed,
        reason="no_submission",
        message="Agent loop ended without a submission",
    )


def _begin_forced_submission(
    loop_control: LoopControlState,
    *,
    trace_parts: list[str],
    messages: list[dict[str, object]],
) -> None:
    loop_control.duplicate_loop_hard_stop_fired = True
    loop_control.forced_submission_mode = True
    loop_control.forced_submission_generations = 0
    forced_output = with_unread_search_hit_pressure(
        DUPLICATE_LOOP_FORCED_SUBMISSION_NOTICE,
        loop_control,
    )
    forced_response = format_harness_notice_tool_response_trace(
        marker="[loop-control: forced-submission]",
        exit_code=0,
        output=forced_output,
    )
    trace_parts.append(forced_response)
    messages.append(
        build_harness_notice_tool_message(
            exit_code=0,
            output=forced_output,
        )
    )


def _process_forced_submission_action(
    task_cwe: str,
    action: TerminalToolCall | SubmitVulnerableFiles | SubmitNoVulnerabilityFound,
    *,
    trace_parts: list[str],
    messages: list[dict[str, object]],
    terminal_calls: int,
    inv_id: str,
    audit: SandboxAuditSink,
    loop_control: LoopControlState,
    duplicate_commands_suppressed: int,
    changed_paths: list[str],
    snapshot_paths: set[str],
    submission_salvaged: bool,
) -> AgentQueryResult | None:
    loop_control.forced_submission_generations += 1
    if loop_control.forced_submission_generations > MAX_FORCED_SUBMISSION_GENERATIONS:
        return _duplicate_loop_result(
            task_cwe,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            forced_submission_failed=True,
        )

    if isinstance(action, TerminalToolCall):
        rejected_output = with_unread_search_hit_pressure(
            FORCED_SUBMISSION_TERMINAL_REJECTED_NOTICE,
            loop_control,
        )
        trace_parts.append(
            format_harness_notice_tool_response_trace(
                marker="[loop-control: terminal-rejected]",
                exit_code=1,
                output=rejected_output,
            )
        )
        messages.append(
            build_harness_notice_tool_message(
                exit_code=1,
                output=rejected_output,
            )
        )
        return None

    if isinstance(action, SubmitNoVulnerabilityFound):
        return _agent_result(
            task_cwe,
            QUERY_COMPLETED_NO_FILES,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            forced_submission=True,
            submission_salvaged=submission_salvaged,
        )

    if isinstance(action, SubmitVulnerableFiles):
        ranked = filter_ranked_files(
            action.ranked_files,
            changed_paths=changed_paths,
            snapshot_paths=snapshot_paths,
        )
        outcome = QUERY_COMPLETED_WITH_FILES if ranked else QUERY_COMPLETED_NO_FILES
        return _agent_result(
            task_cwe,
            outcome,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            ranked_files=ranked,
            forced_submission=True,
            submission_salvaged=submission_salvaged,
        )
    return None


def _harness_failure_result(
    task_cwe: str,
    trace_parts: list[str],
    terminal_calls: int,
    investigation_id: str,
    audit: SandboxAuditSink,
    *,
    loop_control: LoopControlState,
    duplicate_commands_suppressed: int,
    failure_class: str,
    message: str,
) -> AgentQueryResult:
    trace_parts.append(f"[loop-control: {failure_class}]")
    return _agent_result(
        task_cwe,
        QUERY_FAILED,
        trace_parts,
        terminal_calls,
        investigation_id,
        audit,
        loop_control=loop_control,
        duplicate_commands_suppressed=duplicate_commands_suppressed,
        failure_class=failure_class,
        failure_message=message,
    )


def _handle_degenerate_repetition(
    task_cwe: str,
    *,
    raw: str,
    trace_parts: list[str],
    messages: list[dict[str, object]],
    terminal_calls: int,
    inv_id: str,
    audit: SandboxAuditSink,
    loop_control: LoopControlState,
    duplicate_commands_suppressed: int,
    max_terminal_attempts: int,
    max_terminal_calls: int,
) -> AgentQueryResult | None:
    loop_control.degenerate_repetition_rejections += 1
    loop_control.consecutive_degenerate_rejections += 1
    loop_control.total_terminal_attempts += 1
    audit.record(
        SandboxCommandAudit(
            investigation_id=inv_id,
            command=raw[:500],
            exit_code=1,
            output_truncated="degenerate repetition rejected",
            truncated=len(raw) > 500,
            recorded_at=audit_timestamp(),
            charged=False,
        )
    )
    trace_parts.append(format_malformed_tool_response_trace())
    messages.append(build_malformed_tool_message())

    if (
        loop_control.consecutive_degenerate_rejections
        >= CONSECUTIVE_DEGENERATE_HARD_STOP_THRESHOLD
    ):
        return _harness_failure_result(
            task_cwe,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            failure_class="degenerate_repetition",
            message=(
                "Investigation terminated after consecutive degenerate-repetition rejections"
            ),
        )

    if loop_control.total_terminal_attempts >= max_terminal_attempts:
        loop_control.attempt_cap_reached = True
        return _terminal_limit_result(
            task_cwe,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            reason="attempt_cap_exceeded",
            message=(
                f"Exceeded max terminal attempts ({max_terminal_attempts}) "
                "including duplicate suppressions"
            ),
        )

    if terminal_calls >= max_terminal_calls:
        return _terminal_limit_result(
            task_cwe,
            trace_parts,
            terminal_calls,
            inv_id,
            audit,
            loop_control=loop_control,
            duplicate_commands_suppressed=duplicate_commands_suppressed,
            reason="budget_exhausted",
            message=f"Exceeded max terminal calls ({max_terminal_calls})",
        )

    return None


def _duplicate_loop_result(
    task_cwe: str,
    trace_parts: list[str],
    terminal_calls: int,
    investigation_id: str,
    audit: SandboxAuditSink,
    *,
    loop_control: LoopControlState,
    duplicate_commands_suppressed: int,
    forced_submission_failed: bool = False,
) -> AgentQueryResult:
    loop_control.duplicate_loop_hard_stop_fired = True
    loop_control.forced_submission_mode = False
    trace_parts.append("[loop-control: consecutive-duplicate-hard-stop]")
    if forced_submission_failed:
        outcome = QUERY_FAILED
        failure_class = "duplicate_loop_search_unread"
        message = (
            "Investigation terminated after forced submission turn without a submit call"
        )
    else:
        outcome, failure_class, message = classify_duplicate_loop_failure(
            loop_control,
            failed_outcome=QUERY_FAILED,
            failed_unsubmitted_outcome=QUERY_FAILED_UNSUBMITTED,
        )
    return _agent_result(
        task_cwe,
        outcome,
        trace_parts,
        terminal_calls,
        investigation_id,
        audit,
        loop_control=loop_control,
        duplicate_commands_suppressed=duplicate_commands_suppressed,
        failure_class=failure_class,
        failure_message=message,
    )


def _terminal_limit_result(
    task_cwe: str,
    trace_parts: list[str],
    terminal_calls: int,
    investigation_id: str,
    audit: SandboxAuditSink,
    *,
    loop_control: LoopControlState,
    duplicate_commands_suppressed: int,
    reason: str,
    message: str,
) -> AgentQueryResult:
    if loop_control.inspected_files:
        outcome = QUERY_FAILED_UNSUBMITTED
        failure_class = f"{reason}_unsubmitted"
    else:
        outcome = QUERY_FAILED
        failure_class = reason
    return _agent_result(
        task_cwe,
        outcome,
        trace_parts,
        terminal_calls,
        investigation_id,
        audit,
        loop_control=loop_control,
        duplicate_commands_suppressed=duplicate_commands_suppressed,
        failure_class=failure_class,
        failure_message=message,
    )


def _agent_result(
    task_cwe: str,
    outcome: str,
    trace_parts: list[str],
    terminal_calls: int,
    investigation_id: str,
    audit: SandboxAuditSink,
    *,
    loop_control: LoopControlState | None = None,
    duplicate_commands_suppressed: int = 0,
    ranked_files: list[str] | None = None,
    failure_class: str | None = None,
    failure_message: str | None = None,
    forced_submission: bool = False,
    submission_salvaged: bool = False,
) -> AgentQueryResult:
    audit_payload = audit_payload_from_sink(audit)
    control = loop_control or LoopControlState()
    return AgentQueryResult(
        task_cwe=task_cwe,
        outcome=outcome,
        ranked_files=ranked_files or [],
        exploration_trace="\n\n".join(trace_parts),
        terminal_calls_used=terminal_calls,
        total_terminal_attempts=control.total_terminal_attempts,
        duplicate_commands_suppressed=duplicate_commands_suppressed,
        degenerate_repetition_rejections=control.degenerate_repetition_rejections,
        duplicate_loop_hard_stop_fired=control.duplicate_loop_hard_stop_fired,
        forced_submission=forced_submission,
        submission_salvaged=submission_salvaged,
        budget_escalation_fired=control.budget_escalation_fired,
        attempt_cap_reached=control.attempt_cap_reached,
        inspected_files=sorted(control.inspected_files),
        search_hit_files=sorted(control.search_hit_files),
        failure_class=failure_class,
        failure_message=failure_message,
        investigation_id=investigation_id,
        sandbox_audit=audit_payload,
        terminal_budget=control.terminal_budget,
        loop_control_enabled=control.enabled,
        adapter_identity=dict(control.adapter_identity),
        generation_params=dict(control.generation_params),
    )


def build_generator(
    *,
    engine: Any,
    sandbox_root: Path,
    task_cwe: str,
    engine_mode: str,
    generation_params: dict[str, Any] | None = None,
) -> TextGenerator:
    if engine_mode == "scripted":
        return ScriptedTextGenerator(
            ReadOnlySandbox(sandbox_root, investigation_id=new_investigation_id()),
            task_cwe=task_cwe,
        )

    class EngineGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            return engine.generate_agent(
                prompt,
                temperature=temperature,
                top_p=top_p,
                max_new_tokens=int((generation_params or {}).get("max_new_tokens", 2048)),
            )

    return EngineGenerator()


def engine_mode_from_env() -> str:
    mode = os.environ.get("ANTARES_ENGINE", "llm").strip().lower()
    return mode if mode in {"llm", "scripted"} else "llm"
