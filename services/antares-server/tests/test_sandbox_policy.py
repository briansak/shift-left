"""Unit tests for read-only sandbox command validation."""

from __future__ import annotations

from antares_server.sandbox_policy import validate_command


def test_rg_regex_alternation_inside_quotes_is_not_a_pipe_chain() -> None:
    result = validate_command('rg -n "execute\\.|execute_query\\.|raw\\(" .')
    assert result.ok is True
    assert result.argv_command is not None
    assert result.argv_command[0] == "rg"


def test_grep_regex_alternation_with_or_true_chain() -> None:
    result = validate_command(
        'grep -RIn "execute\\.|execute_query\\.|raw\\(" --exclude-dir=.git || true'
    )
    assert result.ok is True
    assert result.shell_command


def test_protocol_rg_pipe_head_with_quoted_regex_alternation() -> None:
    result = validate_command(
        'rg -n "raw\\.query|raw\\.execute|\\.execute\\(" . | head -n 200'
    )
    assert result.ok is True
    assert result.shell_command


def test_find_pipe_head_still_allowed() -> None:
    result = validate_command("find . -maxdepth 2 | head -n 200")
    assert result.ok is True
    assert result.shell_command


def test_redirect_outside_quotes_blocked() -> None:
    result = validate_command("cat foo > bar")
    assert result.ok is False
    assert "blocked by sandbox policy" in result.error


def test_pipe_inside_quotes_does_not_create_empty_chain_segment() -> None:
    result = validate_command('rg -n "a|b|c" .')
    assert result.ok is True


def test_and_chain_allowed() -> None:
    result = validate_command("false && echo ok")
    assert result.ok is True
    assert result.shell_command


def test_semicolon_chain_allowed() -> None:
    result = validate_command("pwd; ls")
    assert result.ok is True
    assert result.shell_command


def test_disallowed_command_in_chain_rejected() -> None:
    result = validate_command("ls | curl example.com")
    assert result.ok is False
