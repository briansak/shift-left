"""Post-inference handler matching failures are not inference errors."""

from __future__ import annotations

import logging

from foundation_sec_server.analyzer import ConfigAnalyzer
from foundation_sec_server.engine import ScriptedEvalEngine


DEVICE_FILE = {
    "path": "firewall/rules.conf",
    "hunks": [
        {
            "new_start": 1,
            "content": "access-list OUT extended permit ip any any",
        }
    ],
}


def test_post_inference_handler_exception_is_handler_error(monkeypatch, caplog) -> None:
    def boom(**_kwargs):
        raise TypeError(
            "match_nx_os_config_rules() missing 1 required keyword-only argument: 'rule_id'"
        )

    monkeypatch.setattr("foundation_sec_server.analyzer.match_handler_cwes", boom)
    analyzer = ConfigAnalyzer(ScriptedEvalEngine())
    with caplog.at_level(logging.ERROR, logger="foundation_sec_server.analyzer"):
        result = analyzer.analyze_files([DEVICE_FILE])

    assert result["outcome"] == "failed"
    assert result["failure_class"] == "handler_error"
    assert result["failure_stage"] == "handler_match"
    assert result["failure_class"] != "inference_error"
    assert result["failure_stage"] != "generation"
    assert "rule_id" in str(result["failure_message"])
    assert result["findings"] == []
    assert any("Post-inference handler matching failed" in rec.message for rec in caplog.records)
    assert any(rec.exc_info for rec in caplog.records)


def test_inference_chunk_exception_stays_chunk_error(monkeypatch) -> None:
    def boom(self, **_kwargs):
        raise RuntimeError("llama exploded")

    monkeypatch.setattr(ScriptedEvalEngine, "evaluate_chunk", boom)
    analyzer = ConfigAnalyzer(ScriptedEvalEngine())
    result = analyzer.analyze_files([DEVICE_FILE])
    assert result["failure_class"] == "chunk_error"
    assert result["failure_stage"] == "chunk"
    assert result["failure_class"] != "handler_error"
    assert result["failure_class"] != "inference_error"
