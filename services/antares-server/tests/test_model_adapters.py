"""Model adapter contract and isolation tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from antares_server.adapters import default_adapter


class _Tokenizer:
    def apply_chat_template(self, messages: list[dict[str, Any]], **kwargs: Any) -> str:
        return json.dumps({"messages": messages, "tools": kwargs["tools"]})


def test_adapter_metadata_and_defaults_are_serializable(monkeypatch) -> None:
    from antares_server.chat_prompt import ChatPromptRenderer, load_chat_template_source

    monkeypatch.setenv("ANTARES_AGENT_MAX_NEW_TOKENS", "2048")
    renderer = ChatPromptRenderer(
        _Tokenizer(),
        model_path=Path("/tmp/model"),
        chat_template=load_chat_template_source(),
    )
    adapter = default_adapter(renderer)

    assert adapter.terminal_budget == 15
    assert adapter.generation_params() == {
        "temperature": 0.3,
        "top_p": 1.0,
        "max_new_tokens": 2048,
    }
    assert json.loads(json.dumps(adapter.identity.to_dict()))["name"] == "Antares"
    assert "terminal" in adapter.render_prompt([], adapter.tools)


def test_concrete_adapter_class_is_confined_to_adapters_package() -> None:
    repo_root = Path(__file__).parents[3]
    class_name = "Antares" + "Adapter"
    checked = list((repo_root / "services" / "antares-server").rglob("*.py"))
    checked.extend(
        [
            repo_root / "validation" / "antares_localization_multidefect.py",
            repo_root / "validation" / "antares_localization_realistic.py",
        ]
    )
    offenders = [
        path.relative_to(repo_root).as_posix()
        for path in checked
        if "adapters" not in path.parts
        and ".venv" not in path.parts
        and class_name in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
