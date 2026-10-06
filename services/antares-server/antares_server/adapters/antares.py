"""Adapter for the shipped local security model."""

from __future__ import annotations

from typing import Any

from antares_server.adapters.base import AdapterIdentity
from antares_server.agent_tools import AgentAction, parse_agent_action_with_salvage
from antares_server.chat_prompt import ANTARES_TOOLS, ChatPromptRenderer, chat_template_path


class AntaresAdapter:
    """Prompt, action, and generation policy for Antares."""

    def __init__(self, renderer: ChatPromptRenderer | None = None) -> None:
        self._renderer = renderer or ChatPromptRenderer.from_env()

    @property
    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            name="Antares",
            quant="bf16",
            params="1B",
            template_source=str(chat_template_path()),
        )

    @property
    def terminal_budget(self) -> int:
        return 15

    @property
    def tools(self) -> list[dict[str, Any]]:
        return ANTARES_TOOLS

    def render_prompt(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> str:
        return self._renderer.render(messages, tools=tools)

    def parse_action(self, raw: str) -> tuple[AgentAction | None, bool]:
        return parse_agent_action_with_salvage(raw)

    def generation_params(self) -> dict[str, Any]:
        from antares_server.inference import agent_max_new_tokens

        return {
            "temperature": 0.3,
            "top_p": 1.0,
            "max_new_tokens": agent_max_new_tokens(),
        }


def default_adapter(
    renderer: ChatPromptRenderer | None = None,
) -> AntaresAdapter:
    return AntaresAdapter(renderer)
