"""Model adapter contracts for agent-loop prompt and action protocols."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol

from antares_server.agent_tools import AgentAction


@dataclass(frozen=True)
class AdapterIdentity:
    """Serializable metadata describing the active model protocol."""

    name: str
    quant: str
    params: str
    template_source: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ModelAdapter(Protocol):
    """Boundary between the generic agent loop and a model's wire protocol."""

    @property
    def identity(self) -> AdapterIdentity: ...

    @property
    def terminal_budget(self) -> int: ...

    @property
    def tools(self) -> list[dict[str, Any]]: ...

    def render_prompt(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> str: ...

    def parse_action(self, raw: str) -> tuple[AgentAction | None, bool]: ...

    def generation_params(self) -> dict[str, Any]: ...
