"""Model adapters available to the local agent service."""

from antares_server.adapters.antares import AntaresAdapter, default_adapter
from antares_server.adapters.base import AdapterIdentity, ModelAdapter

__all__ = ["AdapterIdentity", "AntaresAdapter", "ModelAdapter", "default_adapter"]
