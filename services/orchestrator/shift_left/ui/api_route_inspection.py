"""Verify API route classification against response-model field inspection."""

from __future__ import annotations

import inspect
import types
from dataclasses import dataclass
from typing import Any, Union, get_args, get_origin

from fastapi.routing import APIRoute
from pydantic import BaseModel

from shift_left.models.schema import (
    ApprovalRecord,
    AuditEvent,
    Finding,
    LocalizationResult,
    ReviewResult,
    ReviewSummary,
)
from shift_left.ui.api_presentation import API_CONFIG_TEXT_REQUEST_SURFACES

_CONFIG_TEXT_MODELS: frozenset[type[BaseModel]] = frozenset(
    {
        Finding,
        ReviewResult,
        ReviewSummary,
        LocalizationResult,
        ApprovalRecord,
        AuditEvent,
    }
)

_CONFIG_TEXT_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "evidence",
        "description",
        "model_context",
        "exploration_trace",
        "summary_text",
        "output_text",
        "content",
        "text",
        "hunks",
        "file_views",
        "findings",
        "findings_snapshot",
        "model_only_findings",
        "details",
        "analysis",
    }
)


@dataclass(frozen=True)
class ConfigTextExposure:
    """A response field path that may carry config-derived text."""

    field_path: str
    model: str
    field_name: str


def _normalize_type(annotation: Any) -> Any:
    if annotation is inspect.Parameter.empty:
        return Any
    if isinstance(annotation, str):
        return Any
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        args = [item for item in get_args(annotation) if item is not type(None)]
        return args[0] if len(args) == 1 else annotation
    return annotation


def _model_label(model: type[BaseModel]) -> str:
    return f"{model.__module__}.{model.__name__}"


def _walk_model(
    model: type[BaseModel],
    *,
    prefix: str = "",
    seen: set[type[BaseModel]] | None = None,
) -> list[ConfigTextExposure]:
    if seen is None:
        seen = set()
    if model in seen:
        return []
    seen.add(model)
    exposures: list[ConfigTextExposure] = []
    for field_name, field_info in model.model_fields.items():
        path = f"{prefix}.{field_name}" if prefix else field_name
        annotation = _normalize_type(field_info.annotation)
        origin = get_origin(annotation)
        if origin in (list, tuple, set, frozenset):
            args = get_args(annotation)
            inner = args[0] if args else Any
            inner = _normalize_type(inner)
            if isinstance(inner, type) and issubclass(inner, BaseModel):
                exposures.extend(_walk_model(inner, prefix=f"{path}[]", seen=seen))
                continue
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            exposures.extend(_walk_model(annotation, prefix=path, seen=seen))
            continue
        if field_name in _CONFIG_TEXT_FIELD_NAMES or (
            isinstance(annotation, type) and annotation in _CONFIG_TEXT_MODELS
        ):
            exposures.append(
                ConfigTextExposure(
                    field_path=path,
                    model=_model_label(model),
                    field_name=field_name,
                )
            )
    return exposures


def inspect_route_return_type(route: APIRoute) -> list[ConfigTextExposure]:
    """Inspect a FastAPI route's declared return annotation for config-text fields."""
    endpoint = route.endpoint
    signature = inspect.signature(endpoint)
    return_annotation = signature.return_annotation
    if return_annotation is inspect.Signature.empty:
        return_annotation = route.response_model
    if return_annotation is inspect.Signature.empty or return_annotation is None:
        return []

    annotation = _normalize_type(return_annotation)
    exposures: list[ConfigTextExposure] = []
    origin = get_origin(annotation)
    if origin is dict:
        return [
            ConfigTextExposure(
                field_path="<dict>",
                model="builtins.dict",
                field_name="*",
            )
        ]
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        exposures.extend(_walk_model(annotation))
    return exposures


_REQUEST_CONFIG_TEXT_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "command",
        "output_truncated",
        "evidence",
        "description",
        "model_context",
        "exploration_trace",
        "summary_text",
        "output_text",
        "content",
        "text",
        "hunks",
        "file_views",
        "findings",
        "findings_snapshot",
        "model_only_findings",
        "details",
        "analysis",
    }
)


def inspect_route_request_body(route: APIRoute) -> list[ConfigTextExposure]:
    """Inspect a FastAPI route's request body model for config-text fields."""
    endpoint = route.endpoint
    signature = inspect.signature(endpoint)
    exposures: list[ConfigTextExposure] = []
    for param in signature.parameters.values():
        annotation = _normalize_type(param.annotation)
        if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
            continue
        for field_name in annotation.model_fields:
            if field_name not in _REQUEST_CONFIG_TEXT_FIELD_NAMES:
                continue
            exposures.append(
                ConfigTextExposure(
                    field_path=field_name,
                    model=_model_label(annotation),
                    field_name=field_name,
                )
            )
    return exposures


def verify_request_config_text_surfaces(
    app_routes: list[APIRoute],
    request_surfaces: frozenset[tuple[str, str]],
) -> list[str]:
    """Fail when a route with config-text request fields is not registered."""
    violations: list[str] = []
    registered = {
        (item.method, item.path): item
        for item in API_CONFIG_TEXT_REQUEST_SURFACES
    }
    for route in app_routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path.startswith("/ui"):
            continue
        for method in sorted(route.methods - {"HEAD"}):
            key = (method, route.path)
            exposures = inspect_route_request_body(route)
            if not exposures:
                continue
            if key not in request_surfaces:
                fields = ", ".join(sorted({item.field_path for item in exposures}))
                violations.append(
                    f"{method} {route.path} accepts config-text request fields ({fields}) "
                    "but is not listed in API_CONFIG_TEXT_REQUEST_SURFACES"
                )
                continue
            declared = registered.get(key)
            if declared is None:
                continue
            declared_fields = set(declared.field_paths)
            actual_fields = {item.field_path for item in exposures}
            missing = actual_fields - declared_fields
            if missing:
                violations.append(
                    f"{method} {route.path} missing request field_paths in registry: "
                    f"{', '.join(sorted(missing))}"
                )
    return violations


def verify_clean_routes(
    app_routes: list[APIRoute],
    clean_routes: frozenset[tuple[str, str]],
) -> list[str]:
    """Fail when a route classified as clean exposes config-text response fields."""
    violations: list[str] = []
    for route in app_routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path.startswith("/ui"):
            continue
        for method in sorted(route.methods - {"HEAD"}):
            key = (method, route.path)
            if key not in clean_routes:
                continue
            exposures = inspect_route_return_type(route)
            if exposures:
                fields = ", ".join(sorted({item.field_path for item in exposures}))
                violations.append(f"{method} {route.path} exposes config-text fields: {fields}")
    return violations
