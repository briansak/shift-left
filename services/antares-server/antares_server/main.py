"""Antares local inference HTTP API."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from antares_server.agent_engine import AgentQueryEngine
from antares_server.inference import AntaresEngine, build_engine_from_env

try:
    from shift_left_shared.runtime import assert_no_remote_inference_fallback
    from shift_left_shared.server import startup_model_server
except ImportError:
    def assert_no_remote_inference_fallback(env: dict[str, str]) -> None:
        blocked = [
            k for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTARES_REMOTE_API") if env.get(k)
        ]
        if blocked:
            raise RuntimeError(f"Hosted inference env vars not allowed: {', '.join(blocked)}")

    def startup_model_server(env: dict[str, str], *, service_name: str, bind_env_key: str) -> str:
        assert_no_remote_inference_fallback(env)
        return env.get(bind_env_key, "127.0.0.1")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

BIND_HOST = startup_model_server(
    os.environ,
    service_name="antares-server",
    bind_env_key="ANTARES_BIND_HOST",
)


class HunkInput(BaseModel):
    new_start: int
    new_end: int
    content: str


class FileInput(BaseModel):
    path: str
    hunks: list[HunkInput] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    repo: str
    pr_ref: str
    commit_sha: str
    files: list[FileInput] = Field(default_factory=list)


class SnapshotFileInput(BaseModel):
    path: str
    content: str


class CweQueryInput(BaseModel):
    task_cwe: str
    task_cwe_description: str = ""


class QueryRequest(BaseModel):
    repo: str
    pr_ref: str
    commit_sha: str
    snapshot_files: list[SnapshotFileInput] = Field(default_factory=list)
    changed_paths: list[str] = Field(default_factory=list)
    queries: list[CweQueryInput] = Field(default_factory=list)
    max_terminal_calls: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    loop_control_enabled: bool | None = None
    max_snapshot_bytes: int = 2_000_000


class TriageRunRequest(BaseModel):
    repo: str
    ref: str
    repo_root: str
    queries: list[CweQueryInput]
    max_terminal_calls: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    loop_control_enabled: bool | None = None
    model_variant: str = "fdtn-ai/antares-1b"
    audit_callback_url: str | None = None
    audit_callback_token: str | None = None
    audit_actor: str = "antares"
    audit_subject: str = ""
    investigation_id: str | None = None
    exclude_test_paths: bool = True
    changed_paths: list[str] = Field(default_factory=list)


class CompletionRequest(BaseModel):
    model: str = "antares"
    prompt: str
    max_tokens: int = 1024
    temperature: float = 0.3
    top_p: float = 1.0
    stop: list[str] | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    logger.info("Starting Antares inference service (local weights only)...")
    engine = build_engine_from_env()
    app.state.engine = engine
    app.state.agent_engine = AgentQueryEngine(engine)
    logger.info("Antares engine ready: %s", engine.status())
    yield
    engine.unload()


app = FastAPI(
    title="Antares Local Inference",
    version="0.1.0",
    description=(
        "Serves Antares from pre-staged local weights. "
        "Evaluates supplied diff text only — does not scan live infrastructure."
    ),
    lifespan=lifespan,
)


@app.get("/health")
def health():
    engine: AntaresEngine = app.state.engine
    return {"status": "ok", "bind_host": BIND_HOST, **engine.status()}


@app.post("/v1/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    engine: AntaresEngine = app.state.engine
    if not request.files:
        return {
            "outcome": "completed_no_findings",
            "findings": [],
            "failure_class": None,
            "failure_stage": None,
            "failure_message": None,
            "timings_ms": {},
        }

    payload = [
        {
            "path": file.path,
            "hunks": [hunk.model_dump() for hunk in file.hunks],
        }
        for file in request.files
    ]

    try:
        result = engine.analyze_files(payload)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Antares analysis failed")
        if engine._load_strategy == "on_demand":
            try:
                engine.unload()
            except Exception:  # noqa: BLE001
                pass
        raise HTTPException(
            status_code=500,
            detail=(
                f"Local Antares inference failed: {exc}. "
                "No hosted API fallback — verify weights are staged under ANTARES_MODEL_PATH."
            ),
        ) from exc

    if result.get("outcome") == "failed" and engine._load_strategy == "on_demand":
        try:
            engine.unload()
        except Exception:  # noqa: BLE001
            pass

    return {
        **result,
        "disclaimer": (
            "Likely findings for human review — not a compliance verdict. "
            "Diff-hunk analysis of supplied text only."
        ),
    }


@app.post("/v1/query")
def query_localization(request: QueryRequest) -> dict[str, Any]:
    agent_engine: AgentQueryEngine = app.state.agent_engine
    if not request.queries:
        return {
            "outcome": "completed",
            "localizations": [],
            "failure_class": None,
            "failure_stage": None,
            "failure_message": None,
            "timings_ms": {},
            **agent_engine.runtime_metadata(request.loop_control_enabled),
            "disclaimer": (
                "Ranked file localization for human review — not a compliance verdict. "
                "Advisory only; policy uses handler-asserted CWE on changed hunks."
            ),
        }

    try:
        result = agent_engine.query(
            snapshot_files=[item.model_dump() for item in request.snapshot_files],
            changed_paths=request.changed_paths,
            queries=[item.model_dump() for item in request.queries],
            max_terminal_calls=request.max_terminal_calls,
            temperature=request.temperature,
            top_p=request.top_p,
            loop_control_enabled=request.loop_control_enabled,
            max_snapshot_bytes=request.max_snapshot_bytes,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Antares agent query failed")
        raise HTTPException(
            status_code=500,
            detail=(
                f"Local Antares agent query failed: {exc}. "
                "No hosted API fallback — verify weights are staged under ANTARES_MODEL_PATH."
            ),
        ) from exc

    return {
        **result,
        "disclaimer": (
            "Candidate files for review — advisory triage only; never a merge gate signal."
        ),
    }


def _build_streaming_audit_sink(request: TriageRunRequest):
    if not request.audit_callback_url:
        return None
    from antares_server.http_audit_sink import HttpAuditSink

    subject = request.audit_subject or f"{request.repo}@{request.ref}"
    return HttpAuditSink(
        request.audit_callback_url,
        actor=request.audit_actor,
        subject=subject,
        audit_token=request.audit_callback_token,
    )


@app.post("/v1/investigations/{investigation_id}/cancel")
def cancel_investigation(investigation_id: str) -> dict[str, str]:
    from antares_server.cancellation_registry import request_cancel
    from antares_server.docker_sandbox import destroy_investigation_container

    request_cancel(investigation_id)
    destroy_investigation_container(investigation_id)
    return {"status": "cancelling", "investigation_id": investigation_id}


@app.post("/v1/triage/run")
def triage_run(request: TriageRunRequest) -> dict[str, Any]:
    agent_engine: AgentQueryEngine = app.state.agent_engine
    try:
        result = agent_engine.run_triage(
            repo_root=request.repo_root,
            queries=[item.model_dump() for item in request.queries],
            max_terminal_calls=request.max_terminal_calls,
            temperature=request.temperature,
            top_p=request.top_p,
            loop_control_enabled=request.loop_control_enabled,
            exclude_test_paths=request.exclude_test_paths,
            changed_paths=request.changed_paths,
            audit_sink=_build_streaming_audit_sink(request),
            investigation_id=request.investigation_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Antares triage run failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        **result,
        "model_variant": request.model_variant,
        "disclaimer": "Candidate files for review — advisory only; does not gate merges.",
    }


@app.post("/v1/completions")
def completions(request: CompletionRequest) -> dict[str, Any]:
    """OpenAI-compatible completions surface for official Antares CLI integration."""
    engine: AntaresEngine = app.state.engine
    try:
        engine.load()
        text = engine.generate_agent(
            request.prompt,
            temperature=request.temperature,
            top_p=request.top_p,
            max_new_tokens=request.max_tokens,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "id": "antares-local-completion",
        "object": "text_completion",
        "created": 0,
        "model": request.model,
        "choices": [{"text": text, "index": 0, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


@app.post("/v1/unload")
def unload_model() -> dict[str, str]:
    engine: AntaresEngine = app.state.engine
    engine.unload()
    return {"status": "unloaded"}


def main() -> None:
    uvicorn.run(
        "antares_server.main:app",
        host=BIND_HOST,
        port=int(os.environ.get("ANTARES_PORT", "8090")),
        reload=False,
    )


if __name__ == "__main__":
    main()
