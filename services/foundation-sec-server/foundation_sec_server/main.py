"""Foundation-Sec local config analysis API (llama.cpp GGUF)."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from foundation_sec_server.analyzer import ConfigAnalyzer
from foundation_sec_server.engine import build_engine_from_env

try:
    from shift_left_shared.server import startup_model_server
except ImportError:

    def startup_model_server(env: dict[str, str], *, service_name: str, bind_env_key: str) -> str:
        return env.get(bind_env_key, "127.0.0.1")


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

BIND_HOST = startup_model_server(
    os.environ,
    service_name="foundation-sec-server",
    bind_env_key="FOUNDATION_SEC_BIND_HOST",
)


class HunkInput(BaseModel):
    new_start: int
    new_end: int
    content: str
    context_lines_before: int = 5
    context_lines_after: int = 5


class FileInput(BaseModel):
    path: str
    target_type: str | None = None
    hunks: list[HunkInput] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    repo: str
    pr_ref: str
    commit_sha: str
    files: list[FileInput] = Field(default_factory=list)
    max_context_tokens: int | None = None
    chunk_overlap_lines: int | None = None
    prompt_variant: str = "baseline"
    skip_inference: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    logger.info("Starting Foundation-Sec service (local GGUF via llama.cpp)...")
    engine = build_engine_from_env()
    analyzer = ConfigAnalyzer(
        engine,
        max_context_tokens=int(os.environ.get("FOUNDATION_SEC_N_CTX", "8192")),
        chunk_overlap_lines=int(os.environ.get("FOUNDATION_SEC_CHUNK_OVERLAP", "2")),
    )
    app.state.analyzer = analyzer
    logger.info("Foundation-Sec ready: %s", analyzer.status())
    yield
    analyzer.unload()


app = FastAPI(
    title="Foundation-Sec Local Inference",
    version="0.2.0",
    description=(
        "Defensive review of proposed configuration changes via local llama.cpp inference. "
        "Evaluates supplied config text only — never scans live infrastructure."
    ),
    lifespan=lifespan,
)


@app.get("/health")
def health():
    analyzer: ConfigAnalyzer = app.state.analyzer
    return {"status": "ok", "bind_host": BIND_HOST, **analyzer.status()}


@app.post("/v1/analyze")
def analyze(request: AnalyzeRequest):
    analyzer: ConfigAnalyzer = app.state.analyzer
    if request.max_context_tokens or request.chunk_overlap_lines:
        analyzer = ConfigAnalyzer(
            analyzer._engine,
            max_context_tokens=request.max_context_tokens or analyzer._max_context_tokens,
            chunk_overlap_lines=request.chunk_overlap_lines or analyzer._chunk_overlap_lines,
        )
    payload = [
        {
            "path": f.path,
            "target_type": f.target_type,
            "hunks": [h.model_dump() for h in f.hunks],
        }
        for f in request.files
    ]
    try:
        result = analyzer.analyze_files(
            payload,
            prompt_variant=request.prompt_variant,
            skip_inference=request.skip_inference,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Foundation-Sec analysis failed")
        load_strategy = getattr(analyzer._engine, "_load_strategy", None)
        if load_strategy == "on_demand":
            try:
                analyzer.unload()
            except Exception:  # noqa: BLE001
                pass
        raise HTTPException(
            status_code=500,
            detail=(
                f"Local Foundation-Sec inference failed: {exc}. "
                "No hosted API fallback — verify GGUF weights are staged."
            ),
        ) from exc

    if result.get("outcome") == "failed":
        load_strategy = getattr(analyzer._engine, "_load_strategy", None)
        if load_strategy == "on_demand":
            try:
                analyzer.unload()
            except Exception:  # noqa: BLE001
                pass

    return {
        **result,
        "disclaimer": (
            "Likely findings for human review — not a compliance verdict. "
            "Defensive evaluation of supplied config diff text only."
        ),
    }


class EnrichFindingsRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list)


class ReviewSummaryRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list)


@app.post("/v1/enrich-findings")
def enrich_findings(request: EnrichFindingsRequest):
    analyzer: ConfigAnalyzer = app.state.analyzer
    engine = analyzer._engine
    if not hasattr(engine, "enrich_finding_prose"):
        raise HTTPException(status_code=501, detail="Enrichment not supported by active engine")
    enrichments = [engine.enrich_finding_prose(item) for item in request.findings]
    return {"enrichments": enrichments}


@app.post("/v1/review-summary")
def review_summary(request: ReviewSummaryRequest):
    analyzer: ConfigAnalyzer = app.state.analyzer
    engine = analyzer._engine
    if not hasattr(engine, "generate_review_summary"):
        raise HTTPException(status_code=501, detail="Review summary not supported by active engine")
    summary = engine.generate_review_summary(request.findings)
    return {"review_summary": summary}


@app.post("/v1/unload")
def unload_model():
    analyzer: ConfigAnalyzer = app.state.analyzer
    analyzer.unload()
    return {"status": "unloaded"}


def main() -> None:
    uvicorn.run(
        "foundation_sec_server.main:app",
        host=BIND_HOST,
        port=int(os.environ.get("FOUNDATION_SEC_PORT", "8091")),
        reload=False,
    )


if __name__ == "__main__":
    main()
