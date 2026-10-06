# Model server contract

This document is the HTTP contract for the local Antares and Foundation-Sec processes. Orchestrator authors and operators debugging inference should read it. Review-time egress stays blocked; listeners default to loopback.

## Antares server (`antares-server`, default `:8090`)

### `GET /health`

Returns bind host, load strategy, model path, and recycle configuration.

### `POST /v1/analyze` (legacy diff-hunk JSON)

**Purpose:** Structured JSON findings from diff hunks. Not used for the PR merge gate.

**Request:** `{ "files": [ { "path", "hunks": [ { "new_start", "new_end", "content" } ] } ] }`

**Response:** `{ "outcome", "findings", "timings_ms", ... }` with contract-validated finding objects.

### `POST /v1/triage/run`

**Purpose:** Official Antares agent loop for advisory triage.

**Request:**

```json
{
  "repo_root": "/data/repos/org/repo",
  "queries": [{ "task_cwe": "CWE-89", "task_cwe_description": "SQL Injection" }],
  "max_terminal_calls": 15,
  "temperature": 0.3,
  "top_p": 1.0,
  "model_variant": "fdtn-ai/antares-1b"
}
```

**Response:** `{ "localizations": [...], "outcome", "turn_count", "exploration_trace", ... }`

**Lifecycle:** Model loaded at run start when `load_strategy=resident_for_run`; `unload_after_run()` at completion increments run counter; recycle recommended after `ANTARES_RECYCLE_AFTER_RUNS` (default 10).

### `POST /v1/completions` (OpenAI-compatible)

**Purpose:** Official Antares CLI integration (`/v1/completions`, raw text completion).

**Request:** `{ "prompt", "temperature", "top_p", "max_tokens", "model" }`

**Response:** OpenAI-style `{ "choices": [{ "text" }], ... }`

### `POST /v1/unload`

Unloads transformer weights from memory. Idempotent. Does not reset recycle counter (use triage run completion for counted recycle).

---

## Foundation-Sec server (`foundation-sec-server`, default `:8091`)

### `POST /v1/analyze`

Config/IaC diff analysis with handler rules + optional model enrichment (enrichment is advisory only).

### `POST /v1/unload`

Unloads GGUF context when `load_strategy=on_demand`.

---

## Orchestrator integration

| Workflow | Antares | Foundation-Sec |
|----------|---------|----------------|
| PR code gate | **Not used** — deterministic code handlers only | Optional enrichment (advisory) |
| PR config gate | **Not used** | Handler rules + optional enrichment |
| Antares triage | `POST /v1/triage/run` via `AntaresClient.run_triage_query` | Not used |

## Version history

| Version | Change |
|---------|--------|
| v1 | Initial documented contract: `/v1/analyze`, `/v1/triage/run`, `/v1/completions`, `/v1/unload` |
