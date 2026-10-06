# demo-dryrun — operational smoke test

End-to-end validation of Shift-Left cold start, PR gate, waivers, SHA invalidation,
and unclaimed `.cfg` blocking (CWE-657).

## Prerequisites

- `./shift-left up` completed at least once (Forgejo + orchestrator + model weights)
- Foundation-Sec Q4_K_M staged under `models/foundation-sec-q4_k_m`
- `FORGEJO_TOKEN` in `.env` or `.shift-left/bootstrap-secrets.json`

## Run

```bash
./scripts/demo-dryrun/run
```

Environment:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DRYRUN_COLD_RUNS` | `1` | Cold-start iterations (`shift-left down` + `up`) |
| `DRYRUN_WARM_RUNS` | `3` | Warm-stack iterations (remaining phases) |
| `DRYRUN_SKIP_ADVISORY` | `false` | Skip model for waiver/sha/unclaimed reviews; `gate_block` still measures both paths |
| `DRYRUN_PHASE_TIMEOUT_SEC` | `300` | Per-phase wall-clock limit |
| `DRYRUN_ORCHESTRATOR_URL` | `http://127.0.0.1:8080` | Orchestrator API |
| `DRYRUN_FORGEJO_URL` | `http://127.0.0.1:3000` | Forgejo API |

## Phases

**Cold (once, before warm iterations):**

1. **cold_start** — `./shift-left down` + `up` on Q4_K_M / `n_ctx=4096`, models unloaded

**Warm (repeated `DRYRUN_WARM_RUNS` times against the warm stack):**

2. **create_pr** — Forgejo repo with ASA (`ASA-001`, `ASA-007`) + FMC (`FTD-001`) violations
3. **gate_block_deterministic** — review with `skip_advisory=true`; handler gate only
4. **gate_block_advisory** — full review with model; reports load/inference/handler breakdown
5. **waiver** — grant `ASA-007` waiver (APPROVE); finding visible, non-blocking
6. **sha_invalidate** — amend commit; waiver expired; `ASA-007` blocks again
7. **unclaimed_cfg** — add `misc/unclaimed.cfg`; assert CWE-657 blocks gate
**Cleanup (always runs):** deletes tracked `demo-dryrun-*` Forgejo repos (plus an orphan
sweep), and unloads foundation-sec / antares model weights. Runs on assertion failure,
phase timeout, `KeyboardInterrupt`, or success — reported under `cleanup` in the JSON output.

Each warm iteration always runs both `gate_block_deterministic` and `gate_block_advisory` so
deterministic handler latency is reported separately from model load + inference cost.
The advisory phase reports `stage_timings_ms` breakdown: `model_load_ms`, `inference_ms`,
and `handler_eval_ms`.

With `DRYRUN_SKIP_ADVISORY=true`, waiver / sha_invalidate / unclaimed_cfg use
`skip_advisory=true` on review (handler gate only); gate_block still benchmarks both paths.

## Output

JSON report under `validation/reports/demo-dryrun-<timestamp>.json` with:

- `cold_summary` — cold_start timings (separate from warm)
- `warm_summary` — mean/stdev/min/max across warm iterations for each warm phase
- Per-run phase timings, peak RSS (model server PIDs on :8090/:8091), and swap used
