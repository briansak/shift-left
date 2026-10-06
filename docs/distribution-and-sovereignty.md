# Distribution and runtime sovereignty

This document is for operators who need a hard line between install-time network use and review-time isolation. Air-gap steps: [air-gapped-install.md](air-gapped-install.md). Licenses: [licensing.md](licensing.md).

## Two distinct trust zones

| Zone | What moves | Network |
|------|------------|---------|
| **Supply chain (install/update)** | Tool source, container images, model weights, CVE/CWE reference data | Operator-initiated egress **expected** |
| **Runtime (pipeline)** | Customer code diffs, configs, findings, local inference | **No egress** — hard constraint |

After install, customer data **never leaves the organization’s host**.

## Runtime hard constraints (enforced in code)

1. **No egress at runtime** — HTTP clients use a local allowlist (`shift_left/http/local_client.py`). Compose `sovereign_internal` network is `internal: true`.
2. **No telemetry** — No analytics, crash reporting, usage metrics, or phone-home. Not opt-out — **absent**.
3. **No runtime license validation** — No activation servers or network license checks.
4. **Local inference only** — Models load from pre-staged paths with `local_files_only=True`. On failure, the pipeline **fails closed** — no hosted API fallback.
5. **Reference data** — CVE/CWE enrichment reads only from `data/reference/` populated at install/sync. Never fetched during reviews.
6. **Defensive scope only** — The pipeline evaluates **supplied diff and configuration text**. It does not scan, probe, or connect to live infrastructure.

## Storage boundaries

| Store | Engine | Purpose |
|-------|--------|---------|
| Forgejo metadata | **PostgreSQL** (`postgres` service) | Git hosting, Actions, PR metadata |
| Findings | **SQLite** (`findings_store.sqlite_path`) | Normalized review findings per PR |

These are separate by design — Postgres is not the findings database.

## macOS host-native vs Linux containerized egress

| Deployment | Model servers | Egress boundary |
|------------|---------------|-----------------|
| **Linux Compose** | `antares-server` / `foundation-sec-server` on `sovereign_internal` | Docker `internal: true` + HTTP allowlist + egress probe in orchestrator |
| **macOS Apple Silicon** | Antares (:8090) and Foundation-Sec (:8091) **on the host** | **Loopback bind (127.0.0.1 default)** + startup egress probe + offline weight loading; orchestrator in Compose uses `host.docker.internal:host-gateway` |

Host-native model servers have the **full macOS network stack**. Sovereignty is enforced by:

- Binding to `127.0.0.1` (refuses `0.0.0.0` unless `ALLOW_NON_LOOPBACK_BIND=true`)
- Startup TCP egress probe (fails if public internet is reachable — use host firewall in production; `SHIFT_LEFT_SKIP_EGRESS_PROBE=1` for local dev only)
- No runtime weight download (`HF_HUB_OFFLINE`, local GGUF + optional SHA256 manifest)

The orchestrator container attaches to `sovereign_internal` (no default internet gateway) **and** `edge` so host port `:8080` can be published. It reaches host-native inference via **`extra_hosts: host.docker.internal:host-gateway`** — a Docker engine route to the host, not general WAN egress.

## `sovereign_internal` and `host.docker.internal`

`networks.sovereign_internal.internal: true` removes the default gateway to the public internet.

The orchestrator service sets:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

This adds a static host mapping so `http://host.docker.internal:8090` reaches the Mac host loopback listener. It works **alongside** `internal: true` because it is host routing, not WAN egress.

Runtime HTTP allowlisting is **port-scoped**: `host.docker.internal` is permitted only on **8090** and **8091**, not as a whole-host wildcard.

Integration tests: `services/orchestrator/tests/test_orchestrator_network_boundary.py`.

Verify runtime behavior:

```bash
./scripts/shift-left verify-runtime
# or
./scripts/test-runtime-sovereignty.sh
```

This runs a **full code review + full config review** with socket and HTTP egress guards enabled.

## Outbound connections by lifecycle

| Destination | When | Purpose | Runtime? | How to verify absent at runtime |
|-------------|-------|---------|----------|----------------------------------|
| `github.com` | Install, update | Clone/pull tool source | No | `shift-left verify-runtime`; egress probe in orchestrator startup |
| `huggingface.co` | Install, sync | `hf download` for Antares / Foundation-Sec weights | No | Weights under `models/`; `huggingface_hub>=0.28.0` |
| NVD API 2.0 | `sync-reference-data --fetch-nvd` | Resumable CVE backfill (cursor + windows) | No | Optional `NVD_API_KEY` |
| MITRE CWE catalog (XML zip) | `sync-reference-data --fetch-nvd` | CWE fetcher (separate from NVD pagination) | No | `cwe_catalog_version` in manifest |
| `host.docker.internal:8090` | **Runtime** (macOS) | Orchestrator → host-native Antares | On-host route only | `extra_hosts` + allowlist |
| `host.docker.internal:8091` | **Runtime** (macOS) | Orchestrator → host-native Foundation-Sec | On-host route only | `extra_hosts` + allowlist |
| **Antares host-native :8090** | **Runtime** | Code inference on macOS host | Host process | Loopback bind + egress probe |
| **Foundation-Sec host-native :8091** | **Runtime** | Config inference on macOS host | Host process | Loopback bind + GGUF SHA256 check |
| `antares-server:8090` (Compose) | **Runtime** | Code inference (Linux profile) | `sovereign_internal` only | `ALLOW_NON_LOOPBACK_BIND` in container |
| `foundation-sec-server:8091` (Compose) | **Runtime** | Config inference (Linux profile) | `sovereign_internal` only | `ALLOW_NON_LOOPBACK_BIND` in container |
| Container registries | Install, update | Pull/save images | No | Pre-pull before air-gap |
| `forgejo:3000` (bundled) | **Runtime** | Customer PR diffs, comments | On-host only | Sovereign default |
| `api.github.com` / GitLab API | **Runtime** | External git backend only | Provider egress | Requires acknowledgement |
| Forgejo UI (`localhost:3000`) | **Runtime** | Human PR review in browser | Yes (operator browser → local) | Not pipeline egress of analyzed artifacts |
| Hosted LLM APIs (OpenAI, etc.) | — | — | **Never** | Blocked env vars + no client code |

Forgejo Actions `DEFAULT_ACTIONS_URL` is not separately asserted in `verify-runtime`. Workflows in this repo use shell steps and the local orchestrator; do not add marketplace actions that pull at review time.

## Install paths

### Connected install (default)

```bash
./scripts/shift-left install
```

Pulls images, builds services, writes reference-data stub, documents model staging.

### Offline / air-gapped install

On a connected machine:

```bash
./scripts/shift-left bundle-build --output ./shift-left-bundle.tar.zst
```

Transfer the bundle, then on the isolated host:

```bash
./scripts/shift-left bundle-install --bundle ./shift-left-bundle.tar.zst
```

## Updates (operator-initiated only)

```bash
./scripts/shift-left update                  # connected: git pull + docker pull
./scripts/shift-left sync-reference-data     # refresh local CVE/CWE cache
```

Offline updates: build a **refreshed bundle** on a connected machine and run `bundle-install` again.

There are **no** background update checks and **no** auto-update.

## Configuration

See `config/shift-left.example.yaml`:

```yaml
distribution:
  auto_update: false   # must remain false
  telemetry: false     # must remain false

sovereignty:
  deny_egress: true
```

Orchestrator startup rejects `auto_update: true` or `telemetry: true`.

## Model licensing and offline bundles

See [licensing.md](licensing.md). Offline image/weight bundles: [air-gapped-install.md](air-gapped-install.md). **`python-hcl2` is gate-critical** — without it, every FTD and `generic_terraform` file blocks with CWE-754 (HCL-001).

## Local GGUF quantization (when published quants unavailable)

If no suitable Foundation-Sec GGUF is published for your memory budget:

1. Obtain the base model weights per license terms (operator egress during install only).
2. Quantize with [llama.cpp](https://github.com/ggerganov/llama.cpp) locally, e.g. `llama-quantize`.
3. Stage the output under `models/` and set `FOUNDATION_SEC_GGUF_GLOB` to match the filename.
4. Record `gguf_filename` and `sha256` in `models/.prewarm-manifest.json`.

**Verified (Q4_K_M):** `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` publishes `foundation-sec-1.1-8b-instruct-q4_k_m.gguf` (SHA256 `5813d725…8421ed`). See `docs/licensing.md` and `config/prewarm-manifest.example.json`.

## Human-in-the-loop

Findings are **likely issues for review**, not compliance verdicts. The pipeline never auto-approves or auto-remediates.
