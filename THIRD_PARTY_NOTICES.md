# Third-Party Notices — Shift-Left Review Pipeline

This file covers **runtime and build dependencies** plus **model weights** staged separately from git.

## Project software license

Shift-Left source code: **Apache License 2.0** — see `LICENSE`.

## Model weights (staged separately, not in git)

| Component | Upstream | License | Notes |
|-----------|----------|---------|-------|
| Antares-350M | `fdtn-ai/antares-350m` | Apache-2.0 | Gated HF download; bundling permitted |
| Foundation-Sec Q8_0 GGUF | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF` | Apache-2.0 | Published quant |
| Foundation-Sec Q4_K_M GGUF | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | Apache-2.0 | Low-memory quant |

Retain upstream `LICENSE`, `README.md`, and any `NOTICE` files from each Hugging Face repo when redistributing weights.

## Python dependencies (representative)

See service `pyproject.toml` files for pinned versions. Key runtime libraries include:

- **FastAPI / Starlette / Uvicorn** — MIT
- **Pydantic** — MIT
- **httpx** — BSD-3-Clause
- **PyYAML** — MIT
- **transformers / torch** — Apache-2.0 (Antares inference)
- **llama-cpp-python** — MIT (Foundation-Sec GGUF inference)
- **huggingface_hub** — Apache-2.0 (install-time downloads only)

Generate a full dependency SBOM from your lockfiles before shipping production bundles.

## Reference data (tracked JSON, not upstream source trees)

| Data | Path | Terms |
|------|------|-------|
| MITRE CWE dictionary, localization catalog, and 2024 Top 25 flags | `data/cwe/` | CWE™ © The MITRE Corporation. See [docs/licensing.md](docs/licensing.md). Generated offline from a local XML export; the XML itself is not committed. |

Upstream application checkouts used for localization benchmarks are not in git. Rebuild them from pinned commits as described in [validation/README.md](validation/README.md).

## Documentation UI (vendored in git)

| Component | Version | Path | License |
|-----------|---------|------|---------|
| Swagger UI (`swagger-ui-dist`) | 5.17.14 | `docs/vendor/swagger-ui/` | Apache-2.0 |

Upstream: https://github.com/swagger-api/swagger-ui. The Pages explorer loads `swagger-ui.css` and `swagger-ui-bundle.js` from that directory. `LICENSE` and `NOTICE` from the 5.17.14 package are stored beside those files. Copyright 2020-2021 SmartBear Software Inc.

## Container images

See `docker-compose.yml` for base images (Postgres, Forgejo, etc.). Verify license terms for each image before redistribution.
