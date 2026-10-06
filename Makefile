# Generated documentation. Requires PYTHONPATH into the orchestrator package.

.PHONY: docs docs-openapi docs-config-ref docs-platforms

PYTHON ?= .venv/bin/python
export PYTHONPATH := services/orchestrator:services/shift-left-shared

docs: docs-openapi docs-config-ref docs-platforms

docs-openapi:
	$(PYTHON) scripts/generate-openapi.py

docs-config-ref:
	$(PYTHON) scripts/generate_docs.py --config-ref

docs-platforms:
	$(PYTHON) scripts/generate_docs.py --platforms
