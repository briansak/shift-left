# Air-gapped install

This document is for operators who need to install Shift-Left on a host with no internet access. Connected install (`./shift-left up`) is the usual path; this is the offline variant.

## What the bundle contains

`./shift-left bundle-build` runs on a connected machine and writes a compressed archive of:

- Docker images currently saved by the builder: `postgres:16-alpine`, Forgejo 11 rootless, and the Forgejo runner image
- `config/`, `services/`, `templates/`, `scripts/`, and `docker-compose.yml`
- `models/` when present (weights are not in git)
- `data/reference/` or `reference-seed/`

It does **not** yet vendor a Python wheelhouse. Runtime Python in this project is installed in Compose images and the operator venv on a connected host; air-gapped Python package install from `--no-index` wheels is specified below as a remaining requirement, not as implemented behavior.

`python-hcl2` is a hard gate dependency for FTD and generic Terraform. If it is missing at review time, every claimed `.tf` / `.hcl` file blocks with **HCL-001** (CWE-754). See [gate-enforcement.md](gate-enforcement.md).

## Connected machine

```bash
./shift-left bundle-build --output ./shift-left-bundle.tar.zst
```

The CLI currently writes an xz tar despite the `.tar.zst` suffix commonly used in examples — check the file the command prints.

Transfer the archive to the isolated host.

## Isolated host

```bash
./shift-left bundle-install --bundle ./shift-left-bundle.tar.zst
./shift-left up
```

`bundle-install` loads the saved images and copies staged config, models, and reference data. `up` then starts Compose and host-native model servers from local state.

Offline updates: build a refreshed bundle on a connected machine and run `bundle-install` again. There is no auto-update.

## Python wheels (not implemented)

Air-gapped hosts that must `pip install` orchestrator or Foundation-Sec packages without PyPI still need:

1. A `wheelhouse/` of every transitive dependency, including `python-hcl2`
2. `pip install --no-index --find-links=<wheelhouse> …`
3. A build-time assertion that install does not resolve from the network after the wheelhouse is sealed
4. Filenames, versions, and SHA-256 digests in the bundle manifest

`bundle-build` does not produce that wheelhouse today. Treat a missing `python-hcl2` as a bundle-build failure, not a silent PASS at the gate.

## Related

- [distribution-and-sovereignty.md](distribution-and-sovereignty.md) — install vs runtime network
- [licensing.md](licensing.md) — model-weight redistribution
