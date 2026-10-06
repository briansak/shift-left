# Changelog

## 0.1.0

First public release of the local pull-request review stack.

- Deterministic config gate for ASA, FMC/FTD, IOS-XE, NX-OS, and generic Terraform, with human approval bound to a commit SHA.
- Foundation-Sec and Antares stay advisory. Both are off until installed. `install-antares` turns Antares triage on when it stages the server.
- Upstream CVE and localization checkouts are not in the git tree. Rebuild them from the pinned commits in `validation/multidefect/manifest.json` and `validation/build_localization_corpus.py`.
- Linux x86_64 is documented through the Compose model profile and has not been tested end to end.
