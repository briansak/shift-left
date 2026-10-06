# CWE data (offline)

Runtime lookup reads bundled JSON only — no HTTP requests.

| File | Purpose |
|------|---------|
| `cwe-dictionary.json` | CWE popovers in target detail UI (registry/gate ids only) |
| `localization-candidates.json` | Investigation launch picker (Base + Variant CWEs) |
| `cwe-top-25-2024.json` | MITRE 2024 Top 25 flags for candidate catalog |

## Refresh from MITRE

1. On a connected machine, download the CWE catalog XML from MITRE (operator-initiated egress).
2. Copy `cwec_*.xml` into `data/cwe/source/` (gitignored) or any local path.
3. Regenerate:

```bash
python scripts/build-cwe-dictionary.py /path/to/cwec_latest.xml
python scripts/build-localization-candidates.py /path/to/cwec_latest.xml
```

`build-localization-candidates.py` includes only Base and Variant abstractions (file-localizable
weaknesses). The Base/Variant filter removes 131 of 969 MITRE weaknesses; the remaining **838**
entries are still not a browsable picker list.

**Language filtering is near-ineffective as a narrowing mechanism.** Filtering to a Python-only
repo yields 643 entries — only a 23% reduction — because **591** entries are marked
`Not Language-Specific` in MITRE and apply to every repository. See
`localization-candidates.json` `_meta.language_applicability` for full distribution.

**Viable picker entry points** (use these instead of scrolling 600+ CWEs):

- **Free-text search** over the catalog
- **CWE Top 25** — 10 survivors for a typical Python repo (language-agnostic entries included)
- **Profiler evidence** — CWEs with direct/indirect surface evidence in the target repo

The full 838-entry catalog remains the backing dataset; it is not intended as the default
launch surface.

Tractability ratings (`strong` / `weak` / `unrated`) come from the Antares model card
(`models/1b/README.md`, Limitations §2). CWE-732 and CWE-667 are named weak examples on the
card but are Class abstractions in MITRE and excluded here — see `_meta.tractability_source`.

VLoc Bench's 147 CWE list is not vendored offline; `localization-candidates.json` documents that
in `_meta.vloc_bench_cwes`.

## Finding: config gate vs localization abstraction mismatch

Deterministic handler rules assert **12** unique CWEs today. **6** are Base/Variant and appear
in `localization-candidates.json` with handler badges in the CWE reference UI. **6** are Pillar
or Class and appear only in the out-of-catalog section on `/ui/cwe` (for example CWE-284 backs
**14** rules; CWE-693 backs **5**).

**Why config handlers skew high-abstraction.** Operator-facing config policy classifies at the
Pillar/Class level. A permissive ACL is “improper access control” (CWE-284, Pillar) with no
better Base-level child in the taxonomy — the rule is correct for the gate even though the CWE
is not file-localizable.

**Why code localization requires Base/Variant.** Model-assisted investigation matches grep-able
patterns in changed hunks. Pillar/Class descriptions give the model nothing concrete to search
for in source files.

**Consequence.** The deterministic config gate and model-assisted code localization operate at
**incompatible abstraction levels** of the same MITRE taxonomy. They are not two applications of
one technique — the abstraction level determines which technique can work.

**Cross-reference: Antares model card.** Two of the model card's three stated weak-tractability
examples (CWE-732, CWE-667) are Class abstractions and therefore not file-localizable at all.
The card partly describes a **category mismatch** rather than a model limitation — the same
pattern as config-handler CWEs above. See `_meta.tractability_source.model_card_weak_examples`.

See [docs/licensing.md](../docs/licensing.md) for MITRE CWE attribution.
