# Validation corpora

First-party labeled configs stay in the tree:

- `validation/corpus/config` — generated handler fixtures
- `validation/corpus/holdout` — holdout configs
- `validation/corpus/bad`, `clean`, and `messy` — small hand-written samples

Upstream application source is not redistributed. The CVE and localization checkouts are fetched at pinned commits when you rebuild them, then written under gitignored directories.

## Multi-defect CVE corpus

Pins live in `validation/multidefect/manifest.json` (`fix_commit`, `parent_commit`, and `osv_fix_commit` per entry). Ground truth for those pins is `validation/multidefect/ground-truth.json`.

```bash
python validation/build_multidefect_corpus.py
```

That clones each upstream repository, checks out the pinned parent commit, and writes the tree to `validation/corpus/multidefect/`. The script does not vendor those trees back into git.

## Celery localization corpus

`validation/build_localization_corpus.py` clones `https://github.com/celery/celery` at commit `918a740497a4ce883f37eb1a3e7c2a80dfcc8b7a` and writes `validation/corpus/localization/celery-corpus/`. A profiler test that needs this tree skips, with this rebuild command, until the checkout exists.

## Reports shipped with the release

`validation/reports/` keeps only the artifacts cited from `docs/validation-summary.md`:

- `handler-coverage.json`
- `model-experiments-comparison.txt`
- `structured-output-finding.md`
- `antares-localization-paired-n30-statistical-report.json`
- `antares-localization-multidefect-v3.json`
