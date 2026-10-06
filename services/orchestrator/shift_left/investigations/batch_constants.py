"""Batch investigation launch guardrails and benchmark disclosure numbers."""

BATCH_SIZE_CAP = 25
BATCH_CONFIRM_THRESHOLD = 10
MEDIAN_INVESTIGATION_SECONDS = 62
BENCHMARK_MEAN_PRECISION = 0.226
BENCHMARK_P_AT_1 = 0.200
BENCHMARK_NOTE = (
    "20-run Antares localization benchmark on a seeded, known-present CWE-89 defect "
    "(celery corpus, post-harness bounds fc8d870)."
)
