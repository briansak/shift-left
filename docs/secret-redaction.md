# Secret redaction

This document lists every presentation and outbound surface that must redact config-derived secrets. Contributors adding a JSON route or UI tab should read it; the tests named below fail if a new surface is unclassified.

Shift-Left separates **detection** (parsers, handlers, models) from **presentation** (anything shown to humans or written outside the orchestrator process).

## At-rest invariant

| Store | Config-derived text | Stored form | Redaction |
|-------|---------------------|-------------|-----------|
| Findings SQLite (`findings` table) | `evidence`, `description`, `model_context` | **Raw** (as produced by handlers/models) | Applied by every reader before display or outbound write |
| Investigations SQLite (`investigation_trace_turns`, `investigation_candidates`) | `command`, `output_truncated`, `file_path` | **Raw** (sandbox output and ranked paths) | `redact_trace_record_for_display` / `redact_display_text` at presentation only |
| Approval snapshots (`findings_snapshot`) | Same fields frozen at approval time | **Raw** | Redacted when returned via API |
| Git / Forgejo (PR comments, statuses) | Must never receive raw secrets | N/A — write path only | Redacted in `_format_comment` before `post_pull_request_comment` |
| Audit log (`audit_events.details`) | Usually metadata only | Raw operator/policy text | Recursive string redaction in History tab UI and audit API |
| Waiver records (`reason`) | Operator free text | **Raw** | `redact_display_text` in target detail, PR review UI, and audit detail rendering |

**Rule:** parsers and gate logic operate on raw config. Redaction runs at presentation boundaries only — UI templates, JSON API serializers (`api_presentation.py`), and Forgejo PR comment formatting. The findings store is **not** rewritten when redaction rules change.

There is no `matched_snippet` column. The Findings tab computes `matched_snippet` at render time from `evidence` or declared file content, then passes it through `config_redaction`.

## Presentation chokepoint

All config-derived display text flows through `shift_left/ui/config_redaction.py`:

- `redact_config_line` / `redact_config_content` — CLI and HCL line patterns
- `redact_known_values` — parser-extracted literals (unambiguous always; ambiguous context-gated in prose)
- `redact_display_text` — snippets, prose, waiver reasons, operator free text
- `redact_finding_for_display` — `evidence`, `description`, `model_context`, `recommended_actions`

## Surfaces (complete)

Authoritative lists live in `shift_left/ui/api_presentation.py` (`API_CONFIG_TEXT_SURFACES`, `API_CONFIG_TEXT_REQUEST_SURFACES`, `NON_API_CONFIG_TEXT_SURFACES`, `API_ROUTES_WITHOUT_CONFIG_TEXT`). Tests in `tests/test_outbound_secret_redaction.py` fail if a new JSON route is not classified.

### JSON API (redacted)

| Method | Path |
|--------|------|
| POST | `/api/v1/review` (handler findings only; advisory omitted) |
| GET | `/api/v1/findings/{owner}/{repo}/{pr_number}` (git re-read at finding SHA) |
| PATCH | `/api/v1/findings/{finding_id}/status` |
| GET | `/api/v1/findings` (finding-field extraction only; no git re-read) |
| GET | `/api/v1/pr/{owner}/{repo}/{pr_number}/context` |
| GET | `/api/v1/approvals/{owner}/{repo}/{pr_number}` |
| POST | `/api/v1/approvals/{owner}/{repo}/{pr_number}` |
| POST | `/api/v1/triage/antares` |
| POST | `/api/v1/changes/{owner}/{repo}/{pr_number}/plan` (`output_text`) |
| GET | `/api/v1/audit/events` |
| GET | `/api/v1/audit/export` |

### JSON request ingest

| Method | Path |
|--------|------|
| POST | `/api/v1/internal/antares/sandbox-command-audit` (`command`, `output_truncated`) |

### HTML, git host, CLI

| Kind | Surface |
|------|---------|
| html | `/ui/targets/{target_id}` (declared files, snippets, diffs, waiver reasons) |
| html | `/ui/pr/{owner}/{repo}/{pr_number}` (file views, evidence, waiver reasons) |
| html | `/ui/audit` (history payload) |
| html | `/ui/investigations/{id}` and `/trace` (candidate paths, command, output) |
| html | `/ui/coverage` — handler-coverage.json only (no live config text) |
| outbound | Forgejo PR comment — handler description/evidence; advisory omitted |
| outbound | Forgejo commit status — gate reason strings; no finding bodies |
| download | `/api/v1/audit/export` |
| cli | `./shift-left status` — prerequisite health only |

Foundation-Sec `/v1/analyze` receives raw hunks as inference input (not a presentation surface). Application logs must not echo finding body fields (`test_secret_log_guard.py` on the model server). Waiver `reason` is operator free text, redacted in HTML and audit JSON via `redact_display_text` / `redact_audit_value`.

## Value-based redaction

At parse time (or per-file scan before display), secret **values** are collected into `SecretValueSet` on parse results and file views — never stored in findings.

1. **Unambiguous literals** — replaced everywhere (word-boundary) in config lines and prose.
2. **Ambiguous literals** — common English words / defaults (see below). On config lines they are always replaced. In prose they are replaced only when:
   - inside matching quotes or backticks (`"public"`, `'admin'`, `` `secret` ``), or
   - adjacent to a credential keyword within four words (`community`, `password`, `secret`, `key`, `psk`).
3. **Ambiguous list** (`AMBIGUOUS_SECRET_VALUES` in `secret_values.py`): `public`, `private`, `cisco`, `admin`, `secret`, `password`, `manager`, `monitor`. Classification: exact case-insensitive match after length/numeric eligibility checks.

`redact_display_text` also applies the ambiguous-default prose gates for the full ambiguous list even when no `SecretValueSet` is available (safety net when git-backed resolution fails).

### Skipped values (short / numeric-only)

Values shorter than 3 characters or numeric-only (e.g. SNMP community `1`) are recorded in `SecretValueSet.skipped` with an explicit reason and are **not** literal-replaced.

**Prose policy (accepted residual risk):** directive-pattern redaction covers config evidence lines; skipped values are too generic for safe literal or prose replacement. Model prose that paraphrases a single-digit community string without a credential keyword is extremely rare. Operators should treat any unredacted skipped literal in prose as low sensitivity. No additional prose pattern is applied for skipped values.

## Secret value provenance at render time

| Surface | How `secret_values` are obtained |
|---------|----------------------------------|
| `GET /api/v1/findings/{owner}/{repo}/{pr_number}` | **Re-read** `finding.file_path` at `finding.commit_sha` via git (`resolve_secret_values_for_finding`), merged with values extracted from the finding's own `evidence` / `description` / `model_context`. Response includes `value_redaction_provenance` when git resolution fails or is partial. |
| Forgejo PR comment (`_format_comment`) | Same git re-read at each finding's `commit_sha` before formatting (via `build_secret_index_for_findings`). Review runs at current HEAD but findings carry their recorded SHA. |
| PR review UI / live review API | Current diff `file_views` carry per-file `secret_values` from the in-memory diff text. |
| Target detail UI | Declared HEAD config files include `secret_values` from `build_static_file_view` (git fetch at declared HEAD). |
| Sync `serialize_findings_for_api` (list endpoint) | Finding-field extraction only — no git re-read. |

When git cannot resolve the file at the recorded SHA, provenance `source` is `finding_fields` or `unavailable` and a `message` explains the limitation. Directive and ambiguous-default prose patterns still apply so model prose is not silently leaked.

## Tests

- `tests/test_config_redaction.py` — patterns, ambiguous gating, enumeration guard
- `tests/test_outbound_secret_redaction.py` — API route registry, findings API, provenance, PR comments, waiver text, logs
- `tests/test_ui_target_detail_view.py` — UI tab redaction (Configuration, Changes, Findings)
- `services/foundation-sec-server/tests/test_secret_log_guard.py` — model server log guard
