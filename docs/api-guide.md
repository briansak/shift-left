# HTTP API guide

This is the narrative companion to the generated OpenAPI spec for people automating reviews (CI, scripts) and for anyone wiring the local UI. Browse the spec: [OpenAPI explorer](index.html) (Try it out disabled) · machine-readable [openapi.yaml](openapi.yaml) / [openapi.json](openapi.json). Token capabilities: [auth-tokens.md](auth-tokens.md).

The hosted explorer cannot reach the API. On the operator host the server is `http://127.0.0.1:8080`. JSON unless noted. Errors use HTTP status plus `{"detail": "..."}` (FastAPI default).

There is no Forgejo webhook path on the orchestrator. Actions jobs call `POST /api/v1/review` with a review-capable bearer token. Unauthenticated: `GET /health`, `GET /self-check`.

## Authentication

Send `Authorization: Bearer slt_…` or `X-Shift-Left-Token: slt_…`. Identity is the token's `actor`. JSON bodies must not include `actor` or `approver`.

| Audience | Endpoints |
|----------|-----------|
| Automation | `/health`, `/self-check`, `/api/v1/review`, findings, policy, approvals, waivers, gate, investigations, audit export |
| UI-facing | `/ui/*` (HTML) and `/api/v1/me`, `/api/v1/pr/.../context`, `/api/v1/system/*`, `/api/v1/findings` (filtered list), `/api/v1/changes` |
| Internal | `POST /api/v1/internal/antares/sandbox-command-audit` (`slat_…` callback) |

Refresh the spec after route changes:

```bash
make docs-openapi
```

That writes `docs/openapi.yaml` and `docs/openapi.json` from the FastAPI app (`scripts/generate-openapi.py`). `services/orchestrator/tests/test_openapi_spec.py` fails if the committed files drift.

## Pagination

`GET /api/v1/audit/events` and `GET /api/v1/findings` take `limit` (default 200, max 1000). There is no cursor. `GET /api/v1/audit/export` returns the full log.

## Advisory findings

`POST /api/v1/review` omits advisory (model-only) findings and `review_summary` when `advisory_suppression.omit_from_review_api` is true (default). The same omission applies to Forgejo PR comments (`omit_from_pr_comments`).

Retrieve advisory findings from:

- `GET /api/v1/findings/{owner}/{repo}/{pr_number}`
- `GET /api/v1/pr/{owner}/{repo}/{pr_number}/context` (`model_only_findings`)
- the PR page at `/ui/pr/{owner}/{repo}/{n}`

Handler findings (`source=handler` / `code-handler`, trace `handler:RULE-ID`) remain on the review response and drive policy.

## Review request and response

```json
POST /api/v1/review
{
  "owner": "example-org",
  "repo": "example-configs",
  "pr_number": 42,
  "commit_sha": "0000000000000000000000000000000000000000",
  "skip_advisory": false
}
```

`commit_sha` is optional; the git backend supplies HEAD when omitted. `skip_advisory=true` skips Foundation-Sec inference (handlers still run).

Response shape (fields of `ReviewResult`; advisory findings stripped by default):

```json
{
  "repo": "example-org/example-configs",
  "pr_ref": "PR-42",
  "commit_sha": "0000000000000000000000000000000000000000",
  "findings": [
    {
      "id": "00000000-0000-4000-8000-000000000001",
      "source": "handler",
      "target_kind": "config",
      "file_path": "terraform/policies/edge.tf",
      "handler_asserted_cwe": "CWE-284",
      "policy_severity": "high",
      "title": "Deterministic rule: TF-001",
      "trace": "handler:TF-001",
      "construct_key": "rule:EXAMPLE-INGRESS:seq:0",
      "status": "open"
    }
  ],
  "policy_decision": {
    "pr_decision": "block",
    "commit_sha": "0000000000000000000000000000000000000000",
    "explanation": "One handler finding matched a BLOCK policy."
  },
  "advisory_action": "flag",
  "message": "1 advisory finding(s) omitted from this response (omit_from_review_api).",
  "review_summary": null,
  "stage_timings_ms": {}
}
```

Policy uses `handler_asserted_cwe` only. `model_asserted_cwe` never blocks a merge.

## How the objects relate

```
review ──► findings (SQLite)
        └─► policy_decision (SHA-bound)
              ├─ waivers (path + construct_key + weakness_class, SHA-bound)
              ├─ approval (SHA-bound)
              └─ gate.allowed (commit status shift-left/gate)

investigations ──► LocalizationResult (never a Finding, never policy input)
```

A new commit SHA invalidates approvals and waivers. Line numbers are display-only.

## Worked example

Mint a token that can review, approve, and waive:

```bash
./shift-left token mint --label ci --actor ci --capabilities review,approve
```

Assume the orchestrator is up, Forgejo has `example-org/example-configs` PR 42, and `TOKEN` is the `slt_…` value printed once.

**1. Review**

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/review \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"owner":"example-org","repo":"example-configs","pr_number":42}'
```

Note `commit_sha` and a blocking finding `id` / `trace`.

**2. Gate**

```bash
curl -sS "http://127.0.0.1:8080/api/v1/gate/example-org/example-configs/42?commit_sha=HEADSHA" \
  -H "Authorization: Bearer $TOKEN"
```

`allowed` is false until policy is pass/flag **and** a valid SHA-bound approval exists (and analysis is complete).

**3. Waiver** (optional; BLOCK registry rules need `approve`)

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/waivers/example-org/example-configs/42 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"commit_sha":"HEADSHA","finding_id":"FINDING-ID","reason":"accepted residual on lab ACL"}'
```

**4. Re-read policy decision** (waivers applied when `commit_sha` is passed)

```bash
curl -sS "http://127.0.0.1:8080/api/v1/policy/decision/example-org/example-configs/42?commit_sha=HEADSHA" \
  -H "Authorization: Bearer $TOKEN"
```

Then grant approval (`POST /api/v1/approvals/...`) with the same `commit_sha` and call gate again. Branch protection on the git host is what turns `shift-left/gate` into merge control — [gate-enforcement.md](gate-enforcement.md).

Investigations are a separate queue: `POST /api/v1/investigations` with `repo`, `ref`, and `task_cwe`. See [antares-triage.md](antares-triage.md).
