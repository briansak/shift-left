# Forgejo identity mapping

This document explains why the Shift-Left UI does not create branches, commits, or PRs through the shared Forgejo token. Operators who want per-user git attribution should read it. The mapping is not implemented; merge and comment posting stay in Forgejo.

The orchestrator authenticates to Forgejo with a single shared `FORGEJO_TOKEN`
(service account). Any write performed through that token is attributed to the
service account in Forgejo — not to the human operator using the Shift-Left UI.

Separation of duties resolves commit authorship from Forgejo (`get_commit_author`).
If users could create branches, commits, or pull requests through the shared
token, every author would appear as the service account and the
author-cannot-approve control would be silently defeated.

**Read-heavy embedding is implemented in the UI.** Merge, comment posting, PR
creation, and branch operations remain in Forgejo (deep-linked from the UI).

## What per-user Forgejo identity would require

1. **Map app API tokens to Forgejo users** — each Shift-Left UI/API token carries
   an `actor` identity; that actor must map to a Forgejo login for attribution.

2. **Per-user Forgejo credentials** — either:
   - OAuth/OIDC flow against Forgejo so each operator authorizes their own token, or
   - Operator-provisioned Forgejo PATs stored encrypted per user in the orchestrator.

3. **Write path audit on both sides** — Shift-Left audit log records
   `(actor, action)` while Forgejo records `(forgejo_user, git object)`; both
   must agree for compliance.

4. **Scoped tokens** — write scopes limited to review comments or branch creation,
   not admin, to preserve least privilege.

5. **No shared-token writes from UI** — until the above exists, the UI renders
   deep links to Forgejo instead of controls that would use `FORGEJO_TOKEN`.

## API endpoints used for read embedding (Forgejo API v1)

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| Open PR list | `GET /api/v1/repos/{owner}/{repo}/pulls?state=open` | Gitea-compatible |
| PR detail | `GET /api/v1/repos/{owner}/{repo}/pulls/{index}` | |
| PR diff | `GET /api/v1/repos/{owner}/{repo}/pulls/{index}.diff` | |
| PR commits | `GET /api/v1/repos/{owner}/{repo}/pulls/{index}/commits` | |
| PR comments | `GET /api/v1/repos/{owner}/{repo}/issues/{index}/comments` | Read-only in UI |
| Commit statuses | `GET /api/v1/repos/{owner}/{repo}/statuses/{sha}` | Compare to orchestrator gate |
| Branch protection | `GET /api/v1/repos/{owner}/{repo}/branch_protections/{branch}` | Gate bypass warning |
| Action runners | `GET /api/v1/admin/actions/runners` (also legacy `GET /api/v1/admin/runners` on some builds) | Admin scope; queue health |

**Forgejo 11.0.x note:** Runner *list* routes may return HTTP 404 even when Actions works. Registration uses `GET /api/v1/admin/runners/registration-token` on 11.0.16. The UI suppresses the queue warning when `data/forgejo-runner/.runner` exists locally.

**Version dependency:** Tested against Forgejo 11.x / Gitea API v1. Commit status
payload field names (`status` vs `state`) may vary — the embed layer normalizes both.
If queue health looks wrong, inspect runner list vs `data/forgejo-runner/.runner` first.
