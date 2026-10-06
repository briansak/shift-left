# Git backends

This document is for operators choosing where customer repositories live. Tool source stays on GitHub; customer repos default to bundled Forgejo. Architecture: [architecture.md](architecture.md).

| Context | Host | Contents |
|---------|------|----------|
| **Tool source** | GitHub (open source) | This pipeline's code, releases, issues |
| **Customer data** | Configured `git.backend` | Repos, PRs/MRs, branch protection, reviewed code and configs |

The **sovereign default** bundles **Forgejo** on the local host via Docker Compose. Customer repositories live there and **never leave the organization** during review.

## Backends

| `git.backend` | Customer repos | Sovereign | Use when |
|---------------|----------------|-----------|----------|
| `bundled-forgejo` (default) | Local Forgejo/Gitea | **Yes** | Data sovereignty required |
| `github` | GitHub.com / GHE | **No** | Existing GitHub org, sovereignty not required |
| `gitlab` | GitLab.com / self-managed | **No*** | Existing GitLab org, sovereignty not required |

\*Self-managed GitLab on your network reduces exposure but the orchestrator still calls GitLab's API; treat as non-sovereign unless GitLab is entirely on-host **and** you accept API transit of diffs/comments.

## Interface

All backends implement `GitBackend` (`services/orchestrator/shift_left/git/protocol.py`):

- `get_pull_request(owner, repo, pr_number)`
- `get_pull_diff(owner, repo, pr_number)`
- `post_pull_request_comment(owner, repo, pr_number, body)`
- `get_commit_author(owner, repo, commit_sha)` — used for separation of duties
- `health()`
- `is_sovereign` — whether customer review I/O stays on the installed host

Factory: `create_git_backend(config)` in `git/factory.py`.

## Sovereign default (bundled Forgejo)

```yaml
git:
  backend: bundled-forgejo
  external_sovereignty_acknowledged: false
  bundled:
    provider: forgejo
    url: http://forgejo:3000
    token_env: FORGEJO_TOKEN
```

- Customer code, configs, diffs, findings, and PR comments stay on the **local host**
- Forgejo Actions + `forgejo-runner` trigger reviews on PR events
- Compose `sovereign_internal` network blocks general internet egress
- Runtime verification: `./scripts/shift-left verify-runtime`

Forgejo is Gitea API-compatible. The bundled image is Forgejo 11, which includes Actions.

## Optional: GitHub

```yaml
git:
  backend: github
  external_sovereignty_acknowledged: true   # required
  github:
    api_url: https://api.github.com
    token_env: GITHUB_TOKEN
```

Set `GITHUB_TOKEN` with `repo` scope (comment posting needs pull-request write). Minimum scopes are not further reduced in this repo.

### Sovereignty tradeoffs

When using GitHub, **customer analyzed artifacts egress** to GitHub at review time:

| Data | Bundled Forgejo | GitHub backend |
|------|------------------|----------------|
| PR diff hunks | Fetched from local Forgejo API | Fetched from `api.github.com` |
| Review comments | Posted to local Forgejo | Posted to GitHub |
| Findings store | Local SQLite on host | Local SQLite on host |
| Model inference | Local (if models on-host) | Local (if models on-host) |

**What you keep local:** model weights, findings database, reference data cache, inference compute (when configured on-host).

**What leaves the host:** PR diff text fetched from GitHub's API; handler findings posted back as PR comments (advisory findings are omitted by default — [gate-enforcement.md](gate-enforcement.md)).

**What you lose:**

- Air-gap runtime with blocked egress (orchestrator must reach GitHub API)
- `./scripts/shift-left verify-runtime` full-sovereignty mode (use bundled git for that test)
- Guarantee that customer source never transits a third party

You must set `git.external_sovereignty_acknowledged: true`. Startup fails otherwise.

Wire CI separately (GitHub Actions calling your orchestrator). The Compose stack does not bundle GitHub Actions.

## Optional: GitLab

```yaml
git:
  backend: gitlab
  external_sovereignty_acknowledged: true
  gitlab:
    api_url: https://gitlab.com/api/v4
    token_env: GITLAB_TOKEN
```

Merge request diffs are retrieved via `/merge_requests/:iid/changes` and synthesized into unified diff text.

Tradeoffs mirror GitHub: customer diffs and MR notes traverse GitLab's API. Self-managed GitLab on a private network is a partial mitigation but still not the bundled sovereign default.

## Orchestrator networking

HTTP clients allowlist only:

- Local services (Forgejo, model servers, postgres, …)
- Plus the configured git API hostname when using `github` or `gitlab`

No general internet access. External git backends add **only** their API host to the allowlist — not a blanket egress permit.

## Migration from `forgejo:` config key

Legacy configs with top-level `forgejo:` are auto-migrated to `git.bundled` at load time. Prefer the `git:` section in new deployments.

## Choosing a backend

```
Need customer code to never leave the host?
  └─ Yes → bundled-forgejo (default)
  └─ No  → github or gitlab + external_sovereignty_acknowledged: true
            └─ Read tradeoff table above
            └─ Keep models and findings store local for partial sovereignty
```
