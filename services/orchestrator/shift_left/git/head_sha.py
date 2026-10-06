"""Live head SHA verification — decision points must not trust cached PR metadata."""

from __future__ import annotations

from shift_left.git.protocol import GitBackend


def pr_number_from_ref(pr_ref: str) -> int:
    if not pr_ref.startswith("PR-"):
        raise ValueError(f"Invalid pr_ref: {pr_ref!r}")
    suffix = pr_ref.removeprefix("PR-")
    if not suffix.isdigit():
        raise ValueError(f"Invalid pr_ref: {pr_ref!r}")
    return int(suffix)


def split_repo_slug(repo: str) -> tuple[str, str]:
    owner, _, name = repo.partition("/")
    if not name:
        raise ValueError(f"Invalid repo slug: {repo!r}")
    return owner, name


async def fetch_live_head_sha(git: GitBackend, *, repo: str, pr_number: int) -> str:
    """Fetch current PR head SHA from Forgejo (never cached)."""
    owner, name = split_repo_slug(repo)
    pr = await git.get_pull_request(owner, name, pr_number)
    sha = (pr.get("head") or {}).get("sha")
    if not sha:
        raise ValueError("Forgejo did not return a head SHA for this pull request.")
    return sha


async def assert_head_sha_unchanged(
    git: GitBackend,
    *,
    repo: str,
    pr_number: int,
    rendered_sha: str,
) -> None:
    """
    Refuse when the branch moved since the UI/API rendered a commit SHA.

    Does not silently act on the newer SHA.
    """
    live = await fetch_live_head_sha(git, repo=repo, pr_number=pr_number)
    if live != rendered_sha:
        raise ValueError(
            f"Branch head moved to {live[:7]} since this view was rendered "
            f"({rendered_sha[:7]}). Refresh the page and retry — approval was not recorded."
        )
