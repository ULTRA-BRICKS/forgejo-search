# Checkpoint: search-code-acl (2026-09-27)

## Scope
Add `ForgejoAuth.code_readable_repositories(cookie, repos)` (native
`reqRepoCodeReader`/`unit.TypeCode` check via `/{owner}/{repo}/search`), wire a
`code_allowed` scope through `search()`, and narrow `server.py` AFTER the
empty-query fast path. Fix two bugs from the stale reference draft:
1. `_CODE_DENIED_STATUSES` must be `{404}` only — 403 => VisibilityUnavailable.
2. code-ACL narrowing must run AFTER the empty-query early return, not before.

## Base
Worktree `.worktrees/fix-search-code-read-acl`, branch
`fix/search-code-read-acl`, based on `origin/main@76c0589` (confirmed via
`git log --oneline -3` showing 76c0589 at HEAD).

## Baseline (before any change)
- `uv run ruff check src tests` -> All checks passed (see
  /tmp/search-acl-baseline-ruff.log)
- `uv run pytest -q` -> 56 passed (see /tmp/search-acl-baseline-pytest.log)

## Plan
1. TDD red: add tests to tests/test_auth.py, tests/test_index_search.py,
   tests/test_server.py per brief section 6.
2. auth.py: add `code_readable_repositories`.
3. search.py: add `code_allowed` kwarg / `code_scope` narrowing.
4. server.py: wire in after empty-query check; add total_ms wall latency.
5. cli.py: no change needed (query subcommand keeps defaulting code_allowed=None).
6. README.md: document the code-ACL layer.
7. Green run, ruff clean, review, commit, push, PR, merge, close issue #4.

## Live verification (section 5) — status
Not yet attempted. Will use bread SSH + CDP relay 9223, own new tab only.
Documenting outcome/limitations in the final result doc regardless.

## Progress log
- [x] Worktree created, baseline captured.
- [ ] Tests written (red).
- [ ] Implementation (green).
- [ ] Live verification best-effort.
- [ ] Review, commit, push, PR, merge.
- [ ] Issue closed with proof.
