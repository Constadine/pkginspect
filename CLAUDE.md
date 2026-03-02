# pkginspect

PKGBUILD security analyzer for Arch Linux. Scores packages 0-100 using rule-based analysis.

## Architecture

After refactoring (see plan), the source layout is:

```
src/pkginspect/
  cli.py        – argparse + main() orchestration
  fetchers.py   – HTTP fetchers (AUR, official repos, generic URL)
  scoring.py    – score_pkgbuild(), all detection regexes
  rules.py      – load_rules(), RulesConfig dataclass
  output.py     – text/JSON/color formatting
  rules.yaml    – weights, caps, blockers config
```

Entry point: `pkginspect = "pkginspect.cli:main"` (defined in pyproject.toml).

## Conventions

- **Package manager**: `uv` (never pip/poetry). Run with `uv run pkginspect`.
- **Formatting**: `ruff format` via pre-commit hook.
- **Dependencies**: Keep minimal — only `requests` and `pyyaml` for core. Dev deps in `[dependency-groups] dev`.
- **No ML code in main**: The ML pipeline (aurscraper, build_dataset, train_xgb) lives on a separate branch. Do not add pandas/xgboost/scikit-learn to core dependencies.
- **Python**: >=3.8 compatibility (use `from __future__ import annotations`).

## Scoring Engine

- Starts at 100, applies negative penalties per finding.
- Each category (integrity, transport, privilege, metadata, community, execution) has a cap (max penalty floor).
- Blockers (sudo in build, writes outside $pkgdir) force score to 0.
- Rules are configurable via `rules.yaml` (searched: CLI arg → env var → cwd → XDG_CONFIG_HOME → bundled).
- Comment stripping: full-line comments are removed before risky-rule scanning to avoid false positives.

## Detection Rules (current + planned)

Existing: checksums, SKIP, weak hashes (md5/sha1 only), insecure URLs, git unpinned, curl/wget, sudo/pacman, privilege escalation, metadata fields, AUR community metrics.

Planned additions (in priority order):
1. Pipe-to-shell (`curl|sh`, `source <(curl...)`) — -30
2. Base64/obfuscation decode — -25
3. LD_PRELOAD injection — -20
4. eval/exec, bash -c / sh -c — -15
5. setuid/setgid bit manipulation — -10
6. Predictable /tmp usage — -5

## Testing

Run: `uv run pytest`
Fixtures in `tests/fixtures/` — clean, moderate, and malicious PKGBUILDs.

## Workflow

- One feature per branch, small PRs.
- Verify manually after changes: `pkginspect --aur paru`, `pkginspect --official bash`.
- Pre-commit hooks must pass (ruff-format, gitleaks, uv-lock).

## Key Decisions

- sha256 is NOT flagged as weak (only md5, sha1).
- Focus on rule-based scoring; ML is deferred.
- Personal tool shared with friends — keep it simple, no over-engineering.
