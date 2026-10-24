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
- Blockers force score to 0: sudo/doas/pkexec or write-mode pacman in build, writes outside $pkgdir (actual destination checked), reverse shell. Writes to the home directory are a finding (privilege_escal, -10) but not a blocker.
- Rules are configurable via `rules.yaml` (searched: CLI arg → env var → cwd → XDG_CONFIG_HOME → bundled).
- Comment stripping: full-line comments are removed before risky-rule scanning to avoid false positives.

## Detection Rules

Weights live in `rules.yaml`; code rules are the `CODE_RULES` table in `scoring.py` (each has scopes: PKGBUILD / `*.install` / aux files).

- Integrity: missing checksums -30, SKIP on some -30 / all -50 (SKIP is fine for VCS, signature, local and file:// sources, or a file with a detached signature plus validpgpkeys; documentation files -5), weak hash (md5/sha1 only, all-SKIP arrays ignored) -5.
- Transport: insecure http/ftp -10 (only when not checksum-verified), git_unpinned -10, suspicious_host -25 (raw IP, paste sites, shorteners, Discord CDN, tunnels).
- Execution: pipe_to_shell -30, obfuscation -25, ld_preload -20 (empty value or fakeroot lib is fine), eval_exec -15, reverse_shell -50 (blocker), persistence -30 (cron, rc files, ...), persistence_service -10 (systemctl enable only), tmp_usage -5. `exec` was dropped from eval_exec and LD_LIBRARY_PATH from ld_preload (false positives).
- Privilege: network_fetch -15, sudo_or_pacman -25, privilege_escal -10 (outside $pkgdir / home dir), setuid_bit -10 (also chmod 777; Chromium/Electron *-sandbox helpers are informational).
- Metadata -3/-2/-2 (maintainer tag skipped when the AUR has a maintainer), namcap -5 per error (local --file only), AUR community (votes, orphaned, out-of-date -10 or -2 under 30 days, new package -15 under 30 days / -25 under 7 days).
- Informational (0 pts): install script, install script modifies system files, pacman hook, VCS package, setuid sandbox helper, dynamic sources, unpaired SKIP.
- Metadata arrays (depends etc.) and pure echo lines don't trigger command rules.

## Fetching and scanning scope

- The AUR fetch downloads the repo snapshot tarball (in memory), so `.install` scripts (run as root), pacman hooks, helper scripts, systemd units and patches are scanned, not only the PKGBUILD.
- Fetchers return `Package` objects with `.error` set instead of raising; the CLI reports them and exits 1.
- Every finding carries file:line evidence.

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
