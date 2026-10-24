# pkginspect

PKGBUILD security analyzer for Arch Linux. It scores packages from `0-100` using rule-based checks.

## Installation

`pkginspect` is **not** published on PyPI. Install it from GitHub:

```bash
# run without installing
uvx --from git+https://github.com/Constadine/pkginspect pkginspect yay

# or install as a user tool
uv tool install git+https://github.com/Constadine/pkginspect
pkginspect yay
```

> ⚠️ Don't run `uvx pkginspect` / `uv tool install pkginspect` / `pip install pkginspect`. If a package with that name shows up on PyPI, it is not this project, and you would be running a stranger's code.

### Run from this repo (development)

```bash
uv sync
uv run pkginspect yay
```

## Usage

Bare names are AUR packages.

```bash
pkginspect yay                          # check one AUR package
pkginspect yay paru                     # several at once, with a summary table
pkginspect yay --deps                   # also check its AUR dependencies
pkginspect --official bash              # a package from the official repos
pkginspect --file ./PKGBUILD            # a local PKGBUILD...
pkginspect --file ~/.cache/paru/clone/foo   # ...or a whole directory (paru/yay clone dir)
pkginspect --url https://example.com/PKGBUILD   # a raw PKGBUILD URL
pkginspect yay --json                   # JSON (one target: object; several or --deps: array)
pkginspect foo --fail-under 70 && paru -S foo   # use in a script
```

Other options: `--rules PATH` (custom `rules.yaml`), `-d/--debug`, `--version`.

**Exit codes**: `0` ok, `1` a package scored below `--fail-under` or a fetch/analysis failed, `2` usage error.

Example output (`NO_COLOR=1` strips the colors):

```text
🟠 tests/fixtures/moderate.PKGBUILD 2.3-1 (file) — 50/100 Fair
   sources: example.com (http), example.com, github.com/example (git)

   -30  SKIP used in checksums for 1 downloaded file(s)
        PKGBUILD:9  source=("http://example.com/moderate-pkg-${pkgver}.tar.gz"
   -10  1 unverified source(s) fetched over plain HTTP/FTP
        PKGBUILD:9  source=("http://example.com/moderate-pkg-${pkgver}.tar.gz"
   -10  Unpinned VCS source in a non-VCS package
        PKGBUILD:11  "git+https://github.com/example/repo")
```

For AUR packages the header also shows maintainer, votes, popularity, first-submitted date (with "N days ago" for new packages), last update, the out-of-date flag, and where the sources come from. Every finding shows `file:line` evidence.

## What it checks

For AUR packages pkginspect downloads the repo snapshot, so it scans more than the PKGBUILD:

- **PKGBUILD**: checksums, sources, metadata and all build code (split packages work).
- **Install scripts (`*.install`)**: run as **root** by pacman, so they are scanned for dangerous patterns too.
- **Other files**: pacman hooks, helper scripts, systemd units and patches are scanned for the most serious patterns (pipe-to-shell, reverse shells, persistence, obfuscation, suspicious hosts).

Metadata arrays (`depends`, `optdepends`, ...) and plain `echo` messages don't trigger command rules. Mistyped names get suggestions.

## Rules and weights (from `rules.yaml`)

| Category | Rule | Δ Score | Rationale |
|---|---|---:|---|
| **Integrity** | `missing_checksums` | −30 | Sources but no checksum array: no integrity check. |
|  | `skip_checksum_some` | −30 | `SKIP` on some downloads (VCS sources, signature, local and `file://` files may `SKIP`; a `SKIP` file with a signature source and `validpgpkeys` counts as verified). |
|  | `skip_checksum_all` | −50 | Every download is unverified. |
|  | `skip_checksum_docs` | −5 | `SKIP` on documentation-only downloads (`.html`, `.txt`, `.pdf`, `LICENSE`, ...). |
|  | `weak_hash` | −5 | Only `md5`/`sha1` used (sha256 is fine; all-`SKIP` arrays are ignored). |
| **Transport** | `insecure_url` | −10 | Per `http://`/`ftp://` source that nothing verifies (checksummed ones are fine). |
|  | `git_unpinned` | −10 | Unpinned VCS source in a package that is not a `-git` package. |
|  | `suspicious_host` | −25 | Raw IP, paste/temp-file site, URL shortener, Discord CDN, tunnel or dynamic DNS. |
| **Execution** | `pipe_to_shell` | −30 | `curl \| sh`, `bash <(curl ...)`, `eval "$(curl ...)"`: remote code run directly. |
|  | `eval_exec` | −15 | `eval`, `sh -c` / `bash -c`: dynamic execution. |
|  | `obfuscation` | −25 | `base64 -d`, `xxd -r`, `openssl enc -d`, `\x` escapes, big base64 blobs. |
|  | `ld_preload` | −20 | `LD_PRELOAD=` can inject code into other programs (an empty value or the fakeroot library is fine). |
|  | `reverse_shell` | −50 | `/dev/tcp`, `nc -e`, `socat exec:`, `bash -i >&`, ... (also a blocker). |
|  | `persistence` | −30 | cron, `authorized_keys`, shell rc files, autostart, sudoers. |
|  | `persistence_service` | −10 | `systemctl enable` (start/stop/restart/disable are fine). |
|  | `tmp_usage` | −5 | Hardcoded `/tmp/` paths (predictable temp files). |
| **Privilege / build networking** | `network_fetch` | −15 | `curl`, `wget`, `git clone` in build code (also flagged in install scripts). |
|  | `sudo_or_pacman` | −25 | `sudo`/`doas`/`pkexec`/`su -c`, `pacman -S/-U/-R/-D` (also a blocker). |
|  | `privilege_escal` | −10 | Writes outside `$pkgdir` or into your home directory (the former is also a blocker). |
|  | `setuid_bit` | −10 | `chmod u+s` / `g+s` / `4755`, `setcap`, `chmod 777` (a Chromium/Electron `*-sandbox` helper is only noted). |
| **Metadata** | `no_license` | −3 | No `license=()`. |
|  | `no_arch_field` | −2 | No `arch=()`. |
|  | `no_maintainer_tag` | −2 | No `# Maintainer:` comment (skipped when the AUR lists a maintainer). |
| **Static analysis** | `namcap_error` | −5 | Per `namcap` error (only for local `--file` targets, if `namcap` is installed). |
| **Community (AUR)** | `aur_low_votes_1` | −2 | 15-29 votes. |
|  | `aur_low_votes_2` | −5 | 1-14 votes. |
|  | `aur_low_votes_3` | −15 | 0 votes. |
|  | `aur_orphaned` | −8 | No maintainer. |
|  | `aur_out_of_date` | −10 | Flagged out of date for 30 days or more. |
|  | `aur_out_of_date_recent` | −2 | Flagged out of date less than 30 days ago. |
|  | `aur_new_package` | −15 | First submitted less than 30 days ago. |
|  | `aur_very_new_package` | −25 | First submitted less than 7 days ago (replaces the one above). |

**Informational (0 points)**: the report also notes when a package has an install script, a pacman hook, or is a VCS package (builds the latest upstream commit), when an install script modifies system files, when a setuid sandbox helper is installed, and when the source array is built dynamically or its checksums cannot be matched to sources, so you know what to read.

> 🔒 **Blockers** (score forced to 0): `uses_sudo` (sudo/doas/pkexec or write-mode `pacman` in the build), `writes_outside_pkgdir` (the actual destination is checked), `reverse_shell`.

> 🧢 **Category Caps**:
> - Integrity: max −50
> - Transport: max −30
> - Execution: max −50
> - Privilege: max −40
> - Metadata: max −25
> - Community: max −40

A `rules.yaml` is searched in this order: `--rules`, `$PKGINSPECT_RULES`, `./rules.yaml`, `$XDG_CONFIG_HOME/pkginspect/rules.yaml` (default `~/.config`), then the bundled one. User files are merged over the bundled defaults, so you only need to list what you change.

## Limitations

pkginspect is a regex/heuristic scanner, not a bash parser or a sandbox. A determined attacker can evade it, and a high score is not a guarantee. Always read the PKGBUILD and any `.install` file before installing. The contents of the upstream tarballs/binaries the PKGBUILD downloads are not analysed.
