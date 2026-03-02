# pkginspect

PKGBUILD security analyzer for Arch Linux. It scores packages from `0-100` using rule-based checks.

## Installation and Usage

### Run without installing (recommended quick start)

```bash
uvx pkginspect --aur paru
uvx pkginspect --official bash
```

### Install as a user tool

```bash
uv tool install pkginspect
pkginspect --aur paru
pkginspect --official bash
```

### Run from this repo (development)

```bash
uv sync
uv run pkginspect --aur paru
uv run pkginspect --official bash
```

## Current Rule Set & Weights (From `rules.yaml`)

| Category | Rule / Logic | Δ Score | Rationale |
|---|---|---:|---|
| **Integrity of sources** | Missing any checksum array | −30 | No hash means no integrity check. |
|  | At least one checksum is `SKIP` | −30 | Some sources are unverified. |
|  | All checksums are `SKIP` | −50 | Entire source set is unverified. |
|  | Weak hash (`md5` or `sha1`) | −5 | More collision-prone than modern hashes. |
| **Transport security** | URL starts with `http://` or `ftp://` | −10 | Susceptible to MITM/tampering. |
|  | VCS source unpinned (`git+https` without tag/commit) | −10 | Floating source hurts reproducibility. |
| **Execution (dangerous patterns)** | Pipe-to-shell (`curl|sh`, `source <(curl ...)`) | −30 | Direct remote execution is high risk. |
|  | Base64/binary decode (`base64 -d`, `xxd -r`) | −25 | Can hide payload intent. |
|  | `LD_PRELOAD`/`LD_LIBRARY_PATH` manipulation | −20 | Can alter runtime behavior/inject code. |
|  | `eval`/`exec` or `sh -c` / `bash -c` | −15 | Increases dynamic execution risk. |
| **Build-time net/privilege** | `curl` or `wget` in build steps | −15 | Downloads unvetted content during build. |
|  | Calls to `sudo` or write-mode `pacman` | −25 | Build should not require root/package writes. |
|  | Privilege escalation patterns (`chmod ...+s`, `setcap`, etc.) | −10 | Unsafe permission/capability changes. |
| **Metadata hygiene** | `license=()` is missing | −3 | Required metadata absent. |
|  | `arch=()` is missing | −2 | Architecture unspecified. |
|  | `# Maintainer:` tag is missing | −2 | Reduced traceability. |
| **Static analysis (namcap)** | Each `namcap` error | −5 | Official linting reported an issue. |
| **Community (AUR)** | Low vote number L1 (`15-29` votes) | −2 | Lower trust signal. |
|  | Low vote number L2 (`1-14` votes) | −5 | Low trust signal. |
|  | Low vote number L3 (`0` votes) | −15 | No community validation. |
|  | Orphan package | −8 | No active maintainer. |
|  | Out-of-date package | −10 | Flagged stale by community. |

> 🔒 **Blockers**: If `uses_sudo` is true, if write-mode `pacman` commands are detected, or if `writes_outside_pkgdir` is true, the score is forced to 0.

> 🧢 **Category Caps**:
> - Integrity: max −50
> - Transport: max −30
> - Execution: max −50
> - Privilege: max −40
> - Metadata: max −25
> - Community: max −20
