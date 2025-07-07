# Current Rule Set & Weights (From `rules.yaml`)

| Category                    | Rule / Logic                                        | Δ Score | Rationale                                                  |
|----------------------------|------------------------------------------------------|---------|-------------------------------------------------------------|
| **Integrity of sources**   | Missing any checksum array                           | −30     | No hash = no integrity check.                              |
|                            | At least one checksum is `SKIP`                      | −30     | Some sources are unverified.                               |
|                            | All checksums are `SKIP`                             | −50     | Entire source unverified.                                  |
|                            | Weak hash (`md5` or `sha256` instead of strong hash) | −5      | Weaker to collision attacks.                               |
| **Transport security**     | URL starts with `http://` or `ftp://`                | −10     | Susceptible to MITM.                                       |
|                            | VCS source unpinned (`git+https` without tag/commit) | −10     | Floating version = non-reproducible.                       |
| **Build-time net/privilege** | `curl` or `wget` in build steps                    | −15     | Downloads unvetted content during build.                   |
|                            | Calls to `sudo` or `pacman`                          | −25     | Should not require root/package manager.                   |
|                            | Privilege escalation (`setcap`, `chmod 777`, etc.)   | −10     | Unsafe permission changes.                                 |
| **Metadata hygiene**       | `license=()` is missing                              | −3      | Required metadata absent.                                  |
|                            | `arch=()` is missing                                 | −2      | Architecture unspecified.                                  |
|                            | `# Maintainer:` tag is missing                       | −2      | No traceability of maintainer.                             |
| **Static analysis (namcap)** | Each `namcap` error                                | −5      | Reported lint issue from official tool.                    |
| **Community**              |   Low vote number L1                                 | -2      | 30-100 votes                                               |
|                            |   Low vote number L2                                 | -5      | 15-30 votes                                                |
|                            |   Low vote number L3                                 | -15     | 0 votes                                                    |
|                            |   Orphan package                                     | -8      | No maintainer                                              |
|                            |   Out of date package                                | -10     | Flagged OOD                                                |

> 🔒 **Blockers**: If `uses_sudo` or `writes_outside_pkgdir` is true, the score is forcibly set to 0.

> 🧢 **Category Caps**:  
> - Integrity: max −50  
> - Transport: max −30  
> - Privilege: max −40  
> - Metadata: max −25  
> - Community:  -20

