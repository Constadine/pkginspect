from __future__ import annotations

import dataclasses
import pathlib
import re
import subprocess
import time
from collections import defaultdict
from typing import List, Tuple

from pkginspect.rules import RulesConfig

# ── regexes ──────────────────────────────────────────────────────
# Matches sha256sums=, sha256sums_x86_64=, b2sums_aarch64=, etc.
CHECK_RE = re.compile(
    r"^\s*(sha(?:1|224|256|384|512)sums|md5sums|b2sums)(?:_\w+)?\s*=", re.M
)
URL_RE = re.compile(r'(?:https?|ftp)://[^\s)\'"]+')
CURL_RE = re.compile(r"\b(?:curl|wget)\b")
SUDO_RE = re.compile(r"\bsudo\b")
# Only flag pacman when doing write operations (-S install, -U upgrade, -R remove, -D modify)
# -T (deptest) and -Q (query) are read-only and legitimate in PKGBUILDs
PACMAN_WRITE_RE = re.compile(r"\bpacman\s+(?:[^\n]*\s)?-[SURDsurd]\b", re.M)
SETCAP_RE = re.compile(
    r"\b(?:setcap|chmod\s+[2467][0-7]{3}|chmod\s+[ugo]*\+s|chmod\s+777)\b",
    re.M,
)
WRITE_CMD_RE = re.compile(
    r"^\s*(?:install|cp|mv|mkdir|ln|echo|cat|sed|dd|tee|patch|rm)"
    r"\s+[^\n]*\s/(?:etc|usr|var|lib|bin)/",
    re.M,
)

# New detection patterns
PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|;]*\|\s*(?:ba)?sh\b"
    r"|\bsource\s+<\(\s*(?:curl|wget)\b"
    r"|\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b",
    re.M,
)
EVAL_RE = re.compile(r"\b(?:eval|exec)\s+", re.M)
BASH_C_RE = re.compile(r"\b(?:ba)?sh\s+-c\s+", re.M)
OBFUSCATION_RE = re.compile(r"\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b", re.M)
LD_PRELOAD_RE = re.compile(r"\bLD_PRELOAD\s*=|\bLD_LIBRARY_PATH\s*=", re.M)


@dataclasses.dataclass
class Finding:
    penalty: int
    message: str
    category: str


@dataclasses.dataclass
class ScoringResult:
    score: int
    findings: List[Finding]
    categories: dict[str, int]


def extract_array(name: str, txt: str) -> str:
    """Extract contents of a bash array like source=(...)."""
    m = re.search(rf"^\s*{name}\s*=\s*\((.*?)\)", txt, re.M | re.S)
    return m.group(1) if m else ""


def extract_package_bodies(txt: str) -> list[str]:
    """Extract all package() and package_*() function bodies using brace counting."""
    bodies = []
    for m in re.finditer(r"package(?:_\w+)?\(\)\s*\{", txt):
        start = m.end()
        depth = 1
        i = start
        while i < len(txt) and depth > 0:
            if txt[i] == "{":
                depth += 1
            elif txt[i] == "}":
                depth -= 1
            i += 1
        bodies.append(txt[start : i - 1])
    return bodies


def namcap_errors(p: pathlib.Path | None) -> int | None:
    if p is None:
        return None
    try:
        o = subprocess.run(["namcap", "-i", str(p)], capture_output=True, text=True)
        return o.stdout.count("ERROR")
    except FileNotFoundError:
        return None


def score_pkgbuild(
    lines: List[str],
    *,
    config: RulesConfig,
    local_path: pathlib.Path | None = None,
    aur_meta: dict | None = None,
) -> ScoringResult:
    W = config.weights
    CAP = config.caps
    BLOCK = config.blockers

    score = 100
    cat: dict[str, int] = defaultdict(int)
    findings: List[Finding] = []

    # Remove full-line comments for risky-rule scans
    lines_nc = [l for l in lines if not l.lstrip().startswith("#")]
    txt = "\n".join(lines_nc)

    def note(penalty: int, message: str, bucket: str) -> None:
        cat[bucket] += penalty
        findings.append(Finding(penalty, message, bucket))

    # Integrity ----
    sums_arrays = [m.group(1) for l in lines if (m := CHECK_RE.match(l))]
    if not sums_arrays:
        note(W["missing_checksums"], "No checksum array", "integrity")

    if re.search(
        r"^\s*(?:sha(?:1|224|256|384|512)|md5|b2)sums(?:_\w+)?\s*=\s*\([\s\S]*?\bSKIP\b",
        txt,
        re.M,
    ):
        total = len(re.findall(r'^\s*["\']?https?://', txt, re.M))
        skipped = len(re.findall(r"\bSKIP\b", txt))
        penalty = (
            W["skip_checksum_all"] if skipped == total else W["skip_checksum_some"]
        )
        note(penalty, "SKIP used in checksums", "integrity")
    if any(s.startswith(("md5sums", "sha1sums")) for s in sums_arrays):
        note(W["weak_hash"], "Weak hash (md5/sha1)", "integrity")

    # Transport ----
    source_txt = extract_array("source", txt)
    for url in URL_RE.findall(txt):
        if url.startswith(("http://", "ftp://")):
            note(W["insecure_url"], f"Insecure URL {url}", "transport")
    if "git+https" in source_txt and not re.search(r"#\w*tag|\bcommit=", source_txt):
        note(W["git_unpinned"], "Git source unpinned", "transport")

    # Execution ----
    if PIPE_SHELL_RE.search(txt):
        note(W["pipe_to_shell"], "Pipe to shell (curl|sh)", "execution")
    if EVAL_RE.search(txt):
        note(W["eval_exec"], "eval/exec detected (review manually)", "execution")
    if BASH_C_RE.search(txt):
        note(W["eval_exec"], "sh -c / bash -c detected", "execution")
    if OBFUSCATION_RE.search(txt):
        note(W["obfuscation"], "Base64/binary decode detected", "execution")
    if LD_PRELOAD_RE.search(txt):
        note(W["ld_preload"], "LD_PRELOAD/LD_LIBRARY_PATH manipulation", "execution")

    # Privilege / networking ----
    if CURL_RE.search(txt):
        note(W["network_fetch"], "Network fetch in build", "privilege")
    uses_sudo = bool(SUDO_RE.search(txt) or PACMAN_WRITE_RE.search(txt))
    if SUDO_RE.search(txt):
        note(W["sudo_or_pacman"], "Uses sudo", "privilege")
    if PACMAN_WRITE_RE.search(txt):
        note(
            W["sudo_or_pacman"], "Calls pacman to install/remove packages", "privilege"
        )
    pkg_bodies = extract_package_bodies(txt)
    pkg_text = "\n".join(pkg_bodies)
    writes = bool(pkg_bodies and WRITE_CMD_RE.search(pkg_text))
    if writes:
        note(W["privilege_escal"], "Writes outside $pkgdir", "privilege")
    if SETCAP_RE.search(txt):
        note(
            W["setuid_bit"],
            "Potential privilege escalation (setuid/setcap)",
            "privilege",
        )

    if (BLOCK.get("uses_sudo") and uses_sudo) or (
        BLOCK.get("writes_outside_pkgdir") and writes
    ):
        findings.append(Finding(0, "Fatal rule: privileged operation", "privilege"))
        return ScoringResult(0, findings, dict(cat))

    # Metadata absence ----
    if not any(l.startswith("license=(") for l in lines):
        note(W["no_license"], "No license field", "metadata")
    if not any(l.startswith("arch=(") for l in lines):
        note(W["no_arch_field"], "No arch field", "metadata")
    if not any(l.startswith("# Maintainer:") for l in lines):
        note(W["no_maintainer_tag"], "No maintainer tag", "metadata")
    if e := namcap_errors(local_path):
        note(W["namcap_error"] * e, f"namcap {e} error(s)", "metadata")

    # Community / AUR ----
    if aur_meta:
        votes = aur_meta.get("NumVotes", 0)
        maint = aur_meta.get("Maintainer")
        ood = aur_meta.get("OutOfDate") not in (0, None)

        if votes < 1:
            note(W["aur_low_votes_3"], f"Only {votes} votes", "community")
        elif votes < 15:
            note(W["aur_low_votes_2"], f"Only {votes} votes", "community")
        elif votes < 30:
            note(W["aur_low_votes_1"], f"Only {votes} votes", "community")

        if maint in (None, "", "orphan"):
            note(W["aur_orphaned"], "Package is orphaned", "community")

        if ood:
            age_days = int((time.time() - aur_meta["OutOfDate"]) / 86400)
            note(
                W["aur_out_of_date"],
                f"Flagged out of date ({age_days} days)",
                "community",
            )

    # Apply caps ----
    for k, v in cat.items():
        cap = CAP.get(k)
        if cap is not None and v < cap:
            cat[k] = cap
    score += sum(cat.values())
    return ScoringResult(max(0, score), findings, dict(cat))
