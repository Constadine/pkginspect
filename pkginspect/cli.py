#!/usr/bin/env python3

from __future__ import annotations
import argparse, os, pathlib, re, subprocess, sys, textwrap
from collections import defaultdict
from typing import List, Tuple, Dict
import requests, yaml, importlib.resources as res

# ── rule loader ──────────────────────────────────────────────────
def load_rules(path_cli: str | None) -> dict:
    search = []
    if path_cli:
        search.append(pathlib.Path(path_cli).expanduser())
    if env := os.getenv("PKGINSPECT_RULES"):
        search.append(pathlib.Path(env).expanduser())
    search += [pathlib.Path.cwd() / "rules.yaml",
               pathlib.Path(os.getenv("XDG_CONFIG_HOME",
                                       pathlib.Path.home() / ".config"))
               / "pkginspect" / "rules.yaml"]
    for p in search:
        if p.is_file():
            return yaml.safe_load(p.read_text())
    with res.files("pkginspect").joinpath("rules.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)

W: Dict[str, int] = {}; CAP: Dict[str, int] = {}; BLOCK: Dict[str, bool] = {}

# ── helpers & regexes ────────────────────────────────────────────
HTTPS_OK = {"github.com", "gitlab.com", "kernel.org", "sourcehut.org",
            "codeberg.org", "archlinux.org"}
CHECK_RE = re.compile(r'^\s*(sha(?:1|224|256|384|512)sums|md5sums|b2sums)\s*=', re.M)
URL_RE   = re.compile(r'(?:https?|ftp)://[^\s)\'"]+')
CURL_RE  = re.compile(r'\b(?:curl|wget)\b')
SUDO_RE  = re.compile(r'\b(?:sudo|pacman)\b')
SETCAP_RE = re.compile(r'\b(setcap|chmod\s+777)\b')
WRITE_CMD_RE = re.compile(
    r'^\s*(?:install|cp|mv|mkdir|ln|echo|cat)\s+[^\n]*\s/(?:etc|usr|var|lib|bin)/',
    re.M)

def domain(url: str) -> str: return url.split("/")[2].lower()
def namcap_errors(p: pathlib.Path | None):
    if p is None: return None
    try:
        o = subprocess.run(["namcap", "-i", str(p)],
                           capture_output=True, text=True)
        return o.stdout.count("ERROR")
    except FileNotFoundError: return None

# ── scoring engine  ───────────────
def score_pkgbuild(lines: List[str], *, local_path: pathlib.Path | None = None
                   ) -> Tuple[int, List[Tuple[int,str]], Dict[str,int]]:
    score = 100
    cat = defaultdict(int)
    msgs: List[Tuple[int, str]] = []
    txt = "\n".join(lines)

    def note(penalty: int, message: str, bucket: str):
        cat[bucket] += penalty
        msgs.append((penalty, message))

    # Integrity
    sums_arrays = [m.group(1) for l in lines if (m := CHECK_RE.match(l))]
    if not sums_arrays:
        note(W["missing_checksums"], "No checksum array", "integrity")
    if re.search(r'^\s*(?:sha(?:1|224|256|384|512)|md5|b2)sums\s*=\s*\([\s\S]*?\bSKIP\b',
                 txt, re.M):
        total = len(re.findall(r'^\s*["\']?https?://', txt, re.M))
        skipped = len(re.findall(r'\bSKIP\b', txt))
        penalty = W["skip_checksum_all"] if skipped == total else W["skip_checksum_some"]
        note(penalty, "SKIP used in checksums", "integrity")
    if {"md5sums", "sha256sums"} & set(sums_arrays):
        note(W["weak_hash"], "Weak hash", "integrity")

    # Transport
    for url in URL_RE.findall(txt):
        if url.startswith(("http://", "ftp://")):
            note(W["insecure_url"], f"Insecure URL {url}", "transport")
    if "git+https" in txt and not re.search(r'#\w*tag|\bcommit=', txt):
        note(W["git_unpinned"], "Git source unpinned", "transport")

    # Privilege / networking
    if CURL_RE.search(txt):
        note(W["network_fetch"], "Network fetch in build", "privilege")
    uses_sudo = bool(SUDO_RE.search(txt))
    if uses_sudo:
        note(W["sudo_or_pacman"], "Uses sudo/pacman", "privilege")
    pkg_body = re.search(r'package\(\)\s*\{([\s\S]*?)^\}', txt, re.M)
    writes = bool(pkg_body and WRITE_CMD_RE.search(pkg_body.group(1)))
    if writes:
        note(W["privilege_escal"], "Writes outside $pkgdir", "privilege")
    if SETCAP_RE.search(txt):
        note(W["privilege_escal"], "Potential privilege escalation", "privilege")

    if (BLOCK.get("uses_sudo") and uses_sudo) or (BLOCK.get("writes_outside_pkgdir") and writes):
        msgs.append((0, "Fatal rule: privileged operation"))
        return 0, msgs, cat

    # Metadata absence
    if not any(l.startswith("license=(") for l in lines):
        note(W["no_license"], "No license field", "metadata")
    if not any(l.startswith("arch=(") for l in lines):
        note(W["no_arch_field"], "No arch field", "metadata")
    if not any(l.startswith("# Maintainer:") for l in lines):
        note(W["no_maintainer_tag"], "No maintainer tag", "metadata")
    if (e := namcap_errors(local_path)):
        note(W["namcap_error"] * e, f"namcap {e} error(s)", "metadata")

    # Apply caps
    for k, v in cat.items():
        cap = CAP.get(k)
        if cap is not None and v < cap:
            cat[k] = cap
    score += sum(cat.values())
    return max(0, score), msgs, cat

# ── fetchers  ─────────────────────────────────────────────────────
# ── 1. generic fetch with HTML-guard ──────────────────────────────
def fetch_url(url: str) -> List[str]:
    """Return the remote text split into lines; raise if we get HTML."""
    r = requests.get(url, timeout=10)
    r.raise_for_status()                    # 4xx / 5xx ⇒ exception
    txt = r.text.lstrip()
    if txt.startswith("<!DOCTYPE html"):    # GitLab login page, Cloudflare, etc.
        raise RuntimeError("HTML page returned instead of raw file")
    return txt.splitlines()

# ── 2. fetch from AUR (always public) ────────────────────────────
def fetch_aur(pkg: str) -> List[str]:
    return fetch_url(f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg}")

# ── 3. fetch from the official repos with graceful fallbacks ─────
def fetch_official(pkg: str) -> List[str]:
    """
    1. Try Arch GitLab (needs SSO but still public for some repos)
    2. Fall back to GitHub mirrors: core → extra → community → multilib
    3. If still missing, raise OfficialNotFound so caller can suggest --aur
    """
    # 3a. Arch GitLab
    gl_url = (
        "https://gitlab.archlinux.org/archlinux/packaging/packages/"
        f"{pkg}/-/raw/main/PKGBUILD?inline=false"
    )
    try:
        return fetch_url(gl_url)
    except Exception:                        # HTML login page or 404
        pass

    # 3b. GitHub mirrors
    gh_roots = [
        "archlinux/svntogit-core",
        "archlinux/svntogit-extra",
        "archlinux/svntogit-community",
        "archlinux/svntogit-multilib",
    ]
    for root in gh_roots:
        gh_url = (
            f"https://raw.githubusercontent.com/{root}/packages/{pkg}/trunk/PKGBUILD"
        )
        try:
            return fetch_url(gh_url)
        except Exception:
            continue  # try next mirror

    # 3c. Not found anywhere → tell caller to hint at --aur
    raise RuntimeError("not found in official mirrors")


# ── CLI ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="PKGBUILD analyzer")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file"); g.add_argument("--aur"); g.add_argument("--official"); g.add_argument("--url")
    ap.add_argument("--rules"); ap.add_argument("-d", "--debug", action="store_true")
    args = ap.parse_args()

    global W, CAP, BLOCK
    r = load_rules(args.rules); W, CAP, BLOCK = r["weights"], r["caps"], r["blockers"]

    if args.file:
        p = pathlib.Path(args.file); lines = p.read_text().splitlines(); loc = p
    elif args.aur:      lines, loc = fetch_aur(args.aur), None
    elif args.official:
        try:
            lines, loc = fetch_official(args.official), None
        except RuntimeError as e:
            if "not found in official mirrors" in str(e):
                print(f"'{args.official}' is not in the official repos; "
                    f"try `--aur {args.official}`.", file=sys.stderr)
                sys.exit(1)
            raise
    else:               lines, loc = fetch_url(args.url), None

    score, msgs, cats = score_pkgbuild(lines, local_path=loc)

    # sort by biggest absolute deduction
    msgs_sorted = sorted(msgs, key=lambda t: abs(t[0]), reverse=True)
    biggest = msgs_sorted[0][1] + f" ({msgs_sorted[0][0]})" if msgs_sorted else "None"

    badge, grade = ("🟢", "Excellent") if score >= 90 else \
                   ("🟡", "Good")      if score >= 70 else \
                   ("🟠", "Fair")      if score >= 50 else \
                   ("🔴", "Poor")

    if args.debug:
        print("\n─── PKGBUILD analysed ───")
        print(textwrap.indent("\n".join(lines), "  "))
        print("\n─── Category totals ───")
        for k, v in cats.items():
            print(f"  {k:10}: {v:+}")
        print()

    print(f"{badge}  PKGBUILD safety score: {score}/100  →  {grade}")
    print(f"Biggest flaw: {biggest}\n")
    for score, msg in msgs_sorted:
        print(f"- {msg} ({score})")

if __name__ == "__main__":
    try: main()
    except Exception as e:
        print(f"\nError: {e}\n", file=sys.stderr); sys.exit(1)
