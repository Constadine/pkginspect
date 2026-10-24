from __future__ import annotations

import bisect
import dataclasses
import functools
import ipaddress
import os
import pathlib
import re
import shlex
import subprocess
import time
from collections import defaultdict
from typing import Callable, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlsplit

from pkginspect.rules import RulesConfig

# Work limits, so pathological input cannot make a scan take forever.
_MAX_INPUT = 1_000_000  # chars of PKGBUILD / extra file that get scanned
_MAX_CMD_LINE = 8192  # logical lines longer than this skip command analysis
_MAX_BRACE_ENTRIES = 256  # brace expansion beyond this stays one entry
_MAX_EXPANDED = 4096  # chars a $var expansion may grow to
_MAX_INDEX = 10000  # sha256sums[N]=... beyond this is ignored

# ── regexes ──────────────────────────────────────────────────────
# A command word: at the start of a statement (after ; & | ( { ` ! or a
# keyword like then/do/sudo), optionally behind VAR=value prefixes and a path.
# Keeps "--with-curl", "libcurl" or "pacman" in a string from matching.
_CMD_START = (
    r"(?:^|[;&|({`!]|\b(?:then|do|else|elif|while|until|if|sudo|doas|env|exec"
    r"|command|time|nohup|xargs))\s*(?:\w+=\S*\s+){0,10}(?:[\w.\-/]{0,200}/)?"
)


def _cmd(names: str) -> str:
    return rf"{_CMD_START}(?:{names})\b"


def shell_lines(text: str) -> List[str]:
    """Split shell text the way bash does: only on \\n (str.splitlines() also
    breaks on \\r, form feed, U+2028, ...). No trailing empty line."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


URL_RE = re.compile(r"(?:https?|ftp)://[^\s)'\"`<>|;]+")
NETWORK_RE = re.compile(rf"{_cmd('curl|wget')}|{_cmd('git')}\s+clone\b")
SUDO_RE = re.compile(
    rf"{_cmd('sudo|doas|pkexec')}|{_CMD_START}su\s+(?:[^\n]{{0,1000}}\s)?-c\b"
)
# Only flag pacman when doing write operations (-S install, -U upgrade, -R remove, -D modify)
# -T (deptest) and -Q (query) are read-only and legitimate in PKGBUILDs
PACMAN_WRITE_RE = re.compile(
    rf"{_cmd('pacman')}\s+(?:[^\n]{{0,1000}}\s)?-(?:[SURD][A-Za-z]*|-sync|-upgrade|-remove|-database)\b"
)
_SETUID_MODE = r"(?:[2467][0-7]{3}|[ugoa]*\+[rwxX]*s)"
SETUID_RE = re.compile(rf"\b(?:setcap\b|chmod\s+(?:-\w+\s+)*{_SETUID_MODE}\b)")
# Chromium/Electron sandbox helper (chrome-sandbox, *-sandbox): setuid is standard
SANDBOX_RE = re.compile(
    rf"\bchmod\s+(?:-\w+\s+)*{_SETUID_MODE}\s+[\"']?\S*-sandbox[\"']?(?=\s|[;&|)]|$)"
)
WORLD_WRITABLE_RE = re.compile(r"\bchmod\s+(?:-\w+\s+)*777\b")

_FETCH = r"(?:curl|wget|fetch)"
_SHELLS = r"(?:sh|bash|zsh|dash|ksh|fish)"
_OTHER_INTERP = r"(?:python[\d.]*|perl|ruby|node|php)"
_WRAP = r"(?:(?:sudo|env)\s+(?:(?:-\S+|\w+=\S*)\s+){0,10}){0,5}"
PIPE_SHELL_RE = re.compile(
    # curl ... | [sudo|env] bash   (python & co. only when they read the script
    # from stdin, not `python -c ...` / `perl -pe ...` / `node script.js`)
    rf"\b{_FETCH}\b[^|;\n]{{0,1000}}\|\s*{_WRAP}(?:[\w./-]{{0,200}}/)?"
    rf"(?:{_SHELLS}\b|{_OTHER_INTERP}\b(?!\s+(?:-\w*[cme]\b|[^\s|;&<>-])))"
    # bash <(curl ...), source <(curl ...), . <(curl ...)
    rf"|(?:\bsource|(?<![\w.])\.|\b(?:{_SHELLS}|{_OTHER_INTERP}))\s+(?:<\s*)?<\(\s*{_FETCH}\b"
    # sh -c "$(curl ...)", eval "$(curl ...)"
    rf"|\b{_SHELLS}\s+-c\s+[\"']?\$\(\s*{_FETCH}\b"
    rf"|{_CMD_START}eval\s+[\"']?\$\(\s*{_FETCH}\b"
)
EVAL_RE = re.compile(rf"{_cmd('eval')}(?!\s*=)")
BASH_C_RE = re.compile(r"\b(?:sh|bash|zsh|dash)\s+-c\b")
# up to 50 arguments that do not cross a pipe or `;`
_NOT_PIPE = r"(?:[^\s|;&]{1,200}\s+){0,50}?"
OBFUSCATION_RE = re.compile(
    rf"\bbase64\s+{_NOT_PIPE}(?:-\w*[dD]\b|--decode\b)"
    rf"|\bxxd\s+{_NOT_PIPE}-r\b"
    rf"|\bopenssl\s+(?:enc|base64)\s+{_NOT_PIPE}-d\b"
    r"|\b(?:printf|echo)\b[^\n]{0,1000}(?:\\x[0-9a-fA-F]{2}){8,}"
)
_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{100,}")
# An empty value or the fakeroot library itself is not an injection.
LD_PRELOAD_RE = re.compile(
    r"\bLD_PRELOAD\s*=(?!\s|;|$|(?:\"\"|'')(?:\s|;|$)"
    r"|[\"']?(?:/usr/lib/libfakeroot/)?libfakeroot\.so[\"']?(?:\s|;|$))"
)

_NC = r"(?:nc|ncat|netcat)"
REVERSE_SHELL_RE = re.compile(
    r"/dev/(?:tcp|udp)/"
    rf"|\b{_NC}\b[^\n]{{0,1000}}\s(?:-[a-zA-Z]*[ec]\b|--(?:sh-)?exec\b)"
    r"|\bsocat\b[^\n]{0,1000}\b(?i:exec|system):"
    r"|\b(?:sh|bash|zsh|dash)\s+-i\b[^\n]{0,1000}>&"
    rf"|\bmkfifo\b[^\n]{{0,1000}}\b{_NC}\b|\b{_NC}\b[^\n]{{0,1000}}\bmkfifo\b"
)
_PYTHON_C_RE = re.compile(r"\bpython[\d.]*\s+-c\b")

_PERSIST_PATH_RE = re.compile(
    r"/etc/cron|/var/spool/cron|/etc/ld\.so\.preload|authorized_keys|/etc/sudoers"
    r"|(?<![\w.-])\.(?:bashrc|zshrc|profile|bash_profile|zprofile|xprofile|xinitrc)\b"
    r"|\.config/autostart|\.config/systemd/user"
)
_PERSIST_CMD_RE = re.compile(_cmd("crontab"))
_ENABLE_SERVICE_RE = re.compile(
    rf"{_cmd('systemctl')}\s+(?:[^\n]{{0,1000}}\s)?enable\b"
)
_PKGROOT_RE = re.compile(r"\$\{?(?:pkgdir|srcdir)\b")
_TMP_RE = re.compile(r"(?:^|[\s\"'=:(])/tmp/")

_BAD_HOSTS = (
    # paste / temp-file sites
    "pastebin.com paste.ee ptpb.pw hastebin.com ghostbin.com ghostbin.co termbin.com "
    "transfer.sh 0x0.st temp.sh file.io paste.rs dpaste.com dpaste.org "
    # URL shorteners
    "bit.ly tinyurl.com t.co is.gd goo.gl cutt.ly rb.gy shorturl.at "
    # Discord CDN
    "cdn.discordapp.com media.discordapp.net "
    # tunnels
    "ngrok.io ngrok-free.app trycloudflare.com "
    # dynamic DNS
    "duckdns.org no-ip.org ddns.net"
).split()

# ── whitelist parser for PKGBUILD assignments ───────────────────
# Metadata assignments whose body is plain data get blanked before the command
# rules run, so `optdepends=('sudo: ...')` is not mistaken for running sudo.
_METADATA_RE = re.compile(
    r"(?:pkgname|pkgbase|pkgver|pkgrel|epoch|pkgdesc|url|license|arch|groups"
    r"|depends|makedepends|checkdepends|optdepends|provides|conflicts|replaces"
    r"|backup|options|install|changelog|validpgpkeys|noextract|source"
    r"|(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums)(?:_\w+)?$"
)
_ASSIGN_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)(?:\[([^\]\n]*)\])?(\+?=)", re.M)
_SOURCE_NAME_RE = re.compile(r"source(?:_(\w+))?$")
_SUMS_NAME_RE = re.compile(r"(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_(\w+))?$")
_BARE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+-:=<>@/,%{}$~"
)
_VCS_RE = re.compile(r"(?:git\+|git://|hg\+|svn\+|bzr\+|fossil\+|darcs\+)")
_VCS_NAME_RE = re.compile(r".*-(?:git|hg|svn|bzr|fossil|darcs|cvs|nightly)$")
_SIG_EXTS = (".sig", ".asc", ".sign")
_BRACE_RE = re.compile(r"(?<!\$)\{([^{}]*,[^{}]*)\}")
_VAR_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")

_MSG_LINE_RE = re.compile(
    r"""^\s*(?:echo|printf|msg2?|warning|plain|error)"""
    r"""(?:\s+(?:'[^']*'|"[^"]*"|[^\s'"]+))*\s*$"""
)
_MSG_UNSAFE_RE = re.compile(r"\$\(|[`;|&<>]")

_AUX_EXTS = {".sh", ".bash", ".zsh", ".py", ".pl", ".service", ".timer", ".socket"} | {
    ".desktop"
}
_HOOK_DEF_RE = re.compile(
    r"\s*(?:function\s+)?(pre_install|post_install|pre_upgrade|post_upgrade"
    r"|pre_remove|post_remove)\s*(?:\(\s*\)|\{)"
)


@dataclasses.dataclass
class Evidence:
    """Where a finding was seen, so the user can check it at a glance."""

    file: str  # "PKGBUILD", "foo.install", ...
    line: int  # 1-based line number in that file
    text: str  # the original line, stripped and truncated


@dataclasses.dataclass
class Finding:
    penalty: int  # 0 means informational
    message: str
    category: str
    rule: str = ""  # rules.yaml weight key that produced it, e.g. "pipe_to_shell"
    evidence: List[Evidence] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ScoringResult:
    score: int
    findings: List[Finding]
    categories: dict[str, int]
    blocked: bool = False  # a blocker forced the score to 0
    # Where remote sources come from, e.g. ["github.com/Jguer", "example.org (http)"]
    sources: List[str] = dataclasses.field(default_factory=list)


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


# ── assignments ──────────────────────────────────────────────────


@dataclasses.dataclass
class Assign:
    name: str
    index: Optional[str]  # "4" for sha512sums[4]=...
    op: str  # "=" or "+="
    is_array: bool
    words: List[str]  # array items, or [value] for a scalar (quotes removed)
    word_pos: List[int]  # offset of each word in the text
    start: int
    end: int
    ok: bool  # the body is plain data (safe to blank)
    top: bool  # starts at column 0
    line: int


def _scan_words(
    text: str, i: int, array: bool
) -> Tuple[List[str], List[int], int, bool]:
    """Read an array body (after "(") or a scalar value starting at text[i].

    Only plain data is accepted: single-quoted strings, double-quoted strings
    without `$(`, backticks or backslashes, and bare words from a small
    character set. Anything else makes `ok` False, and the caller keeps the
    text visible to the scanners. Returns (words, offsets, end, ok).
    """
    words: List[str] = []
    pos: List[int] = []
    cur: List[str] = []
    cur_start = i
    ok = True
    n = len(text)

    def flush() -> None:
        if cur:
            words.append("".join(cur))
            pos.append(cur_start)
            cur.clear()

    while i < n:
        c = text[i]
        if c in " \t\r\n":
            flush()
            if not array:
                return words, pos, i, ok
            i += 1
            cur_start = i
        elif c == ")" and array:
            flush()
            return words, pos, i + 1, ok
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return words, pos, n, False
            if not cur:
                cur_start = i
            cur.append(text[i + 1 : j])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return words, pos, n, False
            body = text[i + 1 : j]
            if "$(" in body or "`" in body or "\\" in body:
                ok = False
            if not cur:
                cur_start = i
            cur.append(body)
            i = j + 1
        elif c in _BARE_CHARS:
            if not cur:
                cur_start = i
            cur.append(c)
            i += 1
        else:
            ok = False
            if c == "#" and not cur:  # trailing comment: bash skips to end of line
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if not cur:
                cur_start = i
            cur.append(c)
            i += 1
    flush()
    return words, pos, n, ok and not array  # an array with no ")" is not data


def _line_starts(text: str) -> List[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _parse_assignments(text: str) -> List[Assign]:
    out: List[Assign] = []
    starts = _line_starts(text)
    pos = 0
    while True:
        m = _ASSIGN_RE.search(text, pos)
        if not m:
            return out
        i = m.end()
        is_array = text[i : i + 1] == "("
        words, wpos, end, ok = _scan_words(text, i + 1 if is_array else i, is_array)
        if ok:
            # Whatever follows must be blank or a comment, else it is code
            # (`foo=bar make`, `depends=(a); curl x | sh`).
            eol = text.find("\n", end)
            eol = len(text) if eol < 0 else eol
            rest = text[end:eol].strip()
            if rest == "" or rest.startswith("#"):
                end = eol
            elif not is_array:
                ok = False
        out.append(
            Assign(
                name=m.group(1),
                index=m.group(2),
                op=m.group(3),
                is_array=is_array,
                words=words,
                word_pos=wpos,
                start=m.start(),
                end=end,
                ok=ok,
                top=m.start(1) == m.start(),
                line=bisect.bisect_right(starts, m.start(1)),
            )
        )
        # Not plain data: rescan the body for inner assignments, unless it is
        # long (an unterminated `a=(` runs to EOF; rescanning would be quadratic).
        pos = end if ok or end - m.end() > 4096 else m.end()


def _blank(text: str, assigns: List[Assign]) -> str:
    """Overwrite plain-data metadata assignments with spaces (newlines kept)."""
    chars = list(text)
    for a in assigns:
        if a.ok and _METADATA_RE.match(a.name):
            for k in range(a.start, a.end):
                if chars[k] != "\n":
                    chars[k] = " "
    return "".join(chars)


# ── sources and checksums ───────────────────────────────────────


@dataclasses.dataclass
class SourceEntry:
    url: str
    line: int
    vcs: bool
    sig: bool  # detached signature (makepkg verifies it)
    local: bool  # file shipped in the package repo
    commit: bool  # VCS source pinned to a commit
    pinned: bool  # VCS source pinned to a commit, tag or revision
    name: str  # file name makepkg saves it as
    doc: bool  # documentation only (.html, .txt, LICENSE, ...)
    # "sum", "skip", "signed" (SKIP but a detached signature is a source too),
    # "none", or "unsure" (could not pair)
    state: str = "none"

    @property
    def downloaded(self) -> bool:
        """A downloaded program/data file: SKIP here is a real gap."""
        return not (self.vcs or self.sig or self.local or self.doc)

    @property
    def remote_doc(self) -> bool:
        return self.doc and not (self.vcs or self.sig or self.local)


@dataclasses.dataclass
class SourceInfo:
    entries: List[SourceEntry] = dataclasses.field(default_factory=list)
    algos: Set[str] = dataclasses.field(default_factory=set)
    sums_lines: List[int] = dataclasses.field(default_factory=list)
    any_sums: bool = False
    fallback_skip: bool = False  # entries could not be paired but SKIP is present
    # Same, but the source array also holds signature/VCS/local entries, so the
    # SKIPs are most likely theirs (dynamic arrays such as bash's patch loop).
    skip_unpaired: bool = False
    unpaired_lines: List[int] = dataclasses.field(default_factory=list)
    pkgnames: List[str] = dataclasses.field(default_factory=list)
    source_lines: List[int] = dataclasses.field(default_factory=list)
    dynamic: bool = False  # a source array exists but no URL could be resolved


def _brace_expand(s: str) -> List[str]:
    """a{b,c} -> ab, ac. More than 256 results (or a huge word): left as is."""
    if len(s) > _MAX_EXPANDED:
        return [s]
    out = [s]
    while True:
        nxt: List[str] = []
        for w in out:
            m = _BRACE_RE.search(w)
            if not m:
                nxt.append(w)
                continue
            for alt in m.group(1).split(","):
                nxt.append(w[: m.start()] + alt + w[m.end() :])
            if len(nxt) > _MAX_BRACE_ENTRIES:
                return [s]
        if nxt == out:
            return out
        out = nxt


def _expand_vars(s: str, scalars: Dict[str, str]) -> str:
    def sub(m: "re.Match[str]") -> str:
        name = m.group(1) or m.group(2)
        return scalars.get(name, m.group(0))

    for _ in range(5):
        new = _VAR_RE.sub(sub, s)
        if new == s or len(new) > _MAX_EXPANDED:
            break
        s = new
    return s


def _make_entry(value: str, line: int) -> SourceEntry:
    name, sep, url = value.partition("::")
    if not sep:
        url = name
    path = url.split("#")[0].split("?")[0].lower()
    base = path.rsplit("/", 1)[-1]
    vcs = bool(_VCS_RE.match(url))
    return SourceEntry(
        url=url,
        line=line,
        vcs=vcs,
        sig=name.lower().endswith(_SIG_EXTS) or path.endswith(_SIG_EXTS),
        local="://" not in url or url.startswith("file://"),
        commit=vcs and bool(re.search(r"[#&]commit=", url)),
        pinned=vcs and bool(re.search(r"[#&](?:commit|tag|revision)=", url)),
        name=name.lower() if sep else base,
        doc=bool(_DOC_RE.search(name if sep else base) or _DOC_RE.search(base)),
    )


_DOC_RE = re.compile(r"\.(?:html?|txt|md|rtf|pdf)$|license|copying", re.I)
_SAFE_SKIP_RE = re.compile(
    r"\.(?:sig|asc|sign)\b|\{[^{}]*\b(?:sig|asc|sign)\b[^{}]*\}"
    r"|git\+|git://|hg\+|svn\+|bzr\+|fossil\+|darcs\+"
)


def _raw_array(text: str, a: Assign) -> str:
    """Raw text of an array assignment, to the matching ")" (naive paren count).

    Unlike a.end this survives `$(printf ...)` inside the array.
    """
    i = text.find("(", a.start)
    if i < 0:
        return ""
    j = i
    depth = 0
    for j in range(i, len(text)):
        depth += (text[j] == "(") - (text[j] == ")")
        if depth == 0:
            break
    eol = text.find("\n", j)
    return text[a.start : len(text) if eol < 0 else eol]


def _has_safe_skip_source(text: str, assigns: List[Assign], suffix: str) -> bool:
    """Is a signature, VCS or local source recognizable in this source array?"""
    for a in assigns:
        m = _SOURCE_NAME_RE.match(a.name)
        if not (m and a.is_array and (m.group(1) or "") == suffix):
            continue
        if _SAFE_SKIP_RE.search(_raw_array(text, a)):
            return True
        if any("://" not in w and not re.search(r"[${}]", w) for w in a.words):
            return True
    return False


def _parse_sources(text: str, assigns: List[Assign]) -> SourceInfo:
    info = SourceInfo()
    scalars = {
        a.name: a.words[0] if a.words else ""
        for a in assigns
        if a.top and not a.is_array and a.ok and a.op == "=" and a.index is None
    }
    scalars = {k: _expand_vars(v, scalars) for k, v in scalars.items()}

    starts = _line_starts(text)
    sources: Dict[str, List[Tuple[str, int]]] = {}  # arch suffix -> (value, line)
    sums: Dict[str, Dict[str, List[str]]] = {}  # arch suffix -> algo -> values
    for a in assigns:
        if a.name in ("pkgname", "pkgbase") and a.index is None:
            info.pkgnames += [_expand_vars(w, scalars) for w in a.words]
        m = _SOURCE_NAME_RE.match(a.name)
        if m and a.is_array and a.index is None:
            info.source_lines.append(a.line)
            items = sources.setdefault(m.group(1) or "", [])
            if a.op == "=":
                items.clear()
            for w, off in zip(a.words, a.word_pos):
                line = bisect.bisect_right(starts, off)
                items += [(v, line) for v in _brace_expand(w)]
            continue
        m = _SUMS_NAME_RE.match(a.name)
        if not m:
            continue
        algo, suffix = m.group(1), m.group(2) or ""
        values = sums.setdefault(suffix, {}).setdefault(algo, [])
        info.any_sums = True
        info.sums_lines.append(a.line)
        if a.is_array and a.index is None:
            if a.op == "=":
                values.clear()
            values += a.words
        elif a.index is not None and a.index.isdigit() and a.words:
            k = int(a.index) if len(a.index) < 6 else _MAX_INDEX + 1
            if k > _MAX_INDEX:
                continue
            values += [""] * (k + 1 - len(values))
            values[k] = a.words[0]

    # md5/sha1 arrays that are all SKIP (picom-git) do not make a weak hash
    info.algos = {
        algo
        for per_algo in sums.values()
        for algo, vals in per_algo.items()
        if any(v != "SKIP" for v in vals)
    }
    signed_ok = any(a.name == "validpgpkeys" and a.words for a in assigns)

    for suffix, items in sources.items():
        entries = [_make_entry(_expand_vars(v, scalars), line) for v, line in items]
        algos = sums.get(suffix, {})
        paired = bool(algos) and all(len(v) == len(entries) for v in algos.values())
        any_skip = any("SKIP" in v for v in algos.values())
        for i, e in enumerate(entries):
            if paired:
                vals = [v[i] for v in algos.values()]
                e.state = "skip" if all(v == "SKIP" for v in vals) else "sum"
            elif algos:
                e.state = "unsure" if any_skip else "sum"
        if signed_ok:  # a SKIP'd file with a detached signature is verified
            names = {e.name for e in entries}
            for e in entries:
                if e.state == "skip" and any(e.name + x in names for x in _SIG_EXTS):
                    e.state = "signed"
        if algos and not paired and any_skip and any(e.downloaded for e in entries):
            if _has_safe_skip_source(text, assigns, suffix):
                info.skip_unpaired = True
                info.unpaired_lines += [e.line for e in entries]
            else:
                info.fallback_skip = True
        info.entries += entries
    info.dynamic = (
        any(sources.values())
        and not any(re.match(r"[\w+]+://[^/${]+", e.url) for e in info.entries)
        and any(re.search(r"[${]", e.url) for e in info.entries)
    )
    return info


def _url_host(url: str) -> str:
    try:
        return (urlsplit(re.sub(r"^[a-z]+\+", "", url)).hostname or "").lower()
    except ValueError:
        return ""


def _scheme(url: str) -> str:
    """http for git+http://..., https for https://..."""
    return url.split("://")[0].split("+")[-1]


def _source_label(e: SourceEntry) -> str:
    """host, or host/owner for the big forges, plus (git)/(http) markers."""
    try:
        sp = urlsplit(re.sub(r"^[a-z]+\+", "", e.url))
        host = (sp.hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    label = host
    if host in (
        "github.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "codeberg.org",
        "git.sr.ht",
    ):
        owner = next((p for p in sp.path.split("/") if p), "")
        label = f"{host}/{owner}" if owner else host
    marks = []
    if e.vcs:
        marks.append("git")
    if _scheme(e.url) in ("http", "ftp"):
        marks.append("http")
    return f"{label} ({', '.join(marks)})" if marks else label


def _is_bad_host(url: str) -> bool:
    host = _url_host(url)
    if not host:
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    return any(host == d or host.endswith("." + d) for d in _BAD_HOSTS)


# ── line preparation ─────────────────────────────────────────────


def _blank_comments(lines: List[str]) -> List[str]:
    """Blank full-line comments (line count stays). No trailing-comment
    stripping: without a real bash parser that would be unsafe."""
    return ["" if l.lstrip().startswith("#") else l for l in lines]


# (first 1-based line number, logical line, [(line number, physical piece)])
CodeLine = Tuple[int, str, List[Tuple[int, str]]]


def _code_lines(lines: List[str]) -> List[CodeLine]:
    """Join backslash continuations and blank pure message lines."""
    out: List[CodeLine] = []
    i = 0
    while i < len(lines):
        start = i
        parts = [lines[i]]
        pieces = [(i + 1, lines[i][:-1] if lines[i].endswith("\\") else lines[i])]
        while parts[-1].endswith("\\") and i + 1 < len(lines):
            parts[-1] = parts[-1][:-1]
            i += 1
            nxt = lines[i].strip()
            parts.append(nxt)
            pieces.append((i + 1, nxt.rstrip("\\")))
        i += 1
        cur = " ".join(parts)
        if (
            len(cur) <= _MAX_CMD_LINE
            and _MSG_LINE_RE.match(cur)
            and not _MSG_UNSAFE_RE.search(cur)
        ):
            cur = ""  # `echo "run 'sudo foo'"` only prints
        out.append((start + 1, cur, pieces))
    return out


_HEREDOC_RE = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)(\w+)\2")
# Hoisted out of the f-string: a backslash inside {...} is a SyntaxError before 3.12.
_INTERPRETERS = r"sh|bash|zsh|dash|python[\d.]*|perl|ruby|node|eval|source"
_INTERPRETER_RE = re.compile(rf"{_cmd(_INTERPRETERS)}|{_CMD_START}\.\s")


def _split_heredocs(lines: List[str]) -> Tuple[List[str], List[str]]:
    """Separate heredoc bodies that are written into $pkgdir.

    Such a body is an installed file (e.g. a launcher script), not build code.
    Returns (lines with those bodies blanked, lines holding only those bodies);
    line numbers stay the same. A heredoc fed to an interpreter, or written
    anywhere else, stays code; so does one without a terminator line.
    """
    code = list(lines)
    bodies = [""] * len(lines)
    unterminated: Set[Tuple[bool, str]] = set()  # no terminator after an earlier opener
    i = 0
    while i < len(lines):
        m = _HEREDOC_RE.search(lines[i])
        if not m:
            i += 1
            continue
        strip_tabs, delim = bool(m.group(1)), m.group(3)
        if (strip_tabs, delim) in unterminated:
            i += 1
            continue
        end = next(
            (
                j
                for j in range(i + 1, len(lines))
                if (lines[j].lstrip("\t") if strip_tabs else lines[j]).rstrip("\r")
                == delim
            ),
            None,
        )
        if end is None:
            unterminated.add((strip_tabs, delim))
            i += 1
            continue
        if _PKGROOT_RE.search(lines[i]) and not _INTERPRETER_RE.search(lines[i]):
            for j in range(i + 1, end + 1):
                bodies[j], code[j] = lines[j], ""
        i = end + 1  # a nested "<< EOL" inside the body is just text
    return code, bodies


def _patch_added_lines(lines: List[str]) -> List[str]:
    """Keep only the '+' lines of a patch (without the '+'), blank the rest."""
    return [
        l[1:] if l.startswith("+") and not l.startswith("+++") else "" for l in lines
    ]


# ── command analysis (what a line writes to) ─────────────────────

_PREFIX_WORDS = {
    "then", "do", "else", "elif", "if", "while", "until", "!", "{", "}",
    "sudo", "doas", "command", "exec", "time", "nohup", "env", "builtin",
}  # fmt: skip
_ASSIGN_WORD_RE = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
_REDIRECT_OUT = {">", ">>", ">|", "&>", "&>>"}
_REDIRECT_SKIP = {">&", "<&", "<", "<<", "<<<", "<<-", "<>", "&>&"}
_OUTSIDE_RE = re.compile(
    r"/(?:etc|usr|var|lib|lib64|bin|sbin|opt|boot|root|srv)(?:/|$)"
)
_HOME_RE = re.compile(r"(?:~|\$\{?HOME\}?|/home)(?:/|$)")


def _tokenize(line: str) -> List[str]:
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:  # unbalanced quotes
        return [w.strip("'\"") for w in line.split()]


def _commands(line: str) -> List[Tuple[str, List[str], List[str]]]:
    """Split a line into simple commands: (name, args, redirect targets)."""
    cmds: List[Tuple[str, List[str], List[str]]] = []
    words: List[str] = []
    redirs: List[str] = []

    def flush() -> None:
        i = 0
        while i < len(words) and (
            words[i] in _PREFIX_WORDS
            or _ASSIGN_WORD_RE.match(words[i])
            or (i > 0 and words[i].startswith("-"))
        ):
            i += 1
        if i < len(words):
            cmds.append((words[i].rsplit("/", 1)[-1], words[i + 1 :], redirs[:]))
        elif redirs:
            cmds.append(("", [], redirs[:]))
        words.clear()
        redirs.clear()

    toks = _tokenize(line)
    i = 0
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if t and set(t) <= set(";&|()"):
            flush()
        elif t in _REDIRECT_OUT:
            if nxt is not None:
                redirs.append(nxt)
            i += 1
        elif t in _REDIRECT_SKIP:
            i += 1
        elif re.fullmatch(r"\d", t) and nxt is not None and nxt[:1] in "<>":
            pass  # file descriptor of a redirection (2>/dev/null)
        else:
            words.append(t)
        i += 1
    flush()
    return cmds


def _target_dir(args: List[str]) -> Optional[str]:
    for i, a in enumerate(args):
        if a == "--target-directory" or re.fullmatch(r"-[A-Za-z]*t", a):  # -t, -st, -Dt
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("--target-directory="):
            return a.split("=", 1)[1]
        if a.startswith("-t") and len(a) > 2 and not a.startswith("--"):
            return a[2:]
    return None


@functools.lru_cache(maxsize=4)
def _destinations(line: str) -> Tuple[str, ...]:
    """Paths the line writes to: command destinations and redirect targets."""
    if len(line) > _MAX_CMD_LINE:
        return ()
    dests: List[str] = []
    for name, args, redirs in _commands(line):
        dests += redirs
        plain = [a for a in args if not a.startswith("-") or a == "-"]
        if name == "ln":
            target = _target_dir(args)
            if target is not None:
                dests.append(target)
            elif len(plain) >= 2:  # `ln -s /usr/bin/foo` links in the current dir
                dests.append(plain[-1])
        elif name in ("install", "cp", "mv"):
            target = _target_dir(args)
            is_dir_mode = name == "install" and any(
                a == "--directory" or (re.match(r"-[A-Za-z]*d", a) and a[1] != "-")
                for a in args
            )
            if target is not None:
                dests.append(target)
            elif is_dir_mode:
                dests += plain
            else:
                dests += plain[-1:]
        elif name in ("mkdir", "rmdir", "rm", "touch", "unlink", "tee"):
            dests += plain
        elif name in ("chmod", "chown", "chgrp"):
            dests += plain[1:]
        elif name == "sed":
            if any(a == "--in-place" or re.match(r"-[A-Za-z]*i", a) for a in args):
                dests += plain[-1:]
        elif name == "dd":
            dests += [a[3:] for a in args if a.startswith("of=")]
    return tuple(dests)


def _writes_outside(line: str, scope: str = "") -> bool:
    return any(_OUTSIDE_RE.match(d) for d in _destinations(line))


def _writes_home(line: str, scope: str = "") -> bool:
    return any(_HOME_RE.match(d) for d in _destinations(line))


# ── per-line rule tests ──────────────────────────────────────────


def _matches(rx: "re.Pattern[str]") -> Callable[[str, str], bool]:
    return lambda line, scope: bool(rx.search(line))


def _is_obfuscated(line: str, scope: str) -> bool:
    if OBFUSCATION_RE.search(line):
        return True
    if scope == "aux":  # blobs are normal in scripts and patches
        return False
    for m in _BLOB_RE.finditer(line):
        blob = m.group()
        if (
            not re.fullmatch(r"[0-9a-fA-F]+", blob)
            and re.search(r"[A-Z]", blob)
            and re.search(r"[a-z]", blob)
            and re.search(r"\d", blob)
        ):
            return True
    return False


_SPLIT_EVAL_RE = re.compile(r"""eval\s+["']package_[^\s(]*\(\)""")
_EVAL_DANGER_RE = re.compile(
    r"\b(?:curl|wget|base64)\b|\|\s*(?:sudo\s+)?(?:\S*/)?(?:sh|bash|zsh|dash|ksh|fish)\b"
)


def _is_eval(line: str, scope: str) -> bool:
    """eval, except the split-package idiom: eval "package_$_p() { ...; }"."""
    if not EVAL_RE.search(line):
        return False
    return not (_SPLIT_EVAL_RE.search(line) and not _EVAL_DANGER_RE.search(line))


def _is_reverse_shell(line: str, scope: str) -> bool:
    if REVERSE_SHELL_RE.search(line):
        return True
    return bool(
        _PYTHON_C_RE.search(line)
        and "socket" in line
        and ("subprocess" in line or "pty" in line)
    )


def _has_persistence(line: str, scope: str) -> bool:
    for m in _PERSIST_PATH_RE.finditer(line):
        # Packaging such a file into $pkgdir is legitimate.
        tok_start = max(line.rfind(" ", 0, m.start()), line.rfind("\t", 0, m.start()))
        if not _PKGROOT_RE.search(line[tok_start + 1 : m.start()]):
            return True
    return bool(_PERSIST_CMD_RE.search(line))


def _is_setuid(line: str, scope: str) -> bool:
    return bool(SETUID_RE.search(SANDBOX_RE.sub("", line)))


def _uses_tmp(line: str, scope: str) -> bool:
    return bool(_TMP_RE.search(line)) and "mktemp" not in line


def _suspicious_host(line: str, scope: str) -> bool:
    return any(_is_bad_host(u) for u in URL_RE.findall(line))


@dataclasses.dataclass
class CodeRule:
    key: str  # rules.yaml weight key
    category: str
    message: str
    test: Callable[[str, str], bool]  # (logical line, scope) -> fired?
    scopes: Tuple[str, ...]
    blocker: str = ""  # rules.yaml blocker that this rule feeds
    install_message: str = ""  # message override for .install files


# Scopes: "pkgbuild" (all PKGBUILD code), "install" (*.install, runs as root),
# "aux" (other scripts, hooks, units, patches).
_ALL = ("pkgbuild", "install", "aux")
_PI = ("pkgbuild", "install")
_P = ("pkgbuild",)
_WHERE = {
    "pkgbuild": "",
    "install": " in install script (runs as root)",
    "aux": " in bundled file(s)",
}

# fmt: off
CODE_RULES: List[CodeRule] = [
    CodeRule("pipe_to_shell", "execution", "Pipe to shell (curl|sh)", _matches(PIPE_SHELL_RE), _ALL),
    CodeRule("reverse_shell", "execution", "Reverse shell pattern", _is_reverse_shell, _ALL, blocker="reverse_shell"),
    CodeRule("obfuscation", "execution", "Base64/binary decode detected", _is_obfuscated, _ALL),
    CodeRule("eval_exec", "execution", "eval detected (review manually)", _is_eval, _PI),
    CodeRule("eval_exec", "execution", "sh -c / bash -c detected", _matches(BASH_C_RE), _PI),
    CodeRule("ld_preload", "execution", "LD_PRELOAD manipulation", _matches(LD_PRELOAD_RE), _PI),
    CodeRule("persistence", "execution", "Persistence mechanism (cron, autostart, shell rc, authorized_keys, sudoers)", _has_persistence, _ALL),
    CodeRule("persistence_service", "execution", "Enables a systemd service (systemctl enable)", _matches(_ENABLE_SERVICE_RE), _ALL),
    CodeRule("tmp_usage", "execution", "Hardcoded /tmp path (predictable temp file)", _uses_tmp, _PI),
    CodeRule("suspicious_host", "transport", "URL on a raw IP, paste/temp-file site, shortener, tunnel or dynamic DNS", _suspicious_host, _ALL),
    CodeRule("network_fetch", "privilege", "Network fetch in build", _matches(NETWORK_RE), _PI, install_message="Network fetch in install script (runs as root)"),
    CodeRule("sudo_or_pacman", "privilege", "Uses sudo/doas/pkexec", _matches(SUDO_RE), _P, blocker="uses_sudo"),
    CodeRule("sudo_or_pacman", "privilege", "Calls pacman to install/remove packages", _matches(PACMAN_WRITE_RE), _P, blocker="uses_sudo"),
    CodeRule("privilege_escal", "privilege", "Writes outside $pkgdir", _writes_outside, _P, blocker="writes_outside_pkgdir"),
    CodeRule("privilege_escal", "privilege", "Writes to your home directory", _writes_home, _P),
    CodeRule("setuid_bit", "privilege", "Potential privilege escalation (setuid/setcap)", _is_setuid, _PI),
    CodeRule("setuid_sandbox", "privilege", "Setuid sandbox helper (standard for Chromium/Electron apps)", _matches(SANDBOX_RE), _PI),
    CodeRule("setuid_bit", "privilege", "World-writable permissions (chmod 777)", _matches(WORLD_WRITABLE_RE), _PI),
]
# fmt: on

_BLOCKER_MESSAGES = {
    "privileged": "Fatal rule: privileged operation (score forced to 0)",
    "reverse_shell": "Fatal rule: reverse shell (score forced to 0)",
}

Hit = Tuple[str, int]  # (file, line number)


def _classify(name: str, text: str) -> Optional[str]:
    """What kind of package-repo file is this? None = not worth scanning."""
    base = name.rsplit("/", 1)[-1]
    low = base.lower()
    if base == "PKGBUILD":
        return None
    if low.endswith(".install"):
        return "install"
    if low.endswith(".hook"):
        return "hook"
    if low.endswith((".patch", ".diff")):
        return "patch"
    if os.path.splitext(low)[1] in _AUX_EXTS:
        return "aux"
    if "." not in low and text.startswith("#!"):
        return "aux"
    return None


def _scan(
    file: str,
    lines: List[str],
    scope: str,
    hits: Dict[Tuple[str, int], List[Hit]],
    code: Optional[List[CodeLine]] = None,
) -> None:
    """Run the code rules that apply to `scope` over a file's logical lines."""
    if code is None:
        code = _code_lines(_blank_comments(lines))
    for lineno, text, pieces in code:
        if not text.strip():
            continue
        for i, rule in enumerate(CODE_RULES):
            if scope in rule.scopes and rule.test(text, scope):
                # Point at the physical line that matches, else at the first one.
                n = next((n for n, p in pieces if rule.test(p, scope)), lineno)
                hits[(scope, i)].append((file, n))


def _truncate(lines: List[str]) -> Tuple[List[str], bool]:
    """Keep the first _MAX_INPUT characters of a file's lines."""
    total = 0
    for n, line in enumerate(lines):
        if total + len(line) + 1 > _MAX_INPUT:
            return lines[:n] + [line[: max(0, _MAX_INPUT - total)]], True
        total += len(line) + 1
    return lines, False


def _evidence(hits: List[Hit], files: Mapping[str, List[str]]) -> List[Evidence]:
    out: List[Evidence] = []
    seen: Set[Hit] = set()
    for f, n in hits:
        if (f, n) in seen or n > len(files.get(f, [])):
            continue
        seen.add((f, n))
        out.append(Evidence(f, n, files[f][n - 1].strip()[:120]))
        if len(out) == 3:
            break
    return out


def score_pkgbuild(
    lines: List[str],
    *,
    config: RulesConfig,
    local_path: pathlib.Path | None = None,
    aur_meta: dict | None = None,
    extra_files: Mapping[str, str] | None = None,
    now: float | None = None,
) -> ScoringResult:
    W = config.weights
    CAP = config.caps
    BLOCK = config.blockers
    now = time.time() if now is None else now

    cat: dict[str, int] = defaultdict(int)
    findings: List[Finding] = []
    lines, cut = _truncate(lines)
    files: Dict[str, List[str]] = {"PKGBUILD": lines}

    def note(
        message: str,
        bucket: str,
        rule: str,
        evidence: List[Evidence],
        penalty: Optional[int] = None,
    ) -> None:
        p = W.get(rule, 0) if penalty is None else penalty
        cat[bucket] += p
        findings.append(Finding(p, message, bucket, rule, evidence))

    def info(message: str, bucket: str, rule: str, evidence: List[Evidence]) -> None:
        findings.append(Finding(0, message, bucket, rule, evidence))

    def ev(lines_: List[int], file: str = "PKGBUILD") -> List[Evidence]:
        return _evidence([(file, n) for n in lines_], files)

    # Parse the PKGBUILD: comments out, plain-data metadata blanked ----
    text = "\n".join(_blank_comments(lines))
    assigns = _parse_assignments(text)
    code_text, heredocs = _split_heredocs(_blank(text, assigns).split("\n"))
    code = _code_lines(code_text)
    if cut:
        info(
            "Input truncated: only the first ~1 MB of the PKGBUILD was scanned",
            "integrity",
            "truncated_input",
            [],
        )
    long_lines = [n for n, t, _ in code if len(t) > _MAX_CMD_LINE]
    if long_lines:
        info(
            "Very long line(s) in the PKGBUILD: command analysis skipped "
            "(writes outside $pkgdir are not checked there)",
            "integrity",
            "long_line",
            ev(long_lines),
        )
    src = _parse_sources(text, assigns)
    entries = src.entries

    sources: List[str] = []
    for e in entries:
        label = "" if e.local else _source_label(e)
        if label and label not in sources:
            sources.append(label)

    # Integrity ----
    if entries and not src.any_sums:
        note(
            "No checksum array",
            "integrity",
            "missing_checksums",
            ev([e.line for e in entries]),
        )

    eligible = [e for e in entries if e.downloaded]
    skipped = [e for e in eligible if e.state == "skip"]
    if src.skip_unpaired:
        info(
            "SKIP used in checksums; entries couldn't be matched to sources "
            "(dynamic source array) \u2014 review",
            "integrity",
            "skip_unpaired",
            ev(src.unpaired_lines),
        )
    doc_skipped = [e for e in entries if e.remote_doc and e.state == "skip"]
    if doc_skipped:
        note(
            f"SKIP used in checksums for {len(doc_skipped)} documentation file(s)",
            "integrity",
            "skip_checksum_docs",
            ev([e.line for e in doc_skipped]),
        )
    if src.dynamic:
        info(
            "Source array is built dynamically; no source URL could be resolved "
            "\u2014 review the PKGBUILD",
            "integrity",
            "dynamic_sources",
            ev(src.source_lines),
        )
    if skipped or src.fallback_skip:
        if skipped and len(skipped) == len(eligible) and not src.fallback_skip:
            rule = "skip_checksum_all"
            msg = f"SKIP used in checksums for every downloaded file ({len(skipped)})"
        else:
            rule = "skip_checksum_some"
            msg = (
                f"SKIP used in checksums for {len(skipped)} downloaded file(s)"
                if skipped
                else "SKIP used in checksums for downloaded file(s)"
            )
        note(msg, "integrity", rule, ev([e.line for e in skipped or eligible]))

    if src.algos and src.algos <= {"md5", "sha1"}:
        note("Weak hash (md5/sha1)", "integrity", "weak_hash", ev(src.sums_lines))

    # Transport ----
    # An http source with a real checksum (or a commit-pinned VCS source) cannot be
    # tampered with in transit, so only unprotected ones count.
    insecure = [
        e
        for e in entries
        if not e.local
        and not e.sig
        and _scheme(e.url) in ("http", "ftp")
        and ((not e.commit) if e.vcs else e.state not in ("sum", "signed"))
    ]
    if insecure:
        note(
            f"{len(insecure)} unverified source(s) fetched over plain HTTP/FTP",
            "transport",
            "insecure_url",
            ev([e.line for e in insecure]),
            penalty=W.get("insecure_url", 0) * len(insecure),
        )

    unpinned = [e for e in entries if e.vcs and not e.pinned]
    if unpinned:
        evidence = ev([e.line for e in unpinned])
        if any(_VCS_NAME_RE.match(n) for n in src.pkgnames):
            info(
                "VCS package: builds the latest upstream commit",
                "transport",
                "vcs_package",
                evidence,
            )
        else:
            note(
                "Unpinned VCS source in a non-VCS package",
                "transport",
                "git_unpinned",
                evidence,
            )

    # Code rules: PKGBUILD, then the other files of the package repo ----
    hits: Dict[Tuple[str, int], List[Hit]] = defaultdict(list)
    _scan("PKGBUILD", lines, "pkgbuild", hits, code)
    if any(heredocs):  # files written into $pkgdir: judged like other bundled files
        _scan("PKGBUILD", lines, "aux", hits, _code_lines(_blank_comments(heredocs)))
    host_rule = next(i for i, r in enumerate(CODE_RULES) if r.key == "suspicious_host")
    for e in entries:  # sources are blanked above, but their hosts matter
        if not e.local and _is_bad_host(e.url):
            hits[("pkgbuild", host_rule)].append(("PKGBUILD", e.line))

    for name, content in (extra_files or {}).items():
        kind = _classify(name, content)
        if kind is None:
            continue
        flines, cut_file = _truncate(shell_lines(content))
        if cut_file:
            info(
                f"Input truncated: only the first ~1 MB of {name} was scanned",
                "integrity",
                "truncated_input",
                [],
            )
        files[name] = flines
        if kind == "install":
            funcs = [
                (n + 1, m.group(1))
                for n, l in enumerate(flines)
                if (m := _HOOK_DEF_RE.match(l))
            ]
            names = ", ".join(dict.fromkeys(f for _, f in funcs))
            base = name.rsplit("/", 1)[-1]
            info(
                f"Has install script {base} (runs as root{': ' + names if names else ''})",
                "privilege", "install_script", _evidence([(name, n) for n, _ in funcs], files),
            )  # fmt: skip
            code_i = _code_lines(_blank_comments(flines))
            _scan(name, flines, "install", hits, code_i)
            system: List[str] = []
            where: List[int] = []
            for lineno, text, _ in code_i:
                for d in _destinations(text):
                    if _OUTSIDE_RE.match(d):
                        system += [d] if d not in system else []
                        where.append(lineno)
            if system:
                shown = ", ".join(system[:5]) + (", ..." if len(system) > 5 else "")
                info(
                    f"Install script modifies system files: {shown}",
                    "privilege", "install_writes_system", _evidence([(name, n) for n in where], files),
                )  # fmt: skip
        elif kind == "hook":
            execs = [n + 1 for n, l in enumerate(flines) if re.match(r"\s*Exec\s*=", l)]
            info(
                f"Has pacman hook {name.rsplit('/', 1)[-1]} (runs as root on pacman transactions)",
                "privilege", "pacman_hook", _evidence([(name, n) for n in execs], files),
            )  # fmt: skip
            _scan(name, flines, "aux", hits)
        else:
            body = _patch_added_lines(flines) if kind == "patch" else flines
            _scan(name, flines, "aux", hits, _code_lines(_blank_comments(body)))

    reasons: Dict[str, List[str]] = {}  # blocker group -> why it fired
    first_hit: Dict[str, List[Evidence]] = {}
    for scope in _ALL:
        for i, cr in enumerate(CODE_RULES):
            h = hits.get((scope, i))
            if not h:
                continue
            msg = cr.message + _WHERE[scope]
            if scope == "install" and cr.install_message:
                msg = cr.install_message
            evidence = _evidence(h, files)
            note(msg, cr.category, cr.key, evidence)
            if cr.blocker and BLOCK.get(cr.blocker):
                group = (
                    "reverse_shell" if cr.blocker == "reverse_shell" else "privileged"
                )
                why = reasons.setdefault(group, [])
                if cr.message[0].lower() + cr.message[1:] not in why:
                    why.append(cr.message[0].lower() + cr.message[1:])
                first_hit.setdefault(group, evidence)

    if reasons:
        for group, why in reasons.items():
            msg = _BLOCKER_MESSAGES[group]
            if group == "privileged":
                msg = msg.replace(" (score", f" \u2014 {', '.join(why)} (score")
            findings.append(Finding(0, msg, "privilege", "blocker", first_hit[group]))
        return ScoringResult(0, findings, dict(cat), blocked=True, sources=sources)

    # Metadata absence ----
    if not any(re.match(r"\s*license=", l) for l in lines):
        note("No license field", "metadata", "no_license", [])
    if not any(l.startswith("arch=(") for l in lines):
        note("No arch field", "metadata", "no_arch_field", [])
    has_tag = any(re.match(r"#+\s*Maintainer\b", l, re.I) for l in lines)
    if not has_tag and not (aur_meta and aur_meta.get("Maintainer")):
        note("No maintainer tag", "metadata", "no_maintainer_tag", [])
    if n_err := namcap_errors(local_path):
        note(
            f"namcap {n_err} error(s)",
            "metadata",
            "namcap_error",
            [],
            penalty=W.get("namcap_error", 0) * n_err,
        )

    # Community / AUR ----
    if aur_meta:
        votes = aur_meta.get("NumVotes", 0)
        maint = aur_meta.get("Maintainer")
        ood = aur_meta.get("OutOfDate") not in (0, None)

        if votes < 1:
            note(f"Only {votes} votes", "community", "aur_low_votes_3", [])
        elif votes < 15:
            note(f"Only {votes} votes", "community", "aur_low_votes_2", [])
        elif votes < 30:
            note(f"Only {votes} votes", "community", "aur_low_votes_1", [])

        if maint in (None, "", "orphan"):
            note("Package is orphaned", "community", "aur_orphaned", [])

        if ood:
            age_days = int((now - aur_meta["OutOfDate"]) / 86400)
            when = {0: "today", 1: "1 day"}.get(age_days, f"{age_days} days")
            rule = "aur_out_of_date_recent" if age_days < 30 else "aur_out_of_date"
            note(f"Flagged out of date ({when})", "community", rule, [])

        if aur_meta.get("FirstSubmitted"):
            age_days = int((now - aur_meta["FirstSubmitted"]) / 86400)
            if age_days < 7:
                rule = "aur_very_new_package"
            elif age_days < 30:
                rule = "aur_new_package"
            else:
                rule = ""
            if rule:
                note(
                    f"New package: first submitted {age_days} days ago (not yet vetted)",
                    "community",
                    rule,
                    [],
                )

    # Apply caps ----
    for k, v in cat.items():
        cap = CAP.get(k)
        if cap is not None and v < cap:
            cat[k] = cap
    score = 100 + sum(cat.values())
    return ScoringResult(max(0, score), findings, dict(cat), sources=sources)
