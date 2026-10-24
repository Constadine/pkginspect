from __future__ import annotations

import datetime
import json
import os
import re
import sys
import textwrap
from typing import Any, Dict, List, Optional, Tuple

from pkginspect.fetchers import Package
from pkginspect.scoring import Finding, ScoringResult


def _use_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# ANSI escape helpers
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"

_CROSS = "✗"
_INFO = "ℹ"
_DOT = " · "
_DASH = "—"


_UNSAFE = re.compile(
    "[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)


def _safe(value: Any) -> str:
    """Make untrusted text printable: controls become visible escapes."""
    text = str(value).encode("utf-8", "backslashreplace").decode("utf-8")
    return _UNSAFE.sub(lambda m: m.group().encode("unicode_escape").decode(), text)


def _c(text: str, code: str) -> str:
    if not _use_color():
        return text
    return f"{code}{text}{_RESET}"


def grade(score: int) -> tuple[str, str]:
    if score >= 90:
        return "\U0001f7e2", "Excellent"
    if score >= 70:
        return "\U0001f7e1", "Good"
    if score >= 50:
        return "\U0001f7e0", "Fair"
    return "\U0001f534", "Poor"


def _score_color(score: int) -> str:
    if score >= 90:
        return _GREEN
    if score >= 50:
        return _YELLOW
    return _RED


def _sorted_findings(result: ScoringResult) -> List[Finding]:
    """Biggest penalty first; informational (0) findings last."""
    return sorted(result.findings, key=lambda f: -abs(f.penalty))


# ---------------------------------------------------------------- metadata


def _date(ts: Any) -> str:
    when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return when.strftime("%Y-%m-%d")


def _iso(ts: Any) -> Optional[str]:
    if not ts:
        return None
    when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_ago(ts: Any) -> int:
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    return max(0, int((now - ts) // 86400))


def _pkgbuild_version(pkgbuild: str) -> str:
    """Best-effort [epoch:]pkgver[-pkgrel] from literal assignments."""

    def literal(name: str) -> str:
        m = re.search(rf"^{name}=['\"]?([^\s'\"$()]+)['\"]?\s*$", pkgbuild, re.M)
        return m.group(1) if m else ""

    ver = literal("pkgver")
    if not ver:
        return ""
    epoch, rel = literal("epoch"), literal("pkgrel")
    return (f"{epoch}:" if epoch else "") + ver + (f"-{rel}" if rel else "")


def _version(pkg: Package) -> str:
    return str(pkg.meta.get("Version") or "") or _pkgbuild_version(pkg.pkgbuild)


def _source_label(pkg: Package) -> str:
    if pkg.source == "aur" and pkg.required_by:
        return f"AUR, dependency of {pkg.required_by}"
    return "AUR" if pkg.source == "aur" else pkg.source


def _meta_line(pkg: Package) -> str:
    m = pkg.meta
    if pkg.source != "aur" or not m:
        return ""
    maintainer = m.get("Maintainer")
    parts = [_safe(maintainer) if maintainer else _c("orphan", _RED)]
    try:
        parts.append(f"{_safe(m.get('NumVotes', 0))} votes")
    except Exception:
        pass
    try:
        parts.append(f"popularity {float(m.get('Popularity') or 0):.2f}")
    except Exception:
        pass
    try:
        first = m.get("FirstSubmitted")
        if first:
            since = f"since {_date(first)}"
            days = _days_ago(first)
            if days < 30:
                since += " " + _c(f"({days} days ago)", _YELLOW + _BOLD)
            parts.append(since)
    except Exception:
        pass
    try:
        if m.get("LastModified"):
            parts.append(f"updated {_date(m['LastModified'])}")
    except Exception:
        pass
    try:
        if m.get("OutOfDate"):
            parts.append(_c(f"out of date since {_date(m['OutOfDate'])}", _RED))
    except Exception:
        pass
    return _DOT.join(parts)


# -------------------------------------------------------------------- text


def _header(pkg: Optional[Package], result: ScoringResult) -> str:
    badge, label = grade(result.score)
    what = _safe(pkg.name) if pkg else "PKGBUILD"
    if pkg:
        what = f"{what} {_safe(_version(pkg))}".strip()
        what += f" ({_safe(_source_label(pkg))})"
    score = _c(f"{result.score}/100", _score_color(result.score) + _BOLD)
    head = f"{badge} {_c(what, _BOLD)} {_DASH} {score} {label}"
    if result.blocked:
        head += _DOT + _c("blocked", _RED)
    return head


def _finding_lines(f: Finding) -> List[str]:
    if f.penalty:
        out = [f"   {_c(f'{f.penalty:>+3d}', _RED)}  {_safe(f.message)}"]
    else:
        out = [f"     {_INFO}  {_safe(f.message)}"]
    for ev in f.evidence[:3]:
        out.append(
            _c(f"        {_safe(ev.file)}:{_safe(ev.line)}  {_safe(ev.text)}", _DIM)
        )
    if len(f.evidence) > 3:
        out.append(_c(f"        … and {len(f.evidence) - 3} more", _DIM))
    return out


def format_text(
    result: ScoringResult,
    *,
    lines: Optional[List[str]] = None,
    debug: bool = False,
    rules_path: Optional[str] = None,
    package: Optional[Package] = None,
) -> str:
    parts: List[str] = []

    if debug:
        if rules_path:
            parts.append(_c(f"Rules: {_safe(rules_path)}", _CYAN))
        if lines is not None:
            parts.append("\n" + _c("─── PKGBUILD analysed ───", _BOLD))
            parts.append(textwrap.indent("\n".join(_safe(ln) for ln in lines), "  "))
        parts.append("\n" + _c("─── Category totals ───", _BOLD))
        for k, v in result.categories.items():
            parts.append(f"  {_safe(k):12}: {_c(f'{v:+}', _RED)}")
        parts.append("")

    parts.append(_header(package, result))
    meta = _meta_line(package) if package else ""
    if meta:
        parts.append("   " + meta)
    if result.sources:
        parts.append(
            "   " + _c("sources: ", _DIM) + ", ".join(_safe(x) for x in result.sources)
        )

    findings = _sorted_findings(result)
    if not findings:
        parts.append("   No issues found.")
    else:
        parts.append("")
        for f in findings:
            parts.extend(_finding_lines(f))
    return "\n".join(parts)


def format_error(pkg: Package) -> str:
    return f"{_c(_CROSS, _RED)} {_safe(pkg.name)} {_DASH} {_safe(pkg.error)}"


def format_summary(entries: List[Tuple[Package, Optional[ScoringResult]]]) -> str:
    """Compact table; entries are (package, result), result None on error."""
    if not entries:
        return ""
    width = max(len(_safe(p.name)) for p, _ in entries)
    out = [_c("Summary", _BOLD)]
    for pkg, result in entries:
        name = _safe(pkg.name).ljust(width)
        if result is None:
            row = f"  {_c(_CROSS, _RED)}       {name}   {_safe(pkg.error)}"
        else:
            badge, _ = grade(result.score)
            worst = _sorted_findings(result)
            note = _safe(worst[0].message) if worst and worst[0].penalty else ""
            score = _c(f"{result.score:>3}", _score_color(result.score))
            row = f"  {badge} {score}  {name}   {note}"
        out.append(row.rstrip())
    return "\n".join(out)


# -------------------------------------------------------------------- JSON


def _aur_object(pkg: Package) -> Dict[str, Any]:
    m = pkg.meta
    return {
        "name": m.get("Name", pkg.name),
        "version": m.get("Version"),
        "maintainer": m.get("Maintainer"),
        "votes": m.get("NumVotes"),
        "popularity": m.get("Popularity"),
        "first_submitted": _iso(m.get("FirstSubmitted")),
        "last_modified": _iso(m.get("LastModified")),
        "out_of_date": _iso(m.get("OutOfDate")),
    }


def json_data(
    result: ScoringResult,
    *,
    source: Optional[str] = None,
    package: Optional[str] = None,
    pkg: Optional[Package] = None,
) -> Dict[str, Any]:
    _, label = grade(result.score)
    data: Dict[str, Any] = {
        "score": result.score,
        "grade": label,
        "blocked": result.blocked,
        "findings": [
            {
                "penalty": f.penalty,
                "message": f.message,
                "category": f.category,
                "rule": f.rule,
                "evidence": [
                    {"file": e.file, "line": e.line, "text": e.text} for e in f.evidence
                ],
            }
            for f in _sorted_findings(result)
        ],
        "categories": result.categories,
        "sources": result.sources,
    }
    if pkg:
        source, package = pkg.source, pkg.name
        data["required_by"] = pkg.required_by
        if pkg.source == "aur" and pkg.meta:
            data["aur"] = _aur_object(pkg)
    if source or package:
        data["meta"] = {"source": source, "package": package}
    return data


def error_data(pkg: Package) -> Dict[str, Any]:
    return {"package": pkg.name, "source": pkg.source, "error": pkg.error}


def format_json(
    result: ScoringResult,
    *,
    source: Optional[str] = None,
    package: Optional[str] = None,
    pkg: Optional[Package] = None,
) -> str:
    data = json_data(result, source=source, package=package, pkg=pkg)
    return json.dumps(data, indent=2)
