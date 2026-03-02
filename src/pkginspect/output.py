from __future__ import annotations

import json
import os
import sys
import textwrap
from typing import Any, List

from pkginspect.scoring import ScoringResult


def _use_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# ANSI escape helpers
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


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
    if score >= 70:
        return _YELLOW
    if score >= 50:
        return _YELLOW
    return _RED


def format_text(
    result: ScoringResult,
    *,
    lines: List[str] | None = None,
    debug: bool = False,
    rules_path: str | None = None,
) -> str:
    parts: list[str] = []
    color = _use_color()

    sorted_findings = sorted(
        result.findings, key=lambda f: abs(f.penalty), reverse=True
    )
    biggest = (
        f"{sorted_findings[0].message} ({sorted_findings[0].penalty})"
        if sorted_findings
        else "None"
    )

    badge, label = grade(result.score)
    sc = _score_color(result.score)

    if debug:
        if rules_path:
            parts.append(_c(f"Rules: {rules_path}", _CYAN))
        if lines is not None:
            parts.append(
                "\n"
                + _c("\u2500\u2500\u2500 PKGBUILD analysed \u2500\u2500\u2500", _BOLD)
            )
            parts.append(textwrap.indent("\n".join(lines), "  "))
        parts.append(
            "\n" + _c("\u2500\u2500\u2500 Category totals \u2500\u2500\u2500", _BOLD)
        )
        for k, v in result.categories.items():
            parts.append(f"  {k:12}: {_c(f'{v:+}', _RED)}")
        parts.append("")

    score_text = f"{result.score}/100"
    if color:
        score_text = _c(score_text, sc + _BOLD)
    parts.append(f"{badge}  PKGBUILD safety score: {score_text}  \u2192  {label}")
    parts.append(f"Biggest flaw: {biggest}\n")
    for f in sorted_findings:
        penalty_str = f"({f.penalty})"
        if color:
            penalty_str = _c(penalty_str, _RED)
        parts.append(f"- {f.message} {penalty_str}")

    return "\n".join(parts)


def format_json(
    result: ScoringResult,
    *,
    source: str | None = None,
    package: str | None = None,
) -> str:
    _, label = grade(result.score)
    data: dict[str, Any] = {
        "score": result.score,
        "grade": label,
        "findings": [
            {
                "penalty": f.penalty,
                "message": f.message,
                "category": f.category,
            }
            for f in sorted(result.findings, key=lambda f: abs(f.penalty), reverse=True)
        ],
        "categories": result.categories,
    }
    if source or package:
        data["meta"] = {"source": source, "package": package}
    return json.dumps(data, indent=2)
