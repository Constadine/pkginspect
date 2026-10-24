from __future__ import annotations

import json
import time

import pytest

from pkginspect import cli
from pkginspect.fetchers import FetchError, Package

CLEAN = "pkgname=ok\npkgver=1\npkgrel=1\n"


def aur(name: str, pkgbuild: str = CLEAN, **kw) -> Package:
    meta = {"Name": name, "Version": "1-1", "NumVotes": 5, "Maintainer": "me"}
    meta["FirstSubmitted"] = meta["LastModified"] = time.time() - 900 * 86400
    return Package(name=name, source="aur", pkgbuild=pkgbuild, meta=meta, **kw)


def run(monkeypatch, capsys, *argv):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr("sys.argv", ["pkginspect", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


@pytest.fixture
def seen(monkeypatch):
    """Patch the AUR fetcher; records the calls it received."""
    calls = []

    def fake(names, *, deps=False):
        calls.append((list(names), deps))
        return [aur(n) for n in names]

    monkeypatch.setattr(cli, "fetch_aur_packages", fake)
    return calls


def test_positional_names_go_to_aur(monkeypatch, capsys, seen):
    code, out, _ = run(monkeypatch, capsys, "yay", "paru")
    assert code == 0
    assert seen == [(["yay", "paru"], False)]
    assert "yay" in out and "paru" in out and "Summary" in out


def test_aur_flag_repeatable_and_combined_with_positional(monkeypatch, capsys, seen):
    run(monkeypatch, capsys, "yay", "--aur", "paru", "--aur", "bat", "--deps")
    assert seen == [(["yay", "paru", "bat"], True)]


def test_mixed_targets(monkeypatch, capsys, seen):
    monkeypatch.setattr(
        cli,
        "fetch_official_package",
        lambda n: Package(name=n, source="official", pkgbuild=CLEAN),
    )
    monkeypatch.setattr(
        cli,
        "load_file_package",
        lambda p: Package(name=p, source="file", pkgbuild=CLEAN),
    )
    monkeypatch.setattr(
        cli,
        "fetch_url_package",
        lambda u: Package(name=u, source="url", pkgbuild=CLEAN),
    )
    code, out, _ = run(
        monkeypatch,
        capsys,
        "yay",
        "--official",
        "bash",
        "--file",
        "PKGBUILD",
        "--url",
        "http://x/PKGBUILD",
    )
    assert code == 0
    for label in ("(AUR)", "(official)", "(file)", "(url)"):
        assert label in out


def test_no_target_is_usage_error(monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys)
    assert code == 2 and "at least one package" in err


def test_fail_under(monkeypatch, capsys, seen):
    from pkginspect.scoring import ScoringResult

    monkeypatch.setattr(
        cli, "score_pkgbuild", lambda *a, **k: ScoringResult(60, [], {})
    )
    assert run(monkeypatch, capsys, "yay", "--fail-under", "50")[0] == 0
    assert run(monkeypatch, capsys, "yay", "--fail-under", "70")[0] == 1
    assert run(monkeypatch, capsys, "yay")[0] == 0


def test_failed_fetch_exits_1_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch_aur_packages",
        lambda names, deps=False: [
            aur("yay"),
            Package(name="nope", source="aur", error="not found in the AUR"),
        ],
    )
    code, out, err = run(monkeypatch, capsys, "yay", "nope")
    assert code == 1
    assert "✗ nope" in out and "Traceback" not in out + err


def test_fetch_error_is_friendly(monkeypatch, capsys):
    def boom(names, deps=False):
        raise FetchError("AUR is unreachable")

    monkeypatch.setattr(cli, "fetch_aur_packages", boom)
    code, out, err = run(monkeypatch, capsys, "yay")
    assert code == 1
    assert err.strip() == "pkginspect: error: AUR is unreachable"


def test_oserror_and_debug_traceback(monkeypatch, capsys):
    def boom(path):
        raise FileNotFoundError("no such file: PKGBUILD")

    monkeypatch.setattr(cli, "load_file_package", boom)
    code, _, err = run(monkeypatch, capsys, "--file", "PKGBUILD")
    assert code == 1 and "pkginspect: error:" in err and "Traceback" not in err
    code, _, err = run(monkeypatch, capsys, "--file", "PKGBUILD", "-d")
    assert code == 1 and "Traceback" in err


def test_keyboard_interrupt(monkeypatch, capsys):
    def boom(names, deps=False):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "fetch_aur_packages", boom)
    assert run(monkeypatch, capsys, "yay")[0] == 130


def test_json_two_packages_is_array(monkeypatch, capsys, seen):
    code, out, _ = run(monkeypatch, capsys, "yay", "paru", "--json")
    data = json.loads(out)
    assert code == 0 and isinstance(data, list) and len(data) == 2
    assert data[0]["meta"]["package"] == "yay"
    assert data[0]["aur"]["version"] == "1-1"


def test_json_single_is_object_and_error_slot(monkeypatch, capsys, seen):
    code, out, _ = run(monkeypatch, capsys, "yay", "--json")
    assert isinstance(json.loads(out), dict)

    monkeypatch.setattr(
        cli,
        "fetch_aur_packages",
        lambda names, deps=False: [
            Package(name="nope", source="aur", error="not found in the AUR")
        ],
    )
    code, out, _ = run(monkeypatch, capsys, "nope", "--json")
    assert code == 1
    assert json.loads(out) == {
        "package": "nope",
        "source": "aur",
        "error": "not found in the AUR",
    }


def test_aur_meta_only_for_aur(monkeypatch, capsys, seen):
    got = {}

    def fake_score(lines, **kw):
        got.setdefault("kw", []).append(kw)
        from pkginspect.scoring import ScoringResult

        return ScoringResult(100, [], {})

    monkeypatch.setattr(cli, "score_pkgbuild", fake_score)
    monkeypatch.setattr(
        cli,
        "fetch_official_package",
        lambda n: Package(name=n, source="official", pkgbuild=CLEAN, meta={"a": 1}),
    )
    run(monkeypatch, capsys, "yay", "--official", "bash")
    assert got["kw"][0]["aur_meta"]["Name"] == "yay"
    assert not got["kw"][1]["aur_meta"]


def test_formatter_crash_becomes_error_entry(monkeypatch, capsys, seen):
    real = cli.format_text

    def flaky(result, **kw):
        if kw["package"].name == "bad":
            raise ValueError("boom")
        return real(result, **kw)

    monkeypatch.setattr(cli, "format_text", flaky)
    code, out, err = run(monkeypatch, capsys, "good", "bad")
    assert code == 1 and "Traceback" not in out + err
    assert "good" in out and "\u2717 bad" in out and "boom" in out


def test_unexpected_error_is_one_line(monkeypatch, capsys):
    def boom(names, deps=False):
        raise ValueError("weird")

    monkeypatch.setattr(cli, "fetch_aur_packages", boom)
    code, _, err = run(monkeypatch, capsys, "yay")
    assert code == 1 and err.startswith("pkginspect: internal error:")
    assert "Traceback" not in err
