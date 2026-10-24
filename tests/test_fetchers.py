from __future__ import annotations

import io
import json
import tarfile
from typing import Dict, List, Optional

import pytest
import requests

from pkginspect import fetchers
from pkginspect.fetchers import FetchError


class FakeResponse:
    def __init__(self, body=b"", status: int = 200):
        if isinstance(body, str):
            body = body.encode()
        self.content = body
        self.status_code = status

    @property
    def text(self) -> str:
        return self.content.decode()

    def json(self):
        return json.loads(self.content)

    def iter_content(self, size: int):
        for i in range(0, len(self.content), size):
            yield self.content[i : i + size]

    def close(self):
        pass


def json_response(obj) -> FakeResponse:
    return FakeResponse(json.dumps(obj))


def make_tar(members: List[tarfile.TarInfo], datas: List[bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for info, data in zip(members, datas):
            tar.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return buf.getvalue()


def reg(name: str, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def tar_of(*items) -> bytes:
    return make_tar([i for i, _ in items], [d for _, d in items])


@pytest.fixture
def fake_net(monkeypatch):
    """Route fetchers._get to a dict of {url-substring: response or callable}."""
    routes: Dict[str, object] = {}
    calls: List[str] = []

    def fake_get(url: str, *, stream: bool = False):
        calls.append(url)
        for key, resp in routes.items():
            if key in url:
                return resp(url) if callable(resp) else resp
        return FakeResponse("not found", 404)

    monkeypatch.setattr(fetchers, "_get", fake_get)
    routes["_calls"] = calls  # type: ignore[assignment]
    return routes


def calls_of(routes) -> List[str]:
    return routes["_calls"]  # type: ignore[return-value]


def rpc(*infos) -> FakeResponse:
    return json_response(
        {"resultcount": len(infos), "results": list(infos), "type": "multiinfo"}
    )


def info(name: str, base: Optional[str] = None, **extra) -> dict:
    return {"Name": name, "PackageBase": base or name, "NumVotes": 1, **extra}


def snapshot(base: str, pkgbuild: str = "pkgname=x\n", **files: str) -> FakeResponse:
    items = [reg(f"{base}/PKGBUILD", pkgbuild.encode())]
    items += [reg(f"{base}/{k}", v.encode()) for k, v in files.items()]
    return FakeResponse(tar_of(*items))


# ── snapshot parsing ──────────────────────────────────────────────


def test_snapshot_skips_unsafe_and_binary_members(fake_net):
    symlink = tarfile.TarInfo("evil/link")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"
    big = b"x" * (fetchers.MAX_MEMBER_BYTES + 1)
    data = tar_of(
        reg("evil/PKGBUILD", b"pkgname=evil\n"),
        reg("evil/foo.install", b"post_install() { echo hi; }\n"),
        reg("evil/../evil2", b"nope"),
        reg("/abs/path", b"nope"),
        (symlink, b""),
        reg("evil/huge.txt", big),
        reg("evil/blob.bin", b"\x00\x01binary"),
    )
    fake_net["snapshot/evil.tar.gz"] = FakeResponse(data)
    files = fetchers.fetch_aur_snapshot("evil")
    assert set(files) == {"PKGBUILD", "foo.install"}
    assert "post_install" in files["foo.install"]


def test_snapshot_missing_pkgbuild_and_404(fake_net):
    fake_net["snapshot/nopkg.tar.gz"] = FakeResponse(tar_of(reg("nopkg/a", b"a")))
    with pytest.raises(FetchError, match="no PKGBUILD"):
        fetchers.fetch_aur_snapshot("nopkg")
    with pytest.raises(FetchError):
        fetchers.fetch_aur_snapshot("gone")


def test_snapshot_over_size_limit(fake_net, monkeypatch):
    monkeypatch.setattr(fetchers, "MAX_SNAPSHOT_BYTES", 1024 * 1024)
    fake_net["snapshot/big.tar.gz"] = FakeResponse(b"x" * (2 * 1024 * 1024))
    with pytest.raises(FetchError, match="over 1 MiB"):
        fetchers.fetch_aur_snapshot("big")


def test_snapshot_gzip_bomb_decompressed_cap(fake_net, monkeypatch):
    monkeypatch.setattr(fetchers, "MAX_DECOMPRESSED_BYTES", 1024 * 1024)
    monkeypatch.setattr(fetchers, "MAX_MEMBER_BYTES", 10 * 1024)
    # one member header claiming far more than allowed: skipped, but must be
    # streamed through the counting wrapper, which aborts
    bomb = reg("bomb/zeros", b"\0" * (3 * 1024 * 1024))
    fake_net["snapshot/bomb.tar.gz"] = FakeResponse(
        tar_of(reg("bomb/PKGBUILD", b"x=1\n"), bomb)
    )
    with pytest.raises(FetchError, match="snapshot too large"):
        fetchers.fetch_aur_snapshot("bomb")


def test_snapshot_cumulative_read_cap(fake_net, monkeypatch):
    monkeypatch.setattr(fetchers, "MAX_TOTAL_READ_BYTES", 1000)
    items = [reg("p/PKGBUILD", b"x=1\n")] + [
        reg(f"p/f{i}", b"a" * 400) for i in range(5)
    ]
    fake_net["snapshot/p.tar.gz"] = FakeResponse(tar_of(*items))
    with pytest.raises(FetchError, match="snapshot too large"):
        fetchers.fetch_aur_snapshot("p")


def test_snapshot_non_utf8_member_name_is_printable(fake_net):
    info_, data = reg("p/x.install", b"hi")
    info_.name = b"p/\xff.install".decode("utf-8", "surrogateescape")
    fake_net["snapshot/p.tar.gz"] = FakeResponse(
        tar_of(reg("p/PKGBUILD", b"x=1\n"), (info_, data))
    )
    files = fetchers.fetch_aur_snapshot("p")
    for name in files:
        name.encode("utf-8")  # must not raise
    assert len(files) == 2


def test_network_error_becomes_fetch_error(monkeypatch):
    def boom(url, **kw):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(fetchers.time, "sleep", lambda s: None)
    monkeypatch.setattr(fetchers.SESSION, "get", boom)
    with pytest.raises(FetchError, match="Could not reach the AUR"):
        fetchers.aur_info(["a"])


# ── AUR packages ──────────────────────────────────────────────────


def test_split_package_fetches_base_once(fake_net):
    fake_net["rpc/v5/info"] = rpc(
        info("linux-xanmod", "linux-xanmod"),
        info("linux-xanmod-headers", "linux-xanmod"),
    )
    fake_net["snapshot/linux-xanmod.tar.gz"] = snapshot(
        "linux-xanmod", "pkgbase=linux-xanmod\n", **{"linux.install": "echo\n"}
    )
    pkgs = fetchers.fetch_aur_packages(
        ["linux-xanmod-headers", "linux-xanmod", "linux-xanmod-headers"]
    )
    assert [p.name for p in pkgs] == ["linux-xanmod-headers", "linux-xanmod"]
    assert all(p.pkgbase == "linux-xanmod" for p in pkgs)
    assert pkgs[0].files == {"linux.install": "echo\n"}
    assert pkgs[0].meta["Name"] == "linux-xanmod-headers"
    assert sum("snapshot/" in c for c in calls_of(fake_net)) == 1
    assert sum("rpc/v5/info" in c for c in calls_of(fake_net)) == 1


def test_not_found_suggestions_and_official_hint(fake_net):
    fake_net["rpc/v5/info"] = rpc(info("yay"))
    fake_net["snapshot/yay.tar.gz"] = snapshot("yay")
    fake_net["archlinux.org/packages/search"] = lambda url: json_response(
        {"results": [{"pkgbase": "bash"}] if "name=bash" in url else []}
    )
    fake_net["rpc/v5/search/yoy"] = json_response(
        {
            "results": [
                {"Name": "yoyo", "NumVotes": 1},
                {"Name": "yoy-b", "NumVotes": 50},
                {"Name": "yoy-c", "NumVotes": 10},
                {"Name": "yoy-d", "NumVotes": 5},
                {"Name": "python-hyperpyyaml-git", "NumVotes": 999},
            ]
        }
    )
    pkgs = fetchers.fetch_aur_packages(["yay", "bash", "yoy"])
    assert [p.error is None for p in pkgs] == [True, False, False]
    assert pkgs[1].error == "'bash' is in the official repos; use --official bash"
    assert "did you mean: yoyo, yoy-b, yoy-c?" in (pkgs[2].error or "")
    assert "not found in the AUR" in (pkgs[2].error or "")


def test_deps_recursion_with_cycle(fake_net):
    infos = {
        "a": info("a", Depends=["b>=1.2", "glibc"], MakeDepends=["c"]),
        "b": info("b", Depends=["a", "d"]),  # cycle back to a
        "c": info("c", CheckDepends=["b"]),
        "d": info("d"),
    }

    def rpc_route(url: str):
        from urllib.parse import parse_qs, urlparse

        wanted = parse_qs(urlparse(url).query)["arg[]"]
        return rpc(*[infos[n] for n in wanted if n in infos])

    fake_net["rpc/v5/info"] = rpc_route
    for n in infos:
        fake_net[f"snapshot/{n}.tar.gz"] = snapshot(n)
    pkgs = fetchers.fetch_aur_packages(["a"], deps=True)
    assert [(p.name, p.required_by) for p in pkgs] == [
        ("a", None),
        ("b", "a"),
        ("c", "a"),
        ("d", "b"),
    ]
    # glibc was looked up but is not in the AUR: ignored, no error package
    assert all(p.error is None for p in pkgs)


# ── official repos ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "base, path",
    [
        ("libsigc++", "libsigcplusplus"),
        ("gtk2+extra", "gtk2-extra"),
        ("tree", "unix-tree"),
        ("bash", "bash"),
        ("python_foo", "python_foo"),
    ],
)
def test_gitlab_path(base, path):
    assert fetchers.gitlab_path(base) == path


def test_official_package_with_install(fake_net):
    fake_net["packages/search"] = json_response({"results": [{"pkgbase": "libsigc++"}]})
    fake_net["libsigcplusplus/-/raw/main/PKGBUILD"] = FakeResponse(
        "pkgname=libsigc++\ninstall=$pkgname.install\n"
    )
    fake_net["libsigcplusplus/-/raw/main/libsigc%2B%2B.install"] = FakeResponse(
        "hook\n"
    )
    p = fetchers.fetch_official_package("libsigc++")
    assert p.error is None and p.meta == {} and p.source == "official"
    assert p.pkgbase == "libsigc++"
    assert p.files == {"libsigc++.install": "hook\n"}


def test_official_not_found(fake_net):
    fake_net["packages/search"] = json_response({"results": []})
    p = fetchers.fetch_official_package("nope")
    assert (
        p.error == "'nope' is not in the official repos; try the AUR: pkginspect nope"
    )
    with pytest.raises(RuntimeError, match="not found in official mirrors"):
        fetchers.fetch_official("nope")


# ── local files and URLs ──────────────────────────────────────────


def test_load_file_package_and_directory(tmp_path):
    (tmp_path / "PKGBUILD").write_text(
        "install=foo.install\n"
        "source=('https://x.org/a.tgz' 'fix.patch' 'ren::local.sh' 'big.bin' '$x')\n"
    )
    (tmp_path / "foo.install").write_text("post_install() { :; }\n")
    (tmp_path / "fix.patch").write_text("patch\n")
    (tmp_path / "local.sh").write_text("#!/bin/sh\n")
    (tmp_path / "big.bin").write_bytes(b"\x00\x01")
    (tmp_path / "unrelated.txt").write_text("do not read")
    for arg in (str(tmp_path / "PKGBUILD"), str(tmp_path)):
        p = fetchers.load_file_package(arg)
        assert p.error is None and p.source == "file"
        assert set(p.files) == {"foo.install", "fix.patch", "local.sh"}
        assert p.local_path == tmp_path / "PKGBUILD"


def test_load_file_package_missing(tmp_path):
    assert fetchers.load_file_package(str(tmp_path / "nope")).error


def test_fetch_url_package_rejects_html(fake_net):
    fake_net["page.html"] = FakeResponse("<!DOCTYPE html><html></html>")
    fake_net["raw/PKGBUILD"] = FakeResponse("pkgname=x\n")
    assert "HTML page" in (
        fetchers.fetch_url_package("https://h/page.html").error or ""
    )
    p = fetchers.fetch_url_package("https://h/raw/PKGBUILD")
    assert p.error is None and p.pkgbuild == "pkgname=x\n"


# ── backward compatibility ────────────────────────────────────────


def test_backward_compatible_functions(fake_net):
    fake_net["rpc/v5/info"] = rpc(info("yay"))
    fake_net["snapshot/yay.tar.gz"] = snapshot("yay", "pkgname=yay\npkgver=1\n")
    assert fetchers.aur_metadata("yay")["Name"] == "yay"
    assert fetchers.fetch_aur("yay") == ["pkgname=yay", "pkgver=1"]
    fake_net["page"] = FakeResponse("a\nb\n")
    assert fetchers.fetch_url("https://h/page") == ["a", "b"]
    assert fetchers.domain("https://GitHub.com/x") == "github.com"
    assert "github.com" in fetchers.HTTPS_OK


def test_aur_metadata_swallows_errors(monkeypatch):
    def boom(*a, **k):
        raise FetchError("down")

    monkeypatch.setattr(fetchers, "_get", boom)
    assert fetchers.aur_metadata("x") == {}


def test_fetch_official_lines(fake_net):
    fake_net["packages/search"] = json_response({"results": [{"pkgbase": "bash"}]})
    fake_net["packages/bash/-/raw/main/PKGBUILD"] = FakeResponse("pkgname=bash\n")
    assert fetchers.fetch_official("bash") == ["pkgname=bash"]


def test_no_suggestion_when_all_candidates_are_weak(fake_net):
    fake_net["rpc/v5/info"] = rpc()
    fake_net["rpc/v5/search/yya"] = json_response(
        {"results": [{"Name": "python-types-pyyaml", "NumVotes": 100}]}
    )
    err = fetchers.fetch_aur_packages(["yya"])[0].error
    assert err == "'yya' was not found in the AUR"


class _Resp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}

    def close(self):
        pass


def _patch_session(monkeypatch, outcomes):
    sleeps: List[float] = []
    monkeypatch.setattr(fetchers.time, "sleep", sleeps.append)

    def fake(url, **kw):
        o = outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return o

    monkeypatch.setattr(fetchers.SESSION, "get", fake)
    return sleeps


def test_get_retries_once_on_429_honouring_retry_after(monkeypatch):
    sleeps = _patch_session(monkeypatch, [_Resp(429, {"Retry-After": "3"}), _Resp(200)])
    assert fetchers._get("https://aur.archlinux.org/x").status_code == 200
    assert sleeps == [3.0]


def test_get_retries_once_on_connection_error(monkeypatch):
    sleeps = _patch_session(monkeypatch, [requests.ConnectionError("x"), _Resp(200)])
    assert fetchers._get("https://aur.archlinux.org/x").status_code == 200
    assert sleeps == [fetchers.RETRY_DELAY]


def test_get_ignores_huge_retry_after_and_gives_up_after_one_retry(monkeypatch):
    sleeps = _patch_session(
        monkeypatch, [_Resp(503, {"Retry-After": "99"}), _Resp(503)]
    )
    assert fetchers._get("https://aur.archlinux.org/x").status_code == 503
    assert sleeps == [fetchers.RETRY_DELAY]
    _patch_session(
        monkeypatch, [requests.ConnectionError("a"), requests.ConnectionError("b")]
    )
    with pytest.raises(FetchError, match="Could not reach the AUR"):
        fetchers._get("https://aur.archlinux.org/x")


def test_regexes_are_linear_on_blank_lines():
    import time as _t

    text = "\n" * 200_000 + "x"
    start = _t.time()
    assert fetchers._local_sources(text) == []
    assert fetchers._install_file(text, "a", "a") is None
    assert _t.time() - start < 2


def test_domain_is_forgiving():
    assert fetchers.domain("foo") == "foo"
    assert fetchers.domain("https://GitHub.com/x") == "github.com"
    assert fetchers.domain("http://[bad") == "http://[bad"


def test_invalid_url_gives_friendly_error_without_retry(monkeypatch):
    sleeps: List[float] = []
    monkeypatch.setattr(fetchers.time, "sleep", sleeps.append)
    p = fetchers.fetch_url_package("foo")
    assert p.error and "not a valid URL" in p.error
    assert sleeps == []


def test_text_is_size_capped(fake_net, monkeypatch):
    monkeypatch.setattr(fetchers, "MAX_TEXT_BYTES", 1024)
    fake_net["big"] = FakeResponse(b"a" * 5000)
    p = fetchers.fetch_url_package("https://h/big")
    assert p.error and "over" in p.error


def test_local_symlinks_and_escapes_are_not_read(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "PKGBUILD").write_text("install=foo.install\nsource=(link.txt good.txt)\n")
    (d / "foo.install").symlink_to(outside)
    (d / "link.txt").symlink_to(outside)
    (d / "good.txt").write_text("ok")
    p = fetchers.load_file_package(str(d))
    assert p.files == {"good.txt": "ok"}


def test_rpc_meta_types_are_normalised(fake_net):
    fake_net["rpc/v5/info"] = rpc(
        info(
            "weird",
            NumVotes="12",
            Popularity="nan",
            FirstSubmitted="abc",
            LastModified=1e30,
            OutOfDate=None,
            Maintainer=["x"],
            Depends="notalist",
        ),
        info(
            "ok",
            NumVotes=None,
            Popularity=1.5,
            LastModified=1700000000,
            Maintainer="me",
        ),
        info("inf", NumVotes=float("inf"), OutOfDate="1700000000"),
    )
    got = fetchers.aur_info(["weird", "ok", "inf"])
    w = got["weird"]
    assert w["NumVotes"] == 12 and w["Popularity"] == 0.0
    assert w["FirstSubmitted"] is None and w["LastModified"] is None
    assert w["OutOfDate"] is None and w["Maintainer"] is None and w["Depends"] == []
    o = got["ok"]
    assert o["NumVotes"] == 0 and o["Popularity"] == 1.5
    assert o["LastModified"] == 1700000000 and o["Maintainer"] == "me"
    assert got["inf"]["NumVotes"] == 0 and got["inf"]["OutOfDate"] == 1700000000
