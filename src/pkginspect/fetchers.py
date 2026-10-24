from __future__ import annotations

import dataclasses
import difflib
import gzip
import io
import math
import pathlib
import re
import shlex
import tarfile
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode, urlsplit

import requests


class FetchError(RuntimeError):
    """A user-facing failure; the message is friendly enough to print as-is."""


@dataclasses.dataclass
class Package:
    """Everything needed to score one package, however it was obtained."""

    name: str  # what was asked for: pkgname, file path or URL
    source: str  # "aur" | "official" | "file" | "url"
    pkgbuild: str = ""  # PKGBUILD text ("" when error is set)
    # Other text files from the package repo, e.g. {"foo.install": "..."}
    files: Dict[str, str] = dataclasses.field(default_factory=dict)
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)  # AUR RPC info
    pkgbase: str = ""
    required_by: Optional[str] = None  # set when pulled in by --deps
    error: Optional[str] = None  # friendly message if it could not be fetched
    local_path: Optional[pathlib.Path] = None  # for --file (enables namcap)


HTTPS_OK = {
    "github.com",
    "gitlab.com",
    "kernel.org",
    "sourcehut.org",
    "codeberg.org",
    "archlinux.org",
}

AUR = "https://aur.archlinux.org"
ARCH_SEARCH = "https://archlinux.org/packages/search/json/"
GITLAB_RAW = "https://gitlab.archlinux.org/archlinux/packaging/packages"

TIMEOUT = (5, 15)  # connect, read (seconds)
RPC_CHUNK = 100  # names per RPC request
# The AUR's cgit rate-limits per IP (~1 request/s) and queues the excess, so more
# parallel snapshot downloads only add waiting time toward the read timeout.
MAX_WORKERS = 4
RETRY_STATUS = (429, 503)
RETRY_DELAY = 2.0  # seconds, unless Retry-After says otherwise
MAX_RETRY_AFTER = 10.0
MIN_SIMILARITY = 0.6  # "did you mean" candidates below this are noise
MAX_DEP_PACKAGES = 50

# Limits when reading AUR snapshots (untrusted input, parsed in memory)
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024
MAX_MEMBERS = 300
MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024  # all tar data, after gunzip
MAX_TOTAL_READ_BYTES = 5 * 1024 * 1024  # member contents we actually read
MAX_TEXT_BYTES = 2 * 1024 * 1024  # raw PKGBUILD / install file from a URL
MAX_TIMESTAMP = 32503680000  # year 3000; anything later is garbage


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("pkginspect")
    except Exception:
        return "dev"


SESSION = requests.Session()
SESSION.headers["User-Agent"] = f"pkginspect/{_version()}"


def _lines(text: str) -> List[str]:
    """Split like bash, on \\n only (see scoring.shell_lines)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def domain(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


# ── HTTP helpers ──────────────────────────────────────────────────


def _retry_delay(resp: Any) -> float:
    try:
        wait = float(resp.headers.get("Retry-After", ""))
    except (AttributeError, TypeError, ValueError):
        return RETRY_DELAY
    return wait if 0 <= wait <= MAX_RETRY_AFTER else RETRY_DELAY


def _get(url: str, *, stream: bool = False) -> Any:
    """GET through the shared session, retrying once on 429/503 or a dropped
    connection. Network errors become FetchError."""
    for attempt in (1, 2):
        try:
            r = SESSION.get(url, timeout=TIMEOUT, stream=stream)
        except (
            requests.exceptions.MissingSchema,
            requests.exceptions.InvalidSchema,
            requests.exceptions.InvalidURL,
        ) as e:
            raise FetchError(
                f"'{url[:200]}' is not a valid URL (it must start with http:// or https://)"
            ) from e
        except requests.RequestException as e:
            if attempt == 1:
                time.sleep(RETRY_DELAY)
                continue
            host = domain(url)
            who = "the AUR" if host == "aur.archlinux.org" else host
            raise FetchError(f"Could not reach {who}: {e}") from e
        if r.status_code in RETRY_STATUS and attempt == 1:
            delay = _retry_delay(r)
            r.close()
            time.sleep(delay)
            continue
        return r
    raise AssertionError("unreachable")  # pragma: no cover


def _json(url: str) -> Any:
    r = _get(url)
    if r.status_code != 200:
        raise FetchError(f"{domain(url)} returned HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise FetchError(f"{domain(url)} returned invalid JSON") from e


def _read_capped(r: Any, limit: int, what: str) -> bytes:
    """Read a streamed response body, aborting above `limit` bytes."""
    buf = io.BytesIO()
    try:
        for chunk in r.iter_content(65536):
            buf.write(chunk)
            if buf.tell() > limit:
                raise FetchError(f"{what} is over {limit / 2**20:g} MiB; skipped")
    except requests.RequestException as e:
        raise FetchError(f"Could not download {what}: {e}") from e
    finally:
        r.close()
    return buf.getvalue()


def _text(url: str) -> Optional[str]:
    """Text of a URL (size-capped), or None if it is a 404."""
    r = _get(url, stream=True)
    if r.status_code != 200:
        r.close()
        if r.status_code == 404:
            return None
        raise FetchError(f"{domain(url)} returned HTTP {r.status_code}")
    return _read_capped(r, MAX_TEXT_BYTES, domain(url) + " response").decode(
        "utf-8", errors="replace"
    )


def _is_text(data: bytes) -> bool:
    return b"\0" not in data


# ── AUR ───────────────────────────────────────────────────────────


def _to_int(value: Any) -> Optional[int]:
    """int from an int/float/numeric string; None if odd, non-finite or negative."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return int(number)


def _clean_info(info: Any) -> Optional[dict]:
    """Coerce RPC fields to predictable types so later code never has to guess."""
    if not isinstance(info, dict) or not isinstance(info.get("Name"), str):
        return None
    info = dict(info)
    info["PackageBase"] = str(info.get("PackageBase") or info["Name"])
    info["NumVotes"] = _to_int(info.get("NumVotes")) or 0
    try:
        popularity = float(info.get("Popularity"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        popularity = 0.0
    info["Popularity"] = popularity if math.isfinite(popularity) else 0.0
    for key in ("FirstSubmitted", "LastModified", "OutOfDate"):
        ts = _to_int(info.get(key))
        info[key] = ts if ts is not None and 0 < ts <= MAX_TIMESTAMP else None
    maintainer = info.get("Maintainer")
    info["Maintainer"] = (
        maintainer if isinstance(maintainer, str) and maintainer else None
    )
    for key in ("Depends", "MakeDepends", "CheckDepends"):
        deps = info.get(key)
        info[key] = (
            [d for d in deps if isinstance(d, str)] if isinstance(deps, list) else []
        )
    return info


def aur_info(names: List[str]) -> Dict[str, dict]:
    """Batched RPC info lookup, keyed by package Name. Unknown names are absent."""
    found: Dict[str, dict] = {}
    for i in range(0, len(names), RPC_CHUNK):
        query = urlencode([("arg[]", n) for n in names[i : i + RPC_CHUNK]])
        data = _json(f"{AUR}/rpc/v5/info?{query}")
        if data.get("type") == "error":
            raise FetchError(f"AUR RPC error: {data.get('error')}")
        results = data.get("results", [])
        for info in results if isinstance(results, list) else []:
            info = _clean_info(info)
            if info:
                found[info["Name"]] = info
    return found


def aur_metadata(pkg: str) -> dict:
    try:
        return aur_info([pkg]).get(pkg, {})
    except Exception:
        return {}


class _CappedReader:
    """File-like wrapper that refuses to hand out more than the decompressed cap
    (protects against gzip bombs)."""

    def __init__(self, fileobj: Any, pkgbase: str):
        self.fileobj = fileobj
        self.pkgbase = pkgbase
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        data = self.fileobj.read(size)
        self.total += len(data)
        if self.total > MAX_DECOMPRESSED_BYTES:
            raise FetchError(f"'{self.pkgbase}': snapshot too large")
        return data


def fetch_aur_snapshot(pkgbase: str) -> Dict[str, str]:
    """Download the AUR repo snapshot and return its text files, in memory only."""
    url = f"{AUR}/cgit/aur.git/snapshot/{quote(pkgbase)}.tar.gz"
    r = _get(url, stream=True)
    try:
        if r.status_code == 404:
            raise FetchError(f"No AUR package repo named '{pkgbase}'")
        if r.status_code != 200:
            raise FetchError(f"The AUR returned HTTP {r.status_code} for '{pkgbase}'")
        raw = _read_capped(r, MAX_SNAPSHOT_BYTES, f"Snapshot of '{pkgbase}'")
    finally:
        r.close()

    files: Dict[str, str] = {}
    total = 0
    try:
        stream: Any = _CappedReader(gzip.GzipFile(fileobj=io.BytesIO(raw)), pkgbase)
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for count, member in enumerate(tar):
                if count >= MAX_MEMBERS:
                    break
                if not member.isreg() or member.size > MAX_MEMBER_BYTES:
                    continue
                # non-UTF-8 names arrive surrogate-escaped; make them printable
                name = member.name.encode("utf-8", "surrogateescape").decode(
                    "utf-8", "replace"
                )
                if name.startswith("/"):
                    continue
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if ".." in parts:
                    continue
                if parts and parts[0] == pkgbase:
                    parts = parts[1:]
                f = tar.extractfile(member)
                if not parts or f is None:
                    continue
                total += member.size
                if total > MAX_TOTAL_READ_BYTES:
                    raise FetchError(f"'{pkgbase}': snapshot too large")
                data = f.read()
                if _is_text(data):
                    files["/".join(parts)] = data.decode("utf-8", errors="replace")
    except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
        raise FetchError(f"Could not read the snapshot of '{pkgbase}': {e}") from e
    if "PKGBUILD" not in files:
        raise FetchError(f"The AUR repo for '{pkgbase}' has no PKGBUILD")
    return files


def _suggest_help(name: str) -> str:
    """Friendly 'not found' message for a name the AUR does not have."""
    try:
        official = _json(f"{ARCH_SEARCH}?{urlencode({'name': name})}")
        if official.get("results"):
            return f"'{name}' is in the official repos; use --official {name}"
    except FetchError:
        pass
    msg = f"'{name}' was not found in the AUR"
    try:
        data = _json(f"{AUR}/rpc/v5/search/{quote(name)}?by=name")
        # The search is a substring match, so re-rank by similarity to the query
        # and drop weak matches; votes break ties.
        scored = [
            (difflib.SequenceMatcher(None, name, i["Name"]).ratio(), i)
            for i in data.get("results", [])
            if isinstance(i, dict) and isinstance(i.get("Name"), str)
        ]
        scored = [(r, i) for r, i in scored if r >= MIN_SIMILARITY]
        scored.sort(
            key=lambda t: (t[0], _to_int(t[1].get("NumVotes")) or 0), reverse=True
        )
        if scored:
            names = ", ".join(i["Name"] for _, i in scored[:3])
            msg += f" (did you mean: {names}?)"
    except FetchError:
        pass
    return msg


def _dep_names(info: dict) -> List[str]:
    """Depends + MakeDepends + CheckDepends, version constraints stripped."""
    deps = []
    for key in ("Depends", "MakeDepends", "CheckDepends"):
        for dep in info.get(key, []):
            deps.append(re.split(r"[<>=]", dep, maxsplit=1)[0].strip())
    return [d for d in deps if d]


def _collect_deps(infos: List[Tuple[dict, Optional[str]]], visited: set) -> None:
    """Grow `infos` with AUR dependencies (breadth first, capped)."""
    frontier = [info for info, _ in infos]
    while frontier and len(infos) < MAX_DEP_PACKAGES:
        wanted: Dict[str, str] = {}  # dep name -> first parent that needs it
        for info in frontier:
            for dep in _dep_names(info):
                if dep not in visited:
                    wanted.setdefault(dep, info["Name"])
        visited.update(wanted)
        found = aur_info(list(wanted)) if wanted else {}
        frontier = []
        for dep in wanted:  # keep discovery order
            if dep in found and len(infos) < MAX_DEP_PACKAGES:
                infos.append((found[dep], wanted[dep]))
                frontier.append(found[dep])


def fetch_aur_packages(names: List[str], *, deps: bool = False) -> List[Package]:
    names = list(dict.fromkeys(names))
    info = aur_info(names)

    # (name, info or None, required_by) in output order
    entries: List[Tuple[str, Optional[dict], Optional[str]]] = [
        (n, info.get(n), None) for n in names
    ]
    if deps:
        extra: List[Tuple[dict, Optional[str]]] = [(i, None) for i in info.values()]
        _collect_deps(extra, set(names))
        entries += [(i["Name"], i, parent) for i, parent in extra[len(info) :]]

    bases = list(dict.fromkeys(i["PackageBase"] for _, i, _ in entries if i))
    snapshots: Dict[str, Any] = {}

    def grab(base: str) -> None:
        try:
            snapshots[base] = fetch_aur_snapshot(base)
        except FetchError as e:
            snapshots[base] = e

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(grab, bases))

    packages = []
    for name, i, parent in entries:
        if i is None:
            packages.append(Package(name, "aur", error=_suggest_help(name)))
            continue
        snap = snapshots[i["PackageBase"]]
        if isinstance(snap, FetchError):
            packages.append(
                Package(name, "aur", pkgbase=i["PackageBase"], error=str(snap))
            )
            continue
        files = {k: v for k, v in snap.items() if k != "PKGBUILD"}
        packages.append(
            Package(
                name,
                "aur",
                pkgbuild=snap["PKGBUILD"],
                files=files,
                meta=i,
                pkgbase=i["PackageBase"],
                required_by=parent,
            )
        )
    return packages


def fetch_aur(pkg: str) -> List[str]:
    p = fetch_aur_packages([pkg])[0]
    if p.error:
        raise FetchError(p.error)
    return _lines(p.pkgbuild)


# ── official repos ────────────────────────────────────────────────


def gitlab_path(pkgbase: str) -> str:
    """Project path of a package on Arch's GitLab (same rule as devtools)."""
    n = re.sub(r"([a-zA-Z0-9]+)\+([a-zA-Z]+)", r"\1-\2", pkgbase)
    n = n.replace("+", "plus")
    n = re.sub(r"[^a-zA-Z0-9_\-.]", "-", n)
    n = re.sub(r"[_\-]{2,}", "-", n)
    return "unix-tree" if n == "tree" else n


def _official_pkgbase(name: str) -> Optional[str]:
    data = _json(f"{ARCH_SEARCH}?{urlencode({'name': name})}")
    results = data.get("results") or []
    return results[0]["pkgbase"] if results else None


def _install_file(pkgbuild: str, pkgname: str, pkgbase: str) -> Optional[str]:
    """Name of the .install file declared by `install=`, if it is a plain name."""
    m = re.search(r"^[ \t]*install=['\"]?([^'\"\s#]+)", pkgbuild, re.MULTILINE)
    if not m:
        return None
    value = m.group(1)
    for var, repl in (("pkgname", pkgname), ("pkgbase", pkgbase)):
        if repl:
            value = value.replace("${%s}" % var, repl).replace("$" + var, repl)
    if "$" in value or value.startswith("/") or ".." in value.split("/"):
        return None
    return value


def fetch_official_package(name: str) -> Package:
    base = _official_pkgbase(name)
    if base is None:
        return Package(
            name,
            "official",
            error=f"'{name}' is not in the official repos; try the AUR: pkginspect {name}",
        )
    root = f"{GITLAB_RAW}/{gitlab_path(base)}/-/raw/main"
    pkgbuild = _text(f"{root}/PKGBUILD")
    if pkgbuild is None:
        return Package(
            name,
            "official",
            pkgbase=base,
            error=f"Could not find the PKGBUILD for '{base}' on gitlab.archlinux.org",
        )
    files: Dict[str, str] = {}
    install = _install_file(pkgbuild, name, base)
    if install:
        text = _text(f"{root}/{quote(install)}")
        if text is not None:
            files[install] = text
    return Package(name, "official", pkgbuild=pkgbuild, files=files, pkgbase=base)


def fetch_official(pkg: str) -> List[str]:
    if _official_pkgbase(pkg) is None:
        raise RuntimeError(f"'{pkg}' not found in official mirrors")
    p = fetch_official_package(pkg)
    if p.error:
        raise RuntimeError(p.error)
    return _lines(p.pkgbuild)


# ── local files and URLs ──────────────────────────────────────────


def _read_text(path: pathlib.Path) -> Optional[str]:
    """Small text file contents, or None if missing, huge or binary."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_MEMBER_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return data.decode("utf-8", errors="replace") if _is_text(data) else None


def _inside(base: pathlib.Path, name: str) -> pathlib.Path:
    """base/name, unless it is a symlink or resolves outside base (then a path
    that does not exist, so nothing is read)."""
    candidate = base / name
    try:
        if not candidate.is_symlink():
            candidate.resolve().relative_to(base.resolve())
            return candidate
    except (ValueError, OSError):
        pass
    return base / "\0missing"


def _local_sources(pkgbuild: str) -> List[str]:
    """Entries of source=() / source_<arch>=() that are plain local file names."""
    names = []
    for m in re.finditer(r"^[ \t]*source(?:_\w+)?=\(([^)]{0,20000})\)", pkgbuild, re.M):
        try:
            entries = shlex.split(m.group(1), comments=True)
        except ValueError:
            continue
        for entry in entries:
            entry = entry.split("::", 1)[-1]
            if "://" not in entry and "$" not in entry:
                names.append(entry)
    return names


def load_file_package(path: str) -> Package:
    p = pathlib.Path(path).expanduser()
    if p.is_dir():
        p = p / "PKGBUILD"
    text = _read_text(p)
    if text is None:
        return Package(path, "file", error=f"Could not read a PKGBUILD at {p}")
    wanted = _local_sources(text)
    # install=$pkgname.install cannot be resolved here, so only plain names count
    m = re.search(r"^[ \t]*install=['\"]?([\w.+-]+)", text, re.MULTILINE)
    if m:
        wanted.append(m.group(1))
    files: Dict[str, str] = {}
    for name in wanted:
        if name.startswith("/") or ".." in name.split("/"):
            continue
        content = _read_text(_inside(p.parent, name))
        if content is not None:
            files[name] = content
    return Package(path, "file", pkgbuild=text, files=files, local_path=p)


def fetch_url_package(url: str) -> Package:
    try:
        text = _text(url)
    except FetchError as e:
        return Package(url, "url", error=str(e))
    if text is None:
        return Package(url, "url", error="URL not found (HTTP 404)")
    if re.match(r"\s*<(!doctype html|html)", text, re.IGNORECASE):
        return Package(
            url,
            "url",
            error="URL returned an HTML page, not a raw PKGBUILD (use the raw-file link)",
        )
    return Package(url, "url", pkgbuild=text)


def fetch_url(url: str) -> List[str]:
    p = fetch_url_package(url)
    if p.error:
        raise RuntimeError(p.error)
    return _lines(p.pkgbuild)
