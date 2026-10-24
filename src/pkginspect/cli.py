#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import traceback
from importlib import metadata
from typing import Any, List, Optional, Sequence, Tuple

import requests
import yaml

from pkginspect.fetchers import (
    FetchError,
    Package,
    fetch_aur_packages,
    fetch_official_package,
    fetch_url_package,
    load_file_package,
)
from pkginspect.output import (
    error_data,
    format_error,
    format_summary,
    format_text,
    json_data,
)
from pkginspect.rules import load_rules
from pkginspect.scoring import ScoringResult, score_pkgbuild, shell_lines


def _version() -> str:
    try:
        return metadata.version("pkginspect")
    except metadata.PackageNotFoundError:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pkginspect",
        description="PKGBUILD security analyzer. "
        "Bare names are AUR packages: pkginspect yay paru",
    )
    ap.add_argument("packages", nargs="*", metavar="PKG", help="AUR package(s)")
    ap.add_argument("--aur", action="append", default=[], metavar="PKG")
    ap.add_argument("--official", action="append", default=[], metavar="PKG")
    ap.add_argument("--file", action="append", default=[], metavar="PATH")
    ap.add_argument("--url", action="append", default=[], metavar="URL")
    ap.add_argument(
        "--deps", action="store_true", help="also check AUR dependencies of AUR targets"
    )
    ap.add_argument("--json", action="store_true", help="output as JSON")
    ap.add_argument(
        "--fail-under",
        type=int,
        metavar="N",
        help="exit 1 if any package scores below N",
    )
    ap.add_argument("--rules", help="path to a rules.yaml")
    ap.add_argument("-d", "--debug", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    return ap


def _fetch_all(args: argparse.Namespace) -> List[Package]:
    packages: List[Package] = []
    aur_names = list(args.packages) + list(args.aur)
    if aur_names:
        packages += fetch_aur_packages(aur_names, deps=args.deps)
    packages += [fetch_official_package(n) for n in args.official]
    packages += [load_file_package(p) for p in args.file]
    packages += [fetch_url_package(u) for u in args.url]
    return packages


def _analyze(pkg: Package, config: Any, lines: List[str]) -> ScoringResult:
    return score_pkgbuild(
        lines,
        config=config,
        local_path=pkg.local_path,
        aur_meta=pkg.meta if pkg.source == "aur" else None,
        extra_files=pkg.files,
    )


def run(args: argparse.Namespace) -> int:
    """Analyze every target and print the report; return the exit code."""
    config = load_rules(args.rules)
    packages = _fetch_all(args)

    failed = False
    low = False
    entries: List[Tuple[Package, Optional[ScoringResult]]] = []
    texts: List[str] = []
    objects: List[Any] = []

    for pkg in packages:
        result: Optional[ScoringResult] = None
        text = obj = None
        if not pkg.error:
            try:
                lines = shell_lines(pkg.pkgbuild)
                result = _analyze(pkg, config, lines)
                text = format_text(
                    result,
                    lines=lines,
                    debug=args.debug,
                    rules_path=getattr(config, "path", None),
                    package=pkg,
                )
                obj = json_data(result, pkg=pkg)
            except Exception as e:  # one bad package must not sink the others
                if args.debug:
                    traceback.print_exc()
                pkg.error = f"internal error while analyzing (please report): {e!r}"
                result = None
        if result is None:
            failed = True
            entries.append((pkg, None))
            texts.append(format_error(pkg))
            objects.append(error_data(pkg))
            continue
        entries.append((pkg, result))
        if args.fail_under is not None and result.score < args.fail_under:
            low = True
        texts.append(str(text))
        objects.append(obj)

    if args.json:
        # One target keeps the original single-object shape; anything that can
        # yield several packages (more targets, --deps) is always an array.
        targets = args.packages + args.aur + args.official + args.file + args.url
        single = len(targets) == 1 and not args.deps and len(objects) == 1
        print(json.dumps(objects[0] if single else objects, indent=2))
    else:
        print("\n\n".join(texts))
        if len(entries) > 1:
            print("\n" + format_summary(entries))

    return 1 if failed or low else 0


def main(argv: Optional[Sequence[str]] = None) -> None:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not (args.packages or args.aur or args.official or args.file or args.url):
        ap.error("give at least one package (e.g. `pkginspect yay`) or --file/--url")
    try:
        code = run(args)
    except KeyboardInterrupt:
        sys.exit(130)
    except (FetchError, requests.RequestException, OSError, yaml.YAMLError) as e:
        if args.debug:
            traceback.print_exc()
        print(f"pkginspect: error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # last resort: never show a raw traceback
        if args.debug:
            traceback.print_exc()
        print(f"pkginspect: internal error: {e!r}", file=sys.stderr)
        sys.exit(1)
    sys.exit(code)


if __name__ == "__main__":
    main()
