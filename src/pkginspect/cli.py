#!/usr/bin/env python3

from __future__ import annotations

import argparse
import pathlib
import sys

from pkginspect.fetchers import aur_metadata, fetch_aur, fetch_official, fetch_url
from pkginspect.output import format_json, format_text
from pkginspect.rules import load_rules
from pkginspect.scoring import score_pkgbuild


def main() -> None:
    ap = argparse.ArgumentParser(description="PKGBUILD analyzer")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file")
    g.add_argument("--aur")
    g.add_argument("--official")
    g.add_argument("--url")
    ap.add_argument("--rules")
    ap.add_argument("--json", action="store_true", help="output as JSON")
    ap.add_argument("-d", "--debug", action="store_true")
    args = ap.parse_args()

    config = load_rules(args.rules)

    if args.file:
        p = pathlib.Path(args.file)
        lines = p.read_text().splitlines()
        loc = p
    elif args.aur:
        lines, loc = fetch_aur(args.aur), None
    elif args.official:
        try:
            lines, loc = fetch_official(args.official), None
        except RuntimeError as e:
            if "not found in official mirrors" in str(e):
                print(
                    f"'{args.official}' is not in the official repos; "
                    f"try `--aur {args.official}`.",
                    file=sys.stderr,
                )
                sys.exit(1)
            raise
    else:
        lines, loc = fetch_url(args.url), None

    aur_meta = {}
    if args.aur:
        aur_meta = aur_metadata(args.aur)
        if args.debug:
            print("DEBUG: AUR meta:", aur_meta or "none")

    result = score_pkgbuild(lines, config=config, local_path=loc, aur_meta=aur_meta)

    if args.json:
        source = (
            "aur"
            if args.aur
            else "official"
            if args.official
            else "file"
            if args.file
            else "url"
        )
        pkg = args.aur or args.official or args.file or args.url
        print(format_json(result, source=source, package=pkg))
    else:
        print(format_text(result, lines=lines, debug=args.debug))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nError: {e}\n", file=sys.stderr)
        sys.exit(1)
