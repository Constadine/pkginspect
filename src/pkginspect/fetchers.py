from __future__ import annotations

from typing import List

import requests

HTTPS_OK = {
    "github.com",
    "gitlab.com",
    "kernel.org",
    "sourcehut.org",
    "codeberg.org",
    "archlinux.org",
}


def domain(url: str) -> str:
    return url.split("/")[2].lower()


def aur_metadata(pkg: str) -> dict:
    url = "https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=" + pkg
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("resultcount") == 1:
            return data["results"][0]
    except Exception:
        pass
    return {}


def fetch_url(url: str) -> List[str]:
    """Return the remote text split into lines; raise if we get HTML."""
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    txt = r.text.lstrip()
    if txt.startswith("<!DOCTYPE html"):
        raise RuntimeError("HTML page returned instead of raw file")
    return txt.splitlines()


def fetch_aur(pkg: str) -> List[str]:
    return fetch_url(f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg}")


def fetch_official(pkg: str) -> List[str]:
    """
    1. Try Arch GitLab (needs SSO but still public for some repos)
    2. Fall back to GitHub mirrors: core -> extra -> community -> multilib
    3. If still missing, raise RuntimeError so caller can suggest --aur
    """
    gl_url = (
        "https://gitlab.archlinux.org/archlinux/packaging/packages/"
        f"{pkg}/-/raw/main/PKGBUILD?inline=false"
    )
    try:
        return fetch_url(gl_url)
    except Exception:
        pass

    gh_roots = [
        "archlinux/svntogit-core",
        "archlinux/svntogit-extra",
        "archlinux/svntogit-community",
        "archlinux/svntogit-multilib",
    ]
    for root in gh_roots:
        gh_url = (
            f"https://raw.githubusercontent.com/{root}/packages/{pkg}/trunk/PKGBUILD"
        )
        try:
            return fetch_url(gh_url)
        except Exception:
            continue

    raise RuntimeError("not found in official mirrors")
