from __future__ import annotations

import dataclasses
import os
import pathlib
import pkgutil
from typing import Any, Dict, Optional

import yaml


@dataclasses.dataclass
class RulesConfig:
    weights: dict[str, int]
    caps: dict[str, int]
    blockers: dict[str, bool]
    path: Optional[str] = None  # file the rules came from ("bundled" for the default)


def _bundled() -> Dict[str, Any]:
    # pkgutil works on every supported Python (importlib.resources.files is 3.9+)
    data = pkgutil.get_data("pkginspect", "rules.yaml")
    if data is None:
        raise OSError("bundled rules.yaml is missing from the pkginspect package")
    return yaml.safe_load(data.decode("utf-8"))


def load_rules(path_cli: str | None = None) -> RulesConfig:
    search: list[pathlib.Path] = []
    if path_cli:
        search.append(pathlib.Path(path_cli).expanduser())
    if env := os.getenv("PKGINSPECT_RULES"):
        search.append(pathlib.Path(env).expanduser())
    search += [
        pathlib.Path.cwd() / "rules.yaml",
        pathlib.Path(os.getenv("XDG_CONFIG_HOME", pathlib.Path.home() / ".config"))
        / "pkginspect"
        / "rules.yaml",
    ]
    raw = _bundled()
    used = "bundled"
    for p in search:
        if p.is_file():
            # Merge over the bundled defaults so older user files keep working
            # when new rules are added.
            user = yaml.safe_load(p.read_text()) or {}
            for section in ("weights", "caps", "blockers"):
                raw[section] = {**raw[section], **(user.get(section) or {})}
            used = str(p)
            break
    return RulesConfig(raw["weights"], raw["caps"], raw["blockers"], used)
