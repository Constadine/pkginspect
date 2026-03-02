from __future__ import annotations

import dataclasses
import os
import pathlib

import importlib.resources as res
import yaml


@dataclasses.dataclass
class RulesConfig:
    weights: dict[str, int]
    caps: dict[str, int]
    blockers: dict[str, bool]


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
    for p in search:
        if p.is_file():
            raw = yaml.safe_load(p.read_text())
            return RulesConfig(raw["weights"], raw["caps"], raw["blockers"])
    with res.files("pkginspect").joinpath("rules.yaml").open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return RulesConfig(raw["weights"], raw["caps"], raw["blockers"])
