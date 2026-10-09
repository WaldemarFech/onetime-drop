"""Action recipe registry (allowlist).

An action link can only run a recipe that is shipped in this package and listed in REGISTRY.
The link creator chooses a recipe id plus the recipe's declared NON-secret params; every param
is validated by the recipe (strict allowlist patterns) when the link is created AND again right
before it runs. Secrets (e.g. a root password) are never link params: they are typed by the
person who runs the link and only live in memory for the duration of the run.

Adding a recipe: write a module next to this file that defines a `Recipe` instance, review it
like any other privileged code, and add it to REGISTRY below.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Param:
    name: str
    label: str
    validate: Callable[[str, object], str]  # (raw value, config) -> normalized value or ValueError


@dataclass(frozen=True)
class Secret:
    name: str
    label: str
    max_len: int = 256


@dataclass(frozen=True)
class Option:
    name: str
    label: str
    default: bool = False


@dataclass(frozen=True)
class Step:
    key: str            # "a", "b", ...
    title: str
    script: str         # remote shell snippet, params already filled in (shell-quoted)
    option: str = ""    # only runs when this option is enabled


@dataclass(frozen=True)
class Plan:
    user: str
    host: str
    script: str                                   # full remote script, fed via ssh stdin
    generated: dict = field(default_factory=dict)  # values generated for this run (secret)


@dataclass(frozen=True)
class Recipe:
    id: str
    title: str
    description: str
    params: tuple[Param, ...]
    secrets: tuple[Secret, ...]
    options: tuple[Option, ...]
    # (params, generated-or-placeholders) -> ordered steps
    steps: Callable[[dict, dict], list[Step]]
    # options -> values generated per run (e.g. a new random password); secret, never stored
    generate: Callable[[dict], dict]
    # placeholders for generated values on the review page
    placeholders: dict
    target: Callable[[dict], tuple[str, str]]       # params -> (ssh user, host)
    # (params, options, output lines, exit code, timed_out) -> outcome dict
    evaluate: Callable[..., dict]
    timeout: int = 60
    # params -> extra (label, value) rows for the review page, e.g. an expected fingerprint
    facts: Callable[[dict], list] = lambda params: []

    def build_plan(self, params: dict, options: dict, generated: dict) -> Plan:
        steps = [s for s in self.steps(params, generated) if not s.option or options.get(s.option)]
        user, host = self.target(params)
        script = "set -eu\n" + "\n".join(s.script for s in steps) + "\n"
        return Plan(user=user, host=host, script=script, generated=generated)


def validate_params(recipe: Recipe, raw: dict, cfg) -> dict:
    """Strictly validate link params: no unknown, no missing, each through its validator."""
    names = {p.name for p in recipe.params}
    unknown = set(raw) - names
    if unknown:
        raise ValueError(f"unknown param(s): {', '.join(sorted(unknown))}")
    out = {}
    for p in recipe.params:
        if p.name not in raw:
            raise ValueError(f"missing param: {p.name}")
        value = raw[p.name]
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError(f"invalid param: {p.name}")
        out[p.name] = p.validate(value, cfg)
    return out


def parse_param_args(items: list[str]) -> dict:
    out = {}
    for it in items or []:
        k, sep, v = it.partition("=")
        if not sep or not k:
            raise ValueError(f"param must look like key=value: {it!r}")
        if k in out:
            raise ValueError(f"duplicate param: {k}")
        out[k] = v
    return out


def get(recipe_id: str) -> Recipe:
    try:
        return REGISTRY[recipe_id]
    except KeyError:
        raise ValueError(f"unknown recipe: {recipe_id!r}") from None


from . import cerbo_install_key  # noqa: E402

REGISTRY: dict[str, Recipe] = {r.id: r for r in (cerbo_install_key.RECIPE,)}
