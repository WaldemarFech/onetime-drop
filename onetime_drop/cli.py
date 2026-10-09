"""Command line interface.

  onetime-drop serve
  onetime-drop create-reveal --label "DB password" [--ttl 24h] < secretfile   -> URL
  onetime-drop create-input  --label "API key" --fields name,value [--target x] -> URL
  onetime-drop create-action --recipe ID --param k=v ... --label "..." [--ttl 2h] -> URL
  onetime-drop recipes                    available action recipes and their params
  onetime-drop list                       pending links (no secrets)
  onetime-drop revoke <item-id>
  onetime-drop outbox list | get <id> | rm <id>
  onetime-drop gc
  onetime-drop dil-create|dil-list|dil-revoke|dil-gc|dil-serve   public download links (dil/)
Global: --config PATH (or $ONETIME_DROP_CONFIG, default /etc/onetime-drop/config.toml)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import config as config_mod
from . import recipes
from .store import MAX_SECRET_BYTES, parse_fields, parse_target, parse_ttl


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="onetime-drop")
    ap.add_argument("--config")
    ap.add_argument("--dil-config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    from .dil.cli import add_subcommands as dil_subcommands
    dil_subcommands(sub)
    sub.add_parser("serve")
    r = sub.add_parser("create-reveal")
    r.add_argument("--label", required=True)
    r.add_argument("--ttl")
    i = sub.add_parser("create-input")
    i.add_argument("--label", required=True)
    i.add_argument("--fields", default="value")
    i.add_argument("--target", default="")
    i.add_argument("--ttl")
    ac = sub.add_parser("create-action")
    ac.add_argument("--recipe", required=True)
    ac.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    ac.add_argument("--label", required=True)
    ac.add_argument("--ttl")
    sub.add_parser("recipes")
    sub.add_parser("list")
    rv = sub.add_parser("revoke")
    rv.add_argument("id")
    o = sub.add_parser("outbox")
    o.add_argument("action", choices=["list", "get", "rm"])
    o.add_argument("id", nargs="?")
    sub.add_parser("gc")
    return ap


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    ap = build_parser()
    a = ap.parse_args(argv)
    if a.cmd.startswith("dil-"):
        from .dil.cli import run as dil_run
        return dil_run(a)
    try:
        cfg = config_mod.load(a.config)
        if a.cmd == "serve":
            from .server import serve
            serve(cfg)
            return 0
        store = cfg.store
        ttl = lambda: parse_ttl(a.ttl, cfg.max_ttl) if a.ttl else cfg.default_ttl  # noqa: E731
        if a.cmd == "create-reveal":
            if sys.stdin.isatty():
                ap.error("pipe the secret via stdin (never as an argument)")
            data = sys.stdin.buffer.read(MAX_SECRET_BYTES + 1)
            data = data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") \
                else data
            print(f"{cfg.base_url}/r/{store.create_reveal(a.label, data, ttl(), 'cli')}")
        elif a.cmd == "create-input":
            tok = store.create_input(a.label, parse_fields(a.fields), ttl(),
                                     parse_target(a.target), "cli")
            print(f"{cfg.base_url}/i/{tok}")
        elif a.cmd == "create-action":
            recipe = recipes.get(a.recipe)
            params = recipes.validate_params(recipe, recipes.parse_param_args(a.param), cfg)
            tok = store.create_action(a.label, recipe.id, params, ttl(), "cli")
            print(f"{cfg.base_url}/a/{tok}")
        elif a.cmd == "recipes":
            print(json.dumps([{"id": r.id, "title": r.title,
                               "params": [p.name for p in r.params],
                               "secrets": [s.name for s in r.secrets],
                               "options": [o.name for o in r.options]}
                              for r in recipes.REGISTRY.values()]))
        elif a.cmd == "list":
            print(json.dumps([{"id": i.id, "kind": i.kind, "label": i.label,
                               "target": i.target, "recipe": i.recipe or None,
                               "expires": int(i.expires)}
                              for i in store.pending()]))
        elif a.cmd == "revoke":
            print("revoked" if store.revoke(a.id, "cli") else "not found")
        elif a.cmd == "outbox":
            if a.action == "list":
                print(json.dumps(store.outbox_list()))
            elif not a.id:
                ap.error("id required")
            elif a.action == "get":
                print(json.dumps(store.outbox_get(a.id)))
            else:
                store.outbox_rm(a.id)
        elif a.cmd == "gc":
            print(f"expired {store.gc()}")
    except (ValueError, FileNotFoundError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0
