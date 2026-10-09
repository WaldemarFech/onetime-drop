"""DIL command line (also reachable as `onetime-drop dil-*`).

  dil-create --label TEXT --passphrase-stdin --file PATH [--file PATH ...] [--ttl 2h]
             [--max-downloads 8]                     -> prints https://<host>/d/<token>
  dil-list | dil-revoke <id> | dil-gc | dil-serve
Global: --dil-config PATH (or $ONETIME_DIL_CONFIG, default /etc/onetime-dil/dil.toml)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import config as config_mod
from .store import DilStore


def add_subcommands(sub) -> None:
    c = sub.add_parser("dil-create")
    c.add_argument("--label", required=True)
    c.add_argument("--passphrase-stdin", action="store_true",
                   help="read the passphrase from stdin (never pass it as an argument)")
    c.add_argument("--file", action="append", required=True, dest="files")
    c.add_argument("--ttl", default="2h")
    c.add_argument("--max-downloads", type=int, default=8)
    sub.add_parser("dil-list")
    r = sub.add_parser("dil-revoke")
    r.add_argument("id")
    sub.add_parser("dil-gc")
    sub.add_parser("dil-serve")


def run(a) -> int:
    os.umask(0o077)
    try:
        cfg = config_mod.load(getattr(a, "dil_config", None))
        if a.cmd == "dil-serve":
            from .server import serve
            serve(cfg)
            return 0
        store = DilStore(cfg.state_dir)
        if a.cmd == "dil-create":
            if not a.passphrase_stdin:
                raise ValueError("--passphrase-stdin is required")
            if sys.stdin.isatty():
                pw = getpass.getpass("passphrase: ")
            else:
                pw = sys.stdin.readline().rstrip("\r\n")
            ttl = config_mod.parse_ttl(a.ttl, cfg.max_ttl)
            token, link_id = store.create(a.label, pw, [Path(f) for f in a.files], ttl,
                                          a.max_downloads)
            print(f"{cfg.base_url}/d/{token}")
            print(f"id {link_id}", file=sys.stderr)
        elif a.cmd == "dil-list":
            print(json.dumps(store.list()))
        elif a.cmd == "dil-revoke":
            print("revoked" if store.revoke(a.id) else "not found")
        elif a.cmd == "dil-gc":
            print(f"burned {store.gc()}")
    except (ValueError, OSError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="onetime-dil")
    ap.add_argument("--dil-config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    add_subcommands(sub)
    return run(ap.parse_args(argv))
