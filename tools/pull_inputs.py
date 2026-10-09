#!/usr/bin/env python3
"""Pull submitted input forms from the outbox into a local target directory.

Configured by a small TOML file (see deploy/pull.example.toml):

  remote_command = ["ssh", "drop-host", "sudo", "onetime-drop"]  # how to run the CLI
  target_dir     = "~/secrets/inbox"                               # where files land
  format         = "markdown"                                      # or "json"
  restrict_permissions = true                                      # 0600 / icacls owner-only

Each submission is fetched, written to <target_dir>/<target-or-label>_<UTC>.md|json with
owner-only permissions applied BEFORE content is written, verified, and only then removed from
the remote outbox. Prints labels and local paths only - never field values.

  python tools/pull_inputs.py --config pull.toml [--dry-run]
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

OID_RE = re.compile(r"^[0-9a-f]{32}$")


def run_remote(prefix: list[str], *args: str) -> str:
    try:
        res = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"remote '{args[0]}' timed out") from None
    if res.returncode != 0:  # CLI stderr never contains secret values
        raise RuntimeError(f"remote '{args[0]}' failed: {res.stderr.strip()[-300:]}")
    return res.stdout


def restrict(path: Path) -> None:
    if os.name == "nt":
        user = os.environ.get("USERNAME") or getpass.getuser()
        # drop inherited ACEs (Administrators, SYSTEM, ...) and grant only the current user
        try:
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                           check=True, capture_output=True, timeout=30)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise RuntimeError(f"could not restrict permissions on {path}") from None
    else:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def safe_name(name: str) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "input")[:60]


def render_markdown(rec: dict) -> str:
    lines = [f"# {rec.get('label', 'input')}", "",
             f"- submitted: {rec.get('submitted', '?')} (by {rec.get('user', '?')})",
             f"- target: {rec.get('target') or '-'}", "- source: onetime-drop input link", ""]
    for k, v in rec.get("fields", {}).items():
        lines += [f"## {k}", "", "```", v, "```", ""]
    return "\n".join(lines)


def load_config(path: str) -> dict:
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)
    if not isinstance(cfg.get("remote_command"), list) or not cfg["remote_command"]:
        raise ValueError("remote_command must be a non-empty list")
    if cfg.get("format", "markdown") not in ("markdown", "json"):
        raise ValueError("format must be markdown or json")
    cfg["target_dir"] = Path(os.path.expanduser(os.path.expandvars(cfg["target_dir"])))
    return cfg


def pull(cfg: dict, dry_run: bool = False, out=print) -> int:
    prefix, dest = cfg["remote_command"], cfg["target_dir"]
    fmt = cfg.get("format", "markdown")
    restrict_on = cfg.get("restrict_permissions", True)
    entries = json.loads(run_remote(prefix, "outbox", "list") or "[]")
    if not entries:
        out("outbox empty")
        return 0
    if not dry_run:
        dest.mkdir(parents=True, exist_ok=True)
        if restrict_on:
            restrict(dest)
    n = 0
    for e in entries:
        oid, label = e.get("id", ""), e.get("label", "")
        if not OID_RE.match(oid):
            out(f"skip malformed id for {label!r}")
            continue
        stamp = re.sub(r"[^0-9TZ]", "", e.get("submitted", ""))
        base = safe_name(e.get("target") or label)
        ext = ".md" if fmt == "markdown" else ".json"
        path, i = dest / f"{base}_{stamp}{ext}", 1
        while path.exists():
            path, i = dest / f"{base}_{stamp}_{i}{ext}", i + 1
        if dry_run:
            out(f"would store {label!r} -> {path}")
            continue
        rec = json.loads(run_remote(prefix, "outbox", "get", oid))
        content = render_markdown(rec) if fmt == "markdown" else json.dumps(rec, indent=2)
        path.touch(exist_ok=False)
        if restrict_on:
            restrict(path)  # lock down before any content is written
        path.write_text(content, encoding="utf-8")
        if path.read_text(encoding="utf-8") != content:
            raise RuntimeError(f"verification failed for {path}; remote entry kept")
        run_remote(prefix, "outbox", "rm", oid)
        out(f"stored {label!r} -> {path}")
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true", help="list only, fetch/delete nothing")
    a = ap.parse_args()
    try:
        pull(load_config(a.config), a.dry_run)
    except (RuntimeError, ValueError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
