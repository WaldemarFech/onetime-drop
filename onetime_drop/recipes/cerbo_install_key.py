"""Recipe `cerbo-install-key`: install one ssh-ed25519 public key for root on a Victron
Cerbo GX / Venus OS device, using the root password typed by the person running the link.

Steps (remote, POSIX/busybox sh, fed via ssh stdin - nothing secret on any command line):
  (a) find the persistent authorized_keys (Venus OS: ~/.ssh may be a symlink into /data)
  (b) idempotently append the key (mkdir -p, chmod 700/600)
  (c) verify the installed line (exact key-blob match) and print fingerprints
  (d) optional: set a new random root password via chpasswd (shown once to the runner)
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
import shlex
import struct

from . import Option, Param, Recipe, Secret, Step

PUBKEY_RE = re.compile(r"^ssh-ed25519 (AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]{48,52}={0,2})"
                       r"(?: ([A-Za-z0-9._@+-]{1,64}))?$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
PW_LEN = 24


def _host(value: str, cfg) -> str:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError("host must be a plain IPv4 address") from None
    nets = [ipaddress.IPv4Network(n) for n in getattr(cfg, "action_networks", [])]
    if not any(ip in n for n in nets):
        raise ValueError("host is not in the allowed networks (config: action_networks)")
    return str(ip)


def _blob_of(line: str) -> bytes:
    m = PUBKEY_RE.match(line)
    if not m:
        raise ValueError("pubkey must be exactly one 'ssh-ed25519 <base64> [comment]' line")
    try:
        blob = base64.b64decode(m.group(1), validate=True)
    except ValueError:
        raise ValueError("pubkey: invalid base64") from None
    # wire format: string "ssh-ed25519", string <32-byte key>
    if len(blob) != 51 or blob[:15] != struct.pack(">I", 11) + b"ssh-ed25519" \
            or blob[15:19] != struct.pack(">I", 32):
        raise ValueError("pubkey: not a valid ed25519 key")
    return blob


def _pubkey(value: str, cfg) -> str:
    _blob_of(value)
    return value


def _tag(value: str, cfg) -> str:
    if not TAG_RE.match(value):
        raise ValueError("tag: letters, digits, . _ - (max 40)")
    return value


def fingerprint(pubkey: str) -> str:
    digest = hashlib.sha256(_blob_of(pubkey)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _line(params: dict) -> tuple[str, str]:
    m = PUBKEY_RE.match(params["pubkey"])
    blob, comment = m.group(1), m.group(2) or params["tag"]
    return blob, f"ssh-ed25519 {blob} {comment}"


def _count(var: str = "N") -> str:
    return (f'{var}=$(awk -v b="$BLOB" \'{{for(i=1;i<=NF;i++) if($i==b) n++}} END{{print n+0}}\' '
            '"$AK")')


def steps(params: dict, generated: dict) -> list[Step]:
    blob, line = _line(params)
    fp = fingerprint(params["pubkey"])
    q = shlex.quote
    a = "\n".join([
        f"BLOB={q(blob)}",
        f"LINE={q(line)}",
        'echo "== (a) locate persistent authorized_keys"',
        'if [ -L "$HOME/.ssh" ] && [ ! -e "$HOME/.ssh" ]; then mkdir -p "$(readlink "$HOME/.ssh")"; fi',
        'SSHDIR=$(readlink -f "$HOME/.ssh" 2>/dev/null || true)',
        '[ -n "$SSHDIR" ] || SSHDIR="$HOME/.ssh"',
        'AK="$SSHDIR/authorized_keys"',
        'echo "ssh dir: $HOME/.ssh -> $SSHDIR"',
        'echo "authorized_keys: $AK"',
    ])
    b = "\n".join([
        'echo "== (b) append key (idempotent)"',
        'mkdir -p "$SSHDIR"',
        'chmod 700 "$SSHDIR"',
        'touch "$AK"',
        'chmod 600 "$AK"',
        _count(),
        'if [ "$N" -gt 0 ]; then echo "key already present ($N line(s)), nothing appended"; else',
        '  if [ -s "$AK" ] && [ -n "$(tail -c 1 "$AK")" ]; then echo >> "$AK"; fi',
        '  printf \'%s\\n\' "$LINE" >> "$AK"',
        '  echo "key appended"',
        'fi',
    ])
    c = "\n".join([
        'echo "== (c) verify installed line"',
        _count(),
        'ls -l "$AK"',
        'if [ "$N" -lt 1 ]; then echo "KEY_NOT_FOUND"; exit 3; fi',
        'if command -v base64 >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then',
        '  echo "remote sha256(key blob): $(printf \'%s\' "$BLOB" | base64 -d | sha256sum | '
        'cut -d\' \' -f1)"',
        'fi',
        f'echo "KEY_VERIFIED lines=$N expected={fp}"',
    ])
    d = "\n".join([
        'echo "== (d) set new random root password"',
        f"NEWPW={q(generated['new_password'])}",
        'command -v chpasswd >/dev/null 2>&1 || { echo "PASSWORD_NOT_CHANGED (no chpasswd)"; '
        'exit 4; }',
        'if printf \'root:%s\\n\' "$NEWPW" | chpasswd -c SHA512 2>/dev/null; then :',
        'elif printf \'root:%s\\n\' "$NEWPW" | chpasswd -c sha512 2>/dev/null; then :',
        'elif printf \'root:%s\\n\' "$NEWPW" | chpasswd; then :',
        'else echo "PASSWORD_NOT_CHANGED"; exit 4; fi',
        'echo "PASSWORD_CHANGED"',
    ])
    return [
        Step("a", "Find the persistent authorized_keys path (readlink -f)", a),
        Step("b", "Append the key idempotently (mkdir -p, chmod 700/600)", b),
        Step("c", "Verify the installed line and print the fingerprint", c),
        Step("d", "Set a new random root password (chpasswd)", d, option="reset_password"),
    ]


def generate(options: dict) -> dict:
    pw = "".join(secrets.choice(PW_ALPHABET) for _ in range(PW_LEN))
    return {"new_password": pw if options.get("reset_password") else "-"}


def evaluate(params: dict, options: dict, lines: list[str], rc, timed_out: bool) -> dict:
    fp = fingerprint(params["pubkey"])
    verified = any(ln.startswith("KEY_VERIFIED ") and ln.endswith(f"expected={fp}")
                   for ln in lines)
    out = {"verified": verified, "fingerprint": fp}
    ok = rc == 0 and verified and not timed_out
    if options.get("reset_password"):
        started = any(ln.startswith("== (d)") for ln in lines)
        changed = "PASSWORD_CHANGED" in lines
        failed = any(ln.startswith("PASSWORD_NOT_CHANGED") for ln in lines)
        # reveal when set, or when it may have been set (connection lost / timeout after (d)
        # started) - otherwise the owner could be locked out of password login
        out["password_state"] = "changed" if changed else (
            "not_changed" if failed or not started else "unknown")
        out["reveal_new_password"] = out["password_state"] in ("changed", "unknown")
        ok = ok and changed
    out["ok"] = ok
    return out


RECIPE = Recipe(
    id="cerbo-install-key",
    title="Cerbo GX: install SSH key for root",
    description="Logs in to the Cerbo GX as root with the password you type below and adds "
                "one SSH public key to the persistent authorized_keys. The password is used "
                "only for this single ssh login and is never stored or logged.",
    params=(Param("host", "Host (LAN IPv4)", _host),
            Param("pubkey", "Public key (ssh-ed25519)", _pubkey),
            Param("tag", "Tag", _tag)),
    secrets=(Secret("password", "Current root password"),),
    options=(Option("reset_password", "Root-Passwort danach zufällig neu setzen "
                                      "(set a new random root password afterwards)", True),),
    steps=steps,
    generate=generate,
    placeholders={"new_password": "<NEW-RANDOM-PASSWORD-shown-once-after-run>"},
    target=lambda p: ("root", p["host"]),
    evaluate=evaluate,
    timeout=60,
    facts=lambda p: [("Expected key fingerprint", fingerprint(p["pubkey"]))],
)
