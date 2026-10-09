"""Encrypted one-time item store (reveal + input links).

Layout under data_dir (mode 700, owned by the service user):
  items/<sha256(token)>.json   pending link (reveal payload AES-256-GCM encrypted)
  outbox/<id>.json             encrypted input submissions waiting for pull
  results/<sha256(token)>.json action run result: status + encrypted, redacted output log
  audit.log                    JSON lines; never contains secret content or tokens
The URL token itself is never stored; only its SHA-256 is used as the file name.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
ITEM_ID_RE = re.compile(r"^[0-9a-f]{64}$")
FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$")
OUTBOX_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_TTL = 7 * 86400
MAX_SECRET_BYTES = 32 * 1024
RESULT_KEEP = 7 * 86400


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def token_id(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def clean_label(label: str) -> str:
    label = "".join(ch for ch in label if ch.isprintable()).strip()
    if not label:
        raise ValueError("label must not be empty")
    return label[:100]


def parse_ttl(value: str | int, max_ttl: int = MAX_TTL) -> int:
    m = re.fullmatch(r"(\d+)([smhd]?)", str(value).strip())
    if not m:
        raise ValueError("ttl must look like 30m, 24h, 2d or seconds")
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 60 <= secs <= max_ttl:
        raise ValueError(f"ttl must be between 60s and {max_ttl}s")
    return secs


def parse_fields(value: str) -> list[str]:
    names = [f.strip() for f in value.split(",") if f.strip()]
    if not names or len(names) > 10 or len(set(names)) != len(names):
        raise ValueError("fields: 1-10 unique names")
    for n in names:
        if not FIELD_RE.match(n):
            raise ValueError(f"invalid field name: {n!r}")
    return names


def parse_target(value: str | None) -> str:
    value = (value or "").strip()
    if value and not TARGET_RE.match(value):
        raise ValueError("target: letters, digits, . _ - (max 60)")
    return value


@dataclass
class Item:
    id: str
    kind: str  # "reveal" | "input"
    label: str
    created: float
    expires: float
    fields: list[str] = field(default_factory=list)
    blob: dict | None = None  # encrypted reveal payload
    target: str = ""
    recipe: str = ""
    params: dict = field(default_factory=dict)
    claimed_path: Path | None = None

    def expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires


class Store:
    def __init__(self, root: Path, key: bytes):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self.root = Path(root)
        self.items = self.root / "items"
        self.outbox = self.root / "outbox"
        self.results = self.root / "results"
        self.audit_path = self.root / "audit.log"
        self._aead = AESGCM(key)
        self._csrf_key = hmac.new(key, b"drop-csrf-v1", hashlib.sha256).digest()
        for d in (self.root, self.items, self.outbox, self.results):
            d.mkdir(mode=0o700, exist_ok=True)

    # --- crypto -------------------------------------------------------
    def _seal(self, data: bytes, aad: str) -> dict:
        nonce = os.urandom(12)
        return {"n": _b64(nonce), "c": _b64(self._aead.encrypt(nonce, data, aad.encode()))}

    def _open(self, blob: dict, aad: str) -> bytes:
        return self._aead.decrypt(_unb64(blob["n"]), _unb64(blob["c"]), aad.encode())

    def csrf_for(self, scope: str, user: str) -> str:
        return hmac.new(self._csrf_key, f"{scope}|{user}".encode(), hashlib.sha256).hexdigest()

    def csrf_ok(self, scope: str, user: str, given: str) -> bool:
        return hmac.compare_digest(self.csrf_for(scope, user), given or "")

    # --- audit --------------------------------------------------------
    def audit(self, event: str, item_id: str = "", **extra) -> None:
        rec = {"ts": _now_iso(), "event": event}
        if item_id:
            rec["id"] = item_id[:12]
        rec.update({k: v for k, v in extra.items() if v not in (None, "")})
        fd = os.open(self.audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def recent_events(self, n: int = 25) -> list[dict]:
        try:
            with open(self.audit_path, encoding="utf-8") as fh:
                tail = deque(fh, maxlen=n)
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(tail):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    # --- items --------------------------------------------------------
    def _write_json(self, path: Path, obj: dict) -> None:
        tmp = path.with_name(path.name + f".tmp-{secrets.token_hex(4)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        os.replace(tmp, path)

    def _create(self, kind, label, ttl, user=None, fields=None, payload=None, target="",
                extra=None, event="created"):
        label = clean_label(label)
        token = secrets.token_urlsafe(32)  # 256 bit
        iid = token_id(token)
        now = time.time()
        obj = {"kind": kind, "label": label, "created": now, "expires": now + ttl,
               "fields": fields or [], "target": target, **(extra or {})}
        if payload is not None:
            obj["blob"] = self._seal(payload, iid)
        self._write_json(self.items / f"{iid}.json", obj)
        self.audit(event, iid, kind=kind, label=label, ttl=ttl, user=user, target=target,
                   recipe=(extra or {}).get("recipe"))
        return token

    def create_reveal(self, label: str, secret: bytes, ttl: int = 86400, user=None) -> str:
        if not secret:
            raise ValueError("secret must not be empty")
        if len(secret) > MAX_SECRET_BYTES:
            raise ValueError("secret too large")
        return self._create("reveal", label, ttl, user, payload=secret)

    def create_input(self, label: str, fields: list[str], ttl: int = 86400,
                     target: str = "", user=None) -> str:
        return self._create("input", label, ttl, user, fields=fields,
                            target=parse_target(target))

    def create_action(self, label: str, recipe: str, params: dict, ttl: int = 3600,
                      user=None) -> str:
        """Params must already be validated against the recipe (recipes.validate_params)."""
        return self._create("action", label, ttl, user,
                            extra={"recipe": recipe, "params": dict(params)},
                            event="action_created")

    @staticmethod
    def _load(path: Path, iid: str) -> Item:
        d = json.loads(path.read_text(encoding="utf-8"))
        return Item(iid, d["kind"], d["label"], d["created"], d["expires"],
                    d.get("fields", []), d.get("blob"), d.get("target", ""),
                    d.get("recipe", ""), d.get("params", {}))

    def peek(self, token: str) -> Item | None:
        """Non-destructive lookup; expired items are removed and audited."""
        if not TOKEN_RE.match(token or ""):
            return None
        iid = token_id(token)
        path = self.items / f"{iid}.json"
        try:
            item = self._load(path, iid)
        except (FileNotFoundError, ValueError, KeyError):
            return None
        if item.expired():
            self._expire(path, item)
            return None
        return item

    def _expire(self, path: Path, item: Item) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
        self.audit("expired", item.id, kind=item.kind, label=item.label)

    def claim(self, token: str) -> Item | None:
        """Atomically take ownership of an item (single use). Caller must finish()."""
        if not TOKEN_RE.match(token or ""):
            return None
        iid = token_id(token)
        src = self.items / f"{iid}.json"
        dst = self.items / f"{iid}.claimed-{secrets.token_hex(4)}"
        try:
            os.rename(src, dst)
        except FileNotFoundError:
            return None
        try:
            item = self._load(dst, iid)
        except (ValueError, KeyError):  # corrupt item: consume it, never serve it
            dst.unlink(missing_ok=True)
            self.audit("corrupt", iid)
            return None
        item.claimed_path = dst
        if item.expired():
            dst.unlink(missing_ok=True)
            self.audit("expired", iid, kind=item.kind, label=item.label)
            return None
        return item

    def finish(self, item: Item) -> None:
        if item.claimed_path:
            item.claimed_path.unlink(missing_ok=True)

    def reveal(self, item: Item, user: str) -> bytes:
        try:
            return self._open(item.blob or {}, item.id)
        finally:
            self.finish(item)
            self.audit("revealed", item.id, kind="reveal", label=item.label, user=user)

    def submit(self, item: Item, user: str, values: dict[str, str]) -> str:
        oid = secrets.token_hex(16)
        record = {"label": item.label, "target": item.target, "fields": values,
                  "user": user, "submitted": _now_iso()}
        blob = self._seal(json.dumps(record).encode(), oid)
        self._write_json(self.outbox / f"{oid}.json",
                         {"label": item.label, "target": item.target,
                          "submitted": record["submitted"], "blob": blob})
        self.finish(item)
        self.audit("submitted", item.id, kind="input", label=item.label, user=user,
                   outbox=oid)
        return oid

    def pending(self) -> list[Item]:
        out = []
        now = time.time()
        for p in self.items.glob("*.json"):
            try:
                item = self._load(p, p.stem)
            except (FileNotFoundError, ValueError, KeyError):
                continue
            if not item.expired(now):
                item.blob = None  # never hand ciphertext to listings
                out.append(item)
        return sorted(out, key=lambda i: i.created, reverse=True)

    def revoke(self, item_id: str, user: str | None = None) -> bool:
        if not ITEM_ID_RE.match(item_id or ""):
            raise ValueError("bad item id")
        path = self.items / f"{item_id}.json"
        try:
            item = self._load(path, item_id)
            path.unlink()
        except FileNotFoundError:
            return False
        self.audit("revoked", item_id, kind=item.kind, label=item.label, user=user)
        return True

    # --- action results -----------------------------------------------
    def result_put(self, item: Item, status: str, lines: list[str], **meta) -> None:
        """Store an action run result. `lines` MUST already be redacted."""
        rec = {"label": item.label, "recipe": item.recipe, "params": item.params,
               "status": status, "updated": time.time(), **meta,
               "blob": self._seal(json.dumps(lines).encode(), f"result:{item.id}")}
        self._write_json(self.results / f"{item.id}.json", rec)

    def result_for_token(self, token: str) -> dict | None:
        if not TOKEN_RE.match(token or ""):
            return None
        iid = token_id(token)
        try:
            rec = json.loads((self.results / f"{iid}.json").read_text(encoding="utf-8"))
            rec["lines"] = json.loads(self._open(rec.pop("blob"), f"result:{iid}"))
        except (FileNotFoundError, ValueError, KeyError):
            return None
        rec["id"] = iid
        return rec

    # --- outbox -------------------------------------------------------
    def outbox_list(self) -> list[dict]:
        out = []
        for p in sorted(self.outbox.glob("*.json")):
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({"id": p.stem, "label": d["label"], "target": d.get("target", ""),
                        "submitted": d["submitted"]})
        return out

    def outbox_get(self, oid: str) -> dict:
        if not OUTBOX_ID_RE.match(oid or ""):
            raise ValueError("bad outbox id")
        d = json.loads((self.outbox / f"{oid}.json").read_text(encoding="utf-8"))
        return json.loads(self._open(d["blob"], oid))

    def outbox_rm(self, oid: str) -> None:
        if not OUTBOX_ID_RE.match(oid or ""):
            raise ValueError("bad outbox id")
        (self.outbox / f"{oid}.json").unlink()
        self.audit("pulled", outbox=oid)

    # --- maintenance --------------------------------------------------
    def gc(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        n = 0
        for p in self.items.glob("*.json"):
            try:
                item = self._load(p, p.stem)
            except (FileNotFoundError, ValueError, KeyError):
                continue
            if item.expired(now):
                self._expire(p, item)
                n += 1
        for p in self.results.glob("*.json"):
            try:
                if now - p.stat().st_mtime > RESULT_KEEP:
                    p.unlink()
            except FileNotFoundError:
                pass
        for p in self.items.glob("*.claimed-*"):  # crashed mid-claim: drop after 1h
            try:
                if now - p.stat().st_ctime > 3600:
                    p.unlink()
            except FileNotFoundError:
                pass
        return n
