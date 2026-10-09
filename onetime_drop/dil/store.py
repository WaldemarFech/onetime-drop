"""DIL link store: hashed tokens, scrypt passphrases, private file copies, burn semantics.

Layout under state_dir (mode 0700, owned by the service user):
  links/<sha256(token)>.json   link metadata (no token, passphrase only as scrypt hash)
  blobs/<sha256(token)>/<n>    private copies of the offered files (0600)
  events.log                   audit events: type, link id prefix, IP hash. Never tokens/paths.

All state changes on a link happen under one lock (thread lock + flock across processes), so
concurrent unlock attempts can never exceed MAX_FAILURES and downloads never exceed the cap.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
import unicodedata
from pathlib import Path

try:  # POSIX only; on other platforms the in-process lock is all we have
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
KEY_RE = re.compile(r"[0-9a-f]{64}")
MAX_FAILURES = 3
MAX_FILES = 16
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_DOWNLOADS = 100
MIN_PASSPHRASE = 6
MAX_PASSPHRASE = 256
COOKIE_TTL = 15 * 60
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}
_SCRYPT_SLOTS = threading.BoundedSemaphore(4)  # caps memory: 4 x 32 MiB
_DUMMY_SALT = secrets.token_bytes(16)
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]")


def _norm(passphrase: str) -> bytes:
    return unicodedata.normalize("NFC", passphrase).encode("utf-8")


def _kdf(passphrase: str, salt: bytes) -> bytes:
    with _SCRYPT_SLOTS:
        return hashlib.scrypt(_norm(passphrase)[:MAX_PASSPHRASE * 4], salt=salt, **SCRYPT)


def token_key(token: str) -> str | None:
    """sha256(token) hex, or None for anything that is not a well-formed token."""
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def safe_filename(name: str, n: int) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    base = SAFE_NAME_RE.sub("_", unicodedata.normalize("NFKD", base)).strip(" .")
    return base[:100] or f"file{n}"


class DilStore:
    def __init__(self, state_dir: Path, ip_salt: bytes | None = None):
        self.root = Path(state_dir)
        self.links = self.root / "links"
        self.blobs = self.root / "blobs"
        self.events_path = self.root / "events.log"
        for d in (self.root, self.links, self.blobs):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                os.chmod(d, 0o700)
        self._tlock = threading.RLock()
        self._ip_salt = ip_salt or secrets.token_bytes(16)
        self.now = time.time  # overridable in tests

    # --- locking / audit ------------------------------------------------
    @contextlib.contextmanager
    def locked(self):
        with self._tlock:
            if fcntl is None:
                yield
                return
            fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def ip_hash(self, ip: str) -> str:
        return hmac.new(self._ip_salt, ip.encode(), hashlib.sha256).hexdigest()[:12]

    def event(self, ev: str, link_id: str = "", ip: str = "", **extra) -> None:
        rec = {"ts": int(self.now()), "ev": ev}
        if link_id:
            rec["id"] = link_id[:8]
        if ip:
            rec["ip"] = self.ip_hash(ip)
        rec.update({k: v for k, v in extra.items() if isinstance(v, (int, str, bool))})
        line = json.dumps(rec, separators=(",", ":"))
        try:
            fd = os.open(self.events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
        sys.stderr.write("dil " + line + "\n")

    # --- metadata -------------------------------------------------------
    def _meta_path(self, key: str) -> Path:
        assert KEY_RE.fullmatch(key)
        return self.links / f"{key}.json"

    def _read(self, key: str) -> dict | None:
        try:
            with open(self._meta_path(key), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def _write(self, key: str, meta: dict) -> None:
        path = self._meta_path(key)
        tmp = path.with_suffix(f".tmp{secrets.token_hex(4)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        os.replace(tmp, path)

    def _live(self, key: str | None) -> dict | None:
        """Metadata of a usable link (caller holds the lock); expired links burn here."""
        if key is None:
            return None
        meta = self._read(key)
        if meta is None:
            return None
        if self.now() >= meta["expires"]:
            self._burn(key, meta, "expired")
            return None
        if meta["failures"] >= MAX_FAILURES or meta["downloads"] >= meta["max_downloads"]:
            self._burn(key, meta, "spent")
            return None
        return meta

    def _burn(self, key: str, meta: dict | None, reason: str, ip: str = "") -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._meta_path(key))  # link is dead from here on
        shutil.rmtree(self.blobs / key, ignore_errors=True)  # leftovers: gc removes orphans
        self.event("burned", (meta or {}).get("id", ""), ip, reason=reason)

    # --- create / admin -------------------------------------------------
    def create(self, label: str, passphrase: str, files: list[Path], ttl: int,
               max_downloads: int) -> tuple[str, str]:
        label = " ".join(str(label).split())[:80]
        if not label:
            raise ValueError("label required")
        if not MIN_PASSPHRASE <= len(passphrase) <= MAX_PASSPHRASE:
            raise ValueError(f"passphrase must be {MIN_PASSPHRASE}..{MAX_PASSPHRASE} characters")
        if not 1 <= len(files) <= MAX_FILES:
            raise ValueError(f"1..{MAX_FILES} files")
        if not 1 <= int(max_downloads) <= MAX_DOWNLOADS:
            raise ValueError(f"max_downloads must be 1..{MAX_DOWNLOADS}")
        total = 0
        for f in files:
            st = os.stat(f)
            if not os.path.isfile(f) or st.st_size > MAX_FILE_BYTES:
                raise ValueError(f"not a regular file or larger than {MAX_FILE_BYTES} bytes")
            total += st.st_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("files too large in total")
        token = secrets.token_urlsafe(32)  # 256 bit, 43 chars
        key = token_key(token)
        bdir = self.blobs / key
        bdir.mkdir(mode=0o700)
        entries, names = [], set()
        try:
            for n, src in enumerate(files):
                name = safe_filename(str(src), n)
                while name in names:
                    name = f"{n}_{name}"
                names.add(name)
                h, size = hashlib.sha256(), 0
                fd = os.open(bdir / str(n), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
                    while chunk := fin.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_FILE_BYTES:
                            raise ValueError("file grew beyond the size cap")
                        h.update(chunk)
                        fout.write(chunk)
                entries.append({"name": name, "size": size, "sha256": h.hexdigest()})
            salt = secrets.token_bytes(16)
            now = self.now()
            meta = {"v": 1, "id": secrets.token_hex(6), "label": label, "created": int(now),
                    "expires": now + int(ttl), "max_downloads": int(max_downloads),
                    "downloads": 0, "failures": 0, "salt": salt.hex(),
                    "pw": _kdf(passphrase, salt).hex(), "ck": secrets.token_hex(32),
                    "files": entries}
            with self.locked():
                self._write(key, meta)
        except BaseException:
            shutil.rmtree(bdir, ignore_errors=True)
            raise
        self.event("created", meta["id"], files=len(entries), ttl=int(ttl),
                   max_downloads=int(max_downloads))
        return token, meta["id"]

    def list(self) -> list[dict]:
        out = []
        with self.locked():
            for p in sorted(self.links.glob("*.json")):
                meta = self._live(p.stem) if KEY_RE.fullmatch(p.stem) else None
                if meta:
                    out.append({k: meta[k] for k in ("id", "label", "created", "expires",
                                                      "downloads", "max_downloads", "failures")}
                               | {"files": [f["name"] for f in meta["files"]]})
        return out

    def revoke(self, link_id: str) -> bool:
        with self.locked():
            for p in self.links.glob("*.json"):
                meta = self._read(p.stem) if KEY_RE.fullmatch(p.stem) else None
                if meta and hmac.compare_digest(meta["id"], str(link_id)):
                    self._burn(p.stem, meta, "revoked")
                    return True
        return False

    def gc(self) -> int:
        """Burn expired links and remove orphaned blob dirs / temp files."""
        n = 0
        with self.locked():
            for p in list(self.links.iterdir()):
                if p.suffix == ".json" and KEY_RE.fullmatch(p.stem):
                    if self._read(p.stem) is not None and self._live(p.stem) is None:
                        n += 1
                elif ".tmp" in p.name and self.now() - p.stat().st_mtime > 60:
                    p.unlink(missing_ok=True)
            for d in list(self.blobs.iterdir()):
                if not (self.links / f"{d.name}.json").exists() and \
                        self.now() - d.stat().st_mtime > 3600:  # never race a running create
                    shutil.rmtree(d, ignore_errors=True)
        return n

    # --- public operations ----------------------------------------------
    def exists(self, token: str) -> bool:
        with self.locked():
            return self._live(token_key(token)) is not None

    def unlock(self, token: str, passphrase: str, ip: str = "") -> tuple[str, dict | None]:
        """Return ("ok", meta) | ("wrong", meta) | ("gone", None).

        The KDF runs for unknown tokens too (same cost), and verification + counter update
        happen under the lock, so parallel guesses are strictly serialized.
        """
        key = token_key(token)
        passphrase = passphrase[:MAX_PASSPHRASE]
        with self.locked():
            meta = self._live(key)
            if meta is not None:
                return self._verify(key, meta, passphrase, ip)
        # unknown/dead token: same KDF cost, but outside the store lock so a flood of
        # random tokens cannot serialize (and thereby block) unlocks of real links
        _kdf(passphrase, _DUMMY_SALT)
        return "gone", None

    def _verify(self, key: str, meta: dict, passphrase: str, ip: str):
        """Check the passphrase and update the failure counter (caller holds the lock)."""
        ok = hmac.compare_digest(_kdf(passphrase, bytes.fromhex(meta["salt"])),
                                 bytes.fromhex(meta["pw"]))
        if ok:
            self.event("unlocked", meta["id"], ip)
            return "ok", meta
        meta["failures"] += 1
        if meta["failures"] >= MAX_FAILURES:
            self._burn(key, meta, "wrong-passphrase", ip)
            return "gone", None
        self._write(key, meta)
        self.event("wrong-passphrase", meta["id"], ip, failures=meta["failures"])
        return "wrong", meta

    def make_cookie(self, token: str, meta: dict) -> tuple[str, int]:
        exp = int(min(self.now() + COOKIE_TTL, meta["expires"]))
        nonce = secrets.token_urlsafe(12)
        mac = self._mac(token_key(token), meta, exp, nonce)
        return f"{exp}.{nonce}.{mac}", max(1, exp - int(self.now()))

    @staticmethod
    def _mac(key: str, meta: dict, exp: int, nonce: str) -> str:
        msg = f"dil1|{key}|{exp}|{nonce}".encode()
        return hmac.new(bytes.fromhex(meta["ck"]), msg, hashlib.sha256).hexdigest()

    def _cookie_ok(self, key: str, meta: dict, values: list[str]) -> bool:
        good = False
        for v in values[:4]:
            parts = v.split(".")
            if len(parts) != 3 or not parts[0].isdigit() or len(parts[0]) > 12:
                continue
            exp = int(parts[0])
            expect = self._mac(key, meta, exp, parts[1])
            if hmac.compare_digest(expect, parts[2]) and self.now() < exp:
                good = True
        return good

    def session(self, token: str, cookies: list[str]) -> dict | None:
        """Metadata if the link is live AND one of the cookies is valid for this token."""
        key = token_key(token)
        with self.locked():
            meta = self._live(key)
            if meta is None or not self._cookie_ok(key, meta, cookies):
                return None
            return meta

    def open_download(self, token: str, n: int, cookies: list[str], ip: str = ""):
        """Count one download and return (fileobj, entry, last) or None.

        If this was the last allowed download the caller must call finish_last() after
        streaming (the file stays readable while open; the link refuses everything else).
        """
        key = token_key(token)
        with self.locked():
            meta = self._live(key)
            if meta is None or not self._cookie_ok(key, meta, cookies):
                return None
            if not 0 <= n < len(meta["files"]):
                return None
            try:
                fh = open(self.blobs / key / str(n), "rb")
            except OSError:
                return None
            meta["downloads"] += 1
            self._write(key, meta)
            last = meta["downloads"] >= meta["max_downloads"]
            self.event("download", meta["id"], ip, file=n, count=meta["downloads"])
            return fh, meta["files"][n], last

    def finish_last(self, token: str, ip: str = "") -> None:
        key = token_key(token)
        with self.locked():
            meta = self._read(key) if key else None
            if meta is not None:
                self._burn(key, meta, "max-downloads", ip)

    def burn_csrf(self, token: str, meta: dict) -> str:
        msg = f"dil1-burn|{token_key(token)}".encode()
        return hmac.new(bytes.fromhex(meta["ck"]), msg, hashlib.sha256).hexdigest()

    def burn_by_owner(self, token: str, cookies: list[str], csrf: str, ip: str = "") -> bool:
        """'Done - delete link now': needs a valid session cookie AND the form token."""
        key = token_key(token)
        with self.locked():
            meta = self._live(key)
            if meta is None or not self._cookie_ok(key, meta, cookies):
                return False
            if not hmac.compare_digest(self.burn_csrf(token, meta), str(csrf)[:128]):
                return False
            self._burn(key, meta, "done-by-guest", ip)
            return True
