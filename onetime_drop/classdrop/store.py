"""ClassDrop encrypted file-drop store (AES-256-GCM, atomic writes, file lock)."""
from __future__ import annotations
import hashlib, hmac, json, os, re, secrets, threading, time
from contextlib import contextmanager
try:
    import fcntl
except ImportError:
    fcntl = None
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
CODE_RE = re.compile(r"^[a-hjkmnp-z2-9]{3,64}$")
ITEM_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SLUG_RE = re.compile(r"^[a-z0-9-]{3,24}$")
MIME_RE = re.compile(r"^[\w.+-]+/[\w.+-]+$")
_CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_FAIL_LIMIT, _FAIL_WINDOW, _PBKDF2_ITERS = 30, 900.0, 200_000
_PW_ALPHABET = "abcdefghjkmnpqrstuvwxyz"
_PW_DIGITS = "23456789"
_MAX_FAIL_KEYS = 20000


def gen_password():
    """Readable class password like 'kumo-4827' (~33 bits; brute force is rate-limited)."""
    return "".join(secrets.choice(_PW_ALPHABET) for _ in range(4)) + "-" + "".join(secrets.choice(_PW_DIGITS) for _ in range(4))
class Locked(Exception): pass
class ClassRef(str):
    def __new__(cls, code, info):
        o = super().__new__(cls, code); o._info = dict(info); return o
    def __getitem__(self, key):
        if isinstance(key, str): return str(self) if key == "code" else self._info[key]
        return super().__getitem__(key)
    def get(self, key, default=None):
        return str(self) if key == "code" else self._info.get(key, default)
def _now(): return time.time()
def _chk(rx, v, msg):
    if not isinstance(v, str) or not rx.match(v): raise ValueError(msg)
    return v
def _valid_code(c): return _chk(CODE_RE, c, "invalid class code")
def _valid_id(i): return _chk(ITEM_RE, i, "invalid item id")
def _valid_scope(s): return _chk(SCOPE_RE, s, "invalid scope")
class Store:
    def __init__(self, config=None, state_dir=None, key_file=None, max_file_mb=None,
                 max_files=None, max_bytes=None, default_class_mb=None):
        if isinstance(config, (str, os.PathLike)) and state_dir is None: state_dir, config = str(config), None
        self.state_dir = state_dir or getattr(config, "state_dir", None) or "/var/lib/onetime-class"
        self.key_file = key_file or getattr(config, "key_file", None) or os.path.join(self.state_dir, "key.bin")
        self.max_file_bytes = (max_file_mb * 1048576) if max_file_mb else int(getattr(config, "max_file_mb", 25)) * 1048576
        self.max_files = max_files or int(getattr(config, "max_files", 20))
        self.default_max_bytes = max_bytes or int(default_class_mb or getattr(config, "default_class_mb", None) or 2048) * 1048576
        self._thread_lock = threading.RLock()
        for sub in ("classes", "items", "thumbs"): os.makedirs(os.path.join(self.state_dir, sub), exist_ok=True)
        self._key = self._load_key()
    @contextmanager
    def _locked(self):
        self._thread_lock.acquire()
        try:
            with open(os.path.join(self.state_dir, ".lock"), "a+b") as fh:
                if fcntl is not None:
                    try: fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                    except OSError: pass
                yield self
                if fcntl is not None:
                    try: fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    except OSError: pass
        finally: self._thread_lock.release()
    @staticmethod
    def _check_key(key):
        if len(key) != 32: raise ValueError("key file must hold exactly 32 bytes")
        return key
    def _load_key(self):
        kf = self.key_file
        if os.path.exists(kf):
            with open(kf, "rb") as fh: return self._check_key(fh.read())
        os.makedirs(os.path.dirname(kf) or ".", exist_ok=True)
        key = secrets.token_bytes(32)
        try: fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with open(kf, "rb") as fh: return self._check_key(fh.read())
        with os.fdopen(fd, "wb") as fh: fh.write(key)
        try: os.chmod(kf, 0o600)
        except OSError: pass
        return key
    def _awrite(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data); fh.flush()
            try: os.fsync(fh.fileno())
            except OSError: pass
        os.replace(tmp, path)
    def _awrite_json(self, path, obj): self._awrite(path, json.dumps(obj, sort_keys=True).encode())
    def _read_json(self, path, default):
        try:
            with open(path, "rb") as fh: return json.loads(fh.read().decode())
        except FileNotFoundError: return default
    def _class_path(self, code): return os.path.join(self.state_dir, "classes", code + ".json")
    def _load_class(self, code):
        _valid_code(code)
        try:
            with open(self._class_path(code), "rb") as fh: meta = json.loads(fh.read().decode())
        except FileNotFoundError: raise KeyError(code)
        if not isinstance(meta, dict) or meta.get("code") != code: raise KeyError(code)
        meta.setdefault("items", {})
        return meta
    def _save_class(self, meta): self._awrite_json(self._class_path(meta["code"]), meta)
    def _aad(self, code, item, thumb): return ("%s/%s%s" % (code, item, "/thumb" if thumb else "")).encode()
    def _enc(self, code, item, plain, thumb=False):
        n = secrets.token_bytes(12)
        return n + AESGCM(self._key).encrypt(n, plain, self._aad(code, item, thumb))
    def _dec(self, code, item, blob, thumb=False):
        return AESGCM(self._key).decrypt(blob[:12], blob[12:], self._aad(code, item, thumb))
    def _failures(self): return self._read_json(os.path.join(self.state_dir, "failures.json"), {})
    def _save_failures(self, f):
        now = _now(); f = {k: v for k, v in f.items() if v and now - v[-1] < _FAIL_WINDOW}
        if len(f) > _MAX_FAIL_KEYS:
            f = dict(sorted(f.items(), key=lambda kv: kv[1][-1])[-_MAX_FAIL_KEYS:])
        self._awrite_json(os.path.join(self.state_dir, "failures.json"), f)
    @staticmethod
    def _safe_class(meta):
        return {"code": meta["code"], "label": meta["label"], "created_at": meta["created_at"],
                "expires_at": meta["expires_at"], "max_bytes": meta["max_bytes"], "item_count": len(meta.get("items", {}))}
    def create_class(self, label, code=None, password=None, days=30):
        if not isinstance(label, str) or not label.strip() or len(label) > 200: raise ValueError("invalid label")
        label = label.strip()
        if code is None:
            with self._locked():
                for _ in range(50):
                    c = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(3))
                    if not os.path.exists(self._class_path(c)): code = c; break
                else: raise RuntimeError("could not allocate code")
        _valid_code(code)
        if password is None: password = gen_password()
        if not isinstance(password, str) or not 8 <= len(password) <= 64: raise ValueError("Passwort: mindestens 8 Zeichen")
        if isinstance(days, bool) or not isinstance(days, (int, float)) or not -365 <= days <= 3650: raise ValueError("invalid days")
        now = _now()
        salt = secrets.token_bytes(16)
        meta = {"code": code, "label": label, "salt": salt.hex(),
                "pw": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex(),
                "iters": _PBKDF2_ITERS, "created_at": now, "expires_at": now + float(days) * 86400.0,
                "max_bytes": self.default_max_bytes, "gslug": None, "gexp": None, "epoch": secrets.token_hex(8), "items": {}}
        with self._locked():
            if os.path.exists(self._class_path(code)): raise ValueError("code already exists")
            self._save_class(meta)
        self.event("class.create", code)
        return code, password
    def list_classes(self):
        out, d = [], os.path.join(self.state_dir, "classes")
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if fn.endswith(".json"):
                try: out.append(self._safe_class(self._load_class(fn[:-5])))
                except (KeyError, ValueError): continue
        return out
    def get_class(self, code): return self._safe_class(self._load_class(_valid_code(code)))
    def delete_class(self, code):
        _valid_code(code)
        with self._locked():
            meta = self._load_class(code)
            for i in list(meta.get("items", {})): self._rm_blobs(code, i)
            try: os.unlink(self._class_path(code))
            except FileNotFoundError: raise KeyError(code)
            fails = self._failures()
            for k in [k for k in fails if k.split("\x00")[-1] == code]: del fails[k]
            self._save_failures(fails)
        self.event("class.delete", code)
        return True
    def check_password(self, code, pw, ip):
        _valid_code(code)
        if not isinstance(ip, str) or not ip or len(ip) > 256: raise ValueError("invalid ip")
        key, now = ip + "\x00" + code, _now()
        with self._locked():
            meta = self._load_class(code)
            hist = [t for t in self._failures().get(key, []) if now - t < _FAIL_WINDOW]
            if len(hist) >= _FAIL_LIMIT: raise Locked("locked out")
        ok = isinstance(pw, str) and 0 < len(pw) <= 256 and hmac.compare_digest(
            hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(meta["salt"]),
                                meta.get("iters", _PBKDF2_ITERS)).hex(), meta["pw"])
        with self._locked():
            fails = self._failures()
            if ok:
                if key in fails: del fails[key]; self._save_failures(fails)
                return True
            hist = [t for t in fails.get(key, []) if now - t < _FAIL_WINDOW] + [now]
            fails[key] = hist; self._save_failures(fails)
        return False
    def dummy_password_check(self):
        """Same cost as a real check, for unknown codes (no class enumeration by timing)."""
        hashlib.pbkdf2_hmac("sha256", b"x", b"0" * 16, _PBKDF2_ITERS)
        return False
    def set_gallery(self, code, slug=None, days=None):
        """Short gallery link /g/<slug> (password-protected). slug None = random; days None = until class expiry.
        Changing the link rotates the epoch, so old gallery sessions end. Items are never touched."""
        _valid_code(code)
        if slug is not None and (not isinstance(slug, str) or not SLUG_RE.match(slug)):
            raise ValueError("Galerie-Link: 3-24 Zeichen a-z, 0-9, -")
        if days is not None and (isinstance(days, bool) or not isinstance(days, (int, float)) or not 0 < days <= 3650):
            raise ValueError("invalid days")
        with self._locked():
            meta = self._load_class(code)
            taken = {self._load_class(c["code"]).get("gslug") for c in self.list_classes() if c["code"] != code}
            if slug is None:
                for _ in range(50):
                    slug = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(4))
                    if slug not in taken: break
                else: raise RuntimeError("could not allocate gallery link")
            elif slug in taken:
                raise ValueError("Galerie-Link schon vergeben")
            meta["gslug"] = slug
            meta["gexp"] = None if days is None else _now() + float(days) * 86400.0
            meta.pop("gallery", None)
            meta["epoch"] = secrets.token_hex(8); self._save_class(meta)
        self.event("gallery.set", code)
        return slug
    def disable_gallery(self, code):
        with self._locked():
            meta = self._load_class(_valid_code(code))
            meta["gslug"] = None; meta["gexp"] = None; meta["epoch"] = secrets.token_hex(8); self._save_class(meta)
        self.event("gallery.disable", code)
    def new_gallery_token(self, code):
        return self.set_gallery(code)
    def gallery_info(self, code):
        meta = self._load_class(_valid_code(code))
        slug, exp = meta.get("gslug"), meta.get("gexp")
        if not slug or (exp is not None and exp <= _now()):
            return None
        return {"slug": slug, "expires_at": exp}
    def class_by_gallery_token(self, slug):
        if not isinstance(slug, str) or not SLUG_RE.match(slug): raise ValueError("invalid gallery link")
        for c in self.list_classes():
            meta = self._load_class(c["code"])
            if meta.get("gslug") and hmac.compare_digest(meta["gslug"], slug):
                exp = meta.get("gexp")
                if exp is not None and exp <= _now(): return None
                return ClassRef(meta["code"], self._safe_class(meta))
        return None
    def subkey(self, label):
        return hmac.new(self._key, b"classdrop-subkey|" + label.encode(), hashlib.sha256).digest()
    def _epoch(self, code):
        return self._load_class(code).get("epoch", "")
    def make_cookie(self, scope, code, exp):
        _valid_scope(scope); _valid_code(code); exp = int(exp)
        sig = hmac.new(self.subkey("cookie"), ("%s.%s.%d.%s" % (scope, code, exp, self._epoch(code))).encode(), hashlib.sha256).hexdigest()
        return "%s.%s.%d.%s" % (scope, code, exp, sig)
    def verify_cookie(self, scope, code=None, exp=None, cookie=None):
        if code is None and exp is None and cookie is None and isinstance(scope, str) and scope.count(".") >= 3:
            sc, cd, ex = scope.rsplit(".", 3)[:3]
            try: ok = self.verify_cookie(sc, cd, ex, scope)
            except ValueError: return None
            return (sc, cd, int(ex)) if ok else None
        if exp is not None and cookie is None and isinstance(exp, str) and "." in exp: cookie, exp = exp, None
        if cookie is None: raise ValueError("cookie required")
        _valid_scope(scope); _valid_code(code)
        parts = cookie.rsplit(".", 3)
        if len(parts) != 4: return False
        sc, cd, ex, sig = parts
        if sc != scope or cd != code or (exp is not None and str(exp) != ex): return False
        try: exi = int(ex)
        except ValueError: return False
        try: ep = self._epoch(cd)
        except (KeyError, ValueError): return False
        want = hmac.new(self.subkey("cookie"), ("%s.%s.%s.%s" % (sc, cd, ex, ep)).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, sig) and exi > int(_now())
    def _check_file_args(self, name, filename, mime, data, thumb):
        if not isinstance(name, str) or not name.strip() or len(name) > 200: raise ValueError("invalid name")
        if not isinstance(filename, str) or not filename or len(filename) > 200 or "/" in filename \
                or "\\" in filename or "\x00" in filename or filename in (".", ".."): raise ValueError("invalid filename")
        if not isinstance(mime, str) or len(mime) > 128 or not MIME_RE.match(mime): raise ValueError("invalid mime")
        if not isinstance(data, (bytes, bytearray)) or not data: raise ValueError("invalid data")
        if len(data) > self.max_file_bytes: raise ValueError("file too large")
        if thumb is not None and (not isinstance(thumb, (bytes, bytearray)) or not thumb
                                  or len(thumb) > 2 * 1024 * 1024): raise ValueError("invalid thumb")
    def _rm_blobs(self, code, i):
        for p in (os.path.join(self.state_dir, "items", code + "." + i + ".bin"),
                  os.path.join(self.state_dir, "thumbs", code + "." + i + ".bin")):
            try: os.unlink(p)
            except FileNotFoundError: pass
    def add_item(self, code, name, filename, mime, data, thumb=None):
        _valid_code(code)
        self._check_file_args(name, filename, mime, data, thumb)
        data = bytes(data); thumb = None if thumb is None else bytes(thumb)
        with self._locked():
            meta = self._load_class(code)
            items = meta.get("items", {})
            if len(items) >= 5000: raise ValueError("too many files")
            used = sum(e["size"] + e.get("thumb_size", 0) for e in items.values())
            if used + len(data) + (len(thumb) if thumb else 0) > meta["max_bytes"]: raise ValueError("class quota exceeded")
            for _ in range(20):
                i = secrets.token_hex(8)
                if i not in items: break
            else: raise RuntimeError("could not allocate id")
            self._awrite(os.path.join(self.state_dir, "items", code + "." + i + ".bin"), self._enc(code, i, data))
            tsize = 0
            if thumb is not None:
                self._awrite(os.path.join(self.state_dir, "thumbs", code + "." + i + ".bin"), self._enc(code, i, thumb, True))
                tsize = len(thumb)
            items[i] = {"id": i, "name": name.strip(), "filename": filename, "mime": mime, "size": len(data),
                        "thumb_size": tsize, "hidden": False, "created_at": _now()}
            meta["items"] = items; self._save_class(meta)
        self.event("item.add", code, i)
        return i
    def list_items(self, code, include_hidden=False):
        meta = self._load_class(_valid_code(code))
        items = sorted(meta.get("items", {}).values(), key=lambda e: e["created_at"])
        return [dict(e) for e in items if include_hidden or not e.get("hidden")]
    def read_item(self, code, item_id):
        _valid_code(code); _valid_id(item_id)
        meta = self._load_class(code)
        try: ent = meta["items"][item_id]
        except KeyError: raise KeyError(item_id)
        try:
            with open(os.path.join(self.state_dir, "items", code + "." + item_id + ".bin"), "rb") as fh: blob = fh.read()
        except FileNotFoundError: raise KeyError(item_id)
        return dict(ent), self._dec(code, item_id, blob)
    def read_thumb(self, code, item_id):
        _valid_code(code); _valid_id(item_id)
        meta = self._load_class(code)
        try: ent = meta["items"][item_id]
        except KeyError: raise KeyError(item_id)
        if not ent.get("thumb_size"): raise KeyError(item_id)
        try:
            with open(os.path.join(self.state_dir, "thumbs", code + "." + item_id + ".bin"), "rb") as fh: blob = fh.read()
        except FileNotFoundError: raise KeyError(item_id)
        return self._dec(code, item_id, blob, True)
    def set_hidden(self, code, item_id, hidden=True):
        _valid_code(code); _valid_id(item_id)
        with self._locked():
            meta = self._load_class(code)
            try: ent = meta["items"][item_id]
            except KeyError: raise KeyError(item_id)
            ent["hidden"] = bool(hidden); self._save_class(meta); return dict(ent)
    def delete_item(self, code, item_id):
        _valid_code(code); _valid_id(item_id)
        with self._locked():
            meta = self._load_class(code)
            if item_id not in meta.get("items", {}): raise KeyError(item_id)
            del meta["items"][item_id]; self._rm_blobs(code, item_id); self._save_class(meta)
        self.event("item.delete", code, item_id)
        return True
    def gc(self):
        now, n = _now(), 0
        with self._locked():
            d = os.path.join(self.state_dir, "classes")
            for fn in list(os.listdir(d)) if os.path.isdir(d) else []:
                if not fn.endswith(".json"): continue
                try: meta = self._load_class(fn[:-5])
                except (KeyError, ValueError): continue
                if meta.get("expires_at", 0) <= now:
                    for i in list(meta.get("items", {})): self._rm_blobs(meta["code"], i)
                    try: os.unlink(self._class_path(meta["code"]))
                    except FileNotFoundError: pass
                    n += 1
        if n: self.event("gc", None, n)
        return n
    def event(self, kind=None, code=None, detail=None):
        p = os.path.join(self.state_dir, "events.jsonl")
        if kind is None:
            try:
                with open(p, "rb") as fh: return [json.loads(l) for l in fh.read().decode().splitlines() if l.strip()]
            except FileNotFoundError: return []
        if not isinstance(kind, str) or not kind or len(kind) > 64: raise ValueError("invalid event kind")
        ev = {"ts": _now(), "kind": kind, "code": code, "detail": detail}
        with self._locked():
            with open(p, "ab") as fh: fh.write((json.dumps(ev) + "\n").encode())
        return ev
    def events(self): return self.event()
    def log_event(self, kind, code=None, detail=None): return self.event(kind, code, detail)
ClassStore = Store; ClassDropStore = Store
def selftest():
    import tempfile
    tmp = tempfile.mkdtemp()
    s = Store(state_dir=os.path.join(tmp, "st"), key_file=os.path.join(tmp, "key.bin"))
    code, pw = s.create_class("Projekt", days=30)
    assert s.check_password(code, pw, "127.0.0.1") is True
    assert s.check_password(code, "falsch", "127.0.0.1") is False
    if os.name == "posix": assert os.stat(os.path.join(tmp, "key.bin")).st_mode & 0o777 == 0o600
    tok = s.new_gallery_token(code); ref = s.class_by_gallery_token(tok)
    assert ref == code and ref["code"] == code
    exp = int(_now()) + 3600; c = s.make_cookie("admin", code, exp)
    assert s.verify_cookie("admin", code, exp, c) is True
    i = s.add_item(code, "Foto", "foto.jpg", "image/jpeg", b"12345", b"th")
    m, data = s.read_item(code, i)
    assert data == b"12345" and m["filename"] == "foto.jpg" and s.read_thumb(code, i) == b"th"
    s.set_hidden(code, i, True)
    assert s.list_items(code) == [] and len(s.list_items(code, True)) == 1
    s.set_hidden(code, i, False); assert s.gc() == 0
    s.delete_item(code, i); assert s.list_items(code, True) == []
    s.delete_class(code)
    assert s.list_classes() == [] and isinstance(s.event(), list)
    return {"ok": True}
if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["selftest"]: print(selftest())
