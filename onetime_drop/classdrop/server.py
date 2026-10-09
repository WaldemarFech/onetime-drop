"""Public class-drop listener (stdlib) behind Traefik on a private address.

Public: /<code>, /<code>/unlock, /<code>/upload, /g/<token>[/unlock|/f/<id>|/t/<id>].
Admin:  /admin/klassen[...] (only with Remote-User from the trusted proxy; see admin.py).
Everything else gets one identical 404. Paths, tokens, names, file names are never logged.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

from ..dil.server import DilServer, RateLimiter
from . import multipart, pages, sniff
from .config import ClassDropConfig, load
from .store import ClassStore, Locked

R_CODE = re.compile(r"/([a-z0-9]{3})")
R_UNLOCK = re.compile(r"/([a-z0-9]{3})/unlock")
R_UPLOAD = re.compile(r"/([a-z0-9]{3})/upload")
R_GAL = re.compile(r"/g/([a-z0-9-]{3,24})")
R_GUNLOCK = re.compile(r"/g/([a-z0-9-]{3,24})/unlock")
R_GFILE = re.compile(r"/g/([a-z0-9-]{3,24})/([ft])/([0-9a-f]{16})")
MAX_FORM = 2048
MAX_COOKIE_HDR = 8192
INLINE = {"image/jpeg", "image/png", "image/webp", "image/gif"}


class ClassHandler(BaseHTTPRequestHandler):
    server_version = "drop"
    sys_version = ""
    timeout = 30
    cfg: ClassDropConfig
    store: ClassStore
    limiter: RateLimiter
    uploads: threading.BoundedSemaphore

    # --- plumbing -------------------------------------------------------
    def version_string(self):
        return "-"

    def log_message(self, fmt, *args):
        pass

    def log_error(self, fmt, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self._not_found()

    def _headers(self, ctype="text/html; charset=utf-8", csp=pages.CSP):
        for k, v in (("Content-Type", ctype), ("Cache-Control", "no-store, max-age=0"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                     ("Referrer-Policy", "same-origin"),
                     ("X-Robots-Tag", "noindex, nofollow, noarchive"),
                     ("Cross-Origin-Opener-Policy", "same-origin"),
                     ("Cross-Origin-Resource-Policy", "same-origin"),
                     ("Content-Security-Policy", csp), ("Connection", "close")):
            self.send_header(k, v)

    def _send(self, status, body: bytes, extra=(), ctype="text/html; charset=utf-8",
              csp=pages.CSP):
        self.close_connection = True
        self.send_response(status)
        self._headers(ctype, csp)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _not_found(self):
        self._send(404, pages.message(pages.T["nf"]))

    def _redirect(self, where: str, cookie: str | None = None):
        extra = [("Location", where)] + ([("Set-Cookie", cookie)] if cookie else [])
        self._send(303, b"", extra)

    def _client_ip(self) -> str | None:
        peer = self.client_address[0]
        if peer not in self.cfg.trusted_proxies:
            return None
        xff = ",".join(self.headers.get_all("X-Forwarded-For") or [])
        last = xff.split(",")[-1].strip() if xff else ""
        try:
            return str(ipaddress.ip_address(last))
        except ValueError:
            return peer

    def _cookie(self, name: str) -> list[str]:
        raw = ";".join(self.headers.get_all("Cookie") or [])[:MAX_COOKIE_HDR]
        out = []
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name and v:
                out.append(v.strip())
        return out

    def _gate(self):
        ip = self._client_ip()
        if ip is None:
            self._log("denied-peer")
            self._not_found()
            return None
        parts = self.requestline.split(" ")
        if len(parts) != 3 or parts[1] != self.path or "?" in self.path or len(self.path) > 128:
            self._not_found()
            return None
        if not self.limiter.allow(ip):
            self._log("rate-limited", ip)
            self._send(429, pages.message(pages.T["slow"], "err"), [("Retry-After", "60")])
            return None
        return ip, self.path

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.cfg.base_url:
            return False
        return self.headers.get("Sec-Fetch-Site") in (None, "same-origin", "none")

    def _content_length(self, limit: int) -> int | None:
        if self.headers.get("Transfer-Encoding"):
            return None
        lens = self.headers.get_all("Content-Length") or []
        if len(lens) != 1 or not lens[0].strip().isdigit():
            return None
        n = int(lens[0])
        return n if 0 < n <= limit else None

    def _read_body(self, length: int, seconds: float, min_rate: int = 0) -> bytes | None:
        start = time.monotonic()
        deadline = start + seconds
        chunks, got = [], 0
        try:
            while got < length:
                now = time.monotonic()
                left = deadline - now
                if left <= 0:
                    return None
                if min_rate and now - start > 15 and got < min_rate * (now - start):
                    return None  # slow-drip upload
                self.connection.settimeout(min(left, self.timeout))
                c = self.rfile.read1(min(length - got, 1 << 20))
                if not c:
                    return None
                chunks.append(c)
                got += len(c)
        except OSError:
            return None
        return b"".join(chunks)

    def _read_form(self) -> dict | None:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        n = self._content_length(MAX_FORM)
        if n is None or ctype != "application/x-www-form-urlencoded":
            return None
        body = self._read_body(n, 10)
        if body is None:
            return None
        try:
            raw = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=8)
        except (ValueError, UnicodeDecodeError):
            return None
        return {k: v[0] for k, v in raw.items()}

    def _cls(self, code: str):
        try:
            c = self.store.get_class(code)
        except (KeyError, ValueError):
            return None
        return c if c["expires_at"] > time.time() else None

    def _gal(self, token: str):
        try:
            c = self.store.class_by_gallery_token(token)
        except (KeyError, ValueError):
            return None
        return c if c is not None and c["expires_at"] > time.time() else None

    def _gallery_info(self, code: str):
        try:
            return self.store.gallery_info(code)
        except (KeyError, ValueError):
            return None

    def _log(self, kind: str, ip: str = "") -> None:
        # one line per security event for CrowdSec (journald); no paths, names or tokens
        sys.stderr.write(f"classdrop event={kind} ip={ip or '-'}\n")

    def _session(self, scope: str, key: str) -> bool:
        for v in self._cookie(f"c{scope}"):
            try:
                if self.store.verify_cookie(scope, key, None, v):
                    return True
            except ValueError:
                pass
        return False

    def _set_cookie(self, scope: str, key: str, path: str) -> str:
        max_age = 12 * 3600
        value = self.store.make_cookie(scope, key, int(time.time()) + max_age)
        return f"c{scope}={value}; Max-Age={max_age}; Path={path}; HttpOnly; Secure; SameSite=Strict"

    def _csrf(self, code: str) -> str:
        vals = self._cookie("cu")
        base = vals[0] if vals else ""
        return hashlib.sha256(b"csrf|" + base.encode()).hexdigest()[:32]

    # --- GET ------------------------------------------------------------
    def do_GET(self):
        if self.path.startswith("/admin/klassen"):
            return self._admin("GET")
        g = self._gate()
        if g is None:
            return
        ip, path = g
        if m := R_CODE.fullmatch(path):
            code = m.group(1)
            cls = self._cls(code)
            if cls is not None and self._session("u", code):
                return self._send(200, pages.upload_form(code, cls["label"], self._csrf(code), self.cfg, gal=self._gallery_info(code)))
            # same page for unknown codes: no class enumeration
            return self._send(200, pages.password_form(f"/{code}/unlock", "Abgabe"))
        if m := R_GAL.fullmatch(path):
            token = m.group(1)
            cls = self._gal(token)
            if cls is not None and self._session("g", cls["code"]):
                return self._send(200, pages.gallery(token, cls["label"],
                                                     self.store.list_items(cls["code"])))
            return self._send(200, pages.password_form(f"/g/{token}/unlock", "Galerie"))
        if m := R_GFILE.fullmatch(path):
            return self._file(*m.groups())
        return self._not_found()

    def _file(self, token: str, kind: str, iid: str):
        cls = self._gal(token)
        if cls is None or not self._session("g", cls["code"]):
            return self._not_found()
        code = cls["code"]
        visible = {it["id"]: it for it in self.store.list_items(code)}
        if iid not in visible:
            return self._not_found()
        try:
            if kind == "t":
                data = self.store.read_thumb(code, iid)
                return self._send(200, data, ctype="image/jpeg", csp="default-src 'none'; sandbox")
            meta, data = self.store.read_item(code, iid)
        except Exception:  # noqa: BLE001 - missing/corrupt blob -> 404
            return self._not_found()
        mime = meta["mime"]
        disp = "inline" if mime in INLINE else "attachment"
        fname = meta["filename"].replace('"', "")
        self._send(200, data, [("Content-Disposition", f'{disp}; filename="{fname}"')],
                   ctype=mime if mime in INLINE else "application/octet-stream",
                   csp="default-src 'none'; sandbox")

    # --- POST -----------------------------------------------------------
    def do_POST(self):
        if self.path.startswith("/admin/klassen"):
            return self._admin("POST")
        g = self._gate()
        if g is None:
            return
        ip, path = g
        if not self._origin_ok():
            return self._not_found()
        if m := R_UNLOCK.fullmatch(path):
            code = m.group(1)
            cls = self._cls(code)
            if cls is None:
                if self._read_form() is None:
                    return self._not_found()
                self.store.dummy_password_check()
                self._log("bad-password", ip)
                return self._send(403, pages.password_form(f"/{code}/unlock", "Abgabe", pages.T["wrong"]))
            return self._unlock(ip, cls, code, "u", f"/{code}", "Abgabe")
        if m := R_GUNLOCK.fullmatch(path):
            token = m.group(1)
            cls = self._gal(token)
            if cls is None:
                if self._read_form() is None:
                    return self._not_found()
                self.store.dummy_password_check()
                self._log("bad-password", ip)
                return self._send(403, pages.password_form(f"/g/{token}/unlock", "Galerie", pages.T["wrong"]))
            return self._unlock(ip, cls, cls["code"], "g", f"/g/{token}", "Galerie")
        if m := R_UPLOAD.fullmatch(path):
            return self._upload(ip, m.group(1))
        return self._not_found()

    def _unlock(self, ip, cls, code, scope, home, title):
        if cls is None:
            return self._not_found()
        form = self._read_form()
        if form is None:
            return self._not_found()
        try:
            ok = self.store.check_password(code, form.get("password", "")[:64], ip)
        except Locked:
            self._log("locked", ip)
            return self._send(429, pages.message(pages.T["slow"], "err"), [("Retry-After", "300")])
        if not ok:
            self._log("bad-password", ip)
            return self._send(403, pages.password_form(f"{home}/unlock", title, pages.T["wrong"]))
        cookies = [self._set_cookie(scope, code, home)]
        gal = self._gallery_info(code) if scope == "u" else None
        if gal:  # same password unlocks the class gallery too
            cookies.append(self._set_cookie("g", code, f"/g/{gal['slug']}"))
        self._send(303, b"", [("Location", home)] + [("Set-Cookie", c) for c in cookies])

    def _upload(self, ip: str, code: str):
        cls = self._cls(code)
        if cls is None or not self._session("u", code):
            return self._not_found()
        ctype = self.headers.get("Content-Type") or ""
        n = self._content_length(self.cfg.max_request_mb << 20)
        if n is None or not ctype.lower().startswith("multipart/form-data"):
            return self._send(413, pages.upload_form(code, cls["label"], self._csrf(code), self.cfg, gal=self._gallery_info(code),
                                                     error="Upload zu groß oder ungültig."))
        with self.inflight_lock:  # school NAT: several students share one IP
            busy = self.inflight.get(ip, 0) >= 3
            if not busy:
                self.inflight[ip] = self.inflight.get(ip, 0) + 1
        if busy or not self.uploads.acquire(timeout=60):
            if not busy:
                self._release_ip(ip)
            return self._send(429, pages.message(pages.T["slow"], "err"), [("Retry-After", "30")])
        try:
            body = self._read_body(n, 900, min_rate=32 * 1024)
            if body is None:
                return self._not_found()
            try:
                fields, files = multipart.parse(ctype, body, self.cfg.max_files,
                                                self.cfg.max_file_mb << 20)
            except ValueError:
                return self._send(400, pages.upload_form(code, cls["label"], self._csrf(code), self.cfg, gal=self._gallery_info(code),
                                                         error="Upload ungültig (zu viele/zu große Dateien?)."))
            del body
            if not hmac.compare_digest(fields.get("csrf", ""), self._csrf(code)):
                return self._not_found()
            name = " ".join(fields.get("name", "").split())[:60]
            if not name or not files:
                return self._send(400, pages.upload_form(code, cls["label"], self._csrf(code), self.cfg, gal=self._gallery_info(code),
                                                         error="Bitte Name und mindestens eine Datei angeben."))
            saved, rejected = 0, []
            for filename, data in files:
                if not data:
                    continue
                mime = sniff.sniff(data)
                safe = sniff.safe_filename(filename)
                if mime is None:
                    rejected.append(safe)
                    continue
                try:
                    self.store.add_item(code, name, safe, mime, data, sniff.thumbnail(data, mime))
                except ValueError:
                    rejected.append(safe)
                    continue
                saved += 1
            self.store.event("upload", code, {"n": saved, "rejected": len(rejected)})
        finally:
            self.uploads.release()
            self._release_ip(ip)
        err = ("Nicht angenommen (Dateityp/Speicher): " + ", ".join(rejected)) if rejected else ""
        self._send(200, pages.upload_form(code, cls["label"], self._csrf(code), self.cfg, gal=self._gallery_info(code), error=err,
                                          ok=pages.T["done"].format(n=saved) if saved else ""))

    def _release_ip(self, ip: str) -> None:
        with self.inflight_lock:
            n = self.inflight.get(ip, 1) - 1
            if n > 0:
                self.inflight[ip] = n
            else:
                self.inflight.pop(ip, None)

    def _admin(self, method: str):
        from . import admin  # local import keeps the public path small
        admin.handle(self, method)


def make_server(cfg: ClassDropConfig, store: ClassStore | None = None, host=None, port=None):
    store = store or ClassStore(cfg)
    handler = type("BoundClassHandler", (ClassHandler,), {
        "cfg": cfg, "store": store,
        "limiter": RateLimiter(cfg.per_ip_per_min, cfg.global_per_min),
        "uploads": threading.BoundedSemaphore(4),
        "inflight": {}, "inflight_lock": threading.Lock()})
    return DilServer((host or cfg.bind, cfg.port if port is None else port), handler,
                     cfg.max_connections)


def _gc_loop(store: ClassStore, interval: int = 300) -> None:
    while True:
        try:
            store.gc()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"classdrop gc error: {type(exc).__name__}\n")
        time.sleep(interval)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="onetime-class")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    cfg = load(a.config)
    store = ClassStore(cfg)
    threading.Thread(target=_gc_loop, args=(store,), daemon=True).start()
    srv = make_server(cfg, store)
    sys.stderr.write(f"onetime-class listening on {cfg.bind}:{cfg.port}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
