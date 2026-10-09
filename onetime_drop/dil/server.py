"""Public DIL HTTP listener (stdlib). Sits behind Traefik on a private address.

Exposed: GET /d/<token>, POST /d/<token>/unlock, GET /d/<token>/f/<n>. Everything else,
every other method, malformed requests and dead links get one identical 404.
Paths/tokens are never logged.
"""
from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import re
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .config import DilConfig
from .store import MAX_PASSPHRASE, DilStore

ROUTE_FORM = re.compile(r"/d/([A-Za-z0-9_-]{43})")
ROUTE_UNLOCK = re.compile(r"/d/([A-Za-z0-9_-]{43})/unlock")
ROUTE_BURN = re.compile(r"/d/([A-Za-z0-9_-]{43})/burn")
ROUTE_FILE = re.compile(r"/d/([A-Za-z0-9_-]{43})/f/([0-9]{1,2})")
MAX_UNLOCK_BODY = 1024
MAX_HEADER_COOKIE = 4096
COOKIE = "dil_s"

STYLE = ("body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;"
         "line-height:1.5;color:#222;background:#fafafa}input,button{font-size:1rem;padding:.5rem}"
         "code{font-size:.75rem;word-break:break-all;color:#555}li{margin:.6rem 0}"
         ".err{color:#b00}")
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
CSP = (f"default-src 'none'; style-src 'sha256-{STYLE_HASH}'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")

T = {
    "de": {"title": "Geschützter Download", "prompt": "Bitte Passwort eingeben:",
           "btn": "Öffnen", "wrong": "Falsches Passwort. Verbleibende Versuche: {n}",
           "files": "Dateien", "hint": "Jeder Download zählt. Link läuft automatisch ab.",
           "nf": "Nicht gefunden.", "done": "Erledigt – Link jetzt löschen",
           "deleted": "Link gelöscht. Die Dateien wurden vom Server entfernt.", "slow": "Zu viele Anfragen. Bitte später erneut."},
    "en": {"title": "Protected download", "prompt": "Enter the passphrase:",
           "btn": "Open", "wrong": "Wrong passphrase. Attempts left: {n}",
           "files": "Files", "hint": "Every download counts. The link expires automatically.",
           "nf": "Not found.", "done": "Done – delete link now",
           "deleted": "Link deleted. The files were removed from the server.", "slow": "Too many requests. Try again later."},
}


def _page(lang: str, body: str) -> bytes:
    s = T[lang]
    return (f"<!doctype html><html lang={lang}><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<meta name=robots content='noindex,nofollow'>"
            f"<title>{s['title']}</title><style>{STYLE}</style></head><body>"
            f"<h1>{s['title']}</h1>{body}</body></html>").encode("utf-8")


class RateLimiter:
    def __init__(self, per_ip: int, global_: int, window: float = 60.0):
        self.per_ip, self.global_, self.window = per_ip, global_, window
        self.hits: dict[str, deque] = {}
        self.all: deque = deque()
        self.lock = threading.Lock()

    @staticmethod
    def bucket(ip: str) -> str:
        """IPv6 clients are limited per /64 (one subscriber), IPv4 per address."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if addr.version == 6:
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(ipaddress.ip_network(f"{addr}/64", strict=False))
        return str(addr)

    def allow(self, ip: str) -> bool:
        ip = self.bucket(ip)
        now = time.monotonic()
        cut = now - self.window
        with self.lock:
            while self.all and self.all[0] < cut:
                self.all.popleft()
            if len(self.hits) > 10000:  # bound memory under address spraying
                self.hits = {k: v for k, v in self.hits.items() if v and v[-1] >= cut}
            q = self.hits.setdefault(ip, deque())
            while q and q[0] < cut:
                q.popleft()
            if len(q) >= self.per_ip or len(self.all) >= self.global_:
                return False
            q.append(now)
            self.all.append(now)
            return True


class DilHandler(BaseHTTPRequestHandler):
    server_version = "dil"
    sys_version = ""
    timeout = 15
    cfg: DilConfig
    store: DilStore
    limiter: RateLimiter

    # --- plumbing -------------------------------------------------------
    def version_string(self):
        return "-"

    def log_message(self, fmt, *args):  # never log request lines (tokens)
        pass

    def log_error(self, fmt, *args):
        pass

    def send_error(self, code, message=None, explain=None):  # malformed/unknown method
        self.close_connection = True
        self._not_found()

    def _headers(self, ctype: str = "text/html; charset=utf-8", csp: str = CSP) -> None:
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Connection", "close")

    def _send(self, status: int, body: bytes, extra: list[tuple[str, str]] = ()) -> None:
        self.close_connection = True
        self.send_response(status)
        self._headers()
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _not_found(self) -> None:
        self._send(404, _page(self.cfg.lang, f"<p>{T[self.cfg.lang]['nf']}</p>"))

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

    def _cookies(self) -> list[str]:
        raw = ";".join(self.headers.get_all("Cookie") or [])[:MAX_HEADER_COOKIE]
        out = []
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and v:
                out.append(v.strip())
        return out

    def _gate(self) -> tuple[str, str] | None:
        """Common checks; returns (ip, path) or None after answering."""
        ip = self._client_ip()
        if ip is None:
            self.store.event("denied-peer")
            self._not_found()
            return None
        if not self.limiter.allow(ip):
            self.store.event("rate-limited", ip=ip)
            self._send(429, _page(self.cfg.lang, f"<p>{T[self.cfg.lang]['slow']}</p>"),
                       [("Retry-After", "60")])
            return None
        parts = self.requestline.split(" ")
        if len(parts) != 3 or parts[1] != self.path:  # stdlib collapses "//x" -> "/x"
            self._not_found()
            return None
        if "?" in self.path or "#" in self.path or len(self.path) > 128:
            self._not_found()
            return None
        return ip, self.path

    # --- views ----------------------------------------------------------
    def _form(self, token: str, error: str = "", status: int = 200) -> None:
        s = T[self.cfg.lang]
        err = f"<p class=err>{html.escape(error)}</p>" if error else ""
        body = (f"{err}<form method=post action='/d/{token}/unlock' autocomplete=off>"
                f"<p><label for=p>{s['prompt']}</label></p>"
                f"<p><input id=p type=password name=passphrase maxlength={MAX_PASSPHRASE} "
                f"required autofocus> <button type=submit>{s['btn']}</button></p></form>")
        self._send(status, _page(self.cfg.lang, body))

    def _list(self, token: str, meta: dict) -> None:
        s = T[self.cfg.lang]
        items = "".join(
            f"<li><a href='/d/{token}/f/{i}' download>{html.escape(f['name'])}</a> "
            f"({f['size']:,} B)<br><code>sha256 {f['sha256']}</code></li>"
            for i, f in enumerate(meta["files"]))
        left = meta["max_downloads"] - meta["downloads"]
        body = (f"<p><b>{html.escape(meta['label'])}</b></p><h2>{s['files']}</h2><ul>{items}</ul>"
                f"<p>{s['hint']} ({left})</p>"
                f"<form method=post action='/d/{token}/burn'>"
                f"<input type=hidden name=csrf value='{self.store.burn_csrf(token, meta)}'>"
                f"<p><button type=submit>{s['done']}</button></p></form>")
        self._send(200, _page(self.cfg.lang, body))

    # --- methods --------------------------------------------------------
    def do_GET(self):
        g = self._gate()
        if g is None:
            return
        ip, path = g
        m = ROUTE_FORM.fullmatch(path)
        if m:
            token = m.group(1)
            meta = self.store.session(token, self._cookies())
            if meta is not None:
                return self._list(token, meta)
            if not self.store.exists(token):
                return self._not_found()
            return self._form(token)
        m = ROUTE_FILE.fullmatch(path)
        if m:
            return self._download(m.group(1), int(m.group(2)), ip)
        return self._not_found()

    def do_POST(self):
        g = self._gate()
        if g is None:
            return
        ip, path = g
        m = ROUTE_UNLOCK.fullmatch(path)
        b = ROUTE_BURN.fullmatch(path)
        if not (m or b) or not self._origin_ok():
            return self._not_found()
        form = self._read_form()
        if form is None:
            return self._not_found()
        if b:
            token = b.group(1)
            if not self.store.burn_by_owner(token, self._cookies(), form.get("csrf", ""), ip):
                return self._not_found()
            gone = f"{COOKIE}=; Max-Age=0; Path=/d/{token}; HttpOnly; Secure; SameSite=Strict"
            return self._send(200, _page(self.cfg.lang, f"<p>{T[self.cfg.lang]['deleted']}</p>"),
                              [("Set-Cookie", gone)])
        token = m.group(1)
        result, meta = self.store.unlock(token, form.get("passphrase", ""), ip)
        if result == "gone":
            return self._not_found()
        if result == "wrong":
            left = 3 - meta["failures"]
            return self._form(token, T[self.cfg.lang]["wrong"].format(n=left), 403)
        value, max_age = self.store.make_cookie(token, meta)
        cookie = (f"{COOKIE}={value}; Max-Age={max_age}; Path=/d/{token}; HttpOnly; Secure; "
                  "SameSite=Strict")
        self._send(303, b"", [("Location", f"/d/{token}"), ("Set-Cookie", cookie)])

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.cfg.origin:
            return False
        return self.headers.get("Sec-Fetch-Site") in (None, "same-origin", "none")

    def _read_form(self) -> dict | None:
        if self.headers.get("Transfer-Encoding"):
            return None
        lens = self.headers.get_all("Content-Length") or []
        if len(lens) != 1 or not lens[0].strip().isdigit():
            return None
        length = int(lens[0])
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if not 0 < length <= MAX_UNLOCK_BODY or ctype != "application/x-www-form-urlencoded":
            return None
        deadline = time.monotonic() + 10
        buf = b""
        try:
            while len(buf) < length:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.connection.settimeout(min(left, self.timeout))
                chunk = self.rfile.read1(length - len(buf))
                if not chunk:
                    return None
                buf += chunk
        except OSError:
            return None
        try:
            raw = parse_qs(buf.decode("utf-8", "strict"), keep_blank_values=True,
                           max_num_fields=4, strict_parsing=False)
        except (ValueError, UnicodeDecodeError):
            return None
        return {k: v[0] for k, v in raw.items()}

    def _download(self, token: str, n: int, ip: str) -> None:
        got = self.store.open_download(token, n, self._cookies(), ip)
        if got is None:
            return self._not_found()
        fh, entry, last = got
        try:
            self.close_connection = True
            self.send_response(200)
            self._headers("application/octet-stream", "default-src 'none'; sandbox")
            self.send_header("Content-Disposition", f'attachment; filename="{entry["name"]}"')
            self.send_header("Content-Length", str(entry["size"]))
            self.end_headers()
            while chunk := fh.read(64 * 1024):
                self.wfile.write(chunk)
        except OSError:
            pass
        finally:
            fh.close()
            if last:
                self.store.finish_last(token, ip)


class DilServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, addr, handler, max_connections: int):
        super().__init__(addr, handler)
        self._slots = threading.BoundedSemaphore(max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over the concurrency cap: drop
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(cfg: DilConfig, store: DilStore | None = None, host: str | None = None,
                port: int | None = None) -> DilServer:
    store = store or DilStore(cfg.state_dir)
    handler = type("BoundDilHandler", (DilHandler,), {
        "cfg": cfg, "store": store,
        "limiter": RateLimiter(cfg.per_ip_per_min, cfg.global_per_min)})
    return DilServer((host or cfg.bind, cfg.port if port is None else port), handler,
                     cfg.max_connections)


def _gc_loop(store: DilStore, interval: int = 30) -> None:
    while True:
        try:
            store.gc()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"dil gc error: {type(exc).__name__}\n")
        time.sleep(interval)


def serve(cfg: DilConfig) -> None:
    store = DilStore(cfg.state_dir)
    threading.Thread(target=_gc_loop, args=(store,), daemon=True).start()
    srv = make_server(cfg, store)
    sys.stderr.write(f"onetime-dil listening on {cfg.bind}:{cfg.port}\n")
    srv.serve_forever()
