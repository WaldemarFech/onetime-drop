"""HTTP backend (stdlib http.server) meant to sit behind a forward-auth reverse proxy.

Trust model: only the proxy (allowed_proxies) may connect, it must present the shared secret
header, and the authenticated user header (set by the auth server) must be in allowed_users.
Request paths contain one-time tokens, so they are never logged.
"""
from __future__ import annotations

import hmac
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from . import action_handler, pages
from .config import Config
from .store import MAX_SECRET_BYTES, parse_fields, parse_target, parse_ttl

ROUTE_RE = re.compile(r"^/([ria])/([A-Za-z0-9_-]{43})$")
KINDS = {"r": "reveal", "i": "input", "a": "action"}
MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "onetime-drop"
    timeout = 30  # seconds per socket read; drops slow/idle clients
    sys_version = ""
    cfg: Config  # bound by make_server

    @property
    def s(self) -> dict:
        return pages.T[self.cfg.lang]

    def log_message(self, fmt, *args):  # never log paths (they contain tokens)
        pass

    def _path(self) -> str:
        return self.path.split("?", 1)[0]

    def _log(self, status: int) -> None:
        p = self._path()
        m = ROUTE_RE.match(p)
        where = f"/{m.group(1)}/<token>" if m else (p if p.startswith("/admin") else "-")
        sys.stderr.write(f"{time.strftime('%H:%M:%S')} {self.command} {where} {status}\n")

    def _send(self, status: int, body: bytes = b"", nonce: str = "", location: str = "") -> None:
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers(nonce)
        self.end_headers()
        self.wfile.write(body)
        self._log(status)

    def _security_headers(self, nonce: str) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        # same-origin (not no-referrer): browsers send "Origin: null" on POSTs under no-referrer
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        script = f"'nonce-{nonce}'" if nonce else "'none'"
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         f"script-src {script}; form-action 'self'; frame-ancestors 'none'; "
                         "base-uri 'none'")

    def _stream_start(self, nonce: str) -> None:
        """Start a streamed (close-delimited) HTML response; use _swrite for the body."""
        self._gone = False
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self._security_headers(nonce)
        self.end_headers()
        self._log(200)

    def _swrite(self, data: bytes) -> bool:
        """Write a chunk; a client that went away never stops the running action."""
        if getattr(self, "_gone", False):
            return False
        try:
            self.wfile.write(data)
            self.wfile.flush()
            return True
        except OSError:
            self._gone = True
            return False

    def _msg(self, status: int, title_key: str, text_key: str) -> None:
        self._send(status, pages.message(self.s, title_key, text_key, self.cfg.lang))

    def _authorize(self) -> str | None:
        """Return the authenticated user or answer 403 and return None."""
        cfg = self.cfg
        secrets_ = self.headers.get_all(cfg.proxy_secret_header) or []
        users = self.headers.get_all(cfg.user_header) or []
        given = secrets_[0] if len(secrets_) == 1 else ""
        user = users[0] if len(users) == 1 else ""
        reason = None
        if self.client_address[0] not in cfg.allowed_proxies:
            reason = "proxy-ip"
        elif len(secrets_) > 1 or len(users) > 1:
            reason = "duplicate-header"
        elif not hmac.compare_digest(given.encode(), cfg.proxy_secret.encode()):
            reason = "proxy-secret"
        elif user not in cfg.allowed_users:
            reason = "user"
        if reason:
            cfg.store.audit("denied", reason=reason)
            self._msg(403, "denied", "denied_text")
            return None
        return user

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.cfg.origin:
            return False
        return self.headers.get("Sec-Fetch-Site") in (None, "same-origin", "none")

    def _form(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip()
        if not 0 <= length <= MAX_BODY or ctype != "application/x-www-form-urlencoded":
            return None
        try:
            raw = parse_qs(self.rfile.read(length).decode("utf-8", "replace"),
                           keep_blank_values=True, max_num_fields=32)
        except ValueError:  # e.g. too many fields
            return None
        return {k: v[0] for k, v in raw.items()}

    # ------------------------------------------------------------------
    def do_GET(self):
        user = self._authorize()
        if user is None:
            return
        path = self._path()
        if path in ("/", "/admin"):
            if user not in self.cfg.admin_users:
                return self._msg(404, "nothing", "nothing")
            if path == "/":
                return self._send(303, location="/admin")
            return self._admin_page(user)
        m = ROUTE_RE.match(path)
        if not m:
            return self._msg(404, "nothing", "nothing")
        store, want = self.cfg.store, KINDS[m.group(1)]
        if want == "action":
            return action_handler.handle_get(self, user, m.group(2))
        item = store.peek(m.group(2))
        if item is None or item.kind != want:
            return self._msg(410, "invalid", "invalid_text")
        store.audit("opened", item.id, kind=item.kind, user=user)
        csrf = store.csrf_for(item.id, user)
        render = pages.reveal_confirm if want == "reveal" else pages.input_form
        self._send(200, render(self.s, item, csrf, self.cfg.lang))

    def do_POST(self):
        user = self._authorize()
        if user is None:
            return
        if not self._same_origin():
            self.cfg.store.audit("denied", reason="origin")
            return self._msg(403, "denied", "bad_origin")
        path = self._path()
        if path.startswith("/admin/"):
            return self._admin_post(user, path)
        m = ROUTE_RE.match(path)
        if not m:
            return self._msg(404, "nothing", "nothing")
        form = self._form()
        if form is None:
            return self._msg(400, "error", "bad_request")
        store, token, want = self.cfg.store, m.group(2), KINDS[m.group(1)]
        if want == "action":
            return action_handler.handle_post(self, user, token, form)
        item = store.peek(token)
        if item is None or item.kind != want:
            return self._msg(410, "invalid", "invalid_text")
        if not store.csrf_ok(item.id, user, form.get("csrf", "")):
            store.audit("denied", item.id, reason="csrf")
            return self._msg(403, "denied", "bad_form")
        values = {}
        if want == "input":
            values = {f: form.get(f"f_{f}", "") for f in item.fields}
            if not any(v.strip() for v in values.values()):
                return self._msg(400, "empty", "empty_text")
        claimed = store.claim(token)  # atomic single use
        if claimed is None:
            return self._msg(410, "invalid", "invalid_text")
        if want == "input":
            store.submit(claimed, user, values)
            return self._msg(200, "saved", "saved_text")
        try:
            secret = store.reveal(claimed, user).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - never echo details
            return self._msg(500, "error", "decrypt_err")
        nonce = secrets.token_urlsafe(16)
        self._send(200, pages.revealed(self.s, claimed.label, secret, nonce, self.cfg.lang), nonce)

    # --- admin --------------------------------------------------------
    def _admin_page(self, user: str) -> None:
        cfg, store = self.cfg, self.cfg.store
        body = pages.admin(self.s, user, store.csrf_for("admin", user), store.pending(),
                           store.outbox_list(), store.recent_events(25), cfg.default_ttl,
                           cfg.max_ttl, cfg.lang)
        self._send(200, body)

    def _admin_post(self, user: str, path: str) -> None:
        cfg, store = self.cfg, self.cfg.store
        if user not in cfg.admin_users:
            return self._msg(404, "nothing", "nothing")
        form = self._form()
        if form is None:
            return self._msg(400, "error", "bad_request")
        if not store.csrf_ok("admin", user, form.get("csrf", "")):
            store.audit("denied", reason="csrf-admin")
            return self._msg(403, "denied", "bad_form")
        try:
            if path == "/admin/revoke":
                store.revoke(form.get("id", ""), user)
                return self._send(303, location="/admin")
            ttl = parse_ttl(form.get("ttl") or str(cfg.default_ttl), cfg.max_ttl)
            label = form.get("label", "")
            if path == "/admin/reveal":
                secret = form.get("secret", "").encode("utf-8")
                if len(secret) > MAX_SECRET_BYTES:
                    raise ValueError("secret too large")
                url = f"{cfg.base_url}/r/{store.create_reveal(label, secret, ttl, user)}"
            elif path == "/admin/input":
                fields = parse_fields(form.get("fields", "value"))
                target = parse_target(form.get("target"))
                url = f"{cfg.base_url}/i/{store.create_input(label, fields, ttl, target, user)}"
            else:
                return self._msg(404, "nothing", "nothing")
        except ValueError:
            return self._msg(400, "error", "bad_request")
        nonce = secrets.token_urlsafe(16)
        self._send(200, pages.created(self.s, url, label, nonce, cfg.lang), nonce)


def make_server(cfg: Config, host: str | None = None, port: int | None = None):
    handler = type("BoundHandler", (Handler,), {"cfg": cfg})
    srv = ThreadingHTTPServer((host or cfg.bind, cfg.port if port is None else port), handler)
    srv.daemon_threads = True
    return srv


def _gc_loop(cfg: Config, interval: int = 300) -> None:
    while True:
        try:
            cfg.store.gc()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"gc error: {type(exc).__name__}\n")
        time.sleep(interval)


def serve(cfg: Config) -> None:
    threading.Thread(target=_gc_loop, args=(cfg,), daemon=True).start()
    srv = make_server(cfg)
    sys.stderr.write(f"onetime-drop listening on {cfg.bind}:{cfg.port}\n")
    srv.serve_forever()
