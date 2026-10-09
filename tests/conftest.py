import http.client
import os
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from onetime_drop.config import Config  # noqa: E402
from onetime_drop.server import make_server  # noqa: E402

SECRET = "x" * 48
ORIGIN = "https://drop.example.com"


def make_config(tmp_path, **kw):
    key = tmp_path / "key"
    if not key.exists():
        key.write_bytes(os.urandom(32))
    args = dict(data_dir=tmp_path / "data", key_file=key, proxy_secret=SECRET, base_url=ORIGIN,
                allowed_proxies={"127.0.0.1"}, allowed_users={"alice", "bob"},
                admin_users={"alice"})
    args.update(kw)
    return Config(**args)


@pytest.fixture()
def env(tmp_path):
    cfg = make_config(tmp_path)
    srv = make_server(cfg, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield cfg.store, cfg, srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def req(port, method, path, *, user="alice", secret=SECRET, form=None, headers=None):
    h = {}
    if secret is not None:
        h["X-Drop-Proxy-Secret"] = secret
    if user is not None:
        h["Remote-User"] = user
    body = None
    if form is not None:
        body = urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    h.update(headers or {})
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode("utf-8")
    c.close()
    return r.status, data, r


def csrf_of(html_text):
    return re.search(r"name=csrf value='([0-9a-f]+)'", html_text).group(1)
