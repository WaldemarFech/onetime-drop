#!/usr/bin/env python3
"""Render README screenshots against a throw-away local instance with dummy data.

Requires: pip install playwright && playwright install chromium
The browser talks to https://drop.example.com; requests are routed to the local server with
the proxy headers a forward-auth proxy would add. Nothing real is involved.

  python tools/screenshots.py [--out docs/screenshots] [--lang en]
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from onetime_drop.config import Config  # noqa: E402
from onetime_drop.server import make_server  # noqa: E402

BASE = "https://drop.example.com"
SECRET = "screenshot-proxy-secret-" + "0" * 16


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--lang", default="en")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="onetime-drop-shots-"))
    (tmp / "key").write_bytes(os.urandom(32))
    cfg = Config(data_dir=tmp / "data", key_file=tmp / "key", proxy_secret=SECRET, base_url=BASE,
                 allowed_proxies={"127.0.0.1"}, allowed_users={"alice", "bob"},
                 admin_users={"alice"}, lang=a.lang)
    srv = make_server(cfg, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    local = f"http://127.0.0.1:{srv.server_address[1]}"
    store = cfg.store
    # dummy history so the admin page is not empty
    store.create_input("Payment API key", ["name", "value"], 86400, "payments.key", "alice")
    store.create_reveal("Staging DB password", b"dummy", 3600, "alice")
    t = store.create_reveal("Old Wi-Fi password", b"dummy", 3600, "alice")
    store.revoke(store.peek(t).id, "alice")

    def shoot(page, name):
        page.screenshot(path=str(out / f"{name}.png"), full_page=True)
        print(f"wrote {out / (name + '.png')}")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 390, "height": 844},
                                  device_scale_factor=2, color_scheme="light")
        user = {"v": "alice"}

        def route(r):
            headers = {**r.request.headers, "x-drop-proxy-secret": SECRET,
                       "remote-user": user["v"]}
            resp = r.fetch(url=r.request.url.replace(BASE, local), headers=headers,
                           max_redirects=0)
            hdrs = dict(resp.headers)
            if "location" in hdrs and hdrs["location"].startswith("/"):
                hdrs["location"] = BASE + hdrs["location"]
            r.fulfill(response=resp, headers=hdrs)

        ctx.route(f"{BASE}/**", route)
        page = ctx.new_page()
        page.goto(f"{BASE}/admin")
        shoot(page, "01-admin")
        page.fill("form[action='/admin/reveal'] input[name=label]", "Router admin password")
        page.fill("form[action='/admin/reveal'] textarea[name=secret]", "correct-horse-battery")
        page.click("form[action='/admin/reveal'] button")
        shoot(page, "02-link-created")
        link = page.input_value("#u")
        user["v"] = "bob"  # recipient
        page.goto(link)
        shoot(page, "03-reveal-confirm")
        page.click("button[type=submit]")
        shoot(page, "04-revealed")
        page.goto(link)
        shoot(page, "05-link-used")
        user["v"] = "alice"
        page.goto(f"{BASE}/admin")
        page.fill("form[action='/admin/input'] input[name=label]", "Weather API key")
        page.fill("form[action='/admin/input'] input[name=fields]", "account,api_key")
        page.fill("form[action='/admin/input'] input[name=target]", "weather.key")
        page.click("form[action='/admin/input'] button")
        ilink = page.input_value("#u")
        user["v"] = "bob"
        page.goto(ilink)
        page.fill("textarea[name=f_account]", "team@example.com")
        page.fill("textarea[name=f_api_key]", "wx-0000-dummy")
        shoot(page, "06-input-form")
        page.click("button[type=submit]")
        shoot(page, "07-input-saved")
        user["v"] = "alice"
        dark = browser.new_context(viewport={"width": 390, "height": 844},
                                   device_scale_factor=2, color_scheme="dark")
        dark.route(f"{BASE}/**", route)
        dpage = dark.new_page()
        dpage.goto(f"{BASE}/admin")
        shoot(dpage, "08-admin-dark")
        browser.close()
    srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
