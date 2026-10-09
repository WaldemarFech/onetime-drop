"""End-to-end tests for the class-drop listener (real socket, stdlib client)."""
import http.client
import re
import struct
import threading
import zlib

import pytest

from onetime_drop.classdrop.config import ClassDropConfig
from onetime_drop.classdrop.server import make_server
from onetime_drop.classdrop.store import ClassStore

ORIGIN = "https://drop.test"


def _png() -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"\x00\xff\x00\x00" * 1
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


@pytest.fixture()
def srv(tmp_path):
    cfg = ClassDropConfig(state_dir=str(tmp_path / "s"), key_file=str(tmp_path / "key"), base_url=ORIGIN,
                          trusted_proxies={"127.0.0.1"}, admin_users={"admin"})
    store = ClassStore(cfg)
    s = make_server(cfg, store, host="127.0.0.1", port=0)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield s, store
    s.shutdown()


def req(s, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", s.server_address[1], timeout=10)
    h = {"X-Forwarded-For": "203.0.113.7"}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


def form(s, path, data, cookie=""):
    from urllib.parse import urlencode
    h = {"Content-Type": "application/x-www-form-urlencoded", "Origin": ORIGIN}
    if cookie:
        h["Cookie"] = cookie
    return req(s, "POST", path, urlencode(data).encode(), h)


def cookie_of(r):
    return r.getheader("Set-Cookie").split(";", 1)[0]


def multipart_body(fields, files):
    b = "----x7Kq"
    out = b""
    for k, v in fields.items():
        out += f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    for name, data in files:
        out += (f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    return out + f"--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


def test_full_flow(srv):
    s, store = srv
    code, pw = store.create_class("7b Kunst", password="Mutti123", days=5)
    token = store.new_gallery_token(code)

    r, body = req(s, "GET", f"/{code}")
    assert r.status == 200 and b"type=password" in body
    r, _ = form(s, f"/{code}/unlock", {"password": "nope"})
    assert r.status == 403
    r, _ = form(s, f"/{code}/unlock", {"password": "Mutti123"})
    assert r.status == 303
    ck = cookie_of(r)
    r, body = req(s, "GET", f"/{code}", headers={"Cookie": ck})
    csrf = re.search(rb"name=csrf value='([0-9a-f]{32})'", body).group(1).decode()

    mb, ctype = multipart_body({"csrf": csrf, "name": "Mia <b>"},
                               [("bild.png", _png()), ("virus.jpg", b"MZ\x90\x00evil")])
    r, body = req(s, "POST", f"/{code}/upload", mb,
                  {"Content-Type": ctype, "Cookie": ck, "Origin": ORIGIN})
    assert r.status == 200 and b"1 Datei" in body and b"virus.jpg" in body

    # bad csrf / no cookie / foreign origin
    mb2, _ = multipart_body({"csrf": "0" * 32, "name": "X"}, [("a.png", _png())])
    assert req(s, "POST", f"/{code}/upload", mb2, {"Content-Type": ctype, "Cookie": ck,
                                                  "Origin": ORIGIN})[0].status == 404
    assert req(s, "POST", f"/{code}/upload", mb, {"Content-Type": ctype, "Origin": ORIGIN})[0].status == 404
    assert form(s, f"/{code}/unlock", {"password": "Mutti123"}) [0].status == 303
    r, _ = req(s, "POST", f"/{code}/unlock", b"password=Mutti123",
               {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.test"})
    assert r.status == 404

    # gallery: upload cookie is not a gallery cookie
    assert req(s, "GET", f"/g/{token}", headers={"Cookie": ck})[1].count(b"name=password") == 1
    r, _ = form(s, f"/g/{token}/unlock", {"password": "Mutti123"})
    gk = cookie_of(r)
    r, body = req(s, "GET", f"/g/{token}", headers={"Cookie": gk})
    assert r.status == 200 and b"Mia &lt;b&gt;" in body and b"<b>Mia <b>" not in body
    iid = re.search(rb"/f/([0-9a-f]{16})", body).group(1).decode()
    r, data = req(s, "GET", f"/g/{token}/f/{iid}", headers={"Cookie": gk})
    assert r.status == 200 and data == _png()
    assert req(s, "GET", f"/g/{token}/f/{iid}")[0].status == 404


def test_unknown_and_admin(srv):
    s, store = srv
    r, body = req(s, "GET", "/zzz")  # unknown code looks like a real one (no enumeration)
    assert r.status == 200 and b"name=password" in body
    assert form(s, "/zzz/unlock", {"password": "whatever1"})[0].status == 403
    assert req(s, "GET", "/g/" + "A" * 43)[0].status == 404
    assert req(s, "GET", "/etc/passwd")[0].status == 404
    assert req(s, "GET", "/admin/klassen")[0].status == 404
    assert req(s, "GET", "/admin/klassen", headers={"Remote-User": "mallory"})[0].status == 404
    r, body = req(s, "GET", "/admin/klassen", headers={"Remote-User": "admin"})
    assert r.status == 200 and b"Neue Klasse" in body
    csrf = re.search(rb"name=csrf value='([^']+)'", body).group(1).decode()
    r, body = form(s, "/admin/klassen/create", {"csrf": csrf, "label": "9a", "days": "3"})
    assert r.status == 404  # no Remote-User on the POST
    from urllib.parse import urlencode
    r, body = req(s, "POST", "/admin/klassen/create",
                  urlencode({"csrf": csrf, "label": "9a", "code": "", "password": "", "days": "3"}).encode(),
                  {"Content-Type": "application/x-www-form-urlencoded", "Origin": ORIGIN,
                   "Remote-User": "admin"})
    assert r.status == 200 and b"/g/" in body and len(store.list_classes()) == 1


def test_weak_password_rejected_and_rotate_revokes(srv):
    s, store = srv
    with pytest.raises(ValueError):
        store.create_class("x", password="1234")
    code, pw = store.create_class("Kl")
    assert len(pw) >= 8
    tok = store.new_gallery_token(code)
    r, _ = form(s, f"/g/{tok}/unlock", {"password": pw})
    gk = cookie_of(r)
    assert b"name=password" not in req(s, "GET", f"/g/{tok}", headers={"Cookie": gk})[1]
    tok2 = store.set_gallery(code, "neu-link")
    assert b"name=password" in req(s, "GET", f"/g/{tok}")[1]  # old link: same page as unknown
    assert b"name=password" in req(s, "GET", f"/g/{tok2}", headers={"Cookie": gk})[1]


def test_upload_unlock_also_opens_short_gallery(srv):
    s, store = srv
    code, pw = store.create_class("8c", password="Dummy123")
    slug = store.set_gallery(code, "8c-bio")
    r, _ = form(s, f"/{code}/unlock", {"password": pw})
    cookies = [c.split(";", 1)[0] for c in r.headers.get_all("Set-Cookie")]
    assert len(cookies) == 2
    r, body = req(s, "GET", f"/{code}", headers={"Cookie": cookies[0]})
    assert b"/g/8c-bio" in body
    r, body = req(s, "GET", f"/g/{slug}", headers={"Cookie": cookies[1]})
    assert r.status == 200 and b"name=password" not in body
    assert form(s, "/g/gibts-nicht/unlock", {"password": pw})[0].status == 403
    store.disable_gallery(code)
    assert b"name=password" in req(s, "GET", f"/g/{slug}", headers={"Cookie": cookies[1]})[1]


def test_multipart_many_lines_is_fast():
    import time as _t
    from onetime_drop.classdrop import multipart
    head = b'--b\r\nContent-Disposition: form-data; name="files"; filename="a"\r\n\r\n'
    body = head + b"\n" * (20 << 20) + b"\r\n--b--\r\n"
    t = _t.monotonic()
    _, files = multipart.parse("multipart/form-data; boundary=b", body, 5, 30 << 20)
    assert len(files) == 1 and _t.monotonic() - t < 2
