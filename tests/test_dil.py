"""DIL-lite: public passphrase download links."""
import http.client
import os
import socket
import threading
from urllib.parse import urlencode

import pytest

from onetime_drop.dil.config import DilConfig
from onetime_drop.dil.server import make_server
from onetime_drop.dil.store import DilStore

PW = "Frauchen"
ORIGIN = "https://dil.example.com"


@pytest.fixture()
def dil(tmp_path):
    def start(**kw):
        args = dict(state_dir=tmp_path / "state", base_url=ORIGIN, trusted_proxies={"127.0.0.1"},
                    per_ip_per_min=1000, global_per_min=10000)
        args.update(kw)
        cfg = DilConfig(**args)
        store = DilStore(cfg.state_dir)
        srv = make_server(cfg, store, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return store, srv.server_address[1]
    started = []
    yield start
    for s in started:
        s.shutdown()
        s.server_close()


@pytest.fixture()
def files(tmp_path):
    a = tmp_path / "paket.zip"
    a.write_bytes(os.urandom(200_000))
    b = tmp_path / "PROMPT.txt"
    b.write_text("hallo\n")
    return [a, b]


def req(port, method, path, form=None, cookie=None, headers=None, raw_body=None):
    h = dict(headers or {})
    body = raw_body
    if form is not None:
        body = urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        h["Cookie"] = cookie
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data, r


def raw(port, data: bytes) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(data)
    out = b""
    while chunk := s.recv(65536):
        out += chunk
    s.close()
    return out


def unlock(port, token, pw=PW):
    st, body, r = req(port, "POST", f"/d/{token}/unlock", form={"passphrase": pw})
    cookie = None
    if st == 303:
        cookie = r.getheader("Set-Cookie").split(";")[0]
    return st, cookie, r


def nf_body(port):
    return req(port, "GET", "/nope")[1]


def test_flow_and_download(dil, files):
    store, port = dil()
    tok, _ = store.create("ThinkPad Paket", PW, files, 3600, 8)
    st, body, _ = req(port, "GET", f"/d/{tok}")
    assert st == 200 and b"type=password" in body and b"ThinkPad" not in body
    st, cookie, r = unlock(port, tok)
    assert st == 303
    sc = r.getheader("Set-Cookie")
    for attr in ("HttpOnly", "Secure", "SameSite=Strict", f"Path=/d/{tok}"):
        assert attr in sc
    st, body, _ = req(port, "GET", f"/d/{tok}", cookie=cookie)
    assert st == 200 and b"paket.zip" in body
    st, data, r = req(port, "GET", f"/d/{tok}/f/0", cookie=cookie)
    assert st == 200 and data == files[0].read_bytes()
    assert r.getheader("Content-Disposition") == 'attachment; filename="paket.zip"'
    assert r.getheader("X-Content-Type-Options") == "nosniff"


def test_burn_after_three_wrong(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    assert unlock(port, tok, "falsch1")[0] == 403
    assert unlock(port, tok, "falsch2")[0] == 403
    st, _, _ = unlock(port, tok, "falsch3")
    assert st == 404
    assert unlock(port, tok)[0] == 404  # burned: even the right one
    assert req(port, "GET", f"/d/{tok}")[0] == 404
    assert os.listdir(store.blobs) == [] and os.listdir(store.links) == []


def test_concurrent_wrong_guesses_capped(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    results = []
    ts = [threading.Thread(target=lambda i=i: results.append(unlock(port, tok, f"bad{i}xx")[0]))
          for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results) == [403, 403] + [404] * 6
    assert unlock(port, tok)[0] == 404


def test_ttl_expiry_burns(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 120, 8)
    _, cookie, _ = unlock(port, tok)
    real = store.now
    store.now = lambda: real() + 121
    assert req(port, "GET", f"/d/{tok}")[0] == 404
    assert req(port, "GET", f"/d/{tok}/f/0", cookie=cookie)[0] == 404
    assert os.listdir(store.links) == [] and os.listdir(store.blobs) == []


def test_max_downloads(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 3)
    _, cookie, _ = unlock(port, tok)
    for n in (0, 1, 1):
        assert req(port, "GET", f"/d/{tok}/f/{n}", cookie=cookie)[0] == 200
    assert req(port, "GET", f"/d/{tok}/f/0", cookie=cookie)[0] == 404
    assert req(port, "GET", f"/d/{tok}")[0] == 404
    assert os.listdir(store.blobs) == []


def test_cookie_required_and_bound(dil, files):
    store, port = dil()
    t1, _ = store.create("a", PW, files, 3600, 8)
    t2, _ = store.create("b", PW, files, 3600, 8)
    _, c1, _ = unlock(port, t1)
    assert req(port, "GET", f"/d/{t1}/f/0")[0] == 404
    assert req(port, "GET", f"/d/{t2}/f/0", cookie=c1)[0] == 404  # other token
    assert req(port, "GET", f"/d/{t1}/f/0", cookie=c1[:-2] + "00")[0] == 404  # tampered
    assert req(port, "GET", f"/d/{t1}/f/0", cookie="dil_s=9999999999.x.y")[0] == 404
    assert req(port, "GET", f"/d/{t1}/f/9", cookie=c1)[0] == 404  # out of range


@pytest.mark.parametrize("path", [
    "/d/../../etc/passwd", "/d/%2e%2e/%2e%2e/etc/passwd", "/d/..%5c..%5cetc",
    "/d/{tok}/f/../../links", "/d/{tok}/f/%2e%2e", "/d/{tok}/f/0/../1", "/d/{tok}/f/-1",
    "/d/{tok}/f/0?x=1", "/d/{tok}/", "//d/{tok}", "/d/{tok}%00", "/d/{tok}/f/0%00",
    "/d/{tok}\\f\\0", "/", "/robots.txt", "/favicon.ico", "/d/", "/d/{tok}/unlock",
])
def test_paths_all_identical_404(dil, files, path):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    _, cookie, _ = unlock(port, tok)
    st, body, _ = req(port, "GET", path.replace("{tok}", tok), cookie=cookie)
    assert st == 404 and body == nf_body(port)


def test_null_byte_and_garbage_raw(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    body404 = nf_body(port)
    for line in (f"GET /d/{tok}\x00 HTTP/1.1", "GARBAGE", f"GET /d/{tok}/f/\x000 HTTP/1.1",
                 "GET " + "/a" * 5000 + " HTTP/1.1"):
        out = raw(port, line.encode("latin-1") + b"\r\nHost: x\r\n\r\n")
        # a bare "GARBAGE" line is treated as HTTP/0.9 by the stdlib: body only, no headers
        assert out.endswith(body404) and (out.startswith(b"HTTP/1.0 404") or out == body404)


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE",
                                    "PROPFIND", "CONNECT"])
def test_methods_restricted(dil, files, method):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    st, _, r = req(port, method, f"/d/{tok}")
    assert st == 404 and r.getheader("Allow") is None


def test_unknown_expired_burned_identical(dil, files):
    store, port = dil()
    burned, _ = store.create("x", PW, files, 3600, 8)
    for i in range(3):
        unlock(port, burned, f"wrong{i}x")
    expired, _ = store.create("y", PW, files, 120, 8)
    real = store.now
    store.now = lambda: real() + 500
    unknown = "A" * 43
    responses = {(req(port, "GET", f"/d/{t}")[:2]) for t in (burned, expired, unknown)}
    responses |= {(req(port, "POST", f"/d/{t}/unlock", form={"passphrase": PW})[:2])
                  for t in (burned, expired, unknown)}
    assert responses == {(404, nf_body(port))}


def test_post_limits_and_origin(dil, files):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    big = urlencode({"passphrase": "a" * 2000}).encode()
    st, _, _ = req(port, "POST", f"/d/{tok}/unlock", raw_body=big,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert st == 404
    st, _, _ = req(port, "POST", f"/d/{tok}/unlock", form={"passphrase": "wrongx"},
                   headers={"Origin": "https://evil.example"})
    assert st == 404
    meta = store._read(__import__("onetime_drop.dil.store", fromlist=["x"]).token_key(tok))
    assert meta["failures"] == 0  # foreign origin never counts


def test_rate_limit(dil, files):
    store, port = dil(per_ip_per_min=5)
    statuses = [req(port, "GET", "/x")[0] for _ in range(8)]
    assert statuses[:5] == [404] * 5 and statuses[5:] == [429] * 3


def test_untrusted_peer_rejected(dil, files):
    store, port = dil(trusted_proxies={"10.9.9.9"})
    tok, _ = store.create("x", PW, files, 3600, 8)
    assert req(port, "GET", f"/d/{tok}")[0] == 404


def test_no_secrets_in_logs(dil, files, capsys):
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 2)
    unlock(port, tok, "wrongpass")
    _, cookie, _ = unlock(port, tok)
    req(port, "GET", f"/d/{tok}/f/0", cookie=cookie)
    req(port, "GET", f"/d/{tok}/f/1", cookie=cookie)
    req(port, "GET", "/d/" + "B" * 43)
    logs = store.events_path.read_text() + capsys.readouterr().err
    for bad in (tok, PW, "wrongpass", "/d/", "127.0.0.1", cookie.split("=", 1)[1]):
        assert bad not in logs
    assert '"ev":"burned"' in logs and "max-downloads" in logs


def test_store_secrets_hashed(tmp_path, files):
    store = DilStore(tmp_path / "s")
    tok, _ = store.create("x", PW, files, 3600, 8)
    blob = "".join(p.read_text() for p in store.links.iterdir())
    assert tok not in blob and PW not in blob
    if os.name == "posix":
        assert oct(os.stat(store.root).st_mode & 0o777) == "0o700"
        for p in (store.blobs / os.listdir(store.blobs)[0]).iterdir():
            assert oct(os.stat(p).st_mode & 0o777) == "0o600"


def test_done_button_burns(dil, files):
    import re
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    _, cookie, _ = unlock(port, tok)
    page = req(port, "GET", f"/d/{tok}", cookie=cookie)[1].decode()
    csrf = re.search(r"name=csrf value='([0-9a-f]{64})'", page).group(1)
    assert f"action='/d/{tok}/burn'" in page
    # no cookie / wrong csrf -> 404, nothing burned
    assert req(port, "POST", f"/d/{tok}/burn", form={"csrf": csrf})[0] == 404
    assert req(port, "POST", f"/d/{tok}/burn", form={"csrf": "0" * 64}, cookie=cookie)[0] == 404
    assert req(port, "GET", f"/d/{tok}")[0] == 200
    st, body, r = req(port, "POST", f"/d/{tok}/burn", form={"csrf": csrf}, cookie=cookie)
    assert st == 200 and "gelöscht".encode() in body and "Max-Age=0" in r.getheader("Set-Cookie")
    # double click: same request again is harmless and the token is a plain 404 now
    assert req(port, "POST", f"/d/{tok}/burn", form={"csrf": csrf}, cookie=cookie)[0] == 404
    assert req(port, "GET", f"/d/{tok}")[:2] == (404, nf_body(port))
    assert req(port, "GET", f"/d/{tok}/f/0", cookie=cookie)[0] == 404
    assert os.listdir(store.links) == [] and os.listdir(store.blobs) == []
    assert "done-by-guest" in store.events_path.read_text()


def test_ipv6_rate_limit_per_64():
    from onetime_drop.dil.server import RateLimiter
    rl = RateLimiter(2, 100)
    assert rl.allow("2001:db8::1") and rl.allow("2001:db8::2")
    assert not rl.allow("2001:db8::ffff:1")      # same /64
    assert rl.allow("2001:db8:0:1::1")           # other /64
    assert rl.allow("192.0.2.1") and rl.allow("::ffff:192.0.2.1")
    assert not rl.allow("192.0.2.1")             # v4-mapped counts as the same v4


def test_fuzz_unauthenticated_routes(dil, files):
    import random
    store, port = dil()
    tok, _ = store.create("x", PW, files, 3600, 8)
    body404 = nf_body(port)
    rnd = random.Random(1234)
    alphabet = "abcAZ09_-/.%~:@!$&'()*+,;=\\x7f\u00e4"
    seen = set()
    for i in range(300):
        kind = rnd.choice(["path", "token", "post", "method"])
        junk = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 60)))
        if kind == "path":
            path = "/" + junk
        elif kind == "token":
            path = f"/d/{tok[:rnd.randint(0, 43)]}{junk[:3]}/" + rnd.choice(["unlock", "f/1", "x"])
        else:
            path = f"/d/{tok}/" + rnd.choice(["unlock", "burn", "f/0", ""]) + junk[:5]
        method = rnd.choice(["GET", "POST", "PUT", "HEAD"]) if kind == "method" else \
            ("POST" if kind == "post" else "GET")
        line = f"{method} {path.replace(' ', '%20')} HTTP/1.1\r\nHost: x\r\n"
        body = junk.encode("utf-8", "replace")[:rnd.choice([0, 10, 2000])]
        if method == "POST":
            line += ("Content-Type: application/x-www-form-urlencoded\r\n"
                     f"Content-Length: {len(body)}\r\n")
        out = raw(port, line.encode("utf-8") + b"\r\n" + body)
        status = out[9:12]
        seen.add(status)
        assert status in (b"404", b"200", b"403"), (path, out[:80])
        if status == b"404" and method != "HEAD":
            assert out.endswith(body404)
    # the link survived the fuzzing unharmed (no wrong passphrase got through as POST form)
    assert unlock(port, tok)[0] == 303
