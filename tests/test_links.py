"""Reveal/input link behaviour and access control."""
import json
import time

import pytest
from conftest import ORIGIN, csrf_of, req

from onetime_drop.store import parse_fields, parse_target, parse_ttl, token_id


def audit(store):
    return [json.loads(x) for x in store.audit_path.read_text().splitlines()]


# --- access control ---------------------------------------------------------

def test_missing_or_wrong_proxy_secret_denied(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    assert req(port, "GET", f"/r/{tok}", secret=None)[0] == 403
    assert req(port, "GET", f"/r/{tok}", secret="y" * 48)[0] == 403
    assert req(port, "GET", f"/r/{tok}")[0] == 200


def test_remote_user_must_be_allowed(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    assert req(port, "GET", f"/r/{tok}", user=None)[0] == 403
    assert req(port, "GET", f"/r/{tok}", user="mallory")[0] == 403
    assert req(port, "GET", f"/r/{tok}", user="bob")[0] == 200


def test_untrusted_proxy_ip_denied(env):
    store, cfg, port = env
    cfg.allowed_proxies = {"10.0.0.9"}
    tok = store.create_reveal("t", b"hunter2")
    assert req(port, "GET", f"/r/{tok}")[0] == 403
    assert any(e.get("reason") == "proxy-ip" for e in audit(store))


# --- reveal -----------------------------------------------------------------

def test_reveal_get_does_not_burn_post_burns_once(env):
    store, _, port = env
    tok = store.create_reveal("DB password", b"s3cr3t<&>")
    st, page1, r = req(port, "GET", f"/r/{tok}")
    assert st == 200 and "s3cr3t" not in page1
    assert r.getheader("Cache-Control").startswith("no-store")
    assert r.getheader("Referrer-Policy") == "same-origin"
    st, page2, _ = req(port, "GET", f"/r/{tok}")  # link previews / prefetch: still there
    assert st == 200
    st, shown, _ = req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(page2)},
                       headers={"Origin": ORIGIN})
    assert st == 200 and "s3cr3t&lt;&amp;&gt;" in shown and "Copy" in shown
    assert req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(page2)})[0] == 410
    assert req(port, "GET", f"/r/{tok}")[0] == 410
    assert not list(store.items.iterdir())


def test_reveal_post_requires_csrf_and_same_origin(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    _, p, _ = req(port, "GET", f"/r/{tok}")
    assert req(port, "POST", f"/r/{tok}", form={"csrf": "0" * 64})[0] == 403
    assert req(port, "POST", f"/r/{tok}", form={})[0] == 403
    assert req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(p)},
               headers={"Origin": "https://evil.example"})[0] == 403
    assert req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(p)},
               headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    # csrf is bound to the user
    assert req(port, "POST", f"/r/{tok}", user="bob", form={"csrf": csrf_of(p)})[0] == 403
    assert req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(p)})[0] == 200


def test_expired_reveal_is_gone(env, monkeypatch):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2", ttl=60)
    _, p, _ = req(port, "GET", f"/r/{tok}")
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 61)
    assert req(port, "POST", f"/r/{tok}", form={"csrf": csrf_of(p)})[0] == 410
    assert req(port, "GET", f"/r/{tok}")[0] == 410
    assert any(e["event"] == "expired" for e in audit(store))
    assert not list(store.items.iterdir())


def test_gc_removes_expired(env):
    store, _, _ = env
    store.create_reveal("a", b"1", ttl=60)
    store.create_reveal("b", b"2", ttl=3600)
    assert store.gc(now=time.time() + 120) == 1
    assert len(list(store.items.glob("*.json"))) == 1


def test_wrong_kind_and_bad_token(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    assert req(port, "GET", f"/i/{tok}")[0] == 410
    assert req(port, "GET", "/r/short")[0] == 404
    assert req(port, "GET", "/r/" + "A" * 43)[0] == 410


def test_secret_at_rest_encrypted_and_token_not_stored(env):
    store, _, _ = env
    tok = store.create_reveal("t", b"PLAINTEXT-MARKER")
    blob = b"".join(p.read_bytes() for p in store.root.rglob("*") if p.is_file())
    assert b"PLAINTEXT-MARKER" not in blob and tok.encode() not in blob
    assert (store.items / f"{token_id(tok)}.json").exists()


def test_reveal_post_without_form_body_does_not_burn(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    assert req(port, "POST", f"/r/{tok}", form=None)[0] == 400
    assert req(port, "GET", f"/r/{tok}")[0] == 200


# --- input ------------------------------------------------------------------

def test_input_submit_once_to_outbox(env):
    store, _, port = env
    tok = store.create_input("API key", ["name", "value"], target="vendor-key")
    st, p, _ = req(port, "GET", f"/i/{tok}")
    assert st == 200 and "name='f_value'" in p
    st, _, _ = req(port, "POST", f"/i/{tok}", headers={"Origin": ORIGIN},
                   form={"csrf": csrf_of(p), "f_name": "vendor", "f_value": "tk-MARKER"})
    assert st == 200
    assert req(port, "POST", f"/i/{tok}",
               form={"csrf": csrf_of(p), "f_name": "x", "f_value": "y"})[0] == 410
    [entry] = store.outbox_list()
    assert entry["label"] == "API key" and entry["target"] == "vendor-key"
    raw = (store.outbox / f"{entry['id']}.json").read_bytes()
    assert b"tk-MARKER" not in raw
    rec = store.outbox_get(entry["id"])
    assert rec["fields"] == {"name": "vendor", "value": "tk-MARKER"} and rec["user"] == "alice"
    store.outbox_rm(entry["id"])
    assert store.outbox_list() == []
    assert "tk-MARKER" not in store.audit_path.read_text()


def test_input_empty_submission_does_not_burn(env):
    store, _, port = env
    tok = store.create_input("k", ["value"])
    _, p, _ = req(port, "GET", f"/i/{tok}")
    assert req(port, "POST", f"/i/{tok}", form={"csrf": csrf_of(p), "f_value": " "})[0] == 400
    assert req(port, "GET", f"/i/{tok}")[0] == 200


def test_parsers():
    assert parse_ttl("24h") == 86400 and parse_ttl("30m") == 1800
    for bad in ("0", "8d", "abc", "10s"):
        with pytest.raises(ValueError):
            parse_ttl(bad)
    assert parse_fields("name, value") == ["name", "value"]
    for bad in ("", "a,a", "1x", "a b"):
        with pytest.raises(ValueError):
            parse_fields(bad)
    assert parse_target("") == "" and parse_target("example.key") == "example.key"
    for bad in ("../x", "a/b", ".hidden"):
        with pytest.raises(ValueError):
            parse_target(bad)


# --- hardening --------------------------------------------------------------

def _raw(port, lines, body=b""):
    import socket
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    crlf = "\r\n"
    s.sendall((crlf.join(lines) + crlf + crlf).encode() + body)
    data = s.recv(65536).decode("utf-8", "replace")
    s.close()
    return int(data.split(" ", 2)[1])


def test_duplicate_identity_or_secret_headers_denied(env):
    from conftest import SECRET
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    base = [f"GET /r/{tok} HTTP/1.1", "Host: x", "Connection: close"]
    assert _raw(port, base + [f"X-Drop-Proxy-Secret: {SECRET}", "Remote-User: alice"]) == 200
    assert _raw(port, base + [f"X-Drop-Proxy-Secret: {SECRET}", "Remote-User: alice",
                              "Remote-User: mallory"]) == 403
    assert _raw(port, base + [f"X-Drop-Proxy-Secret: {SECRET}",
                              f"X-Drop-Proxy-Secret: {SECRET}", "Remote-User: alice"]) == 403
    assert any(e.get("reason") == "duplicate-header" for e in audit(store))


def test_too_many_form_fields_is_400_and_does_not_burn(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    form = {f"k{i}": "v" for i in range(40)}
    assert req(port, "POST", f"/r/{tok}", form=form)[0] == 400
    assert req(port, "GET", f"/r/{tok}")[0] == 200


def test_corrupt_item_is_consumed_not_served(env):
    store, _, port = env
    tok = store.create_reveal("t", b"hunter2")
    (store.items / f"{token_id(tok)}.json").write_text("{not json")
    assert store.claim(tok) is None
    assert not list(store.items.iterdir())
    assert any(e["event"] == "corrupt" for e in audit(store))


def test_handler_has_socket_timeout():
    from onetime_drop.server import Handler
    assert Handler.timeout == 30
