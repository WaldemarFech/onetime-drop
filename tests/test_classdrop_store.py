"""pytest: ClassDrop store behaviour (tmp_path, no network)."""
import hashlib
import os

import pytest

from onetime_drop.classdrop.store import Locked, Store


def make_store(tmp_path, **kw):
    kw.setdefault("state_dir", str(tmp_path / "state"))
    kw.setdefault("key_file", str(tmp_path / "key.bin"))
    return Store(**kw)


def test_roundtrip(tmp_path):
    s = make_store(tmp_path)
    code, pw = s.create_class("Physik LK", days=30)
    assert s.check_password(code, pw, "10.0.0.1") is True
    cls = s.get_class(code)
    assert cls["code"] == code and cls["label"] == "Physik LK"
    assert any(c["code"] == code for c in s.list_classes())
    item = s.add_item(code, "Hausaufgaben", "blatt.pdf",
                      "application/pdf", b"%PDF-daten", b"thumb!")
    meta, data = s.read_item(code, item)
    assert data == b"%PDF-daten"
    assert meta["filename"] == "blatt.pdf" and meta["size"] == len(b"%PDF-daten")
    assert s.read_thumb(code, item) == b"thumb!"
    assert [e["id"] for e in s.list_items(code)] == [item]
    assert s.event("ping", code)["kind"] == "ping"
    assert isinstance(s.event(), list) and s.events()
    s.delete_item(code, item)
    assert s.list_items(code, True) == []
    s.delete_class(code)
    assert s.list_classes() == []


def test_wrong_password_lockout(tmp_path):
    s = make_store(tmp_path)
    code, pw = s.create_class("Mathe", password="Mutti123", days=30)
    for _ in range(30):
        assert s.check_password(code, "falsch", "1.2.3.4") is False
    with pytest.raises(Locked):
        s.check_password(code, "falsch", "1.2.3.4")
    with pytest.raises(Locked):  # still locked, even with right pw
        s.check_password(code, "Mutti123", "1.2.3.4")
    # lockout is per (ip, code): other ip still works
    assert s.check_password(code, "Mutti123", "9.9.9.9") is True


def test_quota(tmp_path):
    s = make_store(tmp_path, max_bytes=100, max_files=3, max_file_mb=1)
    code, _ = s.create_class("Kunst", days=30)
    with pytest.raises(ValueError):
        s.add_item(code, "big", "b.bin", "application/octet-stream", b"x" * (2 * 1024 * 1024))
    s.add_item(code, "a", "a.bin", "application/octet-stream", b"a" * 40)
    s.add_item(code, "b", "b.bin", "application/octet-stream", b"b" * 40)
    with pytest.raises(ValueError):  # 40+40+40 > 100 bytes quota
        s.add_item(code, "c", "c.bin", "application/octet-stream", b"c" * 40)
    s2 = make_store(tmp_path / "s2", max_bytes=10 ** 9, max_files=1, max_file_mb=1)
    c2, _ = s2.create_class("Eins", days=30)
    s2.add_item(c2, "a", "a.bin", "application/octet-stream", b"a")
    s2.add_item(c2, "b", "b.bin", "application/octet-stream", b"b")  # max_files is per upload, not per class


def test_hidden(tmp_path):
    s = make_store(tmp_path)
    code, _ = s.create_class("Bio", days=30)
    item = s.add_item(code, "sichtbar", "s.txt", "text/plain", b"hi")
    assert len(s.list_items(code)) == 1
    s.set_hidden(code, item, True)
    assert s.list_items(code) == []
    shown = s.list_items(code, True)
    assert len(shown) == 1 and shown[0]["hidden"] is True
    s.set_hidden(code, item, False)
    assert len(s.list_items(code)) == 1


def test_gallery_token_rotate(tmp_path):
    s = make_store(tmp_path)
    code, _ = s.create_class("Galerie", days=30)
    t1 = s.new_gallery_token(code)
    assert s.class_by_gallery_token(t1) == code
    assert len(t1) == 4
    t2 = s.new_gallery_token(code)
    assert s.class_by_gallery_token(t2) == code
    assert t1 == t2 or s.class_by_gallery_token(t1) is None
    assert s.class_by_gallery_token("nonsense-token-xyz") is None
    # manual short link, validity, disable keeps items
    assert s.set_gallery(code, "7b-kunst", days=1) == "7b-kunst"
    assert s.class_by_gallery_token("7b-kunst") == code
    other, _ = s.create_class("Andere", days=30)
    with pytest.raises(ValueError):
        s.set_gallery(other, "7b-kunst")  # taken
    with pytest.raises(ValueError):
        s.set_gallery(code, "../x")
    i = s.add_item(code, "a", "a.bin", "application/octet-stream", b"x")
    s.disable_gallery(code)
    assert s.class_by_gallery_token("7b-kunst") is None and s.gallery_info(code) is None
    assert [it["id"] for it in s.list_items(code)] == [i]


def test_gc_expiry(tmp_path):
    s = make_store(tmp_path)
    code, _ = s.create_class("Alt", days=0)  # already expired
    keep, _ = s.create_class("Neu", days=30)
    s.add_item(code, "x", "x.txt", "text/plain", b"x")
    assert s.gc() >= 1
    with pytest.raises(KeyError):
        s.get_class(code)
    assert s.get_class(keep)["code"] == keep  # survivor untouched


def test_path_traversal_rejected(tmp_path):
    s = make_store(tmp_path)
    bad_codes = ["../x", "..", "/etc/passwd", "a/b", "a\\b", "", "ab",
                 "ABC", "mit leer", "0abc", "oops", "li1", "x" * 65, ".", "a.b"]
    for bad in bad_codes:
        with pytest.raises(ValueError):
            s.create_class("L", code=bad, days=30)
        with pytest.raises(ValueError):
            s.get_class(bad)
    code, _ = s.create_class("Ok", days=30)
    bad_ids = ["../x", "..", "/etc/passwd", "a/b", "", "a:b", "x" * 65, "."]
    for bad in bad_ids:
        with pytest.raises(ValueError):
            s.read_item(code, bad)
        with pytest.raises(ValueError):
            s.read_thumb(code, bad)
        with pytest.raises(ValueError):
            s.delete_item(code, bad)
        with pytest.raises(ValueError):
            s.set_hidden(code, bad, True)


def test_cookie_and_keyfile(tmp_path):
    import time
    s = make_store(tmp_path)
    code, _ = s.create_class("Cookies", days=30)
    exp = int(time.time()) + 3600
    c = s.make_cookie("admin", code, exp)
    assert s.verify_cookie("admin", code, exp, c) is True
    assert s.verify_cookie("admin", code, exp, c + "x") is False
    assert s.verify_cookie("other", code, exp, c) is False
    st = os.stat(str(tmp_path / "key.bin")).st_mode & 0o777
    if os.name == "posix":
        assert st == 0o600
    else:
        assert os.path.exists(str(tmp_path / "key.bin"))
    # ciphertext at rest: plaintext must not appear in stored blobs
    item = s.add_item(code, "geheim", "g.bin", "application/octet-stream",
                      b"super-secret-bytes")
    blob = open(tmp_path / "state" / "items" / (code + "." + item + ".bin"), "rb").read()
    assert b"super-secret-bytes" not in blob
