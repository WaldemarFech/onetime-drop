"""Class admin under /admin/klassen (Traefik forwardAuth → Authelia 2FA sets Remote-User).

Only requests from a trusted proxy with a Remote-User in cfg.admin_users are served.
State-changing actions are POST-only, Origin-checked and carry an HMAC CSRF token.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import os
import tempfile
import re
import time
import zipfile

from . import pages

BASE = "/admin/klassen"
R_CLASS = re.compile(BASE + r"/([a-z0-9]{3})")
R_ZIP = re.compile(BASE + r"/([a-z0-9]{3})/export\.zip")
ACTIONS = {"create", "rotate", "gallery", "gallery-off", "hide", "unhide", "delete-item", "delete-class"}
_E = html.escape


def _user(h) -> str | None:
    if h.client_address[0] not in h.cfg.trusted_proxies:
        return None
    users = h.headers.get_all("Remote-User") or []
    if len(users) != 1 or users[0] not in h.cfg.admin_users:
        return None
    return users[0]


def handle(h, method: str) -> None:
    user = _user(h)
    path = h.path.split("?", 1)[0]
    if user is None or len(path) > 128:
        return h._not_found()
    if method == "GET":
        if path == BASE:
            return _index(h, user)
        if m := R_ZIP.fullmatch(path):
            return _zip(h, m.group(1))
        if m := R_CLASS.fullmatch(path):
            return _detail(h, user, m.group(1))
        return h._not_found()
    if not h._origin_ok():
        return h._not_found()
    form = h._read_form()
    if form is None or not hmac.compare_digest(form.get("csrf", ""), _csrf(h, user)):
        return h._not_found()
    act = path[len(BASE) + 1:]
    if act not in ACTIONS:
        return h._not_found()
    try:
        _do(h, user, act, form)
    except (ValueError, KeyError) as exc:
        h._send(400, _page("Fehler", f"<div class=card><p class=err>{_E(str(exc))}</p>"
                                     f"<p><a href='{BASE}'>zurück</a></p></div>"))


def _csrf(h, user: str) -> str:
    # stable per admin user; bound to the store key (never leaves the admin pages)
    return hmac.new(h.store.subkey("csrf"), b"admin-csrf|" + user.encode(), hashlib.sha256).hexdigest()


def _btn(csrf: str, act: str, label: str, **fields) -> str:
    hidden = "".join(f"<input type=hidden name={k} value='{_E(str(v))}'>" for k, v in fields.items())
    cls = "danger" if act.startswith("delete") else ""
    return (f"<form class=in method=post action='{BASE}/{act}'>"
            f"<input type=hidden name=csrf value='{_E(csrf)}'>{hidden}"
            f"<button type=submit class='{cls}'>{_E(label)}</button></form>")


def _page(title: str, body: str) -> bytes:
    return pages.page(title, body)


def _index(h, user: str) -> None:
    csrf = _csrf(h, user)
    rows = []
    for c in h.store.list_classes():
        exp = time.strftime("%d.%m.%Y", time.localtime(c["expires_at"]))
        its = h.store.list_items(c["code"], include_hidden=True)
        n, mb = len(its), sum(i["size"] for i in its) / 1e6
        rows.append(f"<div class=card><b><a href='{BASE}/{c['code']}'>{_E(c['label'])}</a></b>"
                    f"<br>{h.cfg.base_url}/{c['code']} · bis {exp} · {n} Dateien · {mb:.1f} MB</div>")
    form = (f"<form class=card method=post action='{BASE}/create' autocomplete=off>"
            f"<input type=hidden name=csrf value='{_E(csrf)}'><b>Neue Klasse</b>"
            "<label>Name der Klasse</label><input type=text name=label maxlength=60 required>"
            "<label>Kurzcode (3 Zeichen, leer = zufällig)</label><input type=text name=code maxlength=3>"
            "<label>Passwort (leer = generiert)</label><input type=text name=password maxlength=32>"
            "<label>Gültig (Tage)</label><input type=text name=days value=30 maxlength=3>"
            "<label>Galerie-Link /g/… (leer = zufällig, z.B. 7b-kunst)</label>"
            "<input type=text name=gallery maxlength=24>"
            "<button type=submit>Anlegen</button></form>")
    h._send(200, _page("Klassen-Drop · Admin", form + "".join(rows)))


def _detail(h, user: str, code: str, extra: str = "") -> None:
    cls = h._cls(code) if _exists(h, code) else None
    if cls is None and _exists(h, code):
        cls = {"label": code}
    if cls is None:
        return h._not_found()
    csrf = _csrf(h, user)
    items = []
    for it in h.store.list_items(code, include_hidden=True):
        t = time.strftime("%d.%m. %H:%M", time.localtime(it["created_at"]))
        hid = it.get("hidden")
        items.append(
            f"<div class=card><b>{_E(it['name'])}</b> – {_E(it['filename'])} "
            f"<span class=mut>{t} · {it['size'] / 1e6:.1f} MB{' · versteckt' if hid else ''}</span><br>"
            + _btn(csrf, "unhide" if hid else "hide", "Zeigen" if hid else "Verstecken", code=code, id=it["id"])
            + " " + _btn(csrf, "delete-item", "Löschen", code=code, id=it["id"]) + "</div>")
    head = (f"<div class=card>{extra}<p>Abgabe-Link: <b>{h.cfg.base_url}/{code}</b></p>"
            + f"<a href='{BASE}/{code}/export.zip'>ZIP-Export</a> · <a href='{BASE}'>alle Klassen</a>"
            + "<br>" + _btn(csrf, "delete-class", "Klasse komplett löschen", code=code) + "</div>"
            + _gallery_card(h, csrf, code))
    h._send(200, _page(f"Klasse {cls['label']}", head + "".join(items)))


def _do(h, user: str, act: str, f: dict) -> None:
    st = h.store
    if act == "create":
        days = int(f.get("days") or 30)
        if not 1 <= days <= 365:
            raise ValueError("Tage 1–365")
        code, pw = st.create_class(f.get("label", "").strip()[:60] or "Klasse",
                                   code=(f.get("code") or "").strip().lower() or None,
                                   password=(f.get("password") or "").strip() or None, days=days)
        token = st.set_gallery(code, (f.get("gallery") or "").strip().lower() or None)
        st.event("admin-create", code)
        return _detail(h, user, code, _once(h, code, pw, token))
    code = f.get("code", "")
    if not _exists(h, code):
        raise KeyError("Klasse unbekannt")
    if act in ("rotate", "gallery"):
        raw = (f.get("days") or "").strip()
        days = int(raw) if raw else None
        st.set_gallery(code, (f.get("gallery") or "").strip().lower() or None, days)
        return h._redirect(f"{BASE}/{code}")
    if act == "gallery-off":
        st.disable_gallery(code)  # items stay; only the link stops working
        return h._redirect(f"{BASE}/{code}")
    if act == "delete-class":
        st.delete_class(code)
        return h._redirect(BASE)
    iid = f.get("id", "")
    if act in ("hide", "unhide"):
        st.set_hidden(code, iid, act == "hide")
    elif act == "delete-item":
        st.delete_item(code, iid)
    h._redirect(f"{BASE}/{code}")


def _once(h, code: str, pw: str | None, token: str) -> str:
    pw_line = f"<p>Passwort: <b>{_E(pw)}</b></p>" if pw else "<p>Passwort: unverändert</p>"
    return (f"<p class=ok>Passwort nur jetzt sichtbar – bitte notieren.</p>{pw_line}"
            f"<p>Galerie-Link: <b>{h.cfg.base_url}/g/{_E(token)}</b></p>")


def _gallery_card(h, csrf: str, code: str) -> str:
    info = h.store.gallery_info(code)
    if info:
        until = ("bis Klassenende" if info["expires_at"] is None else
                 "bis " + time.strftime("%d.%m.%Y %H:%M", time.localtime(info["expires_at"])))
        state = (f"<p>Galerie: <b>{h.cfg.base_url}/g/{_E(info['slug'])}</b> "
                 f"<span class=mut>({until}, gleiches Passwort)</span></p>"
                 + _btn(csrf, "gallery-off", "Galerie-Link deaktivieren", code=code)
                 + "<p class=mut>Deaktivieren löscht keine Dateien.</p>")
    else:
        state = "<p>Galerie: <b>deaktiviert</b> <span class=mut>(Dateien bleiben erhalten)</span></p>"
    return (f"<div class=card>{state}"
            f"<form method=post action='{BASE}/gallery' autocomplete=off>"
            f"<input type=hidden name=csrf value='{_E(csrf)}'><input type=hidden name=code value='{code}'>"
            "<label>Neuer Galerie-Link /g/… (leer = zufällig)</label><input type=text name=gallery maxlength=24>"
            "<label>Gültig (Tage, leer = bis Klassenende)</label><input type=text name=days maxlength=4>"
            "<button type=submit>Galerie-Link setzen</button></form></div>")


def _zip(h, code: str) -> None:
    if not _exists(h, code):
        return h._not_found()
    tmpdir = os.path.join(h.store.state_dir, "tmp")
    os.makedirs(tmpdir, mode=0o700, exist_ok=True)
    with tempfile.TemporaryFile(dir=tmpdir) as fh:  # never the whole class in RAM
        with zipfile.ZipFile(fh, "w", zipfile.ZIP_STORED) as z:
            for it in h.store.list_items(code, include_hidden=True):
                meta, data = h.store.read_item(code, it["id"])
                stamp = time.strftime("%Y%m%d-%H%M", time.localtime(meta["created_at"]))
                who = re.sub(r"[^A-Za-z0-9._-]+", "_", meta["name"])[:40]
                z.writestr(f"{who}/{stamp}_{meta['id'][:6]}_{meta['filename']}", data)
                del data
        size = fh.tell()
        fh.seek(0)
        h.close_connection = True
        h.send_response(200)
        h._headers("application/zip", "default-src 'none'; sandbox")
        h.send_header("Content-Disposition", f'attachment; filename="klasse-{code}.zip"')
        h.send_header("Content-Length", str(size))
        h.end_headers()
        try:
            while chunk := fh.read(1 << 20):
                h.wfile.write(chunk)
        except OSError:
            pass

def _exists(h, code: str) -> bool:
    try:
        h.store.get_class(code)
        return True
    except (KeyError, ValueError):
        return False
