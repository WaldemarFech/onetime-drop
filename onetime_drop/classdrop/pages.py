"""HTML for the public class-drop pages (mobile-first, no JS, strict CSP)."""
from __future__ import annotations

import base64
import hashlib
import html
import time

STYLE = (
    ":root{--fg:#1d1d1f;--mut:#6b6b70;--bg:#f6f6f8;--card:#fff;--acc:#2f6fed;--err:#c0262d;--ok:#1a7f37}"
    "@media(prefers-color-scheme:dark){:root{--fg:#ececf0;--mut:#a0a0a8;--bg:#121214;--card:#1e1e22;"
    "--acc:#6f9bff;--err:#ff6b6b;--ok:#4cc26a}}"
    "*{box-sizing:border-box}body{font-family:system-ui,sans-serif;margin:0;padding:1rem;"
    "background:var(--bg);color:var(--fg);line-height:1.45}main{max-width:40rem;margin:0 auto}"
    "h1{font-size:1.4rem;margin:.5rem 0 1rem}.card{background:var(--card);border-radius:14px;"
    "padding:1rem;margin:0 0 1rem;box-shadow:0 1px 3px #0002}label{display:block;font-weight:600;"
    "margin:.6rem 0 .3rem}input[type=text],input[type=password]{width:100%;font-size:1.1rem;"
    "padding:.7rem;border:1px solid #8885;border-radius:10px;background:var(--bg);color:var(--fg)}"
    "input[type=file]{width:100%;font-size:1rem;padding:1.2rem .6rem;border:2px dashed #8887;"
    "border-radius:12px;background:var(--bg);color:var(--fg)}"
    "button{width:100%;font-size:1.1rem;padding:.8rem;margin-top:1rem;border:0;border-radius:10px;"
    "background:var(--acc);color:#fff;font-weight:600}.mut{color:var(--mut);font-size:.9rem}"
    ".err{color:var(--err);font-weight:600}.ok{color:var(--ok);font-weight:600}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.6rem}"
    ".it{background:var(--card);border-radius:12px;overflow:hidden;box-shadow:0 1px 3px #0002;"
    "text-decoration:none;color:var(--fg);display:block}.it img{width:100%;aspect-ratio:1;"
    "object-fit:cover;display:block;background:#8882}.ic{aspect-ratio:1;display:flex;"
    "align-items:center;justify-content:center;font-size:2.2rem;font-weight:700;background:#8882}"
    ".cap{padding:.4rem .5rem;font-size:.8rem;overflow-wrap:anywhere}.cap b{display:block}"
    "form.in{display:inline}.in button{width:auto;padding:.45rem .9rem;margin:.5rem .4rem 0 0;"
    "font-size:.9rem}.in button.danger{background:var(--err)}a{color:var(--acc)}.big{font-size:1.25rem;font-weight:700}"
)
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
CSP = (f"default-src 'none'; style-src 'sha256-{STYLE_HASH}'; img-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")

T = {
    "nf": "Nicht gefunden.",
    "slow": "Zu viele Versuche. Bitte in ein paar Minuten erneut probieren.",
    "pw": "Klassen-Passwort", "open": "Weiter", "wrong": "Falsches Passwort.",
    "up_title": "Dateien abgeben", "name": "Dein Name",
    "files": "Bilder oder Dokumente (Foto, PDF, Word, PowerPoint)", "send": "Hochladen",
    "done": "Danke! {n} Datei(en) angekommen.", "more": "Weitere Dateien abgeben",
    "gal_title": "Galerie", "empty": "Noch nichts hochgeladen.",
}

_ESC = html.escape


def page(title: str, body: str) -> bytes:
    return ("<!doctype html><html lang=de><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<meta name=robots content='noindex,nofollow'>"
            f"<title>{_ESC(title)}</title><style>{STYLE}</style></head><body><main>"
            f"<h1>{_ESC(title)}</h1>{body}</main></body></html>").encode("utf-8")


def message(text: str, cls: str = "") -> bytes:
    return page("Drop", f"<div class=card><p class='{cls}'>{_ESC(text)}</p></div>")


def password_form(action: str, title: str, error: str = "") -> bytes:
    err = f"<p class=err>{_ESC(error)}</p>" if error else ""
    return page(title, (
        f"<form class=card method=post action='{_ESC(action)}' autocomplete=off>{err}"
        f"<label for=p>{T['pw']}</label>"
        "<input id=p type=password name=password maxlength=64 required autofocus "
        "autocapitalize=off autocorrect=off spellcheck=false>"
        f"<button type=submit>{T['open']}</button></form>"))


def upload_form(code: str, label: str, csrf: str, cfg, error: str = "", ok: str = "",
                gal: dict | None = None) -> bytes:
    note = (f"<p class=err>{_ESC(error)}</p>" if error else "") + \
           (f"<p class=ok>{_ESC(ok)}</p>" if ok else "")
    return page(f"{T['up_title']} – {label}", (
        f"<form class=card method=post action='/{code}/upload' enctype=multipart/form-data "
        f"autocomplete=off>{note}<input type=hidden name=csrf value='{_ESC(csrf)}'>"
        f"<label for=n>{T['name']}</label>"
        "<input id=n type=text name=name maxlength=60 required autocomplete=name>"
        f"<label for=f>{T['files']}</label>"
        "<input id=f type=file name=files multiple required "
        "accept='image/*,.heic,.pdf,.docx,.pptx,.xlsx'>"
        f"<p class=mut>Max. {cfg.max_files} Dateien, je {cfg.max_file_mb} MB.</p>"
        f"<button type=submit>{T['send']}</button></form>" + _gal_box(cfg, gal)))


def _gal_box(cfg, gal: dict | None) -> str:
    if not gal:
        return ""
    url = f"{cfg.base_url}/g/{gal['slug']}"
    short = url.split("://", 1)[-1]
    return (f"<div class=card><b>Galerie der Klasse</b><p class=mut>Alle Abgaben ansehen – "
            f"gleiches Passwort:</p><p><a class=big href='/g/{_ESC(gal['slug'])}'>{_ESC(short)}</a></p></div>")


def _ago(ts: float) -> str:
    return time.strftime("%d.%m. %H:%M", time.localtime(ts))


def gallery(token: str, label: str, items: list[dict]) -> bytes:
    if not items:
        return page(f"{T['gal_title']} – {label}", f"<div class=card><p>{T['empty']}</p></div>")
    cells = []
    for it in items:
        iid = it["id"]
        if it.get("thumb_size"):
            pic = f"<img src='/g/{token}/t/{iid}' alt='' loading=lazy>"
        else:
            ext = (it.get("filename", "").rsplit(".", 1)[-1] or "?")[:4].upper()
            pic = f"<div class=ic>{_ESC(ext)}</div>"
        cells.append(f"<a class=it href='/g/{token}/f/{iid}'>{pic}<div class=cap>"
                     f"<b>{_ESC(it['name'])}</b>{_ESC(it['filename'])}<br>"
                     f"<span class=mut>{_ago(it['created_at'])}</span></div></a>")
    return page(f"{T['gal_title']} – {label}",
                f"<p class=mut>{len(items)} Dateien</p><div class=grid>{''.join(cells)}</div>")
