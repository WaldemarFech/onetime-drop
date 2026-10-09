"""HTML rendering (no templates engine, everything escaped)."""
from __future__ import annotations

import time
from html import escape as e

CSS = """
*{box-sizing:border-box}body{margin:0;font:17px/1.45 system-ui,-apple-system,"Segoe UI",
sans-serif;background:#f4f5f7;color:#111}main{max-width:620px;margin:0 auto;padding:24px 16px}
h1{font-size:1.3rem;margin:0 0 4px}h2{font-size:1.05rem;margin:26px 0 8px}
.sub{color:#666;font-size:.9rem;margin:0 0 18px}
.card{background:#fff;border-radius:14px;padding:18px;box-shadow:0 1px 3px #0002;margin-bottom:14px}
label{display:block;font-weight:600;margin:12px 0 4px;font-size:.95rem}
textarea,input,select{width:100%;font:16px/1.4 ui-monospace,monospace;padding:10px;
border:1px solid #bbb;border-radius:10px;background:#fff;color:inherit}
textarea{resize:vertical}input,select{font-family:inherit}
button{width:100%;margin-top:16px;padding:14px;font-size:1.05rem;font-weight:600;border:0;
border-radius:12px;background:#1a5fd6;color:#fff;cursor:pointer}button.ok{background:#16803c}
button.small{width:auto;margin:0;padding:6px 12px;font-size:.85rem;background:#b42318}
.warn{color:#8a5a00;font-size:.9rem;margin-top:12px}.muted{color:#777;font-size:.85rem}
table{width:100%;border-collapse:collapse;font-size:.88rem}td,th{text-align:left;padding:6px 4px;
border-bottom:1px solid #0001;vertical-align:top}th{color:#666;font-weight:600}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:.78rem;background:#e7eefc;
color:#1a4fb0}.tag.input{background:#e3f4e8;color:#16683a}.row{display:flex;gap:10px}
.row>*{flex:1}.url{word-break:break-all}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.card{background:#1d1f23}
textarea,input,select{background:#15171a;color:#eee;border-color:#444}.sub,.muted,th{color:#aaa}
td,th{border-color:#fff1}.tag{background:#22314f;color:#9cbcf5}.tag.input{background:#1d3a28;
color:#8fd6a7}}
"""

T = {
    "en": {
        "denied": "Access denied", "denied_text": "This page is restricted.",
        "invalid": "Link invalid", "invalid_text": "This link has expired or was already used.",
        "nothing": "Nothing to see here.", "bad_request": "Invalid request.",
        "bad_origin": "Invalid origin.", "bad_form": "Form expired, please reload the link.",
        "once_until": "One-time link · valid until {}", "form_until": "One-time form · valid until {}",
        "reveal_hint": "The secret is deleted as soon as it is shown and cannot be opened again.",
        "reveal_btn": "Show now", "save_btn": "Store securely",
        "once_note": "Can only be submitted once.", "empty": "Empty",
        "empty_text": "Please fill in at least one field. Go back and try again.",
        "saved": "Stored", "saved_text": "Thanks, the input was stored encrypted. "
                                           "This link is now used up.",
        "burned": "Deleted now · only visible on this page",
        "copy": "Copy", "copied": "Copied ✓", "gone_note": "Not retrievable after closing.",
        "decrypt_err": "Secret could not be decrypted.", "error": "Error",
        "admin": "One-time links", "signed_in": "Signed in as {}",
        "new_reveal": "Send a secret (reveal link)", "new_input": "Request input (input link)",
        "label": "Label", "secret": "Secret", "ttl": "Valid for", "fields": "Fields (comma)",
        "target": "Target name (optional)", "create": "Create link",
        "pending": "Pending links", "none": "None.", "kind": "Type", "expires": "Expires",
        "revoke": "Revoke", "outbox": "Submissions waiting for pull", "activity": "Recent activity",
        "created_title": "Link created", "created_note": "Shown only now - the link cannot be "
        "displayed again. Send it to the recipient.", "back": "Back",
        "reveal": "reveal", "input": "input", "action": "action", "when": "When", "event": "Event", "user": "User",
    },
    "de": {
        "denied": "Kein Zugriff", "denied_text": "Diese Seite ist geschützt.",
        "invalid": "Link ungültig",
        "invalid_text": "Dieser Link ist abgelaufen oder wurde bereits verwendet.",
        "nothing": "Nichts zu sehen.", "bad_request": "Ungültige Anfrage.",
        "bad_origin": "Ungültige Herkunft.", "bad_form": "Formular ungültig, bitte Link neu laden.",
        "once_until": "Einmal-Link · gültig bis {}", "form_until": "Einmal-Formular · gültig bis {}",
        "reveal_hint": "Das Geheimnis wird nach dem Anzeigen sofort gelöscht und kann nicht "
                       "erneut geöffnet werden.",
        "reveal_btn": "Jetzt anzeigen", "save_btn": "Sicher speichern",
        "once_note": "Kann nur einmal abgeschickt werden.", "empty": "Leer",
        "empty_text": "Bitte mindestens ein Feld ausfüllen. Zurück und erneut versuchen.",
        "saved": "Gespeichert", "saved_text": "Danke, die Eingabe wurde verschlüsselt abgelegt. "
                                               "Der Link ist jetzt verbraucht.",
        "burned": "Wurde jetzt gelöscht · nur noch auf dieser Seite sichtbar",
        "copy": "Kopieren", "copied": "Kopiert ✓", "gone_note": "Nach dem Schließen nicht mehr "
                                                              "abrufbar.",
        "decrypt_err": "Geheimnis konnte nicht entschlüsselt werden.", "error": "Fehler",
        "admin": "Einmal-Links", "signed_in": "Angemeldet als {}",
        "new_reveal": "Geheimnis senden (Reveal-Link)", "new_input": "Eingabe anfordern (Input-Link)",
        "label": "Bezeichnung", "secret": "Geheimnis", "ttl": "Gültig für",
        "fields": "Felder (Komma)", "target": "Zielname (optional)", "create": "Link erstellen",
        "pending": "Offene Links", "none": "Keine.", "kind": "Typ", "expires": "Läuft ab",
        "revoke": "Widerrufen", "outbox": "Eingänge (warten auf Abholung)",
        "activity": "Letzte Ereignisse", "created_title": "Link erstellt",
        "created_note": "Wird nur jetzt angezeigt - der Link kann nicht erneut angezeigt werden. "
                        "An den Empfänger schicken.", "back": "Zurück",
        "reveal": "reveal", "input": "input", "action": "Aktion", "when": "Wann", "event": "Ereignis", "user": "Nutzer",
    },
}

TTL_CHOICES = [("1h", "1 h"), ("24h", "24 h"), ("3d", "3 d"), ("7d", "7 d")]


def ts(t: float) -> str:
    return time.strftime("%d.%m. %H:%M UTC", time.gmtime(t))


def page(title: str, body: str, lang: str = "en") -> bytes:
    return (
        f"<!doctype html><html lang={lang}><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<meta name=robots content='noindex,nofollow'><title>{e(title)}</title>"
        f"<style>{CSS}</style></head><body><main>{body}</main></body></html>"
    ).encode("utf-8")


def message(s: dict, title_key: str, text_key: str, lang: str) -> bytes:
    return page(s[title_key], f"<h1>{e(s[title_key])}</h1><div class=card>{e(s[text_key])}</div>",
                lang)


def copy_script(nonce: str, s: dict) -> str:
    return (f"<script nonce='{nonce}'>document.querySelectorAll('[data-copy]').forEach(function(b)"
            "{b.onclick=function(){var t=document.getElementById(b.dataset.copy);function ok(){"
            f"b.textContent={s['copied']!r}}}function fb(){{t.select();document.execCommand('copy');"
            "ok()}if(navigator.clipboard){navigator.clipboard.writeText(t.value).then(ok,fb)}"
            "else{fb()}}})</script>")


def reveal_confirm(s, item, csrf, lang) -> bytes:
    return page(item.label, (
        f"<h1>{e(item.label)}</h1><p class=sub>{e(s['once_until'].format(ts(item.expires)))}</p>"
        f"<form method=post class=card><input type=hidden name=csrf value='{csrf}'>"
        f"{e(s['reveal_hint'])}<button type=submit>{e(s['reveal_btn'])}</button></form>"), lang)


def input_form(s, item, csrf, lang) -> bytes:
    inputs = "".join(
        f"<label for=f{i}>{e(f)}</label><textarea id=f{i} name='f_{f}' rows=2 autocomplete=off "
        "autocapitalize=off autocorrect=off spellcheck=false></textarea>"
        for i, f in enumerate(item.fields))
    return page(item.label, (
        f"<h1>{e(item.label)}</h1><p class=sub>{e(s['form_until'].format(ts(item.expires)))}</p>"
        f"<form method=post class=card><input type=hidden name=csrf value='{csrf}'>{inputs}"
        f"<button type=submit class=ok>{e(s['save_btn'])}</button>"
        f"<p class=warn>{e(s['once_note'])}</p></form>"), lang)


def revealed(s, label, secret, nonce, lang) -> bytes:
    return page(label, (
        f"<h1>{e(label)}</h1><p class=sub>{e(s['burned'])}</p>"
        f"<div class=card><textarea id=s rows=4 readonly>{e(secret)}</textarea>"
        f"<button type=button class=ok data-copy=s>{e(s['copy'])}</button>"
        f"<p class=warn>{e(s['gone_note'])}</p></div>{copy_script(nonce, s)}"), lang)


def created(s, url, label, nonce, lang) -> bytes:
    return page(s["created_title"], (
        f"<h1>{e(s['created_title'])}</h1><p class=sub>{e(label)}</p><div class=card>"
        f"<textarea id=u rows=3 readonly class=url>{e(url)}</textarea>"
        f"<button type=button class=ok data-copy=u>{e(s['copy'])}</button>"
        f"<p class=warn>{e(s['created_note'])}</p></div>"
        f"<p><a href='/admin'>{e(s['back'])}</a></p>{copy_script(nonce, s)}"), lang)


def _ttl_select(default_ttl: int, max_ttl: int) -> str:
    secs = {"1h": 3600, "24h": 86400, "3d": 259200, "7d": 604800}
    opts = "".join(
        f"<option value={v}{' selected' if secs[v] == default_ttl else ''}>{lbl}</option>"
        for v, lbl in TTL_CHOICES if secs[v] <= max_ttl)
    return f"<select name=ttl>{opts}</select>"


def admin(s, user, csrf, pending, outbox, events, default_ttl, max_ttl, lang) -> bytes:
    hid = f"<input type=hidden name=csrf value='{csrf}'>"
    ttl = _ttl_select(default_ttl, max_ttl)
    rows = "".join(
        f"<tr><td><span class='tag {e(i.kind)}'>{e(s[i.kind])}</span></td><td>{e(i.label)}"
        f"{'<br><span class=muted>→ ' + e(i.target) + '</span>' if i.target else ''}</td>"
        f"<td>{ts(i.expires)}</td><td><form method=post action='/admin/revoke'>{hid}"
        f"<input type=hidden name=id value='{i.id}'><button class=small>{e(s['revoke'])}"
        "</button></form></td></tr>" for i in pending)
    pend = (f"<table><tr><th>{e(s['kind'])}</th><th>{e(s['label'])}</th><th>{e(s['expires'])}"
            f"</th><th></th></tr>{rows}</table>") if pending else e(s["none"])
    ob = "".join(f"<tr><td>{e(o['label'])}</td><td>{e(o.get('target', ''))}</td>"
                 f"<td>{e(o['submitted'])}</td></tr>" for o in outbox)
    obx = f"<table>{ob}</table>" if outbox else e(s["none"])
    ev = "".join(f"<tr><td class=muted>{e(x.get('ts', ''))}</td><td>{e(x.get('event', ''))}</td>"
                 f"<td>{e(x.get('label', ''))}</td><td>{e(x.get('user', ''))}</td></tr>"
                 for x in events)
    evx = (f"<table><tr><th>{e(s['when'])}</th><th>{e(s['event'])}</th><th>{e(s['label'])}</th>"
           f"<th>{e(s['user'])}</th></tr>{ev}</table>") if events else e(s["none"])
    body = (
        f"<h1>{e(s['admin'])}</h1><p class=sub>{e(s['signed_in'].format(user))}</p>"
        f"<h2>{e(s['new_reveal'])}</h2><form method=post action='/admin/reveal' class=card>{hid}"
        f"<label>{e(s['label'])}</label><input name=label maxlength=100 required>"
        f"<label>{e(s['secret'])}</label><textarea name=secret rows=3 required autocomplete=off "
        "autocapitalize=off autocorrect=off spellcheck=false></textarea>"
        f"<label>{e(s['ttl'])}</label>{ttl}<button type=submit>{e(s['create'])}</button></form>"
        f"<h2>{e(s['new_input'])}</h2><form method=post action='/admin/input' class=card>{hid}"
        f"<label>{e(s['label'])}</label><input name=label maxlength=100 required>"
        f"<div class=row><div><label>{e(s['fields'])}</label><input name=fields value='value' "
        f"required></div><div><label>{e(s['ttl'])}</label>{ttl}</div></div>"
        f"<label>{e(s['target'])}</label><input name=target maxlength=60 "
        "pattern='[A-Za-z0-9][A-Za-z0-9._-]{0,59}'>"
        f"<button type=submit class=ok>{e(s['create'])}</button></form>"
        f"<h2>{e(s['pending'])}</h2><div class=card>{pend}</div>"
        f"<h2>{e(s['outbox'])}</h2><div class=card>{obx}</div>"
        f"<h2>{e(s['activity'])}</h2><div class=card>{evx}</div>")
    return page(s["admin"], body, lang)
