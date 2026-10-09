"""HTML for action links: review/run form, live output stream, stored result."""
from __future__ import annotations

from html import escape as e

from .pages import CSS, copy_script, ts

TERM_CSS = """
pre.term{background:#0d1117;color:#d1d7e0;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,
monospace;padding:12px;border-radius:10px;overflow-x:auto;white-space:pre-wrap;
word-break:break-word;margin:8px 0 0}pre.term.s{max-height:none}
.kv td:first-child{color:#777;white-space:nowrap;width:1%}.code{word-break:break-all}
.st{display:inline-block;padding:2px 10px;border-radius:99px;font-weight:600;font-size:.85rem}
.st.ok{background:#e3f4e8;color:#16683a}.st.fail{background:#fde7e7;color:#a11}
.st.run{background:#fff3d6;color:#8a5a00}.chk{display:flex;gap:10px;align-items:flex-start;
margin-top:14px;font-weight:600}.chk input{width:auto;margin-top:4px}
.danger{border:2px solid #b42318}details summary{cursor:pointer;color:#1a5fd6}
@media (prefers-color-scheme:dark){.st.ok{background:#1d3a28;color:#8fd6a7}
.st.fail{background:#4a1d1d;color:#f5a3a3}.st.run{background:#3d300f;color:#f0c870}}
"""

A = {
    "en": {
        "action_until": "One-time action · valid until {}", "target": "Target",
        "params": "Parameters", "steps": "Exactly these steps will run",
        "local_cmd": "Local command (password via SSH_ASKPASS, never on the command line)",
        "secrets": "Your input (used for this single run only, never stored)",
        "run": "Run now", "run_note": "Runs once. The link is burned when you press Run; the "
        "output is kept (redacted) on this page.", "output": "Output", "status": "Status",
        "ok": "success", "failed": "failed", "timeout": "timeout", "running": "running",
        "exit": "exit code", "fp": "Expected key fingerprint",
        "newpw": "New root password - shown ONCE", "newpw_warn": "Store it in your password "
        "manager now. It is not saved anywhere and cannot be shown again.",
        "newpw_unknown": "The password change MAY have happened (run was interrupted). Keep "
        "this password in case it did.", "copy": "Copy", "copied": "Copied ✓",
        "done_note": "This link is used up. Reloading shows the stored (redacted) log.",
        "option_on": "only if the checkbox is ticked", "user": "Run by", "when": "Started",
        "missing": "Please fill in all fields.", "recipe": "Recipe",
    },
    "de": {
        "action_until": "Einmal-Aktion · gültig bis {}", "target": "Ziel",
        "params": "Parameter", "steps": "Genau diese Schritte werden ausgeführt",
        "local_cmd": "Lokaler Befehl (Passwort via SSH_ASKPASS, nie auf der Kommandozeile)",
        "secrets": "Deine Eingabe (nur für diesen einen Lauf, wird nie gespeichert)",
        "run": "Jetzt ausführen", "run_note": "Läuft genau einmal. Der Link verbrennt beim "
        "Drücken; die Ausgabe bleibt (geschwärzt) auf dieser Seite.", "output": "Ausgabe",
        "status": "Status", "ok": "erfolgreich", "failed": "fehlgeschlagen",
        "timeout": "Zeitüberschreitung", "running": "läuft", "exit": "Exit-Code",
        "fp": "Erwarteter Key-Fingerprint",
        "newpw": "Neues Root-Passwort - wird nur EINMAL angezeigt",
        "newpw_warn": "Jetzt im Passwortmanager speichern. Es wird nirgends gespeichert und "
        "kann nicht erneut angezeigt werden.",
        "newpw_unknown": "Die Passwortänderung ist MÖGLICHERWEISE passiert (Lauf unterbrochen). "
        "Dieses Passwort für den Fall aufbewahren.", "copy": "Kopieren", "copied": "Kopiert ✓",
        "done_note": "Dieser Link ist verbraucht. Neu laden zeigt das gespeicherte "
        "(geschwärzte) Protokoll.", "option_on": "nur wenn das Häkchen gesetzt ist",
        "user": "Ausgeführt von", "when": "Gestartet", "missing": "Bitte alle Felder ausfüllen.",
        "recipe": "Rezept",
    },
}


def _head(title: str, lang: str) -> str:
    return (f"<!doctype html><html lang={lang}><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=robots content='noindex,nofollow'><title>{e(title)}</title>"
            f"<style>{CSS}{TERM_CSS}</style></head><body><main>")


def _params_table(a, recipe, params, user_host) -> str:
    rows = "".join(f"<tr><td>{e(p.label)}</td><td class=code>{e(params.get(p.name, ''))}</td>"
                   "</tr>" for p in recipe.params)
    return (f"<table class=kv><tr><td>{e(a['recipe'])}</td><td class=code>{e(recipe.id)}</td></tr>"
            f"<tr><td>{e(a['target'])}</td><td class=code>{e(user_host)}</td></tr>{rows}</table>")


def action_form(lang, item, recipe, csrf, steps, ssh_cmd, facts) -> bytes:
    a = A[lang]
    user, host = recipe.target(item.params)
    step_html = "".join(
        f"<h2>({e(st.key)}) {e(st.title)}"
        f"{' <span class=muted>– ' + e(a['option_on']) + '</span>' if st.option else ''}</h2>"
        f"<pre class=term>{e(st.script)}</pre>" for st in steps)
    secret_inputs = "".join(
        f"<label for=s{i}>{e(sec.label)}</label><input id=s{i} type=password "
        f"name='s_{e(sec.name)}' maxlength={sec.max_len} required autocomplete=off "
        "autocapitalize=off autocorrect=off spellcheck=false>"
        for i, sec in enumerate(recipe.secrets))
    opts = "".join(
        f"<label class=chk><input type=checkbox name='o_{e(o.name)}' value=1"
        f"{' checked' if o.default else ''}><span>{e(o.label)}</span></label>"
        for o in recipe.options)
    body = (
        f"<h1>{e(recipe.title)}</h1><p class=sub>{e(item.label)} · "
        f"{e(a['action_until'].format(ts(item.expires)))}</p>"
        f"<div class=card>{e(recipe.description)}"
        f"{_params_table(a, recipe, item.params, f'{user}@{host}')}"
        + "".join(f"<p class=muted>{e(k)}: <span class=code>{e(v)}</span></p>" for k, v in facts)
        + "</div>"
        f"<div class=card><b>{e(a['local_cmd'])}</b><pre class=term>{e(ssh_cmd)}</pre>"
        f"<h2>{e(a['steps'])}</h2>{step_html}</div>"
        f"<form method=post class='card danger' autocomplete=off>"
        f"<input type=hidden name=csrf value='{csrf}'><b>{e(a['secrets'])}</b>{secret_inputs}"
        f"{opts}<button type=submit>{e(a['run'])}</button>"
        f"<p class=warn>{e(a['run_note'])}</p></form>")
    return (_head(recipe.title, lang) + body + "</main></body></html>").encode("utf-8")


def stream_start(lang, item, recipe, nonce) -> bytes:
    a = A[lang]
    user, host = recipe.target(item.params)
    pad = "<!--" + " " * 2048 + "-->"  # some mobile browsers render only after ~1-2 KiB
    return (_head(recipe.title, lang) + pad +
            f"<h1>{e(recipe.title)}</h1><p class=sub>{e(item.label)} · {e(user)}@{e(host)}</p>"
            f"<div class=card><b>{e(a['output'])}</b> <span class='st run'>{e(a['running'])}"
            "</span><pre class=term id=out>"
            f"<script nonce='{nonce}'>var iv=setInterval(function(){{window.scrollTo(0,"
            "document.body.scrollHeight)}},400)</script>").encode("utf-8")


def stream_line(line: str) -> bytes:
    return (e(line) + "\n").encode("utf-8")


def _status(a, status) -> str:
    cls = {"ok": "ok", "running": "run"}.get(status, "fail")
    return f"<span class='st {cls}'>{e(a.get(status, status))}</span>"


def stream_end(lang, status, rc, outcome, new_password, nonce) -> bytes:
    a = A[lang]
    out = (f"</pre><p>{e(a['status'])}: {_status(a, status)} · {e(a['exit'])}: "
           f"{e(str(rc))}</p></div>")
    if new_password:
        warn = a["newpw_warn"] if outcome.get("password_state") == "changed" \
            else a["newpw_unknown"] + " " + a["newpw_warn"]
        out += (f"<div class='card danger'><b>{e(a['newpw'])}</b>"
                f"<textarea id=npw rows=1 readonly class=code>{e(new_password)}</textarea>"
                f"<button type=button class=ok data-copy=npw>{e(a['copy'])}</button>"
                f"<p class=warn>{e(warn)}</p></div>")
    out += (f"<p class=muted>{e(a['done_note'])}</p>"
            f"<script nonce='{nonce}'>clearInterval(iv)</script>"
            f"{copy_script(nonce, {'copied': a['copied']})}</main></body></html>")
    return out.encode("utf-8")


def action_result(lang, rec: dict, recipe) -> bytes:
    a = A[lang]
    title = recipe.title if recipe else rec.get("recipe", "")
    started = rec.get("started")
    meta = (f"<p>{e(a['status'])}: {_status(a, rec.get('status', ''))} · {e(a['exit'])}: "
            f"{e(str(rec.get('rc')))}</p><p class=muted>{e(a['user'])}: {e(rec.get('user', ''))}"
            f" · {e(a['when'])}: {e(ts(started) if started else '-')}</p>")
    log = "\n".join(rec.get("lines", []))
    body = (f"<h1>{e(title)}</h1><p class=sub>{e(rec.get('label', ''))}</p>"
            f"<div class=card>{meta}<b>{e(a['output'])}</b><pre class=term>{e(log)}</pre></div>"
            f"<p class=muted>{e(a['done_note'])}</p>")
    return (_head(title, lang) + body + "</main></body></html>").encode("utf-8")
