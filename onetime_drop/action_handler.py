"""HTTP handling for action links (/a/<token>). Only admin_users may view or run actions.

GET  pending -> review page (recipe, params, exact steps, secret inputs, Run)
     used    -> stored result (status + redacted log)
POST         -> CSRF check, atomic claim (burn), run over ssh, stream output live
"""
from __future__ import annotations

import secrets
import shlex
import time

from . import action_pages, recipes
from .actions import Redactor, RunResult, _env, run, ssh_argv


def _recipe_and_params(cfg, item):
    recipe = recipes.get(item.recipe)
    return recipe, recipes.validate_params(recipe, item.params, cfg)


def _known_hosts(store, recipe_id: str):
    d = store.root / "actions"
    d.mkdir(mode=0o700, exist_ok=True)
    return d / f"known_hosts-{recipe_id}"


def handle_get(h, user: str, token: str) -> None:
    cfg, store = h.cfg, h.cfg.store
    if user not in cfg.admin_users:
        return h._msg(404, "nothing", "nothing")
    item = store.peek(token)
    if item is not None:
        if item.kind != "action":
            return h._msg(410, "invalid", "invalid_text")
        try:
            recipe, params = _recipe_and_params(cfg, item)
        except ValueError:
            store.audit("denied", item.id, reason="recipe")
            return h._msg(410, "invalid", "invalid_text")
        store.audit("action_viewed", item.id, recipe=recipe.id, label=item.label, user=user)
        plan = recipe.build_plan(params, {}, recipe.placeholders)
        cmd = " ".join(shlex.quote(x) for x in ssh_argv(
            ["ssh"], plan, _known_hosts(store, recipe.id))) + " < (steps below)"
        steps = recipe.steps(params, recipe.placeholders)
        body = action_pages.action_form(cfg.lang, item, recipe, store.csrf_for(item.id, user),
                                        steps, cmd, recipe.facts(params))
        return h._send(200, body)
    rec = store.result_for_token(token)
    if rec is None:
        return h._msg(410, "invalid", "invalid_text")
    store.audit("action_viewed", rec["id"], recipe=rec.get("recipe"), label=rec.get("label"),
                user=user, state="result")
    h._send(200, action_pages.action_result(cfg.lang, rec, recipes.REGISTRY.get(rec["recipe"])))


def handle_post(h, user: str, token: str, form: dict) -> None:
    cfg, store = h.cfg, h.cfg.store
    if user not in cfg.admin_users:
        return h._msg(404, "nothing", "nothing")
    item = store.peek(token)
    if item is None or item.kind != "action":
        return h._msg(410, "invalid", "invalid_text")
    if not store.csrf_ok(item.id, user, form.get("csrf", "")):
        store.audit("denied", item.id, reason="csrf")
        return h._msg(403, "denied", "bad_form")
    try:
        recipe, params = _recipe_and_params(cfg, item)
    except ValueError:
        store.audit("denied", item.id, reason="recipe")
        return h._msg(410, "invalid", "invalid_text")
    secret_vals = {}
    for sec in recipe.secrets:
        v = form.get(f"s_{sec.name}", "")
        if not v or len(v) > sec.max_len or any(c in v for c in "\r\n\0"):
            form.clear()
            return h._msg(400, "empty", "empty_text")
        secret_vals[sec.name] = v
    options = {o.name: form.get(f"o_{o.name}") == "1" for o in recipe.options}
    form.clear()
    claimed = store.claim(token)  # atomic single use: the link burns here
    if claimed is None:
        secret_vals.clear()
        return h._msg(410, "invalid", "invalid_text")
    _run(h, user, claimed, recipe, params, options, secret_vals)


def _run(h, user, item, recipe, params, options, secret_vals) -> None:
    cfg, store = h.cfg, h.cfg.store
    store.audit("action_run", item.id, recipe=recipe.id, label=item.label, user=user,
                options=",".join(k for k, v in sorted(options.items()) if v))
    store.result_put(item, "running", [], user=user, started=time.time())
    store.finish(item)
    generated = recipe.generate(options)
    plan = recipe.build_plan(params, options, generated)
    redact = Redactor(list(secret_vals.values()) +
                      [v for v in generated.values() if len(v) >= 8])
    argv = ssh_argv(cfg.ssh_command, plan, _known_hosts(store, recipe.id))
    env = _env(store.root, cfg.askpass, secret_vals[recipe.secrets[0].name])
    secret_vals.clear()
    nonce = secrets.token_urlsafe(16)
    h._stream_start(nonce)
    h._swrite(action_pages.stream_start(cfg.lang, item, recipe, nonce))
    result = RunResult()
    try:
        for line in run(argv, plan.script, env, min(recipe.timeout, cfg.action_timeout),
                        redact, result):
            h._swrite(action_pages.stream_line(line))
    except OSError as exc:  # ssh missing, fork failure, ...
        msg = f"ERROR: could not run ssh ({type(exc).__name__})"
        result.lines.append(msg)
        h._swrite(action_pages.stream_line(msg))
    finally:
        env.clear()
    outcome = recipe.evaluate(params, options, result.lines, result.rc, result.timed_out)
    status = "timeout" if result.timed_out else ("ok" if outcome.get("ok") else "failed")
    new_pw = generated.get("new_password", "") if outcome.get("reveal_new_password") else ""
    store.result_put(item, status, result.lines, user=user, started=result.started,
                     finished=result.finished, rc=result.rc, verified=outcome.get("verified"),
                     password_state=outcome.get("password_state"))
    delivered = h._swrite(action_pages.stream_end(cfg.lang, status, result.rc, outcome, new_pw,
                                                  nonce))
    store.audit("action_result", item.id, recipe=recipe.id, label=item.label, user=user,
                status=status, rc=result.rc, verified=outcome.get("verified"),
                password_state=outcome.get("password_state"),
                new_password_delivered=delivered if new_pw else None,
                seconds=round((result.finished or time.time()) - result.started, 1))
    # drop every reference to secrets (Python strings cannot be zeroed in place)
    new_pw = ""
    generated.clear()
    redact.clear()
