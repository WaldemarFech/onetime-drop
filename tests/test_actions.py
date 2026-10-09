"""Action links: recipe validation, single use, CSRF, secret handling, timeout, redaction."""
import json
import re
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest
from conftest import ORIGIN, csrf_of, make_config, req

from onetime_drop import cli, recipes
from onetime_drop.actions import REDACTED, Redactor
from onetime_drop.recipes.cerbo_install_key import fingerprint
from onetime_drop.server import make_server

FAKE = str(Path(__file__).with_name("fake_ssh.py"))
KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGA5viaeuy2McO6B/VES6aIXh6F18p0Qgmrv2bVGpPqN "
       "my-laptop-cerbo")
PW = "Corr3ct-H0rse_battery"
GOOD = {"host": "10.0.0.30", "pubkey": KEY, "tag": "my-laptop-cerbo"}
RECIPE = recipes.get("cerbo-install-key")


@pytest.fixture()
def aenv(tmp_path):
    beh = tmp_path / "behavior.json"
    rec = tmp_path / "record.json"

    def behave(**kw):
        beh.write_text(json.dumps({"expect": PW, "record": str(rec), **kw}))

    behave()
    cfg = make_config(tmp_path, action_networks=["10.0.0.0/24"],
                      ssh_command=[sys.executable, FAKE, str(beh)])
    srv = make_server(cfg, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ns = type("A", (), {})()
    ns.cfg, ns.store, ns.port, ns.behave, ns.record, ns.tmp = (
        cfg, cfg.store, srv.server_address[1], behave, rec, tmp_path)
    yield ns
    srv.shutdown()
    srv.server_close()


def new_link(a, **over):
    params = recipes.validate_params(RECIPE, {**GOOD, **over}, a.cfg)
    return a.store.create_action("Cerbo key", RECIPE.id, params, 3600, "cli")


def run_link(a, tok, pw=PW, reset=True, user="alice"):
    _, page, _ = req(a.port, "GET", f"/a/{tok}", user=user)
    form = {"csrf": csrf_of(page), "s_password": pw}
    if reset:
        form["o_reset_password"] = "1"
    return req(a.port, "POST", f"/a/{tok}", user=user, form=form, headers={"Origin": ORIGIN})


def new_pw_of(html):
    m = re.search(r"<textarea id=npw[^>]*>([^<]+)</textarea>", html)
    return m.group(1) if m else None


def all_data_bytes(a) -> bytes:
    return b"".join(p.read_bytes() for p in a.store.root.rglob("*") if p.is_file())


# --- validation --------------------------------------------------------------

@pytest.mark.parametrize("over", [
    {"host": "10.0.1.30"},                       # outside allowed network
    {"host": "8.8.8.8"},
    {"host": "10.0.0.30; reboot"},
    {"host": "10.0.0.30 -oProxyCommand=sh"},
    {"host": "-oProxyCommand=touch /tmp/x"},
    {"host": "cerbo.local"},
    {"host": "10.000.000.030"},
    {"pubkey": KEY + "\nssh-ed25519 AAAA evil"},     # two lines
    {"pubkey": KEY.replace("my-laptop-cerbo", "$(reboot)")},
    {"pubkey": KEY.replace("my-laptop-cerbo", "x';reboot;'")},
    {"pubkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ x"},
    {"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGA5viaeuy2McO6B/VES6aIXh6F18p0Qgmrv2bVGpPqNAA"},
    {"pubkey": 'command="sh" ' + KEY},
    {"tag": "x;reboot"},
    {"tag": "$(id)"},
    {"tag": ""},
])
def test_params_reject_injection(aenv, over):
    with pytest.raises(ValueError):
        recipes.validate_params(RECIPE, {**GOOD, **over}, aenv.cfg)


def test_params_unknown_missing_and_recipe(aenv):
    with pytest.raises(ValueError):
        recipes.validate_params(RECIPE, {**GOOD, "cmd": "id"}, aenv.cfg)
    with pytest.raises(ValueError):
        recipes.validate_params(RECIPE, {"host": "10.0.0.30"}, aenv.cfg)
    with pytest.raises(ValueError):
        recipes.get("shell")
    assert recipes.validate_params(RECIPE, GOOD, aenv.cfg) == GOOD
    no_nets = make_config(aenv.tmp)
    with pytest.raises(ValueError):  # default: no networks allowed
        recipes.validate_params(RECIPE, GOOD, no_nets)


def test_cli_create_action(aenv, capsys, tmp_path):
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(
        f'base_url = "{ORIGIN}"\ndata_dir = "{aenv.store.root.as_posix()}"\n'
        f'key_file = "{(tmp_path / "key").as_posix()}"\nproxy_secret = "{"x" * 48}"\n'
        'allowed_proxies = ["127.0.0.1"]\nallowed_users = ["alice"]\n'
        'action_networks = ["10.0.0.0/24"]\n')
    args = ["--config", str(cfgfile), "create-action", "--recipe", "cerbo-install-key",
            "--param", "host=10.0.0.30", "--param", f"pubkey={KEY}",
            "--param", "tag=my-laptop-cerbo", "--ttl", "6h", "--label", "Cerbo"]
    assert cli.main(args) == 0
    url = capsys.readouterr().out.strip()
    assert re.fullmatch(re.escape(ORIGIN) + r"/a/[A-Za-z0-9_-]{43}", url)
    assert cli.main(args[:6] + ["host=10.0.1.1"] + args[7:]) == 2
    assert cli.main(args + ["--param", "x=1"]) == 2
    events = [json.loads(x)["event"] for x in aenv.store.audit_path.read_text().splitlines()]
    assert events.count("action_created") == 1


# --- page, access, csrf -----------------------------------------------------

def test_review_page_shows_steps_and_does_not_burn(aenv):
    tok = new_link(aenv)
    st, page, r = req(aenv.port, "GET", f"/a/{tok}")
    assert st == 200 and r.getheader("Cache-Control").startswith("no-store")
    assert "10.0.0.30" in page and fingerprint(KEY) in page
    assert "readlink -f" in page and "chpasswd" in page and "(d)" in page
    assert re.search(r"type=password name='s_password'[^>]*autocomplete=off", page)
    assert re.search(r"name='o_reset_password' value=1 checked", page)
    assert "StrictHostKeyChecking=accept-new" in page
    assert req(aenv.port, "GET", f"/a/{tok}")[0] == 200  # still pending
    assert req(aenv.port, "GET", f"/a/{tok}", user="bob")[0] == 404  # not an admin
    assert req(aenv.port, "GET", f"/a/{tok}", user="mallory")[0] == 403
    assert req(aenv.port, "GET", f"/r/{tok}")[0] == 410  # kind is bound to the route


def test_post_requires_csrf_origin_and_password(aenv):
    tok = new_link(aenv)
    _, page, _ = req(aenv.port, "GET", f"/a/{tok}")
    form = {"csrf": csrf_of(page), "s_password": PW}
    assert req(aenv.port, "POST", f"/a/{tok}", form={**form, "csrf": "0" * 64})[0] == 403
    assert req(aenv.port, "POST", f"/a/{tok}", form=form,
               headers={"Origin": "https://evil.example"})[0] == 403
    assert req(aenv.port, "POST", f"/a/{tok}", form=form,
               headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert req(aenv.port, "POST", f"/a/{tok}", user="bob", form=form)[0] == 404
    assert req(aenv.port, "POST", f"/a/{tok}", form={**form, "s_password": ""})[0] == 400
    assert req(aenv.port, "POST", f"/a/{tok}",
               form={**form, "s_password": "a\nb"})[0] == 400
    assert not aenv.record.exists()  # nothing ran
    assert req(aenv.port, "GET", f"/a/{tok}")[0] == 200  # still pending


# --- run --------------------------------------------------------------------

def test_run_once_secret_never_persisted_new_password_shown_once(aenv):
    tok = new_link(aenv)
    st, out, _ = run_link(aenv, tok)
    assert st == 200
    assert "KEY_VERIFIED" in out and "PASSWORD_CHANGED" in out
    newpw = new_pw_of(out)
    assert newpw and len(newpw) == 24
    assert PW not in out
    # single use
    _, page2, _ = req(aenv.port, "GET", f"/a/{tok}")
    assert req(aenv.port, "POST", f"/a/{tok}", form={"csrf": "0" * 64, "s_password": PW},
               headers={"Origin": ORIGIN})[0] == 410
    # reload: stored log + status, never a secret, never the new password
    assert "KEY_VERIFIED" in page2 and "s_password" not in page2
    assert newpw not in page2 and PW not in page2
    rec = json.loads(aenv.record.read_text())
    assert rec["pw_ok"] and rec["has_newpw"] and rec["askpass_rc"] == 0
    assert not any(PW in x for x in rec["argv"])  # never on the command line
    assert "ONETIME_DROP_ASKPASS_SECRET" in rec["env"] and "SSH_ASKPASS_REQUIRE" in rec["env"]
    assert "NumberOfPasswordPrompts=1" in rec["argv"]
    stored = aenv.store.result_for_token(tok)
    assert stored["status"] == "ok" and stored["verified"] is True
    blob = all_data_bytes(aenv) + "\n".join(stored["lines"]).encode()
    for secret in (PW, newpw):
        assert secret.encode() not in blob
    events = [json.loads(x) for x in aenv.store.audit_path.read_text().splitlines()]
    names = [e["event"] for e in events]
    for ev in ("action_created", "action_viewed", "action_run", "action_result"):
        assert ev in names
    result = [e for e in events if e["event"] == "action_result"][0]
    assert result["status"] == "ok" and result["password_state"] == "changed"
    assert not list(aenv.store.items.iterdir())


def test_redaction_of_echoed_secrets(aenv):
    aenv.behave(mode="echo")
    tok = new_link(aenv)
    _, out, _ = run_link(aenv, tok)
    newpw = new_pw_of(out)
    assert out.count(REDACTED) >= 3  # stdout + stderr echo of the password, chpasswd line
    assert PW not in out
    assert out.count(newpw) == 1  # only in the one-time box, never in the log
    lines = "\n".join(aenv.store.result_for_token(tok)["lines"])
    assert REDACTED in lines and PW not in lines and newpw not in lines


def test_wrong_password_fails_without_revealing_or_changing(aenv):
    tok = new_link(aenv)
    st, out, _ = run_link(aenv, tok, pw="Dummy123")
    assert st == 200 and "Permission denied" in out
    assert new_pw_of(out) is None
    assert aenv.store.result_for_token(tok)["status"] == "failed"
    _, page, _ = req(aenv.port, "GET", f"/a/{tok}")
    assert "s_password" not in page  # burned anyway: no retry / brute force
    assert req(aenv.port, "POST", f"/a/{tok}", form={"csrf": "0" * 64, "s_password": PW},
               headers={"Origin": ORIGIN})[0] == 410


def test_without_reset_no_password_step(aenv):
    tok = new_link(aenv)
    _, out, _ = run_link(aenv, tok, reset=False)
    assert new_pw_of(out) is None and "PASSWORD_CHANGED" not in out
    assert json.loads(aenv.record.read_text())["has_newpw"] is False
    assert aenv.store.result_for_token(tok)["status"] == "ok"


def test_timeout_kills_run(aenv):
    aenv.behave(mode="sleep")
    aenv.cfg.action_timeout = 2
    tok = new_link(aenv)
    t0 = time.time()
    _, out, _ = run_link(aenv, tok)
    assert time.time() - t0 < 15
    assert "TIMEOUT after 2s" in out
    assert aenv.store.result_for_token(tok)["status"] == "timeout"
    assert new_pw_of(out) is None  # step (d) never started


@pytest.mark.skipif(not shutil.which("sh"), reason="needs a POSIX sh")
def test_real_remote_script_is_idempotent(aenv):
    home = aenv.tmp / "home"
    (home / "data_ssh").mkdir(parents=True)
    aenv.behave(mode="sh", home=home.as_posix())
    for _ in range(2):
        _, out, _ = run_link(aenv, new_link(aenv), reset=False)
        assert "KEY_VERIFIED lines=1" in out, out
    assert "key already present" in out
    ak = (home / ".ssh" / "authorized_keys").read_text()
    assert ak.count("AAAAIGA5viaeuy2McO6B") == 1 and ak.endswith("my-laptop-cerbo\n")


# --- units ------------------------------------------------------------------

def test_redactor_and_askpass(monkeypatch, capsys):
    r = Redactor(["abc", "abcdef", ""])
    assert r("x abcdef y abc") == f"x {REDACTED} y {REDACTED}"
    from onetime_drop import askpass
    monkeypatch.setenv(askpass.ENV, "s3cret")
    monkeypatch.setattr(sys, "argv", ["askpass", "Are you sure you want to continue (yes/no)?"])
    assert askpass.main() == 1 and capsys.readouterr().out == ""
    monkeypatch.setattr(sys, "argv", ["askpass", "root@1.2.3.4's password: "])
    assert askpass.main() == 0 and capsys.readouterr().out == "s3cret\n"
