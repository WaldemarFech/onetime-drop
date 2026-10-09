"""Admin web UI, config validation, CLI and pull tool."""
import json
import os
import re
import subprocess
import sys

import pytest
from conftest import ORIGIN, ROOT, SECRET, csrf_of, make_config, req

import pull_inputs
from onetime_drop import config as config_mod


def admin_csrf(port, user="alice"):
    st, p, _ = req(port, "GET", "/admin", user=user)
    assert st == 200
    return csrf_of(p), p


def test_admin_requires_admin_user(env):
    _, _, port = env
    assert req(port, "GET", "/admin", user="bob")[0] == 404  # allowed user, not admin
    assert req(port, "GET", "/admin", user="mallory")[0] == 403
    assert req(port, "GET", "/admin", secret=None)[0] == 403
    st, _, r = req(port, "GET", "/")
    assert st == 303 and r.getheader("Location") == "/admin"


def test_admin_create_reveal_then_recipient_burns(env):
    store, _, port = env
    csrf, _ = admin_csrf(port)
    st, p, r = req(port, "POST", "/admin/reveal", headers={"Origin": ORIGIN},
                   form={"csrf": csrf, "label": "Wifi", "secret": "PW-MARKER", "ttl": "1h"})
    assert st == 200 and "PW-MARKER" not in p
    assert "nonce-" in r.getheader("Content-Security-Policy")
    url = re.search(r"https://drop\.example\.com/r/[A-Za-z0-9_-]{43}", p).group(0)
    path = url[len(ORIGIN):]
    _, page, _ = req(port, "GET", path, user="bob")
    st, shown, _ = req(port, "POST", path, user="bob", form={"csrf": csrf_of(page)})
    assert st == 200 and "PW-MARKER" in shown
    _, adminp = admin_csrf(port)
    assert "PW-MARKER" not in adminp and "revealed" in adminp


def test_admin_create_input_list_and_revoke(env):
    store, _, port = env
    csrf, _ = admin_csrf(port)
    st, p, _ = req(port, "POST", "/admin/input",
                   form={"csrf": csrf, "label": "Token", "fields": "name,value",
                         "target": "svc.token", "ttl": "24h"})
    assert st == 200 and "/i/" in p
    [item] = store.pending()
    assert item.target == "svc.token" and item.blob is None
    _, adminp = admin_csrf(port)
    assert "svc.token" in adminp and item.id in adminp
    st, _, r = req(port, "POST", "/admin/revoke", form={"csrf": csrf, "id": item.id})
    assert st == 303 and store.pending() == []
    assert any(json.loads(x)["event"] == "revoked" for x in store.audit_path.read_text().splitlines())


def test_admin_post_checks_csrf_origin_and_input(env):
    store, _, port = env
    csrf, _ = admin_csrf(port)
    base = {"label": "x", "secret": "y", "ttl": "1h"}
    assert req(port, "POST", "/admin/reveal", form={**base, "csrf": "bad"})[0] == 403
    assert req(port, "POST", "/admin/reveal", form={**base, "csrf": csrf},
               headers={"Origin": "https://evil.example"})[0] == 403
    assert req(port, "POST", "/admin/reveal", user="bob", form={**base, "csrf": csrf})[0] == 404
    assert req(port, "POST", "/admin/reveal", form={**base, "csrf": csrf, "ttl": "30d"})[0] == 400
    assert req(port, "POST", "/admin/input",
               form={"csrf": csrf, "label": "x", "fields": "ok", "target": "../etc"})[0] == 400
    assert req(port, "POST", "/admin/revoke", form={"csrf": csrf, "id": "nothex"})[0] == 400
    assert store.pending() == []


def test_config_validation(tmp_path):
    with pytest.raises(ValueError):
        make_config(tmp_path, proxy_secret="short")
    with pytest.raises(ValueError):
        make_config(tmp_path, admin_users={"eve"})
    with pytest.raises(ValueError):
        make_config(tmp_path, allowed_proxies=set())


def write_toml(tmp_path):
    (tmp_path / "key").write_bytes(b"k" * 32)
    (tmp_path / "proxy_secret").write_text(SECRET)
    p = tmp_path / "config.toml"
    p.write_text(
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        f'key_file = "{(tmp_path / "key").as_posix()}"\n'
        f'proxy_secret_file = "{(tmp_path / "proxy_secret").as_posix()}"\n'
        f'base_url = "{ORIGIN}"\nallowed_proxies = ["10.0.0.2"]\n'
        'allowed_users = ["alice", "bob"]\nadmin_users = ["alice"]\nlang = "de"\n')
    return p


def test_config_load_toml(tmp_path):
    cfg = config_mod.load(write_toml(tmp_path))
    assert cfg.allowed_proxies == {"10.0.0.2"} and cfg.lang == "de"
    assert cfg.proxy_secret == SECRET and cfg.default_ttl == 86400


def cli(cfgpath, *args, stdin=None):
    return subprocess.run([sys.executable, "-m", "onetime_drop", "--config", str(cfgpath), *args],
                          input=stdin, capture_output=True, text=True, cwd=ROOT, timeout=30)


def test_cli_and_pull_tool_end_to_end(tmp_path):
    cfgpath = write_toml(tmp_path)
    r = cli(cfgpath, "create-reveal", "--label", "x", "--ttl", "1h", stdin="secret\n")
    assert r.returncode == 0 and r.stdout.startswith(f"{ORIGIN}/r/")
    r = cli(cfgpath, "create-input", "--label", "API key", "--fields", "value",
            "--target", "svc.key")
    assert r.returncode == 0 and "/i/" in r.stdout
    pend = json.loads(cli(cfgpath, "list").stdout)
    assert {p["kind"] for p in pend} == {"reveal", "input"}
    # simulate a submission directly through the store
    cfg = config_mod.load(cfgpath)
    tok = r.stdout.strip().rsplit("/", 1)[1]
    item = cfg.store.claim(tok)
    cfg.store.submit(item, "alice", {"value": "VAL-MARKER"})
    out_dir = tmp_path / "inbox"
    pcfg = {"remote_command": [sys.executable, "-m", "onetime_drop", "--config", str(cfgpath)],
            "target_dir": out_dir, "format": "markdown", "restrict_permissions": False}
    msgs = []
    old = os.getcwd()
    os.chdir(ROOT)
    try:
        assert pull_inputs.pull(pcfg, out=msgs.append) == 1
    finally:
        os.chdir(old)
    [f] = list(out_dir.iterdir())
    assert f.name.startswith("svc.key_") and "VAL-MARKER" in f.read_text()
    assert not any("VAL-MARKER" in m for m in msgs)
    assert json.loads(cli(cfgpath, "outbox", "list").stdout) == []


def test_pull_tool_reports_remote_failures(tmp_path):
    bad = {"remote_command": [sys.executable, "-c", "import sys; sys.exit(3)"],
           "target_dir": tmp_path / "in", "restrict_permissions": False}
    with pytest.raises(RuntimeError):
        pull_inputs.pull(bad, out=lambda m: None)
    slow = {"remote_command": [sys.executable, "-c", "import time; time.sleep(5)"],
            "target_dir": tmp_path / "in", "restrict_permissions": False}
    orig = pull_inputs.subprocess.run

    def fast_timeout(*a, **kw):
        kw["timeout"] = 0.5
        return orig(*a, **kw)

    pull_inputs.subprocess.run = fast_timeout
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            pull_inputs.pull(slow, out=lambda m: None)
    finally:
        pull_inputs.subprocess.run = orig
    assert not (tmp_path / "in").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL check")
def test_pull_restrict_is_owner_only_on_windows(tmp_path):
    f = tmp_path / "x.md"
    f.write_text("x")
    pull_inputs.restrict(f)
    acl = subprocess.run(["icacls", str(f)], capture_output=True, text=True).stdout
    entries = [l for l in acl.splitlines() if ":(" in l]
    assert len(entries) == 1 and os.environ["USERNAME"].lower() in entries[0].lower()
