"""Test double for ssh. Usage (as cfg.ssh_command): [python, fake_ssh.py, behavior.json].

Like real ssh with SSH_ASKPASS_REQUIRE=force it asks the askpass helper for the password, then
"executes" the stdin script. behavior.json:
  expect   password the fake server accepts
  mode     ok | echo (also prints the secrets, to test redaction) | sleep | sh (run the script
           with a real local sh, HOME=behavior["home"])
  record   path where argv / env names / facts are written (never the secrets themselves)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

beh = json.load(open(sys.argv[1], encoding="utf-8"))
args = sys.argv[2:]
ask = subprocess.run([sys.executable, os.environ["SSH_ASKPASS"], "root@host's password: "],
                     capture_output=True, text=True, env=os.environ)
given = ask.stdout.rstrip("\n")
script = sys.stdin.read()
newpw = re.search(r"^NEWPW='?([^'\n]*)'?$", script, re.M)
if beh.get("record"):
    with open(beh["record"], "w", encoding="utf-8") as fh:
        json.dump({"argv": args, "env": sorted(os.environ), "askpass_rc": ask.returncode,
                   "has_newpw": bool(newpw), "pw_ok": given == beh["expect"]}, fh)
if given != beh["expect"]:
    print("root@host: Permission denied (publickey,password).", file=sys.stderr, flush=True)
    sys.exit(255)
mode = beh.get("mode", "ok")
if mode == "sleep":
    print("== (a) locate persistent authorized_keys", flush=True)
    time.sleep(30)
    sys.exit(0)
if mode == "sh":
    env = dict(os.environ, HOME=beh["home"])
    env.pop("ONETIME_DROP_ASKPASS_SECRET", None)
    sys.exit(subprocess.run([shutil.which("sh"), "-s"], input=script, text=True,
                            env=env).returncode)
fp = re.search(r"expected=(SHA256:[A-Za-z0-9+/]+)", script).group(1)
print("== (a) locate persistent authorized_keys", flush=True)
print("authorized_keys: /data/home/root/.ssh/authorized_keys", flush=True)
if mode == "echo":
    print(f"debug: password was {given}!", flush=True)
    print(f"stderr echo {given}", file=sys.stderr, flush=True)
print("== (b) append key (idempotent)\nkey appended", flush=True)
print(f"== (c) verify installed line\nKEY_VERIFIED lines=1 expected={fp}", flush=True)
if newpw:
    print("== (d) set new random root password", flush=True)
    if mode == "echo":
        print(f"chpasswd: root:{newpw.group(1)}", flush=True)
    print("PASSWORD_CHANGED", flush=True)
