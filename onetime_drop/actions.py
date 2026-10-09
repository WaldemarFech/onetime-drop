"""Run an action recipe over ssh with a password supplied via SSH_ASKPASS.

Secret handling:
- the password is passed to ssh only through the env var read by `askpass.py`
  (SSH_ASKPASS_REQUIRE=force); it is never a command line argument and never written to disk
- the remote script is fed via ssh stdin (`sh -s`), so generated values (e.g. a new password)
  are not visible in any process list either
- every output line is redacted for all secrets before it is streamed, stored or evaluated
- references are dropped after the run (Python strings cannot be reliably zeroed)
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .askpass import ENV as ASKPASS_ENV
from .recipes import Plan

REDACTED = "[REDACTED]"
MAX_LINES = 2000
MAX_LINE = 2000


class Redactor:
    def __init__(self, secrets_: list[str]):
        self._secrets = sorted({s for s in secrets_ if s}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, REDACTED)
        return text

    def clear(self) -> None:
        self._secrets.clear()


@dataclass
class RunResult:
    lines: list[str] = field(default_factory=list)
    rc: int | None = None
    timed_out: bool = False
    started: float = 0.0
    finished: float = 0.0


def ssh_argv(ssh_command: list[str], plan: Plan, known_hosts: Path) -> list[str]:
    opts = {
        "BatchMode": "no", "StrictHostKeyChecking": "accept-new",
        "UserKnownHostsFile": str(known_hosts), "GlobalKnownHostsFile": "/dev/null",
        "PubkeyAuthentication": "no", "IdentitiesOnly": "yes",
        "PreferredAuthentications": "keyboard-interactive,password",
        "NumberOfPasswordPrompts": "1", "ConnectTimeout": "10", "ServerAliveInterval": "10",
        "ControlMaster": "no", "ControlPath": "none", "ForwardAgent": "no", "ForwardX11": "no",
        "UpdateHostKeys": "no", "LogLevel": "ERROR",
    }
    argv = [*ssh_command, "-F", "/dev/null", "-T"]
    for k, v in opts.items():
        argv += ["-o", f"{k}={v}"]
    return argv + ["-l", plan.user, "--", plan.host, "sh -s"]


def _env(home: Path, askpass: str, password: str) -> dict:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "HOME": str(home),
           "SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force",
           "DISPLAY": "onetime-drop:0", ASKPASS_ENV: password}
    if os.name == "nt":  # test runs on Windows need these to start python
        for k in ("SYSTEMROOT", "PATH", "PATHEXT", "TEMP", "TMP"):
            if k in os.environ:
                env[k] = os.environ[k]
    return env


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run(argv: list[str], script: str, env: dict, timeout: int, redact: Redactor,
        result: RunResult):
    """Generator: yields redacted output lines while the command runs; fills `result`."""
    result.started = time.time()
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, close_fds=True,
                            start_new_session=(os.name != "nt"))
    env.clear()  # drop our reference to the secret-bearing env

    def feed():
        try:
            proc.stdin.write(script.encode("utf-8"))
            proc.stdin.close()
        except OSError:
            pass

    def on_timeout():
        result.timed_out = True
        _kill(proc)

    threading.Thread(target=feed, daemon=True).start()
    timer = threading.Timer(timeout, on_timeout)
    timer.daemon = True
    timer.start()
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = redact(raw.decode("utf-8", "replace").rstrip("\r\n"))[:MAX_LINE]
            if len(result.lines) < MAX_LINES:
                result.lines.append(line)
                yield line
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            _kill(proc)
            proc.wait()
        proc.stdout.close()
        result.rc = proc.returncode
        result.finished = time.time()
    if result.timed_out:
        msg = f"TIMEOUT after {timeout}s - process killed"
        result.lines.append(msg)
        yield msg
