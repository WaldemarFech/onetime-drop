"""Configuration (TOML). See deploy/config.example.toml."""
from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .store import MAX_TTL, Store, parse_ttl

DEFAULT_PATH = "/etc/onetime-drop/config.toml"


@dataclass
class Config:
    data_dir: Path
    key_file: Path
    proxy_secret: str
    base_url: str
    allowed_proxies: set[str]
    allowed_users: set[str]
    admin_users: set[str]
    bind: str = "127.0.0.1"
    port: int = 8080
    user_header: str = "Remote-User"
    proxy_secret_header: str = "X-Drop-Proxy-Secret"
    default_ttl: int = 86400
    max_ttl: int = MAX_TTL
    lang: str = "en"
    # action links (see README "Action links")
    action_networks: list[str] = field(default_factory=list)  # hosts recipes may target
    action_timeout: int = 60                                  # hard cap per run (seconds)
    ssh_command: list[str] = field(default_factory=lambda: ["/usr/bin/ssh"])
    askpass: str = str(Path(__file__).with_name("askpass.py"))
    _store: Store | None = field(default=None, repr=False)

    def __post_init__(self):
        if len(self.proxy_secret) < 32:
            raise ValueError("proxy secret must be at least 32 characters")
        if not self.allowed_proxies:
            raise ValueError("allowed_proxies must not be empty")
        if not self.allowed_users:
            raise ValueError("allowed_users must not be empty")
        if not self.admin_users <= self.allowed_users:
            raise ValueError("admin_users must be a subset of allowed_users")
        if self.lang not in ("en", "de"):
            raise ValueError("lang must be 'en' or 'de'")
        for n in self.action_networks:
            ipaddress.IPv4Network(n)  # raises ValueError on garbage
        if not 1 <= int(self.action_timeout) <= 300:
            raise ValueError("action_timeout must be 1..300 seconds")
        if not self.ssh_command or not all(isinstance(x, str) for x in self.ssh_command):
            raise ValueError("ssh_command must be a non-empty list of strings")
        self.base_url = self.base_url.rstrip("/")

    @property
    def origin(self) -> str:
        return self.base_url

    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store(self.data_dir, Path(self.key_file).read_bytes())
        return self._store


def load(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or os.environ.get("ONETIME_DROP_CONFIG", DEFAULT_PATH))
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    secret = raw.get("proxy_secret")
    if secret is None:
        secret = Path(raw["proxy_secret_file"]).read_text(encoding="utf-8").strip()
    max_ttl = parse_ttl(raw.get("max_ttl", "7d"))
    users = set(raw.get("allowed_users", []))
    return Config(
        data_dir=Path(raw.get("data_dir", "/var/lib/onetime-drop")),
        key_file=Path(raw.get("key_file", "/etc/onetime-drop/key")),
        proxy_secret=secret,
        base_url=raw["base_url"],
        allowed_proxies=set(raw.get("allowed_proxies", [])),
        allowed_users=users,
        admin_users=set(raw.get("admin_users", sorted(users))),
        bind=raw.get("bind", "127.0.0.1"),
        port=int(raw.get("port", 8080)),
        user_header=raw.get("user_header", "Remote-User"),
        proxy_secret_header=raw.get("proxy_secret_header", "X-Drop-Proxy-Secret"),
        default_ttl=parse_ttl(raw.get("default_ttl", "24h"), max_ttl),
        max_ttl=max_ttl,
        lang=raw.get("lang", "en"),
        action_networks=list(raw.get("action_networks", [])),
        action_timeout=int(raw.get("action_timeout", 60)),
        ssh_command=list(raw.get("ssh_command", ["/usr/bin/ssh"])),
    )
