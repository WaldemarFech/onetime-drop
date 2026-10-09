"""DIL configuration (TOML, default /etc/onetime-dil/dil.toml)."""
from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = "/etc/onetime-dil/dil.toml"
HARD_MAX_TTL = 7 * 86400


def parse_ttl(value: str | int, max_ttl: int = HARD_MAX_TTL) -> int:
    m = re.fullmatch(r"(\d{1,7})([smhd]?)", str(value).strip())
    if not m:
        raise ValueError("ttl must look like 30m, 2h, 1d or seconds")
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 60 <= secs <= max_ttl:
        raise ValueError(f"ttl must be between 60s and {max_ttl}s")
    return secs


@dataclass
class DilConfig:
    state_dir: Path
    base_url: str
    trusted_proxies: set[str]
    bind: str = "127.0.0.1"
    port: int = 8081
    max_ttl: int = 48 * 3600
    per_ip_per_min: int = 20
    global_per_min: int = 600
    max_connections: int = 64
    lang: str = "de"

    def __post_init__(self):
        self.state_dir = Path(self.state_dir)
        self.base_url = self.base_url.rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?", self.base_url):
            raise ValueError("base_url must be scheme://host[:port] without a path")
        if not self.trusted_proxies:
            raise ValueError("trusted_proxies must not be empty")
        for ip in self.trusted_proxies:
            ipaddress.ip_address(ip)
        if not 60 <= self.max_ttl <= HARD_MAX_TTL:
            raise ValueError("max_ttl out of range")
        for name in ("per_ip_per_min", "global_per_min", "max_connections"):
            if not 1 <= int(getattr(self, name)) <= 100000:
                raise ValueError(f"{name} out of range")
        if self.lang not in ("de", "en"):
            raise ValueError("lang must be 'de' or 'en'")

    @property
    def origin(self) -> str:
        return self.base_url


def load(path: str | os.PathLike | None = None) -> DilConfig:
    path = Path(path or os.environ.get("ONETIME_DIL_CONFIG", DEFAULT_PATH))
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    return DilConfig(
        state_dir=Path(raw.get("state_dir", "/var/lib/onetime-dil")),
        base_url=raw["base_url"],
        trusted_proxies=set(raw.get("trusted_proxies", [])),
        bind=raw.get("bind", "127.0.0.1"),
        port=int(raw.get("port", 8081)),
        max_ttl=parse_ttl(raw.get("max_ttl", "48h")),
        per_ip_per_min=int(raw.get("per_ip_per_min", 20)),
        global_per_min=int(raw.get("global_per_min", 600)),
        max_connections=int(raw.get("max_connections", 64)),
        lang=raw.get("lang", "de"),
    )
