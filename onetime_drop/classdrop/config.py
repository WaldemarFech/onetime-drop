"""ClassDrop configuration (TOML dataclass config)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import List

DEFAULT_TOML = "/etc/onetime-class/class.toml"


@dataclass
class ClassDropConfig:
    state_dir: str = "/var/lib/onetime-class"
    key_file: str = "/etc/onetime-class/key.bin"
    base_url: str = "http://127.0.0.1:8082"
    trusted_proxies: List[str] = field(default_factory=list)
    bind: str = "127.0.0.1"
    port: int = 8082
    max_file_mb: int = 25
    max_files: int = 20
    max_request_mb: int = 100
    default_class_mb: int = 2048
    per_ip_per_min: int = 60
    global_per_min: int = 1200
    max_connections: int = 64
    lang: str = "de"
    admin_users: List[str] = field(default_factory=lambda: ["admin"])

    def validate(self) -> "ClassDropConfig":
        if not isinstance(self.state_dir, str) or not self.state_dir:
            raise ValueError("state_dir must be a non-empty string")
        if not isinstance(self.key_file, str) or not self.key_file:
            raise ValueError("key_file must be a non-empty string")
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ValueError("base_url must be a non-empty string")
        if isinstance(self.trusted_proxies, str):
            self.trusted_proxies = [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]
        if not isinstance(self.trusted_proxies, list):
            raise ValueError("trusted_proxies must be a list")
        for p in self.trusted_proxies:
            if not isinstance(p, str) or not p:
                raise ValueError("trusted_proxies entries must be non-empty strings")
        import ipaddress, re as _re
        for p in self.trusted_proxies:
            ipaddress.ip_address(p)
        self.base_url = self.base_url.rstrip("/")
        if not _re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?", self.base_url):
            raise ValueError("base_url must be scheme://host[:port]")
        if isinstance(self.admin_users, str):
            self.admin_users = [self.admin_users]
        if not isinstance(self.bind, str) or not self.bind:
            raise ValueError("bind must be a non-empty string")
        for name in ("port", "max_file_mb", "max_files", "max_request_mb",
                     "default_class_mb", "per_ip_per_min", "global_per_min",
                     "max_connections"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(f"{name} must be an int")
        if not (1 <= self.port <= 65535):
            raise ValueError("port must be 1..65535")
        if self.max_file_mb <= 0 or self.max_files <= 0 or self.max_request_mb <= 0:
            raise ValueError("max_* limits must be positive")
        if self.default_class_mb <= 0:
            raise ValueError("default_class_mb must be positive")
        if self.per_ip_per_min <= 0 or self.global_per_min <= 0 or self.max_connections <= 0:
            raise ValueError("rate/connection limits must be positive")
        if self.lang not in ("de", "en"):
            raise ValueError("lang must be 'de' or 'en'")
        return self

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024

    @property
    def default_max_bytes(self) -> int:
        return self.default_class_mb * 1024 * 1024


def _coerce(cfg: ClassDropConfig, data: dict) -> ClassDropConfig:
    known = {f.name for f in fields(cfg)}
    for k, v in data.items():
        if k not in known:
            continue
        if k == "trusted_proxies" and isinstance(v, str):
            v = [p.strip() for p in v.split(",") if p.strip()]
        setattr(cfg, k, v)
    return cfg.validate()


def load_config(path: str | None = None) -> ClassDropConfig:
    """Load config from TOML file; defaults + file overlay. Validates."""
    cfg = ClassDropConfig().validate()
    p = path or os.environ.get("ONETIME_CLASS_TOML", DEFAULT_TOML)
    if p and os.path.exists(p):
        try:
            import tomllib
        except ImportError:  # pragma: no cover
            import tomli as tomllib  # type: ignore
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config TOML must be a table")
        _coerce(cfg, data)
    return cfg


load = load_config


def selftest() -> dict:
    import tempfile
    cfg = load_config("/nonexistent-path-xyz.toml")
    assert cfg.bind == "127.0.0.1" and cfg.port == 8082
    assert cfg.max_file_mb == 25 and cfg.max_files == 20
    assert cfg.max_request_mb == 100 and cfg.default_class_mb == 2048
    assert cfg.per_ip_per_min == 60 and cfg.global_per_min == 1200
    assert cfg.max_connections == 64 and cfg.lang == "de"
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write('port = 9099\nlang = "en"\nmax_files = 5\n')
        name = fh.name
    try:
        c2 = load_config(name)
        assert c2.port == 9099 and c2.lang == "en" and c2.max_files == 5
        assert c2.bind == "127.0.0.1"
    finally:
        os.unlink(name)
    try:
        bad = ClassDropConfig(port=0)
        bad.validate()
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    return {"ok": True}
if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["selftest"]: print(selftest())
