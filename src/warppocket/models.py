from __future__ import annotations

import base64
import ipaddress
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


class AppError(Exception):
    """An application-owned message, safe to show without exposing input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host or any(c in self.host for c in "%$[]/\\\x00\r\n"):
            raise ValueError("invalid endpoint host")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid endpoint port")
        try:
            host = str(ipaddress.ip_address(self.host))
        except ValueError:
            host = self.host.rstrip(".").encode("idna").decode("ascii").lower()
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split(".")):
                raise ValueError("invalid endpoint host") from None
        object.__setattr__(self, "host", host)

    @classmethod
    def parse(cls, text: str) -> Endpoint:
        host, port = text.strip().rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        elif ":" in host:
            raise ValueError("IPv6 endpoints require brackets")
        return cls(host, int(port))

    def __str__(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def as_dict(self):
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True)
class Profile:
    private_key: str = field(repr=False)
    addresses: tuple[str, ...]
    dns: tuple[str, ...]
    public_key: str = field(repr=False)
    endpoint: Endpoint
    allowed_ips: tuple[str, ...]
    mtu: int = 1280
    keepalive: int = 0
    preshared_key: str | None = field(default=None, repr=False)

    def identity(self) -> bytes:
        key = bytearray(base64.b64decode(self.private_key, validate=True))
        key[0] &= 248
        key[31] = (key[31] & 127) | 64
        return bytes(key)


@dataclass(frozen=True)
class CheckResult:
    endpoint: Endpoint
    latency_ms: float
    verified_at: str
    role: str

    @classmethod
    def now(cls, endpoint: Endpoint, latency_ms: float, role: str):
        return cls(endpoint, latency_ms, datetime.now(timezone.utc).isoformat(), role)

    def as_dict(self):
        return {"endpoint": self.endpoint.as_dict(), "latency_ms": self.latency_ms,
                "verified_at": self.verified_at, "role": self.role}

    @classmethod
    def from_dict(cls, data):
        endpoint = Endpoint(**data["endpoint"])
        latency = data["latency_ms"]
        if type(latency) not in (float, int) or not math.isfinite(latency) or latency < 0:
            raise ValueError("invalid latency")
        stamp = datetime.fromisoformat(data["verified_at"])
        if stamp.tzinfo is None or data["role"] not in ("primary", "probe"):
            raise ValueError("invalid check result")
        return cls(endpoint, float(latency), stamp.isoformat(), data["role"])


@dataclass(frozen=True)
class Cache:
    last_good: CheckResult | None = None
    preferred: CheckResult | None = None
    fallbacks: tuple[CheckResult, ...] = ()
