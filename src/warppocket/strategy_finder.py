"""Bounded sequential endpoint verification for connect and background search.

One measured identity is used at a time: a trial process is started, checked
with the HTTPS health check and stopped before the next candidate starts. The
connection path instead keeps the first verified process alive because only a
verified process may serve the fixed SOCKS port.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass

from warppocket.endpoints import iter_candidates
from warppocket.models import AppError, Cache, CheckResult, Endpoint, Profile

DEFAULT_LIMIT = 30
DEFAULT_DEADLINE = 180.0
DEFAULT_RESULTS = 3


@dataclass(frozen=True)
class SearchOutcome:
    results: tuple[CheckResult, ...]
    checked: int
    cancelled: bool


class StrategyFinder:
    def __init__(self, backend, health, *, clock=time.monotonic, rng=None):
        self.backend, self.health = backend, health
        self.clock = clock
        self.rng = rng or random.Random()

    def candidates(self, profile: Profile, cache: Cache | None = None, *,
                   endpoints=None, limit: int = DEFAULT_LIMIT) -> list[Endpoint]:
        if endpoints is not None:
            base = [Endpoint.parse(item) if isinstance(item, str) else item for item in endpoints]
        else:
            base = iter_candidates(profile.endpoint, cache, limit=limit, rng=self.rng)
        unique: list[Endpoint] = []
        seen: set[str] = set()
        for endpoint in base:
            key = str(endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(endpoint)
        return unique[:limit]

    def search(self, profile: Profile, *, role: str, cache: Cache | None = None,
               endpoints=None, limit: int = DEFAULT_LIMIT, deadline_seconds: float = DEFAULT_DEADLINE,
               keep: int = DEFAULT_RESULTS, cancel: threading.Event | None = None,
               on_stage=None) -> SearchOutcome:
        """Check candidates sequentially; stop at `keep` successes or the deadline."""
        if role not in ("primary", "probe"):
            raise ValueError("invalid search role")
        cancel = cancel or threading.Event()
        deadline = self.clock() + deadline_seconds
        checked = 0
        results: list[CheckResult] = []
        for endpoint in self.candidates(profile, cache, endpoints=endpoints, limit=limit):
            if cancel.is_set():
                return SearchOutcome((), checked, True)
            if self.clock() >= deadline:
                break
            checked += 1
            instance = None
            try:
                if on_stage:
                    on_stage("trying", endpoint=endpoint, checked=checked, found=len(results))
                instance = self.backend.start(profile, endpoint, role=role, port=None, cancel=cancel)
                latency = self.health(instance.port, cancel=cancel)
                if instance.process.poll() is not None:
                    raise AppError("proxy_exited", "Прокси завершился во время проверки.")
                results.append(CheckResult.now(endpoint, latency, role))
                if on_stage:
                    on_stage("found", endpoint=endpoint, checked=checked, found=len(results))
                if len(results) >= keep:
                    break
            except AppError as error:
                if error.code == "cancelled" or cancel.is_set():
                    return SearchOutcome((), checked, True)
                if error.code == "port_busy":
                    raise
                if on_stage:
                    on_stage("failed", endpoint=endpoint, checked=checked, code=error.code)
            finally:
                if instance is not None:
                    self.backend.stop(instance)
        results.sort(key=lambda item: item.latency_ms)
        return SearchOutcome(tuple(results), checked, False)

    def connect(self, profile: Profile, *, candidates, cancel: threading.Event | None = None,
                deadline_seconds: float = DEFAULT_DEADLINE, on_stage=None):
        """Try candidates on the fixed port; return the live verified instance."""
        cancel = cancel or threading.Event()
        deadline = self.clock() + deadline_seconds
        checked = 0
        for endpoint in candidates:
            if cancel.is_set():
                raise AppError("cancelled", "Операция отменена.")
            if self.clock() >= deadline:
                break
            checked += 1
            instance = None
            try:
                if on_stage:
                    on_stage("trying", endpoint=endpoint, checked=checked)
                instance = self.backend.start(profile, endpoint, role="primary", port=25344, cancel=cancel)
                latency = self.health(instance.port, cancel=cancel)
                if instance.process.poll() is not None:
                    raise AppError("proxy_exited", "Прокси завершился во время проверки.")
                if on_stage:
                    on_stage("found", endpoint=endpoint, checked=checked)
                return instance, latency, checked
            except BaseException as error:
                if instance is not None:
                    self.backend.stop(instance)
                if isinstance(error, AppError):
                    if error.code in ("cancelled", "port_busy"):
                        raise
                    if on_stage:
                        on_stage("failed", endpoint=endpoint, checked=checked, code=error.code)
                else:
                    raise
        if cancel.is_set():
            raise AppError("cancelled", "Операция отменена.")
        raise AppError("no_working_endpoint", "Ни один ограниченно проверенный endpoint не прошёл проверку.")
