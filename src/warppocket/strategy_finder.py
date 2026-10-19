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


class _TrialBudget:
    """Deadline-aware event view; expiry also releases a blocked SOCKS request.

    A health request may be blocked in a socket read when the wall budget ends.
    Stopping only this operation's helper interrupts that read without touching
    the primary connection or needing a second health-check worker.
    """

    def __init__(self, backend, cancel, seconds, clock):
        if seconds <= 0:
            raise ValueError("deadline must be positive")
        self.backend, self.cancel, self.clock = backend, cancel, clock
        seconds = min(seconds, DEFAULT_DEADLINE)
        self.deadline = clock() + seconds
        self._lock = threading.Lock()
        self._instance = None
        self._expired = threading.Event()
        self._stop_failed = False
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._timer.cancel()
        self._timer.join()
        if self._stop_failed and exc_type is None:
            raise AppError("proxy_stop_failed", "Не удалось завершить проверочный прокси.")

    def is_set(self):
        return self.cancel.is_set() or self._expired.is_set() or self.clock() >= self.deadline

    def set(self):
        self.cancel.set()

    def wait(self, timeout=None):
        deadline = self.deadline
        if timeout is not None:
            deadline = min(deadline, self.clock() + max(0, timeout))
        while not self.is_set():
            remaining = deadline - self.clock()
            if remaining <= 0:
                return self.is_set()
            # Native waits can time out slightly early (notably on Windows).
            # Do not report a false timeout before the requested budget ends.
            self.cancel.wait(remaining)
        return True

    def watch(self, instance):
        with self._lock:
            self._instance = instance
            if self.is_set():
                raise AppError("cancelled", "Операция отменена или время поиска истекло.")

    def release(self, instance):
        with self._lock:
            if self._instance is instance:
                self._instance = None

    def keep(self, instance):
        with self._lock:
            if self.is_set():
                raise AppError("cancelled", "Операция отменена или время поиска истекло.")
            self._instance = None

    def _expire(self):
        self._expired.set()
        with self._lock:
            if self._instance is not None:
                try:
                    self.backend.stop(self._instance)
                except Exception:
                    self._stop_failed = True


class StrategyFinder:
    def __init__(self, backend, health, *, clock=time.monotonic, rng=None):
        self.backend, self.health = backend, health
        self.clock = clock
        self.rng = rng or random.Random()

    def candidates(self, profile: Profile, cache: Cache | None = None, *,
                   endpoints=None, limit: int = DEFAULT_LIMIT) -> list[Endpoint]:
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")
        limit = min(limit, DEFAULT_LIMIT)
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
        checked = 0
        results: list[CheckResult] = []
        with _TrialBudget(self.backend, cancel, deadline_seconds, self.clock) as budget:
            for endpoint in self.candidates(profile, cache, endpoints=endpoints, limit=limit):
                if cancel.is_set():
                    return SearchOutcome((), checked, True)
                if budget.is_set():
                    break
                checked += 1
                instance = None
                try:
                    if on_stage:
                        on_stage("trying", endpoint=endpoint, checked=checked, found=len(results))
                    instance = self.backend.start(profile, endpoint, role=role, port=None, cancel=budget)
                    budget.watch(instance)
                    latency = self.health(instance.port, cancel=budget)
                    if budget.is_set():
                        raise AppError("cancelled", "Операция отменена или время поиска истекло.")
                    if instance.process.poll() is not None:
                        raise AppError("proxy_exited", "Прокси завершился во время проверки.")
                    results.append(CheckResult.now(endpoint, latency, role))
                    if on_stage:
                        on_stage("found", endpoint=endpoint, checked=checked, found=len(results))
                    if len(results) >= keep:
                        break
                except AppError as error:
                    if cancel.is_set():
                        return SearchOutcome((), checked, True)
                    if budget.is_set():
                        break
                    if error.code == "cancelled":
                        return SearchOutcome((), checked, True)
                    if error.code == "port_busy":
                        raise
                    if on_stage:
                        on_stage("failed", endpoint=endpoint, checked=checked, code=error.code)
                finally:
                    if instance is not None:
                        budget.release(instance)
                        self.backend.stop(instance)
        if cancel.is_set():
            return SearchOutcome((), checked, True)
        results.sort(key=lambda item: item.latency_ms)
        return SearchOutcome(tuple(results), checked, False)

    def connect(self, profile: Profile, *, candidates, cancel: threading.Event | None = None,
                deadline_seconds: float = DEFAULT_DEADLINE, on_stage=None):
        """Try candidates on the fixed port; return the live verified instance."""
        cancel = cancel or threading.Event()
        checked = 0
        with _TrialBudget(self.backend, cancel, deadline_seconds, self.clock) as budget:
            for endpoint in candidates:
                if cancel.is_set():
                    raise AppError("cancelled", "Операция отменена.")
                if budget.is_set() or checked >= DEFAULT_LIMIT:
                    break
                checked += 1
                instance = None
                try:
                    if on_stage:
                        on_stage("trying", endpoint=endpoint, checked=checked)
                    instance = self.backend.start(profile, endpoint, role="primary", port=25344, cancel=budget)
                    budget.watch(instance)
                    latency = self.health(instance.port, cancel=budget)
                    if instance.process.poll() is not None:
                        raise AppError("proxy_exited", "Прокси завершился во время проверки.")
                    if on_stage:
                        on_stage("found", endpoint=endpoint, checked=checked)
                    budget.keep(instance)
                    return instance, latency, checked
                except BaseException as error:
                    if instance is not None:
                        budget.release(instance)
                        self.backend.stop(instance)
                    if cancel.is_set():
                        raise AppError("cancelled", "Операция отменена.") from None
                    if budget.is_set() and isinstance(error, AppError):
                        break
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
