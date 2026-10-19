"""Application controller: connect, disconnect, bounded search, health monitoring.

All network work happens on worker threads. Results are committed only when the
operation is still current: a late success from a cancelled operation stops its
own process instead of becoming active, and no cancelled or failed operation
can replace the saved strategies.
"""

from __future__ import annotations

import queue
import threading
from enum import Enum

from warppocket.healthcheck import check_proxy
from warppocket.models import AppError, Cache, CheckResult, Profile

DEFAULT_SEARCH_LIMIT = 30
DEFAULT_SEARCH_DEADLINE = 180.0
DEFAULT_HEALTH_INTERVAL = 30.0
DEFAULT_HEALTH_FAILURES = 2


class ConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class Controller:
    def __init__(self, *, storage, profiles, backend, finder, manager, health=check_proxy,
                 logger=None, search_limit: int = DEFAULT_SEARCH_LIMIT,
                 search_deadline: float = DEFAULT_SEARCH_DEADLINE,
                 health_interval: float = DEFAULT_HEALTH_INTERVAL,
                 health_failures: int = DEFAULT_HEALTH_FAILURES):
        self._storage, self._profiles = storage, profiles
        self._backend, self._finder, self._manager = backend, finder, manager
        self._health, self._logger = health, logger
        self._search_limit, self._search_deadline = search_limit, search_deadline
        self._health_interval, self._health_failures = health_interval, health_failures
        self._lock = threading.RLock()
        self._events: queue.Queue = queue.Queue()
        self._state = ConnectionState.DISCONNECTED
        self._state_detail: tuple[str | None, str | None] = (None, None)
        self._active = None
        self._active_result: CheckResult | None = None
        self._op_id = 0
        self._connect_cancel: threading.Event | None = None
        self._search_cancel: threading.Event | None = None
        self._search_op: int | None = None
        self._search_role: str | None = None
        self._health_stop = threading.Event()
        self._closed = False
        self._workers: set[threading.Thread] = set()

    # -- public state ------------------------------------------------------

    @property
    def state(self) -> ConnectionState:
        with self._lock:
            return self._state

    def status(self):
        """Immutable snapshot for the UI."""
        with self._lock:
            return {"state": self._state, "code": self._state_detail[0],
                    "message": self._state_detail[1],
                    "endpoint": self._active_result.endpoint if self._active_result else None,
                    "latency_ms": self._active_result.latency_ms if self._active_result else None,
                    "searching": self._search_op is not None,
                    "search_role": self._search_role if self._search_op is not None else None}

    def poll_events(self) -> list[dict]:
        events = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    # -- operations --------------------------------------------------------

    def connect(self, *, consent: bool = False):
        with self._lock:
            if self._closed:
                self._emit({"type": "error", "code": "closed", "message": "Приложение завершается."})
                return
            if self._state in (ConnectionState.CONNECTING, ConnectionState.CONNECTED):
                return
            if self._search_op is not None:
                self._emit({"type": "error", "code": "search_active",
                            "message": "Дождитесь завершения поиска или отмените его."})
                return
            self._op_id += 1
            op_id = self._op_id
            cancel = self._connect_cancel = threading.Event()
            self._state = ConnectionState.CONNECTING
            self._state_detail = (None, None)
        self._emit_state()
        self._spawn(lambda: self._connect_worker(op_id, cancel, consent))

    def disconnect(self):
        with self._lock:
            if self._closed:
                return
            active, self._active = self._active, None
            self._active_result = None
            self._state = ConnectionState.DISCONNECTED
            self._state_detail = (None, None)
            self._op_id += 1  # invalidate any in-flight operation
            cancels = [item for item in (self._connect_cancel, self._search_cancel) if item]
        self._health_stop.set()
        for cancel in cancels:
            cancel.set()
        self._emit_state()
        self._spawn(lambda: self._disconnect_worker(active))

    def start_search(self, *, probe_consent: bool = False):
        with self._lock:
            if self._closed or self._search_op is not None:
                return
            if self._state == ConnectionState.CONNECTING:
                self._emit({"type": "error", "code": "busy",
                            "message": "Дождитесь завершения подключения."})
                return
            role = "probe" if self._state == ConnectionState.CONNECTED else "primary"
            op_id = self._op_id + 1
            self._op_id = op_id
            cancel = self._search_cancel = threading.Event()
            self._search_op, self._search_role = op_id, role
        self._emit({"type": "search_started", "role": role})
        self._spawn(lambda: self._search_worker(op_id, cancel, role, probe_consent))

    def cancel_search(self):
        with self._lock:
            cancel = self._search_cancel
        if cancel is not None:
            cancel.set()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active, self._active = self._active, None
            self._active_result = None
            cancels = [item for item in (self._connect_cancel, self._search_cancel) if item]
            self._state = ConnectionState.DISCONNECTED
            self._state_detail = (None, None)
            workers = list(self._workers)
        self._health_stop.set()
        for cancel in cancels:
            cancel.set()
        if active is not None:
            self._stop(active)
        self._manager.shutdown()
        for worker in workers:
            if worker.ident is not None:
                worker.join(10)
        try:
            self._storage.clear_runtime()
        except OSError:
            pass

    # -- workers -----------------------------------------------------------

    def _connect_worker(self, op_id: int, cancel: threading.Event, consent: bool):
        try:
            self._profiles.ensure_profile("primary", consent=consent, cancel=cancel)
            profile = self._profiles.ensure_reserved("primary", cancel=cancel)
            cache = self._storage.load_cache()
        except AppError as error:
            self._connect_failure(op_id, error)
            return
        candidates = self._finder.candidates(profile, cache, limit=self._search_limit)

        def stage(kind, **fields):
            if self._connect_current(op_id) and not cancel.is_set():
                self._emit({"type": "connect_progress", "stage": kind,
                            **{key: str(value) if hasattr(value, "host") else value
                               for key, value in fields.items()}})

        try:
            instance, latency, checked = self._finder.connect(profile, candidates=candidates,
                                                              cancel=cancel, on_stage=stage)
        except AppError as error:
            if error.code == "cancelled" or cancel.is_set():
                self._connect_finished(op_id)
            else:
                self._connect_failure(op_id, error)
            return
        except Exception:
            self._connect_failure(op_id, AppError("connect_failed", "Подключение прервано внутренней ошибкой."))
            return
        result = CheckResult.now(instance.endpoint, latency, "primary")
        with self._lock:
            stale = not self._connect_current_locked(op_id) or cancel.is_set()
            if not stale:
                self._active, self._active_result = instance, result
                self._state = ConnectionState.CONNECTED
                self._state_detail = (None, None)
        if stale:
            self._stop(instance)
            self._connect_finished(op_id)
            return
        self._emit_state()
        warning = self._commit_connected(cache, result)
        self._emit({"type": "warning", "code": warning.code, "message": str(warning)} if warning
                   else {"type": "saved", "scope": "connect"})
        self._log("connected", endpoint=result.endpoint, exit_code=None)
        self._connect_finished(op_id)
        self._start_health_monitor()

    def _disconnect_worker(self, active):
        if active is not None:
            self._stop(active)
        try:
            self._storage.clear_runtime()
        except OSError:
            pass

    def _search_worker(self, op_id: int, cancel: threading.Event, role: str, probe_consent: bool):
        try:
            if role == "probe":
                self._profiles.ensure_profile("probe", consent=probe_consent, cancel=cancel)
            profile = self._profiles.ensure_reserved(role, cancel=cancel)
            cache = self._storage.load_cache()
        except AppError as error:
            self._search_end(op_id)
            self._emit({"type": "search_done", "found": 0, "checked": 0, "saved": False,
                        "code": error.code, "message": str(error)})
            return

        def stage(kind, **fields):
            if self._search_current(op_id) and not cancel.is_set():
                self._emit({"type": "search_progress", "stage": kind, "limit": self._search_limit,
                            **{key: str(value) if hasattr(value, "host") else value
                               for key, value in fields.items()}})

        try:
            outcome = self._finder.search(profile, role=role, cache=cache, limit=self._search_limit,
                                          deadline_seconds=self._search_deadline, cancel=cancel,
                                          on_stage=stage)
        except Exception:
            self._search_end(op_id)
            self._emit({"type": "search_done", "found": 0, "checked": 0, "saved": False,
                        "code": "search_failed", "message": "Поиск прерван; сохранённые варианты не изменены."})
            return
        if outcome.cancelled:
            self._search_end(op_id)
            self._emit({"type": "search_cancelled"})
            return
        if not outcome.results:
            self._search_end(op_id)
            self._emit({"type": "search_done", "found": 0, "checked": outcome.checked, "saved": False,
                        "code": "no_working_endpoint",
                        "message": "Рабочие эндпоинты не найдены; сохранённые варианты не изменены."})
            return
        stored = self._search_current(op_id)
        warning = self._commit_search(cache, outcome.results) if stored else None
        self._search_end(op_id)
        self._emit({"type": "search_done", "found": len(outcome.results), "checked": outcome.checked,
                    "saved": stored and warning is None, "role": role,
                    "best": str(outcome.results[0].endpoint)})
        if warning is not None:
            self._emit({"type": "warning", "code": warning.code, "message": str(warning)})

    # -- cache commits -----------------------------------------------------

    def _commit_connected(self, cache: Cache, result: CheckResult) -> AppError | None:
        fallbacks = tuple(item for item in cache.fallbacks if item.endpoint != result.endpoint)[:3]
        try:
            self._storage.save_cache(Cache(last_good=result, preferred=None, fallbacks=fallbacks))
            return None
        except AppError as error:
            return error

    def _commit_search(self, cache: Cache, results) -> AppError | None:
        best = results[0]
        rest = list(results[1:])
        for item in cache.fallbacks:
            if all(item.endpoint != other.endpoint for other in (*rest, best)):
                rest.append(item)
        try:
            self._storage.save_cache(Cache(last_good=cache.last_good, preferred=best,
                                           fallbacks=tuple(rest[:3])))
            return None
        except AppError as error:
            return error

    # -- health monitoring -------------------------------------------------

    def _start_health_monitor(self):
        self._health_stop = threading.Event()
        self._spawn(self._health_loop, daemon=True)

    def _health_loop(self):
        failures = 0
        while not self._health_stop.wait(self._health_interval):
            with self._lock:
                instance = self._active
                if instance is None or self._closed or self._state != ConnectionState.CONNECTED:
                    return
            if instance.process.poll() is not None:
                self._health_failure("proxy_exited", "Сетевой компонент неожиданно завершился.")
                return
            try:
                self._health(instance.port, cancel=self._health_stop)
                failures = 0
            except AppError:
                if self._health_stop.is_set():
                    return
                failures += 1
                if failures >= self._health_failures:
                    self._health_failure("connection_lost", "Соединение WARP перестало отвечать; прокси остановлен.")
                    return

    def _health_failure(self, code: str, message: str):
        with self._lock:
            if self._closed:
                return
            instance, self._active = self._active, None
            self._active_result = None
            self._state = ConnectionState.ERROR
            self._state_detail = (code, message)
        self._health_stop.set()
        if instance is not None:
            self._stop(instance)
        self._emit_state()

    # -- helpers -----------------------------------------------------------

    def _connect_current_locked(self, op_id: int) -> bool:
        return not self._closed and self._op_id == op_id and self._state == ConnectionState.CONNECTING

    def _connect_current(self, op_id: int) -> bool:
        with self._lock:
            return self._connect_current_locked(op_id)

    def _search_current(self, op_id: int) -> bool:
        with self._lock:
            return not self._closed and self._search_op == op_id

    def _connect_finished(self, op_id: int):
        with self._lock:
            if self._op_id == op_id:
                self._connect_cancel = None

    def _connect_failure(self, op_id: int, error: AppError):
        with self._lock:
            current = self._connect_current_locked(op_id)
            if current:
                self._state = ConnectionState.ERROR
                self._state_detail = (error.code, str(error))
                self._connect_cancel = None
        if current:
            self._emit_state()

    def _search_end(self, op_id: int):
        with self._lock:
            if self._search_op == op_id:
                self._search_cancel = None
                self._search_op = None
                self._search_role = None

    def _stop(self, instance):
        try:
            self._backend.stop(instance)
        except Exception:
            pass

    def _emit(self, event: dict):
        self._events.put(event)

    def _emit_state(self):
        with self._lock:
            event = {"type": "state", "state": self._state.value,
                     "code": self._state_detail[0], "message": self._state_detail[1]}
            if self._active_result is not None:
                event["endpoint"] = str(self._active_result.endpoint)
                event["latency_ms"] = self._active_result.latency_ms
        self._emit(event)

    def _log(self, code: str, **fields):
        if self._logger is not None:
            try:
                self._logger(code, **fields)
            except Exception:
                pass

    def _spawn(self, target, daemon: bool = True):
        worker = threading.Thread(target=target, name="warppocket-worker", daemon=daemon)
        with self._lock:
            if self._closed:
                return
            self._workers = {item for item in self._workers if item.is_alive()}
            self._workers.add(worker)
            # Start under the lock so close() can never snapshot an unstarted thread.
            worker.start()
