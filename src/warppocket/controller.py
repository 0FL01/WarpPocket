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
from warppocket.diagnostics import event as log_event
from warppocket.models import AppError, Cache, CheckResult

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
        self._connect_op: int | None = None
        self._disconnecting = False
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
                    "busy": self._disconnecting or (self._connect_cancel is not None
                                                   and self._state != ConnectionState.CONNECTED),
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
            if self._disconnecting or self._connect_cancel is not None:
                return  # The cancelled primary still owns its identity/port.
            if self._search_op is not None:
                self._emit({"type": "error", "code": "search_active",
                            "message": "Дождитесь завершения поиска или отмените его."})
                return
            self._op_id += 1
            op_id = self._op_id
            self._connect_op = op_id
            cancel = self._connect_cancel = threading.Event()
            self._state = ConnectionState.CONNECTING
            self._state_detail = (None, None)
        self._emit_state()
        self._spawn(lambda: self._connect_worker(op_id, cancel, consent))

    def disconnect(self):
        with self._lock:
            if self._closed or self._disconnecting:
                return
            self._disconnecting = True
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
            if self._state == ConnectionState.CONNECTING or self._connect_cancel is not None or self._disconnecting:
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
            if self._search_cancel is not None:
                self._search_cancel.set()

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
        instance = None
        try:
            self._profiles.ensure_profile("primary", consent=consent, cancel=cancel)
            profile = self._profiles.ensure_reserved("primary", cancel=cancel)
            cache = self._storage.load_cache()
            candidates = self._finder.candidates(profile, cache, limit=self._search_limit)

            def stage(kind, **fields):
                if self._connect_current(op_id) and not cancel.is_set():
                    self._emit({"type": "connect_progress", "stage": kind,
                                **{key: str(value) if hasattr(value, "host") else value
                                   for key, value in fields.items()}})

            instance, latency, checked = self._finder.connect(profile, candidates=candidates,
                                                              cancel=cancel, on_stage=stage)
            result = CheckResult.now(instance.endpoint, latency, "primary")
            with self._lock:
                if not self._connect_current_locked(op_id) or cancel.is_set():
                    return  # finally releases a late success before allowing reuse.
                # Serialize cache publication with disconnect/cancel/search. A
                # new search cannot overwrite this last_good from an old snapshot.
                warning = self._commit_connected(cache, result)
                self._active, self._active_result = instance, result
                self._state = ConnectionState.CONNECTED
                self._state_detail = (None, None)
                self._connect_finished(op_id)
                self._emit_state()
                self._emit({"type": "warning", "code": warning.code, "message": str(warning)} if warning
                           else {"type": "saved", "scope": "connect"})
                self._start_health_monitor(instance)
                instance = None  # Ownership has moved to the active connection.
            self._log("connected", endpoint=result.endpoint, exit_code=None)
        except AppError as error:
            if error.code == "cancelled" or cancel.is_set():
                with self._lock:
                    if self._connect_current_locked(op_id):
                        self._state = ConnectionState.DISCONNECTED
                        self._emit_state()
            else:
                self._connect_failure(op_id, error)
        except Exception:
            self._connect_failure(op_id, AppError("connect_failed", "Подключение прервано внутренней ошибкой."))
        finally:
            if instance is not None:
                self._stop(instance)
            self._connect_finished(op_id)

    def _disconnect_worker(self, active):
        try:
            if active is not None:
                self._stop(active)
        finally:
            with self._lock:
                self._disconnecting = False
            # Each backend owns its config. Global runtime cleanup is only
            # safe at close, never while another operation can start a trial.
            self._emit_state()

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
        with self._lock:
            # Checking the operation and writing its result is one transaction
            # against cancel_search/disconnect/close, including late successes.
            if outcome.cancelled or cancel.is_set() or not self._search_current(op_id):
                self._search_end(op_id)
                self._emit({"type": "search_cancelled"})
                return
            if not outcome.results:
                self._search_end(op_id)
                self._emit({"type": "search_done", "found": 0, "checked": outcome.checked, "saved": False,
                            "code": "no_working_endpoint",
                            "message": "Рабочие эндпоинты не найдены; сохранённые варианты не изменены."})
                return
            warning = self._commit_search(self._storage.load_cache(), outcome.results)
            self._search_end(op_id)
            self._emit({"type": "search_done", "found": len(outcome.results), "checked": outcome.checked,
                        "saved": warning is None, "role": role,
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

    def _start_health_monitor(self, instance):
        self._health_stop = threading.Event()
        stop = self._health_stop
        self._spawn(lambda: self._health_loop(instance, stop), daemon=True)

    def _health_loop(self, instance, stop):
        failures = 0
        while not stop.wait(self._health_interval):
            with self._lock:
                if self._active is not instance or self._closed or self._state != ConnectionState.CONNECTED:
                    return
            if instance.process.poll() is not None:
                self._health_failure(instance, stop, "proxy_exited", "Сетевой компонент неожиданно завершился.")
                return
            try:
                self._health(instance.port, cancel=stop)
                failures = 0
            except AppError:
                if stop.is_set():
                    return
                failures += 1
                if failures >= self._health_failures:
                    self._health_failure(instance, stop, "connection_lost", "Соединение WARP перестало отвечать; прокси остановлен.")
                    return

    def _health_failure(self, instance, stop, code: str, message: str):
        with self._lock:
            if self._closed or stop.is_set() or self._active is not instance:
                return
            self._active = None
            self._disconnecting = True
            self._active_result = None
            self._state = ConnectionState.ERROR
            self._state_detail = (code, message)
        stop.set()
        try:
            self._stop(instance)
        finally:
            with self._lock:
                self._disconnecting = False
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
            if self._connect_op == op_id:
                self._connect_cancel = None
                self._connect_op = None

    def _connect_failure(self, op_id: int, error: AppError):
        with self._lock:
            current = self._connect_current_locked(op_id)
            if current:
                self._state = ConnectionState.ERROR
                self._state_detail = (error.code, str(error))
                self._connect_finished(op_id)
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
                log_event(self._logger, code, **fields)
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
