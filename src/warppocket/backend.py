from __future__ import annotations

import platform
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from warppocket.models import AppError, Endpoint, Profile
from warppocket.profiles import render_profile
from warppocket.process_manager import ProcessCancelled
from warppocket.storage import AppPaths, atomic_write


def bundled_root() -> Path:
    return Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]


def bundled_binary(name: str) -> Path:
    if platform.machine().lower() not in ("amd64", "x86_64") or sys.platform not in ("linux", "win32"):
        raise AppError("platform_unsupported", "Поддерживаются Windows/Linux x64.")
    root = bundled_root()
    target = "windows-amd64" if sys.platform == "win32" else "linux-amd64"
    result = root / "vendor" / target / (name + (".exe" if sys.platform == "win32" else ""))
    if not result.is_file():
        raise AppError("helper_missing", "Не найден встроенный компонент; для разработки запустите scripts/fetch_vendor.py.")
    return result.resolve()


@dataclass
class ProxyInstance:
    process: object
    config: Path
    endpoint: Endpoint
    port: int
    role: str

    @property
    def pid(self):
        return self.process.pid


class WireProxyBackend:
    def __init__(self, paths: AppPaths, manager, binary: Path | None = None):
        self.paths, self.manager = paths, manager
        self.binary = binary or bundled_binary("wireproxy")

    def start(self, profile: Profile, endpoint: Endpoint, *, role: str, port: int | None = None,
              cancel: threading.Event | None = None) -> ProxyInstance:
        cancel = cancel or threading.Event()
        for attempt in range(3 if port is None else 1):
            if cancel.is_set():
                raise AppError("cancelled", "Операция отменена.")
            with socket.socket() as reservation:
                if sys.platform == "win32":
                    reservation.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                elif sys.platform == "linux":
                    # Match Go's listener: closed SOCKS sessions may leave TIME_WAIT.
                    reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    reservation.bind(("127.0.0.1", port or 0))
                except OSError:
                    raise AppError("port_busy", "Порт SOCKS5 занят другим приложением; чужой процесс не будет завершён.") from None
                chosen_port = reservation.getsockname()[1]
            config = self.paths.run / f"{role}-{uuid.uuid4().hex}.conf"
            content = render_profile(profile, endpoint) + f"\n[Socks5]\nBindAddress = 127.0.0.1:{chosen_port}\n\n[Resolve]\nResolveStrategy = ipv4\n"
            atomic_write(config, content.encode("utf-8"))
            process = None
            try:
                process = self.manager.start([str(self.binary), "--config", str(config), "--silent"],
                                             cwd=self.paths.run, cancel=cancel)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if cancel.is_set():
                        raise AppError("cancelled", "Операция отменена.")
                    if process.poll() is not None:
                        raise AppError("proxy_start_failed", "Сетевой компонент завершился при запуске.")
                    try:
                        with socket.create_connection(("127.0.0.1", chosen_port), timeout=0.2) as connection:
                            connection.sendall(b"\x05\x01\x00")
                            if connection.recv(2) == b"\x05\x00" and process.poll() is None:
                                return ProxyInstance(process, config, endpoint, chosen_port, role)
                    except OSError:
                        pass
                    cancel.wait(0.03)
                raise AppError("proxy_start_timeout", "SOCKS5 не запустился за отведённое время.")
            except BaseException as error:
                if process is not None:
                    self.manager.stop(process)
                config.unlink(missing_ok=True)
                if isinstance(error, ProcessCancelled):
                    raise AppError("cancelled", "Запуск прокси отменён.") from None
                if port is None and attempt < 2 and isinstance(error, AppError) and error.code == "proxy_start_failed":
                    continue
                raise
        raise AppError("proxy_start_failed", "Не удалось запустить проверочный SOCKS5.")

    def stop(self, instance: ProxyInstance):
        try:
            self.manager.stop(instance.process)
        finally:
            instance.config.unlink(missing_ok=True)
