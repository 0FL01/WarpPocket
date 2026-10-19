"""Offline checks inside the actual application / onefile GUI process.

Only a synthetic WireGuard profile and a loopback UDP endpoint are used. No
registration, system proxy changes, or internet health checks are performed.
The wait mode leaves a Job-owned helper alive for the external crash test.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile

import certifi

from warppocket.backend import WireProxyBackend, bundled_binary, bundled_root
from warppocket.controller import Controller
from warppocket.models import AppError, Endpoint, Profile
from warppocket.process_manager import InstanceLock, ProcessManager
from warppocket.profiles import ProfileService
from warppocket.storage import AppPaths, Storage, atomic_write
from warppocket.strategy_finder import StrategyFinder
from warppocket.ui import WarpPocketApp

LICENSE_FILES = ("NOTICE.md", "wireproxy-LICENSE.txt", "wgcf-LICENSE.txt", "ros-scripts-LICENSE.txt")


def _synthetic_profile() -> Profile:
    return Profile(
        private_key=base64.b64encode(bytes(range(32))).decode("ascii"),
        addresses=("172.16.0.2/32",), dns=("1.1.1.1",),
        public_key=base64.b64encode(bytes(range(32, 64))).decode("ascii"),
        endpoint=Endpoint("127.0.0.1", 9), allowed_ips=("0.0.0.0/0",),
    )


def _write_report(path: Path, report: dict) -> None:
    atomic_write(path, json.dumps(report, indent=2, allow_nan=False).encode("utf-8"))


def _no_network(*args, **kwargs):
    raise AppError("offline_smoke", "Сетевые проверки отключены в offline smoke.")


def run_smoke(report_path: Path, *, wait: bool = False) -> int:
    report_path = report_path.resolve()
    checks: dict[str, bool] = {}
    report = {
        "schema_version": 1, "mode": "wait" if wait else "graceful", "ok": False,
        "pid": os.getpid(), "frozen": bool(getattr(sys, "frozen", False)),
        "checks": checks, "child_pid": None, "port": None,
        "workspace": "", "error_code": None,
    }
    manager, controller, app, root, lock, workspace = None, None, None, None, None, None
    watchdog = None
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        # Put disposable state under the driver's own output directory. The
        # driver can remove this one workspace after the deliberate crash.
        workspace = Path(tempfile.mkdtemp(prefix="runtime-", dir=report_path.parent))
        report["workspace"] = str(workspace)
        paths = AppPaths(workspace)
        lock = InstanceLock(paths.root)
        lock.acquire()
        storage = Storage(paths)
        manager = ProcessManager()
        wgcf, wireproxy = bundled_binary("wgcf"), bundled_binary("wireproxy")
        checks.update(wgcf_binary=wgcf.is_file(), wireproxy_binary=wireproxy.is_file(),
                      tls_bundle=Path(certifi.where()).is_file(),
                      licenses=all((bundled_root() / "vendor/licenses" / name).is_file()
                                   for name in LICENSE_FILES))
        help_process = manager.start([str(wgcf), "--help"], cwd=workspace)
        checks["wgcf_help"] = help_process.wait(15) == 0
        backend = WireProxyBackend(paths, manager, wireproxy)
        profile = _synthetic_profile()
        instance = backend.start(profile, profile.endpoint, role="primary")
        report.update(child_pid=instance.pid, port=instance.port)
        checks.update(socks_started=True, helper_alive=instance.process.poll() is None)

        import tkinter as tk

        root = tk.Tk()
        checks["tk"] = True
        controller = Controller(
            storage=storage, profiles=ProfileService(storage, manager, wgcf),
            backend=backend, finder=StrategyFinder(backend, _no_network),
            manager=manager, health=_no_network,
        )
        app = WarpPocketApp(controller, root=root, confirm=lambda *_: False)
        root.title("WarpPocket — offline smoke")

        def ready():
            try:
                app._render()
                checks["ui"] = root.winfo_exists() == 1 and bool(app._status.cget("text"))
                report["ok"] = bool(checks) and all(checks.values())
                _write_report(report_path, report)
            except Exception:
                report.update(ok=False, error_code="smoke_ui_failed")
            if not wait or not report["ok"]:
                app.close()

        # Runs only after the real Tk loop has started. In wait mode we keep
        # pumping the same GUI; the driver terminates os.getpid(), not its
        # outer PyInstaller launcher. A watchdog bounds failed driver runs.
        root.after(150, ready)
        watchdog = root.after(180_000, app.close)
        app.run()
        checks["window_closed"] = app._close_done.is_set()
        checks["helper_stopped"] = instance.process.poll() is not None
        with socket.socket() as connection:
            connection.settimeout(1)
            checks["runtime_clean"] = (not instance.config.exists()
                                       and connection.connect_ex(("127.0.0.1", instance.port)) != 0)
        report["ok"] = not wait and all(checks.values())
        if wait:
            report["error_code"] = "wait_ended_without_crash"
    except Exception as error:
        # Never write exception text, argv or profile contents into artifacts.
        report["error_code"] = error.code if isinstance(error, AppError) else "smoke_failed"
        report["ok"] = False
    finally:
        try:
            if controller is not None:
                controller.close()
            if manager is not None:
                manager.shutdown()
            if app is not None:
                app.stop_pump()
            if root is not None:
                try:
                    if watchdog is not None:
                        root.after_cancel(watchdog)
                except Exception:
                    pass
                try:
                    root.destroy()
                except Exception:
                    pass  # The normal UI close has already destroyed Tcl.
            if lock is not None:
                lock.release()
            if workspace is not None:
                shutil.rmtree(workspace)
        except Exception:
            report.update(ok=False, error_code="smoke_cleanup_failed")
        _write_report(report_path, report)
    return 0 if report["ok"] else 1
