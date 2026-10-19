"""WarpPocket entry point: single instance, private data directory, Tk UI."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from warppocket import __version__
from warppocket.backend import WireProxyBackend, bundled_binary
from warppocket.controller import Controller
from warppocket.diagnostics import create_logger
from warppocket.healthcheck import check_proxy
from warppocket.models import AppError
from warppocket.process_manager import InstanceLock, ProcessManager
from warppocket.profiles import ProfileService
from warppocket.storage import AppPaths, Storage
from warppocket.strategy_finder import StrategyFinder
from warppocket.ui import WarpPocketApp


def _fatal(message: str) -> None:
    """Report a startup failure without depending on the main window."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("WarpPocket", message)
        root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def _diagnostics_text(paths: AppPaths) -> str:
    return "\n".join([
        f"WarpPocket {__version__}",
        f"Каталог данных: {paths.root}",
        f"Диагностический лог: {paths.logs / 'diagnostics.log'}",
        f"Профиль primary: {paths.profile_dir('primary')}",
        f"Профиль probe: {paths.profile_dir('probe')}",
        "Ключи, токены и содержимое профилей в диагностику не выводятся.",
    ])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="WarpPocket", description="Локальный SOCKS5 через Cloudflare WARP.")
    parser.add_argument("--data-dir", type=Path, help="каталог данных (по умолчанию — системный)")
    smoke = parser.add_mutually_exclusive_group()
    smoke.add_argument("--smoke", type=Path, help="автономная проверка сборки и выход")
    smoke.add_argument("--smoke-wait", type=Path, help="проверка сборки с ожиданием принудительного завершения")
    args = parser.parse_args(argv)

    if args.smoke or args.smoke_wait:
        from warppocket.smoke import run_smoke

        target = args.smoke or args.smoke_wait
        return run_smoke(target.expanduser().resolve(), wait=bool(args.smoke_wait))

    paths = AppPaths(args.data_dir.expanduser().resolve()) if args.data_dir else AppPaths.default()

    lock = InstanceLock(paths.root)
    try:
        lock.acquire()
    except RuntimeError:
        _fatal("WarpPocket уже запущен или каталог данных недоступен.")
        return 1

    controller = None
    try:
        try:
            bundled_binary("wgcf")
            bundled_binary("wireproxy")
        except AppError as error:
            _fatal(str(error))
            return 1
        storage = Storage(paths)
        logger = create_logger(paths)
        manager = ProcessManager()
        backend = WireProxyBackend(paths, manager)
        profiles = ProfileService(storage, manager, bundled_binary("wgcf"))
        finder = StrategyFinder(backend, check_proxy)
        controller = Controller(
            storage=storage, profiles=profiles, backend=backend, finder=finder,
            manager=manager, health=check_proxy, logger=logger,
        )
        app = WarpPocketApp(
            controller,
            importer=lambda source, role: profiles.import_profile(Path(source), role),
            diagnostics=lambda: _diagnostics_text(paths),
        )
        app.run()
    except AppError as error:
        _fatal(str(error))
        return 1
    finally:
        if controller is not None:
            try:
                controller.close()
            except Exception:
                pass
        lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
