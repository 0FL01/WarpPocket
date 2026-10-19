#!/usr/bin/env python3
"""Opt-in live gate. Never run this on ordinary CI or without explicit consent."""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from warppocket.backend import WireProxyBackend, bundled_binary
from warppocket.healthcheck import check_proxy
from warppocket.models import AppError, Cache, CheckResult, Endpoint
from warppocket.process_manager import InstanceLock, ProcessManager
from warppocket.profiles import ProfileService
from warppocket.storage import AppPaths, Storage, atomic_write


def run(args):
    paths = AppPaths(args.data_dir.expanduser().resolve())
    storage = Storage(paths)
    report = {"passed": False, "stages": [], "primary_requests": 0, "probe_attempts": 0}
    manager = ProcessManager()
    traffic_stop, traffic_failures = threading.Event(), []

    def stage(name, **fields):
        report["stages"].append({"stage": name, **fields})
        print(json.dumps(report["stages"][-1], ensure_ascii=False), flush=True)

    try:
        with InstanceLock(paths.root):
            paths_run_gate(storage, manager, report, args, stage, traffic_stop, traffic_failures)
        report["passed"] = True
    except AppError as error:
        report["error"] = error.code
        report["message"] = str(error)
    except KeyboardInterrupt:
        report["error"] = "cancelled"
    except Exception:
        # No helper output, account data or arbitrary exception strings in reports.
        report["error"] = "runtime_error"
    finally:
        manager.shutdown()
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(args.report, json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["passed"] else 1


def paths_run_gate(storage, manager, report, args, stage, traffic_stop, traffic_failures):
    storage.clear_runtime()
    storage.load_cache()
    profiles = ProfileService(storage, manager, bundled_binary("wgcf"))
    backend = WireProxyBackend(storage.paths, manager)
    active, traffic_thread = None, None
    cancel = threading.Event()
    used_ports = set()
    try:
        profiles.ensure_profile("primary", consent=args.accept_tos, cancel=cancel)
        primary = profiles.ensure_reserved("primary", cancel=cancel)
        stage("primary_profile_ready")
        candidates = list(dict.fromkeys([primary.endpoint, *args.endpoint,
                                        Endpoint("162.159.192.1", 2408), Endpoint("162.159.193.1", 2408),
                                        Endpoint("162.159.195.1", 2408), Endpoint("162.159.192.1", 500),
                                        Endpoint("188.114.96.1", 2408)]))

        def connect(excluded=()):
            deadline = time.monotonic() + 180
            for endpoint in candidates[:30]:
                if endpoint in excluded or time.monotonic() >= deadline:
                    continue
                instance = backend.start(primary, endpoint, role="primary", port=25344, cancel=cancel)
                used_ports.add(instance.port)
                try:
                    latency = check_proxy(instance.port, cancel=cancel)
                    if instance.process.poll() is not None:
                        raise AppError("proxy_exited", "Прокси завершился во время проверки.")
                    stage("primary_verified", endpoint=str(endpoint), latency_ms=round(latency, 2), pid=instance.pid)
                    return instance, latency
                except AppError as error:
                    stage("candidate_failed", endpoint=str(endpoint), code=error.code)
                    backend.stop(instance)
            raise AppError("no_working_endpoint", "Ни один ограниченно проверенный endpoint не прошёл обе HTTPS-проверки.")

        active, _ = connect()
        first = active.endpoint
        backend.stop(active)
        active = None
        stage("first_process_stopped")
        active, latency = connect(excluded=(first,))
        second = active.endpoint
        storage.save_cache(Cache(last_good=CheckResult.now(second, latency, "primary")))
        backend.stop(active)
        active = None
        primary_again = profiles.ensure_profile("primary", consent=False, cancel=cancel)
        if primary_again.identity() != primary.identity():
            raise AppError("profile_changed", "Сохранённый профиль неожиданно изменился.")
        active = backend.start(primary_again, storage.load_cache().last_good.endpoint, role="primary", port=25344, cancel=cancel)
        check_proxy(active.port)
        original_pid = active.pid
        original_profile = (storage.paths.profile_dir("primary") / "profile.conf").read_bytes()
        stage("profile_reused_without_registration", pid=original_pid)

        def traffic():
            while not traffic_stop.is_set():
                try:
                    check_proxy(active.port, cancel=traffic_stop)
                    report["primary_requests"] += 1
                except AppError as error:
                    if not traffic_stop.is_set():
                        traffic_failures.append(error.code)
                        return
                traffic_stop.wait(0.3)

        traffic_thread = threading.Thread(target=traffic, name="e2e-primary-traffic")
        traffic_thread.start()
        profiles.ensure_profile("probe", consent=args.accept_probe_tos, cancel=cancel)
        probe = profiles.ensure_reserved("probe", cancel=cancel)
        stage("probe_profile_ready")
        probe_successes = 0
        for endpoint in candidates[:6]:
            instance = backend.start(probe, endpoint, role="probe", cancel=cancel)
            used_ports.add(instance.port)
            try:
                check_proxy(instance.port, cancel=cancel)
                probe_successes += 1
                stage("probe_verified", endpoint=str(endpoint))
            except AppError as error:
                stage("probe_failed", endpoint=str(endpoint), code=error.code)
            finally:
                backend.stop(instance)
                report["probe_attempts"] += 1
            if probe_successes and report["probe_attempts"] >= 2:
                break
        deadline = time.monotonic() + 35
        while report["primary_requests"] < 2 and not traffic_failures and time.monotonic() < deadline:
            time.sleep(0.1)
        if not probe_successes:
            raise AppError("probe_unavailable", "Отдельный проверочный профиль не прошёл сетевой gate.")
        if traffic_failures or report["primary_requests"] < 2:
            raise AppError("primary_traffic_interrupted", "Непрерывность основного HTTPS-трафика не подтверждена.")
        if active.pid != original_pid or active.port != 25344 or active.process.poll() is not None or original_profile != (storage.paths.profile_dir("primary") / "profile.conf").read_bytes():
            raise AppError("active_changed", "Фоновая проверка изменила активное подключение.")
        stage("primary_preserved", pid=original_pid, port=active.port)
    finally:
        traffic_stop.set()
        if active is not None:
            backend.stop(active)
        if traffic_thread is not None:
            traffic_thread.join(35)
        manager.shutdown()
        storage.clear_runtime()
        for port in used_ports:
            with socket.socket() as connection:
                if connection.connect_ex(("127.0.0.1", port)) == 0:
                    raise AppError("listener_leaked", "После завершения остался слушающий порт.")
        stage("cleanup_verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True, help="isolated private persistent directory")
    parser.add_argument("--accept-tos", action="store_true", help="accept https://www.cloudflare.com/application/terms/ for primary")
    parser.add_argument("--accept-probe-tos", action="store_true", help="separate consent for second WARP identity")
    parser.add_argument("--endpoint", type=Endpoint.parse, action="append", default=[])
    parser.add_argument("--report", type=Path)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
