#!/usr/bin/env python3
"""Exercise a Windows onefile EXE without relying on the source tree or tasklist.

The safety Job Objects below are *not* the ownership mechanism under test. They
remain open throughout verification and are terminated only after a failure has
been recorded. Suspended creation makes even a launch with no report containable.
Only the application's inner GUI handle is terminated during the actual test.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


COMMON_CHECKS = frozenset({
    "tk", "ui", "tls_bundle", "licenses", "wgcf_binary", "wireproxy_binary",
    "wgcf_help", "socks_started", "helper_alive",
})
GRACEFUL_CHECKS = COMMON_CHECKS | {"helper_stopped", "runtime_clean", "window_closed"}
REPORT_FIELDS = frozenset({
    "schema_version", "mode", "ok", "pid", "frozen", "checks", "child_pid",
    "port", "workspace", "error_code",
})
SOURCE_ROOT = Path(__file__).resolve().parents[1]
SYNCHRONIZE = 0x00100000
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
MAX_REPORT_BYTES = 64 * 1024


class SmokeFailure(Exception):
    """A driver-controlled code, never an exception message from the application."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Timeouts:
    graceful: float = 180
    report: float = 120
    launcher: float = 60
    child: float = 30
    port: float = 30
    cleanup: float = 10
    poll: float = 0.1


@dataclass(frozen=True)
class Report:
    mode: str
    ok: bool
    pid: int
    frozen: bool
    checks: dict[str, bool]
    child_pid: int | None
    port: int | None
    workspace: Path
    error_code: str | None


def _pid(value) -> bool:
    return type(value) is int and 0 < value <= 0xFFFFFFFF


def _workspace(value, out: Path) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise SmokeFailure("workspace_invalid")
    path = Path(value)
    if not path.is_absolute():
        raise SmokeFailure("workspace_invalid")
    path = path.resolve()
    root = out.resolve()
    if path == root or not path.is_relative_to(root):
        raise SmokeFailure("workspace_outside_output")
    return path


def _validate_report(data, mode: str, out: Path) -> Report:
    if type(data) is not dict or set(data) != REPORT_FIELDS:
        raise SmokeFailure("report_schema_invalid")
    checks = data["checks"]
    expected = GRACEFUL_CHECKS if mode == "graceful" else COMMON_CHECKS
    if (
        type(data["schema_version"]) is not int or data["schema_version"] != 1
        or data["mode"] != mode or type(data["ok"]) is not bool
        or type(data["frozen"]) is not bool or not _pid(data["pid"])
        or (data["child_pid"] is not None and not _pid(data["child_pid"]))
        or (data["port"] is not None and not (
            type(data["port"]) is int and 1 <= data["port"] <= 65535
        ))
        or type(checks) is not dict or not set(checks).issubset(expected)
        or any(type(value) is not bool for value in checks.values())
        or (data["error_code"] is not None and type(data["error_code"]) is not str)
    ):
        raise SmokeFailure("report_schema_invalid")
    return Report(
        mode, data["ok"], data["pid"], data["frozen"], dict(checks),
        data["child_pid"], data["port"], _workspace(data["workspace"], out),
        data["error_code"],
    )


def _require_success(report: Report) -> None:
    required = GRACEFUL_CHECKS if report.mode == "graceful" else COMMON_CHECKS
    if not report.ok or report.error_code is not None:
        raise SmokeFailure("smoke_not_ok")
    if not report.frozen:
        raise SmokeFailure("not_frozen")
    if not required.issubset(report.checks) or any(
        report.checks[name] is not True for name in required
    ):
        raise SmokeFailure("required_checks_failed")
    if report.mode == "wait" and (report.child_pid is None or report.port is None):
        raise SmokeFailure("wait_identity_missing")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SmokeFailure("report_schema_invalid")
        result[key] = value
    return result


def _read_report(path: Path, mode: str, out: Path, not_before_ns: int) -> Report:
    if path.is_symlink():
        raise SmokeFailure("report_file_invalid")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise SmokeFailure("report_file_invalid")
        if info.st_mtime_ns < not_before_ns:
            raise SmokeFailure("report_stale")
        encoded = stream.read(MAX_REPORT_BYTES + 1)
    if len(encoded) > MAX_REPORT_BYTES:
        raise SmokeFailure("report_file_invalid")
    try:
        data = json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError):
        raise SmokeFailure("report_json_invalid") from None
    return _validate_report(data, mode, out)


def _wait_for_report(path, mode, out, not_before_ns, launcher, timeouts) -> Report:
    deadline = time.monotonic() + timeouts.report
    while True:
        try:
            return _read_report(path, mode, out, not_before_ns)
        except FileNotFoundError:
            if launcher.process.exited(0):
                raise SmokeFailure("report_missing") from None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("report_timeout")
        time.sleep(min(timeouts.poll, remaining))


def _port_open(port: int) -> bool:
    # The report carries only a port, never a host that could escape loopback.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        return client.connect_ex(("127.0.0.1", port)) == 0


def _eventually(predicate, timeout: float, interval: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(interval, remaining))


# Defined on all platforms so native calls can be tested with fakes on Linux.
class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


class _BASIC_LIMITS(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class _EXTENDED_LIMITS(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BASIC_LIMITS), ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _ACCOUNTING(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class Windows:
    def __init__(self, kernel=None):
        if kernel is None:
            if sys.platform != "win32":
                raise SmokeFailure("windows_required")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        for name, restype, argtypes in (
            ("OpenProcess", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
            ("WaitForSingleObject", wintypes.DWORD, [wintypes.HANDLE, wintypes.DWORD]),
            ("TerminateProcess", wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
            ("GetExitCodeProcess", wintypes.BOOL,
             [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]),
            ("CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
            ("CreateJobObjectW", wintypes.HANDLE, [wintypes.LPVOID, wintypes.LPCWSTR]),
            ("SetInformationJobObject", wintypes.BOOL,
             [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]),
            ("AssignProcessToJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]),
            ("IsProcessInJob", wintypes.BOOL,
             [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]),
            ("QueryInformationJobObject", wintypes.BOOL,
             [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
              ctypes.POINTER(wintypes.DWORD)]),
            ("TerminateJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
            ("CreateProcessW", wintypes.BOOL,
             [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
              wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
              ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION)]),
            ("ResumeThread", wintypes.DWORD, [wintypes.HANDLE]),
        ):
            function = getattr(kernel, name)
            function.restype = restype
            function.argtypes = argtypes

    @staticmethod
    def check(value, code="native_operation_failed"):
        if not value:
            raise SmokeFailure(code)
        return value

    def open_process(self, pid: int, *, terminate: bool = False):
        if not _pid(pid) or pid == os.getpid():
            raise SmokeFailure("process_identity_invalid")
        rights = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
        if terminate:
            rights |= PROCESS_TERMINATE
        handle = self.check(self.kernel.OpenProcess(rights, False, pid), "process_open_failed")
        return ProcessHandle(self, handle, pid)

    def launch(self, argv: list[str], cwd: Path):
        job = self.check(self.kernel.CreateJobObjectW(None, None), "job_create_failed")
        info = _PROCESS_INFORMATION()
        transferred = False
        try:
            limits = _EXTENDED_LIMITS()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            self.check(self.kernel.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits),
            ))
            startup = _STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            self.check(self.kernel.CreateProcessW(
                argv[0], command, None, None, False, 0x08000004, None, str(cwd),
                ctypes.byref(startup), ctypes.byref(info),
            ), "process_create_failed")  # CREATE_NO_WINDOW | CREATE_SUSPENDED
            self.check(self.kernel.AssignProcessToJobObject(job, info.hProcess), "job_assign_failed")
            if self.kernel.ResumeThread(info.hThread) == 0xFFFFFFFF:
                raise SmokeFailure("process_resume_failed")
            launch = Launch(self, job, ProcessHandle(self, info.hProcess, info.dwProcessId))
            transferred = True
            return launch
        finally:
            if info.hThread:
                self.kernel.CloseHandle(info.hThread)
            if not transferred:
                # The launcher is still suspended: no application child can exist.
                if info.hProcess:
                    self.kernel.TerminateProcess(info.hProcess, 1)
                    self.kernel.WaitForSingleObject(info.hProcess, 10000)
                    self.kernel.CloseHandle(info.hProcess)
                self.kernel.CloseHandle(job)


class ProcessHandle:
    def __init__(self, native: Windows, handle, pid: int):
        self.native, self.handle, self.pid = native, handle, pid

    def exited(self, timeout: float) -> bool:
        milliseconds = min(0xFFFFFFFE, max(0, math.ceil(timeout * 1000)))
        result = self.native.kernel.WaitForSingleObject(self.handle, milliseconds)
        if result not in (WAIT_OBJECT_0, WAIT_TIMEOUT):
            raise SmokeFailure("process_wait_failed")
        return result == WAIT_OBJECT_0

    def exit_code(self) -> int:
        if not self.exited(0):
            raise SmokeFailure("process_not_exited")
        code = wintypes.DWORD()
        self.native.check(self.native.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)))
        return code.value

    def terminate(self):
        self.native.check(self.native.kernel.TerminateProcess(self.handle, 1), "process_terminate_failed")

    def belongs_to(self, launch) -> bool:
        member = wintypes.BOOL()
        self.native.check(self.native.kernel.IsProcessInJob(self.handle, launch.job, ctypes.byref(member)))
        return bool(member.value)

    def close(self):
        if self.handle is not None:
            self.native.check(self.native.kernel.CloseHandle(self.handle), "handle_close_failed")
            self.handle = None


class Launch:
    def __init__(self, native: Windows, job, process: ProcessHandle):
        self.native, self.job, self.process = native, job, process

    def empty(self) -> bool:
        info = _ACCOUNTING()
        self.native.check(self.native.kernel.QueryInformationJobObject(
            self.job, 1, ctypes.byref(info), ctypes.sizeof(info), None,
        ))
        return info.ActiveProcesses == 0

    def teardown(self, timeout: float, poll: float):
        try:
            self.native.check(self.native.kernel.TerminateJobObject(self.job, 1), "job_terminate_failed")
            if not _eventually(self.empty, timeout, poll) or not self.process.exited(0):
                raise SmokeFailure("cleanup_timeout")
        except Exception:
            # KILL_ON_JOB_CLOSE is a last resort if termination/querying failed.
            # Retain the launcher's process handle until the fallback has run.
            self._close_job()
            self.process.exited(timeout)
            raise

    def _close_job(self):
        if self.job is not None:
            self.native.check(self.native.kernel.CloseHandle(self.job), "handle_close_failed")
            self.job = None

    def close(self):
        try:
            self._close_job()
        finally:
            self.process.close()


def _snapshot(report: Report) -> dict:
    # Never copy arbitrary fields, workspace contents, error text, or exception messages.
    return {"ok": False, "reported_ok": report.ok, "frozen": report.frozen,
            "checks": {name: report.checks[name] for name in sorted(report.checks)}}


def _filesystem_timestamp(directory: Path) -> int:
    # Windows' precise wall clock and filesystem metadata do not necessarily
    # advance together. Use a closed marker on the same filesystem, preserving
    # the strict stale-report check without falsely rejecting a fresh report.
    fd, name = tempfile.mkstemp(prefix=".launch-", dir=directory)
    os.close(fd)
    marker = Path(name)
    try:
        return marker.stat().st_mtime_ns
    finally:
        marker.unlink()


def _run_checks(copied, out, cwd, native, result, launches, handles, workspaces, timeouts):
    for mode, option, filename, key in (
        ("graceful", "--smoke", "graceful.json", "graceful"),
        ("wait", "--smoke-wait", "wait.json", "forced_kill"),
    ):
        path = out / filename
        path.unlink(missing_ok=True)
        started_ns = _filesystem_timestamp(out)
        launch = native.launch([str(copied), option, str(path)], cwd)
        launches.append(launch)
        phase = result[key] = {"ok": False, "launcher_pid": launch.process.pid}
        if mode == "graceful":
            if not launch.process.exited(timeouts.graceful):
                raise SmokeFailure("graceful_timeout")
            phase["exit_code"] = launch.process.exit_code()
        report = _wait_for_report(path, mode, out, started_ns, launch, timeouts)
        workspaces.add(report.workspace)
        phase.update(_snapshot(report))
        _require_success(report)
        if mode == "graceful":
            if phase["exit_code"] != 0:
                raise SmokeFailure("graceful_exit_nonzero")
        else:
            inner, child = report.pid, report.child_pid
            phase.update({"inner_pid": inner, "child_pid": child, "port": report.port})
            if len({inner, child, launch.process.pid, os.getpid()}) != 4:
                raise SmokeFailure("process_identity_invalid")
            gui = native.open_process(inner, terminate=True)
            handles.append(gui)
            helper = native.open_process(child)
            handles.append(helper)
            if not gui.belongs_to(launch) or not helper.belongs_to(launch):
                raise SmokeFailure("process_not_owned")
            phase["gui_live"] = not gui.exited(0)
            phase["child_live"] = not helper.exited(0)
            if launch.process.exited(0) or not phase["gui_live"] or not phase["child_live"]:
                raise SmokeFailure("wait_process_not_live")
            if not _port_open(report.port):
                raise SmokeFailure("socks_not_listening")
            gui.terminate()  # Deliberately no job/tree kill and no helper termination.
            if not gui.exited(timeouts.launcher):
                raise SmokeFailure("gui_exit_timeout")
            if not launch.process.exited(timeouts.launcher):
                raise SmokeFailure("launcher_exit_timeout")
            phase["launcher_exit"] = launch.process.exit_code()
            phase["child_stopped"] = helper.exited(timeouts.child)
            if not phase["child_stopped"]:
                raise SmokeFailure("helper_survived_gui")
            phase["port_closed"] = _eventually(
                lambda: not _port_open(report.port), timeouts.port, timeouts.poll,
            )
            if not phase["port_closed"]:
                raise SmokeFailure("socks_port_still_open")
        if not _eventually(launch.empty, timeouts.child, timeouts.poll):
            raise SmokeFailure("owned_processes_remain")
        phase["ok"] = True


def _remove_workspace(path: Path, out: Path, copied: Path):
    # Re-resolve immediately before removal; never follow a changed symlink/junction
    # outside out, delete out itself, or remove the copied executable's directory.
    resolved = _workspace(str(path), out)
    if resolved != path or copied.is_relative_to(resolved):
        raise SmokeFailure("workspace_cleanup_unsafe")
    if resolved.exists():
        shutil.rmtree(resolved)


def _write_summary(out: Path, result: dict):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=out, prefix="summary-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(out / "summary.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_ci(exe: Path, out: Path, *, native=None, timeouts: Timeouts = Timeouts()) -> int:
    result = {"schema_version": 1, "ok": False, "graceful": None,
              "forced_kill": None, "error_code": None,
              "cleanup": {"ok": True, "error_codes": []}}
    launches, handles, workspaces = [], [], set()
    cwd_context = None
    out = out.resolve()
    copied = out / "Копия WarpPocket" / "WarpPocket.exe"
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").unlink(missing_ok=True)
        if sys.platform != "win32":
            raise SmokeFailure("windows_required")
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(exe.resolve(), copied)
        cwd_context = tempfile.TemporaryDirectory(prefix="warppocket-ci-cwd-")
        cwd = Path(cwd_context.name).resolve()
        if cwd.is_relative_to(SOURCE_ROOT):
            raise SmokeFailure("working_directory_inside_source")
        _run_checks(copied, out, cwd, native if native is not None else Windows(),
                    result, launches, handles, workspaces, timeouts)
        result["ok"] = True
    except (Exception, KeyboardInterrupt) as error:
        result["error_code"] = error.code if isinstance(error, SmokeFailure) else (
            "interrupted" if isinstance(error, KeyboardInterrupt) else "driver_failed"
        )
    finally:
        # Record failure BEFORE emergency teardown. A helper killed here can never
        # turn a failed ownership assertion into a passing result.
        for launch in reversed(launches):
            if not result["ok"]:
                try:
                    launch.teardown(timeouts.cleanup, timeouts.poll)
                except Exception:
                    result["cleanup"]["error_codes"].append("process_cleanup_failed")
        for owned in [*reversed(handles), *reversed(launches)]:
            try:
                owned.close()
            except Exception:
                result["cleanup"]["error_codes"].append("handle_cleanup_failed")
        for workspace in sorted(workspaces):
            try:
                _remove_workspace(workspace, out, copied)
            except Exception:
                result["cleanup"]["error_codes"].append("workspace_cleanup_failed")
        if cwd_context is not None:
            try:
                cwd_context.cleanup()
            except Exception:
                result["cleanup"]["error_codes"].append("working_directory_cleanup_failed")
        result["cleanup"]["ok"] = not result["cleanup"]["error_codes"]
        if not result["cleanup"]["ok"]:
            result["ok"] = False
            result["error_code"] = result["error_code"] or "cleanup_failed"
        try:
            _write_summary(out, result)
        except Exception:
            # An unwritable output cannot contain a summary; still emit only safe
            # fields and fail rather than exposing filesystem/exception text.
            result["ok"] = False
            result["error_code"] = "summary_write_failed"
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else (2 if result["error_code"] == "windows_required" else 1)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_ci(args.exe, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
