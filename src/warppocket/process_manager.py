"""Owned, output-silent helper processes for Windows and Linux.

Windows children enter a private kill-on-close Job Object *during* creation.
Linux children use an ordinary process group: unlike a Windows job, that group
does not provide an owner-crash guarantee or contain children which setsid().
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import threading
import time

__all__ = [
    "InstanceLock", "ManagedProcess", "ProcessCancelled", "ProcessError",
    "ProcessManager",
]


class ProcessError(RuntimeError):
    """A process operation failed; messages never include helper arguments."""


class ProcessCancelled(ProcessError):
    """Launch was cancelled, and any child created by it has been stopped."""


class InstanceLock:
    """An advisory, nonblocking lock; the persistent lockfile is never deleted."""

    def __init__(self, directory: Path):
        self._path = Path(directory) / ".instance.lock"
        self._fd: int | None = None
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            if self._fd is not None:
                return
            fd = None
            try:
                self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(self._path, flags, 0o600)
                os.set_inheritable(fd, False)
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if fd is not None:
                    os.close(fd)
                raise RuntimeError("Cannot acquire the application instance lock.") from None
            self._fd = fd

    def release(self) -> None:
        with self._lock:
            fd, self._fd = self._fd, None
            if fd is None:
                return
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                raise RuntimeError("Cannot release the application instance lock.") from None
            finally:
                os.close(fd)

    def __enter__(self) -> InstanceLock:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _SIZE_T = ctypes.c_size_t
    _INFINITE = 0xFFFFFFFF
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

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

    class _STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", _STARTUPINFOW), ("lpAttributeList", wintypes.LPVOID)]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", _SIZE_T), ("MaximumWorkingSetSize", _SIZE_T),
            ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", _SIZE_T),
            ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS), ("ProcessMemoryLimit", _SIZE_T),
            ("JobMemoryLimit", _SIZE_T), ("PeakProcessMemoryUsed", _SIZE_T),
            ("PeakJobMemoryUsed", _SIZE_T),
        ]

    # Explicit signatures are essential: HANDLE and SIZE_T are pointer-sized.
    for _name, _restype, _argtypes in (
        ("CreateJobObjectW", wintypes.HANDLE, [wintypes.LPVOID, wintypes.LPCWSTR]),
        ("SetInformationJobObject", wintypes.BOOL,
         [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]),
        ("SetHandleInformation", wintypes.BOOL,
         [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]),
        ("CreateFileW", wintypes.HANDLE,
         [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]),
        ("InitializeProcThreadAttributeList", wintypes.BOOL,
         [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_SIZE_T)]),
        ("UpdateProcThreadAttribute", wintypes.BOOL,
         [wintypes.LPVOID, wintypes.DWORD, _SIZE_T, wintypes.LPVOID,
          _SIZE_T, wintypes.LPVOID, wintypes.LPVOID]),
        ("DeleteProcThreadAttributeList", None, [wintypes.LPVOID]),
        ("CreateProcessW", wintypes.BOOL,
         [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
          wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
          ctypes.POINTER(_STARTUPINFOEXW), ctypes.POINTER(_PROCESS_INFORMATION)]),
        ("TerminateJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
        ("WaitForSingleObject", wintypes.DWORD, [wintypes.HANDLE, wintypes.DWORD]),
        ("GetExitCodeProcess", wintypes.BOOL,
         [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]),
        ("CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
    ):
        _function = getattr(_kernel32, _name)
        _function.restype = _restype
        _function.argtypes = _argtypes

    def _win_check(result):
        if not result:
            raise ProcessError(
                f"Windows process operation failed (error {ctypes.get_last_error()})."
            )
        return result

    def _launch_windows(args, cwd, env):
        job = nul = None
        attributes = None
        attributes_initialized = False
        info = _PROCESS_INFORMATION()
        transferred = False
        try:
            job = _win_check(_kernel32.CreateJobObjectW(None, None))
            _win_check(_kernel32.SetHandleInformation(job, 1, 0))
            limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            _win_check(_kernel32.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ))

            security = _SECURITY_ATTRIBUTES()
            security.nLength = ctypes.sizeof(security)
            security.bInheritHandle = True
            nul = _kernel32.CreateFileW(
                "NUL", 0xC0000000, 3, ctypes.byref(security), 3, 0x80, None
            )
            if nul == ctypes.c_void_p(-1).value:
                nul = None
                _win_check(False)

            size = _SIZE_T()
            _kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if not size.value:
                _win_check(False)
            attributes = ctypes.create_string_buffer(size.value)
            _win_check(_kernel32.InitializeProcThreadAttributeList(
                attributes, 2, 0, ctypes.byref(size)
            ))
            attributes_initialized = True
            jobs = (wintypes.HANDLE * 1)(job)
            handles = (wintypes.HANDLE * 1)(nul)
            # Both arrays and the attribute buffer must live through CreateProcessW.
            _win_check(_kernel32.UpdateProcThreadAttribute(
                attributes, 0, 0x0002000D, jobs, ctypes.sizeof(jobs), None, None
            ))  # PROC_THREAD_ATTRIBUTE_JOB_LIST: assignment is atomic with creation.
            _win_check(_kernel32.UpdateProcThreadAttribute(
                attributes, 0, 0x00020002, handles, ctypes.sizeof(handles), None, None
            ))  # PROC_THREAD_ATTRIBUTE_HANDLE_LIST: inherit only the NUL handle.

            startup = _STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput = nul
            startup.StartupInfo.hStdOutput = nul
            startup.StartupInfo.hStdError = nul
            startup.lpAttributeList = ctypes.cast(attributes, wintypes.LPVOID)
            environment = None
            if env is not None:
                # Windows environment names are case insensitive and sorted.
                folded = {key.upper(): (key, value) for key, value in env.items()}
                environment = ctypes.create_unicode_buffer("\0".join(
                    f"{key}={value}" for key, value in sorted(
                        folded.values(), key=lambda item: item[0].upper()
                    )
                ) + "\0\0")
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(args))
            flags = 0x08000000 | 0x00000400 | 0x00080000
            _win_check(_kernel32.CreateProcessW(
                args[0], command, None, None, True, flags, environment, cwd,
                ctypes.byref(startup), ctypes.byref(info),
            ))  # CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
            transferred = True
            return info.dwProcessId, info.hProcess, job
        finally:
            if not transferred and info.hProcess:
                # Even exceptions immediately after creation cannot leave a live child.
                _kernel32.TerminateJobObject(job, 1)
                _kernel32.CloseHandle(job)
                job = None
                _kernel32.WaitForSingleObject(info.hProcess, _INFINITE)
                _kernel32.CloseHandle(info.hProcess)
            if info.hThread:
                _kernel32.CloseHandle(info.hThread)
            if attributes_initialized:
                _kernel32.DeleteProcThreadAttributeList(attributes)
            if nul is not None:
                _kernel32.CloseHandle(nul)
            if job is not None and not transferred:
                _kernel32.CloseHandle(job)


class ManagedProcess:
    """A process tree, cleaned up on stop or when poll/wait observes leader exit."""

    def __init__(self, owner: ProcessManager):
        self._owner = owner
        self._pid = 0
        self._popen: subprocess.Popen | None = None
        self._handle = None
        self._job = None
        self._returncode: int | None = None
        self._stopped = False

    @property
    def pid(self) -> int:
        return self._pid

    def _start_locked(self, args, cwd, env) -> None:
        if os.name == "nt":
            self._pid, self._handle, self._job = _launch_windows(args, cwd, env)
        else:
            self._popen = subprocess.Popen(
                args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                shell=False, close_fds=True, start_new_session=True,
            )
            self._pid = self._popen.pid

    def _poll_locked(self) -> int | None:
        if self._stopped:
            return self._returncode
        if os.name == "nt":
            result = _kernel32.WaitForSingleObject(self._handle, 0)
            if result == _WAIT_TIMEOUT:
                return None
            if result != _WAIT_OBJECT_0:
                _win_check(False)
        else:
            # WNOWAIT keeps the leader's PID reserved until its group is stopped.
            # Reaping it with Popen.poll() first could later target a reused PGID.
            if os.waitid(os.P_PID, self._pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                return None
        self._stop_locked()
        self._owner._processes.discard(self)
        return self._returncode

    def poll(self) -> int | None:
        with self._owner._lock:
            try:
                return self._poll_locked()
            except ProcessError:
                raise
            except Exception:
                # In particular, never expose Popen's argument-bearing exceptions.
                raise ProcessError("Unable to check managed process status.") from None

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + max(0, timeout)
        while True:
            result = self.poll()
            if result is not None:
                return result
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise subprocess.TimeoutExpired("managed process", timeout)
            # Do not hold the ownership lock while waiting: stop/shutdown must run.
            time.sleep(0.02 if remaining is None else min(0.02, remaining))

    def stop(self) -> None:
        self._owner.stop(self)

    def _stop_locked(self) -> None:
        if self._stopped:
            return
        if os.name == "nt":
            if self._job is not None:
                job, self._job = self._job, None
                try:
                    _win_check(_kernel32.TerminateJobObject(job, 1))
                finally:
                    _kernel32.CloseHandle(job)
            if self._handle is not None:
                if _kernel32.WaitForSingleObject(self._handle, 5000) != _WAIT_OBJECT_0:
                    raise ProcessError("Managed process did not stop within its deadline.")
                code = wintypes.DWORD()
                _win_check(_kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)))
                self._returncode = code.value
                _kernel32.CloseHandle(self._handle)
                self._handle = None
        elif self._popen is not None:
            try:
                os.killpg(self._pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            else:
                # Keep the leader unreaped throughout the grace period and final kill.
                # Descendants get the same grace even if the leader exits immediately.
                time.sleep(0.3)
                try:
                    os.killpg(self._pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self._returncode = self._popen.wait(timeout=5)
        self._stopped = True


class ProcessManager:
    """Serialize process ownership, cancellation, stopping and permanent shutdown."""

    def __init__(self):
        self._lock = threading.RLock()
        self._processes: set[ManagedProcess] = set()
        self._shutdown = False

    def start(
        self, args: list[str], *, cwd: Path | None = None,
        env: dict[str, str] | None = None, cancel: threading.Event | None = None,
    ) -> ManagedProcess:
        if not isinstance(args, list) or not args:
            raise ValueError("A nonempty argument list is required.")
        args = args.copy()
        if any(not isinstance(arg, str) or "\0" in arg for arg in args):
            raise ValueError("Process arguments must be strings without NUL characters.")
        if not Path(args[0]).is_absolute():
            raise ValueError("The executable path must be absolute.")
        if env is not None:
            env = env.copy()
            if any(
                not isinstance(key, str) or not key or "=" in key or "\0" in key
                or not isinstance(value, str) or "\0" in value
                for key, value in env.items()
            ):
                raise ValueError("The process environment is invalid.")
        cwd_string = None if cwd is None else os.fspath(cwd)
        with self._lock:
            if self._shutdown:
                raise ProcessError("The process manager has been shut down.")
            if cancel is not None and cancel.is_set():
                raise ProcessCancelled("Process launch was cancelled.")
            process = ManagedProcess(self)
            try:
                process._start_locked(args, cwd_string, env)
                self._processes.add(process)
                if cancel is not None and cancel.is_set():
                    raise ProcessCancelled("Process launch was cancelled.")
                return process
            except BaseException as error:
                try:
                    process._stop_locked()
                except Exception:
                    # Retain ownership so shutdown can retry cleanup after a failure.
                    self._processes.add(process)
                    raise ProcessError("Unable to clean up a failed process launch.") from None
                self._processes.discard(process)
                if isinstance(error, (ProcessCancelled, KeyboardInterrupt, SystemExit)):
                    raise
                if cancel is not None and cancel.is_set():
                    raise ProcessCancelled("Process launch was cancelled.") from None
                if isinstance(error, ProcessError):
                    raise
                raise ProcessError("Unable to start managed process.") from None

    def stop(self, process: ManagedProcess) -> None:
        with self._lock:
            if not isinstance(process, ManagedProcess) or process._owner is not self:
                raise ValueError("The process belongs to a different manager.")
            try:
                process._stop_locked()
            except Exception:
                raise ProcessError("Unable to stop managed process.") from None
            self._processes.discard(process)

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
            failed = False
            for process in tuple(self._processes):
                try:
                    self.stop(process)
                except ProcessError:
                    failed = True
            if failed:
                raise ProcessError("Unable to stop one or more managed processes.") from None
