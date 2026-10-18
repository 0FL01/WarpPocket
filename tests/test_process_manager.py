from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from warppocket.process_manager import (
    InstanceLock, ProcessCancelled, ProcessError, ProcessManager,
)


_LISTENER = """
import os, pathlib, socket, sys, time
server = socket.socket()
server.bind(('127.0.0.1', int(sys.argv[1])))
server.listen()
pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
while True:
    time.sleep(1)
"""

_PARENT = """
import os, pathlib, signal, subprocess, sys, time
child = subprocess.Popen(
    [sys.executable, '-c', sys.argv[1], sys.argv[2], sys.argv[3]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    creationflags=0x08000000 if os.name == 'nt' else 0,
)
def finish(signum, frame):
    child.terminate()
    child.wait()
    sys.exit(0)
signal.signal(signal.SIGTERM, finish)
pathlib.Path(sys.argv[4]).write_text(str(os.getpid()))
while True:
    time.sleep(1)
"""


def _eventually(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _running(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # An orphan zombie cannot listen or execute, even on containers whose PID 1
    # does not reap promptly. The managed direct child is separately wait()-reaped.
    status = Path(f"/proc/{pid}/stat")
    try:
        return status.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def _listening(port):
    with socket.socket() as client:
        client.settimeout(0.1)
        return client.connect_ex(("127.0.0.1", port)) == 0


class ProcessManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.manager = ProcessManager()
        self.addCleanup(self.manager.shutdown)

    def start(self, code, *args, **kwargs):
        return self.manager.start([sys.executable, "-c", code, *map(str, args)], **kwargs)

    def tree(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        child_file = self.directory / "child.pid"
        parent_file = self.directory / "parent.pid"
        process = self.start(_PARENT, _LISTENER, port, child_file, parent_file)
        self.assertTrue(_eventually(lambda: child_file.exists() and parent_file.exists()))
        self.assertTrue(_listening(port))
        self.assertEqual(int(parent_file.read_text()), process.pid)
        return process, int(child_file.read_text()), port

    def test_stdio_cwd_environment_and_nonshell_arguments(self):
        result = self.directory / "result.txt"
        environment = dict(os.environ, WARPPOCKET_TEST_VALUE="private-value")
        process = self.start(
            "import json,os,pathlib,sys; "
            "print('must not be captured'); print('must not be captured',file=sys.stderr); "
            "pathlib.Path('result.txt').write_text(json.dumps([sys.stdin.read(), "
            "os.environ['WARPPOCKET_TEST_VALUE'], sys.argv[1]])); sys.exit(7)",
            'literal ; & " quoted', cwd=self.directory, env=environment,
        )
        self.assertGreater(process.pid, 0)
        self.assertEqual(process.wait(timeout=5), 7)
        self.assertEqual(process.poll(), 7)
        import json
        self.assertEqual(json.loads(result.read_text()), ["", "private-value", 'literal ; & " quoted'])
        process.stop()
        self.manager.stop(process)

    def test_stop_tree_listener_and_reconnect(self):
        process, child_pid, port = self.tree()
        self.assertIsNone(process.poll())
        process.stop()
        process.stop()
        self.manager.stop(process)
        self.assertIsNotNone(process.wait(timeout=1))
        self.assertFalse(_running(process.pid))
        self.assertTrue(_eventually(lambda: not _running(child_pid) and not _listening(port)))
        replacement = self.start("pass")
        self.assertEqual(replacement.wait(timeout=5), 0)

    def test_natural_leader_exit_also_cleans_up_descendant(self):
        child_file = self.directory / "orphan.pid"
        code = """
import os, pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c',
    'import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)',
    sys.argv[1]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL, creationflags=0x08000000 if os.name == 'nt' else 0)
while not pathlib.Path(sys.argv[1]).exists():
    time.sleep(0.01)
sys.exit(12)
"""
        process = self.start(code, child_file)
        self.assertEqual(process.wait(timeout=5), 12)
        child_pid = int(child_file.read_text())
        self.assertTrue(_eventually(lambda: not _running(child_pid)))
        process.stop()

    @unittest.skipUnless(os.name == "posix", "POSIX signal escalation")
    def test_sigterm_resistant_child_is_killed_and_reaped(self):
        ready = self.directory / "ready"
        process = self.start(
            "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).touch(); time.sleep(60)", ready,
        )
        self.assertTrue(_eventually(ready.exists))
        process.stop()
        self.assertEqual(process.wait(timeout=1), -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_wait_timeout_is_redacted_and_stop_can_interrupt_wait(self):
        secret = "sensitive-config-value"
        process = self.start("import time; time.sleep(60)", secret)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            process.wait(timeout=0.01)
        self.assertNotIn(secret, str(caught.exception))
        results = []
        waiter = threading.Thread(target=lambda: results.append(process.wait()))
        waiter.start()
        process.stop()
        waiter.join(timeout=5)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(results, [process.poll()])

    def test_cancel_before_launch(self):
        cancel = threading.Event()
        cancel.set()
        created = self.directory / "unexpected"
        with self.assertRaises(ProcessCancelled):
            self.start("import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", created, cancel=cancel)
        self.assertFalse(created.exists())
        self.assertEqual(self.start("pass").wait(timeout=5), 0)

    def test_cancel_during_launch_stops_actual_child(self):
        child_file = self.directory / "cancelled.pid"

        class CancelAfterCreation(threading.Event):
            def __init__(self):
                super().__init__()
                self.checks = 0

            def is_set(self):
                self.checks += 1
                if self.checks == 2:
                    # Exercise the real native launch; no fake process backend.
                    if not _eventually(child_file.exists):
                        raise AssertionError("The launched test child did not become ready.")
                    self.set()
                return super().is_set()

        with self.assertRaises(ProcessCancelled):
            self.start(
                "import os,pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)",
                child_file, cancel=CancelAfterCreation(),
            )
        pid = int(child_file.read_text())
        self.assertTrue(_eventually(lambda: not _running(pid)))
        self.assertEqual(self.start("pass").wait(timeout=5), 0)

    def test_invalid_launch_is_redacted_and_does_not_poison_manager(self):
        with self.assertRaises(ValueError):
            self.manager.start(["relative-helper"])
        with self.assertRaises(ValueError):
            self.manager.start([])
        secret = "private-config-secret"
        with self.assertRaises(ProcessError) as caught:
            self.manager.start([str(self.directory / secret), secret], env={"KEY": secret})
        self.assertNotIn(secret, str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.start("pass").wait(timeout=5), 0)

    def test_shutdown_stops_tree_and_permanently_rejects_launches(self):
        process, child_pid, port = self.tree()
        self.manager.shutdown()
        self.manager.shutdown()
        process.stop()
        self.assertIsNotNone(process.poll())
        self.assertTrue(_eventually(lambda: not _running(child_pid) and not _listening(port)))
        with self.assertRaises(ProcessError):
            self.start("pass")

    def test_launch_shutdown_ownership_race(self):
        barrier = threading.Barrier(5)
        processes = []
        errors = []

        def launch():
            try:
                barrier.wait(timeout=5)
                processes.append(self.start("import time; time.sleep(60)"))
            except ProcessError:
                pass  # Shutdown won the ownership lock.
            except BaseException as error:
                errors.append(error)

        workers = [threading.Thread(target=launch) for _ in range(4)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=5)
        self.manager.shutdown()
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        for process in processes:
            self.assertIsNotNone(process.poll())
            self.assertFalse(_running(process.pid))

    def test_other_manager_cannot_stop_owned_process(self):
        process = self.start("import time; time.sleep(60)")
        other = ProcessManager()
        self.addCleanup(other.shutdown)
        with self.assertRaises(ValueError):
            other.stop(process)
        process.stop()

    @unittest.skipUnless(os.name == "nt", "native Windows handle accounting")
    def test_windows_native_handles_close_after_success_and_failure(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetProcessHandleCount.restype = wintypes.BOOL

        def handle_count():
            count = wintypes.DWORD()
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count)))
            return count.value

        self.assertEqual(self.start("pass").wait(timeout=5), 0)
        before = handle_count()
        for _ in range(8):
            with self.assertRaises(ProcessError):
                self.manager.start([str(self.directory / "missing-helper.exe")])
            process = self.start("pass")
            self.assertEqual(process.wait(timeout=5), 0)
            process.stop()
        self.assertLessEqual(handle_count(), before + 2)

    @unittest.skipUnless(os.name == "nt", "native Windows owner-crash guarantee")
    def test_windows_job_kills_tree_after_owner_crash(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        parent_file = self.directory / "owned-parent.pid"
        child_file = self.directory / "owned-child.pid"
        owner_code = """
import pathlib, sys, time
from warppocket.process_manager import ProcessManager
manager = ProcessManager()
manager.start([sys.executable, '-c', sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]])
while True:
    time.sleep(1)
"""
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        owner = subprocess.Popen(
            [sys.executable, "-c", owner_code, _PARENT, _LISTENER, str(port),
             str(child_file), str(parent_file)],
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            self.assertTrue(_eventually(lambda: parent_file.exists() and child_file.exists()))
            parent_pid, child_pid = int(parent_file.read_text()), int(child_file.read_text())
            self.assertTrue(_listening(port))
            owner.kill()  # TerminateProcess, not manager shutdown or Python cleanup.
            owner.wait(timeout=5)
            self.assertTrue(_eventually(
                lambda: not _running(parent_pid) and not _running(child_pid) and not _listening(port)
            ))
        finally:
            if owner.poll() is None:
                owner.kill()
            owner.wait(timeout=5)


class InstanceLockTests(unittest.TestCase):
    def test_second_lock_release_and_reacquire_keep_same_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = InstanceLock(directory)
            second = InstanceLock(directory)
            first.acquire()
            first.acquire()
            try:
                with self.assertRaises(RuntimeError):
                    second.acquire()
            finally:
                first.release()
                first.release()
            second.acquire()
            second.release()
            before = {path.name: path.stat().st_ino for path in directory.iterdir()}
            with InstanceLock(directory):
                pass
            after = {path.name: path.stat().st_ino for path in directory.iterdir()}
            self.assertEqual(before, after)
            self.assertEqual(len(after), 1)

    def test_lock_is_exclusive_across_processes_and_released_on_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            code = """
import pathlib, sys
from warppocket.process_manager import InstanceLock
try:
    with InstanceLock(pathlib.Path(sys.argv[1])):
        sys.exit(0)
except RuntimeError:
    sys.exit(17)
"""
            manager = ProcessManager()
            self.addCleanup(manager.shutdown)
            environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
            with InstanceLock(directory):
                child = manager.start([sys.executable, "-c", code, str(directory)], env=environment)
                self.assertEqual(child.wait(timeout=5), 17)
            child = manager.start([sys.executable, "-c", code, str(directory)], env=environment)
            self.assertEqual(child.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main()
