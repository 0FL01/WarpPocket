from __future__ import annotations

from contextlib import redirect_stdout
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import ci_smoke as smoke


FAST = smoke.Timeouts(graceful=0, report=0, launcher=0, child=0, port=0, cleanup=0, poll=0.001)
LAUNCHER = 0x10000000
INNER = LAUNCHER + 10
CHILD = LAUNCHER + 11


def report_data(out, mode="graceful"):
    return {
        "schema_version": 1, "mode": mode, "ok": True, "pid": INNER,
        "frozen": True,
        "checks": dict.fromkeys(
            smoke.GRACEFUL_CHECKS if mode == "graceful" else smoke.COMMON_CHECKS, True,
        ),
        "child_pid": CHILD, "port": 1080,
        "workspace": str(out / f"workspace-{mode}"), "error_code": None,
    }


class FakeProcess:
    def __init__(self, owner, pid, *, live=True, code=0):
        self.owner, self.pid, self.live, self.code = owner, pid, live, code
        self.closed = False
        self.on_terminate = None

    def exited(self, timeout):
        if self.closed:
            raise AssertionError("A process handle was closed before verification.")
        self.owner.events.append(("wait", self.pid, timeout))
        return not self.live

    def exit_code(self):
        if self.live:
            raise AssertionError("An active process has no final exit code.")
        return self.code

    def terminate(self):
        self.owner.events.append(("terminate", self.pid))
        if self.on_terminate is not None:
            self.on_terminate()

    def belongs_to(self, launch):
        return not self.owner.foreign and self in launch.members

    def close(self):
        self.owner.events.append(("close_process", self.pid))
        self.closed = True


class FakeLaunch:
    def __init__(self, owner, mode, process):
        self.owner, self.mode, self.process = owner, mode, process
        self.members = [process]
        self.closed = False

    def empty(self):
        return not any(process.live for process in self.members)

    def teardown(self, timeout, poll):
        # Emergency cleanup must never be used to make the assertion pass.
        if self.owner.result["ok"] or self.owner.result["error_code"] is None:
            raise AssertionError("Failure was not recorded before safety teardown.")
        self.owner.events.append(("teardown", self.mode, timeout))
        self.owner.live_at_teardown[self.mode] = [p.pid for p in self.members if p.live]
        for process in self.members:
            process.live = False
        if self.owner.cleanup_fails:
            raise smoke.SmokeFailure("cleanup_timeout")

    def close(self):
        self.process.close()
        self.closed = True
        self.owner.events.append(("close_job", self.mode))


class FakeWindows:
    def __init__(self):
        self.events = []
        self.launches = []
        self.processes = {}
        self.live_at_teardown = {}
        self.mutations = {}
        self.no_report = set()
        self.graceful_hangs = False
        self.graceful_code = 0
        self.helper_survives = False
        self.launcher_survives = False
        self.gui_survives = False
        self.helper_dead = False
        self.foreign = False
        self.port_stays_open = False
        self.no_listener = False
        self.cleanup_fails = False
        self.result = None

    def launch(self, argv, cwd):
        path = Path(argv[2])
        if path.exists():
            raise AssertionError("The driver did not remove a previous report.")
        if not path.is_absolute() or not Path(argv[0]).is_absolute():
            raise AssertionError("The executable and report paths must be absolute.")
        if Path(cwd).is_relative_to(smoke.SOURCE_ROOT):
            raise AssertionError("The working directory is inside the source tree.")
        if Path(argv[0]).parent.name != "Копия WarpPocket":
            raise AssertionError("The non-ASCII/space path was not exercised.")
        mode = "wait" if argv[1] == "--smoke-wait" else "graceful"
        self.events.append(("launch", mode, str(cwd)))
        launcher = FakeProcess(
            self, LAUNCHER + len(self.launches),
            live=(mode == "wait" or self.graceful_hangs), code=self.graceful_code,
        )
        launch = FakeLaunch(self, mode, launcher)
        self.launches.append(launch)
        if mode == "wait":
            gui = FakeProcess(self, INNER)
            helper = FakeProcess(self, CHILD, live=not self.helper_dead)
            launch.members.extend((gui, helper))
            self.processes.update({INNER: gui, CHILD: helper})

            def terminate_gui():
                gui.live = self.gui_survives
                launcher.live = self.launcher_survives
                helper.live = self.helper_survives

            gui.on_terminate = terminate_gui
        data = report_data(path.parent, mode)
        workspace = Path(data["workspace"])
        workspace.mkdir(exist_ok=True)
        (workspace / "synthetic.conf").write_text("synthetic-only", encoding="utf-8")
        if mode in self.mutations:
            self.mutations[mode](data)
        if mode not in self.no_report:
            path.write_text(json.dumps(data), encoding="utf-8")
        return launch

    def open_process(self, pid, *, terminate=False):
        self.events.append(("open", pid, terminate))
        return self.processes[pid]

    def port_open(self, port):
        if port != 1080:
            raise AssertionError("Unexpected SOCKS port.")
        return not self.no_listener and (self.port_stays_open or self.processes[CHILD].live)


class TemporaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.out = self.directory / "out"
        self.out.mkdir()

    def assert_failure(self, code, operation, *args, **kwargs):
        with self.assertRaises(smoke.SmokeFailure) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class ReportTests(TemporaryTests):
    def test_valid_report_and_nullable_graceful_identity(self):
        data = report_data(self.out)
        data.update(child_pid=None, port=None)
        report = smoke._validate_report(data, "graceful", self.out)
        smoke._require_success(report)
        self.assertEqual(report.workspace, self.out / "workspace-graceful")

    def test_rejects_bad_schema_and_types(self):
        invalid = [
            ("schema_version", True), ("schema_version", 2), ("mode", "wait"),
            ("ok", 1), ("frozen", 1), ("pid", True), ("pid", 0), ("pid", -1),
            ("pid", "123"), ("pid", 2 ** 32), ("child_pid", True),
            ("child_pid", -10), ("port", True), ("port", 0), ("port", 65536),
            ("port", "127.0.0.1:1080"), ("error_code", {}), ("checks", []),
            ("checks", {"tk": 1}), ("checks", {"raw-error-message": True}),
        ]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                data = report_data(self.out)
                data[key] = value
                self.assert_failure("report_schema_invalid", smoke._validate_report,
                                    data, "graceful", self.out)
        for data in ([], None, "text", {}, {**report_data(self.out), "extra": "secret"}):
            with self.subTest(root=data):
                self.assert_failure("report_schema_invalid", smoke._validate_report,
                                    data, "graceful", self.out)

    def test_missing_false_and_empty_checks_cannot_pass(self):
        for checks in ({}, {"tk": True}, dict.fromkeys(smoke.GRACEFUL_CHECKS, False)):
            with self.subTest(checks=checks):
                data = report_data(self.out)
                data["checks"] = checks
                report = smoke._validate_report(data, "graceful", self.out)
                self.assert_failure("required_checks_failed", smoke._require_success, report)

    def test_unfrozen_failed_or_not_ready_reports_cannot_pass(self):
        cases = [
            ("graceful", {"frozen": False}, "not_frozen"),
            ("graceful", {"ok": False}, "smoke_not_ok"),
            ("graceful", {"error_code": "sensitive text"}, "smoke_not_ok"),
            ("wait", {"child_pid": None}, "wait_identity_missing"),
            ("wait", {"port": None}, "wait_identity_missing"),
        ]
        for mode, changes, code in cases:
            with self.subTest(changes=changes):
                data = report_data(self.out, mode)
                data.update(changes)
                self.assert_failure(code, smoke._require_success,
                                    smoke._validate_report(data, mode, self.out))

    def test_workspace_must_be_an_absolute_strict_descendant(self):
        cases = [
            ("relative", "workspace_invalid"), ("", "workspace_invalid"),
            (None, "workspace_invalid"), ("bad\0path", "workspace_invalid"),
            (str(self.out), "workspace_outside_output"),
            (str(self.directory / "outside"), "workspace_outside_output"),
            (str(self.out / ".." / "outside"), "workspace_outside_output"),
        ]
        for workspace, code in cases:
            with self.subTest(workspace=workspace):
                data = report_data(self.out)
                data["workspace"] = workspace
                self.assert_failure(code, smoke._validate_report, data, "graceful", self.out)

    def test_read_rejects_stale_malformed_duplicate_and_oversized_reports(self):
        path = self.out / "report.json"
        path.write_text(json.dumps(report_data(self.out)), encoding="utf-8")
        os.utime(path, ns=(1, 1))
        self.assert_failure("report_stale", smoke._read_report, path, "graceful", self.out, 2)
        for content in (b"not-json", b"\xff", b"[]"):
            path.write_bytes(content)
            code = "report_schema_invalid" if content == b"[]" else "report_json_invalid"
            self.assert_failure(code, smoke._read_report, path, "graceful", self.out, 0)
        path.write_text('{"pid": 1, "pid": 2}', encoding="utf-8")
        self.assert_failure("report_schema_invalid", smoke._read_report,
                            path, "graceful", self.out, 0)
        path.write_bytes(b"x" * (smoke.MAX_REPORT_BYTES + 1))
        self.assert_failure("report_file_invalid", smoke._read_report,
                            path, "graceful", self.out, 0)

    def test_valid_fresh_json_is_read(self):
        path = self.out / "report.json"
        path.write_text(json.dumps(report_data(self.out)), encoding="utf-8")
        report = smoke._read_report(path, "graceful", self.out, path.stat().st_mtime_ns)
        smoke._require_success(report)

    @unittest.skipUnless(os.name == "posix", "symlink fixture requires no Windows privileges")
    def test_symlink_reports_and_workspace_escapes_are_rejected(self):
        outside = self.directory / "outside"
        outside.mkdir()
        target = outside / "report.json"
        target.write_text(json.dumps(report_data(self.out)), encoding="utf-8")
        path = self.out / "report.json"
        path.symlink_to(target)
        self.assert_failure("report_file_invalid", smoke._read_report,
                            path, "graceful", self.out, 0)
        link = self.out / "workspace"
        link.symlink_to(outside, target_is_directory=True)
        data = report_data(self.out)
        data["workspace"] = str(link)
        self.assert_failure("workspace_outside_output", smoke._validate_report,
                            data, "graceful", self.out)
        self.assertTrue(target.is_file())

    @unittest.skipUnless(os.name == "posix", "symlink fixture requires no Windows privileges")
    def test_workspace_changed_to_an_external_symlink_is_not_removed(self):
        workspace = smoke._validate_report(report_data(self.out), "graceful", self.out).workspace
        external = self.directory / "external"
        external.mkdir()
        marker = external / "must-survive"
        marker.touch()
        workspace.symlink_to(external, target_is_directory=True)
        copied = self.out / "Копия WarpPocket" / "WarpPocket.exe"
        self.assert_failure("workspace_outside_output", smoke._remove_workspace,
                            workspace, self.out, copied)
        self.assertTrue(marker.is_file())


class DriverTests(TemporaryTests):
    def setUp(self):
        super().setUp()
        self.exe = self.directory / "supplied.exe"
        self.exe.write_bytes(b"fake onefile executable")
        self.native = FakeWindows()

    def run_driver(self):
        original = smoke._run_checks

        def capture(copied, out, cwd, native, result, *args):
            native.result = result
            return original(copied, out, cwd, native, result, *args)

        with mock.patch.object(smoke.sys, "platform", "win32"), \
                mock.patch.object(smoke, "_run_checks", side_effect=capture), \
                mock.patch.object(smoke, "_port_open", side_effect=self.native.port_open), \
                redirect_stdout(io.StringIO()) as output:
            code = smoke.run_ci(self.exe, self.out, native=self.native, timeouts=FAST)
        result = json.loads((self.out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(output.getvalue()), result)
        for launch in self.native.launches:
            self.assertTrue(launch.closed)
            self.assertTrue(launch.process.closed)
            self.assertTrue(launch.empty())
        for process in self.native.processes.values():
            if any(event[:2] == ("open", process.pid) for event in self.native.events):
                self.assertTrue(process.closed)
        return code, result

    def test_freshness_uses_filesystem_clock_not_precise_wall_clock(self):
        # NTFS metadata can lag GetSystemTimePreciseAsFileTime even for a file
        # just created by this launch. Compare filesystem timestamps instead.
        with mock.patch.object(smoke.time, "time_ns", return_value=2**63 - 1):
            code, result = self.run_driver()
        self.assertEqual(code, 0, result["error_code"])
        self.assertTrue(result["ok"])

    def test_success_kills_only_gui_and_retains_handles_until_verification(self):
        # Both phases must remove stale reports instead of accepting them.
        for name in ("graceful.json", "wait.json"):
            (self.out / name).write_text("stale report", encoding="utf-8")
        code, result = self.run_driver()
        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        self.assertTrue(result["graceful"]["ok"])
        self.assertTrue(result["forced_kill"]["child_stopped"])
        self.assertTrue(result["forced_kill"]["port_closed"])
        self.assertEqual([e for e in self.native.events if e[0] == "terminate"],
                         [("terminate", INNER)])
        self.assertFalse(any(e[0] == "teardown" for e in self.native.events))
        events = self.native.events
        killed = events.index(("terminate", INNER))
        child_verified = events.index(("wait", CHILD, FAST.child), killed)
        self.assertLess(child_verified, events.index(("close_process", CHILD)))
        self.assertLess(child_verified, events.index(("close_process", INNER)))
        self.assertEqual((self.out / "Копия WarpPocket" / "WarpPocket.exe").read_bytes(),
                         self.exe.read_bytes())
        self.assertFalse((self.out / "workspace-graceful").exists())
        self.assertFalse((self.out / "workspace-wait").exists())
        for event in events:
            if event[0] == "launch":
                self.assertFalse(Path(event[2]).exists())

    def test_graceful_timeout_tears_down_containment_without_a_report(self):
        self.native.graceful_hangs = True
        self.native.no_report.add("graceful")
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "graceful_timeout")
        self.assertEqual(self.native.live_at_teardown["graceful"], [LAUNCHER])
        self.assertEqual(len(self.native.launches), 1)

    def test_wait_report_timeout_cleans_up_unreported_inner_and_helper(self):
        self.native.no_report.add("wait")
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "report_timeout")
        self.assertIn(INNER, self.native.live_at_teardown["wait"])
        self.assertIn(CHILD, self.native.live_at_teardown["wait"])
        self.assertFalse(any(e[0] == "terminate" for e in self.native.events))

    def test_missing_report_after_graceful_exit_cannot_reuse_previous_file(self):
        self.native.no_report.add("graceful")
        (self.out / "graceful.json").write_text(json.dumps(report_data(self.out)), encoding="utf-8")
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "report_missing")

    def test_report_with_a_stale_timestamp_is_rejected_and_contained(self):
        original = smoke._read_report

        def stale(path, mode, out, not_before_ns):
            if mode == "wait":
                os.utime(path, ns=(1, 1))
            return original(path, mode, out, not_before_ns)

        with mock.patch.object(smoke, "_read_report", side_effect=stale):
            code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "report_stale")
        self.assertIn(CHILD, self.native.live_at_teardown["wait"])

    def test_nonzero_graceful_exit_fails_even_with_successful_report(self):
        self.native.graceful_code = 7
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "graceful_exit_nonzero")
        self.assertEqual(result["graceful"]["exit_code"], 7)
        self.assertEqual(len(self.native.launches), 1)

    def test_invalid_and_failed_reports_have_safe_summary_and_cleanup(self):
        cases = [
            ({"pid": True}, "report_schema_invalid"),
            ({"ok": False, "error_code": "secret-token=do-not-log"}, "smoke_not_ok"),
            ({"checks": {}}, "required_checks_failed"),
            ({"frozen": False}, "not_frozen"),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                self.native = FakeWindows()
                self.native.mutations["wait"] = lambda data: data.update(changes)
                code, result = self.run_driver()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["error_code"], expected)
                self.assertNotIn("do-not-log", json.dumps(result))
                self.assertIn(CHILD, self.native.live_at_teardown["wait"])

    def test_inner_must_differ_from_launcher_and_helper(self):
        for changes in ({"pid": LAUNCHER + 1}, {"child_pid": INNER}, {"pid": os.getpid()}):
            with self.subTest(changes=changes):
                self.native = FakeWindows()
                self.native.mutations["wait"] = lambda data: data.update(changes)
                code, result = self.run_driver()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["error_code"], "process_identity_invalid")
                self.assertFalse(any(e[0] == "terminate" for e in self.native.events))

    def test_report_cannot_authorize_terminating_a_foreign_process(self):
        self.native.foreign = True
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "process_not_owned")
        self.assertFalse(any(e[0] == "terminate" for e in self.native.events))

    def test_dead_helper_or_closed_initial_port_cannot_pass_vacuously(self):
        for attribute, expected in (("helper_dead", "wait_process_not_live"),
                                    ("no_listener", "socks_not_listening")):
            with self.subTest(attribute=attribute):
                self.native = FakeWindows()
                setattr(self.native, attribute, True)
                code, result = self.run_driver()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["error_code"], expected)
                self.assertFalse(any(e[0] == "terminate" for e in self.native.events))

    def test_helper_survival_is_failure_before_emergency_teardown(self):
        self.native.helper_survives = True
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertFalse(result["forced_kill"]["child_stopped"])
        self.assertEqual(result["error_code"], "helper_survived_gui")
        self.assertIn(CHILD, self.native.live_at_teardown["wait"])
        events = self.native.events
        killed = events.index(("terminate", INNER))
        verified = events.index(("wait", CHILD, FAST.child), killed)
        self.assertLess(verified, events.index(("teardown", "wait", FAST.cleanup)))

    def test_gui_and_launcher_timeouts_still_clean_up(self):
        for attribute, expected in (("gui_survives", "gui_exit_timeout"),
                                    ("launcher_survives", "launcher_exit_timeout")):
            with self.subTest(attribute=attribute):
                self.native = FakeWindows()
                setattr(self.native, attribute, True)
                code, result = self.run_driver()
                self.assertNotEqual(code, 0)
                self.assertEqual(result["error_code"], expected)
                self.assertIn("wait", self.native.live_at_teardown)

    def test_open_socks_port_is_failure_even_when_child_handle_is_signaled(self):
        self.native.port_stays_open = True
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "socks_port_still_open")
        self.assertTrue(result["forced_kill"]["child_stopped"])
        self.assertFalse(result["forced_kill"]["port_closed"])

    def test_cleanup_error_never_hides_original_failure(self):
        self.native.helper_survives = True
        self.native.cleanup_fails = True
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "helper_survived_gui")
        self.assertFalse(result["cleanup"]["ok"])
        self.assertIn("process_cleanup_failed", result["cleanup"]["error_codes"])

    def test_exception_after_opening_gui_closes_handle_and_contains_helper(self):
        original = self.native.open_process

        def broken_open(pid, **kwargs):
            if pid == CHILD:
                raise OSError("do-not-log secret path")
            return original(pid, **kwargs)

        self.native.open_process = broken_open
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "driver_failed")
        self.assertNotIn("do-not-log", json.dumps(result))
        self.assertTrue(self.native.processes[INNER].closed)
        self.assertIn(CHILD, self.native.live_at_teardown["wait"])

    def test_interrupt_is_bounded_and_does_not_bypass_cleanup_or_summary(self):
        def interrupted(port):
            raise KeyboardInterrupt("do-not-log private text")

        self.native.port_open = interrupted
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "interrupted")
        self.assertNotIn("do-not-log", json.dumps(result))
        self.assertIn(CHILD, self.native.live_at_teardown["wait"])

    def test_temp_directory_inside_source_tree_is_rejected_before_launch(self):
        with mock.patch.object(smoke, "SOURCE_ROOT", Path(tempfile.gettempdir()).resolve()):
            code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "working_directory_inside_source")
        self.assertEqual(self.native.launches, [])

    def test_copy_failure_and_nonwindows_execution_still_write_summary(self):
        with mock.patch.object(smoke.sys, "platform", "win32"), redirect_stdout(io.StringIO()):
            code = smoke.run_ci(self.directory / "missing.exe", self.out)
        self.assertEqual(code, 1)
        result = json.loads((self.out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(result["error_code"], "driver_failed")
        with mock.patch.object(smoke.sys, "platform", "linux"), redirect_stdout(io.StringIO()):
            code = smoke.main(["--exe", str(self.exe), "--out", str(self.out)])
        self.assertEqual(code, 2)
        result = json.loads((self.out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(result["error_code"], "windows_required")
        self.assertFalse(result["ok"])

    def test_external_workspace_is_not_removed_on_report_failure(self):
        external = self.directory / "must-survive"
        external.mkdir()
        marker = external / "private"
        marker.write_text("do-not-log secret", encoding="utf-8")
        self.native.mutations["wait"] = lambda data: data.update(workspace=str(external))
        code, result = self.run_driver()
        self.assertNotEqual(code, 0)
        self.assertEqual(result["error_code"], "workspace_outside_output")
        self.assertTrue(marker.is_file())
        self.assertNotIn("do-not-log", json.dumps(result))

    def test_cleanup_refuses_output_root_and_executable_directory(self):
        copied = self.out / "Копия WarpPocket" / "WarpPocket.exe"
        copied.parent.mkdir()
        copied.write_bytes(b"exe")
        self.assert_failure("workspace_outside_output", smoke._remove_workspace,
                            self.out, self.out, copied)
        self.assert_failure("workspace_cleanup_unsafe", smoke._remove_workspace,
                            copied.parent, self.out, copied)
        self.assertTrue(copied.is_file())


class NativeHandleTests(unittest.TestCase):
    def setUp(self):
        self.kernel = mock.Mock()
        for name in ("CloseHandle", "TerminateProcess", "SetInformationJobObject",
                     "AssignProcessToJobObject", "TerminateJobObject"):
            getattr(self.kernel, name).return_value = True
        self.kernel.OpenProcess.return_value = 0x100001234
        self.kernel.CreateJobObjectW.return_value = 0x100002345
        self.kernel.WaitForSingleObject.return_value = smoke.WAIT_TIMEOUT
        self.kernel.ResumeThread.return_value = 1
        self.native = smoke.Windows(self.kernel)

    def test_full_signatures_and_pointer_sized_handles(self):
        self.assertIs(self.kernel.OpenProcess.restype, wintypes.HANDLE)
        self.assertEqual(self.kernel.OpenProcess.argtypes,
                         [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
        self.assertEqual(self.kernel.WaitForSingleObject.argtypes,
                         [wintypes.HANDLE, wintypes.DWORD])
        self.assertIs(self.kernel.WaitForSingleObject.restype, wintypes.DWORD)
        self.assertEqual(self.kernel.TerminateProcess.argtypes,
                         [wintypes.HANDLE, wintypes.UINT])
        self.assertIs(self.kernel.TerminateProcess.restype, wintypes.BOOL)
        process = self.native.open_process(INNER, terminate=True)
        rights = smoke.SYNCHRONIZE | smoke.PROCESS_QUERY_LIMITED_INFORMATION | smoke.PROCESS_TERMINATE
        self.kernel.OpenProcess.assert_called_once_with(rights, False, INNER)
        self.assertFalse(process.exited(0))
        self.kernel.WaitForSingleObject.return_value = smoke.WAIT_OBJECT_0
        self.assertTrue(process.exited(0.125))
        self.kernel.WaitForSingleObject.assert_called_with(0x100001234, 125)
        process.terminate()
        self.kernel.TerminateProcess.assert_called_once_with(0x100001234, 1)
        process.close()
        process.close()
        self.kernel.CloseHandle.assert_called_once_with(0x100001234)

    def test_helper_handle_does_not_request_terminate_access(self):
        self.native.open_process(CHILD)
        self.kernel.OpenProcess.assert_called_once_with(
            smoke.SYNCHRONIZE | smoke.PROCESS_QUERY_LIMITED_INFORMATION, False, CHILD,
        )

    def test_invalid_pid_open_failure_and_failed_wait_never_mean_dead(self):
        for pid in (True, 0, -1, "123", os.getpid()):
            with self.subTest(pid=pid), self.assertRaises(smoke.SmokeFailure):
                self.native.open_process(pid)
        self.kernel.OpenProcess.assert_not_called()
        self.kernel.OpenProcess.return_value = None
        with self.assertRaises(smoke.SmokeFailure):
            self.native.open_process(INNER)
        self.kernel.OpenProcess.return_value = 1234
        process = self.native.open_process(INNER)
        self.kernel.WaitForSingleObject.return_value = 0xFFFFFFFF
        with self.assertRaises(smoke.SmokeFailure) as caught:
            process.exited(1)
        self.assertEqual(caught.exception.code, "process_wait_failed")

    def test_native_membership_and_exit_code_use_output_pointers(self):
        def membership(handle, job, output):
            ctypes.cast(output, ctypes.POINTER(wintypes.BOOL)).contents.value = True
            return True

        def exit_code(handle, output):
            ctypes.cast(output, ctypes.POINTER(wintypes.DWORD)).contents.value = 7
            return True

        self.kernel.IsProcessInJob.side_effect = membership
        self.kernel.GetExitCodeProcess.side_effect = exit_code
        self.kernel.WaitForSingleObject.return_value = smoke.WAIT_OBJECT_0
        process = self.native.open_process(INNER)
        self.assertTrue(process.belongs_to(SimpleNamespace(job=456)))
        self.assertEqual(process.exit_code(), 7)

    def native_creation(self, *args):
        self.assertEqual(args[0], 'C:\\Копия WarpPocket\\WarpPocket.exe')
        self.assertIn('"C:\\Копия WarpPocket\\WarpPocket.exe"', args[1].value)
        self.assertFalse(args[4])  # No handles (especially the safety job) inherited.
        self.assertEqual(args[5], 0x08000004)  # Suspended, before assignment.
        startup = ctypes.cast(args[8], ctypes.POINTER(smoke._STARTUPINFOW)).contents
        self.assertEqual(startup.cb, ctypes.sizeof(smoke._STARTUPINFOW))
        info = ctypes.cast(args[9], ctypes.POINTER(smoke._PROCESS_INFORMATION)).contents
        info.hProcess, info.hThread, info.dwProcessId = 0x100003456, 0x100004567, LAUNCHER
        return True

    def launch(self):
        self.kernel.CreateProcessW.side_effect = self.native_creation
        return self.native.launch(
            ['C:\\Копия WarpPocket\\WarpPocket.exe', '--smoke-wait', 'C:\\out\\wait.json'],
            Path('C:\\external'),
        )

    def test_launcher_is_assigned_to_safety_job_before_resuming(self):
        flags = []

        def set_limits(job, kind, output, size):
            self.assertEqual(kind, 9)
            flags.append(ctypes.cast(output, ctypes.POINTER(smoke._EXTENDED_LIMITS))
                         .contents.BasicLimitInformation.LimitFlags)
            return True

        self.kernel.SetInformationJobObject.side_effect = set_limits
        launch = self.launch()
        names = [call[0] for call in self.kernel.mock_calls]
        self.assertLess(names.index("CreateProcessW"), names.index("AssignProcessToJobObject"))
        self.assertLess(names.index("AssignProcessToJobObject"), names.index("ResumeThread"))
        self.kernel.AssignProcessToJobObject.assert_called_once_with(0x100002345, 0x100003456)
        self.kernel.CloseHandle.assert_called_once_with(0x100004567)  # Only thread closed.
        self.kernel.TerminateJobObject.assert_not_called()
        self.assertEqual(launch.process.pid, LAUNCHER)
        self.assertEqual(launch.process.handle, 0x100003456)
        self.assertEqual(flags, [0x2000])  # Last-resort KILL_ON_JOB_CLOSE.
        launch.close()

    def test_assignment_or_resume_failure_cleans_suspended_process_boundedly(self):
        for failure in ("assign", "resume"):
            with self.subTest(failure=failure):
                self.setUp()
                if failure == "assign":
                    self.kernel.AssignProcessToJobObject.return_value = False
                else:
                    self.kernel.ResumeThread.return_value = 0xFFFFFFFF
                with self.assertRaises(smoke.SmokeFailure):
                    self.launch()
                self.kernel.TerminateProcess.assert_called_once_with(0x100003456, 1)
                self.kernel.WaitForSingleObject.assert_called_once_with(0x100003456, 10000)
                self.assertEqual(self.kernel.CloseHandle.call_count, 3)
                if failure == "assign":
                    self.kernel.ResumeThread.assert_not_called()

    def test_job_empty_query_and_cleanup_timeout_are_not_assumed_success(self):
        def active(job, kind, output, size, returned):
            self.assertEqual(kind, 1)
            ctypes.cast(output, ctypes.POINTER(smoke._ACCOUNTING)).contents.ActiveProcesses = 1
            return True

        self.kernel.QueryInformationJobObject.side_effect = active
        process = self.native.open_process(INNER)
        launch = smoke.Launch(self.native, 456, process)
        self.assertFalse(launch.empty())
        with self.assertRaises(smoke.SmokeFailure) as caught:
            launch.teardown(0, 0.001)
        self.assertEqual(caught.exception.code, "cleanup_timeout")
        self.kernel.TerminateJobObject.assert_called_once_with(456, 1)

    def test_failed_job_termination_closes_job_before_releasing_launcher_handle(self):
        self.kernel.TerminateJobObject.return_value = False
        process = self.native.open_process(INNER)
        launch = smoke.Launch(self.native, 456, process)
        with self.assertRaises(smoke.SmokeFailure) as caught:
            launch.teardown(0.01, 0.001)
        self.assertEqual(caught.exception.code, "job_terminate_failed")
        self.assertIsNone(launch.job)
        self.assertIsNotNone(process.handle)
        self.kernel.CloseHandle.assert_called_once_with(456)
        self.kernel.WaitForSingleObject.assert_called_once_with(process.handle, 10)
        launch.close()
        self.assertEqual(self.kernel.CloseHandle.call_count, 2)


class PortTests(unittest.TestCase):
    def test_probe_is_ipv4_loopback_with_a_bounded_timeout(self):
        with mock.patch.object(smoke.socket, "socket") as factory:
            client = factory.return_value.__enter__.return_value
            client.connect_ex.return_value = 0
            self.assertTrue(smoke._port_open(1080))
            factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout.assert_called_once_with(0.2)
            client.connect_ex.assert_called_once_with(("127.0.0.1", 1080))

    def test_real_listener_then_closed_port(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertTrue(smoke._port_open(port))
        self.assertFalse(smoke._port_open(port))


if __name__ == "__main__":
    unittest.main()
