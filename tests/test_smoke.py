import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from warppocket.backend import bundled_binary
from warppocket.models import AppError
from warppocket.smoke import run_smoke


class SmokeTests(unittest.TestCase):
    def test_missing_resource_records_safe_failure_and_cleans_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "smoke.json"
            with patch("warppocket.smoke.bundled_binary",
                       side_effect=AppError("helper_missing", "secret must never be recorded")):
                self.assertEqual(run_smoke(report_path), 1)
            report = json.loads(report_path.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["error_code"], "helper_missing")
            self.assertEqual(report["pid"], os.getpid())
            self.assertNotIn("secret", report_path.read_text())
            self.assertFalse(Path(report["workspace"]).exists())

    def test_smoke_modes_are_mutually_exclusive(self):
        from warppocket.__main__ import main
        with self.assertRaises(SystemExit) as caught:
            main(["--smoke", "first.json", "--smoke-wait", "second.json"])
        self.assertEqual(caught.exception.code, 2)

    def test_real_offline_smoke_closes_gui_helper_and_workspace(self):
        try:
            import tkinter as tk
        except ImportError:
            self.skipTest("Tk required")
        try:
            root = tk.Tk()
            root.destroy()
        except tk.TclError:
            self.skipTest("Tk display required (use Xvfb on Linux)")
        try:
            bundled_binary("wgcf")
            bundled_binary("wireproxy")
        except AppError:
            self.skipTest("build/fetch the pinned helpers to run offline smoke")
        with tempfile.TemporaryDirectory(prefix="WarpPocket путь ") as directory:
            report_path = Path(directory) / "smoke.json"
            result = subprocess.run(
                [sys.executable, "-m", "warppocket", "--smoke", str(report_path)],
                timeout=30, capture_output=True,
            )
            report = json.loads(report_path.read_text())
            self.assertEqual(result.returncode, 0, report)
            self.assertTrue(report["ok"])
            self.assertTrue(report["checks"]["ui"])
            self.assertTrue(report["checks"]["helper_stopped"])
            self.assertTrue(report["checks"]["runtime_clean"])
            self.assertTrue(report["checks"]["window_closed"])
            self.assertNotEqual(report["pid"], os.getpid())
            self.assertFalse(Path(report["workspace"]).exists())
