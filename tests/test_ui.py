"""UI behaviour tests. They need a display; on headless Linux they skip.

CI runs this module under Xvfb on Linux and natively on Windows.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from warppocket.controller import ConnectionState
from warppocket.ui import SOCKS_ADDRESS, WarpPocketApp


class FakeController:
    def __init__(self):
        self.state = ConnectionState.DISCONNECTED
        self.endpoint = None
        self.latency_ms = None
        self.searching = False
        self.calls = []
        self.closed = threading.Event()
        self._events = []

    def status(self):
        return {
            "state": self.state, "code": None, "message": None,
            "endpoint": self.endpoint, "latency_ms": self.latency_ms,
            "searching": self.searching, "search_role": None,
        }

    def push(self, event):
        self._events.append(event)

    def poll_events(self):
        events, self._events = self._events, []
        return events

    def connect(self, *, consent=False):
        self.calls.append(("connect", consent))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def start_search(self, *, probe_consent=False):
        self.calls.append(("start_search", probe_consent))
        self.searching = True

    def cancel_search(self):
        self.calls.append(("cancel_search",))
        self.searching = False

    def close(self):
        self.calls.append(("close",))
        self.closed.set()


class UiTests(unittest.TestCase):
    def setUp(self):
        try:
            import tkinter as tk
        except Exception as error:  # pragma: no cover - platform dependent
            self.skipTest(f"Tk unavailable: {error}")
        try:
            self.root = tk.Tk()
        except Exception as error:  # pragma: no cover - headless Linux
            self.skipTest(f"display unavailable: {error}")
        self.root.withdraw()
        self._apps = []

    def tearDown(self):
        for app in getattr(self, "_apps", []):
            app.stop_pump()
        try:
            self.root.destroy()
        except Exception:
            pass

    def make(self, controller, **kwargs):
        app = WarpPocketApp(controller, root=self.root, **kwargs)
        self._apps.append(app)
        return app

    def test_initial_labels_and_address(self):
        app = self.make(FakeController())
        app._render()
        self.assertEqual(app._status.cget("text"), "Отключено")
        self.assertEqual(app._address.get(), SOCKS_ADDRESS)
        self.assertEqual(app._connect.cget("text"), "Подключиться")
        self.assertEqual(app._search.cget("text"), "Найти новую стратегию")

    def test_connect_requires_consent_then_retries_with_it(self):
        controller = FakeController()
        app = self.make(controller, confirm=lambda title, text: True)
        app._on_connect()
        controller.push({"type": "state", "state": "error", "code": "consent_required", "message": "нужно согласие"})
        app.process_events()
        self.assertEqual(controller.calls, [("connect", False), ("connect", True)])

    def test_declined_consent_does_not_connect(self):
        controller = FakeController()
        app = self.make(controller, confirm=lambda title, text: False)
        controller.push({"type": "state", "state": "error", "code": "consent_required", "message": "нужно согласие"})
        app.process_events()
        self.assertEqual(controller.calls, [])

    def test_connected_state_renders_endpoint_and_toggle(self):
        controller = FakeController()
        controller.state = ConnectionState.CONNECTED
        controller.endpoint = "162.159.192.1:2408"
        controller.latency_ms = 82.0
        app = self.make(controller)
        app._render()
        self.assertEqual(app._status.cget("text"), "Подключено через WARP")
        self.assertEqual(app._connect.cget("text"), "Отключиться")
        self.assertIn("162.159.192.1:2408", app._endpoint.cget("text"))
        self.assertIn("82 мс", app._endpoint.cget("text"))

    def test_connecting_button_cancels_instead_of_starting_again(self):
        controller = FakeController()
        controller.state = ConnectionState.CONNECTING
        app = self.make(controller)
        app._render()
        self.assertEqual(app._connect.cget("text"), "Отмена")
        app._on_connect()
        self.assertEqual(controller.calls, [("disconnect",)])

    def test_search_toggle_progress_and_cancel(self):
        controller = FakeController()
        controller.state = ConnectionState.CONNECTED
        app = self.make(controller)
        app._on_search()
        self.assertEqual(controller.calls, [("start_search", False)])
        app._render()
        self.assertEqual(app._search.cget("text"), "Отменить поиск")
        self.assertNotIn("disabled", app._connect.state())  # Disconnect remains available during probe search.
        controller.push({"type": "search_progress", "checked": 3, "limit": 30, "found": 1})
        app.process_events()
        app._render()
        self.assertEqual(app._progress_label.cget("text"), "Проверено 3 из 30; найдено 1")
        app._on_search()
        self.assertIn(("cancel_search",), controller.calls)

    def test_search_done_reports_saved_variant(self):
        controller = FakeController()
        app = self.make(controller)
        controller.push({"type": "search_done", "saved": True, "best": "188.114.96.1:4500",
                         "checked": 5, "found": 2})
        app.process_events()
        app._render()
        self.assertIn("Сохранено", app._notice_label.cget("text"))
        self.assertIn("188.114.96.1:4500", app._notice_label.cget("text"))

    def test_copy_puts_address_into_clipboard(self):
        app = self.make(FakeController())
        try:
            app._on_copy()
            self.root.update()
            self.assertEqual(self.root.clipboard_get(), SOCKS_ADDRESS)
        except Exception as error:  # pragma: no cover - clipboardless display
            self.skipTest(f"clipboard unavailable: {error}")

    def test_import_is_blocked_until_disconnected(self):
        controller = FakeController()
        controller.state = ConnectionState.CONNECTED
        shown, imported = [], []
        app = self.make(controller, show=lambda title, text: shown.append(text),
                        choose_file=lambda title, types: "/tmp/profile.conf",
                        importer=lambda path, role: imported.append((path, role)))
        app._on_import("primary")
        self.assertEqual(imported, [])
        self.assertTrue(shown)
        controller.state = ConnectionState.DISCONNECTED
        app._on_import("primary")
        self.assertEqual(imported, [("/tmp/profile.conf", "primary")])

    def test_error_event_is_shown_to_the_user(self):
        controller = FakeController()
        app = self.make(controller)
        controller.push({"type": "error", "code": "busy", "message": "Идёт другая операция."})
        app.process_events()
        app._render()
        self.assertEqual(app._notice_label.cget("text"), "Идёт другая операция.")

    def test_window_close_stops_the_controller(self):
        controller = FakeController()
        app = self.make(controller)
        app.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not controller.closed.is_set():
            time.sleep(0.05)
        self.assertTrue(controller.closed.is_set())
        self.assertIn(("close",), controller.calls)
        self.assertTrue(app._close_done.is_set())


if __name__ == "__main__":
    unittest.main()
