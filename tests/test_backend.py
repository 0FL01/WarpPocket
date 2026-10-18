import socket
import tempfile
import unittest
import base64
from pathlib import Path
from unittest.mock import Mock

from warppocket.backend import WireProxyBackend, bundled_binary
from warppocket.models import AppError, Endpoint, Profile
from warppocket.storage import AppPaths, Storage


class BackendTests(unittest.TestCase):
    def test_occupied_port_never_launches_or_kills_foreign_process(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as occupied:
            paths = AppPaths(Path(directory))
            Storage(paths)
            manager = Mock()
            backend = WireProxyBackend(paths, manager, Path("/not-used"))
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            with self.assertRaises(AppError) as caught:
                backend.start(Mock(), Endpoint("127.0.0.1", 2408), role="primary", port=occupied.getsockname()[1])
            self.assertEqual(caught.exception.code, "port_busy")
            manager.start.assert_not_called()
            manager.stop.assert_not_called()

    def test_real_helper_offline_loopback_configuration_and_cleanup(self):
        from warppocket.process_manager import ProcessManager
        try:
            binary = bundled_binary("wireproxy")
        except AppError:
            self.skipTest("run scripts/fetch_vendor.py to enable actual-helper smoke")
        key = base64.b64encode(bytes(range(32))).decode()
        public = base64.b64encode(bytes(range(32, 64))).decode()
        profile = Profile(key, ("172.16.0.2/32",), ("1.1.1.1",), public,
                          Endpoint("127.0.0.1", 9), ("0.0.0.0/0",))
        with tempfile.TemporaryDirectory(prefix="WarpPocket путь ") as directory:
            paths = AppPaths(Path(directory))
            Storage(paths)
            manager = ProcessManager()
            self.addCleanup(manager.shutdown)
            backend = WireProxyBackend(paths, manager, binary)
            instance = backend.start(profile, profile.endpoint, role="primary")
            self.assertIsNone(instance.process.poll())
            config = instance.config.read_text(encoding="utf-8")
            self.assertIn("ResolveStrategy = ipv4", config)
            self.assertIn("DNS = 1.1.1.1", config)
            self.assertIn(f"BindAddress = 127.0.0.1:{instance.port}", config)
            backend.stop(instance)
            backend.stop(instance)
            self.assertFalse(instance.config.exists())
            with socket.socket() as connection:
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", instance.port)), 0)
