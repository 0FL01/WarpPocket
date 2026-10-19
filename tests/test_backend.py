import socket
import tempfile
import unittest
import base64
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from warppocket.backend import WireProxyBackend, bundled_binary
from warppocket.models import AppError, Endpoint, Profile
from warppocket.profiles import ProfileService, parse_profile, render_profile
from warppocket.storage import AppPaths, Storage, atomic_write


class BackendTests(unittest.TestCase):
    def test_runtime_dns_override_preserves_saved_and_imported_profiles_for_both_roles(self):
        original = Profile(base64.b64encode(bytes(range(32))).decode(),
                           ("172.16.0.2/32", "2606:4700:110::1/128"),
                           ("1.1.1.1", "2606:4700:4700::1111"),
                           base64.b64encode(bytes(range(32, 64))).decode(),
                           Endpoint("127.0.0.1", 9), ("0.0.0.0/0", "::/0", "10.0.0.0/8"),
                           mtu=1420, keepalive=25,
                           preshared_key=base64.b64encode(bytes(range(64, 96))).decode(),
                           reserved=(7, 8, 9))
        original_content = render_profile(original).encode("utf-8")
        endpoint = Endpoint("127.0.0.1", 10)
        for role in ("primary", "probe"):
            for mode in ("saved", "imported"):
                with self.subTest(role=role, mode=mode), tempfile.TemporaryDirectory() as directory:
                    paths = AppPaths(Path(directory))
                    storage = Storage(paths)
                    service = ProfileService(storage, None, Path("/not-used"))
                    persisted = paths.profile_dir(role) / "profile.conf"
                    source = paths.root / "import.conf"
                    if mode == "imported":
                        source.write_bytes(original_content)
                        profile = service.import_profile(source, role)
                    else:
                        atomic_write(persisted, original_content)
                        profile = service.load(role)
                    manager = Mock()
                    manager.start.return_value.poll.return_value = None
                    backend = WireProxyBackend(paths, manager, Path("/not-used"))
                    with patch("warppocket.backend.socket.create_connection") as connect:
                        connect.return_value.__enter__.return_value.recv.return_value = b"\x05\x00"
                        instance = backend.start(profile, endpoint, role=role)
                    try:
                        config = instance.config.read_text(encoding="utf-8")
                        self.assertEqual([line for line in config.splitlines() if line.startswith("DNS =")],
                                         ["DNS = 83.220.169.155, 212.109.195.93, 194.87.196.13, 45.151.102.219, 9.9.9.9"])
                        runtime = parse_profile(config.split("\n[Socks5]\n", 1)[0])
                        self.assertEqual(runtime, replace(original, dns=("83.220.169.155", "212.109.195.93", "194.87.196.13",
                                                                        "45.151.102.219", "9.9.9.9"),
                                                          endpoint=endpoint))
                        self.assertEqual(profile, original)
                        self.assertEqual(persisted.read_bytes(), original_content)
                        if mode == "imported":
                            self.assertEqual(source.read_bytes(), original_content)
                        self.assertEqual(instance.role, role)
                        self.assertEqual(instance.endpoint, endpoint)
                        manager.start.assert_called_once()
                        manager.stop.assert_not_called()
                    finally:
                        backend.stop(instance)
                    manager.stop.assert_called_once_with(instance.process)
                    self.assertFalse(instance.config.exists())

    def test_occupied_port_never_launches_or_kills_foreign_process(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as occupied:
            paths = AppPaths(Path(directory))
            Storage(paths)
            manager = Mock()
            backend = WireProxyBackend(paths, manager, Path("/not-used"))
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            with self.assertRaises(AppError) as caught:
                backend.start(Mock(), Endpoint("127.0.0.1", 2408), role="primary", port=occupied.getsockname()[1])
            self.assertEqual(caught.exception.code, "port_busy")
            manager.start.assert_not_called()
            manager.stop.assert_not_called()

    def test_real_helper_reconnects_after_server_closes_socks_session(self):
        from warppocket.process_manager import ProcessManager
        try:
            binary = bundled_binary("wireproxy")
        except AppError:
            self.skipTest("run scripts/fetch_vendor.py to enable actual-helper smoke")
        profile = Profile(base64.b64encode(bytes(range(32))).decode(), ("172.16.0.2/32",),
                          ("1.1.1.1",), base64.b64encode(bytes(range(32, 64))).decode(),
                          Endpoint("127.0.0.1", 9), ("0.0.0.0/0",))
        with tempfile.TemporaryDirectory() as directory:
            paths = AppPaths(Path(directory))
            Storage(paths)
            manager = ProcessManager()
            self.addCleanup(manager.shutdown)
            backend = WireProxyBackend(paths, manager, binary)
            first = backend.start(profile, profile.endpoint, role="primary")
            port = first.port
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(b"\x05\x01\x02")  # Unsupported auth: server closes first.
                self.assertEqual(connection.recv(2), b"\x05\xff")
                self.assertEqual(connection.recv(1), b"")
            backend.stop(first)
            second = backend.start(profile, profile.endpoint, role="primary", port=port)
            self.assertIsNone(second.process.poll())
            self.assertEqual(second.port, port)
            backend.stop(second)

    def test_real_helper_offline_loopback_configuration_and_cleanup(self):
        from warppocket.process_manager import ProcessManager
        try:
            binary = bundled_binary("wireproxy")
        except AppError:
            self.skipTest("run scripts/fetch_vendor.py to enable actual-helper smoke")
        key = base64.b64encode(bytes(range(32))).decode()
        public = base64.b64encode(bytes(range(32, 64))).decode()
        profile = Profile(key, ("172.16.0.2/32",), ("1.1.1.1",), public,
                          Endpoint("127.0.0.1", 9), ("0.0.0.0/0",), reserved=(7, 8, 9))
        original_content = render_profile(profile)
        with tempfile.TemporaryDirectory(prefix="WarpPocket путь ") as directory:
            paths = AppPaths(Path(directory))
            Storage(paths)
            manager = ProcessManager()
            self.addCleanup(manager.shutdown)
            backend = WireProxyBackend(paths, manager, binary)
            for role in ("primary", "probe"):
                with self.subTest(role=role):
                    instance = backend.start(profile, profile.endpoint, role=role)
                    try:
                        self.assertIsNone(instance.process.poll())
                        config = instance.config.read_text(encoding="utf-8")
                        self.assertIn("ResolveStrategy = ipv4", config)
                        self.assertEqual([line for line in config.splitlines() if line.startswith("DNS =")],
                                         ["DNS = 83.220.169.155, 212.109.195.93, 194.87.196.13, 45.151.102.219, 9.9.9.9"])
                        self.assertIn("Reserved = 7, 8, 9", config)
                        self.assertEqual(profile.dns, ("1.1.1.1",))
                        self.assertEqual(render_profile(profile), original_content)
                        self.assertIn(f"BindAddress = 127.0.0.1:{instance.port}", config)
                    finally:
                        backend.stop(instance)
                    backend.stop(instance)
                    self.assertFalse(instance.config.exists())
                    with socket.socket() as connection:
                        self.assertNotEqual(connection.connect_ex(("127.0.0.1", instance.port)), 0)
