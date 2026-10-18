import base64
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from warppocket.models import AppError
from warppocket.profiles import ProfileService, parse_profile, render_profile
from warppocket.storage import AppPaths, Storage, atomic_write

PRIVATE = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(range(32, 64))).decode()
PROFILE = f"""[Interface]
PrivateKey = {PRIVATE}
Address = 172.16.0.2/32, 2606:4700:110::1/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
[Peer]
PublicKey = {PUBLIC}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25
"""


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = Storage(AppPaths(Path(self.temp.name)))
        self.service = ProfileService(self.storage, None, Path("/unused/wgcf"))

    def test_normalization_and_reject_unsafe_extensions(self):
        parsed = parse_profile(PROFILE)
        self.assertEqual(parse_profile(render_profile(parsed)), parsed)
        self.assertNotIn(PRIVATE, repr(parsed))
        for text in (PROFILE + "Reserved = 1, 2, 3\n", PROFILE + "[Socks5]\nBindAddress = 0.0.0.0:1\n",
                     PROFILE.replace("MTU = 1280", "MTU = 1280\nmtu = 1280"),
                     PROFILE + "[peer]\nPublicKey = bad\n", PROFILE.replace(PRIVATE, "$PRIVATE_KEY"),
                     PROFILE.replace("DNS = 1.1.1.1, 1.0.0.1", "DNS = localhost"),
                     "WGConfig = /private/file\n" + PROFILE):
            with self.subTest(kind=text[-25:]):
                with self.assertRaises(AppError) as caught:
                    parse_profile(text)
                self.assertNotIn(PRIVATE, str(caught.exception))

    def test_import_rejects_same_effective_identity(self):
        primary = self.storage.paths.profile_dir("primary") / "profile.conf"
        atomic_write(primary, PROFILE.encode())
        alternate = bytearray(range(32))
        alternate[0] ^= 7  # X25519 discards these bits.
        source = self.storage.paths.root / "import.conf"
        source.write_text(PROFILE.replace(PRIVATE, base64.b64encode(alternate).decode()), encoding="utf-8")
        with self.assertRaises(AppError) as caught:
            self.service.import_profile(source, "probe")
        self.assertEqual(caught.exception.code, "profile_same_key")
        self.assertFalse(self.service.exists("probe"))

    def test_profile_reuse_never_registers(self):
        atomic_write(self.storage.paths.profile_dir("primary") / "profile.conf", PROFILE.encode())
        with patch.object(self.service, "_run") as run:
            self.assertEqual(self.service.ensure_profile("primary"), parse_profile(PROFILE))
        run.assert_not_called()

    def test_partial_registration_account_recovers_by_generate(self):
        folder = self.storage.paths.profile_dir("primary")
        account = folder / "account.toml"
        calls = []
        def run(args, cwd, cancel):
            calls.append(args)
            if "register" in args:
                account.write_text(f'private_key = "{PRIVATE}"\ndevice_id = "device"\naccess_token = "secret-token"\n', encoding="utf-8")
                return 1  # Upstream can write the account then fail.
            Path(args[-1]).write_text(PROFILE, encoding="utf-8")
            return 0
        with patch.object(self.service, "_run", side_effect=run):
            self.service.ensure_profile("primary", consent=True)
            self.service.ensure_profile("primary", consent=False)
        self.assertEqual(sum("register" in call for call in calls), 1)
        self.assertEqual(sum("generate" in call for call in calls), 1)
        self.assertFalse((folder / "generated.conf").exists())

    def test_missing_consent_and_corrupt_account_do_not_register(self):
        with patch.object(self.service, "_run") as run:
            with self.assertRaises(AppError):
                self.service.ensure_profile("primary")
            (self.storage.paths.profile_dir("primary") / "account.toml").write_text("broken", encoding="utf-8")
            with self.assertRaises(AppError):
                self.service.ensure_profile("primary", consent=True)
        run.assert_not_called()

    def test_run_sanitizes_environment_and_stops_on_cancel(self):
        from unittest.mock import Mock
        process, manager = Mock(), Mock()
        process.poll.return_value = 0
        manager.start.return_value = process
        service = ProfileService(self.storage, manager, Path("/unused/wgcf"))
        with patch.dict(os.environ, {"WGCF_PRIVATE_KEY": "secret", "wgcf_access_token": "token"}):
            service._run(["--help"], self.storage.paths.root, threading.Event())
        self.assertFalse(any(key.upper().startswith("WGCF_") for key in manager.start.call_args.kwargs["env"]))
        manager.stop.assert_called_once_with(process)
