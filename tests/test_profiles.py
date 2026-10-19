import base64
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from warppocket.models import AppError
from warppocket.profiles import ProfileService, _fetch_reserved, parse_profile, render_profile
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


RESERVED = bytes((7, 8, 9))


class FakeResponse:
    def __init__(self, status_code=200, payload=b""):
        self.status_code = status_code
        self._payload = payload

    def iter_content(self, size):
        yield self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.trust_env = True

    def get(self, url, **kwargs):
        self.requests.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def patch(self, url, **kwargs):
        self.requests.append(("PATCH", url, kwargs))
        return self.responses.pop(0)

    def close(self):
        pass


def api_body(warp_enabled=True, client_id=RESERVED):
    return json.dumps({"config": {"warp_enabled": warp_enabled,
                                  "client_id": base64.b64encode(client_id).decode()}}).encode()


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
        for text in (PROFILE + "[Socks5]\nBindAddress = 0.0.0.0:1\n",
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

    def test_reserved_round_trip_and_import(self):
        text = PROFILE + "Reserved = 7, 8, 9\n"
        parsed = parse_profile(text)
        self.assertEqual(parsed.reserved, (7, 8, 9))
        self.assertEqual(parse_profile(render_profile(parsed)), parsed)
        source = self.storage.paths.root / "import.conf"
        source.write_text(text, encoding="utf-8")
        imported = self.service.import_profile(source, "primary")
        self.assertEqual(imported.reserved, (7, 8, 9))
        self.assertIn("Reserved = 7, 8, 9", render_profile(self.service.load("primary")))

    def test_invalid_reserved_rejected(self):
        for value in ("1, 2", "1, 2, 3, 4", "256, 0, 0", "a, b, c", "-1, 2, 3", "0x1, 2, 3", "1, 2, 3.5"):
            with self.subTest(value=value):
                with self.assertRaises(AppError):
                    parse_profile(PROFILE + f"Reserved = {value}\n")

    def test_ensure_reserved_persists_and_reuses(self):
        atomic_write(self.storage.paths.profile_dir("primary") / "profile.conf", PROFILE.encode())
        account = self.storage.paths.profile_dir("primary") / "account.toml"
        account.write_text(f'private_key = "{PRIVATE}"\ndevice_id = "device"\naccess_token = "token"\n', encoding="utf-8")
        with patch("warppocket.profiles._fetch_reserved", return_value=(7, 8, 9)) as fetch:
            updated = self.service.ensure_reserved("primary")
            self.assertEqual(updated.reserved, (7, 8, 9))
            self.assertEqual(updated.identity(), parse_profile(PROFILE).identity())
            self.assertEqual(self.service.load("primary").reserved, (7, 8, 9))
            self.service.ensure_reserved("primary")
        self.assertEqual(fetch.call_count, 1)

    def test_ensure_reserved_without_account_is_safe(self):
        atomic_write(self.storage.paths.profile_dir("primary") / "profile.conf", PROFILE.encode())
        with patch("warppocket.profiles._fetch_reserved") as fetch:
            with self.assertRaises(AppError) as caught:
                self.service.ensure_reserved("primary")
        self.assertEqual(caught.exception.code, "reserved_unavailable")
        fetch.assert_not_called()
        self.assertIsNone(self.service.load("primary").reserved)

    def test_fetch_reserved_enables_warp_and_reads_client_id(self):
        session = FakeSession([
            FakeResponse(payload=api_body(warp_enabled=False, client_id=RESERVED)),
            FakeResponse(payload=api_body(warp_enabled=True, client_id=bytes((10, 11, 12)))),
        ])
        self.assertEqual(_fetch_reserved("device", "token", session=session), (10, 11, 12))
        self.assertEqual([item[0] for item in session.requests], ["GET", "PATCH"])
        self.assertFalse(session.trust_env)
        self.assertIn(b"warp_enabled", session.requests[1][2]["data"])

    def test_fetch_reserved_returns_bytes_without_patch_when_enabled(self):
        session = FakeSession([FakeResponse(payload=api_body(warp_enabled=True, client_id=RESERVED))])
        self.assertEqual(_fetch_reserved("device", "token", session=session), (7, 8, 9))
        self.assertEqual([item[0] for item in session.requests], ["GET"])

    def test_fetch_reserved_errors_are_safe(self):
        with self.assertRaises(AppError) as caught:
            _fetch_reserved("device", "token", session=FakeSession([FakeResponse(status_code=500)]))
        self.assertEqual(caught.exception.code, "reserved_unavailable")
        with self.assertRaises(AppError):
            _fetch_reserved("device", "token", session=FakeSession([FakeResponse(payload=api_body(client_id=b"ab"))]))
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(AppError) as stopped:
            _fetch_reserved("device", "token", cancel=cancelled, session=FakeSession([]))
        self.assertEqual(stopped.exception.code, "cancelled")
