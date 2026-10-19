"""Offline vendor integrity tests. Network calls are replaced with stdlib mocks."""

from __future__ import annotations

import copy
import hashlib
from http.client import IncompleteRead
import importlib.util
import io
import json
from pathlib import Path
import shutil
import ssl
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.error import URLError
from urllib.request import HTTPSHandler, Request


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "warppocket_fetch_vendor", ROOT / "scripts" / "fetch_vendor.py"
)
assert SPEC is not None and SPEC.loader is not None
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)
BUILD_SPEC = importlib.util.spec_from_file_location(
    "warppocket_build_wireproxy", ROOT / "scripts" / "build_wireproxy.py"
)
assert BUILD_SPEC is not None and BUILD_SPEC.loader is not None
builder = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(builder)

WGCF_LINUX_SHA256 = "4fb7a136aa470ece11d17949c7db07b040ec9c604742dc8680bcf1889f85d0c8"
WGCF_WINDOWS_SHA256 = "e222fd9443d7cb3264d825a3e86967797fc9c938507c5d93e3cc21e4aed11dcc"


class Response(io.BytesIO):
    def __init__(self, payload: bytes, *, length: int | None = None):
        super().__init__(payload)
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def geturl(self):
        return "https://release-assets.githubusercontent.com/fake-verified-download"


def make_archive(entries: list[tuple[str, bytes, bytes]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, kind, payload in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                entry.linkname = "../../outside"
            elif kind in (tarfile.REGTYPE, tarfile.AREGTYPE):
                entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload) if entry.size else None)
    return stream.getvalue()


class VendorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="warppocket-vendor-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "vendor" / "linux-amd64"
        self.manifest = json.loads((ROOT / "vendor" / "manifest.json").read_text("utf-8"))
        self.opener = mock.Mock()
        self.opener.open.side_effect = AssertionError("Tests must never use the Internet")
        self.open_patch = mock.patch.object(vendor, "build_opener", return_value=self.opener)
        self.build_opener = self.open_patch.start()
        self.addCleanup(self.open_patch.stop)

    def record(self, name: str, payload: bytes, platform: str = "linux-amd64") -> dict:
        record = {
            "platform": platform,
            "name": name,
            "version": "0.0.0",
            "url": (
                f"https://github.com/windtf/wireproxy/releases/download/v0.0.0"
                f"/wireproxy_{platform}.tar.gz"
                if name == "wireproxy"
                else f"https://github.com/ViRb3/wgcf/releases/download/v0.0.0/{name}"
            ),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        if name == "wireproxy":
            record["archive_member"] = (
                "wireproxy.exe" if platform == "windows-amd64" else "wireproxy"
            )
        return record

    def respond(self, payload: bytes, *, length: int | None = None):
        self.opener.open.side_effect = None
        self.opener.open.return_value = Response(payload, length=length)

    def write_manifest(self, data: dict):
        path = self.root / "vendor" / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def assert_clean_directory(self, expected: list[str]):
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), expected)

    def test_manifest_has_exact_supported_targets(self):
        records = vendor.load_manifest()
        self.assertEqual(len(records), 2)
        self.assertEqual(
            {vendor.binary_name(item["platform"], item["name"]) for item in records},
            {"wgcf", "wgcf.exe"},
        )
        digests = {record["platform"]: record["sha256"] for record in records}
        self.assertEqual(digests, {
            "linux-amd64": WGCF_LINUX_SHA256,
            "windows-amd64": WGCF_WINDOWS_SHA256,
        })

    def test_raw_success_is_atomic_and_executable(self):
        payload = b"verified-linux-executable"
        record = self.record("wgcf", payload)
        self.respond(payload, length=len(payload))
        self.directory.mkdir(parents=True)
        target = self.directory / "wgcf"
        target.write_bytes(b"previous-binary")
        with mock.patch.object(vendor.os, "replace", wraps=vendor.os.replace) as replace:
            self.assertEqual(vendor.fetch_artifact(record, self.directory), target)
        self.assertEqual(target.read_bytes(), payload)
        if vendor.os.name != "nt":
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        replace.assert_called_once()
        staged, final = replace.call_args.args
        self.assertEqual(final, target)
        self.assertEqual(staged.parent.parent, self.directory)
        self.assert_clean_directory(["wgcf"])
        self.assertEqual(self.opener.open.call_args.kwargs["timeout"], vendor.SOCKET_TIMEOUT)
        self.assertEqual(self.opener.open.call_args.args[0].full_url, record["url"])
        handler = next(arg for arg in self.build_opener.call_args.args
                       if isinstance(arg, HTTPSHandler))
        self.assertTrue(handler._context.check_hostname)
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)

    def test_archive_success_copies_only_expected_binary(self):
        binary = b"verified-wireproxy"
        payload = make_archive([("wireproxy", tarfile.REGTYPE, binary)])
        self.respond(payload)
        target = vendor.fetch_artifact(self.record("wireproxy", payload), self.directory)
        self.assertEqual(target, self.directory / "wireproxy")
        self.assertEqual(target.read_bytes(), binary)
        self.assert_clean_directory(["wireproxy"])

    def test_windows_targets_have_exe_extension(self):
        for name in ("wgcf", "wireproxy"):
            with self.subTest(name=name):
                binary = b"windows-binary"
                payload = (make_archive([("wireproxy.exe", tarfile.REGTYPE, binary)])
                           if name == "wireproxy" else binary)
                record = self.record(name, payload, "windows-amd64")
                self.respond(payload)
                directory = self.root / "vendor" / "windows-amd64"
                target = vendor.fetch_artifact(record, directory)
                self.assertEqual(target, directory / f"{name}.exe")
                self.assertEqual(target.read_bytes(), binary)

    def test_bad_hash_never_extracts_or_replaces_existing_binary(self):
        payload = b"untrusted-archive-content"
        record = self.record("wireproxy", payload)
        record["sha256"] = "0" * 64
        self.respond(payload)
        self.directory.mkdir(parents=True)
        target = self.directory / "wireproxy"
        target.write_bytes(b"previous-verified-binary")
        with mock.patch.object(vendor, "unpack_binary") as unpack, \
                mock.patch.object(vendor.os, "replace") as replace:
            with self.assertRaisesRegex(vendor.VendorError, "SHA-256 mismatch"):
                vendor.fetch_artifact(record, self.directory)
        unpack.assert_not_called()
        replace.assert_not_called()
        self.assertEqual(target.read_bytes(), b"previous-verified-binary")
        self.assert_clean_directory(["wireproxy"])

    def test_download_error_leaves_no_binary_or_temporary_files(self):
        self.opener.open.side_effect = URLError("offline test failure")
        with self.assertRaisesRegex(vendor.VendorError, "Download failed"):
            vendor.fetch_artifact(self.record("wgcf", b"binary"), self.directory)
        self.assert_clean_directory([])

    def test_download_read_error_leaves_no_binary(self):
        for error in (OSError("read failed"), IncompleteRead(b"partial", 10)):
            with self.subTest(error=type(error).__name__):
                self.respond(b"partial")
                self.opener.open.return_value.read1 = mock.Mock(side_effect=error)
                with self.assertRaisesRegex(vendor.VendorError, "Download failed"):
                    vendor.fetch_artifact(self.record("wgcf", b"binary"), self.directory)
                self.assert_clean_directory([])

    def test_download_size_limits_cover_headers_and_stream(self):
        for length in (None, 100):
            with self.subTest(content_length=length):
                payload = b"too-many-bytes"
                self.respond(payload, length=length)
                with mock.patch.object(vendor, "MAX_DOWNLOAD_BYTES", 4):
                    with self.assertRaisesRegex(vendor.VendorError, "size limit"):
                        vendor.fetch_artifact(self.record("wgcf", payload), self.directory)
                self.assert_clean_directory([])

    def test_download_time_limit(self):
        payload = b"binary"
        self.respond(payload)
        with mock.patch.object(vendor.time, "monotonic", side_effect=[0, 121]):
            with self.assertRaisesRegex(vendor.VendorError, "time budget"):
                vendor.fetch_artifact(self.record("wgcf", payload), self.directory)
        self.assert_clean_directory([])

    def test_rejects_empty_download(self):
        self.respond(b"")
        with self.assertRaisesRegex(vendor.VendorError, "empty artifact"):
            vendor.fetch_artifact(self.record("wgcf", b""), self.directory)
        self.assert_clean_directory([])

    def test_rejects_unexpected_unsafe_duplicate_or_link_archive_members(self):
        regular = ("wireproxy", tarfile.REGTYPE, b"binary")
        cases = {
            "missing": [],
            "wrong-name": [("other", tarfile.REGTYPE, b"binary")],
            "traversal": [("../wireproxy", tarfile.REGTYPE, b"binary")],
            "absolute": [("/wireproxy", tarfile.REGTYPE, b"binary")],
            "nested": [("sub/wireproxy", tarfile.REGTYPE, b"binary")],
            "embedded-traversal": [("sub/../wireproxy", tarfile.REGTYPE, b"binary")],
            "symlink": [("wireproxy", tarfile.SYMTYPE, b"")],
            "hardlink": [("wireproxy", tarfile.LNKTYPE, b"")],
            "directory": [("wireproxy", tarfile.DIRTYPE, b"")],
            "fifo": [("wireproxy", tarfile.FIFOTYPE, b"")],
            "duplicate": [regular, regular],
            "extra-before": [("LICENSE", tarfile.REGTYPE, b"notice"), regular],
            "extra-after": [regular, ("LICENSE", tarfile.REGTYPE, b"notice")],
            "empty-binary": [("wireproxy", tarfile.REGTYPE, b"")],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                payload = make_archive(entries)
                self.respond(payload)
                with mock.patch.object(vendor.os, "replace") as replace:
                    with self.assertRaises(vendor.VendorError):
                        vendor.fetch_artifact(self.record("wireproxy", payload), self.directory)
                replace.assert_not_called()
                self.assert_clean_directory([])
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_malformed_archive(self):
        payload = b"not-a-gzip-tar"
        self.respond(payload)
        with self.assertRaisesRegex(vendor.VendorError, "Invalid helper archive"):
            vendor.fetch_artifact(self.record("wireproxy", payload), self.directory)
        self.assert_clean_directory([])

    def test_rejects_oversized_archive_binary(self):
        payload = make_archive([("wireproxy", tarfile.REGTYPE, b"binary")])
        self.respond(payload)
        with mock.patch.object(vendor, "MAX_BINARY_BYTES", 4):
            with self.assertRaisesRegex(vendor.VendorError, "binary size limit"):
                vendor.fetch_artifact(self.record("wireproxy", payload), self.directory)
        self.assert_clean_directory([])

    def test_fetch_platform_uses_deterministic_manifest_targets(self):
        raw = b"wgcf-binary"
        for artifact in self.manifest["artifacts"]:
            if artifact["platform"] == "linux-amd64":
                artifact["sha256"] = hashlib.sha256(raw).hexdigest()
        self.write_manifest(self.manifest)
        self.opener.open.side_effect = [Response(raw)]
        paths = vendor.fetch_platform("linux-amd64", root=self.root)
        self.assertEqual(paths, [self.directory / "wgcf"])
        self.assertEqual([path.read_bytes() for path in paths], [raw])
        self.assert_clean_directory(["wgcf"])
        self.assertFalse((self.root / "vendor" / "windows-amd64").exists())

    def test_manifest_rejects_unfixed_sources_and_bad_records(self):
        cases = []
        for key, value in (
            ("url", "http://github.com/windtf/wireproxy/releases/download/v1.1.3/a.tar.gz"),
            ("url", "https://example.org/wireproxy.tar.gz"),
            ("name", "../../outside"),
            ("archive_member", "../wireproxy"),
            ("sha256", "not-a-digest"),
        ):
            data = copy.deepcopy(self.manifest)
            data["artifacts"][0][key] = value
            cases.append(data)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["artifacts"].append(duplicate["artifacts"][0])
        cases.append(duplicate)
        missing = copy.deepcopy(self.manifest)
        missing["artifacts"].pop()
        cases.append(missing)
        for data in cases:
            with self.subTest(data=data["artifacts"][0]):
                self.write_manifest(data)
                with self.assertRaises(vendor.VendorError):
                    vendor.load_manifest(self.root)
        self.opener.open.assert_not_called()

    def test_redirect_cannot_downgrade_tls(self):
        handler = vendor.HTTPSOnlyRedirectHandler()
        request = Request("https://github.com/fixed-source")
        with self.assertRaisesRegex(vendor.VendorError, "non-HTTPS"):
            handler.redirect_request(request, None, 302, "Found", {}, "http://unsafe.invalid/a")

    def test_cli_failure_is_nonzero_and_does_not_claim_verified_cache(self):
        with mock.patch.object(vendor, "fetch_platform", side_effect=vendor.VendorError("bad hash")), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as error, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(vendor.main(["--platform", "linux-amd64"]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Do not use cached helpers", error.getvalue())


class WireproxyBuildTests(unittest.TestCase):
    """Offline checks for the pinned source-build inputs and target mapping."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="warppocket-build-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pins = json.loads(
            (ROOT / "vendor" / "wireproxy-build.json").read_text("utf-8")
        )

    def mutated(self, path: str, value) -> dict:
        data = copy.deepcopy(self.pins)
        target = data
        keys = path.split(".")
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value
        return data

    def write_pins(self, pins: dict):
        path = self.root / "vendor" / "wireproxy-build.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(pins), encoding="utf-8")

    def test_checked_in_pins_are_valid_and_pinned(self):
        pins = builder.load_pins()
        self.assertEqual(pins["schema_version"], 1)
        self.assertEqual(pins["patch"], "reserved-support")
        self.assertEqual(pins["wireproxy"]["version"], "1.1.3")
        self.assertEqual(pins["wireproxy"]["url"],
                         "https://github.com/windtf/wireproxy/archive/refs/tags/v1.1.3.tar.gz")
        self.assertEqual(pins["wireproxy"]["sha256"],
                         "b62e925d9efe402a14c6501dfa56137c49ece6a5be264095295d2565d747b1c7")
        self.assertEqual(pins["wireguard"]["module"], "golang.zx2c4.com/wireguard")
        self.assertEqual(pins["wireguard"]["version"], "v0.0.0-20250521234502-f333402bd9cb")

    def test_pins_reject_unfixed_sources_and_bad_records(self):
        cases = {
            "http-url": self.mutated(
                "wireproxy.url",
                "http://github.com/windtf/wireproxy/archive/refs/tags/v1.1.3.tar.gz",
            ),
            "foreign-host": self.mutated(
                "wireproxy.url",
                "https://example.org/windtf/wireproxy/archive/refs/tags/v1.1.3.tar.gz",
            ),
            "wrong-tag": self.mutated(
                "wireproxy.url",
                "https://github.com/windtf/wireproxy/archive/refs/tags/v9.9.9.tar.gz",
            ),
            "bad-digest": self.mutated("wireproxy.sha256", "not-a-digest"),
            "uppercase-digest": self.mutated("wireproxy.sha256", "B62E925D9EFE402A14C6501DFA56137C49ECE6A5BE264095295D2565D747B1C7"),
            "foreign-module": self.mutated("wireguard.module", "example.com/wireguard"),
            "unpinned-version": self.mutated("wireguard.version", "v1.2.3"),
            "bad-schema": self.mutated("schema_version", 2),
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                self.write_pins(data)
                with self.assertRaises(builder.BuildError):
                    builder.load_pins(self.root)

    def test_build_targets_map_to_fixed_goos_goarch_and_names(self):
        self.assertEqual(builder.target_for("linux-amd64"), ("linux", "amd64", "wireproxy"))
        self.assertEqual(builder.target_for("windows-amd64"),
                         ("windows", "amd64", "wireproxy.exe"))
        with self.assertRaises(builder.BuildError):
            builder.target_for("darwin-arm64")

    def test_source_extraction_accepts_only_safe_regular_members(self):
        good = make_archive([
            ("wireproxy-1.1.3", tarfile.DIRTYPE, b""),
            ("wireproxy-1.1.3/go.mod", tarfile.REGTYPE, b"module wireproxy\n"),
            ("wireproxy-1.1.3/cmd", tarfile.DIRTYPE, b""),
            ("wireproxy-1.1.3/cmd/app.go", tarfile.REGTYPE, b"package main\n"),
        ])
        root = builder.extract_source(good, "1.1.3")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.assertEqual((root / "go.mod").read_bytes(), b"module wireproxy\n")
        self.assertEqual((root / "cmd" / "app.go").read_bytes(), b"package main\n")

        unsafe = {
            "traversal": [("wireproxy-1.1.3/../outside", tarfile.REGTYPE, b"x")],
            "absolute": [("/wireproxy-1.1.3/go.mod", tarfile.REGTYPE, b"x")],
            "symlink": [("wireproxy-1.1.3/go.mod", tarfile.SYMTYPE, b"")],
            "hardlink": [("wireproxy-1.1.3/go.mod", tarfile.LNKTYPE, b"")],
            "fifo": [("wireproxy-1.1.3/go.mod", tarfile.FIFOTYPE, b"")],
            "empty": [("wireproxy-1.1.3/go.mod", tarfile.REGTYPE, b"")],
            "foreign-root": [("other-1.1.3/go.mod", tarfile.REGTYPE, b"x")],
        }
        for label, entries in unsafe.items():
            with self.subTest(label=label):
                with self.assertRaises(builder.BuildError):
                    builder.extract_source(make_archive(entries), "1.1.3")
        self.assertFalse((self.root / "outside").exists())


if __name__ == "__main__":
    unittest.main()
