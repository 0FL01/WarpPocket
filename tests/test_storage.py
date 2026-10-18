import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from warppocket.models import AppError, Cache, CheckResult, Endpoint
from warppocket.storage import AppPaths, Storage, atomic_write


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = AppPaths(Path(self.temp.name) / "данные с пробелом")
        self.storage = Storage(self.paths)

    def test_roundtrip_and_failed_replace_preserves_previous_file(self):
        result = CheckResult.now(Endpoint("162.159.192.1", 2408), 20.0, "primary")
        self.storage.save_cache(Cache(last_good=result))
        self.assertEqual(self.storage.load_cache().last_good, result)
        before = self.paths.settings.read_bytes()
        with patch("warppocket.storage.os.replace", side_effect=OSError):
            with self.assertRaises(AppError):
                self.storage.save_cache(Cache())
        self.assertEqual(self.paths.settings.read_bytes(), before)
        self.assertEqual(list(self.paths.root.glob(".settings.json.*")), [])

    def test_corrupt_cache_preserves_profile(self):
        profile = self.paths.profile_dir("primary") / "profile.conf"
        atomic_write(profile, b"private profile")
        self.paths.settings.write_text("{", encoding="utf-8")
        self.assertEqual(self.storage.load_cache(), Cache())
        self.assertEqual(self.storage.warning, "cache_corrupt")
        self.assertEqual(profile.read_bytes(), b"private profile")
        self.assertEqual(len(list(self.paths.root.glob("settings.corrupt.*.json"))), 1)

    def test_unknown_schema_is_not_overwritten(self):
        content = json.dumps({"schema_version": 200})
        self.paths.settings.write_text(content, encoding="utf-8")
        self.assertEqual(self.storage.load_cache(), Cache())
        with self.assertRaises(AppError):
            self.storage.save_cache(Cache())
        self.assertEqual(self.paths.settings.read_text(encoding="utf-8"), content)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_private_permissions(self):
        self.storage.save_cache(Cache())
        self.assertEqual(self.paths.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.paths.settings.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.paths.profile_dir("probe").stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(os.name == "nt", "Windows protected DACL")
    def test_windows_data_directory_has_one_protected_allow_entry(self):
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        length = wintypes.DWORD()
        advapi.GetFileSecurityW(str(self.paths.root), 4, None, 0, ctypes.byref(length))
        descriptor = ctypes.create_string_buffer(length.value)
        self.assertTrue(advapi.GetFileSecurityW(str(self.paths.root), 4, descriptor, length, ctypes.byref(length)))
        text = wintypes.LPWSTR()
        self.assertTrue(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ctypes.byref(text), None))
        try:
            self.assertTrue(text.value.startswith("D:P"), text.value)
            self.assertEqual(text.value.count("(A;"), 1)
            self.assertNotIn(";;;WD)", text.value)
            self.assertNotIn(";;;AU)", text.value)
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
