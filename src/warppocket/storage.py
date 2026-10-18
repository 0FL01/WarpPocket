from __future__ import annotations

import ctypes
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from warppocket.models import AppError, Cache, CheckResult


def _windows_private(path: Path):
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    token, sid_text, descriptor = wintypes.HANDLE(), wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = f"D:P(A;OICI;FA;;;{sid_text.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def private_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        _windows_private(path)
    else:
        path.chmod(0o700)


def private_file(path: Path):
    if os.name == "nt":
        _windows_private(path)
    else:
        path.chmod(0o600)


def atomic_write(path: Path, content: bytes):
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        private_file(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class AppPaths:
    root: Path

    @classmethod
    def default(cls):
        if os.name == "nt":
            return cls(Path(os.environ["LOCALAPPDATA"]) / "WarpPocket")
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
        return cls(base / "warppocket")

    @property
    def run(self):
        return self.root / "run"

    @property
    def settings(self):
        return self.root / "settings.json"

    @property
    def logs(self):
        return self.root / "logs"

    def profile_dir(self, role: str):
        if role not in ("primary", "probe"):
            raise ValueError("invalid profile role")
        return self.root / "profiles" / role

    def ensure(self):
        for path in (self.root, self.root / "profiles", self.profile_dir("primary"), self.profile_dir("probe"), self.run, self.logs):
            private_directory(path)


class Storage:
    def __init__(self, paths: AppPaths):
        self.paths = paths
        self.paths.ensure()
        self.write_enabled = True
        self.warning: str | None = None

    def load_cache(self) -> Cache:
        self.warning = None
        if not self.paths.settings.exists():
            return Cache()
        try:
            with self.paths.settings.open("rb") as stream:
                content = stream.read(65537)
            if len(content) > 65536:
                raise ValueError("oversized cache")
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("invalid cache")
            if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
                self.write_enabled = False
                self.warning = "cache_schema_unknown"
                return Cache()
            def result(key):
                return CheckResult.from_dict(data[key]) if data.get(key) is not None else None
            fallbacks = tuple(CheckResult.from_dict(item) for item in data.get("fallbacks", []))
            if len(fallbacks) > 3:
                raise ValueError("too many fallbacks")
            return Cache(result("last_good"), result("preferred"), fallbacks)
        except (ValueError, TypeError, KeyError, UnicodeError):
            self.warning = "cache_corrupt"
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            try:
                os.replace(self.paths.settings, self.paths.root / f"settings.corrupt.{stamp}.json")
            except OSError:
                self.write_enabled = False
            return Cache()
        except OSError:
            self.warning = "cache_read_failed"
            self.write_enabled = False
            return Cache()

    def save_cache(self, cache: Cache):
        if not self.write_enabled:
            raise AppError("cache_read_only", "Кеш недоступен для записи; существующий файл сохранён.")
        data = {"schema_version": 1,
                "last_good": cache.last_good.as_dict() if cache.last_good else None,
                "preferred": cache.preferred.as_dict() if cache.preferred else None,
                "fallbacks": [item.as_dict() for item in cache.fallbacks[:3]]}
        try:
            atomic_write(self.paths.settings, json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8"))
        except OSError:
            raise AppError("cache_write_failed", "Не удалось сохранить стратегии; текущее подключение не изменено.") from None

    def clear_runtime(self):
        """Call only while holding InstanceLock for this data directory."""
        for path in self.paths.run.glob("*.conf"):
            path.unlink(missing_ok=True)
