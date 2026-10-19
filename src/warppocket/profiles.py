from __future__ import annotations

import base64
import configparser
import ipaddress
import json
import os
import threading
import time
import tomllib
from dataclasses import replace
from pathlib import Path

import requests

from warppocket.models import AppError, Cache, Profile, Endpoint
from warppocket.storage import Storage, atomic_write, private_file

API_VERSION = "v0a5641"
API_BASE = "https://api.cloudflareclient.com"
RESERVED_HINT = ("Не удалось получить идентификатор WARP-клиента. "
                 "Проверьте доступ к API Cloudflare или импортируйте профиль с полем Reserved.")


def _key(value: str) -> str:
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32:
        raise ValueError("invalid key length")
    return base64.b64encode(decoded).decode("ascii")


def parse_profile(text: str) -> Profile:
    try:
        if len(text.encode("utf-8")) > 65536 or "$" in text or "\x00" in text:
            raise ValueError("unsupported profile")
        parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=False,
                                           delimiters=("=",), inline_comment_prefixes=("#", ";"))
        parser.read_string(text)
        sections = {name.strip().lower(): name for name in parser.sections()}
        if len(parser.sections()) != 2 or set(sections) != {"interface", "peer"} or parser.defaults():
            raise ValueError("expected single interface and peer")
        interface, peer = parser[sections["interface"]], parser[sections["peer"]]
        if set(interface) - {"privatekey", "address", "dns", "mtu"} or set(peer) - {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive", "reserved"}:
            raise ValueError("unsupported profile field")
        if any("\n" in value for section in (interface, peer) for value in section.values()):
            raise ValueError("multiline values not supported")
        addresses = tuple(str(ipaddress.ip_interface(item.strip())) for item in interface["address"].split(","))
        dns = tuple(str(ipaddress.ip_address(item.strip())) for item in interface["dns"].split(","))
        routes = tuple(str(ipaddress.ip_network(item.strip(), strict=False)) for item in peer["allowedips"].split(","))
        if any("%" in value for value in (*addresses, *dns)):
            raise ValueError("scoped addresses not supported")
        if not any(ipaddress.ip_interface(addr).version == 4 for addr in addresses) or "0.0.0.0/0" not in routes:
            raise ValueError("IPv4 default route required")
        has_v6 = any(ipaddress.ip_interface(addr).version == 6 for addr in addresses)
        if (has_v6 and "::/0" not in routes) or (not has_v6 and any(ipaddress.ip_address(addr).version == 6 for addr in dns)):
            raise ValueError("inconsistent IPv6 configuration")
        mtu, keepalive = int(interface.get("mtu", "1280")), int(peer.get("persistentkeepalive", "0"))
        if not (1280 if has_v6 else 576) <= mtu <= 65535 or not 0 <= keepalive <= 65535:
            raise ValueError("invalid MTU or keepalive")
        reserved = None
        if "reserved" in peer:
            parts = [item.strip() for item in peer["reserved"].split(",")]
            if len(parts) != 3 or any(not (item.isascii() and item.isdecimal()) or int(item) > 255 for item in parts):
                raise ValueError("invalid reserved bytes")
            reserved = (int(parts[0]), int(parts[1]), int(parts[2]))
        return Profile(_key(interface["privatekey"]), addresses, dns, _key(peer["publickey"]),
                       Endpoint.parse(peer["endpoint"]), routes, mtu, keepalive,
                       _key(peer["presharedkey"]) if "presharedkey" in peer else None, reserved)
    except (ValueError, KeyError, TypeError, configparser.Error, UnicodeError):
        raise AppError("profile_invalid", "Несовместимый профиль: нужен один WireGuard peer, явные DNS-IP и полный IPv4-маршрут; расширения запрещены.") from None


def render_profile(profile: Profile, endpoint: Endpoint | None = None) -> str:
    lines = ["[Interface]", f"PrivateKey = {profile.private_key}",
             f"Address = {', '.join(profile.addresses)}", f"DNS = {', '.join(profile.dns)}", f"MTU = {profile.mtu}",
             "", "[Peer]", f"PublicKey = {profile.public_key}", f"AllowedIPs = {', '.join(profile.allowed_ips)}",
             f"Endpoint = {endpoint or profile.endpoint}", f"PersistentKeepalive = {profile.keepalive}"]
    if profile.reserved:
        lines.append("Reserved = " + ", ".join(str(item) for item in profile.reserved))
    if profile.preshared_key:
        lines.append(f"PresharedKey = {profile.preshared_key}")
    return "\n".join(lines) + "\n"


def _read_profile(path: Path) -> Profile:
    try:
        with path.open("rb") as stream:
            content = stream.read(65537)
        if len(content) > 65536:
            raise ValueError("oversized profile")
        return parse_profile(content.decode("utf-8-sig"))
    except (OSError, ValueError, UnicodeError):
        raise AppError("profile_read_failed", "Не удалось прочитать совместимый профиль.") from None


def _api_config(response, cancel) -> dict:
    if response.status_code != 200:
        raise AppError("reserved_unavailable", RESERVED_HINT)
    body = bytearray()
    for chunk in response.iter_content(4096):
        if cancel is not None and cancel.is_set():
            raise AppError("cancelled", "Операция отменена.")
        body.extend(chunk)
        if len(body) > 40960:
            raise AppError("reserved_unavailable", RESERVED_HINT)
    try:
        data = json.loads(bytes(body).decode("utf-8"))
    except (ValueError, UnicodeError):
        raise AppError("reserved_unavailable", RESERVED_HINT) from None
    config = data.get("config") if isinstance(data, dict) else None
    return config if isinstance(config, dict) else {}


def _fetch_reserved(device_id: str, access_token: str, *, cancel=None, session=None) -> tuple[int, int, int]:
    """Fetch the three WARP reserved bytes for an existing account.

    Verified TLS, no redirects and no environment proxy; tests may inject a
    session. The warp_enabled service flag is enabled when the API reports it as
    false, because registrations performed by wgcf skip that legacy step.
    """

    def stopped():
        return cancel is not None and cancel.is_set()

    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    own_session = session is None
    session = session or requests.Session()
    try:
        session.trust_env = False
        url = f"{API_BASE}/{API_VERSION}/reg/{device_id}"
        if stopped():
            raise AppError("cancelled", "Операция отменена.")
        with session.get(url, headers=headers, timeout=(5, 10), allow_redirects=False, stream=True) as response:
            config = _api_config(response, cancel)
        if config.get("warp_enabled") is False:
            patch_headers = {"Authorization": headers["Authorization"], "Accept": "application/json",
                             "Content-Type": "application/json"}
            if stopped():
                raise AppError("cancelled", "Операция отменена.")
            with session.patch(url, headers=patch_headers, data=b'{"warp_enabled": true}',
                               timeout=(5, 10), allow_redirects=False, stream=True) as response:
                try:
                    patched = _api_config(response, cancel)
                except AppError:
                    patched = {}
            if isinstance(patched.get("client_id"), str):
                config["client_id"] = patched["client_id"]
        client_id = config.get("client_id")
        decoded = base64.b64decode(client_id, validate=True) if isinstance(client_id, str) else b""
        if len(decoded) != 3:
            raise AppError("reserved_unavailable", RESERVED_HINT)
        return (decoded[0], decoded[1], decoded[2])
    except AppError:
        raise
    except (requests.RequestException, ValueError, TypeError):
        raise AppError("reserved_unavailable", RESERVED_HINT) from None
    finally:
        if own_session:
            session.close()


class ProfileService:
    def __init__(self, storage: Storage, manager, wgcf_binary: Path):
        self.storage, self.manager, self.wgcf_binary = storage, manager, wgcf_binary

    def exists(self, role: str):
        return (self.storage.paths.profile_dir(role) / "profile.conf").is_file()

    def load(self, role: str) -> Profile:
        profile = _read_profile(self.storage.paths.profile_dir(role) / "profile.conf")
        self._different(role, profile)
        return profile

    def _different(self, role, profile):
        other_path = self.storage.paths.profile_dir("probe" if role == "primary" else "primary") / "profile.conf"
        if other_path.exists():
            other = _read_profile(other_path)
            if profile.identity() == other.identity():
                raise AppError("profile_same_key", "Основной и проверочный профили должны иметь разные WireGuard-ключи.")

    def import_profile(self, source: Path, role: str):
        """Caller must hold InstanceLock and finish all network operations first."""
        profile = _read_profile(source)
        self._different(role, profile)
        folder = self.storage.paths.profile_dir(role)
        atomic_write(folder / "profile.conf", render_profile(profile).encode("utf-8"))
        (folder / "account.toml").unlink(missing_ok=True)
        cache = self.storage.load_cache()
        if role == "primary":
            cache = Cache()
        else:
            cache = Cache(cache.last_good,
                          cache.preferred if cache.preferred and cache.preferred.role != "probe" else None,
                          tuple(item for item in cache.fallbacks if item.role != "probe"))
        self.storage.save_cache(cache)
        return profile

    def _account_data(self, account: Path):
        try:
            with account.open("rb") as stream:
                data = tomllib.loads(stream.read(65537).decode("utf-8"))
            _key(data["private_key"])
            if all(isinstance(data.get(key), str) and data[key] for key in ("device_id", "access_token")):
                return data
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return None

    def _account_valid(self, account):
        return self._account_data(account) is not None

    def _run(self, args, folder, cancel):
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("WGCF_")}
        process = self.manager.start([str(self.wgcf_binary), *args], cwd=folder, env=env, cancel=cancel)
        deadline = time.monotonic() + 60
        try:
            while process.poll() is None:
                if cancel.is_set():
                    raise AppError("cancelled", "Операция отменена.")
                if time.monotonic() >= deadline:
                    raise AppError("profile_timeout", "Время ожидания WARP API истекло.")
                cancel.wait(0.05)
            return process.poll()
        finally:
            self.manager.stop(process)

    def ensure_profile(self, role: str, *, consent=False, cancel: threading.Event | None = None):
        cancel = cancel or threading.Event()
        if cancel.is_set():
            raise AppError("cancelled", "Операция отменена.")
        if self.exists(role):
            return self.load(role)
        folder = self.storage.paths.profile_dir(role)
        account = folder / "account.toml"
        if not account.exists():
            if not consent:
                raise AppError("consent_required", "Для регистрации требуется согласие с условиями Cloudflare.")
            registration_error = None
            try:
                self._run(["--config", str(account), "register", "--accept-tos"], folder, cancel)
            except AppError as error:
                registration_error = error
            if account.exists():
                private_file(account)
            if cancel.is_set():
                raise AppError("cancelled", "Операция отменена.")
            if not self._account_valid(account):
                if registration_error:
                    raise registration_error
                raise AppError("registration_failed", "Регистрация WARP не завершилась. Можно импортировать совместимый профиль.")
        if not self._account_valid(account):
            raise AppError("account_incomplete", "Сохранённый аккаунт неполон; автоматическая повторная регистрация запрещена. Импортируйте профиль.")
        temporary = folder / "generated.conf"
        try:
            status = self._run(["--config", str(account), "generate", "--profile", str(temporary)], folder, cancel)
            if cancel.is_set():
                raise AppError("cancelled", "Операция отменена.")
            if status != 0 or not temporary.exists():
                raise AppError("generation_failed", "Не удалось получить профиль WARP; аккаунт сохранён для повторной генерации.")
            private_file(temporary)
            profile = _read_profile(temporary)
            self._different(role, profile)
            atomic_write(folder / "profile.conf", render_profile(profile).encode("utf-8"))
            return profile
        finally:
            temporary.unlink(missing_ok=True)

    def ensure_reserved(self, role: str, *, cancel: threading.Event | None = None):
        """Fetch and persist the WARP reserved bytes using the saved account.

        Profiles without a saved account keep their state; the caller reports a
        clear error instead of starting a tunnel that cannot carry data.
        """
        cancel = cancel or threading.Event()
        if cancel.is_set():
            raise AppError("cancelled", "Операция отменена.")
        profile = self.load(role)
        if profile.reserved:
            return profile
        data = self._account_data(self.storage.paths.profile_dir(role) / "account.toml")
        if data is None:
            raise AppError("reserved_unavailable",
                           "Аккаунт недоступен, поэтому Reserved не получен. Импортируйте профиль с полем Reserved.")
        reserved = _fetch_reserved(data["device_id"], data["access_token"], cancel=cancel)
        updated = replace(profile, reserved=reserved)
        atomic_write(self.storage.paths.profile_dir(role) / "profile.conf",
                     render_profile(updated).encode("utf-8"))
        return updated
