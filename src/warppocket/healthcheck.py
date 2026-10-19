from __future__ import annotations

import threading
import time

import requests

from warppocket.models import AppError

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
INDEPENDENT_URL = "https://www.gstatic.com/generate_204"
FALLBACK_URL = "https://www.apple.com/library/test/success.html"


def check_proxy(port: int, *, cancel: threading.Event | None = None) -> float:
    """Return Cloudflare HTTPS elapsed milliseconds only after both checks pass."""
    cancel = cancel or threading.Event()
    deadline = time.monotonic() + 30
    proxy = f"socks5h://127.0.0.1:{port}"

    def request(session, url):
        if cancel.is_set():
            raise AppError("cancelled", "Операция отменена.")
        if time.monotonic() >= deadline:
            raise AppError("health_timeout", "Время проверки истекло.")
        with session.get(url, timeout=(5, 5), allow_redirects=False, stream=True, verify=True) as response:
            content = bytearray()
            # A one-byte stream also bounds slow-drip responses by the wall deadline.
            for chunk in response.iter_content(chunk_size=1):
                if cancel.is_set():
                    raise AppError("cancelled", "Операция отменена.")
                if time.monotonic() >= deadline:
                    raise AppError("health_timeout", "Время проверки истекло.")
                content.extend(chunk)
                if len(content) > 16384:
                    raise AppError("health_response_large", "Некорректный ответ проверочного ресурса.")
            return response.status_code, bytes(content)

    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {"http": proxy, "https": proxy}
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
        try:
            started = time.monotonic()
            status, body = request(session, TRACE_URL)
            latency = (time.monotonic() - started) * 1000
            warp = [line.partition("=")[2] for line in body.decode("utf-8").splitlines() if line.partition("=")[0] == "warp"]
            if status != 200 or len(warp) != 1 or warp[0] not in ("on", "plus"):
                raise AppError("warp_not_enabled", "Прокси не подтвердил работу через WARP.")
            for url in (INDEPENDENT_URL, FALLBACK_URL):
                try:
                    status, body = request(session, url)
                    if (url == INDEPENDENT_URL and status == 204 and not body) or (url == FALLBACK_URL and status == 200 and b"<body>success</body>" in body.lower()):
                        return latency
                except requests.RequestException:
                    continue
            raise AppError("external_unavailable", "WARP отвечает, но независимый HTTPS-ресурс недоступен.")
        except requests.exceptions.SSLError:
            raise AppError("health_tls", "Проверка TLS через SOCKS5 не пройдена.") from None
        except requests.exceptions.Timeout:
            raise AppError("health_timeout", "Время ожидания HTTPS через SOCKS5 истекло.") from None
        except (requests.RequestException, UnicodeError):
            raise AppError("health_failed", "HTTPS через SOCKS5 недоступен; прямое соединение не используется.") from None
