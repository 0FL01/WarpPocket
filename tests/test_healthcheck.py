import threading
import unittest
from unittest.mock import MagicMock, patch

import requests

from warppocket.healthcheck import check_proxy, TRACE_URL, INDEPENDENT_URL, FALLBACK_URL
from warppocket.models import AppError


class HealthcheckTests(unittest.TestCase):
    def response(self, status, content):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = status
        response.iter_content.return_value = [content]
        return response

    def session(self, responses):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = responses
        return session

    def test_verified_socks_remote_dns_no_env_retries_redirects_and_cleanup(self):
        trace, independent = self.response(200, b"ip=1.2.3.4\nwarp=on\n"), self.response(204, b"")
        session = self.session([trace, independent])
        with patch("warppocket.healthcheck.requests.Session", return_value=session):
            self.assertGreaterEqual(check_proxy(25344), 0)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.proxies["https"], "socks5h://127.0.0.1:25344")
        for call in session.get.call_args_list:
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertTrue(call.kwargs["verify"])
            self.assertEqual(call.kwargs["timeout"], (3, 5))
        self.assertEqual(session.mount.call_args.args[1].max_retries.total, 0)
        trace.__exit__.assert_called_once()
        independent.__exit__.assert_called_once()
        session.__exit__.assert_called_once()

    def test_warp_off_and_duplicate_trace_are_not_connected(self):
        for content in (b"warp=off\n", b"warp=on\nwarp=plus\n"):
            session = self.session([self.response(200, content)])
            with patch("warppocket.healthcheck.requests.Session", return_value=session):
                with self.assertRaises(AppError) as caught:
                    check_proxy(1234)
            self.assertEqual(caught.exception.code, "warp_not_enabled")
            self.assertEqual(session.get.call_count, 1)

    def test_independent_failure_falls_back_but_both_must_not_fail(self):
        for final, succeeds in ((self.response(200, b"<HTML><BODY>Success</BODY></HTML>"), True),
                                (requests.ConnectionError(), False)):
            session = self.session([self.response(200, b"warp=plus\n"), requests.Timeout(), final])
            with patch("warppocket.healthcheck.requests.Session", return_value=session):
                if succeeds:
                    check_proxy(1234)
                else:
                    with self.assertRaises(AppError) as caught:
                        check_proxy(1234)
                    self.assertEqual(caught.exception.code, "external_unavailable")
            self.assertEqual([call.args[0] for call in session.get.call_args_list], [TRACE_URL, INDEPENDENT_URL, FALLBACK_URL])

    def test_tls_timeout_dns_and_redirect_never_use_direct_fallback(self):
        for failure in (requests.exceptions.SSLError(), requests.Timeout(), requests.ConnectionError(), self.response(302, b"")):
            session = self.session([failure])
            with patch("warppocket.healthcheck.requests.Session", return_value=session):
                with self.assertRaises(AppError):
                    check_proxy(1234)
            self.assertEqual(session.get.call_count, 1)
            self.assertTrue(session.proxies["https"].startswith("socks5h://127.0.0.1:"))

    def test_oversized_response_and_cancellation(self):
        session = self.session([self.response(200, b"x" * 16385)])
        with patch("warppocket.healthcheck.requests.Session", return_value=session):
            with self.assertRaises(AppError) as caught:
                check_proxy(1234)
        self.assertEqual(caught.exception.code, "health_response_large")
        cancelled = threading.Event()
        cancelled.set()
        with patch("warppocket.healthcheck.requests.Session", return_value=self.session([])):
            with self.assertRaises(AppError) as caught:
                check_proxy(1234, cancel=cancelled)
        self.assertEqual(caught.exception.code, "cancelled")
