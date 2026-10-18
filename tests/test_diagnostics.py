import tempfile
import unittest
from pathlib import Path

from warppocket.diagnostics import create_logger, event
from warppocket.models import Endpoint
from warppocket.storage import AppPaths, Storage


class DiagnosticsTests(unittest.TestCase):
    def test_structured_fields_only_and_bounded_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = AppPaths(Path(directory))
            Storage(paths)
            logger = create_logger(paths)
            try:
                event(logger, "proxy_started", role="primary", endpoint=Endpoint("127.0.0.1", 2408))
                text = (paths.logs / "diagnostics.log").read_text(encoding="utf-8")
                self.assertIn("event=proxy_started", text)
                self.assertNotIn("PrivateKey", text)
                handler = logger.handlers[0]
                self.assertEqual(handler.maxBytes, 262144)
                self.assertEqual(handler.backupCount, 2)
                with self.assertRaises(TypeError):
                    event(logger, "bad", private_key="must not be accepted")
            finally:
                for handler in logger.handlers[:]:
                    handler.close()
                    logger.removeHandler(handler)
