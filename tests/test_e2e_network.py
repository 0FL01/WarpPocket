import argparse
import threading
import unittest
from unittest.mock import Mock, patch

from scripts import e2e_network
from warppocket.models import AppError, Endpoint


class E2ECleanupTests(unittest.TestCase):
    def test_failed_gate_still_verifies_cleanup(self):
        storage, manager, stage = Mock(), Mock(), Mock()
        profile = Mock(endpoint=Endpoint("162.159.192.1", 2408))
        instance = Mock(port=25344)
        args = argparse.Namespace(accept_tos=False, endpoint=[])
        with patch.object(e2e_network, "bundled_binary"), \
                patch.object(e2e_network, "ProfileService") as profiles, \
                patch.object(e2e_network, "WireProxyBackend") as backend, \
                patch.object(e2e_network, "check_proxy", side_effect=AppError("health_timeout", "Timeout")), \
                patch.object(e2e_network.socket, "socket") as socket:
            profiles.return_value.ensure_profile.return_value = profile
            backend.return_value.start.return_value = instance
            socket.return_value.__enter__.return_value.connect_ex.return_value = 111
            with self.assertRaises(AppError) as raised:
                e2e_network.paths_run_gate(storage, manager, {}, args, stage, threading.Event(), [])
            self.assertEqual(raised.exception.code, "no_working_endpoint")
            self.assertEqual(backend.return_value.stop.call_count, backend.return_value.start.call_count)
            manager.shutdown.assert_called_once()
            self.assertEqual(storage.clear_runtime.call_count, 2)
            socket.return_value.__enter__.return_value.connect_ex.assert_called_once_with(("127.0.0.1", 25344))
            self.assertEqual(stage.call_args.args, ("cleanup_verified",))


if __name__ == "__main__":
    unittest.main()
