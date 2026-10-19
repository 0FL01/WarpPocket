import random
import threading
import time
import unittest
from base64 import b64encode

from warppocket.controller import ConnectionState, Controller
from warppocket.models import AppError, Cache, CheckResult, Endpoint, Profile
from warppocket.strategy_finder import SearchOutcome, StrategyFinder

KEY = b64encode(b"\x01" * 32).decode("ascii")


def make_profile(endpoint="188.114.96.1:4500"):
    return Profile(KEY, ("172.16.0.2/32",), ("1.1.1.1",), KEY,
                   Endpoint.parse(endpoint), ("0.0.0.0/0",))


def wait_for(predicate, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class FakeProcess:
    def __init__(self):
        self.alive = True

    def poll(self):
        return None if self.alive else 0


class FakeInstance:
    def __init__(self, endpoint, port, role):
        self.endpoint, self.port, self.role = endpoint, port, role
        self.process = FakeProcess()
        self.stopped = False


class FakeBackend:
    def __init__(self):
        self.instance = None
        self.sequence = []
        self.live = 0

    def start(self, profile, endpoint, *, role, port=None, cancel=None):
        # One long-lived active proxy plus at most one sequential trial.
        if self.live >= 2:
            raise AssertionError("at most one trial next to the active proxy")
        if cancel is not None and cancel.is_set():
            raise AppError("cancelled", "cancelled")
        instance = FakeInstance(endpoint, port or 44444, role)
        self.instance = instance
        self.live += 1
        self.sequence.append(("start", str(endpoint), port))
        return instance

    def stop(self, instance):
        if instance.stopped:
            return
        instance.stopped = True
        self.live -= 1
        self.sequence.append(("stop", str(instance.endpoint), instance.port))


class FakeStorage:
    def __init__(self, cache=None, fail_save=None):
        self.cache = cache or Cache()
        self.fail_save = fail_save
        self.saved = None
        self.clear_calls = 0

    def load_cache(self):
        return self.cache

    def save_cache(self, cache):
        if self.fail_save is not None:
            raise self.fail_save
        self.saved = cache
        self.cache = cache

    def clear_runtime(self):
        self.clear_calls += 1


class FakeProfiles:
    def __init__(self, profile=None, profile_error=None, reserved_error=None):
        self.profile = profile or make_profile()
        self.profile_error, self.reserved_error = profile_error, reserved_error
        self.calls = []

    def ensure_profile(self, role, *, consent=False, cancel=None):
        self.calls.append(("ensure_profile", role, consent))
        if self.profile_error is not None:
            raise self.profile_error
        return self.profile

    def ensure_reserved(self, role, *, cancel=None):
        self.calls.append(("ensure_reserved", role))
        if self.reserved_error is not None:
            raise self.reserved_error
        return self.profile


class FakeManager:
    def __init__(self):
        self.shutdown_calls = 0

    def shutdown(self):
        self.shutdown_calls += 1


class ScriptedFinder:
    """Blocks inside connect/search until the test releases it."""

    def __init__(self):
        self.connect_started = threading.Event()
        self.search_started = threading.Event()
        self.release = threading.Event()
        self.connect_result = None
        self.search_result = SearchOutcome((), 0, False)

    def candidates(self, profile, cache=None, *, endpoints=None, limit=30):
        return [Endpoint("188.114.96.1", 4500)]

    def connect(self, profile, *, candidates, cancel=None, deadline_seconds=180.0, on_stage=None):
        # Simulates a late success: the verified instance is handed back even
        # when cancellation arrived meanwhile, and the controller must clean it up.
        self.connect_started.set()
        self.release.wait(8)
        return self.connect_result()

    def search(self, profile, *, role, cache=None, endpoints=None, limit=30, deadline_seconds=180.0,
               keep=3, cancel=None, on_stage=None):
        self.search_started.set()
        self.release.wait(8)
        if cancel is not None and cancel.is_set():
            return SearchOutcome((), 1, True)
        return self.search_result


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.latency_map = {}
        self.monitor_health = lambda port, cancel=None: 12.0

        def finder_health(port, cancel=None):
            endpoint = str(self.backend.instance.endpoint)
            if cancel is not None and cancel.is_set():
                raise AppError("cancelled", "cancelled")
            if endpoint not in self.latency_map:
                raise AppError("health_timeout", "timeout")
            return self.latency_map[endpoint]

        self.finder_health = finder_health
        self.finder = StrategyFinder(self.backend, finder_health, rng=random.Random(1))

    def make_controller(self, *, finder=None, storage=None, profiles=None, manager=None,
                        health=None, search_limit=4, health_interval=0.02, health_failures=2):
        self.manager = manager or FakeManager()
        self.storage = storage or FakeStorage()
        self.profiles = profiles or FakeProfiles()
        controller = Controller(storage=self.storage, profiles=self.profiles, backend=self.backend,
                                finder=finder or self.finder, manager=self.manager,
                                health=health or self.monitor_health, search_limit=search_limit,
                                health_interval=health_interval, health_failures=health_failures)
        self.addCleanup(controller.close)
        return controller

    def events(self, controller):
        return controller.poll_events()

    # -- connect -----------------------------------------------------------

    def test_connect_success_saves_last_good_and_clears_preferred(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        stale = CheckResult.now(Endpoint("8.6.112.5", 500), 99.0, "probe")
        controller = self.make_controller(storage=FakeStorage(cache=Cache(preferred=stale)))
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        self.assertEqual(self.profiles.calls, [("ensure_profile", "primary", True),
                                               ("ensure_reserved", "primary")])
        saved = self.storage.saved
        self.assertEqual(str(saved.last_good.endpoint), "188.114.96.1:4500")
        self.assertIsNone(saved.preferred)
        status = controller.status()
        self.assertEqual(str(status["endpoint"]), "188.114.96.1:4500")
        self.assertEqual(status["latency_ms"], 12.0)
        kinds = [event["type"] for event in self.events(controller)]
        self.assertEqual(kinds.count("state"), 2)
        self.assertIn("saved", kinds)

    def test_connect_without_working_endpoint_goes_to_error_without_cache_write(self):
        controller = self.make_controller()
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.ERROR))
        status = controller.status()
        self.assertEqual(status["code"], "no_working_endpoint")
        self.assertIsNone(self.storage.saved)
        result = [event for event in self.events(controller) if event["type"] == "state"]
        self.assertEqual(result[-1]["state"], "error")

    def test_connect_consent_required_is_reported_without_registration(self):
        profiles = FakeProfiles(profile_error=AppError("consent_required", "consent"))
        controller = self.make_controller(profiles=profiles)
        controller.connect(consent=False)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.ERROR))
        self.assertEqual(controller.status()["code"], "consent_required")
        self.assertNotIn(("ensure_reserved", "primary"), profiles.calls)


    def test_connect_success_with_failing_cache_write_emits_warning(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        storage = FakeStorage(fail_save=AppError("cache_write_failed", "write"))
        controller = self.make_controller(storage=storage)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        events = self.events(controller)
        self.assertNotIn("saved", [event["type"] for event in events])
        self.assertIn("cache_write_failed", [event.get("code") for event in events])

    def test_reserved_unavailable_is_reported_as_error(self):
        profiles = FakeProfiles(reserved_error=AppError("reserved_unavailable", "no account"))
        controller = self.make_controller(profiles=profiles)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.ERROR))
        self.assertEqual(controller.status()["code"], "reserved_unavailable")

    def test_disconnect_while_connecting_stops_the_late_instance(self):
        finder = ScriptedFinder()
        controller = self.make_controller(finder=finder)
        controller.connect(consent=True)
        self.assertTrue(finder.connect_started.wait(5))
        instance = self.backend.start(make_profile(), Endpoint("188.114.96.1", 4500),
                                      role="primary", port=25344)
        finder.connect_result = lambda: (instance, 10.0, 1)
        controller.disconnect()
        finder.release.set()
        self.assertTrue(wait_for(lambda: instance.stopped))
        self.assertEqual(self.backend.live, 0)
        self.assertEqual(controller.state, ConnectionState.DISCONNECTED)
        states = [event["state"] for event in self.events(controller) if event["type"] == "state"]
        self.assertEqual(states[-1], "disconnected")

    # -- search ------------------------------------------------------------

    def test_search_while_connected_uses_probe_and_keeps_last_good(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller(search_limit=4)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        self.events(controller)
        controller.start_search(probe_consent=True)
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertIn(("ensure_profile", "probe", True), self.profiles.calls)
        self.assertEqual(controller.state, ConnectionState.CONNECTED)
        done = [event for event in self.events(controller) if event["type"] == "search_done"][0]
        self.assertEqual(done["role"], "probe")
        self.assertTrue(done["saved"])
        self.assertEqual(self.storage.saved.last_good.role, "primary")
        self.assertEqual(self.storage.saved.preferred.role, "probe")
        self.assertEqual(self.storage.saved.preferred.endpoint, Endpoint("188.114.96.1", 4500))

    def test_search_while_disconnected_uses_primary_only(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller(search_limit=2)
        controller.start_search()
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertNotIn(("ensure_profile", "probe", True), self.profiles.calls)
        self.assertIn(("ensure_reserved", "primary"), self.profiles.calls)
        done = [event for event in self.events(controller) if event["type"] == "search_done"][0]
        self.assertEqual(done["role"], "primary")
        self.assertEqual(self.storage.saved.preferred.role, "primary")
        self.assertIsNone(self.storage.saved.last_good)

    def test_cancelled_search_keeps_cache_untouched(self):
        finder = ScriptedFinder()
        controller = self.make_controller(finder=finder)
        controller.start_search()
        self.assertTrue(finder.search_started.wait(5))
        controller.cancel_search()
        finder.release.set()
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertIsNone(self.storage.saved)
        kinds = [event["type"] for event in self.events(controller)]
        self.assertIn("search_cancelled", kinds)

    def test_cancelled_search_rejects_a_late_success(self):
        finder = ScriptedFinder()
        original_search = finder.search

        def late_search(*args, **kwargs):
            original_search(*args, **kwargs)
            return SearchOutcome((CheckResult.now(Endpoint("188.114.97.1", 4500), 5, "primary"),), 1, False)

        finder.search = late_search
        controller = self.make_controller(finder=finder)
        self.addCleanup(controller.close)
        controller.start_search()
        self.assertTrue(finder.search_started.wait(5))
        controller.cancel_search()
        finder.release.set()
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertIsNone(self.storage.saved)
        self.assertIn("search_cancelled", [event["type"] for event in self.events(controller)])

    def test_disconnect_blocks_reconnect_until_old_helper_has_stopped(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller()
        self.addCleanup(controller.close)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        entered, release = threading.Event(), threading.Event()
        original_stop = self.backend.stop

        def delayed_stop(instance):
            entered.set()
            release.wait(5)
            original_stop(instance)

        self.backend.stop = delayed_stop
        self.addCleanup(release.set)
        controller.disconnect()
        self.assertTrue(entered.wait(5))
        profile_calls = len(self.profiles.calls)
        controller.connect(consent=True)
        self.assertEqual(len(self.profiles.calls), profile_calls)
        release.set()
        self.assertTrue(wait_for(lambda: self.backend.live == 0))

    def test_empty_search_result_does_not_replace_cache(self):
        old = CheckResult.now(Endpoint("8.6.112.5", 500), 99.0, "probe")
        controller = self.make_controller(storage=FakeStorage(cache=Cache(preferred=old)))
        controller.start_search()
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertIsNone(self.storage.saved)
        done = [event for event in self.events(controller) if event["type"] == "search_done"][0]
        self.assertEqual(done["code"], "no_working_endpoint")
        self.assertFalse(done["saved"])

    def test_connect_is_rejected_while_search_is_running(self):
        finder = ScriptedFinder()
        controller = self.make_controller(finder=finder)
        controller.start_search()
        self.assertTrue(finder.search_started.wait(5))
        controller.connect(consent=True)
        events = self.events(controller)
        self.assertIn("search_active", [event.get("code") for event in events])
        self.assertEqual(self.backend.sequence, [])
        finder.release.set()
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))

    # -- health and close --------------------------------------------------

    def test_two_health_failures_stop_the_active_proxy(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        calls = {"count": 0}

        def failing_health(port, cancel=None):
            calls["count"] += 1
            raise AppError("health_timeout", "timeout")

        controller = self.make_controller(health=failing_health)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.ERROR))
        self.assertGreaterEqual(calls["count"], 2)
        self.assertTrue(self.backend.instance.stopped)
        self.assertEqual(controller.status()["code"], "connection_lost")

    def test_proxy_exit_is_detected_by_the_monitor(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller()
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        self.backend.instance.process.alive = False
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.ERROR))
        self.assertEqual(controller.status()["code"], "proxy_exited")

    def test_late_health_failure_cannot_stop_a_new_connection(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        entered, release = threading.Event(), threading.Event()
        first_thread = []

        def delayed_failure(port, cancel=None):
            if not first_thread:
                first_thread.append(threading.current_thread())
                entered.set()
                release.wait(5)
                raise AppError("health_timeout", "old connection")
            return 12.0

        controller = self.make_controller(health=delayed_failure, health_failures=1)
        self.addCleanup(release.set)
        controller.connect(consent=True)
        self.assertTrue(entered.wait(5))
        old_instance = self.backend.instance
        controller.disconnect()
        self.assertTrue(wait_for(lambda: old_instance.stopped and not controller.status()["busy"]))
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        new_instance = self.backend.instance
        release.set()
        first_thread[0].join(5)
        self.assertFalse(first_thread[0].is_alive())
        self.assertEqual(controller.state, ConnectionState.CONNECTED)
        self.assertFalse(new_instance.stopped)

    def test_health_success_resets_failure_counter(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        state = {"fail": True}

        def health(port, cancel=None):
            if state["fail"]:
                state["fail"] = False
                raise AppError("health_timeout", "timeout")
            return 12.0

        controller = self.make_controller(health=health, health_interval=0.02)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        time.sleep(0.4)
        self.assertEqual(controller.state, ConnectionState.CONNECTED)
        controller.close()

    def test_close_stops_active_proxy_and_rejects_new_operations(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller()
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        instance = self.backend.instance
        controller.close()
        self.assertTrue(instance.stopped)
        self.assertEqual(self.manager.shutdown_calls, 1)
        self.assertGreaterEqual(self.storage.clear_calls, 1)
        self.assertEqual(controller.state, ConnectionState.DISCONNECTED)
        controller.connect(consent=True)
        codes = [event.get("code") for event in self.events(controller)]
        self.assertIn("closed", codes)

    def test_disconnect_cancels_search_and_stops_active(self):
        self.latency_map = {"188.114.96.1:4500": 12.0}
        controller = self.make_controller(search_limit=30)
        controller.connect(consent=True)
        self.assertTrue(wait_for(lambda: controller.state == ConnectionState.CONNECTED))
        instance = self.backend.instance
        controller.start_search(probe_consent=True)
        controller.disconnect()
        self.assertTrue(wait_for(lambda: instance.stopped))
        self.assertEqual(controller.state, ConnectionState.DISCONNECTED)
        self.assertTrue(wait_for(lambda: not controller.status()["searching"]))
        self.assertEqual(self.backend.live, 0)


if __name__ == "__main__":
    unittest.main()
