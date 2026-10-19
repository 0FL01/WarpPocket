import threading
import time
import unittest
from base64 import b64encode
from unittest.mock import Mock

from warppocket.models import AppError, Endpoint, Profile
from warppocket.strategy_finder import StrategyFinder, _TrialBudget

KEY = b64encode(b"\x01" * 32).decode("ascii")


def make_profile():
    return Profile(KEY, ("172.16.0.2/32",), ("1.1.1.1",), KEY,
                   Endpoint("162.159.192.1", 2408), ("0.0.0.0/0",))


class FakeProcess:
    def poll(self):
        return None


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
        assert self.live == 0, "finder must run one trial at a time"
        if cancel is not None and cancel.is_set():
            raise AppError("cancelled", "cancelled")
        self.instance = FakeInstance(endpoint, port or 44444, role)
        self.live = 1
        self.sequence.append(("start", str(endpoint), port))
        return self.instance

    def stop(self, instance):
        instance.stopped = True
        self.live = 0
        self.sequence.append(("stop", str(instance.endpoint), instance.port))


class FakeClock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value


class FinderTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.clock = FakeClock()
        self.health_map = {}
        self.health_calls = []

        def health(port, cancel=None):
            endpoint = str(self.backend.instance.endpoint)
            self.health_calls.append(endpoint)
            if cancel is not None and cancel.is_set():
                raise AppError("cancelled", "cancelled")
            result = self.health_map.get(endpoint, "health_timeout")
            if isinstance(result, str):
                raise AppError(result, result)
            return result

        self.health = health
        self.finder = StrategyFinder(self.backend, health, clock=self.clock)

    def explicit(self, *endpoints):
        return [Endpoint.parse(item) for item in endpoints]

    def test_budget_wait_rechecks_after_an_early_native_timeout(self):
        cancel = threading.Event()
        waits = []

        def early_wait(timeout):
            waits.append(timeout)
            self.clock.value = 90.0 if len(waits) == 1 else 180.0
            return False

        cancel.wait = Mock(side_effect=early_wait)
        with _TrialBudget(self.backend, cancel, 180, self.clock) as budget:
            self.assertTrue(budget.wait(200))
        self.assertEqual(waits, [180.0, 90.0])

    def test_deadline_interrupts_an_inflight_trial_not_just_the_next_candidate(self):
        def slow_health(port, cancel=None):
            cancel.wait(2)
            raise AppError("health_timeout", "timeout")

        finder = StrategyFinder(self.backend, slow_health)
        started = time.monotonic()
        outcome = finder.search(make_profile(), role="primary", deadline_seconds=0.03,
                                endpoints=self.explicit("188.114.96.1:4500", "188.114.97.1:4500"))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(outcome.checked, 1)
        self.assertFalse(outcome.cancelled)
        self.assertEqual(self.backend.live, 0)

    def test_successful_connect_is_not_stopped_when_old_deadline_expires(self):
        finder = StrategyFinder(self.backend, lambda port, cancel=None: 12.0)
        instance, _, _ = finder.connect(make_profile(), deadline_seconds=0.03,
                                        candidates=self.explicit("188.114.96.1:4500"))
        time.sleep(0.06)
        self.assertFalse(instance.stopped)
        self.backend.stop(instance)

    def test_explicit_candidate_limit_cannot_exceed_contract(self):
        endpoints = [Endpoint("188.114.96.1", port) for port in range(2000, 2040)]
        self.assertEqual(len(self.finder.candidates(make_profile(), endpoints=endpoints, limit=100)), 30)

    def test_search_ranks_by_latency_and_stops_at_keep(self):
        self.health_map = {"188.114.96.1:4500": 30.0, "188.114.97.1:4500": 10.0, "188.114.98.1:4500": 20.0}
        outcome = self.finder.search(
            make_profile(), role="probe", keep=3,
            endpoints=self.explicit("188.114.96.1:4500", "188.114.97.1:4500", "188.114.98.1:4500"))
        self.assertFalse(outcome.cancelled)
        self.assertEqual([str(item.endpoint) for item in outcome.results],
                         ["188.114.97.1:4500", "188.114.98.1:4500", "188.114.96.1:4500"])
        self.assertEqual(outcome.checked, 3)
        self.assertEqual([item.role for item in outcome.results], ["probe"] * 3)
        self.health_map = {"188.114.96.1:4500": 30.0, "188.114.97.1:4500": 10.0}
        outcome = self.finder.search(
            make_profile(), role="probe", keep=1,
            endpoints=self.explicit("188.114.96.1:4500", "188.114.97.1:4500"))
        self.assertEqual(len(outcome.results), 1)
        self.assertEqual(outcome.checked, 1)

    def test_search_is_sequential_and_releases_every_trial(self):
        self.health_map = {"8.6.112.1:500": "health_timeout", "8.34.70.1:2408": 15.0}
        outcome = self.finder.search(
            make_profile(), role="primary",
            endpoints=self.explicit("8.6.112.1:500", "8.34.70.1:2408"))
        self.assertEqual([kind for kind, *_ in self.backend.sequence], ["start", "stop", "start", "stop"])
        self.assertEqual(self.backend.live, 0)
        self.assertEqual(outcome.checked, 2)
        self.assertEqual([str(item.endpoint) for item in outcome.results], ["8.34.70.1:2408"])

    def test_deadline_stops_new_trials(self):
        self.health_map = {"8.6.112.1:500": "health_timeout"}
        original = self.health

        def health(port, cancel=None):
            self.clock.value = 500.0
            return original(port, cancel)

        finder = StrategyFinder(self.backend, health, clock=self.clock)
        outcome = finder.search(
            make_profile(), role="primary", deadline_seconds=180.0,
            endpoints=self.explicit("8.6.112.1:500", "8.34.70.1:2408"))
        self.assertEqual(outcome.checked, 1)
        self.assertEqual([kind for kind, *_ in self.backend.sequence], ["start", "stop"])

    def test_cancel_returns_cancelled_outcome_and_releases_instance(self):
        cancel = threading.Event()

        def health(port, cancel=None):
            cancel.set()
            raise AppError("cancelled", "cancelled")

        finder = StrategyFinder(self.backend, health, clock=self.clock)
        outcome = finder.search(
            make_profile(), role="probe", cancel=cancel,
            endpoints=self.explicit("188.114.96.1:4500", "188.114.97.1:4500"))
        self.assertTrue(outcome.cancelled)
        self.assertEqual(outcome.results, ())
        self.assertEqual(outcome.checked, 1)
        self.assertEqual(self.backend.live, 0)

    def test_precancelled_search_never_starts_a_trial(self):
        cancel = threading.Event()
        cancel.set()
        outcome = self.finder.search(make_profile(), role="primary", cancel=cancel,
                                     endpoints=self.explicit("8.6.112.1:500"))
        self.assertTrue(outcome.cancelled)
        self.assertEqual(self.backend.sequence, [])

    def test_connect_keeps_verified_instance_on_fixed_port(self):
        self.health_map = {"188.114.96.1:4500": "health_timeout", "188.114.97.1:4500": 12.0}
        instance, latency, checked = self.finder.connect(
            make_profile(), candidates=self.explicit("188.114.96.1:4500", "188.114.97.1:4500"))
        self.assertEqual(latency, 12.0)
        self.assertEqual(checked, 2)
        self.assertFalse(instance.stopped)
        self.assertEqual([str(instance.endpoint)], ["188.114.97.1:4500"])
        self.assertTrue(all(port == 25344 for kind, _, port in self.backend.sequence if kind == "start"))
        self.assertEqual([kind for kind, *_ in self.backend.sequence], ["start", "stop", "start"])

    def test_connect_reports_no_working_endpoint_after_all_failures(self):
        with self.assertRaises(AppError) as caught:
            self.finder.connect(make_profile(), candidates=self.explicit("8.6.112.1:500", "8.34.70.1:2408"))
        self.assertEqual(caught.exception.code, "no_working_endpoint")
        self.assertEqual(self.backend.live, 0)

    def test_connect_aborts_immediately_on_busy_fixed_port(self):
        backend = FakeBackend()

        def busy_start(profile, endpoint, *, role, port=None, cancel=None):
            raise AppError("port_busy", "busy")

        backend.start = busy_start
        finder = StrategyFinder(backend, self.health, clock=self.clock)
        with self.assertRaises(AppError) as caught:
            finder.connect(make_profile(), candidates=self.explicit("8.6.112.1:500"))
        self.assertEqual(caught.exception.code, "port_busy")

    def test_candidates_deduplicate_and_validate(self):
        candidates = self.finder.candidates(
            make_profile(), endpoints=["188.114.96.1:4500", "188.114.96.1:4500", "188.114.97.1:4500"])
        self.assertEqual([str(item) for item in candidates],
                         ["188.114.96.1:4500", "188.114.97.1:4500"])
        with self.assertRaises(ValueError):
            self.finder.candidates(make_profile(), endpoints=["not-an-endpoint"])
        with self.assertRaises(ValueError):
            self.finder.search(make_profile(), role="system", endpoints=[])


if __name__ == "__main__":
    unittest.main()
