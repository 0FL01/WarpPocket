import random
import unittest

from warppocket.endpoints import (MEASURED_PREFIXES, MINI_PREFIXES, PORTS, PREFIXES,
                                  iter_candidates, seed_endpoints)
from warppocket.models import Cache, CheckResult, Endpoint


class EndpointPoolTests(unittest.TestCase):
    def test_fixed_pools_match_the_pinned_source(self):
        self.assertEqual(len(PREFIXES), 15)
        self.assertEqual(len(set(PREFIXES)), 15)
        self.assertEqual(len(PORTS), 54)
        self.assertEqual(len(set(PORTS)), 54)
        self.assertTrue(all(1 <= port <= 65535 for port in PORTS))
        self.assertEqual(MINI_PREFIXES, ("162.159.192.", "162.159.193.", "162.159.195."))
        self.assertEqual(MEASURED_PREFIXES, PREFIXES[-4:])
        self.assertEqual([endpoint.port for endpoint in seed_endpoints()[:3]], [2408, 500, 4500])

    def test_order_prefers_saved_results_then_profile_endpoint_then_seeds(self):
        preferred = CheckResult.now(Endpoint("8.6.112.5", 500), 10.0, "primary")
        last = CheckResult.now(Endpoint("8.34.70.5", 2408), 12.0, "primary")
        fallback = CheckResult.now(Endpoint("8.39.125.5", 4500), 20.0, "probe")
        cache = Cache(last_good=last, preferred=preferred, fallbacks=(fallback,))
        profile_endpoint = Endpoint("engage.cloudflareclient.com", 2408)
        candidates = iter_candidates(profile_endpoint, cache)
        self.assertEqual(candidates[:4], [preferred.endpoint, last.endpoint, fallback.endpoint,
                                          profile_endpoint])
        self.assertEqual(candidates[4:4 + len(seed_endpoints())], seed_endpoints())

    def test_duplicates_and_limit(self):
        duplicate = CheckResult.now(Endpoint("162.159.192.1", 2408), 1.0, "primary")
        cache = Cache(last_good=duplicate, preferred=duplicate, fallbacks=(duplicate,))
        candidates = iter_candidates(Endpoint("162.159.192.1", 2408), cache, limit=30)
        keys = [str(endpoint) for endpoint in candidates]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(candidates), 30)
        self.assertEqual(candidates[0], duplicate.endpoint)
        self.assertEqual(len(iter_candidates(None, None, limit=5)), 5)
        with self.assertRaises(ValueError):
            iter_candidates(None, None, limit=0)

    def test_deterministic_with_seeded_rng_and_bounded_sampling(self):
        self.assertEqual(iter_candidates(None, None, rng=random.Random(7)),
                         iter_candidates(None, None, rng=random.Random(7)))
        self.assertEqual(len(iter_candidates(None, None)), 30)
        self.assertEqual(len(iter_candidates(None, None, limit=17)), len(seed_endpoints()))


if __name__ == "__main__":
    unittest.main()
