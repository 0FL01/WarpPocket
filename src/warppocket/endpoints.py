"""Fixed WARP endpoint pools with bounded, deduplicated enumeration.

The address lists are copied from Viktor45/ros-scripts ``warp-finder.rsc`` at
commit ``d92d68db030e833c7f6032697e4f177dfe976230`` (MIT). RouterOS commands,
route handling and the original random generator are intentionally not copied.
"""

from __future__ import annotations

import random

from warppocket.models import Cache, Endpoint

PREFIXES = (
    "8.6.112.", "8.34.70.", "8.34.146.", "8.35.211.", "8.39.125.",
    "8.39.204.", "8.39.214.", "8.47.69.", "162.159.192.", "162.159.193.",
    "162.159.195.", "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
)

PORTS = (
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
    1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
    4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
    8854, 8886,
)

MINI_PREFIXES = ("162.159.192.", "162.159.193.", "162.159.195.")
SEED_PORTS = (2408, 500, 4500)
# Measured working ranges (R1 gate): 188.114.9x.1:4500 passed on real networks.
MEASURED_PREFIXES = PREFIXES[-4:]
MEASURED_PORTS = (4500, 2408)


def seed_endpoints() -> list[Endpoint]:
    """Small deterministic set of historically likely candidates."""
    seeds = [Endpoint(prefix + "1", port) for prefix in MINI_PREFIXES for port in SEED_PORTS]
    seeds.extend(Endpoint(prefix + "1", port) for prefix in MEASURED_PREFIXES for port in MEASURED_PORTS)
    return seeds


def _random_sample(rng: random.Random, taken: set, count: int) -> list[Endpoint]:
    sample: list[Endpoint] = []
    seen = set(taken)
    for _ in range(count * 40):
        if len(sample) >= count:
            break
        endpoint = Endpoint(PREFIXES[rng.randrange(len(PREFIXES))] + str(rng.randrange(2, 255)),
                            PORTS[rng.randrange(len(PORTS))])
        if str(endpoint) in seen:
            continue
        seen.add(str(endpoint))
        sample.append(endpoint)
    return sample


def iter_candidates(profile_endpoint: Endpoint | None, cache: Cache | None, *,
                    limit: int = 30, rng: random.Random | None = None) -> list[Endpoint]:
    """Ordered candidates: saved results, profile endpoint, seeds, bounded sample.

    The cartesian product of the full pools is never enumerated; the trailing
    sample is finite and deduplicated.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    rng = rng or random.Random()
    ordered: list[Endpoint] = []
    for result in (cache.preferred if cache else None, cache.last_good if cache else None,
                   *(cache.fallbacks if cache else ())):
        if result is not None:
            ordered.append(result.endpoint)
    if profile_endpoint is not None:
        ordered.append(profile_endpoint)
    ordered.extend(seed_endpoints())
    unique: list[Endpoint] = []
    seen: set[str] = set()
    for endpoint in ordered:
        key = str(endpoint)
        if key not in seen:
            seen.add(key)
            unique.append(endpoint)
    if len(unique) < limit:
        unique.extend(_random_sample(rng, seen, limit - len(unique)))
    return unique[:limit]
