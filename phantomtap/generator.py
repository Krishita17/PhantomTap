"""Test-candidate generators: the core of PhantomTap's efficiency claim.

The auditor's job is to *characterize* a deployment -- discover as much of the
issued credential population as possible -- using as few reader queries as
possible.  Three strategies are compared:

``bruteforce``
    No structure at all: enumerate every (facility, card) pair in natural order.

``dictionary``
    The classic Flipper-style approach: a fixed priority list of "commonly
    seen" facility codes swept from low card numbers upward.  Better than brute
    force *only* when the deployment happens to match the dictionary's guesses.
    It does not adapt to what it reads.

``ml`` (PhantomTap)
    Reason from the observed reads.  Two moves win the day:

    1. **Lock the facility code** inferred from the captured cards -- this alone
       divides the search space by the whole facility-code range.
    2. **Region-grow** over card numbers: seed from the observed cards and
       expand outward, so a sequential/clustered population is walked directly
       instead of scanning empty low-numbered space.  This is a simple, honest
       active-learning policy -- probe where the evidence says credentials live.

The deterministic baselines are scored analytically (their query cost to reach
a credential is just its rank in a fixed ordering -- no need to simulate
millions of queries).  The ML auditor is run as a *real* adaptive loop against
the reader oracle, seeing only the observed sample and the reader's yes/no
answers -- never the ground truth.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .inference import infer_format
from .population import Deployment, NumberingScheme
from .reader import SimulatedReader

# A fixed "known-common" facility-code priority list, standing in for the kind
# of static dictionary shipped with off-the-shelf tooling.
DICTIONARY_FCS: List[int] = [
    0, 1, 2, 3, 5, 7, 10, 11, 12, 13, 20, 24, 33, 42, 48, 50, 55, 63, 64,
    99, 100, 101, 111, 123, 128, 200, 222, 233, 250, 255,
]

MAX_GAP = 12  # consecutive misses a region-growing ray tolerates before giving up


@dataclass
class CharacterizationResult:
    method: str
    queries_to_target: Optional[int]
    fraction_found: float
    discovered: int
    total_issued: int
    target_fraction: float
    censored: bool = False
    trajectory: List[Tuple[int, int]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "queries_to_target": self.queries_to_target,
            "fraction_found": round(self.fraction_found, 4),
            "discovered": self.discovered,
            "total_issued": self.total_issued,
            "target_fraction": self.target_fraction,
            "censored": self.censored,
        }


def _cn_percentile(cards: List[int], fraction: float) -> int:
    """Card number at ``fraction`` of the sorted issued population."""
    s = sorted(cards)
    idx = max(0, math.ceil(fraction * len(s)) - 1)
    return s[idx]


# ---------------------------------------------------------------------------
# Deterministic baselines (analytic query cost)
# ---------------------------------------------------------------------------
def bruteforce_characterize(dep: Deployment, target: float = 0.9) -> CharacterizationResult:
    """Enumerate (fc, cn) in natural order; cost = rank of the target credential."""
    fmt = dep.fmt
    cards = [c.card_number for c in dep.credentials]
    cn_t = _cn_percentile(cards, target)
    # Natural enumeration index of (fc, cn):
    cost = dep.facility_code * (fmt.max_card + 1) + cn_t + 1
    n = len(cards)
    return CharacterizationResult(
        method="bruteforce",
        queries_to_target=cost,
        fraction_found=target,
        discovered=math.ceil(target * n),
        total_issued=n,
        target_fraction=target,
    )


def dictionary_characterize(dep: Deployment, target: float = 0.9) -> CharacterizationResult:
    """Fixed facility-code priority list, card numbers swept low->high."""
    fmt = dep.fmt
    cards = [c.card_number for c in dep.credentials]
    cn_t = _cn_percentile(cards, target)
    fc = dep.facility_code
    if fc in DICTIONARY_FCS:
        fc_rank = DICTIONARY_FCS.index(fc)
    else:
        # after the whole priority list, fall back to numeric order
        fc_rank = len(DICTIONARY_FCS) + fc
    cost = fc_rank * (fmt.max_card + 1) + cn_t + 1
    n = len(cards)
    return CharacterizationResult(
        method="dictionary",
        queries_to_target=cost,
        fraction_found=target,
        discovered=math.ceil(target * n),
        total_issued=n,
        target_fraction=target,
    )


# ---------------------------------------------------------------------------
# ML-guided active-learning auditor (real adaptive loop)
# ---------------------------------------------------------------------------
def ml_characterize(
    reader: SimulatedReader,
    dep: Deployment,
    observations: List[int],
    target: float = 0.9,
    budget: int = 1_200_000,
) -> CharacterizationResult:
    """Adaptive region-growing search seeded only from observed reads.

    ``dep`` is used *only* for its total issued count (so the benchmark can
    define "90% discovered") and its format -- never to peek at which specific
    credentials are valid.  All validity comes from ``reader.query``.
    """
    total = reader.total_issued
    hyp = infer_format(observations)
    fmt = hyp.fmt or dep.fmt
    fc = hyp.facility_code if hyp.facility_code is not None else dep.facility_code

    # Seed discovered set from the physically captured cards (no reader queries).
    discovered: set = set()
    obs_cards: List[int] = []
    for raw in observations:
        d = fmt.decode(raw)
        discovered.add(raw)
        obs_cards.append(d.card_number)

    reader.reset_counters()
    trajectory: List[Tuple[int, int]] = [(0, len(discovered))]
    target_count = math.ceil(target * total)
    queries_to_target: Optional[int] = None
    visited: set = set(obs_cards)

    def record() -> None:
        trajectory.append((reader.queries, len(discovered)))

    def note_target() -> None:
        nonlocal queries_to_target
        if queries_to_target is None and len(discovered) >= target_count:
            queries_to_target = reader.queries

    # --- Phase 1: region-grow rays outward from every observed card ---------
    # Heap entries: (consecutive_misses, next_cn, step). Lower misses first, so
    # dense (recently-hit) regions are explored before speculative edges.
    heap: List[Tuple[int, int, int]] = []
    for cn in obs_cards:
        for step in (-1, 1):
            nxt = cn + step
            if 0 <= nxt <= fmt.max_card:
                heapq.heappush(heap, (0, nxt, step))

    while heap and reader.queries < budget and len(discovered) < target_count:
        misses, cn, step = heapq.heappop(heap)
        if cn in visited or not (0 <= cn <= fmt.max_card):
            continue
        visited.add(cn)
        raw = fmt.encode(fc, cn)
        hit = reader.query(raw)
        if hit:
            discovered.add(raw)
            note_target()
            record()
            nxt = cn + step
            if 0 <= nxt <= fmt.max_card and nxt not in visited:
                heapq.heappush(heap, (0, nxt, step))
        else:
            if misses + 1 <= MAX_GAP:
                nxt = cn + step
                if 0 <= nxt <= fmt.max_card and nxt not in visited:
                    heapq.heappush(heap, (misses + 1, nxt, step))

    # --- Phase 2: fallback linear sweep within the locked facility ----------
    # Reached for random numbering, where neighbours carry no signal. Still
    # far better than brute force because the facility code is pinned.
    if len(discovered) < target_count and reader.queries < budget:
        cn = 0
        while cn <= fmt.max_card and reader.queries < budget and len(discovered) < target_count:
            if cn not in visited:
                visited.add(cn)
                raw = fmt.encode(fc, cn)
                if reader.query(raw):
                    discovered.add(raw)
                    note_target()
                    if reader.queries % 25 == 0 or len(discovered) >= target_count:
                        record()
            cn += 1

    record()
    frac = len(discovered) / total if total else 0.0
    return CharacterizationResult(
        method="ml",
        queries_to_target=queries_to_target,
        fraction_found=frac,
        discovered=len(discovered),
        total_issued=total,
        target_fraction=target,
        censored=queries_to_target is None,
        trajectory=trajectory,
    )


def run_all_methods(
    dep: Deployment,
    n_observations: int = 8,
    target: float = 0.9,
    seed: int = 0,
) -> dict:
    """Convenience: run all three strategies on one deployment."""
    import random

    rng = random.Random(seed + 7)
    obs = [c.raw for c in dep.observed_sample(n_observations, rng)]
    reader = SimulatedReader.from_deployment(dep)
    return {
        "bruteforce": bruteforce_characterize(dep, target),
        "dictionary": dictionary_characterize(dep, target),
        "ml": ml_characterize(reader, dep, obs, target),
    }
