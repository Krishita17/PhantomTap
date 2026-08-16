"""Bayesian active-learning population estimator.

Discovering *every* issued credential costs at least one reader query per card.
But an auditor's first, most valuable question is cheaper to answer:

    "How many credentials has this facility issued, and over what range?"

PhantomTap answers it with **information-optimal boundary localization**. Given
one credential known to be in range (from the captured reads) and the
facility-code locked by inference, the estimator treats the issued population as
an interval ``[lo, hi]`` with a fill density, and finds the endpoints by:

1. **Galloping search** -- double the step outward to *bracket* each boundary in
   O(log distance) queries, then
2. **Binary search** -- bisect the bracket to pin the boundary, where each query
   is chosen at the midpoint of the current uncertainty (the query that
   maximises expected information -- ~1 bit -- about the boundary location).

A handful of interior probes then estimate the fill *density*, giving a
population-size estimate. The result: a facility's population and range recovered
in **O(log N)** reader queries instead of the **O(N)** a scan would need -- a
different, and for reconnaissance a more useful, capability than exhaustive
discovery.

Small gaps (near-sequential numbering) are tolerated via a look-ahead window, so
the interval model degrades gracefully from strictly-contiguous to gappy
populations; the density estimate corrects the count for sparser layouts.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional

from .formats import WiegandFormat
from .reader import SimulatedReader


@dataclass
class RangeEstimate:
    facility_code: int
    lo_est: int
    hi_est: int
    density_est: float
    count_est: int
    queries: int

    @property
    def span(self) -> int:
        return self.hi_est - self.lo_est + 1

    def as_dict(self) -> dict:
        return {
            "facility_code": self.facility_code,
            "lo_est": self.lo_est,
            "hi_est": self.hi_est,
            "span": self.span,
            "density_est": round(self.density_est, 3),
            "count_est": self.count_est,
            "queries": self.queries,
        }


def _member(reader: SimulatedReader, fmt: WiegandFormat, fc: int, cn: int,
            gap_tol: int) -> bool:
    """Membership test with a small look-ahead so gaps don't fake a boundary.

    Returns True if ``cn`` is issued, or an issued card lies within ``gap_tol``
    just beyond it (in either direction) -- i.e. we are still inside the block.
    """
    if not (0 <= cn <= fmt.max_card):
        return False
    if reader.query(fmt.encode(fc, cn)):
        return True
    for g in range(1, gap_tol + 1):
        if cn + g <= fmt.max_card and reader.query(fmt.encode(fc, cn + g)):
            return True
        if cn - g >= 0 and reader.query(fmt.encode(fc, cn - g)):
            return True
    return False


def _find_boundary(reader, fmt, fc, start, direction, gap_tol):
    """Locate the outermost member from ``start`` in ``direction`` (+1/-1).

    Gallop to bracket the boundary, then bisect. Returns the extreme member cn.
    """
    inside = start                      # known member
    step = 1
    outside = None                      # known non-member (past the edge)
    while True:
        probe = start + direction * step
        if probe < 0 or probe > fmt.max_card:
            outside = probe
            break
        if _member(reader, fmt, fc, probe, gap_tol):
            inside = probe
            step *= 2
        else:
            outside = probe
            break

    # Bisect (inside, outside) -- each query ~1 bit about the boundary location.
    lo, hi = sorted((inside, outside))
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _member(reader, fmt, fc, mid, gap_tol):
            if direction > 0:
                lo = mid
            else:
                hi = mid
            inside = mid
        else:
            if direction > 0:
                hi = mid
            else:
                lo = mid
    return inside


def estimate_population(
    reader: SimulatedReader,
    fmt: WiegandFormat,
    facility_code: int,
    seed_cn: int,
    gap_tol: int = 8,
    density_samples: int = 24,
    rng: Optional[random.Random] = None,
) -> RangeEstimate:
    """Estimate a facility's issued range and count in O(log N) reader queries.

    ``seed_cn`` must be a card number known to be issued (from the captured
    reads). Query cost is measured on ``reader``.
    """
    rng = rng or random.Random(0)
    reader.reset_counters()

    hi = _find_boundary(reader, fmt, facility_code, seed_cn, +1, gap_tol)
    lo = _find_boundary(reader, fmt, facility_code, seed_cn, -1, gap_tol)

    span = hi - lo + 1
    # Interior density: a few cheap probes turn "range" into "population size".
    if span <= density_samples:
        hits = sum(1 for cn in range(lo, hi + 1)
                   if reader.query(fmt.encode(facility_code, cn)))
        density = hits / span if span else 0.0
    else:
        picks = rng.sample(range(lo, hi + 1), density_samples)
        hits = sum(1 for cn in picks
                   if reader.query(fmt.encode(facility_code, cn)))
        density = hits / density_samples

    count_est = max(1, round(density * span))
    return RangeEstimate(
        facility_code=facility_code,
        lo_est=lo,
        hi_est=hi,
        density_est=density,
        count_est=count_est,
        queries=reader.queries,
    )
