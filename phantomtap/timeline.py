"""Organizational-intelligence leakage from sequential badge numbering.

Sequential card numbers leak far more than a population count. Because badges are
issued *in hire order*, the card number is a proxy for **seniority**, and if an
auditor can tie even a *couple* of card numbers to real dates (a LinkedIn "started
in March 2022", a visible printed issue date, a press release about a new hire),
a simple linear fit dates **every other badge in the building** -- reconstructing
the organization's headcount, growth curve, and hiring spikes.

This module quantifies that leak on a synthetic org:

* ``estimate_issue_dates`` -- from a few (card, date) anchors, predict the issue
  date of any card (least-squares fit, pure Python);
* ``date_leakage`` -- how accurately the whole population can be dated from only
  ``n_known`` anchors (mean absolute error, in days);
* ``growth_curve`` -- cumulative headcount over time and detected hiring spikes;
* ``leakage_report`` -- a defender-facing summary of what the numbering reveals.

The point is defensive: it shows *why* card numbers should be randomised. On a
randomised scheme the card→date fit collapses (no correlation), and the leak
vanishes -- which the evaluation surfaces directly.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple


@dataclass
class Employee:
    card_number: int
    hire_day: int          # days since the org's start


@dataclass
class OrgModel:
    name: str
    employees: List[Employee]
    base_card: int
    randomized: bool = False

    @property
    def n(self) -> int:
        return len(self.employees)

    def pairs(self) -> List[Tuple[int, int]]:
        return [(e.card_number, e.hire_day) for e in self.employees]


def synthesize_org(n: int = 400, seed: int = 0, base_card: int = 1000,
                   mean_gap_days: float = 6.0, spikes: int = 3,
                   randomized: bool = False, card_space: int = 65535) -> OrgModel:
    """Fabricate an org: people hired over time, badges issued in hire order.

    With ``randomized=True`` the card numbers are shuffled across the space, so
    the card->date correlation (the leak) is destroyed.
    """
    rng = random.Random(seed)
    hire_days: List[int] = []
    day = rng.randint(0, 30)
    # schedule a few hiring spikes (batches of hires on nearby days)
    spike_at = set(rng.sample(range(n), min(spikes, n))) if spikes else set()
    for i in range(n):
        hire_days.append(int(day))
        if i in spike_at:
            # a burst: several hires within a couple of days
            day += rng.uniform(0.1, 0.6)
        else:
            day += max(0.2, rng.expovariate(1.0 / mean_gap_days))
    hire_days.sort()

    if randomized:
        cards = rng.sample(range(base_card, base_card + card_space - 1), n)
    else:
        cards = [base_card + i for i in range(n)]  # sequential in hire order

    emps = [Employee(c, d) for c, d in zip(cards, hire_days)]
    return OrgModel(name="synthetic-org", employees=emps, base_card=base_card,
                    randomized=randomized)


# ---------------------------------------------------------------------------
# Least-squares card -> date model (pure Python)
# ---------------------------------------------------------------------------
@dataclass
class LinearFit:
    slope: float
    intercept: float
    r2: float

    def predict(self, card: int) -> float:
        return self.slope * card + self.intercept


def fit_card_to_date(pairs: Sequence[Tuple[int, int]]) -> Optional[LinearFit]:
    n = len(pairs)
    if n < 2:
        return None
    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return None
    slope = sxy / sxx
    intercept = my - slope * mx
    # R^2
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / ss_tot if ss_tot else 0.0
    return LinearFit(slope, intercept, r2)


def estimate_issue_dates(anchors: Sequence[Tuple[int, int]],
                         query_cards: Sequence[int]) -> Optional[List[float]]:
    """Predict issue day for each query card from a few (card, day) anchors."""
    fit = fit_card_to_date(anchors)
    if fit is None:
        return None
    return [fit.predict(c) for c in query_cards]


@dataclass
class LeakResult:
    n_known: int
    mae_days: float
    r2: float
    randomized: bool

    def as_dict(self) -> dict:
        return {"n_known": self.n_known, "mae_days": round(self.mae_days, 1),
                "r2": round(self.r2, 3), "randomized": self.randomized}


def date_leakage(org: OrgModel, n_known: int = 2, seed: int = 0) -> LeakResult:
    """How accurately can the whole population be dated from ``n_known`` anchors?"""
    rng = random.Random(seed + 5)
    pairs = org.pairs()
    if n_known >= len(pairs):
        n_known = max(2, len(pairs) // 2)
    anchors = rng.sample(pairs, n_known)
    rest = [p for p in pairs if p not in anchors]
    preds = estimate_issue_dates(anchors, [c for c, _ in rest])
    fit = fit_card_to_date(anchors)
    if preds is None or not rest:
        return LeakResult(n_known, float("nan"), 0.0, org.randomized)
    mae = sum(abs(p - d) for p, (_, d) in zip(preds, rest)) / len(rest)
    # r2 measured on the full population against the anchor-derived line
    full_fit = fit_card_to_date(pairs)
    return LeakResult(n_known, mae, full_fit.r2 if full_fit else 0.0, org.randomized)


# ---------------------------------------------------------------------------
# Growth curve + hiring-spike detection
# ---------------------------------------------------------------------------
@dataclass
class GrowthCurve:
    days: List[int]            # sorted hire days
    cumulative: List[int]      # headcount over time
    spike_days: List[int]      # start-day of each detected hiring spike
    hires_per_month: List[Tuple[int, int]]  # (month_index, count)


def growth_curve(org: OrgModel, bin_days: int = 30, spike_k: float = 2.0) -> GrowthCurve:
    days = sorted(e.hire_day for e in org.employees)
    cumulative = list(range(1, len(days) + 1))
    # bin hires per month
    if not days:
        return GrowthCurve([], [], [], [])
    span = days[-1] - days[0] + 1
    n_bins = max(1, math.ceil(span / bin_days))
    counts = [0] * n_bins
    for d in days:
        counts[min(n_bins - 1, (d - days[0]) // bin_days)] += 1
    mean = sum(counts) / len(counts)
    var = sum((c - mean) ** 2 for c in counts) / len(counts)
    std = math.sqrt(var)
    spike_days = [days[0] + i * bin_days for i, c in enumerate(counts)
                  if c > mean + spike_k * std]
    hires_per_month = [(i, c) for i, c in enumerate(counts)]
    return GrowthCurve(days, cumulative, spike_days, hires_per_month)


def leakage_report(org: OrgModel) -> str:
    leak2 = date_leakage(org, n_known=2)
    leak5 = date_leakage(org, n_known=5)
    g = growth_curve(org)
    span_days = (g.days[-1] - g.days[0]) if g.days else 0
    rate = org.n / (span_days / 30.0) if span_days else 0.0
    L: List[str] = ["# PhantomTap Organizational-Leakage Report", "",
                    f"**Deployment numbering:** "
                    f"{'randomised' if org.randomized else 'sequential'}  ",
                    f"**Headcount inferred:** {org.n} · "
                    f"**Hiring window:** ~{span_days} days · "
                    f"**Avg hiring rate:** {rate:.1f}/month  ", ""]
    if org.randomized:
        L += ["Randomised numbering **breaks** the card→date correlation "
              f"(R² {leak2.r2:.2f}). Dating badges from a few anchors fails "
              f"(MAE {leak2.mae_days:.0f} days) — org intel does **not** leak. "
              "This is the defended posture."]
    else:
        L += [f"Sequential numbering leaks the hiring timeline (card→date "
              f"R² {leak2.r2:.2f}).", "",
              f"- With **2 known badge dates**, every other badge is dated to "
              f"**±{leak2.mae_days:.0f} days** (MAE).",
              f"- With **5 known dates**, ±{leak5.mae_days:.0f} days.",
              f"- **{len(g.spike_days)} hiring spike(s)** are visible in the "
              f"growth curve — reorganisations / funding events leak too.", "",
              "**Remediation:** issue card numbers from a random pool, decoupled "
              "from hire order, so the number reveals nothing about tenure."]
    return "\n".join(L)
