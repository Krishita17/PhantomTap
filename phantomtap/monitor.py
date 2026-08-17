"""Blue-team detection: turning the auditor's lens around.

Everything else in PhantomTap models the *red* side -- reasoning about a badge
system to characterise its weakness. This module is the *blue* side: given a
stream of reader events (badge-ins), it flags the very behaviours the rest of
the toolkit would produce. That makes PhantomTap a small **purple-team**
platform -- it both performs and detects the attack.

Four detectors run over a :class:`BadgeEvent` stream:

``impossible_travel``
    The same credential presented at two readers faster than a human could walk
    between them -- the classic signature of a **cloned / replayed** card.

``enumeration``
    A burst of many distinct credentials at one reader (especially rejected, or
    marching through consecutive card numbers) -- someone **scanning** the
    reader, i.e. exactly PhantomTap's own guided search.

``off_hours``
    An accepted access outside declared business hours.

``rogue_credential``
    A format-valid credential whose card number falls **outside the issued
    range** -- a forged or guessed number that the issuance model never minted.

The ``red_vs_blue`` experiment runs PhantomTap's ML auditor against a recording
reader and measures how quickly the enumeration detector catches it -- and how a
"low-and-slow" attacker trades speed for evasion.
"""

from __future__ import annotations

import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .generator import ml_characterize
from .population import Deployment
from .reader import SimulatedReader

SECONDS_PER_HOUR = 3600.0
MAX_HUMAN_SPEED = 3.0  # m/s -- a brisk run; anything faster between readers is impossible


# ---------------------------------------------------------------------------
# Event + alert model
# ---------------------------------------------------------------------------
@dataclass
class BadgeEvent:
    t: float                    # seconds since midnight of day 0
    reader_id: str
    credential_raw: int
    accepted: bool
    card_number: Optional[int] = None

    @property
    def hour(self) -> float:
        return (self.t % 86400) / SECONDS_PER_HOUR


@dataclass
class Alert:
    kind: str
    severity: str
    t: float
    detail: str
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity,
                "t": round(self.t, 1), "detail": self.detail,
                "evidence": self.evidence}


# ---------------------------------------------------------------------------
# Reader topology + recording reader
# ---------------------------------------------------------------------------
DEFAULT_TOPOLOGY: Dict[str, Tuple[float, float]] = {
    "lobby": (0.0, 0.0),
    "east-wing": (80.0, 0.0),
    "datacenter": (40.0, 120.0),
    "garage": (-60.0, -30.0),
}


def _distance(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    return ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2) ** 0.5


class RecordingReader(SimulatedReader):
    """A simulated reader that logs every credential presented to it."""

    def __init__(self, valid):
        super().__init__(valid=set(valid))
        self.log: List[int] = []

    def query(self, raw: int) -> bool:
        self.log.append(raw)
        return super().query(raw)


# ---------------------------------------------------------------------------
# Synthetic event-stream generator
# ---------------------------------------------------------------------------
def synthetic_stream(
    dep: Deployment,
    *,
    n_employees: int = 40,
    days: int = 1,
    seed: int = 0,
    inject: bool = True,
    topology: Optional[Dict[str, Tuple[float, float]]] = None,
) -> Tuple[List[BadgeEvent], List[str]]:
    """Build a realistic badge stream with (optionally) injected attacks.

    Returns ``(events, injected_kinds)`` where ``injected_kinds`` is the set of
    attack types seeded, for evaluation.
    """
    rng = random.Random(seed)
    topo = topology or DEFAULT_TOPOLOGY
    readers = list(topo)
    events: List[BadgeEvent] = []
    fmt = dep.fmt

    staff = dep.credentials[:min(n_employees, len(dep.credentials))]

    # --- normal traffic: business hours, a few badge-ins per employee ------
    for day in range(days):
        base = day * 86400
        for cred in staff:
            for _ in range(rng.randint(2, 6)):
                hour = rng.uniform(8.0, 18.0)
                t = base + hour * SECONDS_PER_HOUR + rng.uniform(0, 120)
                events.append(BadgeEvent(t, rng.choice(readers), cred.raw,
                                         True, cred.card_number))

    injected: List[str] = []
    if inject and staff:
        # clone: one credential at two distant readers ~2s apart (impossible).
        victim = rng.choice(staff)
        t0 = 11 * SECONDS_PER_HOUR
        events.append(BadgeEvent(t0, "lobby", victim.raw, True, victim.card_number))
        events.append(BadgeEvent(t0 + 2.0, "datacenter", victim.raw, True,
                                  victim.card_number))
        injected.append("impossible_travel")

        cards = [c.card_number for c in dep.credentials]
        lo, hi = min(cards), max(cards)

        # enumeration: a scan burst of consecutive card numbers, mostly rejected.
        # Placed in a range-safe region just outside the issued population.
        scan_len = 60
        if hi + 500 + scan_len <= fmt.max_card:
            start_cn = hi + 500
        elif lo - 500 - scan_len >= 0:
            start_cn = lo - 500 - scan_len
        else:
            start_cn = max(0, min(fmt.max_card - scan_len, 0))
        t1 = 2 * SECONDS_PER_HOUR   # 2am, low-and-quiet
        for i in range(scan_len):
            cn = start_cn + i
            raw = fmt.encode(dep.facility_code, cn)
            events.append(BadgeEvent(t1 + i * 1.5, "garage", raw,
                                     raw in dep.valid_raws, cn))
        injected.append("enumeration")

        # off-hours: an accepted access at 3am.
        oh = rng.choice(staff)
        events.append(BadgeEvent(3 * SECONDS_PER_HOUR, "datacenter", oh.raw,
                                 True, oh.card_number))
        injected.append("off_hours")

        # rogue: a format-valid credential strictly below the issued range
        # (guaranteed outside [lo, hi] and never minted).
        rogue_cn = lo // 2
        rogue_raw = fmt.encode(dep.facility_code, rogue_cn)
        events.append(BadgeEvent(14 * SECONDS_PER_HOUR, "east-wing", rogue_raw,
                                 False, rogue_cn))
        injected.append("rogue_credential")

    events.sort(key=lambda e: e.t)
    return events, injected


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
def detect_impossible_travel(events, topology=None, max_speed=MAX_HUMAN_SPEED):
    topo = topology or DEFAULT_TOPOLOGY
    last: Dict[int, Tuple[float, str]] = {}
    alerts: List[Alert] = []
    for e in events:
        prev = last.get(e.credential_raw)
        if prev and prev[1] != e.reader_id and prev[1] in topo and e.reader_id in topo:
            dt = e.t - prev[0]
            dist = _distance(topo[prev[1]], topo[e.reader_id])
            if dt >= 0 and dist / max(dt, 1e-6) > max_speed:
                alerts.append(Alert(
                    "impossible_travel", "critical", e.t,
                    f"credential 0x{e.credential_raw:X} seen at {prev[1]} then "
                    f"{e.reader_id} ({dist:.0f} m in {dt:.1f} s -> "
                    f"{dist/max(dt,1e-6):.0f} m/s) -- likely cloned/replayed",
                    {"from": prev[1], "to": e.reader_id, "dt_s": round(dt, 1),
                     "dist_m": round(dist, 1)}))
        last[e.credential_raw] = (e.t, e.reader_id)
    return alerts


def detect_enumeration(events, window_s=90.0, distinct_threshold=20,
                       run_threshold=8):
    """Flag scan bursts: many distinct creds in a window, or consecutive runs."""
    per_reader: Dict[str, deque] = defaultdict(deque)
    alerts: List[Alert] = []
    fired_reader: set = set()
    recent_cns: Dict[str, deque] = defaultdict(deque)
    for e in events:
        w = per_reader[e.reader_id]
        w.append(e)
        while w and e.t - w[0].t > window_s:
            w.popleft()
        distinct = {ev.credential_raw for ev in w}
        rejects = sum(1 for ev in w if not ev.accepted)

        # consecutive card-number run (a sequential sweep)
        cns = recent_cns[e.reader_id]
        if e.card_number is not None:
            cns.append(e.card_number)
            while len(cns) > run_threshold:
                cns.popleft()
        run = len(cns) >= run_threshold and all(
            cns[i] + 1 == cns[i + 1] for i in range(len(cns) - 1))

        if e.reader_id not in fired_reader and (
                (len(distinct) >= distinct_threshold and rejects >= distinct_threshold // 2)
                or run):
            fired_reader.add(e.reader_id)
            why = ("consecutive card-number sweep" if run else
                   f"{len(distinct)} distinct creds / {rejects} rejects in "
                   f"{window_s:.0f}s")
            alerts.append(Alert(
                "enumeration", "high", e.t,
                f"scan/enumeration at {e.reader_id}: {why}",
                {"reader": e.reader_id, "distinct": len(distinct),
                 "rejects": rejects, "sequential_run": run}))
    return alerts


def detect_off_hours(events, business=(8.0, 19.0)):
    alerts: List[Alert] = []
    for e in events:
        if e.accepted and not (business[0] <= e.hour <= business[1]):
            alerts.append(Alert(
                "off_hours", "medium", e.t,
                f"accepted access at {e.hour:04.1f}h (outside "
                f"{business[0]:.0f}-{business[1]:.0f}h) at {e.reader_id}",
                {"reader": e.reader_id, "hour": round(e.hour, 2)}))
    return alerts


def detect_rogue_credentials(events, issued_lo, issued_hi):
    alerts: List[Alert] = []
    for e in events:
        if e.card_number is not None and not (issued_lo <= e.card_number <= issued_hi):
            alerts.append(Alert(
                "rogue_credential", "high", e.t,
                f"card #{e.card_number} outside issued range "
                f"[{issued_lo}, {issued_hi}] at {e.reader_id} -- forged/guessed",
                {"reader": e.reader_id, "card_number": e.card_number,
                 "accepted": e.accepted}))
    return alerts


def analyze(events, dep: Optional[Deployment] = None, topology=None,
            issued_range: Optional[Tuple[int, int]] = None) -> List[Alert]:
    """Run all detectors and return alerts sorted by time."""
    alerts: List[Alert] = []
    alerts += detect_impossible_travel(events, topology)
    alerts += detect_enumeration(events)
    alerts += detect_off_hours(events)
    if issued_range is None and dep is not None:
        cards = [c.card_number for c in dep.credentials]
        issued_range = (min(cards), max(cards))
    if issued_range is not None:
        alerts += detect_rogue_credentials(events, *issued_range)
    alerts.sort(key=lambda a: a.t)
    return alerts


# ---------------------------------------------------------------------------
# Purple-team: does the blue side catch PhantomTap's own red side?
# ---------------------------------------------------------------------------
@dataclass
class RedBlueResult:
    attempts_total: int
    detected: bool
    detected_after_attempts: Optional[int]
    rate_per_min: float

    def as_dict(self) -> dict:
        return {
            "attempts_total": self.attempts_total,
            "detected": self.detected,
            "detected_after_attempts": self.detected_after_attempts,
            "rate_per_min": self.rate_per_min,
        }


def red_vs_blue(dep: Deployment, rate_per_min: float = 40.0,
                n_observations: int = 8) -> RedBlueResult:
    """Run the ML auditor against a recording reader, then see how fast the
    enumeration detector flags its query pattern at the given attempt rate.
    """
    reader = RecordingReader(dep.valid_raws)
    obs = [c.raw for c in dep.observed_sample(n_observations)]
    ml_characterize(reader, dep, obs, target=0.9)

    dt = 60.0 / max(rate_per_min, 1e-6)
    events = []
    for i, raw in enumerate(reader.log):
        d = dep.fmt.decode(raw)
        events.append(BadgeEvent(i * dt, "target-reader", raw,
                                 raw in dep.valid_raws, d.card_number))
    alerts = detect_enumeration(events)
    if alerts:
        first_t = min(a.t for a in alerts)
        after = int(round(first_t / dt)) + 1
        return RedBlueResult(len(reader.log), True, after, rate_per_min)
    return RedBlueResult(len(reader.log), False, None, rate_per_min)
