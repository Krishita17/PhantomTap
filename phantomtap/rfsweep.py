"""Counter-surveillance: rogue-reader / skimmer detection by RF fingerprint.

Inspired by the excellent **Specter** project for the Flipper Zero
(github.com/at0m-b0mb/Specter-FlipperZero), which turns a Flipper into a
*passive* bug-sweep: it never transmits, it just listens for the 13.56 MHz
carrier a powered-on reader is constantly emitting and flags hidden skimmers,
covert door readers, and rogue loggers.

PhantomTap adds the analysis half. A reader's carrier has a **timing
fingerprint** -- how often it polls for a card, how wide each burst is, the
duty cycle, and the jitter of a cheap clone versus a real terminal. This module
models those signatures, classifies an observed emitter against a library of
known reader types, and answers Specter's four questions:

* **what is it?**  -> classify the emitter (access reader, payment terminal,
  transit gate, skimmer, rogue logger),
* **where is it?** -> proximity band from field strength,
* **is the room clean?** -> sweep a set of emitters against an expected
  whitelist and flag the rogues,
* **did one show up while I was away?** -> watch-mode detection latency.

Everything runs on a synthetic RF environment (no hardware, no transmit), in
keeping with PhantomTap's defensive, simulation-first design.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Feature order used for classification (identity, not proximity):
#   polling_period_ms, burst_width_ms, duty_cycle, jitter_ms
_FEATURES = ("polling_period_ms", "burst_width_ms", "duty_cycle", "jitter_ms")
# Per-feature scale for normalised distance.
_SCALE = {"polling_period_ms": 300.0, "burst_width_ms": 40.0,
          "duty_cycle": 0.3, "jitter_ms": 20.0}
_OOD_THRESHOLD = 1.15   # distance beyond which an emitter is "unknown/suspicious"


@dataclass(frozen=True)
class EmitterProfile:
    """A known reader/emitter type and its characteristic carrier signature."""

    name: str
    kind: str
    legit: bool
    polling_period_ms: float
    burst_width_ms: float
    duty_cycle: float
    jitter_ms: float

    def vec(self) -> Dict[str, float]:
        return {f: getattr(self, f) for f in _FEATURES}


# A small library of plausible carrier signatures. Legit readers keep tight,
# regular timing; cheap covert devices betray themselves with high jitter and
# odd duty cycles.
PROFILES: List[EmitterProfile] = [
    EmitterProfile("HID access reader", "access_reader", True,
                   polling_period_ms=300, burst_width_ms=20, duty_cycle=0.07,
                   jitter_ms=4),
    EmitterProfile("EMV payment terminal", "payment_terminal", True,
                   polling_period_ms=50, burst_width_ms=45, duty_cycle=0.9,
                   jitter_ms=2),
    EmitterProfile("Transit gate", "transit_gate", True,
                   polling_period_ms=200, burst_width_ms=30, duty_cycle=0.15,
                   jitter_ms=3),
    EmitterProfile("Covert skimmer", "skimmer", False,
                   polling_period_ms=80, burst_width_ms=70, duty_cycle=0.85,
                   jitter_ms=26),
    EmitterProfile("Rogue data logger", "rogue_logger", False,
                   polling_period_ms=800, burst_width_ms=15, duty_cycle=0.02,
                   jitter_ms=42),
]

PROFILE_BY_KIND = {p.kind: p for p in PROFILES}


@dataclass
class EmitterObservation:
    """A single passively-sensed carrier, as Specter would measure it."""

    location: str
    polling_period_ms: float
    burst_width_ms: float
    duty_cycle: float
    jitter_ms: float
    field_strength: float          # 0..1 proxy for RSSI / proximity
    truth_kind: Optional[str] = None   # ground truth, for evaluation only

    def vec(self) -> Dict[str, float]:
        return {f: getattr(self, f) for f in _FEATURES}


@dataclass
class Detection:
    location: str
    classified_kind: str
    profile_name: str
    is_rogue: bool
    confidence: float
    proximity: str
    distance: float

    def as_dict(self) -> dict:
        return {"location": self.location, "classified_kind": self.classified_kind,
                "profile_name": self.profile_name, "is_rogue": self.is_rogue,
                "confidence": round(self.confidence, 3),
                "proximity": self.proximity, "distance": round(self.distance, 3)}


def _distance(a: Dict[str, float], b: Dict[str, float]) -> float:
    return math.sqrt(sum(((a[f] - b[f]) / _SCALE[f]) ** 2 for f in _FEATURES))


def proximity_band(field_strength: float) -> str:
    if field_strength >= 0.75:
        return "STRONG"
    if field_strength >= 0.5:
        return "CLOSE"
    if field_strength >= 0.25:
        return "NEAR"
    return "FAINT"


def classify(obs: EmitterObservation) -> Detection:
    """Nearest-profile classification with an out-of-distribution rogue flag."""
    dists = sorted(((_distance(obs.vec(), p.vec()), p) for p in PROFILES),
                   key=lambda t: t[0])
    best_d, best = dists[0]
    second_d = dists[1][0] if len(dists) > 1 else best_d + 1.0
    # Confidence rises with the gap to the runner-up and tightness of the fit.
    margin = (second_d - best_d) / max(second_d, 1e-6)
    confidence = max(0.0, min(1.0, (1.0 / (1.0 + best_d)) * (0.5 + 0.5 * margin)))

    # Rogue if the best match is a known-bad type, OR the signature matches no
    # known emitter well (an unknown device is itself suspicious).
    if best_d > _OOD_THRESHOLD:
        return Detection(obs.location, "unknown", "unknown (OOD)", True,
                         confidence, proximity_band(obs.field_strength), best_d)
    return Detection(obs.location, best.kind, best.name, not best.legit,
                     confidence, proximity_band(obs.field_strength), best_d)


# ---------------------------------------------------------------------------
# Synthetic RF environment (no hardware, never transmits)
# ---------------------------------------------------------------------------
def _sample(profile: EmitterProfile, location: str, field_strength: float,
            rng: random.Random) -> EmitterObservation:
    def jit(v, frac):
        return max(0.0, v + rng.gauss(0, frac * max(v, 1e-6)))
    # measurement noise scales with the emitter's own jitter
    noise = 0.10 + profile.jitter_ms / 200.0
    return EmitterObservation(
        location=location,
        polling_period_ms=jit(profile.polling_period_ms, noise),
        burst_width_ms=jit(profile.burst_width_ms, noise),
        duty_cycle=min(1.0, jit(profile.duty_cycle, noise)),
        jitter_ms=jit(profile.jitter_ms, 0.25),
        field_strength=field_strength,
        truth_kind=profile.kind,
    )


def synthetic_sweep(seed: int = 0, inject_rogue: bool = True
                    ) -> Tuple[List[EmitterObservation], List[str]]:
    """Build a room's worth of sensed emitters, optionally with hidden rogues.

    Returns ``(observations, rogue_locations)``.
    """
    rng = random.Random(seed)
    obs: List[EmitterObservation] = []

    # Expected, installed legit readers.
    installed = [
        ("main-entrance", PROFILE_BY_KIND["access_reader"], 0.8),
        ("cafeteria-till", PROFILE_BY_KIND["payment_terminal"], 0.6),
        ("turnstile-A", PROFILE_BY_KIND["transit_gate"], 0.7),
        ("server-room-door", PROFILE_BY_KIND["access_reader"], 0.55),
    ]
    for loc, prof, fs in installed:
        obs.append(_sample(prof, loc, fs, rng))

    rogue_locations: List[str] = []
    if inject_rogue:
        # a skimmer taped inside a payment terminal, and a slow rogue logger
        obs.append(_sample(PROFILE_BY_KIND["skimmer"], "lobby-atm", 0.35, rng))
        obs.append(_sample(PROFILE_BY_KIND["rogue_logger"], "under-desk-7", 0.2, rng))
        rogue_locations = ["lobby-atm", "under-desk-7"]

    rng.shuffle(obs)
    return obs, rogue_locations


@dataclass
class SweepResult:
    detections: List[Detection]
    rogues: List[Detection]
    clean: bool

    def as_dict(self) -> dict:
        return {"clean": self.clean,
                "n_emitters": len(self.detections),
                "n_rogue": len(self.rogues),
                "detections": [d.as_dict() for d in self.detections]}


def sweep(observations: List[EmitterObservation],
          whitelist: Optional[Dict[str, str]] = None) -> SweepResult:
    """Classify every sensed emitter; the room is 'clean' iff no rogues.

    ``whitelist`` optionally maps ``location -> expected kind``; an emitter whose
    classified kind contradicts the whitelist is also treated as rogue (a legit
    reader type showing up where it shouldn't be).
    """
    detections = [classify(o) for o in observations]
    for d in detections:
        if whitelist and d.location in whitelist and not d.is_rogue:
            if d.classified_kind != whitelist[d.location]:
                d.is_rogue = True
    rogues = [d for d in detections if d.is_rogue]
    return SweepResult(detections=detections, rogues=rogues, clean=not rogues)


def watch_detection_latency(seed: int = 0, appear_at: int = 15,
                            ticks: int = 40) -> Optional[int]:
    """Watch-mode: a rogue skimmer appears mid-window; return ticks-to-detect."""
    rng = random.Random(seed)
    for t in range(ticks):
        if t < appear_at:
            continue
        # once present, each tick is a fresh noisy measurement of the skimmer
        obs = _sample(PROFILE_BY_KIND["skimmer"], "watch", 0.3, rng)
        if classify(obs).is_rogue:
            return t - appear_at + 1
    return None
