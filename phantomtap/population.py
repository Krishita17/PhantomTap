"""Synthetic credential-population generator.

This is PhantomTap's main workbench.  It fabricates a realistic *deployment* --
a badge system with an issued population of credentials -- so the whole
inference / candidate-generation / audit pipeline can be developed and
benchmarked with **no hardware and no real facility data**.

Nothing in here is tied to any real building.  A ``Deployment`` carries its own
ground truth (the true format, numbering scheme, keys) so evaluation code can
score how well the auditor recovers it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from . import keys as keymod
from .formats import ALL_FORMATS, WiegandFormat, get_format


class NumberingScheme(str, Enum):
    SEQUENTIAL = "sequential"          # cards issued base, base+1, base+2, ...
    SEQUENTIAL_GAPS = "sequential_gaps"  # sequential but with occasional holes
    CLUSTERED = "clustered"            # a few contiguous blocks (departments)
    RANDOM = "random"                  # card numbers drawn uniformly at random


class CardFamily(str, Enum):
    UID_ONLY = "uid_only"        # low-frequency prox / UID-only: trivially cloned
    MIFARE_CLASSIC = "mifare_classic"  # sectored card with per-sector keys


@dataclass(frozen=True)
class Credential:
    """A single issued credential (the ground-truth object)."""

    raw: int                 # the Wiegand frame value the reader checks
    facility_code: int
    card_number: int
    fmt_name: str


@dataclass
class Deployment:
    """A synthetic badge deployment plus its ground truth."""

    name: str
    fmt: WiegandFormat
    facility_code: int
    numbering: NumberingScheme
    family: CardFamily
    credentials: List[Credential]
    # Key posture (only meaningful for sectored cards):
    uses_default_keys: bool
    default_key_fraction: float   # fraction of sectors still on a default key
    key_diversified: bool         # unique key per card vs one shared key
    seed: int = 0

    # ground-truth numbering span (for evaluation of range recovery)
    card_lo: int = 0
    card_hi: int = 0

    @property
    def valid_raws(self) -> set:
        return {c.raw for c in self.credentials}

    def observed_sample(self, n: int, rng: Optional[random.Random] = None) -> List[Credential]:
        """A random handful of credentials, as an auditor would first capture."""
        rng = rng or random.Random(self.seed + 12345)
        n = min(n, len(self.credentials))
        return rng.sample(self.credentials, n)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "format": self.fmt.name,
            "facility_code": self.facility_code,
            "numbering": self.numbering.value,
            "family": self.family.value,
            "issued": len(self.credentials),
            "card_lo": self.card_lo,
            "card_hi": self.card_hi,
            "uses_default_keys": self.uses_default_keys,
            "default_key_fraction": round(self.default_key_fraction, 3),
            "key_diversified": self.key_diversified,
        }


def _issue_card_numbers(
    scheme: NumberingScheme,
    count: int,
    max_card: int,
    rng: random.Random,
) -> List[int]:
    if scheme == NumberingScheme.SEQUENTIAL:
        base = rng.randint(1000, min(50_000, max_card - count - 1))
        return list(range(base, base + count))

    if scheme == NumberingScheme.SEQUENTIAL_GAPS:
        base = rng.randint(1000, min(50_000, max_card - 3 * count - 1))
        nums, cur = [], base
        while len(nums) < count:
            nums.append(cur)
            cur += 1 if rng.random() > 0.15 else rng.randint(2, 6)
        return nums

    if scheme == NumberingScheme.CLUSTERED:
        nums: List[int] = []
        blocks = rng.randint(2, 4)
        per = max(1, count // blocks)
        for _ in range(blocks):
            base = rng.randint(1000, min(60_000, max_card - per - 1))
            nums.extend(range(base, base + per))
        return nums[:count]

    # RANDOM: scatter across (most of) the format's actual card space, so the
    # spread genuinely reflects the available range rather than an arbitrary cap.
    hi = max(count * 20, min(max_card, 1 << 20))
    return rng.sample(range(1, hi + 1), count)


def generate_deployment(
    *,
    fmt_name: str = "H10301-26",
    numbering: NumberingScheme = NumberingScheme.SEQUENTIAL,
    family: CardFamily = CardFamily.MIFARE_CLASSIC,
    issued: int = 500,
    facility_code: Optional[int] = None,
    uses_default_keys: bool = True,
    default_key_fraction: float = 0.6,
    key_diversified: bool = False,
    seed: int = 0,
    name: Optional[str] = None,
) -> Deployment:
    """Fabricate one synthetic deployment with reproducible ground truth."""
    rng = random.Random(seed)
    fmt = get_format(fmt_name)

    if facility_code is None:
        # Formats with no facility field (e.g. H10302) always use FC 0.
        facility_code = 0 if fmt.max_facility == 0 else rng.randint(
            1, min(fmt.max_facility, 250))

    card_nums = _issue_card_numbers(numbering, issued, fmt.max_card, rng)
    creds = [
        Credential(
            raw=fmt.encode(facility_code, cn),
            facility_code=facility_code,
            card_number=cn,
            fmt_name=fmt.name,
        )
        for cn in card_nums
    ]

    return Deployment(
        name=name or f"{fmt.name}/{numbering.value}/{family.value}/seed{seed}",
        fmt=fmt,
        facility_code=facility_code,
        numbering=numbering,
        family=family,
        credentials=creds,
        uses_default_keys=uses_default_keys,
        default_key_fraction=default_key_fraction if family == CardFamily.MIFARE_CLASSIC else 0.0,
        key_diversified=key_diversified,
        seed=seed,
        card_lo=min(card_nums),
        card_hi=max(card_nums),
    )


def sector_key_posture(dep: Deployment, sectors: int = 16) -> List[str]:
    """Return the (synthetic) key each sector carries, for audit demonstration.

    Default-keyed sectors use publicly documented default keys; the rest use a
    random 6-byte key.  Only meaningful for MIFARE-family cards.
    """
    rng = random.Random(dep.seed + 999)
    posture: List[str] = []
    defaults = keymod.DEFAULT_KEYS
    for _ in range(sectors):
        if dep.family == CardFamily.MIFARE_CLASSIC and dep.uses_default_keys and rng.random() < dep.default_key_fraction:
            posture.append(rng.choice(defaults))
        else:
            posture.append("%012X" % rng.getrandbits(48))
    return posture
