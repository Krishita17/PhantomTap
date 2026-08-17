"""Information-theoretic credential-security scoring.

Access-control risk is usually argued qualitatively ("sequential numbering is
bad"). PhantomTap makes it *quantitative* by measuring, in **bits**, how hard it
is to forge a valid credential -- and, crucially, how much of that difficulty
*collapses* once an adversary reasons about the credential's structure.

Two adversaries are compared:

``naive``
    Knows only the format. Must guess across the whole parity-valid credential
    space. Expected guesses to a first valid credential ~ space / issued.

``structure-aware`` (what PhantomTap's inference enables)
    Has locked the facility code and bounded the issued card-number range from a
    handful of reads. Now only guesses inside that range, at the population's
    fill density. Expected guesses ~ range / issued = 1 / density.

The gap between them is the deployment's **structure leakage** -- the number of
bits of credential security handed to any adversary who bothers to look at the
data instead of brute-forcing blindly. This is a compact, defensible, and (for
physical access control) original security metric.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .population import Deployment


@dataclass
class Guessability:
    issued: int
    format_space_bits: float        # log2 of the full parity-valid space
    issued_range: int               # observed/true issued card-number span
    density: float                  # issued / range within the facility
    naive_guess_bits: float         # log2(expected guesses), no structure
    informed_guess_bits: float      # log2(expected guesses), structure-aware
    leaked_bits: float              # naive - informed
    rating: str

    def as_dict(self) -> dict:
        return {
            "issued": self.issued,
            "format_space_bits": round(self.format_space_bits, 2),
            "issued_range": self.issued_range,
            "density": round(self.density, 4),
            "naive_guess_bits": round(self.naive_guess_bits, 2),
            "informed_guess_bits": round(self.informed_guess_bits, 2),
            "leaked_bits": round(self.leaked_bits, 2),
            "rating": self.rating,
        }


def _rate(informed_bits: float) -> str:
    if informed_bits < 4:
        return "TRIVIAL"      # < 16 guesses to forge a working credential
    if informed_bits < 8:
        return "WEAK"
    if informed_bits < 14:
        return "MODERATE"
    return "STRONG"


def assess_guessability(dep: Deployment) -> Guessability:
    fmt = dep.fmt
    issued = len(dep.credentials)
    cards = [c.card_number for c in dep.credentials]
    rng = max(cards) - min(cards) + 1

    # Full parity-valid space = every (facility, card) combination.
    space_bits = float(fmt.data_bits)

    # Expected guesses (in bits) to land a first valid credential.
    naive = space_bits - math.log2(issued)
    density = issued / rng if rng else 1.0
    informed = math.log2(rng / issued) if rng > issued else 0.0

    leaked = max(0.0, naive - informed)
    return Guessability(
        issued=issued,
        format_space_bits=space_bits,
        issued_range=rng,
        density=density,
        naive_guess_bits=max(0.0, naive),
        informed_guess_bits=max(0.0, informed),
        leaked_bits=leaked,
        rating=_rate(informed),
    )
