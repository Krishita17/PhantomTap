"""Credential-format inference from a handful of observed reads.

Given a small set of captured raw Wiegand frames, recover a structured
hypothesis about the deployment:

* which **format** (bit width + field layout + parity) explains the reads,
* the **facility code** in use,
* the **numbering scheme** (sequential vs. clustered vs. random),
* an estimate of the **issued card-number range**.

This is the "brain's first half": it replaces a human eyeballing hex dumps.
The method is deliberately simple and inspectable -- parity-consistency scoring
plus lightweight statistics over the decoded card numbers -- because an auditor
has to be able to justify every line of the report.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from .formats import ALL_FORMATS, WiegandFormat
from .population import NumberingScheme


@dataclass
class FormatHypothesis:
    fmt: Optional[WiegandFormat]
    facility_code: Optional[int]
    numbering: NumberingScheme
    card_lo: Optional[int]
    card_hi: Optional[int]
    format_confidence: float
    numbering_confidence: float
    n_observations: int
    # Every format that explains the reads equally well. The chosen ``fmt`` is
    # the narrowest of these (minimal-decoder principle); wider entries are
    # width-ambiguous because their extra high-order bits are unused here.
    consistent_formats: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "format": self.fmt.name if self.fmt else None,
            "consistent_formats": self.consistent_formats,
            "facility_code": self.facility_code,
            "numbering": self.numbering.value,
            "card_lo": self.card_lo,
            "card_hi": self.card_hi,
            "format_confidence": round(self.format_confidence, 3),
            "numbering_confidence": round(self.numbering_confidence, 3),
            "n_observations": self.n_observations,
        }


def _bit_width(raw: int) -> int:
    return max(raw.bit_length(), 1)


def _score_format(fmt: WiegandFormat, raws: List[int]) -> float:
    """Fraction of observations whose parity is valid under ``fmt``.

    The observed frames may carry fewer significant bits than the frame width
    (leading zeros), so we only test formats at least as wide as the widest
    observation.
    """
    widest = max(_bit_width(r) for r in raws)
    if fmt.total_bits < widest:
        return -1.0
    ok = sum(1 for r in raws if fmt.decode(r).parity_ok)
    return ok / len(raws)


def infer_format(raws: List[int]) -> "FormatHypothesis":
    if not raws:
        raise ValueError("need at least one observation")

    # 1. Rank candidate formats by parity consistency. Among those that explain
    #    the reads equally well, pick the *narrowest* (minimal decoder): a wider
    #    format is only distinguishable when its extra high-order bits are used.
    scored = [(f, _score_format(f, raws)) for f in ALL_FORMATS]
    scored = [(f, s) for f, s in scored if s >= 0.0]
    scored.sort(key=lambda t: (t[1], -t[0].total_bits), reverse=True)

    notes: List[str] = []
    if not scored or scored[0][1] < 0.5:
        notes.append("no format matched parity with confidence; frames may be "
                     "raw UID rather than Wiegand")
        return FormatHypothesis(
            fmt=None, facility_code=None,
            numbering=NumberingScheme.RANDOM,
            card_lo=None, card_hi=None,
            format_confidence=0.0, numbering_confidence=0.0,
            n_observations=len(raws), notes=notes,
        )

    best_score = scored[0][1]
    tied = [f for f, s in scored if abs(s - best_score) < 1e-9]
    consistent = sorted((f.name for f in tied),
                        key=lambda n: next(x.total_bits for x in tied if x.name == n))
    best_fmt = min(tied, key=lambda f: f.total_bits)
    if len(tied) > 1:
        wider = [n for n in consistent if n != best_fmt.name]
        notes.append(
            f"width-ambiguous: reads are equally consistent with {', '.join(wider)} "
            f"(high-order bits unused). Reporting narrowest: {best_fmt.name}."
        )

    # 2. Decode with the winner; facility code = the mode across observations.
    decoded = [best_fmt.decode(r) for r in raws]
    fc_counts = Counter(d.facility_code for d in decoded)
    facility_code, fc_hits = fc_counts.most_common(1)[0]
    fc_agreement = fc_hits / len(decoded)
    if fc_agreement < 1.0:
        notes.append(
            f"facility code not unanimous ({fc_hits}/{len(decoded)}); deployment "
            f"may span multiple facility codes"
        )

    cards = sorted(d.card_number for d in decoded)
    card_lo, card_hi = cards[0], cards[-1]

    # 3. Numbering scheme from the spacing of observed card numbers.
    numbering, numbering_conf = _infer_numbering(cards, best_fmt)

    return FormatHypothesis(
        fmt=best_fmt,
        facility_code=facility_code,
        numbering=numbering,
        card_lo=card_lo,
        card_hi=card_hi,
        format_confidence=best_score * (0.5 + 0.5 * fc_agreement),
        numbering_confidence=numbering_conf,
        n_observations=len(raws),
        consistent_formats=consistent,
        notes=notes,
    )


def _infer_numbering(cards: List[int], fmt: WiegandFormat):
    """Classify numbering from observed card-number spread.

    Intuition: a *sequential* population packs many cards into a narrow window,
    so observed numbers land close together relative to the whole card space.
    A *random* population scatters them across the full space.
    """
    if len(cards) < 2:
        return NumberingScheme.SEQUENTIAL, 0.3

    span = cards[-1] - cards[0]
    n = len(cards)
    # Density = how tightly the observations cluster vs. what random would give.
    # Under random issuance over [0, max_card], the expected span of n samples
    # is roughly max_card * (n-1)/(n+1). Compare observed span to that.
    #
    # From a *sparse* handful of reads, strictly-sequential and
    # sequential-with-small-gaps are not honestly distinguishable, so both fall
    # into one predictable "sequential-like" class (reported as SEQUENTIAL).
    # What matters for the audit -- predictability of neighbours -- is captured
    # by how tightly the reads cluster, not by the exact gap pattern.
    expected_random_span = fmt.max_card * (n - 1) / (n + 1)
    density = span / max(expected_random_span, 1)

    if density < 0.05:
        return NumberingScheme.SEQUENTIAL, min(0.95, 0.6 + 0.35 * (1 - density * 20))
    if density < 0.35:
        return NumberingScheme.CLUSTERED, 0.6
    return NumberingScheme.RANDOM, min(0.9, 0.5 + density * 0.4)
