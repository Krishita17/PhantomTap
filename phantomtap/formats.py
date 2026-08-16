"""Wiegand / access-control credential format definitions.

A :class:`WiegandFormat` describes how a facility code (FC) and card number
(CN) are packed into a fixed-width bit frame, together with the parity bits that
bracket the data payload.  These are the *public, documented* formats used by
the overwhelming majority of physical access-control deployments; nothing here
is proprietary or site-specific.

The frame layout modelled is the classic one used by HID and compatible
readers::

    [ leading parity ][ ...data bits... ][ trailing parity ]

where the leading parity covers the high half of the data payload and the
trailing parity covers the low half.  This is exactly the H10301 (26-bit)
scheme and generalises cleanly to the wider formats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def _int_to_bits(value: int, width: int) -> List[int]:
    """Big-endian bit list of ``value`` in ``width`` bits."""
    if value < 0 or value >= (1 << width):
        raise ValueError(f"value {value} does not fit in {width} bits")
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def _bits_to_int(bits: List[int]) -> int:
    out = 0
    for b in bits:
        out = (out << 1) | (b & 1)
    return out


def _xor(bits: List[int]) -> int:
    acc = 0
    for b in bits:
        acc ^= b & 1
    return acc


@dataclass(frozen=True)
class Parity:
    """A single parity bit computed over a slice of the *data* bit array.

    ``kind`` is ``"even"`` or ``"odd"``.  ``start``/``stop`` index into the
    concatenated data payload (facility code followed by card number).
    """

    kind: str
    start: int
    stop: int

    def compute(self, data_bits: List[int]) -> int:
        chunk = data_bits[self.start:self.stop]
        x = _xor(chunk)
        return x if self.kind == "even" else (1 ^ x)


@dataclass(frozen=True)
class WiegandFormat:
    name: str
    total_bits: int
    facility_bits: int
    card_bits: int
    leading: Parity
    trailing: Parity
    description: str = ""

    @property
    def data_bits(self) -> int:
        return self.facility_bits + self.card_bits

    @property
    def max_facility(self) -> int:
        return (1 << self.facility_bits) - 1

    @property
    def max_card(self) -> int:
        return (1 << self.card_bits) - 1

    def __post_init__(self) -> None:
        # A well-formed frame is: 1 leading parity + data + 1 trailing parity.
        expected = self.data_bits + 2
        if expected != self.total_bits:
            raise ValueError(
                f"{self.name}: data({self.data_bits}) + 2 parity != "
                f"total({self.total_bits})"
            )

    # -- encode / decode -------------------------------------------------
    def encode(self, facility_code: int, card_number: int) -> int:
        """Pack (FC, CN) into the full integer frame value, parity included."""
        if not 0 <= facility_code <= self.max_facility:
            raise ValueError(f"facility_code out of range for {self.name}")
        if not 0 <= card_number <= self.max_card:
            raise ValueError(f"card_number out of range for {self.name}")
        data = _int_to_bits(facility_code, self.facility_bits) + _int_to_bits(
            card_number, self.card_bits
        )
        frame = [self.leading.compute(data)] + data + [self.trailing.compute(data)]
        return _bits_to_int(frame)

    def decode(self, raw: int) -> "DecodedCredential":
        bits = _int_to_bits(raw, self.total_bits)
        leading, trailing = bits[0], bits[-1]
        data = bits[1:-1]
        fc = _bits_to_int(data[: self.facility_bits])
        cn = _bits_to_int(data[self.facility_bits:])
        parity_ok = (
            leading == self.leading.compute(data)
            and trailing == self.trailing.compute(data)
        )
        return DecodedCredential(
            fmt=self,
            facility_code=fc,
            card_number=cn,
            raw=raw,
            parity_ok=parity_ok,
        )

    def parity_ok(self, raw: int) -> bool:
        return self.decode(raw).parity_ok


@dataclass(frozen=True)
class DecodedCredential:
    fmt: WiegandFormat
    facility_code: int
    card_number: int
    raw: int
    parity_ok: bool

    def __str__(self) -> str:
        return (
            f"{self.fmt.name} FC={self.facility_code} CN={self.card_number} "
            f"raw=0x{self.raw:X} parity={'ok' if self.parity_ok else 'BAD'}"
        )


# ---------------------------------------------------------------------------
# The registry of public, documented Wiegand formats.
# ---------------------------------------------------------------------------
# Leading parity is *even* over the high half of the data payload; trailing
# parity is *odd* over the low half.  The split points below reproduce the
# published field boundaries for each format.

H10301_26 = WiegandFormat(
    name="H10301-26",
    total_bits=26,
    facility_bits=8,
    card_bits=16,
    leading=Parity("even", 0, 12),
    trailing=Parity("odd", 12, 24),
    description="HID 26-bit, the ubiquitous legacy format. Tiny 8-bit facility "
    "code space (0-255) makes facility collisions and guessing trivial.",
)

N10002_34 = WiegandFormat(
    name="N10002-34",
    total_bits=34,
    facility_bits=16,
    card_bits=16,
    leading=Parity("even", 0, 16),
    trailing=Parity("odd", 16, 32),
    description="HID 34-bit. Wider 16-bit facility code, still 16-bit card "
    "number so per-facility populations stay small.",
)

H10304_37 = WiegandFormat(
    name="H10304-37",
    total_bits=37,
    facility_bits=16,
    card_bits=19,
    leading=Parity("even", 0, 17),
    trailing=Parity("odd", 17, 35),
    description="HID 37-bit. Larger card-number space; stronger against pure "
    "enumeration but still fully predictable if numbering is sequential.",
)

H10302_37 = WiegandFormat(
    name="H10302-37",
    total_bits=37,
    facility_bits=0,
    card_bits=35,
    leading=Parity("even", 0, 18),
    trailing=Parity("odd", 18, 35),
    description="HID 37-bit with NO facility code -- a single 35-bit card "
    "number. With no facility field to lock, the space cannot be divided by "
    "facility, so such formats are markedly more enumerable. (Parity split "
    "modelled with the standard bracket approximation; exact HID map validated "
    "in Tier-2.)",
)

# Registry keyed by name plus a convenient list ordered by total width.
# Note: H10302-37 and H10304-37 share a width but differ in field split and
# parity ranges, so they remain distinguishable by parity consistency.
REGISTRY = {f.name: f for f in (H10301_26, N10002_34, H10304_37, H10302_37)}
ALL_FORMATS: List[WiegandFormat] = sorted(REGISTRY.values(), key=lambda f: f.total_bits)


def get_format(name: str) -> WiegandFormat:
    try:
        return REGISTRY[name]
    except KeyError as exc:  # pragma: no cover - defensive
        raise KeyError(
            f"unknown format {name!r}; known: {sorted(REGISTRY)}"
        ) from exc


def candidate_formats_for_width(total_bits: int) -> List[WiegandFormat]:
    return [f for f in ALL_FORMATS if f.total_bits == total_bits]
