"""Wiegand / access-control credential format definitions.

A :class:`WiegandFormat` describes how a facility code (FC) and card number
(CN) are packed into a fixed-width bit frame, together with the parity bits that
protect it.  These are the *public, documented* formats used by the
overwhelming majority of physical access-control deployments; nothing here is
proprietary or site-specific.

**Real spec alignment.** The field offsets and parity ranges below follow the
Proxmark3 reference implementation (``client/src/wiegand_formats.c`` in
RfidResearchGroup/proxmark3), so the encoder is *bit-compatible* with what a
Proxmark3 or Flipper Zero produces for these formats -- not a simplified
approximation.  Frame bits are numbered MSB-first (bit 0 is the first bit on the
wire), exactly as in that source.

Example (HID H10301, 26-bit)::

    bit  0: odd  parity over bits 1..12
    bits 1..16 : card number (16 bits)
    bits 17..24: facility code (8 bits)
    bit 25: even parity over bits 13..24
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def _int_to_bits(value: int, width: int) -> List[int]:
    """Big-endian (MSB-first) bit list of ``value`` in ``width`` bits."""
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
class Field:
    """A named field placed at an MSB-first ``offset`` in the frame."""

    name: str
    offset: int
    width: int


@dataclass(frozen=True)
class ParityBit:
    """A parity bit at frame ``position`` covering frame bits ``[start, stop)``.

    ``kind`` is ``"even"`` or ``"odd"``; the ranges cover *data* bits only.
    """

    position: int
    kind: str
    start: int
    stop: int

    def compute(self, frame: List[int]) -> int:
        x = _xor(frame[self.start:self.stop])
        return x if self.kind == "even" else (1 ^ x)


@dataclass(frozen=True)
class WiegandFormat:
    name: str
    total_bits: int
    fields: Tuple[Field, ...]
    parities: Tuple[ParityBit, ...]
    description: str = ""
    proxmark_compatible: bool = False

    # -- derived field accessors ----------------------------------------
    def _field(self, name: str) -> Optional[Field]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    @property
    def facility_bits(self) -> int:
        f = self._field("facility")
        return f.width if f else 0

    @property
    def card_bits(self) -> int:
        f = self._field("card")
        return f.width if f else 0

    @property
    def data_bits(self) -> int:
        return sum(f.width for f in self.fields)

    @property
    def max_facility(self) -> int:
        return (1 << self.facility_bits) - 1

    @property
    def max_card(self) -> int:
        return (1 << self.card_bits) - 1

    def __post_init__(self) -> None:
        expected = self.data_bits + len(self.parities)
        if expected != self.total_bits:
            raise ValueError(
                f"{self.name}: data({self.data_bits}) + parity({len(self.parities)})"
                f" != total({self.total_bits})"
            )

    # -- encode / decode -------------------------------------------------
    def encode(self, facility_code: int, card_number: int) -> int:
        if not 0 <= facility_code <= self.max_facility:
            raise ValueError(f"facility_code out of range for {self.name}")
        if not 0 <= card_number <= self.max_card:
            raise ValueError(f"card_number out of range for {self.name}")
        frame = [0] * self.total_bits
        placements = {"facility": facility_code, "card": card_number}
        for f in self.fields:
            bits = _int_to_bits(placements[f.name], f.width)
            frame[f.offset:f.offset + f.width] = bits
        for p in self.parities:
            frame[p.position] = p.compute(frame)
        return _bits_to_int(frame)

    def decode(self, raw: int) -> "DecodedCredential":
        frame = _int_to_bits(raw, self.total_bits)
        fc_f, cn_f = self._field("facility"), self._field("card")
        fc = _bits_to_int(frame[fc_f.offset:fc_f.offset + fc_f.width]) if fc_f else 0
        cn = _bits_to_int(frame[cn_f.offset:cn_f.offset + cn_f.width]) if cn_f else 0
        parity_ok = all(frame[p.position] == p.compute(frame) for p in self.parities)
        return DecodedCredential(self, fc, cn, raw, parity_ok)

    def parity_ok(self, raw: int) -> bool:
        return self.decode(raw).parity_ok

    def layout_str(self) -> str:
        parts = []
        for f in sorted(self.fields, key=lambda x: x.offset):
            parts.append(f"{f.name}@{f.offset}:{f.width}")
        pp = ", ".join(f"P{p.position}={p.kind}[{p.start}..{p.stop})"
                       for p in self.parities)
        return f"{'; '.join(parts)} | {pp}"


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
# Field offsets + parity ranges follow Proxmark3 wiegand_formats.c (MSB-first).
# ---------------------------------------------------------------------------
H10301_26 = WiegandFormat(
    name="H10301-26",
    total_bits=26,
    fields=(Field("card", 1, 16), Field("facility", 17, 8)),
    parities=(ParityBit(0, "odd", 1, 13), ParityBit(25, "even", 13, 25)),
    description="HID 26-bit, the ubiquitous legacy format. Tiny 8-bit facility "
    "code space (0-255) makes facility collisions and guessing trivial.",
    proxmark_compatible=True,
)

H10306_34 = WiegandFormat(
    name="H10306-34",
    total_bits=34,
    fields=(Field("facility", 1, 16), Field("card", 17, 16)),
    parities=(ParityBit(0, "even", 1, 17), ParityBit(33, "odd", 17, 33)),
    description="HID H10306 34-bit. 16-bit facility + 16-bit card. Structurally "
    "identical to N10002-34.",
    proxmark_compatible=True,
)

N10002_34 = WiegandFormat(
    name="N10002-34",
    total_bits=34,
    fields=(Field("facility", 1, 16), Field("card", 17, 16)),
    parities=(ParityBit(0, "even", 1, 17), ParityBit(33, "odd", 17, 33)),
    description="HID 34-bit. Wider 16-bit facility code, still 16-bit card "
    "number so per-facility populations stay small. Alias of H10306-34.",
    proxmark_compatible=True,
)

H10304_37 = WiegandFormat(
    name="H10304-37",
    total_bits=37,
    fields=(Field("facility", 1, 16), Field("card", 17, 19)),
    parities=(ParityBit(0, "even", 1, 19), ParityBit(36, "odd", 18, 36)),
    description="HID 37-bit. Larger card-number space; stronger against pure "
    "enumeration but still fully predictable if numbering is sequential.",
    proxmark_compatible=True,
)

H10302_37 = WiegandFormat(
    name="H10302-37",
    total_bits=37,
    fields=(Field("card", 1, 35),),
    parities=(ParityBit(0, "even", 1, 19), ParityBit(36, "odd", 19, 36)),
    description="HID 37-bit with NO facility code -- a single 35-bit card "
    "number. With no facility field to divide the space by, such formats are "
    "markedly more enumerable.",
    proxmark_compatible=True,
)

# Registry keyed by name plus a convenient list ordered by total width.
# H10306-34 and N10002-34 share a structure (aliases); H10302-37 and H10304-37
# share a width but differ in fields/parity, so they remain distinguishable.
REGISTRY = {f.name: f for f in
            (H10301_26, H10306_34, N10002_34, H10304_37, H10302_37)}
ALL_FORMATS: List[WiegandFormat] = sorted(REGISTRY.values(),
                                          key=lambda f: f.total_bits)


def get_format(name: str) -> WiegandFormat:
    try:
        return REGISTRY[name]
    except KeyError as exc:  # pragma: no cover - defensive
        raise KeyError(
            f"unknown format {name!r}; known: {sorted(REGISTRY)}"
        ) from exc


def candidate_formats_for_width(total_bits: int) -> List[WiegandFormat]:
    return [f for f in ALL_FORMATS if f.total_bits == total_bits]
