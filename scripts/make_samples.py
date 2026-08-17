"""Regenerate the committed synthetic sample datasets.

Every credential here is fabricated and self-contained -- no real facility data.
The raw frames are produced by the Proxmark3-aligned encoder in
``phantomtap.formats``, so they are bit-compatible with what real tooling would
emit for these formats.

Run::

    python -m scripts.make_samples
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from phantomtap.population import (
    CardFamily,
    Credential,
    NumberingScheme,
    generate_deployment,
)

OUT = Path(__file__).resolve().parents[1] / "data" / "synthetic"


@dataclass
class Sample:
    name: str
    creds: List[Credential]
    meta: dict


def _dep_sample(name, note="", **kw) -> Sample:
    dep = generate_deployment(**kw)
    meta = dep.summary()
    meta["name"] = name
    meta["note"] = note
    return Sample(name, dep.credentials, meta)


def _campus_sample() -> Sample:
    """A realistic multi-building campus: three facility codes, one 34-bit
    format, sequential issuance per building -- exactly the predictable layout
    an auditor most often meets in the field."""
    creds: List[Credential] = []
    facs = [42, 118, 205]
    for i, fc in enumerate(facs):
        dep = generate_deployment(
            fmt_name="H10306-34", numbering=NumberingScheme.SEQUENTIAL,
            family=CardFamily.MIFARE_CLASSIC, issued=80, facility_code=fc,
            seed=300 + i)
        creds.extend(dep.credentials)
    meta = {
        "name": "example_campus_multifacility",
        "format": "H10306-34",
        "facility_codes": facs,
        "numbering": "sequential",
        "family": "mifare_classic",
        "issued": len(creds),
        "note": "Three-building campus; each building is its own facility code "
                "with sequential badge numbers. Multi-facility deployments are "
                "common and each facility is internally predictable.",
    }
    return Sample("example_campus_multifacility", creds, meta)


def build() -> List[Sample]:
    return [
        _dep_sample(
            "example_weak_26bit_sequential",
            fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
            family=CardFamily.MIFARE_CLASSIC, issued=120,
            uses_default_keys=True, default_key_fraction=0.6,
            key_diversified=False, seed=11,
            note="Classic weak deployment: 26-bit format, sequential numbering, "
                 "default keys. The archetype PhantomTap flags as CRITICAL."),
        _dep_sample(
            "example_strong_37bit_random",
            fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
            family=CardFamily.MIFARE_CLASSIC, issued=120,
            uses_default_keys=False, default_key_fraction=0.0,
            key_diversified=True, seed=7,
            note="Hardened deployment: wide 37-bit format, randomized numbering, "
                 "no default keys, per-card diversified keys."),
        _dep_sample(
            "example_h10306_clustered",
            fmt_name="H10306-34", numbering=NumberingScheme.CLUSTERED,
            family=CardFamily.MIFARE_CLASSIC, issued=150,
            uses_default_keys=True, default_key_fraction=0.3,
            key_diversified=False, seed=23,
            note="34-bit H10306 issued in departmental blocks; each block is "
                 "internally predictable."),
        _dep_sample(
            "example_prox_uid_sequential",
            fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
            family=CardFamily.UID_ONLY, issued=100, seed=31,
            note="Low-frequency UID-only prox (EM4100-class): no authentication, "
                 "clonable to a blank in seconds. Sequential numbering."),
        _campus_sample(),
    ]


def write(samples: List[Sample]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    index = []
    for s in samples:
        with (OUT / f"{s.name}.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["raw_hex", "facility_code", "card_number", "format"])
            for c in s.creds:
                w.writerow([f"{c.raw:X}", c.facility_code, c.card_number, c.fmt_name])
        (OUT / f"{s.name}.summary.json").write_text(json.dumps(s.meta, indent=2))
        index.append(s.meta)
        print(f"  wrote {s.name}.csv ({len(s.creds)} credentials)")
    (OUT / "INDEX.json").write_text(json.dumps(index, indent=2))
    print(f"  wrote INDEX.json ({len(index)} datasets)")


def main() -> None:
    print("Regenerating synthetic samples ->", OUT)
    write(build())
    print("done.")


if __name__ == "__main__":
    main()
