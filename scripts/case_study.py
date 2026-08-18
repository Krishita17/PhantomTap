"""Case study: a full fleet audit of a synthetic multi-building campus.

Reconstructs the ``example_campus_multifacility`` estate (three facility codes,
mixed security posture) and runs the complete PhantomTap pipeline on it,
emitting a fleet report and a SARIF file into ``examples/``.

Run::

    python -m scripts.case_study
"""

from __future__ import annotations

import json
from pathlib import Path

from phantomtap.fleet import audit_fleet, render_fleet_markdown
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment
from phantomtap.sarif import to_sarif

EX = Path(__file__).resolve().parents[1] / "examples"

# A realistic estate: an old lobby/garage on 26-bit prox, two mid-tier
# buildings on 34-bit MIFARE, and a new datacenter done right.
CAMPUS = [
    ("lobby (fc42)", dict(facility_code=42, fmt_name="H10301-26",
        numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.UID_ONLY,
        uses_default_keys=True, default_key_fraction=0.9, seed=300)),
    ("east-wing (fc118)", dict(facility_code=118, fmt_name="H10306-34",
        numbering=NumberingScheme.CLUSTERED, family=CardFamily.MIFARE_CLASSIC,
        uses_default_keys=True, default_key_fraction=0.4, seed=301)),
    ("west-wing (fc205)", dict(facility_code=205, fmt_name="H10306-34",
        numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.MIFARE_CLASSIC,
        uses_default_keys=True, default_key_fraction=0.2, seed=302)),
    ("datacenter (fc250)", dict(facility_code=250, fmt_name="H10304-37",
        numbering=NumberingScheme.RANDOM, family=CardFamily.MIFARE_CLASSIC,
        uses_default_keys=False, default_key_fraction=0.0,
        key_diversified=True, seed=303)),
]


def main() -> None:
    EX.mkdir(parents=True, exist_ok=True)
    deps = [generate_deployment(issued=120, name=name, **kw) for name, kw in CAMPUS]
    fleet = audit_fleet(deps, name="Acme HQ campus")

    report = render_fleet_markdown(fleet)
    (EX / "case_study_campus.md").write_text(report)
    print(f"wrote {EX/'case_study_campus.md'}  (fleet risk {fleet.fleet_risk}/100 "
          f"{fleet.fleet_band})")

    # SARIF for the worst building, to show dashboard integration.
    worst = fleet.facilities[0].result
    (EX / "case_study_campus.sarif").write_text(json.dumps(to_sarif(worst), indent=2))
    print(f"wrote {EX/'case_study_campus.sarif'}  ({len(worst.findings)} findings)")


if __name__ == "__main__":
    main()
