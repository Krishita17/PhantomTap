"""Tests for multi-facility fleet auditing."""

import pytest

from phantomtap.fleet import audit_fleet, render_fleet_markdown
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment


def _campus():
    return [
        generate_deployment(fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
                            family=CardFamily.UID_ONLY, uses_default_keys=True,
                            default_key_fraction=0.9, facility_code=42, issued=100,
                            name="weak-bldg", seed=1),
        generate_deployment(fmt_name="H10306-34", numbering=NumberingScheme.CLUSTERED,
                            family=CardFamily.MIFARE_CLASSIC, facility_code=118,
                            issued=100, name="mid-bldg", seed=2),
        generate_deployment(fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
                            family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
                            key_diversified=True, facility_code=205, issued=100,
                            name="strong-bldg", seed=3),
    ]


def test_fleet_risk_is_weakest_link_dominated():
    fleet = audit_fleet(_campus(), name="campus")
    risks = [f.result.risk_score for f in fleet.facilities]
    mean = sum(risks) / len(risks)
    # weakest-link composite sits between the estate mean and its worst building
    assert mean <= fleet.fleet_risk <= max(risks)
    assert fleet.worst_facility == 42  # the UID-only sequential building


def test_fleet_orders_facilities_worst_first():
    fleet = audit_fleet(_campus())
    scores = [f.result.risk_score for f in fleet.facilities]
    assert scores == sorted(scores, reverse=True)
    assert fleet.total_credentials == 300


def test_fleet_report_lists_every_facility():
    fleet = audit_fleet(_campus(), name="campus")
    md = render_fleet_markdown(fleet)
    for fc in (42, 118, 205):
        assert str(fc) in md
    assert "Fleet risk" in md


def test_empty_fleet_rejected():
    with pytest.raises(ValueError):
        audit_fleet([])
