"""Tests for the prioritized remediation planner."""

from phantomtap.audit import quick_risk_score
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment
from phantomtap.remediation import candidate_fixes, prioritized_plan


def _weak():
    return generate_deployment(
        fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
        family=CardFamily.UID_ONLY, uses_default_keys=True,
        default_key_fraction=0.9, key_diversified=False, seed=1)


def test_fixes_reduce_risk():
    dep = _weak()
    base = quick_risk_score(dep)
    fixes = candidate_fixes(dep)
    assert fixes, "a weak deployment should have candidate fixes"
    for f in fixes:
        assert f.new_risk <= base
        assert f.delta == base - f.new_risk


def test_candidate_fixes_are_sorted_by_impact():
    fixes = candidate_fixes(_weak())
    deltas = [f.delta for f in fixes]
    assert deltas == sorted(deltas, reverse=True)


def test_roadmap_is_monotonically_safer():
    dep = _weak()
    plan = prioritized_plan(dep)
    assert plan, "expected a non-empty roadmap for a weak deployment"
    risks = [quick_risk_score(dep)] + [f.new_risk for f in plan]
    assert all(risks[i + 1] <= risks[i] for i in range(len(risks) - 1))
    # The roadmap must materially improve the deployment.
    assert risks[-1] < risks[0] - 10


def test_strong_deployment_has_little_to_fix():
    strong = generate_deployment(
        fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
        family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
        default_key_fraction=0.0, key_diversified=True, seed=1)
    assert quick_risk_score(strong) < quick_risk_score(_weak())
