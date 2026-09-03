"""Tests for organizational-intelligence leakage from badge numbering."""

from phantomtap.timeline import (
    date_leakage,
    estimate_issue_dates,
    fit_card_to_date,
    growth_curve,
    synthesize_org,
)


def test_sequential_numbering_leaks_dates_from_two_anchors():
    org = synthesize_org(n=400, seed=1, randomized=False)
    leak = date_leakage(org, n_known=2)
    # two anchors should date the whole population tightly on a 6+ year window
    assert leak.r2 > 0.95
    assert leak.mae_days < 120


def test_randomized_numbering_destroys_the_leak():
    org = synthesize_org(n=400, seed=1, randomized=True)
    leak = date_leakage(org, n_known=2)
    assert leak.r2 < 0.2
    assert leak.mae_days > 200          # dating fails — the defended posture


def test_more_anchors_do_not_hurt():
    org = synthesize_org(n=300, seed=2, randomized=False)
    two = date_leakage(org, n_known=2).mae_days
    ten = date_leakage(org, n_known=10).mae_days
    # both should be small; sequential numbering is dated well from very few
    assert two < 150 and ten < 150


def test_linear_fit_is_exact_on_a_line():
    fit = fit_card_to_date([(0, 0), (10, 100), (20, 200)])
    assert abs(fit.slope - 10) < 1e-9
    assert abs(fit.predict(5) - 50) < 1e-9
    assert fit.r2 > 0.999


def test_growth_curve_detects_spikes():
    org = synthesize_org(n=400, seed=1, randomized=False, spikes=3)
    g = growth_curve(org)
    assert g.cumulative[-1] == org.n
    assert len(g.spike_days) >= 1


def test_estimate_requires_two_anchors():
    assert estimate_issue_dates([(1, 10)], [5]) is None
