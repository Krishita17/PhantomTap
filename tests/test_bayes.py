"""Tests for the Bayesian active-learning population estimator."""

import math

from phantomtap.bayes import estimate_population
from phantomtap.population import NumberingScheme, generate_deployment
from phantomtap.reader import SimulatedReader


def _run(scheme, issued=800, seed=0):
    dep = generate_deployment(numbering=scheme, issued=issued, seed=seed)
    reader = SimulatedReader.from_deployment(dep)
    seed_cn = dep.observed_sample(8)[0].card_number
    est = estimate_population(reader, dep.fmt, dep.facility_code, seed_cn)
    return dep, est


def test_sequential_is_sized_accurately_and_cheaply():
    dep, est = _run(NumberingScheme.SEQUENTIAL, issued=800, seed=1)
    err = abs(est.count_est - len(dep.credentials)) / len(dep.credentials)
    assert err < 0.15, f"sequential sizing error too high: {err:.2%}"
    # O(log N): sizing must cost far fewer queries than scanning the population.
    assert est.queries < len(dep.credentials)


def test_sublinear_query_scaling():
    _, e_small = _run(NumberingScheme.SEQUENTIAL, issued=500, seed=2)
    _, e_big = _run(NumberingScheme.SEQUENTIAL, issued=5000, seed=2)
    # 10x the population must not cost anywhere near 10x the queries.
    assert e_big.queries < 3 * e_small.queries


def test_random_numbering_resists_estimation():
    # Randomised numbering should defeat interval-based sizing -- a positive
    # security property, and an honest limitation of the method.
    dep, est = _run(NumberingScheme.RANDOM, issued=800, seed=3)
    err = abs(est.count_est - len(dep.credentials)) / len(dep.credentials)
    assert err > 0.3


def test_range_brackets_seed():
    dep, est = _run(NumberingScheme.SEQUENTIAL, issued=800, seed=4)
    assert est.lo_est <= dep.card_lo + 5
    assert est.hi_est >= dep.card_hi - 5
