"""Tests for information-theoretic guessing-resistance scoring."""

from phantomtap.entropy import assess_guessability
from phantomtap.population import NumberingScheme, generate_deployment


def _g(scheme, seed=0):
    dep = generate_deployment(numbering=scheme, issued=500, seed=seed)
    return assess_guessability(dep)


def test_leaked_bits_nonnegative_and_bounded():
    g = _g(NumberingScheme.SEQUENTIAL)
    assert g.leaked_bits >= 0
    assert g.informed_guess_bits <= g.naive_guess_bits + 1e-9


def test_sequential_leaks_more_than_random():
    seq = _g(NumberingScheme.SEQUENTIAL)
    rnd = _g(NumberingScheme.RANDOM)
    # A compact sequential population hands an informed adversary a much easier
    # guess than a population scattered across the whole card space.
    assert seq.informed_guess_bits < rnd.informed_guess_bits
    assert seq.leaked_bits > rnd.leaked_bits


def test_sequential_is_rated_weak_or_worse():
    seq = _g(NumberingScheme.SEQUENTIAL)
    assert seq.rating in {"TRIVIAL", "WEAK", "MODERATE"}
