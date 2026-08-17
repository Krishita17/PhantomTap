"""Tests for the blue-team badge-event detectors and red-vs-blue experiment."""

from phantomtap.monitor import (
    analyze,
    detect_impossible_travel,
    red_vs_blue,
    synthetic_stream,
)
from phantomtap.population import NumberingScheme, generate_deployment


def _dep(scheme=NumberingScheme.SEQUENTIAL, seed=1):
    return generate_deployment(numbering=scheme, issued=500, seed=seed)


def test_all_injected_attacks_are_caught():
    dep = _dep()
    events, injected = synthetic_stream(dep, seed=2)
    alerts = analyze(events, dep=dep)
    kinds = {a.kind for a in alerts}
    for k in injected:
        assert k in kinds, f"detector missed injected attack: {k}"


def test_no_injection_is_quiet_on_travel_and_rogue():
    dep = _dep()
    events, injected = synthetic_stream(dep, seed=2, inject=False)
    assert injected == []
    # Normal business traffic must not raise clone alerts.
    assert detect_impossible_travel(events) == []


def test_rogue_out_of_range_flagged():
    dep = _dep()
    events, _ = synthetic_stream(dep, seed=5)
    alerts = analyze(events, dep=dep)
    rogue = [a for a in alerts if a.kind == "rogue_credential"]
    assert rogue and all(a.severity == "high" for a in rogue)


def test_red_vs_blue_catches_ml_auditor():
    dep = _dep()
    rb = red_vs_blue(dep, rate_per_min=40.0)
    assert rb.detected
    assert rb.detected_after_attempts is not None
    # It should be caught well before it finishes characterising the population.
    assert rb.detected_after_attempts < rb.attempts_total


def test_impossible_travel_needs_two_readers():
    dep = _dep()
    events, _ = synthetic_stream(dep, seed=3)
    clones = [a for a in analyze(events, dep=dep) if a.kind == "impossible_travel"]
    assert clones and clones[0].severity == "critical"
