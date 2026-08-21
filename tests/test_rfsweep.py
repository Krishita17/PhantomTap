"""Tests for the Specter-inspired rogue-reader / skimmer RF sweep."""

from phantomtap.rfsweep import (
    PROFILE_BY_KIND,
    EmitterObservation,
    classify,
    proximity_band,
    sweep,
    synthetic_sweep,
)


def _obs_from(kind, location="x", fs=0.6):
    p = PROFILE_BY_KIND[kind]
    return EmitterObservation(location, p.polling_period_ms, p.burst_width_ms,
                              p.duty_cycle, p.jitter_ms, fs, truth_kind=kind)


def test_legit_readers_classified_not_rogue():
    for kind in ("access_reader", "payment_terminal", "transit_gate"):
        d = classify(_obs_from(kind))
        assert not d.is_rogue, f"{kind} should not be flagged rogue"


def test_rogue_devices_flagged():
    for kind in ("skimmer", "rogue_logger"):
        d = classify(_obs_from(kind))
        assert d.is_rogue, f"{kind} should be flagged rogue"


def test_proximity_bands_are_ordered():
    assert proximity_band(0.9) == "STRONG"
    assert proximity_band(0.6) == "CLOSE"
    assert proximity_band(0.3) == "NEAR"
    assert proximity_band(0.1) == "FAINT"


def test_sweep_catches_injected_rogues_without_false_positives():
    obs, rogue_locs = synthetic_sweep(seed=3)
    res = sweep(obs)
    assert not res.clean
    caught = {d.location for d in res.rogues}
    assert caught == set(rogue_locs)


def test_clean_room_when_no_injection():
    obs, rogue_locs = synthetic_sweep(seed=5, inject_rogue=False)
    res = sweep(obs)
    assert rogue_locs == []
    assert res.clean
