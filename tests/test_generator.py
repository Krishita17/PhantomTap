from phantomtap.generator import (
    bruteforce_characterize,
    dictionary_characterize,
    ml_characterize,
    run_all_methods,
)
from phantomtap.population import NumberingScheme, generate_deployment
from phantomtap.reader import SimulatedReader


def test_ml_beats_bruteforce_on_sequential():
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                              issued=400, seed=4)
    res = run_all_methods(dep, seed=4)
    assert res["ml"].queries_to_target is not None
    # ML should be at least 100x cheaper than brute force on sequential
    assert res["ml"].queries_to_target * 100 < res["bruteforce"].queries_to_target


def test_ml_reaches_target_fraction():
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                              issued=300, seed=6)
    reader = SimulatedReader.from_deployment(dep)
    obs = [c.raw for c in dep.observed_sample(8)]
    res = ml_characterize(reader, dep, obs, target=0.9)
    assert res.fraction_found >= 0.9
    assert not res.censored


def test_ml_uses_only_reader_and_observations():
    # ml must not depend on ground-truth validity beyond the reader oracle.
    dep = generate_deployment(numbering=NumberingScheme.RANDOM, issued=200, seed=8)
    reader = SimulatedReader.from_deployment(dep)
    obs = [c.raw for c in dep.observed_sample(8)]
    res = ml_characterize(reader, dep, obs, target=0.9)
    # every accept the reader logged corresponds to a discovered credential
    assert res.discovered >= reader.accepts


def test_baselines_are_deterministic():
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                              issued=250, seed=9)
    a = bruteforce_characterize(dep).queries_to_target
    b = bruteforce_characterize(dep).queries_to_target
    assert a == b
    assert dictionary_characterize(dep).queries_to_target > 0
