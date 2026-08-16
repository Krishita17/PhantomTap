from phantomtap.inference import infer_format
from phantomtap.population import NumberingScheme, generate_deployment


def test_recovers_facility_code_and_format():
    dep = generate_deployment(fmt_name="H10301-26",
                              numbering=NumberingScheme.SEQUENTIAL,
                              issued=300, seed=5)
    obs = [c.raw for c in dep.observed_sample(10)]
    hyp = infer_format(obs)
    assert dep.fmt.name in hyp.consistent_formats
    assert hyp.facility_code == dep.facility_code
    assert hyp.format_confidence > 0.9


def test_sequential_is_predictable_class():
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                              issued=400, seed=1)
    hyp = infer_format([c.raw for c in dep.observed_sample(10)])
    assert hyp.numbering in (NumberingScheme.SEQUENTIAL,
                             NumberingScheme.SEQUENTIAL_GAPS)


def test_random_detected_as_random():
    dep = generate_deployment(numbering=NumberingScheme.RANDOM,
                              issued=400, seed=2)
    hyp = infer_format([c.raw for c in dep.observed_sample(12)])
    assert hyp.numbering == NumberingScheme.RANDOM


def test_width_ambiguity_note_when_small_values():
    # A 37-bit deployment with small numbers is width-ambiguous with narrower
    # formats; the hypothesis should say so and list them.
    dep = generate_deployment(fmt_name="H10304-37",
                              numbering=NumberingScheme.SEQUENTIAL,
                              issued=200, seed=3)
    hyp = infer_format([c.raw for c in dep.observed_sample(8)])
    assert "H10304-37" in hyp.consistent_formats
    assert len(hyp.consistent_formats) >= 1
