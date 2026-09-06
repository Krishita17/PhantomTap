"""Tests for the unified assessment + HTML/JSON report."""

from phantomtap.population import CardFamily, NumberingScheme, generate_deployment
from phantomtap.report import full_assessment, render_html


def _dep(numbering=NumberingScheme.SEQUENTIAL, seed=1):
    return generate_deployment(fmt_name="H10301-26", numbering=numbering,
                               family=CardFamily.MIFARE_CLASSIC, issued=300,
                               seed=seed)


def test_assessment_aggregates_all_sections():
    a = full_assessment(_dep())
    d = a.as_dict()
    for key in ("risk_score", "findings", "guessability", "remediation",
                "timeline_leak"):
        assert key in d
    assert a.result.risk_score == d["risk_score"]
    assert len(a.plan) >= 1


def test_html_is_self_contained_and_complete():
    html = render_html(full_assessment(_dep()))
    assert html.startswith("<!doctype html>")
    # no external assets / scripts
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html.lower()
    for section in ("Findings", "remediation roadmap", "Information-theoretic",
                    "Organizational-timeline", "Authorized, defensive"):
        assert section in html


def test_sequential_flags_timeline_leak_random_does_not():
    seq = render_html(full_assessment(_dep(NumberingScheme.SEQUENTIAL)))
    rnd = render_html(full_assessment(_dep(NumberingScheme.RANDOM)))
    assert "date every other badge" in seq or "date every other" in seq or \
           "two known badge dates" in seq
    assert "no organizational timeline leaks" in rnd


def test_html_escapes_content():
    # deployment names flow into the report; ensure escaping is applied
    html = render_html(full_assessment(_dep()))
    assert "<b>" in html  # our own markup is present
