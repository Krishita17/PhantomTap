"""Tests for reader-to-controller wire-protocol posture."""

import pytest

from phantomtap.wireprotocol import (
    PROTOCOLS,
    assess_link,
    compare_protocols,
    render_markdown,
)


def test_wiegand_is_worst_osdp_sc_is_best():
    wiegand = assess_link("wiegand")
    osdp = assess_link("osdp_sc")
    assert wiegand.link_risk == 100 and wiegand.band == "CRITICAL"
    assert osdp.link_risk == 0 and osdp.band == "MINIMAL"


def test_risk_strictly_decreases_with_protocol_strength():
    order = ["wiegand", "osdp_sc"]
    risks = [assess_link(p).link_risk for p in order]
    assert risks[0] > risks[1]


def test_wiegand_flags_replay_and_cleartext():
    titles = {f.title.lower() for f in assess_link("wiegand").findings}
    assert any("unencrypted" in t for t in titles)
    assert any("replay" in t for t in titles)


def test_osdp_sc_has_only_an_info_finding():
    findings = assess_link("osdp_sc").findings
    assert len(findings) == 1 and findings[0].severity == "info"


def test_compare_returns_all_protocols():
    names = {a.protocol for a in compare_protocols()}
    assert names == set(PROTOCOLS)


def test_unknown_protocol_rejected():
    with pytest.raises(KeyError):
        assess_link("smoke-signals")


def test_markdown_has_comparison_table():
    md = render_markdown("wiegand")
    assert "Protocol comparison" in md and "OSDP Secure Channel" in md
