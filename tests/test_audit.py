from phantomtap.audit import audit_deployment, render_markdown
from phantomtap.bridge import CardRead, MockFlipperBridge
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment


def _weak():
    return generate_deployment(
        fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
        family=CardFamily.UID_ONLY, uses_default_keys=True,
        default_key_fraction=0.9, key_diversified=False, issued=400, seed=1)


def _strong():
    return generate_deployment(
        fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
        family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
        default_key_fraction=0.0, key_diversified=True, issued=400, seed=1)


def test_weak_scores_higher_than_strong():
    weak = audit_deployment(_weak())
    strong = audit_deployment(_strong())
    assert weak.risk_score > strong.risk_score
    assert weak.risk_band in ("CRITICAL", "HIGH")


def test_report_renders_markdown():
    dep = _weak()
    result = audit_deployment(dep)
    md = render_markdown(result, dep)
    assert "PhantomTap Access-Control Audit Report" in md
    assert "Composite risk score" in md
    assert str(result.risk_score) in md


def test_findings_sorted_by_severity():
    result = audit_deployment(_weak())
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev = [order[f.severity] for f in result.findings]
    assert sev == sorted(sev)


def test_mock_flipper_bridge_replays_reads():
    reads = [CardRead(uid="04A1B2C3", card_type="MIFARE Classic 1K"),
             CardRead(uid="04D4E5F6", card_type="MIFARE Classic 1K")]
    with MockFlipperBridge(reads) as flip:
        assert flip.read_card().uid == "04A1B2C3"
        assert flip.read_card().uid == "04D4E5F6"
        assert flip.read_card() is None
        flip.emulate(0xDEADBEEF)
        assert flip.emulated == [0xDEADBEEF]
