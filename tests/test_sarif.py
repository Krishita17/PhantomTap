"""Tests for SARIF export of audit findings."""

from phantomtap.audit import audit_deployment
from phantomtap.population import NumberingScheme, generate_deployment
from phantomtap.sarif import to_sarif


def _sarif(seed=1):
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL, issued=300,
                              seed=seed)
    return audit_deployment(dep), to_sarif(audit_deployment(dep))


def test_sarif_shape_is_valid_2_1_0():
    result, doc = _sarif()
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PhantomTap"
    # one SARIF result per finding
    assert len(run["results"]) == len(result.findings)
    # composite carried in run properties
    assert run["properties"]["compositeRiskScore"] == result.risk_score


def test_severity_maps_to_sarif_level():
    result, doc = _sarif()
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    by_factor = {f.factor: f.severity for f in result.findings}
    for factor, level in levels.items():
        sev = by_factor[factor]
        if sev in ("critical", "high"):
            assert level == "error"
        elif sev == "medium":
            assert level == "warning"
        else:
            assert level == "note"


def test_rules_are_deduplicated():
    _, doc = _sarif()
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
